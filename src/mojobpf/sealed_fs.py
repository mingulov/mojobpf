# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Descriptor-bound sealed filesystem operations (A1M4-1/A1M4-2).

Attestation staging must never trust a pathname twice: every
operation here binds itself to an open descriptor whose identity
was verified, so a directory or file substituted between a check
and its operation cannot divert the operation.

- :func:`open_owned_dir` opens a directory without following a
  final symlink and verifies its identity against a pinned
  ``(st_dev, st_ino)`` record.
- :func:`install_sealed` publishes a buffer under a fresh inode
  that no pathname could reach while writable (``O_TMPFILE`` +
  ``linkat``), sealed before publication, then verifies the
  published entry is that same inode holding those bytes.
- :func:`rmtree_owned` removes a verified directory tree through
  its descriptor and proves the removal.
- :func:`snapshot_at` records the identity bytes a later
  comparison detects any touch with (any write, chmod or
  replacement moves ``ctime`` or the identity).
- :class:`NameWatch` is the inotify name monitor (moved here
  from the test harness so product staging shares the one
  implementation); it raises :class:`OSError` on taint and each
  layer maps that to its own vocabulary.

Integrity violations raise :class:`AssertionError` (fail the
run, never attest through them); unavailable primitives raise
:class:`OSError` (fail closed, like a missing monitor).
"""

import contextlib
import ctypes
import errno
import fcntl
import hashlib
import os
import signal
import stat as _stat
import sys
import threading


_AT_FDCWD = -100
_AT_EMPTY_PATH = 0x1000

# Per-thread install-lease depth (A1M10-1): the verify
# lifecycle's signal handler consults this to decide
# whether a pending break notification may be on this
# thread (mask must stay) or the incoming mask restores
# exactly (R4 item 2).
_lease_tls = threading.local()


def _lease_held_in_this_thread():
    """True while this thread holds an install lease window."""
    return getattr(_lease_tls, "depth", 0) > 0


def _register_lease_guard(fd):
    """Track an acquired lease for handler-side cleanup (A1M13-1)."""
    guards = getattr(_lease_tls, "guards", None)
    if guards is None:
        guards = []
        _lease_tls.guards = guards
    guards.append(fd)


def _unregister_lease_guard(fd):
    """Drop a lease the release path retired.

    Tolerates a prior handler-side pop: the signal
    handler may already have retired this lease.
    """
    guards = getattr(_lease_tls, "guards", None)
    if guards:
        try:
            guards.remove(fd)
        except ValueError:
            pass


def _release_active_lease_guards():
    """Retire this thread's active install leases for a signal handler.

    A pending Python-level handler can run before the
    release path below is entered (A1M13-1: CPython runs
    it before the deferral-masking call returns), and a
    cross-thread trip can land mid-release despite the
    mask; in both cases the normal release-and-drain is
    skipped but the break notification is still pending.
    Retiring here first (unlock attempt, then drain)
    removes the fatal signal before the handler raises.
    Descriptor ownership stays with the install path
    (close drops the lease as a backstop even when the
    unlock attempt fails), so this never closes. Pops
    before cleaning, so a nested handler pass finds an
    empty stack. The drain sits in a finally (A1M14-1):
    a nested cancellation raising through the unlock
    loop must not abandon the drain with the guard
    already popped and the notification still pending.
    Returns failure descriptions (empty when clean)
    for the interruption message; never raises its own
    errors (a nested interruption still propagates,
    drained).
    """
    guards = getattr(_lease_tls, "guards", None)
    if not guards:
        return []
    failures = []
    try:
        while guards:
            fd = guards.pop()
            try:
                fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
            except OSError as exc:
                if exc.errno != errno.EAGAIN:
                    failures.append("lease release failed: %s" % exc)
    finally:
        try:
            while signal.sigtimedwait(
                {signal.SIGIO, signal.SIGPOLL}, 0
            ) is not None:
                pass
        except OSError as exc:
            failures.append("lease drain failed: %s" % exc)
    return failures

# Linux ABI numerics for lease signal ownership
# (asm-generic/fcntl.h: F_SETOWN_EX 15, F_OWNER_TID 0),
# pinned against the exposed constants where present
# (A1M10-2).
_LINUX_F_SETOWN_EX = 15
_LINUX_F_OWNER_TID = 0


def _lease_owner_args():
    """Return ``(cmd, kind)`` for thread-owned lease signals.

    CPython exposes ``F_SETOWN_EX``/``F_OWNER_TID`` only from
    3.13 while requires-python is >= 3.11: on Linux without
    them, use the stable ABI numerics above. Without either,
    raise :class:`OSError` (classified refusal, like a
    missing monitor).
    """
    try:
        return fcntl.F_SETOWN_EX, fcntl.F_OWNER_TID
    except AttributeError:
        if sys.platform != "linux":
            raise OSError(
                "install lease ownership unavailable: no "
                "F_SETOWN_EX on this interpreter/platform"
            )
        return _LINUX_F_SETOWN_EX, _LINUX_F_OWNER_TID


@contextlib.contextmanager
def _held_read_lease(fd):
    """Hold a writer-excluding read lease on ``fd`` (A1M9-1).

    The lease is acquired while the backing is still
    unnamed (no writer can pre-exist) and held across
    publication and the snapshot: any writer open
    inside the window blocks or fails EWOULDBLOCK and
    initiates a break, which the installer's final
    lease check refuses. Notifications are owned by
    this thread (a default break signal is fatal) and
    masked here; pending owned notifications drain
    before the mask is restored. Lease setup failure
    raises :class:`OSError` (fail closed, like a
    missing monitor): filesystems without lease
    support cannot stage. Teardown failures propagate
    (chained behind any install error).
    """
    import struct as _struct

    _lease_tls.depth = getattr(_lease_tls, "depth", 0) + 1
    try:
        setown_cmd, owner_tid = _lease_owner_args()
        try:
            fcntl.fcntl(
                fd, setown_cmd,
                _struct.pack(
                    "=iI", owner_tid,
                    threading.get_native_id(),
                ),
            )
        except OSError as exc:
            raise OSError(
                "install lease ownership unavailable: %s" % exc
            ) from exc
        prev = signal.pthread_sigmask(
            signal.SIG_BLOCK, {signal.SIGIO, signal.SIGPOLL}
        )
        try:
            primary = None
            try:
                try:
                    fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
                except OSError as exc:
                    raise OSError(
                        "install lease unavailable: %s" % exc
                    ) from exc
                _register_lease_guard(fd)
                yield fd
            except BaseException as exc:
                # Explicit in-flight record (A1M13-3):
                # sys.exception() read in the finally below
                # would also see a caller's already-handled
                # ambient exception (a normal install inside
                # the caller's `except` clause), and a later
                # release failure would then re-raise that
                # unrelated error instead of the OSError. Only
                # an error from the acquisition/yield region
                # above is a primary; a clean yield leaves
                # None.
                primary = exc
                raise
            finally:
                # Release-and-drain owns the whole window from
                # acquisition on (A1M11-1): cancellation landing
                # on the acquisition's return still releases and
                # drains before the mask restores below. No
                # acquired flag: UNLCK on a lease-less fd is
                # EAGAIN-tolerated (a forced break already
                # revoked it, or acquisition never succeeded),
                # and an empty drain is a no-op.
                # Cancellation defers across release-and-drain
                # (A1M12-1): a raise landing on the unlock's
                # return or mid-drain would otherwise abandon
                # the drain and deliver a pending break signal
                # to its fatal default on the mask restore
                # below. The deferred signal delivers right
                # after, with the lease released and drained.
                release_mask = signal.pthread_sigmask(
                    signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT}
                )
                try:
                    unlock_error = None
                    try:
                        fcntl.fcntl(
                            fd, fcntl.F_SETLEASE, fcntl.F_UNLCK
                        )
                    except OSError as exc:
                        if exc.errno != errno.EAGAIN:
                            # Recorded, not raised (A1M13-2):
                            # raising here would skip the
                            # drain below and leave a pending
                            # break notification to die on at
                            # the mask restore.
                            unlock_error = exc
                    try:
                        while signal.sigtimedwait(
                            {signal.SIGIO, signal.SIGPOLL}, 0
                        ) is not None:
                            pass
                    except OSError as drain_error:
                        if unlock_error is not None:
                            unlock_error.add_note(
                                "install lease drain also failed: %s"
                                % drain_error
                            )
                        elif primary is not None:
                            primary.add_note(
                                "install lease release also failed: %s"
                                % drain_error
                            )
                        else:
                            raise
                    # Unregister only after the drain
                    # (A1M13-1): a handler landing before
                    # this point must still find the guard
                    # and retire it; a landing after this
                    # point is safe because the drain is
                    # complete. Before any raise below, so
                    # no path leaves a stale registration
                    # behind.
                    _unregister_lease_guard(fd)
                    if unlock_error is not None:
                        # A secondary cleanup failure must not
                        # mask a primary in-flight error
                        # (A1M12-2): record it on the primary
                        # and re-raise the primary. With no
                        # primary the release failure itself
                        # propagates.
                        if primary is None:
                            raise unlock_error
                        primary.add_note(
                            "install lease release also failed: %s"
                            % unlock_error
                        )
                        raise primary
                finally:
                    signal.pthread_sigmask(
                        signal.SIG_SETMASK, release_mask
                    )
        finally:
            # Mask first (S13): a trip landing on the
            # unregister below raises through the handler,
            # which pops the guard itself, so skipping the
            # unregister is harmless; skipping the restore
            # would leak a blocked mask to the caller
            # instead.
            signal.pthread_sigmask(signal.SIG_SETMASK, prev)
            # Backstop unregister (A1M13-1): every exit from
            # the window above drops the registration, so no
            # path (including a raise at the deferral entry
            # itself) can leave a stale fd for a later
            # handler pass. Idempotent: the release path
            # already unregistered on its normal exits, and
            # the handler pops before raising.
            _unregister_lease_guard(fd)
    finally:
        _lease_tls.depth -= 1


def open_owned_dir(path, want):
    """Open ``path`` and verify it is the owned directory.

    ``want`` is the pinned ``(st_dev, st_ino)`` record or None
    for an unbound directory (unit-test stand-ins, which can
    never back a PASS through the attested finish path).
    Returns the open descriptor; the caller owns (and must
    close) it. A registered directory that fails to open or
    mismatches raises.
    """
    fd = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        pinned = os.fstat(fd)
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    if want is not None and (pinned.st_dev, pinned.st_ino) != want:
        try:
            os.close(fd)
        except OSError:
            pass
        raise AssertionError(
            "owned directory substituted: %s" % path
        )
    return fd


def _link_tmpfile(tmpfd, dirfd, name):
    """Publish the sealed ``tmpfd`` inode under ``name`` (seam)."""
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        linkat = libc.linkat
    except AttributeError as exc:
        raise OSError("linkat is unavailable") from exc
    linkat.argtypes = [
        ctypes.c_int, ctypes.c_char_p,
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
    ]
    linkat.restype = ctypes.c_int
    if linkat(tmpfd, b"", dirfd, os.fsencode(name), _AT_EMPTY_PATH):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _verify_install(dirfd, name, heldfd, data):
    """Prove ``name`` is the sealed inode holding ``data`` (seam).

    The published entry is bound with an O_PATH open
    (which never breaks the install lease, unlike a
    read open) and its identity is compared against
    the installer-held descriptor; the bytes are read
    positionally through that same held inode, so a
    directory or file substituted between the check
    and the read cannot divert the proof. Returns the
    snapshot of the verified inode, in
    :func:`snapshot_at` shape, so callers adopt a
    baseline from the installer-held inode and never
    from a later pathname read (A1M6-1, A1M9-1).
    """
    want = os.fstat(heldfd)
    fd = os.open(
        name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=dirfd,
    )
    try:
        got = os.fstat(fd)
        if (got.st_dev, got.st_ino) != (want.st_dev, want.st_ino):
            raise AssertionError(
                "staged handoff published foreign backing for %r"
                % name
            )
        chunks = []
        offset = 0
        while True:
            block = os.pread(heldfd, 65536, offset)
            if not block:
                break
            chunks.append(block)
            offset += len(block)
        if b"".join(chunks) != data:
            raise AssertionError(
                "staged handoff published foreign bytes for %r" % name
            )
        return (
            got.st_dev, got.st_ino, got.st_mode,
            got.st_size, got.st_mtime_ns, got.st_ctime_ns,
        )
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def install_sealed(dirfd, name, data, seal):
    """Install ``data`` under ``name`` through sealed backing.

    The buffer is written to an unnamed temporary (never
    pathname-visible while writable, so no mapping or
    descriptor to it can pre-exist), sealed with ``seal``
    before publication, linked under ``name`` (replacing any
    prior entry, never following it), and verified to be the
    sealed inode holding exactly ``data``. A name monitor
    armed before publication refuses any touch of ``name``
    inside the link-to-snapshot window; an inode
    monitor armed on the still-unnamed backing refuses
    any touch through any alias (directory notifications
    follow the alias used, and an alias outside the
    watched directory leaves no directory event at
    all); and a read lease held from before
    publication until after the snapshot structurally
    excludes writer acquisition inside the window
    (conflicting opens block or fail, and any break
    attempt voids the handoff at the final lease
    check). The adopted baseline's mode must equal
    ``seal`` (a chmod left unrestored would bless a
    writable baseline). Without all of these a chmod
    there could acquire a retained writable mapping
    whose later flips leave no event and no ctime
    move, so the snapshot must not bless it (A1M7-1,
    A1M8-1, A1M9-1). Returns the hex digest of
    ``data`` plus the snapshot of the verified inode,
    so callers adopt their baseline from the
    installer-held inode rather than a later pathname
    read (A1M6-1).
    """
    watch = NameWatch("/proc/self/fd/%d" % dirfd)
    try:
        try:
            tmpfd = os.open(
                ".", os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC,
                0o600, dir_fd=dirfd,
            )
        except OSError as exc:
            raise OSError(
                "sealed backing unavailable: %s" % exc
            ) from exc
        tmpfd_closed = False
        try:
            view = memoryview(bytes(data))
            while view:
                written = os.write(tmpfd, view)
                view = view[written:]
            os.fchmod(tmpfd, seal)
            try:
                heldfd = os.open(
                    "/proc/self/fd/%d" % tmpfd,
                    os.O_RDONLY | os.O_CLOEXEC,
                )
            except OSError as exc:
                raise OSError(
                    "sealed backing reopen unavailable: %s" % exc
                ) from exc
            # The reopened descriptor is owned from
            # here by the finally below (A1M10-3): an
            # fstat failure or an identity mismatch
            # closes it on the way out, like every
            # later branch.
            try:
                held = os.fstat(heldfd)
                want = os.fstat(tmpfd)
                if (held.st_dev, held.st_ino) != (
                    want.st_dev, want.st_ino
                ):
                    raise AssertionError(
                        "sealed backing changed before publication"
                    )
                # The writable descriptor closes before
                # the lease is taken: a read lease
                # refuses to set while any writer is
                # open, so a leaked writer fails the
                # install closed at lease setup.
                try:
                    os.close(tmpfd)
                except OSError:
                    pass
                tmpfd_closed = True
                with _held_read_lease(heldfd):
                    igram = InodeWatch(
                        "/proc/self/fd/%d" % heldfd
                    )
                    try:
                        try:
                            os.unlink(name, dir_fd=dirfd)
                        except FileNotFoundError:
                            pass
                        _link_tmpfile(heldfd, dirfd, name)
                        try:
                            igram.confirm_own_link(name)
                        except OSError as exc:
                            raise AssertionError(
                                "staged handoff %r touched between "
                                "publication and verification: %s"
                                % (name, exc)
                            ) from exc
                        installed = _verify_install(
                            dirfd, name, heldfd, bytes(data)
                        )
                        if not _stat.S_ISREG(installed[2]) or (
                            _stat.S_IMODE(installed[2]) != seal
                        ):
                            raise AssertionError(
                                "staged handoff %r was not published "
                                "with the sealed mode" % name
                            )
                        try:
                            igram.confirm_quiet(name)
                        except OSError as exc:
                            raise AssertionError(
                                "staged handoff %r touched between "
                                "publication and verification: %s"
                                % (name, exc)
                            ) from exc
                    finally:
                        igram.close()
                    try:
                        watch.check_publication(name)
                    except OSError as exc:
                        raise AssertionError(
                            "staged handoff %r touched between "
                            "publication and verification: %s"
                            % (name, exc)
                        ) from exc
                    # The lease must still be held: any
                    # writer open inside the window (or a
                    # forced break during an adversarial
                    # pause) voids the handoff, without
                    # reacquisition. Query errors refuse.
                    try:
                        state = fcntl.fcntl(
                            heldfd, fcntl.F_GETLEASE
                        )
                    except OSError as exc:
                        raise AssertionError(
                            "staged handoff %r lost its install "
                            "lease: %s" % (name, exc)
                        ) from exc
                    if state != fcntl.F_RDLCK:
                        raise AssertionError(
                            "staged handoff %r lost its install "
                            "lease" % name
                        )
            finally:
                try:
                    os.close(heldfd)
                except OSError:
                    pass
        finally:
            # Only when the reopen or the identity
            # check failed first: the descriptor is
            # otherwise already closed above, and a
            # second close could catch a recycled
            # number.
            if not tmpfd_closed:
                try:
                    os.close(tmpfd)
                except OSError:
                    pass
    finally:
        watch.close()
    return hashlib.sha256(bytes(data)).hexdigest(), installed


def _clear_owned_dir(dirfd):
    try:
        entries = os.listdir("/proc/self/fd/%d" % dirfd)
    except OSError as exc:
        raise OSError(
            "owned directory listing unavailable: %s" % exc
        ) from exc
    for entry in entries:
        if entry in (".", ".."):
            continue
        # An entry present at listing but gone now was
        # relocated, not removed: vanishing is an error,
        # never a skip (A1M5-2).
        try:
            st = os.stat(entry, dir_fd=dirfd, follow_symlinks=False)
        except FileNotFoundError:
            raise AssertionError(
                "owned entry vanished during removal: %r" % entry
            )
        if _stat.S_ISLNK(st.st_mode):
            # O_PATH|O_NOFOLLOW holds the link itself (O_PATH
            # alone would report the target): verify its
            # identity, retain it through the unlink, and
            # prove the held link inode unlinked (A1M6-2). A
            # dangling link needs no target to hold.
            try:
                child = os.open(
                    entry,
                    os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=dirfd,
                )
            except FileNotFoundError:
                raise AssertionError(
                    "owned entry vanished during removal: %r"
                    % entry
                )
            try:
                pinned = os.fstat(child)
                if (pinned.st_dev, pinned.st_ino) != (
                    st.st_dev, st.st_ino
                ):
                    raise AssertionError(
                        "owned entry substituted during removal: "
                        "%r" % entry
                    )
                os.unlink(entry, dir_fd=dirfd)
                if os.fstat(child).st_nlink != 0:
                    raise AssertionError(
                        "owned entry removal unprovable for %r"
                        % entry
                    )
            finally:
                try:
                    os.close(child)
                except OSError:
                    pass
            continue
        flags = (
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            | os.O_NONBLOCK
        )
        if _stat.S_ISDIR(st.st_mode):
            flags |= os.O_DIRECTORY
        try:
            child = os.open(entry, flags, dir_fd=dirfd)
        except FileNotFoundError:
            raise AssertionError(
                "owned entry vanished during removal: %r" % entry
            )
        try:
            pinned = os.fstat(child)
            if (pinned.st_dev, pinned.st_ino) != (
                st.st_dev, st.st_ino
            ):
                raise AssertionError(
                    "owned entry substituted during removal: "
                    "%r" % entry
                )
            if _stat.S_ISDIR(st.st_mode):
                _clear_owned_dir(child)
                os.rmdir(entry, dir_fd=dirfd)
            else:
                os.unlink(entry, dir_fd=dirfd)
            # The descriptor is retained through the removal
            # proof: only our own inode reaching zero links
            # proves its removal (A1M5-2). A hard-linked
            # survivor fails here, loudly, instead of
            # reporting clean.
            if os.fstat(child).st_nlink != 0:
                raise AssertionError(
                    "owned entry removal unprovable for %r" % entry
                )
        finally:
            try:
                os.close(child)
            except OSError:
                pass


def rmtree_owned(parent_fd, name, want):
    """Remove the verified ``name`` tree under ``parent_fd``.

    Opens ``name`` without following links, verifies its
    identity against ``want``, removes every entry below it
    through descriptors, removes the directory itself, and
    proves the removal of the held inode. Returns True when a
    tree was removed, False when ``name`` was already absent.
    A present-but-foreign entry raises instead of removing
    anything. The parent pathname is only a hint: identity
    decides, so a swapped parent can at worst report absence
    or refusal, never a foreign removal.
    """
    if want is None:
        raise AssertionError(
            "refusing to remove an unbound directory: %r" % name
        )
    try:
        child = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        return False
    try:
        pinned = os.fstat(child)
        if (pinned.st_dev, pinned.st_ino) != want:
            raise AssertionError(
                "owned directory substituted; refusing to remove: "
                "%r" % name
            )
        _clear_owned_dir(child)
        os.rmdir(name, dir_fd=parent_fd)
        # A replacement can race the removal. Prove removal of
        # the original directory while its descriptor is held
        # (mirrors the harness input-alias cleanup proof).
        if os.fstat(child).st_nlink != 0:
            raise AssertionError(
                "owned directory removal could not be established "
                "for %r" % name
            )
    finally:
        try:
            os.close(child)
        except OSError:
            pass
    return True


def snapshot_at(dirfd, name):
    """Return the tamper-evident snapshot of ``name``.

    The tuple ``(st_dev, st_ino, st_mode, st_size,
    st_mtime_ns, st_ctime_ns)`` is read without following a
    final symlink: any later write, chmod, replacement or
    removal changes it. Returns None when ``name`` is absent.
    """
    try:
        st = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return (
        st.st_dev, st.st_ino, st.st_mode, st.st_size,
        st.st_mtime_ns, st.st_ctime_ns,
    )


class NameWatch:
    """Guard names in a pinned directory (inotify).

    The backing bytes are sealed. Only replacing an entry can
    change them; every such directory event invalidates the
    guarded set, even if the original entry is restored before
    the consumer returns. Raises :class:`OSError` when the set
    is voided or the monitor loses events.
    """

    _CREATE = 0x100
    _DELETE = 0x200
    _MASK = (0x2 | 0x4 | 0x8 | 0x40 | 0x80 | _CREATE | _DELETE |
             0x400 | 0x800 | 0x2000 | 0x4000 | 0x8000 | 0x1000000)

    # Inode observations (no directory-only bits): opening or
    # reading the watched file stays silent, so the
    # installer's own verification reads cannot taint.
    _ATTRIB = 0x4
    _FILE_MASK = (0x2 | _ATTRIB | 0x8 | 0x400 | 0x800 |
                  0x2000 | 0x4000 | 0x8000)

    # Events that void the monitored set even when they carry
    # no watched name: queue overflow (events were lost),
    # watch removal, and the directory itself going away.
    _FATAL_MASK = 0x4000 | 0x8000 | 0x400 | 0x800 | 0x2000

    def __init__(self, path, mask=None):
        import ctypes as _ctypes

        libc = _ctypes.CDLL(None, use_errno=True)
        try:
            init, add = libc.inotify_init1, libc.inotify_add_watch
        except AttributeError as exc:
            raise OSError("input pathname monitoring is unavailable") from exc
        init.argtypes, init.restype = [_ctypes.c_int], _ctypes.c_int
        add.argtypes = [_ctypes.c_int, _ctypes.c_char_p, _ctypes.c_uint32]
        add.restype = _ctypes.c_int
        self.fd = init(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            error = _ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        self.tainted = None
        self.tainted_name = None
        self.mask = self._MASK if mask is None else mask
        try:
            self.wd = add(self.fd, os.fsencode(path), self.mask)
            if self.wd < 0:
                error = _ctypes.get_errno()
                raise OSError(error, os.strerror(error))
        except BaseException:
            try:
                os.close(self.fd)
            except OSError as exc:
                raise OSError(
                    "input monitor setup teardown failed: %s" % exc
                ) from exc
            raise

    def check(self, *, created=None, names=None):
        """Raise :class:`OSError` when the guarded set is voided."""
        import struct

        header = struct.Struct("=iIII")
        creation_seen = False
        watched = (
            None if names is None
            else set(os.fsencode(name) for name in names)
        )
        while self.tainted is None:
            try:
                events = os.read(self.fd, 65536)
            except BlockingIOError:
                break
            if not events:
                self.tainted = "input monitor returned no event stream"
                break
            offset = 0
            while offset < len(events):
                if len(events) - offset < header.size:
                    self.tainted = "input monitor returned a truncated event"
                    break
                wd, mask, _cookie, size = header.unpack_from(events, offset)
                offset += header.size
                if size > len(events) - offset:
                    self.tainted = "input monitor returned a truncated name"
                    break
                name = events[offset:offset + size].split(b"\0", 1)[0]
                offset += size
                if (created is not None and not creation_seen and
                        wd == self.wd and mask == self._CREATE and
                        name == os.fsencode(created)):
                    creation_seen = True
                    continue
                if watched is not None and name not in watched:
                    if mask & self._FATAL_MASK:
                        self.tainted = (
                            "input monitor lost events for %r"
                            % sorted(names)
                        )
                        self.tainted_name = None
                        break
                    continue
                self.tainted = "input pathname changed or its monitor lost events"
                try:
                    self.tainted_name = name.decode("utf-8", "replace")
                except (UnicodeError, ValueError):
                    self.tainted_name = None
                break
        if created is not None and not creation_seen and self.tainted is None:
            self.tainted = "input monitor did not observe alias publication"
        if self.tainted is not None:
            raise OSError(self.tainted)

    def forgive_names(self, names):
        """Drain pending events, dropping ones for ``names`` only.

        A handoff extended with generated files must not trip
        over its own create/write/chmod events, which predate
        the extension. Events naming any other name taint
        immediately (that handoff predates this call, so the
        event falls inside its window), as do queue overflow,
        watch removal, or a truncated stream.
        """
        import struct

        header = struct.Struct("=iIII")
        forgiven = set(os.fsencode(name) for name in names)
        while self.tainted is None:
            try:
                events = os.read(self.fd, 65536)
            except BlockingIOError:
                break
            if not events:
                self.tainted = "input monitor returned no event stream"
                break
            offset = 0
            while offset < len(events):
                if len(events) - offset < header.size:
                    self.tainted = "input monitor returned a truncated event"
                    break
                _wd, mask, _cookie, size = header.unpack_from(
                    events, offset
                )
                offset += header.size
                if size > len(events) - offset:
                    self.tainted = "input monitor returned a truncated name"
                    break
                name = events[offset:offset + size].split(b"\0", 1)[0]
                offset += size
                if name in forgiven and not (mask & self._FATAL_MASK):
                    continue
                self.tainted = (
                    "input pathname changed or its monitor lost events"
                )
                try:
                    self.tainted_name = name.decode("utf-8", "replace")
                except (UnicodeError, ValueError):
                    self.tainted_name = None
                break

    def check_publication(self, name):
        """Refuse a publication touched before its snapshot.

        The watch must arm before the ``linkat`` that
        publishes ``name``; this drains its queue after the
        installer's snapshot and allows only the trusted
        publication sequence for ``name``: an optional
        delete of a prior entry, then exactly one create.
        ``linkat`` emits no other event for the published
        name (probed: the temporary's own writes/chmod
        arrive under its ``#inode`` pseudo-name, never
        under ``name``), so any attribute, write, move or
        second create/delete naming ``name`` is a
        chmod/mmap/replacement inside the
        link-to-snapshot window (A1M7-1): a retained
        mapping would then flip bytes with no later
        inotify event and no ctime move. Events for other
        names are ignored; queue overflow, watch removal
        or a truncated stream taints (events may have
        been lost). Raises :class:`OSError` on any
        violation; the caller maps it to its own
        integrity vocabulary.
        """
        import struct

        header = struct.Struct("=iIII")
        target = os.fsencode(name)
        seen_delete = False
        seen_create = False

        def _taint(reason):
            self.tainted = reason
            try:
                self.tainted_name = name
            except (UnicodeError, ValueError):
                self.tainted_name = None

        while self.tainted is None:
            try:
                events = os.read(self.fd, 65536)
            except BlockingIOError:
                break
            if not events:
                self.tainted = "input monitor returned no event stream"
                break
            offset = 0
            while offset < len(events):
                if len(events) - offset < header.size:
                    self.tainted = (
                        "input monitor returned a truncated event"
                    )
                    break
                _wd, mask, _cookie, size = header.unpack_from(
                    events, offset
                )
                offset += header.size
                if size > len(events) - offset:
                    self.tainted = (
                        "input monitor returned a truncated name"
                    )
                    break
                event_name = events[offset:offset + size].split(
                    b"\0", 1
                )[0]
                offset += size
                if event_name != target:
                    if mask & self._FATAL_MASK:
                        self.tainted = (
                            "input monitor lost events during "
                            "publication of %r" % name
                        )
                        self.tainted_name = None
                        break
                    continue
                if mask & self._FATAL_MASK:
                    _taint(
                        "input monitor lost events during "
                        "publication of %r" % name
                    )
                    break
                if mask == self._DELETE:
                    if seen_create or seen_delete:
                        _taint(
                            "published entry %r removed inside "
                            "the install window" % name
                        )
                        break
                    seen_delete = True
                    continue
                if mask == self._CREATE:
                    if seen_create:
                        _taint(
                            "published entry %r created twice "
                            "inside the install window" % name
                        )
                        break
                    seen_create = True
                    continue
                _taint(
                    "published entry %r touched inside the "
                    "install window" % name
                )
                break
        if self.tainted is None and not seen_create:
            _taint(
                "input monitor did not observe publication "
                "of %r" % name
            )
        if self.tainted is not None:
            raise OSError(self.tainted)

    def _drain_inode(self):
        """Yield ``(mask, name)`` pairs, tainting on damage.

        Queued-overflow, watch removal, an unmounted
        backing store and a truncated stream all taint:
        events may have been lost. Returns the drained
        pairs; raises :class:`OSError` when tainted.
        """
        import struct

        header = struct.Struct("=iIII")
        pairs = []
        while self.tainted is None:
            try:
                events = os.read(self.fd, 65536)
            except BlockingIOError:
                break
            if not events:
                self.tainted = "input monitor returned no event stream"
                break
            offset = 0
            while offset < len(events):
                if len(events) - offset < header.size:
                    self.tainted = (
                        "input monitor returned a truncated event"
                    )
                    break
                _wd, mask, _cookie, size = header.unpack_from(
                    events, offset
                )
                offset += header.size
                if size > len(events) - offset:
                    self.tainted = (
                        "input monitor returned a truncated name"
                    )
                    break
                name = events[offset:offset + size].split(
                    b"\0", 1
                )[0]
                offset += size
                if mask & self._FATAL_MASK:
                    self.tainted = (
                        "input monitor lost inode events"
                    )
                    self.tainted_name = None
                    break
                pairs.append((mask, name))
        if self.tainted is not None:
            raise OSError(self.tainted)
        return pairs

    def confirm_own_link(self, name):
        """Consume the install's own link event (A1M8-1, D1).

        The inode watch must arm before ``linkat``; this
        runs immediately after and accepts only attribute
        changes (the link itself), proving the watch
        observes this backing inode on this filesystem:
        an empty queue means the gate is blind and fails
        closed. Any other event is a touch inside the
        link-to-drain gap. Raises :class:`OSError`; the
        caller maps it to its integrity vocabulary.
        """
        pairs = self._drain_inode()
        if not pairs:
            self.tainted = (
                "input monitor did not observe publication "
                "of %r" % name
            )
            self.tainted_name = None
            raise OSError(self.tainted)
        for mask, _event in pairs:
            if mask != self._ATTRIB:
                self.tainted = (
                    "published entry %r touched inside the "
                    "install window" % name
                )
                self.tainted_name = name
                raise OSError(self.tainted)

    def confirm_quiet(self, name):
        """Refuse any inode event since the link drain (D2).

        Runs after the installer's snapshot: link, chmod,
        write, move or removal through any alias, inside
        or outside the watched directory, has nowhere to
        hide, because the watch observes the backing inode
        itself rather than a name. Raises
        :class:`OSError`; the caller maps it to its
        integrity vocabulary.
        """
        pairs = self._drain_inode()
        if pairs:
            self.tainted = (
                "published entry %r touched inside the "
                "install window" % name
            )
            self.tainted_name = name
            raise OSError(self.tainted)

    def close(self):
        # Idempotent: signal-owned teardown and the exit
        # backstop both close the monitor (A1M5-3). The
        # number is retired before closing so a second
        # close can never catch a recycled descriptor; a
        # real teardown error still fails closed.
        fd, self.fd = self.fd, -1
        if fd >= 0:
            os.close(fd)


class InodeWatch(NameWatch):
    """Observe one backing inode across every alias (A1M8-1).

    A separate class (same lifecycle and drain vocabulary
    as :class:`NameWatch`) so the install's inode gate
    keeps its file mask even when tests substitute the
    name-watch seam: directory notifications follow the
    alias used, so only inode observations see chmod
    and mapping acquisition through a non-handed name.
    """

    def __init__(self, path):
        super().__init__(path, mask=self._FILE_MASK)
