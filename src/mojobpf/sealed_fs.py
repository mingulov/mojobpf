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

import ctypes
import hashlib
import os
import stat as _stat


_AT_FDCWD = -100
_AT_EMPTY_PATH = 0x1000


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


def _verify_install(dirfd, name, tmpfd, data):
    """Prove ``name`` is the sealed inode holding ``data`` (seam).

    Returns the snapshot of the verified inode, in
    :func:`snapshot_at` shape, so callers adopt a baseline
    from the installer-held inode and never from a later
    pathname read (A1M6-1).
    """
    want = os.fstat(tmpfd)
    fd = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
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
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            chunks.append(block)
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
    inside the link-to-snapshot window (a chmod there
    could acquire a retained writable mapping whose
    later flips leave no event and no ctime move, so
    the snapshot must not bless it: A1M7-1). Returns
    the hex digest of ``data`` plus the snapshot of the
    verified inode, so callers adopt their baseline from
    the installer-held inode rather than a later pathname
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
        try:
            view = memoryview(bytes(data))
            while view:
                written = os.write(tmpfd, view)
                view = view[written:]
            os.fchmod(tmpfd, seal)
            try:
                os.unlink(name, dir_fd=dirfd)
            except FileNotFoundError:
                pass
            _link_tmpfile(tmpfd, dirfd, name)
            installed = _verify_install(
                dirfd, name, tmpfd, bytes(data)
            )
        finally:
            try:
                os.close(tmpfd)
            except OSError:
                pass
        try:
            watch.check_publication(name)
        except OSError as exc:
            raise AssertionError(
                "staged handoff %r touched between "
                "publication and verification: %s" % (name, exc)
            ) from exc
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

    # Events that void the monitored set even when they carry
    # no watched name: queue overflow (events were lost),
    # watch removal, and the directory itself going away.
    _FATAL_MASK = 0x4000 | 0x8000 | 0x400 | 0x800 | 0x2000

    def __init__(self, directory):
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
        try:
            self.wd = add(self.fd, os.fsencode(directory), self._MASK)
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

    def close(self):
        # Idempotent: signal-owned teardown and the exit
        # backstop both close the monitor (A1M5-3). The
        # number is retired before closing so a second
        # close can never catch a recycled descriptor; a
        # real teardown error still fails closed.
        fd, self.fd = self.fd, -1
        if fd >= 0:
            os.close(fd)
