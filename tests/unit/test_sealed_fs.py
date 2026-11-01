# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Controls for descriptor-bound sealed staging (A1M4-1/A1M4-2)."""

import fcntl
import hashlib
import mmap
import os
import shutil
import sys
import tempfile

import pytest

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

from mojobpf import sealed_fs  # noqa: E402


def _owned_dir():
    root = tempfile.mkdtemp(prefix="sealed-probe-")
    created = os.stat(root, follow_symlinks=False)
    return root, (created.st_dev, created.st_ino)


def test_install_sealed_publishes_expected_bytes_with_seal():
    root, _identity = _owned_dir()
    try:
        dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            digest, installed = sealed_fs.install_sealed(
                dirfd, "input.bpf.o", b"captured-bytes", 0o444
            )
        finally:
            os.close(dirfd)
        assert digest == hashlib.sha256(b"captured-bytes").hexdigest()
        # The installer attests the published inode itself.
        current = os.stat(
            os.path.join(root, "input.bpf.o"), follow_symlinks=False
        )
        assert installed[:2] == (current.st_dev, current.st_ino)
        assert installed[2] & 0o777 == 0o444
        path = os.path.join(root, "input.bpf.o")
        with open(path, "rb") as handle:
            assert handle.read() == b"captured-bytes"
        assert os.stat(path).st_mode & 0o777 == 0o444
        with pytest.raises(OSError):
            os.open(path, os.O_RDWR)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_install_sealed_replaces_without_following():
    # A1M4-1: publishing over a planted symlink replaces the
    # link itself; the link target is never followed or adopted.
    root, _identity = _owned_dir()
    try:
        target = os.path.join(root, "target")
        with open(target, "wb") as handle:
            handle.write(b"target-bytes")
        os.symlink(target, os.path.join(root, "input.bpf.o"))
        dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            sealed_fs.install_sealed(
                dirfd, "input.bpf.o", b"captured-bytes", 0o444
            )
        finally:
            os.close(dirfd)
        path = os.path.join(root, "input.bpf.o")
        assert not os.path.islink(path)
        with open(path, "rb") as handle:
            assert handle.read() == b"captured-bytes"
        with open(target, "rb") as handle:
            assert handle.read() == b"target-bytes"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_install_sealed_is_sealed_before_any_pathname():
    # A1M4-1: the backing must be sealed before any pathname
    # reaches it. At link time there is no temporary entry to
    # pre-link, open or map, and the descriptor already carries
    # the seal.
    root, _identity = _owned_dir()
    real_link = sealed_fs._link_tmpfile
    observed = {}

    def _spying_link(tmpfd, dirfd, name):
        observed["entries"] = sorted(os.listdir(root))
        observed["mode"] = os.fstat(tmpfd).st_mode & 0o777
        observed["fdlink"] = os.readlink(
            "/proc/self/fd/%d" % tmpfd
        )
        return real_link(tmpfd, dirfd, name)

    sealed_fs._link_tmpfile = _spying_link
    try:
        dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            sealed_fs.install_sealed(
                dirfd, "input.bpf.o", b"captured-bytes", 0o444
            )
        finally:
            os.close(dirfd)
    finally:
        sealed_fs._link_tmpfile = real_link
    assert observed["entries"] == [], observed
    assert observed["mode"] == 0o444, oct(observed["mode"])
    assert observed["fdlink"].endswith(" (deleted)"), observed


def test_install_sealed_refuses_inode_mismatch_after_link():
    # A1M4-1: a hard link to byte-identical, already-mapped
    # backing substituted between link and verify passes a byte
    # comparison; the install must refuse on inode identity.
    import mmap as _mmap

    root, _identity = _owned_dir()
    real_verify = sealed_fs._verify_install
    try:
        evil = os.path.join(root, "evil.bpf.o")
        with open(evil, "wb") as handle:
            handle.write(b"captured-bytes")
        os.chmod(evil, 0o644)
        fd = os.open(evil, os.O_RDWR)
        try:
            mapping = _mmap.mmap(
                fd, 0, access=_mmap.ACCESS_WRITE
            )
            try:
                def _swapping_verify(dirfd, name, tmpfd, data):
                    os.unlink(os.path.join(root, name))
                    os.link(evil, os.path.join(root, name))
                    return real_verify(dirfd, name, tmpfd, data)

                sealed_fs._verify_install = _swapping_verify
                dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with pytest.raises(AssertionError):
                        sealed_fs.install_sealed(
                            dirfd, "input.bpf.o",
                            b"captured-bytes", 0o444,
                        )
                finally:
                    os.close(dirfd)
                # The retained mapping never reached a published
                # entry: the swap was refused, not adopted.
                mapping[0:8] = b"ATTACK!!"
                mapping.flush()
            finally:
                mapping.close()
        finally:
            os.close(fd)
    finally:
        sealed_fs._verify_install = real_verify
        shutil.rmtree(root, ignore_errors=True)


def test_install_sealed_refuses_inwindow_mapping_acquisition():
    # A1M7-1: a chmod+mmap+restore between publication and
    # the installer's snapshot must refuse: the snapshot
    # would otherwise bless a mapped inode whose later
    # flips leave no inotify event and no ctime move.
    # (Under the A1M9-1 lease the acquisition itself is
    # excluded, so the attempt degrades to a chmod-only
    # touch the post-link drain still refuses.)
    import errno as _errno
    import mmap as _mmap

    root, _identity = _owned_dir()
    real_verify = sealed_fs._verify_install
    held = []
    fired = []

    def _attacking_verify(dirfd, name, tmpfd, data):
        if not fired:
            fired.append(True)
            path = os.path.join(root, name)
            before = os.stat(path)
            os.chmod(path, 0o644)
            try:
                wfd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
            except OSError as exc:
                if exc.errno != _errno.EWOULDBLOCK:
                    raise
                os.chmod(path, 0o444)
                return real_verify(dirfd, name, tmpfd, data)
            try:
                mapping = _mmap.mmap(
                    wfd, before.st_size,
                    access=_mmap.ACCESS_WRITE,
                )
            except BaseException:
                os.close(wfd)
                raise
            mapping[0:8] = b"ATTACK!!"
            mapping[0:8] = bytes(data[0:8])
            os.fchmod(wfd, 0o444)
            os.utime(
                wfd,
                ns=(before.st_atime_ns, before.st_mtime_ns),
            )
            os.close(wfd)
            held.append(mapping)
        return real_verify(dirfd, name, tmpfd, data)

    sealed_fs._verify_install = _attacking_verify
    try:
        dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(AssertionError):
                sealed_fs.install_sealed(
                    dirfd, "input.bpf.o",
                    b"captured-bytes", 0o444,
                )
        finally:
            os.close(dirfd)
    finally:
        sealed_fs._verify_install = real_verify
    assert fired, "verify seam never fired"
    if held:
        # The retained mapping still writes: without the
        # refusal the blessed inode stays attacker-writable
        # (absent under the lease, which excludes the
        # acquisition itself).
        held[0][0:8] = b"ATTACK!!"
        held[0][0:8] = b"captured"
        held[0].close()
    shutil.rmtree(root, ignore_errors=True)


def _attack_through_alias(root, alias_dir, name, data, held):
    # A1M8-1 adversary: expose the published inode under an
    # A1M8-1 adversary: expose the published inode under an
    # alias, acquire + prime + restore through it, then drop
    # the alias. Directory notifications follow the alias
    # used, so a name-restricted gate never sees the chmod.
    import errno as _errno
    import mmap as _mmap

    path = os.path.join(root, name)
    alias = os.path.join(alias_dir, "alias-%d" % len(held))
    before = os.stat(path)
    os.link(path, alias)
    os.chmod(alias, 0o644)
    try:
        wfd = os.open(alias, os.O_RDWR | os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno != _errno.EWOULDBLOCK:
            raise
        # The install lease excluded the acquisition
        # (A1M9-1): restore and let the drains refuse
        # the alias touch.
        os.chmod(alias, 0o444)
        os.unlink(alias)
        return
    try:
        mapping = _mmap.mmap(
            wfd, before.st_size, access=_mmap.ACCESS_WRITE,
        )
    except BaseException:
        os.close(wfd)
        raise
    mapping[0:8] = b"ATTACK!!"
    mapping[0:8] = bytes(data[0:8])
    os.fchmod(wfd, 0o444)
    os.utime(wfd, ns=(before.st_atime_ns, before.st_mtime_ns))
    os.close(wfd)
    os.unlink(alias)
    held.append(mapping)


def test_install_sealed_refuses_inwindow_alias_mapping(tmp_path):
    # A1M8-1: the same acquire-prime-restore through a
    # same-directory hard-link alias must refuse: the
    # alias's chmod/mmap/unlink never name the handed
    # entry, so only the backing inode's own events can
    # catch it.
    root, _identity = _owned_dir()
    real_verify = sealed_fs._verify_install
    held = []
    fired = []

    def _attacking_verify(dirfd, name, tmpfd, data):
        if not fired:
            fired.append(True)
            _attack_through_alias(root, root, name, data, held)
        return real_verify(dirfd, name, tmpfd, data)

    sealed_fs._verify_install = _attacking_verify
    try:
        dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(AssertionError):
                sealed_fs.install_sealed(
                    dirfd, "input.bpf.o",
                    b"captured-bytes", 0o444,
                )
        finally:
            os.close(dirfd)
    finally:
        sealed_fs._verify_install = real_verify
    assert fired, "verify seam never fired"
    if held:
        held[0][0:8] = b"ATTACK!!"
        held[0][0:8] = b"captured"
        held[0].close()
    shutil.rmtree(root, ignore_errors=True)


def test_install_sealed_refuses_inwindow_foreign_alias(tmp_path):
    # A1M8-1: an alias outside the watched directory leaves
    # no directory event at all; the inode gate must still
    # refuse the acquisition.
    root, _identity = _owned_dir()
    outside = str(tmp_path / "foreign")
    os.mkdir(outside)
    real_verify = sealed_fs._verify_install
    held = []
    fired = []

    def _attacking_verify(dirfd, name, tmpfd, data):
        if not fired:
            fired.append(True)
            _attack_through_alias(
                root, outside, name, data, held
            )
        return real_verify(dirfd, name, tmpfd, data)

    sealed_fs._verify_install = _attacking_verify
    try:
        dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(AssertionError):
                sealed_fs.install_sealed(
                    dirfd, "input.bpf.o",
                    b"captured-bytes", 0o444,
                )
        finally:
            os.close(dirfd)
    finally:
        sealed_fs._verify_install = real_verify
    assert fired, "verify seam never fired"
    if held:
        held[0][0:8] = b"ATTACK!!"
        held[0][0:8] = b"captured"
        held[0].close()
    shutil.rmtree(root, ignore_errors=True)


def test_install_sealed_refuses_break_tainted_handoff():
    # A1M9-1/P1: a nonblocking writer-acquire attempt
    # inside the link-to-drain gap fails EWOULDBLOCK
    # on the install lease AND taints the handoff: the
    # break is initiated despite the refusal, so the
    # install refuses at its final lease check even
    # though mode and bytes are fully restored.
    import errno as _errno

    root, _identity = _owned_dir()
    real_link = sealed_fs._link_tmpfile
    observed = []

    def _probing_link(tmpfd, dirfd, name):
        out = real_link(tmpfd, dirfd, name)
        if not observed:
            # Through an alias, so the drains stay
            # clean and only the final lease check can
            # refuse: the EWOULDBLOCK attempt initiates
            # the break it reports.
            path = os.path.join(root, name)
            alias = os.path.join(root, "alias-probe")
            os.link(path, alias)
            os.chmod(alias, 0o644)
            try:
                wfd = os.open(alias, os.O_RDWR | os.O_NONBLOCK)
            except OSError as exc:
                observed.append(exc.errno)
            else:
                observed.append("opened")
                os.close(wfd)
            os.chmod(alias, 0o444)
            os.unlink(alias)
        return out

    sealed_fs._link_tmpfile = _probing_link
    try:
        dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(AssertionError):
                sealed_fs.install_sealed(
                    dirfd, "input.bpf.o",
                    b"captured-bytes", 0o444,
                )
        finally:
            os.close(dirfd)
    finally:
        sealed_fs._link_tmpfile = real_link
    assert observed == [_errno.EWOULDBLOCK], observed
    shutil.rmtree(root, ignore_errors=True)


def test_install_sealed_refuses_revoked_lease_acquisition():
    # A1M9-1/P2: simulates kernel revocation after an
    # adversarial pause (SIGSTOP + lease-break-time):
    # the lease is released before a full pre-D1
    # alias/mmap/restore schedule, which then runs to
    # completion with restored bytes and mode. The
    # install still refuses: the final lease check
    # reports loss instead of the held lease.
    import fcntl as _fcntl
    import mmap as _mmap

    root, _identity = _owned_dir()
    real_link = sealed_fs._link_tmpfile
    held = []

    def _revoking_link(tmpfd, dirfd, name):
        import errno as _errno

        out = real_link(tmpfd, dirfd, name)
        if not held:
            # Simulated forced revocation of the
            # installer's lease (F_SETLEASE=1024 and
            # F_UNLCK=2 are stable Linux ABI; EAGAIN
            # means no lease was held at all).
            try:
                _fcntl.fcntl(tmpfd, 1024, 2)
            except OSError as exc:
                if exc.errno != _errno.EAGAIN:
                    raise
            path = os.path.join(root, name)
            alias = os.path.join(root, "alias-revoked")
            before = os.stat(path)
            with open(path, "rb") as handle:
                original = handle.read()
            os.link(path, alias)
            os.chmod(alias, 0o644)
            try:
                probe = os.open(alias, os.O_RDWR | os.O_NONBLOCK)
            except OSError as exc:
                if exc.errno == _errno.EWOULDBLOCK:
                    raise AssertionError(
                        "revocation did not release the lease"
                    )
                raise
            # Retained: closing a writable fd would fire
            # close-write and taint the drains itself.
            held.append(probe)
            wfd = os.open(alias, os.O_RDWR)
            mapping = _mmap.mmap(
                wfd, before.st_size,
                access=_mmap.ACCESS_WRITE,
            )
            mapping[0:8] = b"ATTACK!!"
            mapping[:] = original
            os.fchmod(wfd, 0o444)
            os.utime(
                wfd,
                ns=(before.st_atime_ns, before.st_mtime_ns),
            )
            os.unlink(alias)
            # Retained open through D2: closing a
            # writable fd would fire close-write (the
            # reviewer's A1M9-1 schedule).
            held.append((wfd, mapping))
        return out

    sealed_fs._link_tmpfile = _revoking_link
    try:
        dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(AssertionError):
                sealed_fs.install_sealed(
                    dirfd, "input.bpf.o",
                    b"captured-bytes", 0o444,
                )
        finally:
            os.close(dirfd)
    finally:
        sealed_fs._link_tmpfile = real_link
    assert len(held) == 2, held
    probe, (wfd, mapping) = held
    mapping.close()
    os.close(wfd)
    os.close(probe)
    shutil.rmtree(root, ignore_errors=True)


def test_install_sealed_clean_install_passes_with_lease():
    # A1M9-1/P3: the attack-free pair: an undisturbed
    # install returns the digest and a sealed snapshot.
    # Guards the boundary against over-refusal.
    import hashlib as _hashlib
    import stat as _stat

    root, _identity = _owned_dir()
    dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        digest, snap = sealed_fs.install_sealed(
            dirfd, "input.bpf.o", b"captured-bytes", 0o444,
        )
    finally:
        os.close(dirfd)
    assert digest == _hashlib.sha256(b"captured-bytes").hexdigest()
    assert _stat.S_ISREG(snap[2]), snap
    assert _stat.S_IMODE(snap[2]) == 0o444, snap
    assert snap[3] == len(b"captured-bytes"), snap
    shutil.rmtree(root, ignore_errors=True)


def test_install_sealed_refuses_unrestored_seal_mode():
    # A1M9-1/SEAL: a chmod left unrestored inside the
    # link-to-drain gap (merged, invisible to the
    # drains) still refuses: the adopted snapshot's
    # mode must equal the requested seal, so no
    # blessed baseline is ever writable.
    root, _identity = _owned_dir()
    real_link = sealed_fs._link_tmpfile
    drifted = []

    def _drifting_link(tmpfd, dirfd, name):
        out = real_link(tmpfd, dirfd, name)
        if not drifted:
            drifted.append(True)
            # Through an alias, so the drains stay
            # clean and only the seal-mode check can
            # refuse the left-writable baseline.
            path = os.path.join(root, name)
            alias = os.path.join(root, "alias-drift")
            os.link(path, alias)
            os.chmod(alias, 0o644)
        return out

    sealed_fs._link_tmpfile = _drifting_link
    try:
        dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(AssertionError, match="seal"):
                sealed_fs.install_sealed(
                    dirfd, "input.bpf.o",
                    b"captured-bytes", 0o444,
                )
        finally:
            os.close(dirfd)
    finally:
        sealed_fs._link_tmpfile = real_link
    assert drifted, "link seam never fired"
    shutil.rmtree(root, ignore_errors=True)


def test_install_sealed_refuses_without_tmpfile():
    # A1M4-1: without unnamed temporaries there is no safe
    # backing; the install fails closed instead of publishing
    # through a pathname-visible writable window.
    root, _identity = _owned_dir()
    real_open = os.open

    def _refusing_open(path, flags, *args, **kwargs):
        if flags & os.O_TMPFILE:
            raise OSError(95, "Operation not supported")
        return real_open(path, flags, *args, **kwargs)

    os.open = _refusing_open
    try:
        dirfd = real_open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(OSError):
                sealed_fs.install_sealed(
                    dirfd, "input.bpf.o", b"captured-bytes", 0o444
                )
        finally:
            os.close(dirfd)
        assert os.listdir(root) == []
    finally:
        os.open = real_open
        shutil.rmtree(root, ignore_errors=True)


def test_open_owned_dir_binds_and_releases():
    root, identity = _owned_dir()
    try:
        fd = sealed_fs.open_owned_dir(root, identity)
        try:
            assert os.fstat(fd).st_ino == identity[1]
        finally:
            os.close(fd)
        # Unbound stand-ins open without a record.
        fd = sealed_fs.open_owned_dir(root, None)
        os.close(fd)
        # A final symlink is never followed.
        link = root + ".link"
        os.symlink(root, link)
        try:
            with pytest.raises(OSError):
                sealed_fs.open_owned_dir(link, identity)
        finally:
            os.unlink(link)
        # A substituted directory refuses.
        relocated = root + ".relocated"
        os.rename(root, relocated)
        try:
            os.mkdir(root)
            with pytest.raises(AssertionError):
                sealed_fs.open_owned_dir(root, identity)
        finally:
            os.rmdir(root)
            os.rename(relocated, root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_rmtree_owned_removes_verified_tree():
    root, identity = _owned_dir()
    try:
        nested = os.path.join(root, "nested")
        os.mkdir(nested)
        with open(os.path.join(nested, "leaf"), "wb") as handle:
            handle.write(b"leaf")
        os.symlink("leaf", os.path.join(nested, "alias"))
        parent = os.path.dirname(root)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            assert sealed_fs.rmtree_owned(
                parent_fd, os.path.basename(root), identity
            ) is True
        finally:
            os.close(parent_fd)
        assert not os.path.lexists(root)
        # Already absent counts as removed, not an error.
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            assert sealed_fs.rmtree_owned(
                parent_fd, os.path.basename(root), identity
            ) is False
        finally:
            os.close(parent_fd)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_rmtree_owned_refuses_foreign_tree():
    # A1M4-2: a substituted directory (and anything planted in
    # it) survives; only the verified identity is removed.
    root, identity = _owned_dir()
    try:
        relocated = root + ".relocated"
        os.rename(root, relocated)
        os.mkdir(root)
        foreign = os.path.join(root, "foreign")
        with open(foreign, "wb") as handle:
            handle.write(b"foreign-bytes")
        parent = os.path.dirname(root)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(AssertionError):
                sealed_fs.rmtree_owned(
                    parent_fd, os.path.basename(root), identity
                )
        finally:
            os.close(parent_fd)
        with open(foreign, "rb") as handle:
            assert handle.read() == b"foreign-bytes"
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(relocated, ignore_errors=True)


def test_rmtree_owned_refuses_child_substituted_after_stat():
    # A1M5-2: a child substituted between its stat and its
    # open must not have foreign contents deleted: the
    # opened child is verified against the observed
    # identity, and the original survives with its content.
    root, identity = _owned_dir()
    real_stat = os.stat
    swapped = []
    realroot = os.path.realpath(root)
    try:
        sub = os.path.join(root, "sub")
        os.mkdir(sub)
        with open(os.path.join(sub, "owned"), "wb") as handle:
            handle.write(b"owned-bytes")

        def _swapping_stat(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            dirfd = kwargs.get("dir_fd")
            if (
                not swapped and path == "sub"
                and isinstance(dirfd, int)
            ):
                try:
                    parent = os.readlink(
                        "/proc/self/fd/%d" % dirfd
                    )
                except OSError:
                    parent = None
                if (
                    parent is not None
                    and os.path.realpath(parent) == realroot
                ):
                    swapped.append(True)
                    outside = root + ".relocated-sub"
                    os.rename(sub, outside)
                    os.mkdir(sub)
                    with open(
                        os.path.join(sub, "marker"), "wb"
                    ) as handle:
                        handle.write(b"marker-bytes")
            return result

        os.stat = _swapping_stat
        parent = os.path.dirname(root)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(AssertionError):
                sealed_fs.rmtree_owned(
                    parent_fd, os.path.basename(root), identity
                )
        finally:
            os.close(parent_fd)
            os.stat = real_stat
        assert swapped, "stat seam never fired"
        with open(
            os.path.join(root + ".relocated-sub", "owned"), "rb"
        ) as handle:
            assert handle.read() == b"owned-bytes"
    finally:
        os.stat = real_stat
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(root + ".relocated", ignore_errors=True)
        shutil.rmtree(root + ".relocated-sub", ignore_errors=True)


def test_rmtree_owned_proves_child_removal_on_held_fd():
    # A1M5-2: a child replaced between clearing and its
    # pathname removal must fail the removal proof on the
    # held descriptor: the rmdir takes the substitute, so
    # the original is still linked and the removal is
    # refused instead of reported.
    root, identity = _owned_dir()
    real_rmdir = os.rmdir
    swapped = []
    realroot = os.path.realpath(root)
    try:
        sub = os.path.join(root, "sub")
        os.mkdir(sub)
        with open(os.path.join(sub, "owned"), "wb") as handle:
            handle.write(b"owned-bytes")

        def _swapping_rmdir(path, *args, **kwargs):
            dirfd = kwargs.get("dir_fd")
            if (
                not swapped and path == "sub"
                and isinstance(dirfd, int)
            ):
                try:
                    parent = os.readlink(
                        "/proc/self/fd/%d" % dirfd
                    )
                except OSError:
                    parent = None
                if (
                    parent is not None
                    and os.path.realpath(parent) == realroot
                ):
                    swapped.append(True)
                    outside = root + ".relocated-sub"
                    os.rename(sub, outside)
                    os.mkdir(sub)
            return real_rmdir(path, *args, **kwargs)

        os.rmdir = _swapping_rmdir
        parent = os.path.dirname(root)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(AssertionError):
                sealed_fs.rmtree_owned(
                    parent_fd, os.path.basename(root), identity
                )
        finally:
            os.close(parent_fd)
            os.rmdir = real_rmdir
        assert swapped, "rmdir seam never fired"
        # The original's contents were cleared before the
        # swap (clear-then-remove); the guarantee is the
        # loud refusal plus the surviving original inode,
        # never a silent report.
        assert os.path.isdir(root + ".relocated-sub"), (
            "original inode did not survive the refusal"
        )
    finally:
        os.rmdir = real_rmdir
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(root + ".relocated", ignore_errors=True)
        shutil.rmtree(root + ".relocated-sub", ignore_errors=True)


def test_rmtree_owned_refuses_link_substituted_before_unlink():
    # A1M6-2: a link swapped for a regular file between its
    # observation and its unlink must not delete the
    # substitute and report clean while the original link
    # survives elsewhere: the link is held through
    # O_PATH|O_NOFOLLOW and proven removed on that handle.
    root, identity = _owned_dir()
    real_stat = os.stat
    swapped = []
    realroot = os.path.realpath(root)
    try:
        target = os.path.join(root, "target")
        with open(target, "wb") as handle:
            handle.write(b"target-bytes")
        link = os.path.join(root, "link")
        os.symlink(target, link)

        def _swapping_stat(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            dirfd = kwargs.get("dir_fd")
            if (
                not swapped and path == "link"
                and isinstance(dirfd, int)
            ):
                try:
                    parent = os.readlink(
                        "/proc/self/fd/%d" % dirfd
                    )
                except OSError:
                    parent = None
                if (
                    parent is not None
                    and os.path.realpath(parent) == realroot
                ):
                    swapped.append(True)
                    os.rename(link, root + ".relocated-link")
                    with open(link, "wb") as handle:
                        handle.write(b"substitute-bytes")
            return result

        os.stat = _swapping_stat
        parent = os.path.dirname(root)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(AssertionError):
                sealed_fs.rmtree_owned(
                    parent_fd, os.path.basename(root), identity
                )
        finally:
            os.close(parent_fd)
            os.stat = real_stat
        assert swapped, "stat seam never fired"
        assert os.path.islink(root + ".relocated-link"), (
            "original link did not survive the refusal"
        )
    finally:
        os.stat = real_stat
        shutil.rmtree(root, ignore_errors=True)
        if os.path.islink(root + ".relocated-link"):
            os.unlink(root + ".relocated-link")
        shutil.rmtree(root + ".relocated", ignore_errors=True)


def test_rmtree_owned_removes_dangling_link():
    # A1M6-2 guard: a legitimate dangling link is still
    # removed cleanly (O_PATH holds it without a target).
    root, identity = _owned_dir()
    try:
        link = os.path.join(root, "dangling")
        os.symlink(os.path.join(root, "absent"), link)
        parent = os.path.dirname(root)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            assert sealed_fs.rmtree_owned(
                parent_fd, os.path.basename(root), identity
            ) is True
        finally:
            os.close(parent_fd)
        assert not os.path.lexists(root)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_snapshot_at_detects_any_touch():
    root, _identity = _owned_dir()
    try:
        path = os.path.join(root, "input.bpf.o")
        with open(path, "wb") as handle:
            handle.write(b"captured-bytes")
        dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            before = sealed_fs.snapshot_at(dirfd, "input.bpf.o")
            assert before is not None
            assert sealed_fs.snapshot_at(dirfd, "missing") is None
            # A plain read changes nothing.
            with open(path, "rb") as handle:
                handle.read()
            assert sealed_fs.snapshot_at(dirfd, "input.bpf.o") == before
            # A write moves the snapshot even when restored.
            with open(path, "wb") as handle:
                handle.write(b"evil-bytes!!")
            with open(path, "wb") as handle:
                handle.write(b"captured-bytes")
            assert sealed_fs.snapshot_at(dirfd, "input.bpf.o") != before
            # A chmod moves the snapshot even with the same mode.
            os.chmod(path, 0o644)
            assert sealed_fs.snapshot_at(dirfd, "input.bpf.o") != before
        finally:
            os.close(dirfd)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_name_watch_reports_change_and_restore():
    root, _identity = _owned_dir()
    try:
        path = os.path.join(root, "input.bpf.o")
        with open(path, "wb") as handle:
            handle.write(b"captured-bytes")
        watch = sealed_fs.NameWatch(root)
        try:
            watch.check(names=["input.bpf.o"])
            os.chmod(path, 0o644)
            with open(path, "wb") as handle:
                handle.write(b"evil-bytes!!")
            with open(path, "wb") as handle:
                handle.write(b"captured-bytes")
            with pytest.raises(OSError):
                watch.check(names=["input.bpf.o"])
        finally:
            watch.close()
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_name_watch_close_is_idempotent():
    # A1M5-3: signal-owned teardown and the exit backstop
    # both close the monitor; a second close must neither
    # raise nor close a recycled descriptor.
    root, _identity = _owned_dir()
    try:
        watch = sealed_fs.NameWatch(root)
        watch.close()
        watch.close()
        probe = os.path.join(root, "probe")
        with open(probe, "wb") as handle:
            handle.write(b"probe-bytes")
        with open(probe, "rb") as handle:
            assert handle.read() == b"probe-bytes"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_name_watch_ignores_unrelated_names():
    root, _identity = _owned_dir()
    try:
        path = os.path.join(root, "input.bpf.o")
        with open(path, "wb") as handle:
            handle.write(b"captured-bytes")
        watch = sealed_fs.NameWatch(root)
        try:
            with open(os.path.join(root, "transcript"), "w") as handle:
                handle.write("guest output")
            watch.check(names=["input.bpf.o"])
        finally:
            watch.close()
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_install_sealed_fstat_failure_closes_reopened_descriptor():
    # A1M10-3: an fstat failure on either the reopened
    # descriptor or the tmpfile closes the reopened
    # descriptor (fault-injection descriptor census).
    for fail_on_call in (1, 2):
        root, _identity = _owned_dir()
        try:
            dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                real_fstat = os.fstat
                calls = []

                def flaky(fd):
                    calls.append(fd)
                    if len(calls) == fail_on_call:
                        raise OSError(5, "injected fstat failure")
                    return real_fstat(fd)

                before = set(os.listdir("/proc/self/fd"))
                os.fstat = flaky
                try:
                    with pytest.raises(OSError):
                        sealed_fs.install_sealed(
                            dirfd, "input.bpf.o", b"x", 0o444
                        )
                finally:
                    os.fstat = real_fstat
                assert calls, "fault never injected"
                leaked = set(os.listdir("/proc/self/fd")) - before
                assert leaked == set(), (
                    "fail_on_call=%d leaked %s"
                    % (fail_on_call, sorted(leaked))
                )
            finally:
                os.close(dirfd)
        finally:
            shutil.rmtree(root, ignore_errors=True)


def _hide_lease_owner_consts():
    # Simulate CPython < 3.13, which does not expose
    # F_SETOWN_EX/F_OWNER_TID (requires-python >= 3.11).
    saved = {}
    for attr in ("F_SETOWN_EX", "F_OWNER_TID"):
        if hasattr(fcntl, attr):
            saved[attr] = getattr(fcntl, attr)
            delattr(fcntl, attr)
    return saved


def _restore_lease_owner_consts(saved):
    for attr, value in saved.items():
        setattr(fcntl, attr, value)


def test_install_sealed_supports_pre_313_lease_ownership():
    # A1M10-2: without the 3.13-only constants, the
    # install falls back to the Linux ABI numerics and
    # the full lease lifecycle still engages (the final
    # F_GETLEASE check would refuse otherwise).
    root, _identity = _owned_dir()
    try:
        dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            saved = _hide_lease_owner_consts()
            try:
                digest, installed = sealed_fs.install_sealed(
                    dirfd, "input.bpf.o", b"fallback-bytes", 0o444
                )
            finally:
                _restore_lease_owner_consts(saved)
            assert digest == hashlib.sha256(b"fallback-bytes").hexdigest()
            current = os.stat(
                os.path.join(root, "input.bpf.o"), follow_symlinks=False
            )
            assert installed[:2] == (current.st_dev, current.st_ino)
        finally:
            os.close(dirfd)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_lease_owner_fallback_matches_exposed_constants():
    # A1M10-2: the fallback numerics must equal the real
    # constants where CPython exposes them (ABI pin).
    if hasattr(fcntl, "F_SETOWN_EX"):
        assert sealed_fs._LINUX_F_SETOWN_EX == fcntl.F_SETOWN_EX
        assert sealed_fs._LINUX_F_OWNER_TID == fcntl.F_OWNER_TID


def test_install_sealed_lease_ownership_unavailable_is_oserror():
    # A1M10-2: without the constants and without the
    # Linux ABI, the install refuses with OSError
    # (classified, like a missing monitor), never
    # AttributeError.
    root, _identity = _owned_dir()
    try:
        dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            saved = _hide_lease_owner_consts()
            real_platform = sys.platform
            sys.platform = "darwin"
            try:
                with pytest.raises(OSError):
                    sealed_fs.install_sealed(
                        dirfd, "input.bpf.o", b"x", 0o444
                    )
            finally:
                sys.platform = real_platform
                _restore_lease_owner_consts(saved)
        finally:
            os.close(dirfd)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _direct_names():
    return sorted(
        name
        for name in globals()
        if name.startswith("test_") and callable(globals()[name])
    )


def _direct_run():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    for name in _direct_names():
        try:
            globals()[name]()
        except Exception:
            failures += 1
            print("FAIL %s" % name)
            import traceback

            traceback.print_exc()
        else:
            print("ok %s" % name)
    print("%d tests, %d failures" % (len(_direct_names()), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_direct_run())
