# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Controls for descriptor-bound sealed staging (A1M4-1/A1M4-2)."""

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
            digest = sealed_fs.install_sealed(
                dirfd, "input.bpf.o", b"captured-bytes", 0o444
            )
        finally:
            os.close(dirfd)
        assert digest == hashlib.sha256(b"captured-bytes").hexdigest()
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
