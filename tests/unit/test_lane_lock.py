# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the supra-level lane-lock helper (no guests)."""

import json
import os
import shutil
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "tests", "harness"))

import lane_lock


def write_lock(directory, name, lanes):
    path = os.path.join(directory, "ci")
    os.makedirs(path, exist_ok=True)
    lock_path = os.path.join(path, name)
    with open(lock_path, "w", encoding="utf-8") as handle:
        json.dump({"lanes": lanes}, handle)
    return lock_path


def test_exact_release_accepted():
    root = tempfile.mkdtemp(prefix="lane-lock-")
    try:
        write_lock(root, "kernels.lock.json", [
            {"id": "v6.12-tcg", "release": "v6.12",
             "kernel_release": "6.12.0-061200-generic",
             "kernel_debs": []},
        ])
        assert lane_lock.expected_kernel_release(root, "v6.12") == (
            "6.12.0-061200-generic"
        )
        assert lane_lock.check_booted_kernel(
            "6.12.0-061200-generic", root, "v6.12"
        ) == "6.12.0-061200-generic"
        print("PASS exact release accepted")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_sibling_release_refused():
    # The -64k sibling passes a "6.12" prefix check; the lock refuses it.
    root = tempfile.mkdtemp(prefix="lane-lock-")
    try:
        write_lock(root, "kernels.lock.json", [
            {"id": "v6.12-tcg", "release": "v6.12",
             "kernel_release": "6.12.0-061200-generic",
             "kernel_debs": []},
        ])
        sibling = "6.12.0-061200-generic-64k"
        assert sibling.startswith("6.12"), "prefix control must pass"
        try:
            lane_lock.check_booted_kernel(sibling, root, "v6.12")
        except lane_lock.LaneLockError:
            print("PASS sibling release refused")
        else:
            raise AssertionError("sibling kernel must be refused")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_missing_lane_fails():
    root = tempfile.mkdtemp(prefix="lane-lock-")
    try:
        write_lock(root, "kernels.lock.json", [
            {"id": "v6.12-tcg", "release": "v6.12",
             "kernel_release": "6.12.0-061200-generic",
             "kernel_debs": []},
        ])
        try:
            lane_lock.expected_kernel_release(root, "v9.99")
        except lane_lock.LaneLockError as exc:
            assert "v6.12" in str(exc), str(exc)
            print("PASS missing lane fails")
        else:
            raise AssertionError("missing lane must fail, never skip")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_missing_lockfile_fails():
    root = tempfile.mkdtemp(prefix="lane-lock-")
    try:
        try:
            lane_lock.expected_kernel_release(root, "v6.12")
        except lane_lock.LaneLockError:
            print("PASS missing lockfile fails")
        else:
            raise AssertionError("missing lockfile must fail")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_missing_kernel_line_fails():
    try:
        lane_lock.booted_kernel_from_output("no kernel here\n")
    except lane_lock.LaneLockError:
        print("PASS missing kernel line fails")
    else:
        raise AssertionError("missing guest-kernel line must fail")


def test_last_kernel_line_wins():
    assert lane_lock.booted_kernel_from_output(
        "guest-kernel: 6.6.0-060600-generic\n"
        "guest-kernel: 6.12.0-061200-generic\n"
    ) == "6.12.0-061200-generic"
    print("PASS last kernel line wins")


def test_arm64_lock_selected():
    root = tempfile.mkdtemp(prefix="lane-lock-")
    try:
        write_lock(root, "kernels.lock.json", [
            {"id": "v6.12-tcg", "release": "v6.12",
             "kernel_release": "6.12.0-061200-generic",
             "kernel_debs": []},
        ])
        write_lock(root, "kernels.arm64.lock.json", [
            {"id": "v6.12-arm64-tcg", "release": "v6.12",
             "arch": "arm64",
             "kernel_release": "6.12.0-061200-generic",
             "kernel_debs": []},
        ])
        lane = lane_lock.lane_for_release(root, "v6.12", "arm64")
        assert lane["id"] == "v6.12-arm64-tcg", lane
        print("PASS arm64 lock selected")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_cache_hash_mismatch_fails():
    root = tempfile.mkdtemp(prefix="lane-lock-")
    home = tempfile.mkdtemp(prefix="lane-home-")
    try:
        cache = os.path.join(home, ".cache", "virtme-ng", "v9.99")
        os.makedirs(os.path.join(cache, "amd64"))
        deb = os.path.join(cache, "amd64", "kernel-amd64.deb")
        with open(deb, "wb") as handle:
            handle.write(b"tampered")
        write_lock(root, "kernels.lock.json", [
            {"id": "v9.99-tcg", "release": "v9.99",
             "kernel_release": "9.99.0-x",
             "kernel_debs": [{"file": "kernel-amd64.deb",
                              "sha256": "0" * 64}]},
        ])
        old_home = os.environ.get("HOME")
        os.environ["HOME"] = home
        try:
            try:
                lane_lock.check_kernel_cache(root, "v9.99")
            except lane_lock.LaneLockError as exc:
                assert "hash mismatch" in str(exc), str(exc)
                print("PASS cache hash mismatch fails")
            else:
                raise AssertionError("tampered cache must fail")
        finally:
            if old_home is None:
                del os.environ["HOME"]
            else:
                os.environ["HOME"] = old_home
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(home, ignore_errors=True)


def test_cache_ambiguous_basename_fails():
    root = tempfile.mkdtemp(prefix="lane-lock-")
    home = tempfile.mkdtemp(prefix="lane-home-")
    try:
        for sub in ("amd64", "stale"):
            path = os.path.join(
                home, ".cache", "virtme-ng", "v9.99", sub
            )
            os.makedirs(path)
            with open(os.path.join(path, "kernel-amd64.deb"), "wb") as h:
                h.write(b"bytes")
        write_lock(root, "kernels.lock.json", [
            {"id": "v9.99-tcg", "release": "v9.99",
             "kernel_release": "9.99.0-x",
             "kernel_debs": [{"file": "kernel-amd64.deb",
                              "sha256": "0" * 64}]},
        ])
        old_home = os.environ.get("HOME")
        os.environ["HOME"] = home
        try:
            try:
                lane_lock.check_kernel_cache(root, "v9.99")
            except lane_lock.LaneLockError as exc:
                assert "ambiguous" in str(exc), str(exc)
                print("PASS cache ambiguous basename fails")
            else:
                raise AssertionError("ambiguous cache must fail")
        finally:
            if old_home is None:
                del os.environ["HOME"]
            else:
                os.environ["HOME"] = old_home
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(home, ignore_errors=True)


def test_guest_root_codename_checked():
    root = tempfile.mkdtemp(prefix="lane-lock-")
    stage = tempfile.mkdtemp(prefix="lane-root-")
    try:
        write_lock(root, "kernels.arm64.lock.json", [
            {"id": "v9.99-arm64-tcg", "release": "v9.99",
             "arch": "arm64",
             "kernel_release": "9.99.0-x",
             "kernel_debs": [],
             "rootfs": {"image": "img.tar.xz", "release": "resolute",
                        "bytes": 4, "sha256": "0" * 64}},
        ])
        guest = os.path.join(stage, "guest")
        os.makedirs(os.path.join(guest, "etc"))
        with open(os.path.join(guest, "etc", "os-release"), "w") as h:
            h.write('NAME="Ubuntu"\nVERSION_CODENAME=noble\n')
        try:
            lane_lock.check_guest_root(guest, root, "v9.99", "arm64")
        except lane_lock.LaneLockError as exc:
            assert "noble" in str(exc) and "resolute" in str(exc), str(exc)
            print("PASS guest root codename checked")
        else:
            raise AssertionError("wrong root codename must fail")
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(stage, ignore_errors=True)


def test_guest_root_absent_without_pin():
    root = tempfile.mkdtemp(prefix="lane-lock-")
    try:
        write_lock(root, "kernels.lock.json", [
            {"id": "v6.12-tcg", "release": "v6.12",
             "kernel_release": "6.12.0-061200-generic",
             "kernel_debs": []},
        ])
        assert lane_lock.check_guest_root(
            "/nonexistent", root, "v6.12"
        ) is None
        print("PASS guest root skipped without pin")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_real_locks_resolve():
    assert lane_lock.expected_kernel_release(
        REPO_ROOT, "v6.12"
    ) == "6.12.0-061200-generic"
    assert lane_lock.expected_kernel_release(
        REPO_ROOT, "v6.6"
    ) == "6.6.0-060600-generic"
    assert lane_lock.expected_kernel_release(
        REPO_ROOT, "v6.12", "arm64"
    ) == "6.12.0-061200-generic"
    print("PASS real locks resolve")


def test_real_cache_verifies():
    summary = lane_lock.check_kernel_cache(REPO_ROOT, "v6.12")
    assert "linux-image-unsigned-6.12.0-061200-generic" in " ".join(
        summary["debs"]
    ), summary["debs"]
    print("PASS real cache verifies")


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    for name, func in sorted(
        [(k, v) for k, v in globals().items() if k.startswith("test_")]
    ):
        try:
            func()
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
    if failures:
        return 1
    print("lane lock: 13 unit checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
