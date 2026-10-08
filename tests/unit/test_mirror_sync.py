# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Fast auto-check: packaged adapter copies mirror ``compiler/``.

No wheel build: the wheel contract
(``tests/packaging/test_wheel_contents.py``) re-checks the same
table against the built wheel. Toolchain-independent, standard
library only.
"""

import os
import shutil
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "tests", "harness"))

import mirror_sync


def _fake_root(drift_audit=False, drop_service=False):
    root = tempfile.mkdtemp(prefix="mirror-sync-")
    pairs = []
    for shipped, source in mirror_sync.SYNCED_FILES:
        src_path = os.path.join(root, source)
        os.makedirs(os.path.dirname(src_path), exist_ok=True)
        with open(src_path, "wb") as handle:
            handle.write(b"# source %s\n" % source.encode())
        dst_path = mirror_sync.packaged_path(root, shipped)
        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
        body = b"# source %s\n" % source.encode()
        if drift_audit and source == "compiler/audit.py":
            body += b"# drift\n"
        if drop_service and source == "compiler/adapter_service.py":
            pairs.append((src_path, None))
            continue
        with open(dst_path, "wb") as handle:
            handle.write(body)
        pairs.append((src_path, dst_path))
    return root, pairs


def test_committed_tree_in_sync():
    assert mirror_sync.check_tree_mirrors(REPO_ROOT) == 3
    print("PASS committed tree in sync")


def test_drift_refused():
    root, _ = _fake_root(drift_audit=True)
    try:
        try:
            mirror_sync.check_tree_mirrors(root)
        except mirror_sync.MirrorDriftError as exc:
            assert "audit.py" in str(exc), str(exc)
            print("PASS drift refused")
        else:
            raise AssertionError("drifted audit copy must be refused")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_missing_copy_refused():
    root, _ = _fake_root(drop_service=True)
    try:
        try:
            mirror_sync.check_tree_mirrors(root)
        except mirror_sync.MirrorDriftError as exc:
            assert "adapter_service.py" in str(exc), str(exc)
            print("PASS missing copy refused")
        else:
            raise AssertionError("missing packaged copy must be refused")
    finally:
        shutil.rmtree(root, ignore_errors=True)


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
    print("mirror sync: 3 checks pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
