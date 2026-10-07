# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the VM matrix runner's suite discipline.

Pins ``ci/run_vm_tests.py`` verdicts against fake suites: a quick
pass, and a timeout that must kill the whole suite process group
(child and grandchild) while still reporting ``timeout``. Nothing
here boots a guest: the live matrix runs in CI.

Deterministic on any host: only the standard library plus pytest's
plain function collection.

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3
tests/unit/test_matrix_runner.py``).
"""

import importlib.util
import os
import shutil
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)


def _load_runner():
    spec = importlib.util.spec_from_file_location(
        "matrix_runner",
        os.path.join(REPO_ROOT, "ci", "run_vm_tests.py"),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_FAKE_PASS = """\
import sys
print("PASS fake-suite-proof")
sys.exit(0)
"""

_FAKE_SLEEPER = """\
import os
import subprocess
import sys
import time
child = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(300)"]
)
with open(os.environ["MOJOBPF_FAKE_PIDFILE"], "w") as handle:
    handle.write(str(child.pid))
time.sleep(300)
"""

_LANE = {"id": "test-lane", "release": "v9.99"}


def _run_fake(runner, source, timeout, extra_env=None):
    root = tempfile.mkdtemp(prefix="mojobpf-matrix-unit-")
    out_dir = os.path.join(root, "out")
    os.makedirs(out_dir)
    suite_path = os.path.join(root, "fake_suite.py")
    with open(suite_path, "w", encoding="utf-8") as handle:
        handle.write(source)
    saved_root = runner.REPO_ROOT
    saved_env = dict(os.environ)
    runner.REPO_ROOT = root
    try:
        if extra_env:
            os.environ.update(extra_env)
        record = runner.run_suite(
            "fake-suite", "fake_suite.py", _LANE, out_dir,
            timeout, "unit-test-commit", None,
        )
    finally:
        runner.REPO_ROOT = saved_root
        os.environ.clear()
        os.environ.update(saved_env)
    return root, out_dir, record


def _pid_dead(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    try:
        with open("/proc/%d/stat" % pid, "r", encoding="utf-8") as handle:
            state = handle.read().rsplit(")", 1)[1].split()[0]
    except OSError:
        return True
    return state in ("Z", "X")


def test_quick_suite_passes():
    runner = _load_runner()
    root, out_dir, record = _run_fake(runner, _FAKE_PASS, 120)
    try:
        assert record["outcome"] == "pass", record
        assert record["exit_code"] == 0, record
        assert record["passes"] == 1, record
        assert record["failures"] == 0, record
        assert record["timed_out"] is False, record
        assert record["commit"] == "unit-test-commit", record
        assert os.path.isfile(
            os.path.join(out_dir, "test-lane.fake-suite.log")
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_timeout_kills_the_whole_suite_group():
    runner = _load_runner()
    scratch = tempfile.mkdtemp(prefix="mojobpf-matrix-pid-")
    pidfile = os.path.join(scratch, "grandchild.pid")
    try:
        root, _out, record = _run_fake(
            runner, _FAKE_SLEEPER, 5,
            extra_env={"MOJOBPF_FAKE_PIDFILE": pidfile},
        )
        try:
            assert record["outcome"] == "timeout", record
            assert record["timed_out"] is True, record
            assert record["exit_code"] is None, record
            with open(record["log"], "r", encoding="utf-8") as handle:
                assert "MATRIX TIMEOUT after 5s" in handle.read()
            with open(pidfile, "r", encoding="utf-8") as handle:
                grandchild = int(handle.read().strip())
            deadline = time.monotonic() + 15
            while not _pid_dead(grandchild):
                assert time.monotonic() < deadline, (
                    "grandchild %d survived the suite timeout"
                    % grandchild
                )
                time.sleep(0.2)
        finally:
            shutil.rmtree(root, ignore_errors=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _direct_names():
    return sorted(
        name
        for name in globals()
        if name.startswith("test_") and callable(globals()[name])
    )


def _direct_run():
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
