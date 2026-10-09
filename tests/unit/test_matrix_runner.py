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
import subprocess
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

_FAKE_MIXED_EXIT_ZERO = """\
import sys
print("PASS fake-one")
print("FAIL fake-two: boom")
sys.exit(0)
"""

_FAKE_ENVLINE_EXIT_ZERO = """\
import sys
print("PASS fake-one")
print("ENVIRONMENT FAILURE in fake-two: boom")
sys.exit(0)
"""

_FAKE_ENV_DUMP = """\
import os
import sys
print("PATH=" + os.environ.get("PATH", ""))
print("PYTHONPATH=" + os.environ.get("PYTHONPATH", "<absent>"))
print("PASS fake-env-proof")
sys.exit(0)
"""

_LANE = {"id": "test-lane", "release": "v9.99"}


def _run_fake(runner, source, timeout, extra_env=None, farm=None):
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
            timeout, "unit-test-commit", None, farm,
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


def test_exit_zero_with_a_counted_failure_is_not_a_pass():
    # A lone PASS must not mask counted FAILs: exit 0 with one
    # PASS and one FAIL line is a failure, not a pass.
    runner = _load_runner()
    root, _out, record = _run_fake(runner, _FAKE_MIXED_EXIT_ZERO, 120)
    try:
        assert record["exit_code"] == 0, record
        assert record["passes"] == 1, record
        assert record["failures"] == 1, record
        assert record["outcome"] == "fail", record
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_exit_zero_with_an_environment_line_is_not_a_pass():
    # Likewise an ENVIRONMENT FAILURE line with exit 0 and a PASS
    # reports envfail, never pass.
    runner = _load_runner()
    root, _out, record = _run_fake(runner, _FAKE_ENVLINE_EXIT_ZERO, 120)
    try:
        assert record["exit_code"] == 0, record
        assert record["passes"] == 1, record
        assert record["envfailures"] == 1, record
        assert record["outcome"] == "envfail", record
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_interrupt_reaps_the_suite_tree():
    # An interruption during the suite run reaps the whole owned
    # suite tree (child and grandchild) and propagates.
    runner = _load_runner()
    scratch = tempfile.mkdtemp(prefix="mojobpf-matrix-ki-")
    pidfile = os.path.join(scratch, "grandchild.pid")
    real_popen = subprocess.Popen

    class _InterruptOnce(real_popen):
        def communicate(self, *args, **kwargs):
            deadline = time.monotonic() + 15
            while not os.path.isfile(pidfile):
                if time.monotonic() > deadline:
                    raise AssertionError(
                        "sleeper never wrote its pidfile"
                    )
                time.sleep(0.1)
            raise KeyboardInterrupt

    root = tempfile.mkdtemp(prefix="mojobpf-matrix-unit-")
    out_dir = os.path.join(root, "out")
    os.makedirs(out_dir)
    suite_path = os.path.join(root, "fake_suite.py")
    with open(suite_path, "w", encoding="utf-8") as handle:
        handle.write(_FAKE_SLEEPER)
    saved_root = runner.REPO_ROOT
    saved_env = dict(os.environ)
    runner.REPO_ROOT = root
    os.environ["MOJOBPF_FAKE_PIDFILE"] = pidfile
    subprocess.Popen = _InterruptOnce
    try:
        try:
            runner.run_suite(
                "fake-suite", "fake_suite.py", _LANE, out_dir,
                120, "unit-test-commit", None,
            )
        except KeyboardInterrupt:
            pass
        else:
            raise AssertionError(
                "run_suite swallowed the interruption"
            )
        with open(pidfile, "r", encoding="utf-8") as handle:
            grandchild = int(handle.read().strip())
        deadline = time.monotonic() + 15
        while not _pid_dead(grandchild):
            assert time.monotonic() < deadline, (
                "grandchild %d survived the interruption"
                % grandchild
            )
            time.sleep(0.2)
    finally:
        subprocess.Popen = real_popen
        runner.REPO_ROOT = saved_root
        os.environ.clear()
        os.environ.update(saved_env)
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def _lane(lane_id="vX-tcg", release="v9.99", accelerator="tcg",
          debs=("a.deb",), argv=None):
    return {
        "id": lane_id,
        "release": release,
        "accelerator": accelerator,
        "kernel_release": "9.99-test",
        "kernel_debs": [
            {"file": name, "sha256": "0" * 64} for name in debs
        ],
        "vng_argv_prefix": (
            argv if argv is not None
            else ["vng", "--run", release, "--disable-kvm"]
        ),
    }


def _lock(lanes, qemu="QEMU test", runner_extra=None):
    runner = {
        "name": "vng",
        "version": "v",
        "sha256": "s",
        "qemu": qemu,
    }
    if runner_extra:
        runner.update(runner_extra)
    return {"schema_version": 1, "runner": runner, "lanes": lanes}


def _load_lock_text(runner, lock):
    import json

    root = tempfile.mkdtemp(prefix="mojobpf-lock-unit-")
    path = os.path.join(root, "lock.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(lock, handle)
    try:
        return runner.load_lock(path)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _assert_setup_failure(func, *args):
    try:
        func(*args)
    except Exception as exc:
        assert type(exc).__name__ == "SetupFailure", exc
        return str(exc)
    raise AssertionError("expected SetupFailure, call passed")


def test_load_lock_accepts_the_committed_lock():
    runner = _load_runner()
    lock = runner.load_lock(
        os.path.join(REPO_ROOT, "ci", "kernels.lock.json")
    )
    assert [lane["id"] for lane in lock["lanes"]] == [
        "v6.12-tcg", "v6.6-tcg",
    ]


def test_load_lock_rejects_duplicate_lane_ids():
    runner = _load_runner()
    lock = _lock([
        _lane(lane_id="dup", release="v9.1"),
        _lane(lane_id="dup", release="v9.2"),
    ])
    message = _assert_setup_failure(_load_lock_text, runner, lock)
    assert "duplicate lane id" in message, message


def test_load_lock_rejects_empty_kernel_debs():
    runner = _load_runner()
    lock = _lock([
        _lane(lane_id="a", release="v9.1", debs=()),
        _lane(lane_id="b", release="v9.2"),
    ])
    message = _assert_setup_failure(_load_lock_text, runner, lock)
    assert "no kernel debs" in message, message


def test_load_lock_rejects_deb_without_file_or_hash():
    runner = _load_runner()
    lane = _lane(lane_id="a", release="v9.1")
    lane["kernel_debs"] = [{"file": "a.deb"}]
    lock = _lock([lane, _lane(lane_id="b", release="v9.2")])
    message = _assert_setup_failure(_load_lock_text, runner, lock)
    assert "without file+sha256" in message, message


def test_load_lock_rejects_accelerator_argv_mismatch():
    runner = _load_runner()
    lane = _lane(lane_id="a", release="v9.1")
    lane["vng_argv_prefix"] = ["vng", "--run", "v9.1"]
    lock = _lock([lane, _lane(lane_id="b", release="v9.2")])
    message = _assert_setup_failure(_load_lock_text, runner, lock)
    assert "accelerator" in message, message
    lane = _lane(
        lane_id="a", release="v9.1", accelerator="kvm",
        argv=["vng", "--run", "v9.1", "--disable-kvm"],
    )
    lock = _lock([lane, _lane(lane_id="b", release="v9.2")])
    message = _assert_setup_failure(_load_lock_text, runner, lock)
    assert "accelerator" in message, message


def test_load_lock_requires_the_qemu_pin():
    runner = _load_runner()
    lock = _lock(
        [_lane(lane_id="a", release="v9.1"),
         _lane(lane_id="b", release="v9.2")],
        qemu="",
    )
    message = _assert_setup_failure(_load_lock_text, runner, lock)
    assert "runner lacks qemu" in message, message


def test_qemu_binary_selection():
    runner = _load_runner()
    lanes = [
        _lane(lane_id="a", release="v9.1"),
        _lane(lane_id="b", release="v9.2"),
    ]
    assert runner.qemu_binary_for_lock(_lock(lanes)) == (
        "qemu-system-x86_64"
    )
    assert runner.qemu_binary_for_lock(
        _lock(lanes, runner_extra={"qemu_binary": "custom-qemu"})
    ) == "custom-qemu"
    arch_lanes = [dict(lane, arch="arm64") for lane in lanes]
    assert runner.qemu_binary_for_lock(
        _lock(arch_lanes)
    ) == "qemu-system-aarch64"
    mixed = [lanes[0], dict(lanes[1], arch="arm64")]
    message = _assert_setup_failure(
        runner.qemu_binary_for_lock, _lock(mixed)
    )
    assert "mixed-arch" in message, message


def _write_stub_qemu(directory, name, version_line):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            "#!/bin/sh\necho '%s'\n" % version_line
        )
    os.chmod(path, 0o755)
    return path


def _sha256_of(path):
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def test_check_qemu_matches_and_mismatches():
    runner = _load_runner()
    root = tempfile.mkdtemp(prefix="mojobpf-qemu-unit-")
    saved_path = os.environ.get("PATH", "")
    try:
        stub = _write_stub_qemu(root, "stub-qemu", "QEMU stub 1.0")
        os.environ["PATH"] = root + os.pathsep + saved_path
        lanes = [
            _lane(lane_id="a", release="v9.1"),
            _lane(lane_id="b", release="v9.2"),
        ]
        record = runner.check_qemu(
            _lock(
                lanes, qemu="QEMU stub 1.0",
                runner_extra={
                    "qemu_binary": "stub-qemu",
                    "qemu_sha256": _sha256_of(stub),
                },
            )
        )
        assert record["binary"] == "stub-qemu", record
        assert record["version"] == "QEMU stub 1.0", record
        assert record["sha256"] == _sha256_of(stub), record
        message = _assert_setup_failure(
            runner.check_qemu,
            _lock(
                lanes, qemu="QEMU stub 2.0",
                runner_extra={
                    "qemu_binary": "stub-qemu",
                    "qemu_sha256": _sha256_of(stub),
                },
            ),
        )
        assert "admission refused" in message, message
        message = _assert_setup_failure(
            runner.check_qemu,
            _lock(
                lanes, qemu="QEMU stub 1.0",
                runner_extra={"qemu_binary": "stub-qemu-missing"},
            ),
        )
        assert "qemu_sha256" in message, message
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(root, ignore_errors=True)


def test_check_qemu_rejects_unrelated_same_version_binary():
    # F-041 scratch reproducer, preserved: an unrelated binary
    # printing the locked version string is refused by hash
    # before any probe, leaving no execution marker.
    runner = _load_runner()
    root = tempfile.mkdtemp(prefix="mojobpf-qemu-evil-")
    saved_path = os.environ.get("PATH", "")
    marker = os.path.join(root, "EXECUTED.marker")
    try:
        stub = _write_stub_qemu(root, "stub-qemu", "QEMU stub 1.0")
        pinned = _sha256_of(stub)
        with open(stub, "w", encoding="utf-8") as handle:
            handle.write(
                "#!/bin/sh\ntouch '%s'\necho 'QEMU stub 1.0'\n" % marker
            )
        os.environ["PATH"] = root + os.pathsep + saved_path
        lanes = [
            _lane(lane_id="a", release="v9.1"),
            _lane(lane_id="b", release="v9.2"),
        ]
        message = _assert_setup_failure(
            runner.check_qemu,
            _lock(
                lanes, qemu="QEMU stub 1.0",
                runner_extra={
                    "qemu_binary": "stub-qemu",
                    "qemu_sha256": pinned,
                },
            ),
        )
        assert "admission refused" in message, message
        assert not os.path.exists(marker), "substituted qemu executed"
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(root, ignore_errors=True)


_VNG_FIXTURE_VERSION = "virtme-ng 9.99-fixture"
_QEMU_FIXTURE_VERSION = "QEMU fixture 9.99"
_VIRTME_RUN_FIXTURE_LINE = "virtme-run fixture 9.99"


def _write_executable(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o755)


def _runner_tree(run_body=None, launcher_body=None):
    """Stage a fixture vng console script, package and emulator.

    Also stages the fixture ``virtme-run`` launcher the runner
    would invoke plus its ``matrix_virtme_pkg`` implementation
    (with a nested ``commands`` subpackage, mirroring the real
    ``virtme.commands.run`` layout).
    """
    root = tempfile.mkdtemp(prefix="mojobpf-runner-unit-")
    pkgdir = os.path.join(root, "pkg")
    package = os.path.join(pkgdir, "matrix_vng_pkg")
    os.makedirs(package)
    with open(os.path.join(package, "__init__.py"), "w") as handle:
        handle.write("")
    if run_body is None:
        run_body = (
            "VERSION = %r\n\ndef main():\n    print(VERSION)\n"
            "    return 0\n" % (_VNG_FIXTURE_VERSION,)
        )
    with open(os.path.join(package, "run.py"), "w") as handle:
        handle.write(run_body)
    entry = os.path.join(root, "vng")
    _write_executable(
        entry,
        "#!%s\nimport sys\nfrom matrix_vng_pkg.run import main\n"
        "if __name__ == '__main__':\n"
        "    if sys.argv[1:] == ['--version']:\n"
        "        print(%r)\n    else:\n        sys.exit(main())\n"
        % (sys.executable, _VNG_FIXTURE_VERSION),
    )
    launcher_package = os.path.join(pkgdir, "matrix_virtme_pkg")
    launcher_commands = os.path.join(launcher_package, "commands")
    os.makedirs(launcher_commands)
    with open(
        os.path.join(launcher_package, "__init__.py"), "w"
    ) as handle:
        handle.write("")
    with open(
        os.path.join(launcher_commands, "__init__.py"), "w"
    ) as handle:
        handle.write("")
    if launcher_body is None:
        launcher_body = (
            "VERSION = %r\n\ndef main():\n    print(VERSION)\n"
            "    return 0\n" % (_VIRTME_RUN_FIXTURE_LINE,)
        )
    with open(
        os.path.join(launcher_commands, "run.py"), "w"
    ) as handle:
        handle.write(launcher_body)
    launcher = os.path.join(root, "virtme-run")
    _write_executable(
        launcher,
        "#!%s\nimport sys\n"
        "from matrix_virtme_pkg.commands.run import main\n"
        "if __name__ == '__main__':\n"
        "    if sys.argv[1:] == ['--help']:\n"
        "        print(%r)\n    else:\n        sys.exit(main())\n"
        % (sys.executable, _VIRTME_RUN_FIXTURE_LINE),
    )
    qemu = os.path.join(root, "matrix-qemu")
    _write_executable(
        qemu, "#!/bin/sh\necho '%s'\n" % _QEMU_FIXTURE_VERSION
    )
    return {
        "root": root,
        "entry": entry,
        "pkgdir": pkgdir,
        "package": package,
        "launcher": launcher,
        "launcher_package": launcher_package,
        "qemu": qemu,
    }


def _pinned_runner_lock(tree):
    lanes = [
        _lane(lane_id="a", release="v9.1"),
        _lane(lane_id="b", release="v9.2"),
    ]
    return _lock(
        lanes, qemu=_QEMU_FIXTURE_VERSION,
        runner_extra={
            "version": _VNG_FIXTURE_VERSION,
            "sha256": _sha256_of(tree["entry"]),
            "exec_sha256": None,
            "interpreter": {
                "sha256": _sha256_of(
                    os.path.realpath(sys.executable)
                ),
            },
            "package": {
                "name": "matrix_vng_pkg",
                "modules": {
                    "matrix_vng_pkg": _sha256_of(
                        os.path.join(tree["package"], "__init__.py")
                    ),
                    "matrix_vng_pkg.run": _sha256_of(
                        os.path.join(tree["package"], "run.py")
                    ),
                },
            },
            "python_path": [tree["pkgdir"]],
            "qemu_binary": "matrix-qemu",
            "qemu_sha256": _sha256_of(tree["qemu"]),
            "qemu_exec_sha256": None,
            "virtme_run_sha256": _sha256_of(tree["launcher"]),
            "virtme_run_exec_sha256": None,
            "virtme_package": {
                "name": "matrix_virtme_pkg",
                "modules": {
                    "matrix_virtme_pkg": _sha256_of(
                        os.path.join(
                            tree["launcher_package"], "__init__.py"
                        )
                    ),
                    "matrix_virtme_pkg.commands": _sha256_of(
                        os.path.join(
                            tree["launcher_package"], "commands",
                            "__init__.py",
                        )
                    ),
                    "matrix_virtme_pkg.commands.run": _sha256_of(
                        os.path.join(
                            tree["launcher_package"], "commands",
                            "run.py",
                        )
                    ),
                },
            },
        },
    )


def test_check_runner_admits_pinned_chain():
    """The fixture runner admits with its launcher, emulator and farm."""
    runner = _load_runner()
    tree = _runner_tree()
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        record = runner.check_runner(
            _pinned_runner_lock(tree), farm_parent=tree["root"]
        )
        try:
            assert record["version"] == _VNG_FIXTURE_VERSION, record
            assert record["sha256"] == _sha256_of(tree["entry"])
            assert record["qemu_version"] == _QEMU_FIXTURE_VERSION
            assert record["virtme_run_version"] == (
                _VIRTME_RUN_FIXTURE_LINE
            ), record
            assert record["virtme_run_sha256"] == _sha256_of(
                tree["launcher"]
            )
            assert record["digest"], record
            farm = record["farm"]
            assert os.path.realpath(
                os.path.join(farm, "vng")
            ) == os.path.realpath(tree["entry"])
            assert os.path.realpath(
                os.path.join(farm, "virtme-run")
            ) == os.path.realpath(tree["launcher"])
            assert os.path.realpath(
                os.path.join(farm, "matrix-qemu")
            ) == os.path.realpath(tree["qemu"])
            report = runner.runner_report(record)
            import json as _json

            _json.dumps(report)
            assert report["admission"]["digest"] == record["digest"]
            assert report["virtme_run_admission"]["digest"] == (
                record["virtme_run_execution"].digest
            )
        finally:
            shutil.rmtree(record["farm"], ignore_errors=True)
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_check_runner_rejects_arbitrary_vng():
    """An arbitrary vng with the locked version is refused
    before any process starts (F-001, matrix half)."""
    runner = _load_runner()
    tree = _runner_tree()
    marker = os.path.join(tree["root"], "EXECUTED.marker")
    saved_path = os.environ.get("PATH", "")
    lock = _pinned_runner_lock(tree)
    _write_executable(
        tree["entry"],
        "#!/bin/sh\ntouch '%s'\necho '%s'\n"
        % (marker, _VNG_FIXTURE_VERSION),
    )
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(
            runner.check_runner, lock
        )
        assert "admission refused" in message, message
        assert not os.path.exists(marker), "substituted vng executed"
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_check_runner_ignores_pythonpath_shadow():
    """An ambient PYTHONPATH shadow of the runner package is
    never imported (N-3, matrix half)."""
    runner = _load_runner()
    tree = _runner_tree()
    marker = os.path.join(tree["root"], "EXECUTED.marker")
    shadow = os.path.join(tree["root"], "shadow", "matrix_vng_pkg")
    os.makedirs(shadow)
    with open(os.path.join(shadow, "__init__.py"), "w") as handle:
        handle.write("")
    with open(os.path.join(shadow, "run.py"), "w") as handle:
        handle.write(
            "open(%r, 'w').write('shadowed')\n"
            "VERSION = %r\n\ndef main():\n    print(VERSION)\n"
            "    return 0\n" % (marker, _VNG_FIXTURE_VERSION)
        )
    saved_path = os.environ.get("PATH", "")
    saved_pythonpath = os.environ.get("PYTHONPATH")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    os.environ["PYTHONPATH"] = os.path.dirname(shadow)
    try:
        record = runner.check_runner(
            _pinned_runner_lock(tree), farm_parent=tree["root"]
        )
        try:
            assert record["version"] == _VNG_FIXTURE_VERSION, record
        finally:
            shutil.rmtree(record["farm"], ignore_errors=True)
        assert not os.path.exists(marker), "PYTHONPATH shadow imported"
    finally:
        os.environ["PATH"] = saved_path
        if saved_pythonpath is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = saved_pythonpath
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_check_runner_rejects_modified_package():
    runner = _load_runner()
    tree = _runner_tree()
    marker = os.path.join(tree["root"], "EXECUTED.marker")
    saved_path = os.environ.get("PATH", "")
    lock = _pinned_runner_lock(tree)
    with open(os.path.join(tree["package"], "run.py"), "w") as handle:
        handle.write(
            "open(%r, 'w').write('evil')\n"
            "VERSION = %r\n\ndef main():\n    print(VERSION)\n"
            "    return 0\n" % (marker, _VNG_FIXTURE_VERSION)
        )
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(
            runner.check_runner, lock
        )
        assert "admission refused" in message, message
        assert not os.path.exists(marker), "evil module imported"
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_check_runner_rejects_substituted_launcher():
    """A substituted virtme-run launcher is refused before any
    process starts (no execution marker)."""
    runner = _load_runner()
    tree = _runner_tree()
    marker = os.path.join(tree["root"], "EXECUTED.marker")
    saved_path = os.environ.get("PATH", "")
    lock = _pinned_runner_lock(tree)
    _write_executable(
        tree["launcher"],
        "#!/bin/sh\ntouch '%s'\necho '%s'\n"
        % (marker, _VIRTME_RUN_FIXTURE_LINE),
    )
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(
            runner.check_runner, lock
        )
        assert "launcher admission refused" in message, message
        assert not os.path.exists(marker), "substituted launcher executed"
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_check_runner_rejects_modified_launcher_package():
    """A rewritten virtme.* module is rejected by hash before any
    import (the marker proves the evil module never loaded)."""
    runner = _load_runner()
    tree = _runner_tree()
    marker = os.path.join(tree["root"], "EXECUTED.marker")
    saved_path = os.environ.get("PATH", "")
    lock = _pinned_runner_lock(tree)
    with open(
        os.path.join(
            tree["launcher_package"], "commands", "run.py"
        ),
        "w",
    ) as handle:
        handle.write(
            "open(%r, 'w').write('evil')\n"
            "VERSION = %r\n\ndef main():\n    print(VERSION)\n"
            "    return 0\n" % (marker, _VIRTME_RUN_FIXTURE_LINE)
        )
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(
            runner.check_runner, lock
        )
        assert "launcher admission refused" in message, message
        assert not os.path.exists(marker), "evil launcher module imported"
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_check_runner_requires_launcher_pins():
    """A lock without virtme-run pins cannot qualify guests."""
    runner = _load_runner()
    tree = _runner_tree()
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        lock = _pinned_runner_lock(tree)
        del lock["runner"]["virtme_run_sha256"]
        message = _assert_setup_failure(
            runner.check_runner, lock
        )
        assert "virtme_run_sha256" in message, message
        lock = _pinned_runner_lock(tree)
        del lock["runner"]["virtme_package"]
        message = _assert_setup_failure(
            runner.check_runner, lock
        )
        assert "virtme_package" in message, message
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_sitecustomize_never_executes_during_module_probe():
    """A sitecustomize.py in an admitted module root is rejected
    before any spawn -- and the module-path probe itself never
    executes startup code (no marker either way)."""
    runner = _load_runner()
    tree = _runner_tree()
    marker = os.path.join(tree["root"], "EXECUTED.marker")
    with open(
        os.path.join(tree["pkgdir"], "sitecustomize.py"), "w"
    ) as handle:
        handle.write("open(%r, 'w').write('startup')\n" % marker)
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(
            runner.check_runner, _pinned_runner_lock(tree)
        )
        assert "admission refused" in message, message
        assert "sitecustomize" in message, message
        assert not os.path.exists(marker), "startup code executed"
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def _write_dep_dist(pkgdir, name, version, files):
    """Stage a fixture distribution; return (metadata, record) digests.

    ``files`` maps root-relative paths (``pkg/__init__.py``) to
    text content. Writes the package files, the ``.dist-info``
    with ``METADATA``, and a ``RECORD`` manifest with real
    per-file hashes plus its own empty-hash self entry.
    """
    import base64
    import hashlib

    dist_info = "%s-%s.dist-info" % (name, version)
    os.makedirs(os.path.join(pkgdir, dist_info), exist_ok=True)
    staged = {}
    for rel, text in files.items():
        path = os.path.join(pkgdir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        staged[rel] = path
    metadata_rel = "%s/METADATA" % dist_info
    metadata = os.path.join(pkgdir, metadata_rel)
    with open(metadata, "w", encoding="utf-8") as handle:
        handle.write(
            "Metadata-Version: 2.1\nName: %s\nVersion: %s\n"
            % (name, version)
        )
    staged[metadata_rel] = metadata

    def _record_hash(path):
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return (
            "sha256="
            + base64.urlsafe_b64encode(digest.digest())
            .rstrip(b"=")
            .decode("ascii")
        )

    rows = [
        "%s,%s," % (rel, _record_hash(path))
        for rel, path in sorted(staged.items())
    ]
    rows.append("%s/RECORD,," % dist_info)
    record = os.path.join(pkgdir, dist_info, "RECORD")
    with open(record, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(rows) + "\n")
    return _sha256_of(metadata), _sha256_of(record)


def _lock_with_distribution(tree, distribution):
    lock = _pinned_runner_lock(tree)
    lock["distribution"] = distribution
    return lock


def _fixture_distribution(tree):
    metadata_digest, record_digest = _write_dep_dist(
        tree["pkgdir"],
        "matrix_dep",
        "1.0",
        {"matrix_dep/__init__.py": "VALUE = 1\n"},
    )
    return {
        "runner": {
            "dependencies": [
                {
                    "name": "matrix_dep",
                    "version": "1.0",
                    "metadata_sha256": metadata_digest,
                    "record_sha256": record_digest,
                },
            ],
        },
        "emulator": {"qemu_version": _QEMU_FIXTURE_VERSION},
    }


def test_check_runner_enforces_distribution():
    """The lock's distribution bindings are verified, never
    trusted descriptively."""
    runner = _load_runner()
    tree = _runner_tree()
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        record = runner.check_runner(
            _lock_with_distribution(tree, _fixture_distribution(tree)),
            farm_parent=tree["root"],
        )
        shutil.rmtree(record["farm"], ignore_errors=True)
        assert record["version"] == _VNG_FIXTURE_VERSION, record

        stale = _fixture_distribution(tree)
        stale["runner"]["dependencies"][0]["metadata_sha256"] = (
            "0" * 64
        )
        message = _assert_setup_failure(
            runner.check_runner, _lock_with_distribution(tree, stale)
        )
        assert "distribution" in message, message
        assert "zero" in message, message

        stale_record = _fixture_distribution(tree)
        stale_record["runner"]["dependencies"][0]["record_sha256"] = (
            "0" * 64
        )
        message = _assert_setup_failure(
            runner.check_runner,
            _lock_with_distribution(tree, stale_record),
        )
        assert "distribution" in message, message
        assert "zero" in message, message

        missing = _fixture_distribution(tree)
        missing["runner"]["dependencies"][0]["name"] = "matrix_absent"
        message = _assert_setup_failure(
            runner.check_runner, _lock_with_distribution(tree, missing)
        )
        assert "distribution" in message, message

        tampered = _fixture_distribution(tree)
        tampered["emulator"]["qemu_version"] = "QEMU tampered 0.0"
        message = _assert_setup_failure(
            runner.check_runner,
            _lock_with_distribution(tree, tampered),
        )
        assert "distribution" in message, message

        malformed = _fixture_distribution(tree)
        del malformed["runner"]["dependencies"][0]["version"]
        message = _assert_setup_failure(
            runner.check_runner,
            _lock_with_distribution(tree, malformed),
        )
        assert "distribution is malformed" in message, message

        malformed_record = _fixture_distribution(tree)
        del malformed_record["runner"]["dependencies"][0][
            "record_sha256"
        ]
        message = _assert_setup_failure(
            runner.check_runner,
            _lock_with_distribution(tree, malformed_record),
        )
        assert "distribution is malformed" in message, message
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_check_runner_substituted_content_refused():
    """METADATA alone cannot bind a dependency on the matrix
    path either: substituted package bytes with untouched
    METADATA are refused through the RECORD chain before any
    probe, leaving no execution marker."""
    runner = _load_runner()
    tree = _runner_tree(
        run_body=(
            "import matrix_dep\nVERSION = %r\n\ndef main():\n"
            "    print(VERSION)\n    return 0\n"
            % (_VNG_FIXTURE_VERSION,)
        )
    )
    marker = os.path.join(tree["root"], "DEP.marker")
    lock = _lock_with_distribution(tree, _fixture_distribution(tree))
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        record = runner.check_runner(
            lock,
            farm_parent=tree["root"],
        )
        shutil.rmtree(record["farm"], ignore_errors=True)
        assert record["version"] == _VNG_FIXTURE_VERSION, record
        with open(
            os.path.join(tree["pkgdir"], "matrix_dep", "__init__.py"),
            "w",
        ) as handle:
            handle.write(
                "open(%r, 'w').write('evil')\nVALUE = 1\n" % marker
            )
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "distribution" in message, message
        assert not os.path.exists(marker), (
            "substituted dependency executed"
        )
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_check_runner_distribution_failure_allows_zero_probes():
    """A failed distribution binding is enforced before ANY
    entry probe on the matrix path too: with an all-zero
    dependency digest, the vng/qemu/launcher entries never
    spawn."""
    runner = _load_runner()
    tree = _runner_tree()
    stale = _fixture_distribution(tree)
    stale["runner"]["dependencies"][0]["metadata_sha256"] = "0" * 64
    lock = _lock_with_distribution(tree, stale)
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    spawns = []
    real_popen = subprocess.Popen

    def _spy(*args, **kwargs):
        argv = args[0] if args else kwargs.get("args", [])
        spawns.append(list(argv))
        return real_popen(*args, **kwargs)

    subprocess.Popen = _spy
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "distribution" in message, message
        assert "zero" in message, message
    finally:
        subprocess.Popen = real_popen
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)
    entry_probes = [
        argv
        for argv in spawns
        if argv and argv[0].startswith(tree["root"] + os.path.sep)
    ]
    assert entry_probes == [], entry_probes


def test_load_lock_rejects_malformed_distribution():
    runner = _load_runner()
    lanes = [
        _lane(lane_id="a", release="v9.1"),
        _lane(lane_id="b", release="v9.2"),
    ]
    lock = _lock(lanes)
    lock["distribution"] = {"runner": {"dependencies": [{}]}}
    message = _assert_setup_failure(_load_lock_text, runner, lock)
    assert "dependency lacks" in message, message
    lock["distribution"] = {"emulator": {"qemu_version": 7}}
    message = _assert_setup_failure(_load_lock_text, runner, lock)
    assert "qemu_version" in message, message


def test_farm_forces_admitted_resolution():
    """Shadows earlier on PATH cannot win once the farm heads it."""
    runner = _load_runner()
    tree = _runner_tree()
    shadow_dir = os.path.join(tree["root"], "shadow-bin")
    os.makedirs(shadow_dir)
    with open(os.path.join(shadow_dir, "vng"), "w") as handle:
        handle.write("#!/bin/sh\necho shadow-vng\n")
    os.chmod(os.path.join(shadow_dir, "vng"), 0o755)
    with open(os.path.join(shadow_dir, "virtme-run"), "w") as handle:
        handle.write("#!/bin/sh\necho shadow-launcher\n")
    os.chmod(os.path.join(shadow_dir, "virtme-run"), 0o755)
    with open(os.path.join(shadow_dir, "matrix-qemu"), "w") as handle:
        handle.write("#!/bin/sh\necho shadow-qemu\n")
    os.chmod(os.path.join(shadow_dir, "matrix-qemu"), 0o755)
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        record = runner.check_runner(
            _pinned_runner_lock(tree), farm_parent=tree["root"]
        )
        try:
            farm = record["farm"]
            ambient = shadow_dir + os.pathsep + saved_path
            assert shutil.which("vng", path=ambient) == os.path.join(
                shadow_dir, "vng"
            )
            assert shutil.which(
                "virtme-run", path=ambient
            ) == os.path.join(shadow_dir, "virtme-run")
            forced = farm + os.pathsep + ambient
            assert os.path.realpath(
                shutil.which("vng", path=forced)
            ) == os.path.realpath(tree["entry"])
            assert os.path.realpath(
                shutil.which("virtme-run", path=forced)
            ) == os.path.realpath(tree["launcher"])
            assert os.path.realpath(
                shutil.which("matrix-qemu", path=forced)
            ) == os.path.realpath(tree["qemu"])
        finally:
            shutil.rmtree(record["farm"], ignore_errors=True)
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_run_suite_uses_farm_first_and_strips_import_path():
    runner = _load_runner()
    tree = _runner_tree()
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        record = runner.check_runner(
            _pinned_runner_lock(tree), farm_parent=tree["root"]
        )
        farm = record["farm"]
        try:
            root, out_dir, suite_record = _run_fake(
                runner, _FAKE_ENV_DUMP, 120,
                extra_env={"PYTHONPATH": "/tmp/ambient-shadow"},
                farm=farm,
            )
            try:
                assert suite_record["outcome"] == "pass", suite_record
                assert suite_record["farm"] == farm, suite_record
                assert "PYTHONPATH" in suite_record["env_stripped"]
                with open(suite_record["log"], encoding="utf-8") as handle:
                    log = handle.read()
                assert ("matrix: farm=%s" % farm) in log, log
                assert "PYTHONPATH" in log, log
                path_line = next(
                    line for line in log.splitlines()
                    if line.startswith("PATH=")
                )
                assert path_line.startswith(
                    "PATH=%s%s" % (farm, os.pathsep)
                ), path_line
                assert "PYTHONPATH=<absent>" in log, log
            finally:
                shutil.rmtree(root, ignore_errors=True)
        finally:
            shutil.rmtree(farm, ignore_errors=True)
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_consumer_vng_shadow_rejected():
    runner = _load_runner()
    root = tempfile.mkdtemp(prefix="mojobpf-shadow-unit-")
    try:
        shadow_dir = os.path.join(root, "shadow")
        os.makedirs(shadow_dir)
        with open(
            os.path.join(shadow_dir, "vng"), "w", encoding="utf-8"
        ) as handle:
            handle.write("#!/bin/sh\necho shadow-vng\n")
        os.chmod(os.path.join(shadow_dir, "vng"), 0o755)
        message = _assert_setup_failure(
            runner.check_consumer_vng_shadow,
            [shadow_dir], "/elsewhere/validated-vng",
        )
        assert "shadows the locked vng" in message, message
        clean_dir = os.path.join(root, "clean")
        os.makedirs(clean_dir)
        saved_path = os.environ.get("PATH", "")
        try:
            # No vng anywhere on PATH: nothing resolves, so
            # nothing can shadow.
            os.environ["PATH"] = clean_dir
            runner.check_consumer_vng_shadow(
                [clean_dir], "/elsewhere/validated-vng"
            )
            runner.check_consumer_vng_shadow(
                [], "/elsewhere/validated-vng"
            )
        finally:
            os.environ["PATH"] = saved_path
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_consumer_qemu_shadow_rejected():
    # vng resolves qemu-system-{arch} PATH-only under the
    # augmented PATH, so a consumer QEMU must be rejected the
    # same way a consumer vng is.
    runner = _load_runner()
    root = tempfile.mkdtemp(prefix="mojobpf-qemu-shadow-unit-")
    try:
        shadow_dir = os.path.join(root, "shadow")
        os.makedirs(shadow_dir)
        with open(
            os.path.join(shadow_dir, "stub-qemu"), "w",
            encoding="utf-8",
        ) as handle:
            handle.write("#!/bin/sh\necho shadow-qemu\n")
        os.chmod(os.path.join(shadow_dir, "stub-qemu"), 0o755)
        message = _assert_setup_failure(
            runner.check_consumer_qemu_shadow,
            [shadow_dir], "stub-qemu", "/elsewhere/validated-qemu",
        )
        assert "shadows the locked stub-qemu" in message, message
        clean_dir = os.path.join(root, "clean")
        os.makedirs(clean_dir)
        saved_path = os.environ.get("PATH", "")
        try:
            # No QEMU anywhere on PATH: nothing resolves, so
            # nothing can shadow.
            os.environ["PATH"] = clean_dir
            runner.check_consumer_qemu_shadow(
                [clean_dir], "stub-qemu", "/elsewhere/validated-qemu"
            )
            runner.check_consumer_qemu_shadow(
                [], "stub-qemu", "/elsewhere/validated-qemu"
            )
        finally:
            os.environ["PATH"] = saved_path
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_consumer_virtme_run_shadow_rejected():
    # vng invokes the bare virtme-run name through a shell under
    # the augmented PATH, so a consumer launcher must be rejected
    # the same way a consumer vng is.
    runner = _load_runner()
    root = tempfile.mkdtemp(prefix="mojobpf-launcher-shadow-unit-")
    try:
        shadow_dir = os.path.join(root, "shadow")
        os.makedirs(shadow_dir)
        with open(
            os.path.join(shadow_dir, "virtme-run"), "w",
            encoding="utf-8",
        ) as handle:
            handle.write("#!/bin/sh\necho shadow-launcher\n")
        os.chmod(os.path.join(shadow_dir, "virtme-run"), 0o755)
        message = _assert_setup_failure(
            runner.check_consumer_virtme_run_shadow,
            [shadow_dir], "/elsewhere/validated-launcher",
        )
        assert "shadows the locked virtme-run" in message, message
        clean_dir = os.path.join(root, "clean")
        os.makedirs(clean_dir)
        saved_path = os.environ.get("PATH", "")
        try:
            # No launcher anywhere on PATH: nothing resolves, so
            # nothing can shadow.
            os.environ["PATH"] = clean_dir
            runner.check_consumer_virtme_run_shadow(
                [clean_dir], "/elsewhere/validated-launcher"
            )
            runner.check_consumer_virtme_run_shadow(
                [], "/elsewhere/validated-launcher"
            )
        finally:
            os.environ["PATH"] = saved_path
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


def test_check_lane_cache_rejects_ambiguous_basename():
    runner = _load_runner()
    home = tempfile.mkdtemp(prefix="mojobpf-ambiguous-unit-")
    try:
        for sub in ("amd64", "stale"):
            path = os.path.join(
                home, ".cache", "virtme-ng", "v9.99", sub
            )
            os.makedirs(path)
            with open(
                os.path.join(path, "kernel-amd64.deb"), "wb"
            ) as handle:
                handle.write(b"bytes")
        lane = {
            "id": "v9.99-tcg",
            "release": "v9.99",
            "kernel_debs": [
                {"file": "kernel-amd64.deb", "sha256": "0" * 64}
            ],
        }
        old_home = os.environ.get("HOME")
        os.environ["HOME"] = home
        try:
            message = _assert_setup_failure(
                runner.check_lane_cache, lane
            )
        finally:
            if old_home is None:
                del os.environ["HOME"]
            else:
                os.environ["HOME"] = old_home
        assert "ambiguous" in message, message
    finally:
        shutil.rmtree(home, ignore_errors=True)


# Guest-backed suites intentionally outside the x86 matrix, with
# the reason each stays out. Anything else guest-backed must be
# wired into SUITES; the matrix never silently drops a suite.
MATRIX_EXCEPTIONS = {
    # AArch64 lane: runs directly with MOJOBPF_VNG_ARCH /
    # MOJOBPF_VNG_ROOT (the arm64 lock is not consumed by the
    # matrix runner).
    "tests/kernel/test_arch_portability.py": "aarch64-lane-direct",
    # Host-only structural check (no guest, no toolchain).
    "tests/verifier/test_subset_doc.py": "host-only",
}


def _guest_suite_files():
    """Every guest-backed suite file by directory convention.

    ``tests/kernel/`` boots a guest in every suite;
    ``tests/verifier/`` boots except the doc check;
    ``tests/packaging/`` boots in the consumer suites only (the
    installed/wheel/compat suites are host-only).
    """
    found = set()
    kernel_dir = os.path.join(REPO_ROOT, "tests", "kernel")
    for name in sorted(os.listdir(kernel_dir)):
        if name.startswith("test_") and name.endswith(".py"):
            found.add("tests/kernel/" + name)
    verifier_dir = os.path.join(REPO_ROOT, "tests", "verifier")
    for name in sorted(os.listdir(verifier_dir)):
        if name.startswith("test_") and name.endswith(".py"):
            found.add("tests/verifier/" + name)
    packaging_dir = os.path.join(REPO_ROOT, "tests", "packaging")
    for name in sorted(os.listdir(packaging_dir)):
        if name.startswith("test_") and name.endswith("_consumer.py"):
            found.add("tests/packaging/" + name)
    return found


def test_matrix_wires_every_guest_suite():
    runner = _load_runner()
    entries = list(runner.SUITES)
    ids = [suite_id for suite_id, _relpath, _timeout in entries]
    assert len(ids) == len(set(ids)), "duplicate suite ids"
    for suite_id, relpath, timeout in entries:
        assert isinstance(timeout, int) and timeout > 0, (
            suite_id,
            timeout,
        )
    wired = {relpath for _suite_id, relpath, _timeout in entries}
    expected = _guest_suite_files() - set(MATRIX_EXCEPTIONS)
    assert wired == expected, (
        "matrix drift: unwired=%r extra=%r"
        % (sorted(expected - wired), sorted(wired - expected))
    )
    for relpath in MATRIX_EXCEPTIONS:
        assert relpath not in wired, relpath


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
