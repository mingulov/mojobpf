# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the shared guest-runner composition.

Pins ``tests/harness/guest_proc.py``: ``None``/``bytes``/``str``
decode exactly, split UTF-8 never raises, and every guest-suite
timeout path decodes through the shared helper (no remaining
bare ``(exc.stdout or "")`` concatenation anywhere under
``tests/``).

Pins the owned runner itself with host-only stand-ins (no guest
boot): success passthrough, timeout tree-kill with the partial
line exactly once (never duplicated) in both the error and the
stage log, interruption reaping with propagation, and every
converted suite's timeout mapping (each suite's own error type
carrying the partial output, with no survivors).

Deterministic on any host: only the standard library plus
pytest's plain function collection.

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3
tests/unit/test_guest_proc.py``).
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


def _load_helper():
    spec = importlib.util.spec_from_file_location(
        "guest_proc",
        os.path.join(REPO_ROOT, "tests", "harness", "guest_proc.py"),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _require_tools(*tools):
    for tool in tools:
        if shutil.which(tool) is None:
            raise AssertionError("%s not found on PATH" % tool)


def _proc_cmdlines_containing(needle):
    """Return the pids whose command line still contains ``needle``."""
    found = []
    want = needle.encode("utf-8")
    try:
        entries = [
            entry for entry in os.listdir("/proc") if entry.isdigit()
        ]
    except OSError:
        return found
    for entry in entries:
        try:
            with open("/proc/%s/cmdline" % entry, "rb") as handle:
                cmdline = handle.read()
        except OSError:
            continue
        if want in cmdline:
            found.append(int(entry))
    return found


def _reap_marked(marker):
    import signal

    for pid in _proc_cmdlines_containing(marker):
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def _standin_argv(marker):
    return [
        "bash", "-c",
        "echo %s-PARTIAL; (exec -a %s-child sleep 60) & "
        "exec -a %s-leader sleep 60" % (marker, marker, marker),
    ]


def _read_log(stage, name="guest.log"):
    log_path = os.path.join(stage, name)
    assert os.path.isfile(log_path), (
        "expected a stage log at %s" % log_path
    )
    with open(log_path, "r", encoding="utf-8") as handle:
        return handle.read()


def test_decode_none_bytes_and_str():
    helper = _load_helper()
    assert helper.decode_timeout_partial(None) == ""
    assert helper.decode_timeout_partial(b"partial-out\n") == (
        "partial-out\n"
    )
    assert helper.decode_timeout_partial("already-text") == (
        "already-text"
    )
    # A byte split mid-character decodes with replacement and
    # never raises.
    assert helper.decode_timeout_partial(b"ab\xffcd") == "ab\ufffdcd"
    assert helper.decode_timeout_partial(b"\xe2\x82") == "\ufffd"


def test_no_bare_timeout_partial_concatenation():
    # Every suite timeout path must decode through the shared
    # helper: a bare ``(exc.stdout or "")`` concatenation raises
    # TypeError on partial bytes and loses the evidence.
    offenders = []
    self_rel = os.path.relpath(__file__, REPO_ROOT)
    for root, _dirs, files in os.walk(
        os.path.join(REPO_ROOT, "tests")
    ):
        for name in sorted(files):
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, REPO_ROOT)
            if rel == self_rel:
                continue
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
            if '(exc.stdout or "")' in text:
                offenders.append(rel)
    assert offenders == [], offenders


def test_owned_success_passthrough():
    helper = _load_helper()
    stage = tempfile.mkdtemp(prefix="owned-success-")
    try:
        code, output = helper.run_owned(
            ["bash", "-c", "echo hello; exit 3"], stage, timeout=30
        )
        assert code == 3, (code, output)
        assert output == "hello\n", repr(output)
        log = _read_log(stage)
        assert log.splitlines()[0] == "guest exit: 3", log[:200]
        assert "hello\n" in log, log
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def test_owned_timeout_kills_tree_and_saves_partial_once():
    _require_tools("bash", "sleep")
    helper = _load_helper()
    marker = "owned-standin-%d" % os.getpid()
    stage = tempfile.mkdtemp(prefix="owned-standin-")
    try:
        try:
            helper.run_owned(
                _standin_argv(marker), stage, timeout=5
            )
        except helper.GuestTimeout as exc:
            assert exc.timeout == 5, exc.timeout
            assert exc.output.count("%s-PARTIAL" % marker) == 1, (
                exc.output[-500:]
            )
            assert exc.log_path == os.path.join(stage, "guest.log"), (
                exc.log_path
            )
        else:
            raise AssertionError("stand-in run unexpectedly finished")
        log = _read_log(stage)
        assert "partial" in log.splitlines()[0], log[:200]
        # The post-timeout drain carries the complete stream: the
        # partial line appears exactly once, never duplicated.
        assert log.count("%s-PARTIAL" % marker) == 1, log[-500:]
        survivors = _proc_cmdlines_containing(marker)
        assert survivors == [], (
            "stand-in descendants survived the timeout: %s" % survivors
        )
    finally:
        _reap_marked(marker)
        shutil.rmtree(stage, ignore_errors=True)


def test_owned_interrupt_reaps_tree_and_propagates():
    _require_tools("bash", "sleep")
    helper = _load_helper()
    marker = "owned-standin-ki-%d" % os.getpid()
    stage = tempfile.mkdtemp(prefix="owned-standin-ki-")
    real_popen = subprocess.Popen

    class _InterruptOnce(real_popen):
        fired = False

        def communicate(self, *args, **kwargs):
            if not _InterruptOnce.fired:
                deadline = time.monotonic() + 15
                while not _proc_cmdlines_containing(
                    "%s-child" % marker
                ):
                    if time.monotonic() > deadline:
                        raise AssertionError(
                            "stand-in child never appeared"
                        )
                    time.sleep(0.1)
                _InterruptOnce.fired = True
                raise KeyboardInterrupt
            return super().communicate(*args, **kwargs)

    subprocess.Popen = _InterruptOnce
    try:
        try:
            helper.run_owned(
                _standin_argv(marker), stage, timeout=60
            )
        except KeyboardInterrupt:
            pass
        else:
            raise AssertionError(
                "stand-in run swallowed the interruption"
            )
    finally:
        subprocess.Popen = real_popen
    try:
        log = _read_log(stage)
        assert "interrupted" in log.splitlines()[0], log[:200]
        assert log.count("%s-PARTIAL" % marker) == 1, log[-500:]
        survivors = _proc_cmdlines_containing(marker)
        assert survivors == [], (
            "stand-in descendants survived the interruption: %s"
            % survivors
        )
    finally:
        _reap_marked(marker)
        shutil.rmtree(stage, ignore_errors=True)


# (suite module, runner attribute, convention, error name).
# Conventions: "owned3" is (argv, stage, timeout) through the
# shared runner; "owned4" adds the lane release; "exec" is the
# cleanup guest_exec(script_text, name, timeout) driven through
# a Popen stand-in (it builds vng argv internally, so the mock
# swaps the spawn, never the wrapper).
_WRAPPERS = (
    ("tests/kernel/test_core_layouts.py", "_run_guest", "owned3",
     "EnvironmentFailure"),
    ("tests/kernel/test_arch_portability.py", "_run_guest", "owned3",
     "EnvironmentFailure"),
    ("tests/kernel/test_hash_maps.py", "_run_guest", "owned3",
     "EnvironmentFailure"),
    ("tests/kernel/test_ringbuf_reserve.py", "_run_guest", "owned3",
     "EnvironmentFailure"),
    ("tests/kernel/test_subprog_calls.py", "_run_guest", "owned3",
     "EnvironmentFailure"),
    ("tests/kernel/test_uprobe_register.py", "_run_guest", "owned3",
     "EnvironmentFailure"),
    ("tests/packaging/test_hash_consumer.py", "_run_guest", "owned3",
     "EnvironmentFailure"),
    ("tests/packaging/test_reserve_consumer.py", "_run_guest",
     "owned3", "EnvironmentFailure"),
    ("tests/packaging/test_subprog_consumer.py", "_run_guest",
     "owned3", "EnvironmentFailure"),
    ("tests/packaging/test_uprobe_consumer.py", "_run_guest",
     "owned3", "EnvironmentFailure"),
    ("tests/kernel/test_array_maps.py", "_run_guest", "owned3",
     "EnvironmentFailure"),
    ("tests/kernel/test_generalized_arrays.py", "_run_guest",
     "owned3", "EnvironmentFailure"),
    ("tests/kernel/test_map_roundtrip.py", "_run_guest", "owned3",
     "EnvironmentFailure"),
    ("tests/kernel/test_mojo_percpu.py", "_run_guest", "owned3",
     "EnvironmentFailure"),
    ("tests/kernel/test_mojo_xdp.py", "_run_guest", "owned3",
     "EnvironmentFailure"),
    ("tests/kernel/test_packet_sdk.py", "_run_guest", "owned3",
     "EnvironmentFailure"),
    ("tests/kernel/test_parse_checksum_sdk.py", "_run_guest",
     "owned3", "EnvironmentFailure"),
    ("tests/kernel/test_percpu_maps.py", "_run_guest", "owned3",
     "EnvironmentFailure"),
    ("tests/kernel/test_xdp_accounting.py", "_run_guest", "owned3",
     "EnvironmentFailure"),
    ("tests/verifier/test_subset_kernel.py", "_run_guest", "owned3",
     "EnvironmentFailure"),
    ("tests/packaging/test_external_consumer.py", "_run_guest",
     "owned3", "EnvironmentFailure"),
    ("tests/kernel/test_tracepoint_counter.py", "_run_guest",
     "owned4", "ProofFailure"),
    ("tests/kernel/test_tracepoint_events.py", "_run_guest",
     "owned4", "ProofFailure"),
    ("tests/kernel/test_cleanup.py", "guest_exec", "exec",
     "EnvironmentFailure"),
    ("tests/kernel/test_tracing_lifecycle.py", "run_guest", "owned3",
     "ProofFailure"),
    ("tests/verifier/test_helper_licenses.py", "run_guest", "owned3",
     "ProofFailure"),
)


def _load_suite(relpath):
    name = "wrapper_%s" % relpath.replace("/", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(REPO_ROOT, relpath)
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _check_wrapper_timeout(relpath, attr, convention, error_name):
    _require_tools("bash", "sleep")
    marker = "wrap-%s-%d" % (
        os.path.basename(relpath).replace(".py", "").replace("test_", ""),
        os.getpid(),
    )
    suite = _load_suite(relpath)
    runner = getattr(suite, attr)
    stage = tempfile.mkdtemp(prefix="owned-wrap-")
    real_popen = subprocess.Popen
    if convention == "exec":
        held = {}

        class _StandinPopen:
            def __init__(self, argv, **kwargs):
                proc = real_popen(
                    _standin_argv(marker),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    start_new_session=True,
                )
                held["proc"] = proc
                self._proc = proc

            def __getattr__(self, name):
                return getattr(held["proc"], name)

        subprocess.Popen = _StandinPopen
    try:
        try:
            if convention == "owned3":
                runner(_standin_argv(marker), stage, 2)
            elif convention == "owned4":
                runner(_standin_argv(marker), stage, 2, "v6.12")
            elif convention == "exec":
                # Seed the shared fixture cache with the
                # stand-in stage: guest_exec only needs
                # fix["stage"], and the real fixture build
                # needs the Mojo toolchain.
                suite._FIXTURE.clear()
                suite._FIXTURE["stage"] = stage
                runner("exit 0\n", "wrap_probe.sh", 2)
            else:
                raise AssertionError("unknown convention %s" % convention)
        except Exception as exc:
            assert type(exc).__name__ == error_name, (
                "%s: want %s, got %s (%s)"
                % (relpath, error_name, type(exc).__name__, exc)
            )
            message = str(exc)
        else:
            raise AssertionError(
                "%s: stand-in run unexpectedly finished" % relpath
            )
    finally:
        subprocess.Popen = real_popen
    try:
        assert "timed out" in message, (relpath, message[-300:])
        assert message.count("%s-PARTIAL" % marker) == 1, (
            relpath, message[-500:]
        )
        if convention == "exec":
            log = _read_log(stage, "wrap_probe.sh.log")
        else:
            log = _read_log(stage)
        assert log.count("%s-PARTIAL" % marker) == 1, (
            relpath, log[-500:]
        )
        survivors = _proc_cmdlines_containing(marker)
        assert survivors == [], (
            "%s: stand-in descendants survived: %s" % (relpath, survivors)
        )
    finally:
        _reap_marked(marker)
        shutil.rmtree(stage, ignore_errors=True)


def test_every_wrapper_maps_timeout():
    for relpath, attr, convention, error_name in _WRAPPERS:
        _check_wrapper_timeout(relpath, attr, convention, error_name)


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
