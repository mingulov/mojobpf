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

Also pins the typed-outcome composition: harness-record
mapping (environment branches before the exit assertion,
never an AssertionError), the unified guest-exit rule, the
owned-process census and leak attribution, the suite recorder
(plan sealing, typed cases, terminal emission), and the packet
temporary-file cleanup on every harness early return.

Deterministic on any host: only the standard library plus
pytest's plain function collection.

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3
tests/unit/test_guest_proc.py``).
"""

import contextlib
import importlib.util
import io
import json
import os
import pytest
import shutil
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

sys.path.insert(
    0, os.path.join(REPO_ROOT, "src"),
)

from mojobpf import validation as validation_mod  # noqa: E402
from mojobpf.validation.aggregate import (  # noqa: E402
    verify_suite_result,
)


def _load_helper():
    spec = importlib.util.spec_from_file_location(
        "guest_proc",
        os.path.join(REPO_ROOT, "tests", "harness", "guest_proc.py"),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextlib.contextmanager
def _simulated_admission_env():
    """Grant a test target lease for a simulated admitted flow.

    Only tests drive this helper: the fake-bpftool fixtures
    below never touch a real target, but the execution gates
    refuse unleased runs, so admitted-path probes set the
    lease explicitly here. Production code never synthesizes
    a lease (see the matrix propagation regression test).
    """
    saved = os.environ.get("MOJOBPF_TARGET_LEASE")
    os.environ["MOJOBPF_TARGET_LEASE"] = "1"
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop("MOJOBPF_TARGET_LEASE", None)
        else:
            os.environ["MOJOBPF_TARGET_LEASE"] = saved


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


def _proc_argv0_present(name):
    """True when a live process has exactly ``name`` as argv[0].

    The stand-in child is spawned with ``exec -a <marker>-child``,
    so only its argv[0] matches; the parent's ``bash -c`` script
    text merely contains the marker and must not count as the
    child having started.
    """
    want = name.encode("utf-8")
    try:
        entries = [
            entry for entry in os.listdir("/proc") if entry.isdigit()
        ]
    except OSError:
        return False
    for entry in entries:
        try:
            with open("/proc/%s/cmdline" % entry, "rb") as handle:
                cmdline = handle.read()
        except OSError:
            continue
        argv = cmdline.split(b"\x00")
        if argv and argv[0] == want:
            return True
    return False


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


def test_owned_interrupt_during_timeout_drain_still_saves_log():
    # An abort landing inside the post-timeout drain must still
    # save the stage log under the interrupted banner: the
    # sibling KeyboardInterrupt handler cannot catch what the
    # TimeoutExpired handler raises.
    _require_tools("bash", "sleep")
    helper = _load_helper()
    stage = tempfile.mkdtemp(prefix="owned-standin-drain-ki-")
    real_popen = subprocess.Popen
    created = []

    class _DrainInterrupt(real_popen):
        calls = 0

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            created.append(self)

        def communicate(self, *args, **kwargs):
            _DrainInterrupt.calls += 1
            if _DrainInterrupt.calls == 1:
                raise subprocess.TimeoutExpired(
                    self.args, timeout=kwargs.get("timeout")
                )
            if _DrainInterrupt.calls == 2:
                raise KeyboardInterrupt
            return super().communicate(*args, **kwargs)

    subprocess.Popen = _DrainInterrupt
    try:
        try:
            helper.run_owned(
                ["bash", "-c", "exec -a drain-standin sleep 60"],
                stage,
                timeout=5,
            )
        except KeyboardInterrupt:
            pass
        else:
            raise AssertionError(
                "stand-in run swallowed the drain interruption"
            )
    finally:
        subprocess.Popen = real_popen
        for proc in created:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=10)
            except (OSError, subprocess.SubprocessError):
                pass
    try:
        log = _read_log(stage)
        assert "interrupted" in log.splitlines()[0], log[:200]
    finally:
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
                while not _proc_argv0_present(
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
     "owned4", "EnvironmentFailure"),
    ("tests/kernel/test_tracepoint_events.py", "_run_guest",
     "owned4", "EnvironmentFailure"),
    ("tests/kernel/test_cleanup.py", "guest_exec", "exec",
     "EnvironmentFailure"),
    ("tests/kernel/test_tracing_lifecycle.py", "run_guest", "owned3",
     "EnvironmentFailure"),
    ("tests/verifier/test_helper_licenses.py", "run_guest", "owned3",
     "EnvironmentFailure"),
)
# Timeout mapping is unified: a timeout yields no completed
# observation, so every wrapper reports EnvironmentFailure
# (INFRA_ERROR), never a proof verdict. The gate still fails.


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
    # Wrappers that build vng commands need the target lease;
    # the spawn itself is stubbed to a stand-in above, so no
    # guest boots here.
    saved_lease = os.environ.get("MOJOBPF_TARGET_LEASE")
    os.environ["MOJOBPF_TARGET_LEASE"] = "1"
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
        if saved_lease is None:
            os.environ.pop("MOJOBPF_TARGET_LEASE", None)
        else:
            os.environ["MOJOBPF_TARGET_LEASE"] = saved_lease
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


def test_cleanup_verify_paths_refuse_without_lease():
    # Both cleanup-suite verify invocations (run_step and
    # direct Popen) refuse before any spawn without a target
    # lease, whether the variable is absent or "0". With an
    # explicit test lease both reach their (stubbed) spawn.
    suite = _load_suite("tests/kernel/test_cleanup.py")
    lease_mod = suite.guest_proc
    real_run_step = suite.run_step
    real_popen = suite.subprocess.Popen

    def _forbidden_step(*args, **kwargs):
        raise AssertionError("verify_cli spawned without a lease")

    def _forbidden_popen(*args, **kwargs):
        raise AssertionError("_spawn_wrapper spawned without a lease")

    saved = os.environ.get("MOJOBPF_TARGET_LEASE")
    suite.run_step = _forbidden_step
    suite.subprocess.Popen = _forbidden_popen
    try:
        for value in (None, "0"):
            if value is None:
                os.environ.pop("MOJOBPF_TARGET_LEASE", None)
            else:
                os.environ["MOJOBPF_TARGET_LEASE"] = value
            calls = (
                lambda: suite.verify_cli(["--object", "probe.bpf.o"]),
                lambda: suite._spawn_wrapper("probe.bpf.o", []),
            )
            for call in calls:
                try:
                    call()
                except lease_mod.TargetLeaseRequired as exc:
                    assert "MOJOBPF_TARGET_LEASE" in str(exc), exc
                else:
                    raise AssertionError(
                        "unleased verify path ran (lease=%r)" % (value,)
                    )
    finally:
        suite.run_step = real_run_step
        suite.subprocess.Popen = real_popen
        if saved is None:
            os.environ.pop("MOJOBPF_TARGET_LEASE", None)
        else:
            os.environ["MOJOBPF_TARGET_LEASE"] = saved
    # Positive control: an explicit test lease admits both
    # paths to their spawn (stubbed; nothing boots).
    spawns = []

    class _StubProc:
        returncode = 0
        stdout = '{"status": "pass"}'
        stderr = ""

    def _stub_step(argv, **kwargs):
        spawns.append(list(argv))
        return _StubProc()

    class _StubPopen:
        def __init__(self, argv, **kwargs):
            spawns.append(["popen"] + list(argv))
            self.pid = 424242

    saved_roots = set(suite._OWNED_ROOTS)
    suite.run_step = _stub_step
    suite.subprocess.Popen = _StubPopen
    try:
        with _simulated_admission_env():
            code, record = suite.verify_cli(
                ["--object", "probe.bpf.o"]
            )
            assert code == 0, (code, record)
            assert record["status"] == "pass", record
            proc = suite._spawn_wrapper("probe.bpf.o", [])
            assert proc.pid == 424242
            assert 424242 in suite._OWNED_ROOTS
        assert len(spawns) == 2, spawns
    finally:
        suite.run_step = real_run_step
        suite.subprocess.Popen = real_popen
        suite._OWNED_ROOTS.clear()
        suite._OWNED_ROOTS.update(saved_roots)


def test_check_harness_exit_pass_track():
    helper = _load_helper()
    assert helper.check_harness_exit(
        "t", exit=0, classification=None, stage="run",
        contract_version=2, expect=0) == ("PASS", None)
    # Contract check is skipped when the record carries none
    # (custom-shaped records), but the exit still binds.
    assert helper.check_harness_exit(
        "t", exit=0, classification=None, stage="run",
        expect=0) == ("PASS", None)


def test_check_harness_exit_env_preempts_assertion():
    helper = _load_helper()
    try:
        helper.check_harness_exit(
            "t", exit=3, classification="environment",
            stage="load", contract_version=2,
            note="load denied (permission substrings in output)",
            expect=0)
    except helper.HarnessEnvironment as exc:
        assert exc.stage == "LOAD", exc.stage
        assert exc.availability == "POLICY_DENIED", exc.availability
        assert exc.exit_code == 3
        assert "permission substrings" in str(exc), str(exc)
    else:
        raise AssertionError("environment record accepted on pass track")
    # The env branch wins even when the case expected a failure
    # exit: a denial's proof needs a real rejection, not trouble.
    try:
        helper.check_harness_exit(
            "t", exit=3, classification="environment",
            stage="load", expect=4)
    except helper.HarnessEnvironment as exc:
        assert exc.stage == "LOAD"
    else:
        raise AssertionError("environment record accepted as rejection")
    # And it is never an AssertionError: caller-side assertion
    # handlers must not swallow it.
    assert not issubclass(
        helper.HarnessEnvironment, AssertionError
    )


def test_check_harness_exit_availability_table():
    helper = _load_helper()

    def availability(note, stage="load", exit_code=3,
                     classification="environment"):
        try:
            helper.check_harness_exit(
                "t", exit=exit_code, classification=classification,
                stage=stage, note=note, expect=0)
        except helper.HarnessEnvironment as exc:
            return exc.stage, exc.availability
        raise AssertionError("env record not raised for %r" % note)

    assert availability(
        "load denied (permission substrings in output)"
    ) == ("LOAD", "POLICY_DENIED")
    assert availability("test-run command timed out", stage="run") == (
        "TEST_RUN", "UNKNOWN")
    assert availability("bpftool version failed", stage="setup") == (
        "INFRA", "TOOLCHAIN_UNAVAILABLE")
    assert availability(
        "bpftool binary not found", stage="setup"
    ) == ("INFRA", "TOOLCHAIN_UNAVAILABLE")
    assert availability("object file not found", stage="setup") == (
        "INFRA", "TARGET_RESOURCE_ABSENT")
    assert availability(
        "bpftool admission refused: entry hash f00 does not match "
        "the pinned hash", stage="setup") == ("INFRA", "POLICY_DENIED")
    assert availability(
        "pin path '/x' is outside the owned root", stage="setup"
    ) == ("INFRA", "POLICY_DENIED")
    assert availability(None, stage="run") == ("TEST_RUN", "UNKNOWN")
    assert availability("pin path remains", stage="unload") == (
        "CLEANUP", "UNKNOWN")


def test_check_harness_exit_setup_records():
    helper = _load_helper()
    try:
        helper.check_harness_exit(
            "t", exit=6, classification="setup", stage="setup",
            note="bpftool version failed", expect=0)
    except helper.HarnessEnvironment as exc:
        assert exc.stage == "INFRA", exc.stage
        assert exc.availability == "TOOLCHAIN_UNAVAILABLE"
        assert exc.exit_code == 6
    else:
        raise AssertionError("setup record accepted on pass track")


def test_check_harness_exit_failure_tracks():
    helper = _load_helper()
    assert helper.check_harness_exit(
        "t", exit=1, classification="runtime", stage="run",
        expect=1) == ("FAIL", "RUNTIME")
    assert helper.check_harness_exit(
        "t", exit=4, classification="verifier", stage="load",
        expect=4) == ("FAIL", "VERIFY")
    assert helper.check_harness_exit(
        "t", exit=5, classification="loader", stage="load",
        expect=5) == ("FAIL", "LOAD")
    # Exit/classification incoherence is a product-visible
    # failure, never silently accepted.
    for exit_code, classification in (
        (1, "verifier"), (4, "runtime"), (5, None), (7, "runtime"),
        (0, "runtime"),
    ):
        try:
            helper.check_harness_exit(
                "t", exit=exit_code, classification=classification,
                stage="run", expect=exit_code)
        except AssertionError:
            pass
        else:
            raise AssertionError(
                "incoherent record accepted: %r/%r"
                % (exit_code, classification)
            )
    # Plain mismatches keep the historical message shape.
    try:
        helper.check_harness_exit(
            "t", exit=1, classification="runtime", stage="run",
            expect=0)
    except AssertionError as exc:
        assert "want 0" in str(exc), str(exc)
    else:
        raise AssertionError("exit mismatch accepted")


def test_check_harness_exit_signal_and_misuse():
    helper = _load_helper()
    try:
        helper.check_harness_exit(
            "t", exit=-9, classification=None, stage="run",
            expect=0)
    except AssertionError as exc:
        assert "-9" in str(exc), str(exc)
    else:
        raise AssertionError("signal death accepted")
    try:
        helper.check_harness_exit(
            "t", exit=2, classification="setup", stage="setup",
            expect=0)
    except AssertionError as exc:
        assert "CLI misuse" in str(exc), str(exc)
    else:
        raise AssertionError("harness misuse accepted")
    try:
        helper.check_harness_exit(
            "t", exit=0, classification=None, stage="run",
            contract_version=99, expect=0)
    except AssertionError as exc:
        assert "revision 2" in str(exc), str(exc)
    else:
        raise AssertionError("contract drift accepted")


def test_check_harness_exit_expected_environment_is_strict():
    helper = _load_helper()
    assert helper.check_harness_exit(
        "t", exit=3, classification="environment", stage="load",
        note="load denied (permission substrings in output)",
        expect_environment=True) == ("PASS", None)
    for exit_code, classification in (
        (0, None), (1, "runtime"), (4, "verifier"), (3, "setup"),
    ):
        try:
            helper.check_harness_exit(
                "t", exit=exit_code, classification=classification,
                stage="run", expect_environment=True)
        except AssertionError:
            pass
        else:
            raise AssertionError(
                "non-environment record accepted as expected env: "
                "%r/%r" % (exit_code, classification)
            )


def test_guest_missing_attributes():
    helper = _load_helper()
    exc = helper.GuestMissing("guest output lacks cases x")
    assert isinstance(exc, helper.HarnessEnvironment)
    assert exc.stage == "TEST_RUN"
    assert exc.availability == "UNKNOWN"
    assert exc.exit_code is None


def test_combine_outcomes_first_failure_wins():
    helper = _load_helper()
    assert helper.combine_outcomes() == ("PASS", None)
    assert helper.combine_outcomes(None, ("PASS", None)) == (
        ("PASS", None))
    assert helper.combine_outcomes(
        ("PASS", None), ("FAIL", "VERIFY"), ("FAIL", "RUNTIME")
    ) == ("FAIL", "VERIFY")


def test_classify_guest_exit():
    helper = _load_helper()
    banner = "=== begin guest ==="
    assert helper.classify_guest_exit(
        0, "", progress_banner=banner) == "ok"
    proof_record = {"classification": "runtime"}
    assert helper.classify_guest_exit(
        1, banner + "\n", records=[proof_record],
        progress_banner=banner) == "proof"
    assert helper.classify_guest_exit(
        1, banner + "\nGUEST PROOF FAILURE x\n",
        product_markers=("GUEST PROOF FAILURE",),
        progress_banner=banner) == "proof"
    assert helper.classify_guest_exit(
        1, "Traceback (most recent call last)\n  File vng",
        progress_banner=banner) == "env"
    assert helper.classify_guest_exit(
        1, "qemu: failed to boot\n", progress_banner=banner
    ) == "env"
    # Proof evidence beats a later runner crash: a completed
    # failing observation stands.
    assert helper.classify_guest_exit(
        1, banner + "\nTraceback (most recent call last)\n",
        records=[{"classification": "verifier"}],
        progress_banner=banner) == "proof"
    # Ambiguous nonzero (guest ran, no proof, no runner
    # traceback) fails closed to proof, so a bare product
    # exit 1 can never hide in the env bucket.
    assert helper.classify_guest_exit(
        1, banner + "\nall cases done\n", progress_banner=banner
    ) == "proof"
    try:
        helper.classify_guest_exit(1, "x", progress_banner="")
    except ValueError:
        pass
    else:
        raise AssertionError("bannerless classification accepted")
    # Non-mapping records are ignored, not fatal.
    assert helper.classify_guest_exit(
        1, banner + "\n", records=[None, 42],
        progress_banner=banner) == "proof"


def test_note_owned_group_validation():
    helper = _load_helper()
    for bad in (0, -3, "1", None, 1.5):
        try:
            helper.note_owned_group(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(
                "owned group %r accepted" % (bad,)
            )


def test_kill_guest_tree_reports_clean_when_reaped():
    _require_tools("bash", "sleep")
    helper = _load_helper()
    proc = subprocess.Popen(
        ["bash", "-c", "exec -a clean-sleeper sleep 60"],
        start_new_session=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        residue = helper.kill_guest_tree(proc.pid)
        assert residue == [], residue
        proc.wait(timeout=30)
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        for pipe in (proc.stdout, proc.stderr):
            try:
                pipe.close()
            except (OSError, ValueError):
                pass
        _reap_marked("clean-sleeper")


def test_guest_timeout_carries_kill_residue():
    _require_tools("bash", "sleep")
    helper = _load_helper()
    stage = tempfile.mkdtemp(prefix="owned-residue-")
    real_kill = helper.kill_guest_tree
    helper.kill_guest_tree = lambda pgid: [
        "pid 424242 (pgid 424242, state D)"
    ]
    try:
        try:
            helper.run_owned(
                _standin_argv("residue-probe"), stage, timeout=1
            )
        except helper.GuestTimeout as exc:
            assert exc.residue == [
                "pid 424242 (pgid 424242, state D)"
            ], exc.residue
            assert "owned residue" in str(exc), str(exc)
            assert "timed out" in str(exc), str(exc)
        else:
            raise AssertionError("stand-in run unexpectedly finished")
    finally:
        helper.kill_guest_tree = real_kill
        _reap_marked("residue-probe")
        shutil.rmtree(stage, ignore_errors=True)


def test_kill_guest_tree_reports_deadline_survivors():
    _require_tools("bash", "sleep")
    helper = _load_helper()
    proc = subprocess.Popen(
        ["bash", "-c", "exec -a stray-sleeper sleep 60"],
        start_new_session=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    real_time = helper.time
    real_signal = helper._signal_live_owned

    class _FastClock:
        def __init__(self):
            self.calls = 0

        def monotonic(self):
            self.calls += 1
            if self.calls <= 2:
                return 0.0
            return 1000.0

        def sleep(self, seconds):
            time.sleep(0.01)

        def time(self):
            return time.time()

    helper.time = _FastClock()
    helper._signal_live_owned = lambda *args: ([proc.pid], [])
    try:
        residue = helper.kill_guest_tree(proc.pid)
        assert len(residue) == 1, residue
        assert residue[0].startswith(
            "pid %d (pgid %d, " % (proc.pid, proc.pid)
        ), residue
    finally:
        helper.time = real_time
        helper._signal_live_owned = real_signal
        try:
            proc.kill()
        except OSError:
            pass
        proc.wait(timeout=30)
        for pipe in (proc.stdout, proc.stderr):
            try:
                pipe.close()
            except (OSError, ValueError):
                pass
        _reap_marked("stray-sleeper")


def test_census_detects_owned_stray_and_reap_cleans():
    _require_tools("bash", "sleep")
    helper = _load_helper()
    before = helper.census_snapshot()
    assert before is not None
    proc = subprocess.Popen(
        ["bash", "-c", "exec -a census-sleeper sleep 60"],
        start_new_session=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    helper.note_owned_group(proc.pid)
    try:
        leaks = helper.census_leaks(before)
        assert len(leaks) == 1, leaks
        assert leaks[0].startswith(
            "pid %d (pgid %d, " % (proc.pid, proc.pid)
        ), leaks
        survivors = helper.reap_owned_strays(before, timeout=10.0)
        assert survivors == [], survivors
        proc.wait(timeout=30)
        assert helper.census_leaks(before) == []
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        for pipe in (proc.stdout, proc.stderr):
            try:
                pipe.close()
            except (OSError, ValueError):
                pass
        _reap_marked("census-sleeper")


def test_census_detects_reparented_group_member():
    _require_tools("bash", "sleep")
    helper = _load_helper()
    before = helper.census_snapshot()
    assert before is not None
    # The intermediate shell exits at once, leaving its sleep
    # child reparented away but in the same group: reachable
    # only through the registered group, not the parent chain.
    parent = subprocess.Popen(
        ["bash", "-c", "exec -a reparent-sleeper sleep 60 & exit 0"],
        start_new_session=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    helper.note_owned_group(parent.pid)
    parent.wait(timeout=30)
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            orphans = _proc_cmdlines_containing("reparent-sleeper")
            orphans = [pid for pid in orphans if pid != parent.pid]
            if orphans:
                break
            time.sleep(0.1)
        assert orphans, "reparented sleeper vanished"
        leaks = helper.census_leaks(before)
        assert len(leaks) == 1, leaks
        assert leaks[0].startswith("pid %d " % orphans[0]), leaks
        survivors = helper.reap_owned_strays(before, timeout=10.0)
        assert survivors == [], survivors
        assert helper.census_leaks(before) == []
    finally:
        _reap_marked("reparent-sleeper")


def test_census_session_branch_needs_leadership():
    helper = _load_helper()
    me = os.getpid()
    table = {
        me: (1, me, me, "S"),
        me + 1000000: (1, me + 1000000, me, "S"),
    }
    peer = helper._living_owned_identities(table, me, True, set())
    assert peer == {me + 1000000}, peer
    follower = helper._living_owned_identities(
        table, me, False, set()
    )
    assert follower == set(), follower
    # Zombies never count as owned, in any branch.
    table[me + 1000000] = (1, me + 1000000, me, "Z")
    assert helper._living_owned_identities(
        table, me, True, set()
    ) == set()


def test_session_leader_census_round_trip():
    _require_tools("bash", "sleep")
    harness_dir = os.path.join(REPO_ROOT, "tests", "harness")
    script = (
        "import subprocess, sys, time\n"
        "sys.path.insert(0, %r)\n"
        "import guest_proc\n"
        "before = guest_proc.census_snapshot()\n"
        "assert before is not None, 'leader uncensused'\n"
        "proc = subprocess.Popen(\n"
        "    ['bash', '-c', 'exec -a leader-sleeper sleep 60'],\n"
        "    stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n"
        "guest_proc.note_owned_group(proc.pid)\n"
        "deadline = time.time() + 10\n"
        "leaks = []\n"
        "while time.time() < deadline:\n"
        "    leaks = guest_proc.census_leaks(before)\n"
        "    if leaks:\n"
        "        break\n"
        "    time.sleep(0.1)\n"
        "assert len(leaks) == 1, leaks\n"
        "print('LEAK ' + leaks[0])\n"
        "survivors = guest_proc.reap_owned_strays(before)\n"
        "assert survivors == [], survivors\n"
        "proc.wait(timeout=30)\n"
        "assert guest_proc.census_leaks(before) == []\n"
        "print('LEADER-CLEAN')\n"
        % harness_dir
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        raise AssertionError(
            "leader census hung: %s%s" % (stdout, stderr)
        )
    finally:
        _reap_marked("leader-sleeper")
    assert proc.returncode == 0, (stdout, stderr)
    assert "LEADER-CLEAN" in stdout, (stdout, stderr)


def test_denied_owned_stat_is_unknown_cleanup():
    # Denying one owned child's /proc stat read (enumeration
    # intact) must fail closed: the census is refused (None),
    # never a clean snapshot missing the live child, and a
    # case ending under the denial becomes INFRA_ERROR at
    # CLEANUP instead of PASS.
    _require_tools("sleep")
    helper = _load_helper()
    with _harness_path():
        baseline = helper.census_snapshot()
        assert baseline is not None
        child = subprocess.Popen(["sleep", "120"])
        try:
            deadline = time.time() + 10
            while time.time() < deadline:
                seen = helper.census_snapshot() or frozenset()
                if child.pid in seen:
                    break
                time.sleep(0.1)
            assert child.pid in (
                helper.census_snapshot() or frozenset()
            ), "owned child invisible to the census"
            import builtins

            real_open = builtins.open
            denied = "/proc/%d/stat" % child.pid

            def _denying(path, *args, **kwargs):
                if isinstance(path, str) and path == denied:
                    raise PermissionError("injected stat denial")
                return real_open(path, *args, **kwargs)

            builtins.open = _denying
            try:
                assert helper.census_snapshot() is None
                assert helper.census_leaks(baseline) is None
                rec = _make_recorder(helper, ["test_probe"])
                rec.begin_case("test_probe")
                rec.end_case_pass("test_probe")
                exit_code, lines = _finish_lines(rec)
            finally:
                builtins.open = real_open
            assert exit_code != 0, lines
            _plan, parsed, suite = _parse_emitted(lines)
            assert suite.decision["verdict"] != "PASS", suite.decision
            assert parsed[0].outcome == "INFRA_ERROR", (
                parsed[0].to_dict()
            )
            assert parsed[0].failure_stage == "CLEANUP", (
                parsed[0].to_dict()
            )
            assert parsed[0].cleanup["status"] == "NOT_CHECKED", (
                parsed[0].to_dict()
            )
        finally:
            try:
                child.kill()
            except ProcessLookupError:
                pass
            child.wait()


def test_reap_zombie_children():
    helper = _load_helper()
    # Drain stragglers from earlier tests first: this test
    # counts exactly its own three children.
    helper.reap_zombie_children()
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", "pass"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        for _ignored in range(3)
    ]
    deadline = time.time() + 30
    reaped = 0
    while time.time() < deadline and reaped < 3:
        reaped += helper.reap_zombie_children()
        if reaped < 3:
            time.sleep(0.1)
    for proc in procs:
        try:
            proc.wait(timeout=10)
        except (subprocess.TimeoutExpired, ChildProcessError, OSError):
            pass
        for pipe in (proc.stdout, proc.stderr):
            try:
                pipe.close()
            except (OSError, ValueError):
                pass
    assert reaped == 3, reaped


@contextlib.contextmanager
def _harness_path():
    """Isolate recorder tests: harness import path, no matrix wire env.

    Standalone-identity recorders must never inherit a matrix
    run's MOJOBPF_PLAN_* / MOJOBPF_TARGET_MANIFEST wiring, so
    the wire variables are scrubbed (and restored) here.
    """
    harness_dir = os.path.join(REPO_ROOT, "tests", "harness")
    added = harness_dir not in sys.path
    if added:
        sys.path.insert(0, harness_dir)
    scrubbed = {}
    for var in (
        "MOJOBPF_TARGET_MANIFEST", "MOJOBPF_PLAN_COMMIT",
        "MOJOBPF_PLAN_TOOL",
    ):
        if var in os.environ:
            scrubbed[var] = os.environ.pop(var)
    try:
        yield
    finally:
        os.environ.update(scrubbed)
        if added:
            sys.path.remove(harness_dir)


@pytest.fixture(scope="module", autouse=True)
def _release_subreaper_at_module_end():
    """Restore pre-module subreaper state after this module.

    Recorder flows mark the process a child subreaper, which
    changes orphan reparenting (and zombie ownership) for the
    whole pytest process; later modules must observe the
    pre-module behavior. Clearing here is safe because no
    recorder is mid-flight once this module's tests complete,
    and any later in-process recorder re-asserts the guard at
    construction.
    """
    yield
    release = getattr(_load_helper(), "_release_subreaper", None)
    if release is not None:
        release()


def _make_recorder(helper, case_ids, **kwargs):
    """Build a standalone-identity recorder for this test file."""
    params = {
        "suite_id": "fake-recorder",
        "suite_path": os.path.abspath(__file__),
        "case_ids": list(case_ids),
        "lane_release": "v6.12",
    }
    params.update(kwargs)
    return helper.SuiteRecorder(**params)


def _finish_lines(recorder, **kwargs):
    """Finish a recorder, capturing exit code and printed lines."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        exit_code = recorder.finish(**kwargs)
    return exit_code, buffer.getvalue().splitlines()


def _finish_unrun_lines(recorder, reason):
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        exit_code = recorder.finish_unrun(reason)
    return exit_code, buffer.getvalue().splitlines()


def _parse_emitted(lines):
    """Parse MOJOBPF_* lines into (plan, results, suite) records."""
    plans, results, suites = [], [], []
    for line in lines:
        if line.startswith("MOJOBPF_RUN_PLAN "):
            plans.append(json.loads(line[len("MOJOBPF_RUN_PLAN "):]))
        elif line.startswith("MOJOBPF_CASE_RESULT "):
            results.append(
                json.loads(line[len("MOJOBPF_CASE_RESULT "):])
            )
        elif line.startswith("MOJOBPF_SUITE_RESULT "):
            suites.append(
                json.loads(line[len("MOJOBPF_SUITE_RESULT "):])
            )
    assert len(plans) == 1, lines
    assert len(suites) == 1, lines
    plan = validation_mod.RunPlan.from_dict(plans[0])
    parsed = [
        validation_mod.CaseResult.from_dict(doc) for doc in results
    ]
    suite = validation_mod.SuiteResult.from_dict(suites[0])
    verify_suite_result(suite, plan, parsed)
    return plan, parsed, suite


def test_recorder_rejects_bad_construction():
    helper = _load_helper()

    def build(**kwargs):
        params = {
            "suite_id": "fake-recorder",
            "suite_path": os.path.abspath(__file__),
            "case_ids": ["test_alpha", "test_beta"],
            "lane_release": "v6.12",
        }
        params.update(kwargs)
        return helper.SuiteRecorder(**params)

    for kwargs in (
        {"suite_id": "Bad id!"},
        {"suite_id": ""},
        {"case_ids": []},
        {"case_ids": ["test_alpha", "test_alpha"]},
        {"case_ids": ["nope!"]},
        {"denials": {"test_nope": ("test_alpha", "RUNTIME")}},
        {"denials": {"test_alpha": ("test_alpha", "RUNTIME")}},
        {"denials": {"test_alpha": ("test_beta", "NOPE")}},
        {"denials": {
            "test_alpha": ("test_beta", "RUNTIME"),
            "test_beta": ("test_alpha", "RUNTIME"),
        }},
        {"inputs": {"test_nope": {
            "sources": [], "objects": [], "corpus": []}}},
        {"inputs": {"test_alpha": {"sources": []}}},
        {"inputs": {"test_alpha": {
            "sources": [""], "objects": [], "corpus": []}}},
        {"inputs": {"test_alpha": {
            "sources": ["rel/path"], "objects": [],
            "corpus": []}}},
        {"inputs": {"test_alpha": {
            "sources": [("cache", "x")],
            "objects": [], "corpus": []}}},
    ):
        try:
            build(**kwargs)
        except ValueError:
            pass
        else:
            raise AssertionError(
                "bad construction accepted: %r" % (kwargs,)
            )


def test_recorder_begin_end_protocol():
    helper = _load_helper()
    with _harness_path():
        rec = _make_recorder(helper, ["test_alpha", "test_beta"])
        for thunk in (
            lambda: rec.begin_case("test_nope"),
            lambda: rec.end_case_pass("test_nope"),
            lambda: rec.end_case_pass("test_alpha"),
            lambda: rec.end_case_hint("test_alpha", ("PASS",)),
            lambda: rec.end_case_hint("test_alpha", ("FAIL", "NOPE")),
            lambda: rec.end_case_hint("test_alpha", "PASS"),
            lambda: rec.end_case_hint("test_alpha", 42),
            lambda: rec.end_case_fail("test_alpha", "NOPE"),
            lambda: rec.end_case_infra(
                "test_alpha", "NOPE", "UNKNOWN"),
            lambda: rec.end_case_infra(
                "test_alpha", "INFRA", "NOPE"),
            lambda: rec.end_case_not_run("test_alpha", "NOPE"),
            lambda: rec.note_transcript("", "x"),
        ):
            try:
                thunk()
            except ValueError:
                pass
            else:
                raise AssertionError("bad recorder call accepted")
        rec.begin_case("test_alpha")
        try:
            rec.begin_case("test_alpha")
        except ValueError:
            pass
        else:
            raise AssertionError("double begin accepted")
        rec.end_case_pass("test_alpha")
        try:
            rec.end_case_pass("test_alpha")
        except ValueError:
            pass
        else:
            raise AssertionError("double end accepted")


def test_recorder_pass_emits_verifying_terminal():
    helper = _load_helper()
    source = os.path.abspath(__file__)
    with _harness_path():
        rec = _make_recorder(
            helper, ["test_alpha", "test_denial"],
            denials={"test_denial": ("test_alpha", "VERIFY")},
            inputs={
                "test_alpha": {
                    "sources": [source], "objects": [source],
                    "corpus": [source],
                },
                "test_denial": {
                    "sources": [source], "objects": [],
                    "corpus": [source],
                },
            },
        )
        rec.begin_case("test_alpha")
        rec.note_transcript("guest", "guest did work")
        rec.end_case_pass("test_alpha")
        rec.begin_case("test_denial")
        rec.end_case_hint("test_denial", ("FAIL", "VERIFY"))
        exit_code, lines = _finish_lines(rec)
    assert exit_code == 0, lines
    plan, parsed, suite = _parse_emitted(lines)
    assert len(parsed) == 2
    assert suite.decision["verdict"] == "PASS", suite.decision
    assert plan.revisions["tool"] == "standalone"
    assert len(plan.revisions["repository_commit"]) == 40
    by_case = {result.case_id: result for result in parsed}
    assert by_case["test_alpha"].outcome == "PASS"
    assert by_case["test_denial"].outcome == "FAIL"
    assert suite.attempts_preserved == 2


def test_recorder_fail_drives_exit_1():
    helper = _load_helper()
    with _harness_path():
        rec = _make_recorder(helper, ["test_alpha"])
        rec.begin_case("test_alpha")
        rec.end_case_fail("test_alpha")
        exit_code, lines = _finish_lines(rec)
    assert exit_code == 1, lines
    _plan, _parsed, suite = _parse_emitted(lines)
    assert suite.decision["verdict"] == "FAIL", suite.decision


def test_recorder_infra_abort_fills_not_run():
    helper = _load_helper()
    with _harness_path():
        rec = _make_recorder(
            helper, ["test_one", "test_two", "test_three"]
        )
        rec.begin_case("test_one")
        rec.end_case_infra("test_one", "INFRA", "UNKNOWN")
        exit_code, lines = _finish_lines(rec)
    assert exit_code == 2, lines
    _plan, parsed, suite = _parse_emitted(lines)
    assert suite.decision["verdict"] == "INCOMPLETE"
    by_case = {result.case_id: result for result in parsed}
    assert by_case["test_one"].outcome == "INFRA_ERROR"
    assert by_case["test_two"].outcome == "NOT_RUN"
    assert by_case["test_two"].cleanup["status"] == "NOT_CHECKED"
    assert by_case["test_three"].outcome == "NOT_RUN"


def test_recorder_denial_needs_failure_hint():
    helper = _load_helper()
    with _harness_path():
        rec = _make_recorder(
            helper, ["test_positive", "test_denial"],
            denials={"test_denial": ("test_positive", "VERIFY")},
        )
        rec.begin_case("test_positive")
        rec.end_case_pass("test_positive")
        rec.begin_case("test_denial")
        # No hint: the denial observed nothing failing, which
        # can never satisfy its expectation (loud author
        # error, not a silent PASS).
        for bad in (None, ("PASS", None)):
            try:
                rec.end_case_hint("test_denial", bad)
            except ValueError:
                pass
            else:
                raise AssertionError(
                    "denial accepted hint %r" % (bad,)
                )
        try:
            rec.end_case_pass("test_denial")
        except ValueError:
            pass
        else:
            raise AssertionError("denial accepted end_case_pass")


def test_recorder_denial_exception_cannot_satisfy():
    helper = _load_helper()
    with _harness_path():
        rec = _make_recorder(
            helper, ["test_positive", "test_denial"],
            denials={"test_denial": ("test_positive", "VERIFY")},
        )
        rec.begin_case("test_positive")
        rec.end_case_pass("test_positive")
        rec.begin_case("test_denial")
        # The proof broke (assert mismatch): recorded at
        # TEST_RUN, which can never equal the pinned wire
        # stage, so the denial cell fails typed.
        rec.end_case_fail("test_denial")
        exit_code, lines = _finish_lines(rec)
    assert exit_code == 1, lines
    _plan, parsed, suite = _parse_emitted(lines)
    assert suite.decision["verdict"] == "FAIL", suite.decision
    by_case = {result.case_id: result for result in parsed}
    assert by_case["test_denial"].failure_stage == "TEST_RUN"


def test_recorder_leak_poisons_pass_and_reaps():
    _require_tools("bash", "sleep")
    helper = _load_helper()
    with _harness_path():
        rec = _make_recorder(helper, ["test_alpha"])
        rec.begin_case("test_alpha")
        proc = subprocess.Popen(
            ["bash", "-c", "exec -a leak-sleeper sleep 60"],
            start_new_session=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        helper.note_owned_group(proc.pid)
        try:
            rec.end_case_pass("test_alpha")
            exit_code, lines = _finish_lines(rec)
        finally:
            try:
                proc.kill()
            except OSError:
                pass
            for pipe in (proc.stdout, proc.stderr):
                try:
                    pipe.close()
                except (OSError, ValueError):
                    pass
            _reap_marked("leak-sleeper")
    assert exit_code == 1, lines
    _plan, parsed, suite = _parse_emitted(lines)
    assert suite.decision["verdict"] == "FAIL", suite.decision
    assert parsed[0].outcome == "INFRA_ERROR"
    assert parsed[0].failure_stage == "CLEANUP"
    assert parsed[0].cleanup["status"] == "RESIDUE"
    assert "(gone at finish)" in parsed[0].cleanup["residue"][0]


def test_recorder_uncensused_is_not_clean():
    helper = _load_helper()
    real_snapshot = helper.census_snapshot
    helper.census_snapshot = lambda: None
    try:
        with _harness_path():
            rec = _make_recorder(helper, ["test_alpha"])
            rec.begin_case("test_alpha")
            rec.end_case_pass("test_alpha")
            exit_code, lines = _finish_lines(rec)
    finally:
        helper.census_snapshot = real_snapshot
    assert exit_code == 2, lines
    _plan, parsed, suite = _parse_emitted(lines)
    assert suite.decision["verdict"] == "INCOMPLETE"
    assert parsed[0].outcome == "INFRA_ERROR"
    assert parsed[0].cleanup["status"] == "NOT_CHECKED"


def test_recorder_finish_unrun():
    helper = _load_helper()
    with _harness_path():
        rec = _make_recorder(helper, ["test_alpha", "test_beta"])
        exit_code, lines = _finish_unrun_lines(
            rec, "must not run under python -O (asserts stripped)"
        )
    assert exit_code == 2, lines
    assert lines[0].startswith("REFUSED: "), lines
    _plan, parsed, suite = _parse_emitted(lines)
    assert suite.decision["verdict"] == "INCOMPLETE"
    for result in parsed:
        assert result.outcome == "NOT_RUN"
        assert result.applicability == "TOOLCHAIN_UNAVAILABLE"
        assert result.cleanup["status"] == "NOT_CHECKED"


def test_recorder_finish_unrun_under_dash_O():
    harness_dir = os.path.join(REPO_ROOT, "tests", "harness")
    script = (
        "import sys\n"
        "sys.path.insert(0, %r)\n"
        "import guest_proc\n"
        "rec = guest_proc.SuiteRecorder(\n"
        "    suite_id='fake-dash-o',\n"
        "    suite_path=%r,\n"
        "    case_ids=['test_alpha'],\n"
        "    lane_release='v6.12')\n"
        "sys.exit(rec.finish_unrun('must not run under python -O'))\n"
        % (harness_dir, os.path.abspath(__file__))
    )
    env = {
        key: value for key, value in os.environ.items()
        if key not in (
            "MOJOBPF_TARGET_MANIFEST", "MOJOBPF_PLAN_COMMIT",
            "MOJOBPF_PLAN_TOOL",
        )
    }
    proc = subprocess.run(
        [sys.executable, "-O", "-c", script],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=120, env=env,
    )
    assert proc.returncode == 2, (proc.returncode, proc.stderr[-500:])
    assert "MOJOBPF_SUITE_RESULT " in proc.stdout, proc.stdout[-500:]
    _plan, parsed, suite = _parse_emitted(
        proc.stdout.splitlines()
    )
    assert suite.decision["verdict"] == "INCOMPLETE"
    assert parsed[0].outcome == "NOT_RUN"


def test_injected_xdp_env_record_replays_infra_error():
    helper = _load_helper()
    record = {
        "_harness_exit": 3,
        "classification": "environment",
        "stage": "load",
        "contract_version": 2,
        "note": "load denied (permission substrings in output)",
    }
    source = os.path.abspath(__file__)
    with _harness_path():
        rec = _make_recorder(
            helper, ["test_base_packet_actions"],
            inputs={"test_base_packet_actions": {
                "sources": [source], "objects": [],
                "corpus": [source]}},
        )
        rec.begin_case("test_base_packet_actions")
        try:
            try:
                helper.check_harness_exit(
                    "base-drop", exit=record["_harness_exit"],
                    classification=record["classification"],
                    stage=record["stage"],
                    contract_version=record["contract_version"],
                    note=record["note"], expect=0)
            except AssertionError:
                raise AssertionError(
                    "env record collapsed into AssertionError"
                )
        except helper.HarnessEnvironment as exc:
            rec.end_case_infra(
                "test_base_packet_actions", exc.stage,
                exc.availability)
        exit_code, lines = _finish_lines(rec)
    assert exit_code == 2, lines
    _plan, parsed, suite = _parse_emitted(lines)
    assert suite.decision["verdict"] == "INCOMPLETE"
    assert parsed[0].outcome == "INFRA_ERROR"
    assert parsed[0].applicability == "POLICY_DENIED"
    assert parsed[0].failure_stage == "LOAD"


def _write_executable(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o755)


def _sha256_of(path):
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _harness_base_args(root, token, owned_root, fake, version):
    obj = os.path.join(root, "obj.bpf.o")
    with open(obj, "wb") as handle:
        handle.write(b"\x7fELF-fake-object")
    return [
        sys.executable,
        os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py"),
        "--object", obj,
        "--expect-action", "1",
        "--repeat", "3",
        "--pin-path", os.path.join(owned_root, token, "pin"),
        "--ownership-token", token,
        "--owned-root", owned_root,
        "--bpftool", fake,
        "--bpftool-sha256", _sha256_of(fake),
        "--bpftool-version", version,
        "--timeout", "30",
    ]


def _run_harness_censused(argv, census_dir):
    env = dict(os.environ)
    env["TMPDIR"] = census_dir
    # The censused runs execute against a fake bpftool owned by
    # this test, so the target lease is granted here; the
    # missing-lease refusal has its own regression test below.
    env["MOJOBPF_TARGET_LEASE"] = "1"
    proc = subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=120, env=env,
    )
    leftovers = sorted(
        name for name in os.listdir(census_dir)
        if name.startswith("bpf_test_run_")
    )
    return proc, leftovers


def test_harness_cleans_generated_frame_on_probe_failure():
    root = tempfile.mkdtemp(prefix="owned-n2-probe-")
    try:
        census_dir = os.path.join(root, "tmp")
        owned_root = os.path.join(root, "owned")
        os.makedirs(census_dir)
        os.makedirs(os.path.join(owned_root, "n2tok"))
        fake = os.path.join(root, "fake_bpftool.sh")
        _write_executable(fake, "#!/bin/sh\nexit 1\n")
        argv = _harness_base_args(
            root, "n2tok", owned_root, fake, "fake 0.0"
        )
        proc, leftovers = _run_harness_censused(argv, census_dir)
        assert proc.returncode == 3, (proc.returncode, proc.stderr[-500:])
        record = json.loads(proc.stdout)
        assert record["classification"] == "environment", record
        assert record["stage"] == "setup", record
        assert record["note"] == "bpftool version failed", record
        assert record["contract_version"] == 2, record
        assert leftovers == [], leftovers
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_harness_cleans_generated_frame_on_load_failure():
    root = tempfile.mkdtemp(prefix="owned-n2-load-")
    try:
        census_dir = os.path.join(root, "tmp")
        owned_root = os.path.join(root, "owned")
        os.makedirs(census_dir)
        os.makedirs(os.path.join(owned_root, "n2tok"))
        fake = os.path.join(root, "fake_bpftool.py")
        _write_executable(
            fake,
            "#!%s\nimport sys\n"
            "if sys.argv[1:] == ['version']:\n"
            "    print('fake 0.0')\n"
            "else:\n"
            "    sys.stderr.write(\n"
            "        'libbpf: prog load rejected by verifier')\n"
            "    sys.exit(1)\n" % sys.executable,
        )
        argv = _harness_base_args(
            root, "n2tok", owned_root, fake, "fake 0.0"
        )
        proc, leftovers = _run_harness_censused(argv, census_dir)
        assert proc.returncode == 4, (proc.returncode, proc.stderr[-500:])
        record = json.loads(proc.stdout)
        assert record["classification"] == "verifier", record
        assert leftovers == [], leftovers
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_harness_cleans_nothing_when_nothing_generated():
    # Control paths: setup refuses before generation (missing
    # object, wrong bpftool pin) with setup/6, or skips
    # generation (caller data) and fails the version probe with
    # setup/environment/3; all leave no frame residue.
    root = tempfile.mkdtemp(prefix="owned-n2-ctl-")
    try:
        census_dir = os.path.join(root, "tmp")
        owned_root = os.path.join(root, "owned")
        os.makedirs(census_dir)
        os.makedirs(os.path.join(owned_root, "n2tok"))
        fake = os.path.join(root, "fake_bpftool.sh")
        _write_executable(fake, "#!/bin/sh\nexit 1\n")
        argv = _harness_base_args(
            root, "n2tok", owned_root, fake, "fake 0.0"
        )
        argv[argv.index("--object") + 1] = os.path.join(
            root, "no-such-object.bpf.o"
        )
        proc, leftovers = _run_harness_censused(argv, census_dir)
        assert proc.returncode == 6, (proc.returncode, proc.stderr[-500:])
        assert "object file not found" in proc.stdout, proc.stdout[-300:]
        assert leftovers == [], leftovers
        argv = _harness_base_args(
            root, "n2tok", owned_root, fake, "fake 0.0"
        )
        argv[argv.index("--bpftool-sha256") + 1] = "0" * 64
        proc, leftovers = _run_harness_censused(argv, census_dir)
        assert proc.returncode == 6, (proc.returncode, proc.stderr[-500:])
        assert "admission refused" in proc.stdout, proc.stdout[-300:]
        assert leftovers == [], leftovers
        data_in = os.path.join(root, "data.bin")
        with open(data_in, "wb") as handle:
            handle.write(b"\x00" * 60)
        argv = _harness_base_args(
            root, "n2tok", owned_root, fake, "fake 0.0"
        ) + ["--data-in", data_in]
        proc, leftovers = _run_harness_censused(argv, census_dir)
        assert proc.returncode == 3, (proc.returncode, proc.stderr[-500:])
        assert leftovers == [], leftovers
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _load_matrix_runner():
    spec = importlib.util.spec_from_file_location(
        "matrix_runner_probe",
        os.path.join(REPO_ROOT, "ci", "run_vm_tests.py"),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_harness():
    spec = importlib.util.spec_from_file_location(
        "bpf_test_run_probe",
        os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py"),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sealed_plan_ignores_posthoc_denial():
    # The plan seals before execution: a denial added after the
    # cases ran must not flip a FAIL into a PASS.
    helper = _load_helper()
    source = os.path.abspath(__file__)
    inputs = {
        case: {"sources": [source], "objects": [], "corpus": []}
        for case in ("test_first", "test_second")
    }
    with _harness_path():
        rec = _make_recorder(
            helper, ["test_first", "test_second"], inputs=inputs
        )
        rec.begin_case("test_first")
        rec.end_case_pass("test_first")
        rec.begin_case("test_second")
        rec.end_case_fail("test_second", "LOAD")
        rec.denials["test_second"] = ("test_first", "LOAD")
        exit_code, lines = _finish_lines(rec)
    assert exit_code == 1, lines
    plan, parsed, suite = _parse_emitted(lines)
    assert suite.decision["verdict"] == "FAIL", suite.decision
    by_case = {case.case_id: case for case in plan.cases}
    assert by_case["test_second"].expectation == "positive"
    assert by_case["test_first"].expectation == "positive"


def test_post_completion_object_swap_fails_closed():
    # A staged object swapped after case completion must fail
    # closed: the case attests FAIL at TEST_RUN (never the
    # replacement digest with PASS) and the terminal is FAIL.
    # An unswapped control run still passes.
    helper = _load_helper()
    source = os.path.abspath(__file__)
    stage = helper.owned_stage(prefix="reseal-probe-")
    try:
        target = os.path.join(stage, "probe.bpf.o")
        with open(target, "wb") as handle:
            handle.write(b"original-object-bytes-v1")
        inputs = {
            "test_probe": {
                "sources": [source],
                "objects": [("stage", "probe.bpf.o")],
                "corpus": [],
            }
        }
        with _harness_path():
            rec = _make_recorder(
                helper, ["test_probe"], inputs=inputs
            )
            rec.begin_case("test_probe")
            rec.end_case_pass("test_probe")
            with open(target, "wb") as handle:
                handle.write(b"replacement-object-bytes-v2")
            exit_code, lines = _finish_lines(rec, stage_dir=stage)
        assert exit_code == 1, lines
        _plan, parsed, suite = _parse_emitted(lines)
        assert suite.decision["verdict"] == "FAIL", suite.decision
        assert parsed[0].outcome == "FAIL", parsed[0].to_dict()
        assert parsed[0].failure_stage == "TEST_RUN", (
            parsed[0].to_dict()
        )
        assert parsed[0].cleanup["status"] == "RESIDUE", (
            parsed[0].to_dict()
        )
        assert any(
            "changed after seal" in entry
            for entry in parsed[0].cleanup["residue"]
        ), parsed[0].to_dict()
    finally:
        helper.discard_owned_stages()
        shutil.rmtree(stage, ignore_errors=True)
    control = helper.owned_stage(prefix="reseal-control-")
    try:
        target = os.path.join(control, "probe.bpf.o")
        with open(target, "wb") as handle:
            handle.write(b"stable-object-bytes")
        inputs = {
            "test_probe": {
                "sources": [source],
                "objects": [("stage", "probe.bpf.o")],
                "corpus": [],
            }
        }
        with _harness_path():
            rec = _make_recorder(
                helper, ["test_probe"], inputs=inputs
            )
            rec.begin_case("test_probe")
            rec.end_case_pass("test_probe")
            exit_code, lines = _finish_lines(rec, stage_dir=control)
        assert exit_code == 0, lines
        _plan, parsed, suite = _parse_emitted(lines)
        assert suite.decision["verdict"] == "PASS", suite.decision
    finally:
        helper.discard_owned_stages()
        shutil.rmtree(control, ignore_errors=True)


def test_empty_backed_inputs_digest_empty_and_matrix_rejects():
    # Declared-but-empty input classes digest to the empty-input
    # hash, so a PASS over them fails the matrix no-op rule.
    helper = _load_helper()
    runner = _load_matrix_runner()
    root = tempfile.mkdtemp(prefix="empty-inputs-")
    try:
        empty = os.path.join(root, "empty.bin")
        with open(empty, "wb") as handle:
            pass
        lane = {
            "id": "probe-lane",
            "release": "v9.99",
            "accelerator": "tcg",
            "kernel_release": "9.99-probe",
        }
        manifest = runner.lane_target_manifest(lane)
        commit = "c" * 40
        with _harness_path():
            rec = _make_recorder(
                helper, ["test_probe"],
                inputs={"test_probe": {
                    "sources": [empty], "objects": [],
                    "corpus": []}},
                revisions={
                    "repository_commit": commit,
                    "package": "mojobpf@" + commit,
                    "tool": "run_vm_tests",
                },
                target_manifest=manifest,
            )
            rec.begin_case("test_probe")
            rec.end_case_pass("test_probe")
            exit_code, lines = _finish_lines(rec)
        plan, _parsed, _suite = _parse_emitted(lines)
        assert (
            plan.cases[0].source_sha256 == helper.EMPTY_SHA256
        ), plan.cases[0].source_sha256
        output = "\n".join(lines) + "\n"
        outcome, note, _detail = runner.accept_suite_output(
            "fake-recorder", ["test_probe"], output, exit_code,
            commit, manifest, _sha256_of(os.path.abspath(__file__)),
            {},
        )
        assert outcome == "fail", (outcome, note)
        assert "no-op workload" in note, note
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_setsid_escape_is_residue_not_clean():
    # A setsid escapee (new session and group, pipes closed)
    # reparents to the subreaper suite and poisons its case;
    # the escapee is killed and reaped before this returns.
    helper = _load_helper()
    marker = "setsid-escape-probe-%d" % os.getpid()
    code = (
        "import os, time\n"
        "marker = %r\n"
        "pid = os.fork()\n"
        "if pid != 0:\n"
        "    os._exit(0)\n"
        "os.setsid()\n"
        "for fd in (0, 1, 2):\n"
        "    try:\n"
        "        os.close(fd)\n"
        "    except OSError:\n"
        "        pass\n"
        "time.sleep(60)\n" % marker
    )
    with _harness_path():
        rec = _make_recorder(helper, ["test_alpha"])
        rec.begin_case("test_alpha")
        proc = subprocess.Popen(
            [sys.executable, "-c", code],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, start_new_session=True,
        )
        try:
            proc.wait(timeout=30)
            deadline = time.time() + 10
            orphans = []
            while time.time() < deadline:
                orphans = _proc_cmdlines_containing(marker)
                orphans = [
                    pid for pid in orphans if pid != proc.pid
                ]
                if orphans:
                    break
                time.sleep(0.1)
            assert orphans, "escapee vanished before the census"
            rec.end_case_pass("test_alpha")
            exit_code, lines = _finish_lines(rec)
        finally:
            for pipe in (proc.stdout, proc.stderr):
                try:
                    pipe.close()
                except (OSError, ValueError):
                    pass
            deadline = time.time() + 10
            while time.time() < deadline:
                _reap_marked(marker)
                helper.reap_zombie_children()
                if not _proc_cmdlines_containing(marker):
                    break
                time.sleep(0.1)
            assert not _proc_cmdlines_containing(marker), marker
    assert exit_code == 1, lines
    _plan, parsed, suite = _parse_emitted(lines)
    assert suite.decision["verdict"] == "FAIL", suite.decision
    assert parsed[0].cleanup["status"] == "RESIDUE", (
        parsed[0].cleanup
    )


def test_recorder_without_subreaper_guard_is_not_checked():
    # Fail-closed guard: a run that cannot set the subreaper
    # cannot rule out a setsid escape, so its censuses read
    # uncensused instead of CLEAN.
    helper = _load_helper()
    real_ensure = helper._ensure_subreaper
    helper._ensure_subreaper = lambda: False
    try:
        with _harness_path():
            rec = _make_recorder(helper, ["test_alpha"])
            rec.begin_case("test_alpha")
            rec.end_case_pass("test_alpha")
            exit_code, lines = _finish_lines(rec)
    finally:
        helper._ensure_subreaper = real_ensure
    assert exit_code == 2, lines
    _plan, parsed, suite = _parse_emitted(lines)
    assert suite.decision["verdict"] == "INCOMPLETE", (
        suite.decision
    )
    assert parsed[0].outcome == "INFRA_ERROR", parsed[0].outcome
    assert parsed[0].cleanup["status"] == "NOT_CHECKED", (
        parsed[0].cleanup
    )


def test_unavailable_final_reaping_withdraws_clean():
    # Final hygiene that cannot be observed withdraws earlier
    # CLEAN claims instead of reporting them.
    helper = _load_helper()
    with _harness_path():
        rec = _make_recorder(helper, ["test_alpha"])
        rec.begin_case("test_alpha")
        rec.end_case_pass("test_alpha")
        assert (
            rec._cases["test_alpha"]["cleanup"]["status"]
            == "CLEAN"
        )
        rec._reap_and_annotate = lambda: None
        exit_code, lines = _finish_lines(rec)
    assert exit_code == 2, lines
    _plan, parsed, suite = _parse_emitted(lines)
    assert suite.decision["verdict"] == "INCOMPLETE", (
        suite.decision
    )
    assert parsed[0].outcome == "INFRA_ERROR", parsed[0].outcome
    assert parsed[0].failure_stage == "CLEANUP", (
        parsed[0].failure_stage
    )
    assert parsed[0].cleanup["status"] == "NOT_CHECKED", (
        parsed[0].cleanup
    )


def test_denied_proc_enumeration_is_not_clean():
    # /proc present but unreadable (or listing nothing, not even
    # this process) is uncensused, never an empty clean census.
    helper = _load_helper()
    real_listdir = os.listdir

    def _denied(path):
        if path == "/proc":
            raise PermissionError("injected enumeration denial")
        return real_listdir(path)

    def _empty(path):
        if path == "/proc":
            return []
        return real_listdir(path)

    try:
        os.listdir = _denied
        assert helper.census_snapshot() is None
        os.listdir = _empty
        assert helper.census_snapshot() is None
        assert helper.census_leaks(frozenset()) is None
    finally:
        os.listdir = real_listdir


def test_vng_boot_without_lease_refuses_before_spawn():
    # Guest boots without a target lease refuse before any
    # process starts; non-guest commands still run unleased.
    helper = _load_helper()
    stage = tempfile.mkdtemp(prefix="lease-probe-")
    saved = os.environ.pop("MOJOBPF_TARGET_LEASE", None)
    real_popen = helper.subprocess.Popen

    def _forbidden(*args, **kwargs):
        raise AssertionError(
            "spawned without a lease: %r" % (args,)
        )

    helper.subprocess.Popen = _forbidden
    try:
        try:
            helper.run_owned(
                ["vng", "--run", "v9.99", "--exec", "true"],
                stage, 60,
            )
        except helper.TargetLeaseRequired as exc:
            assert "MOJOBPF_TARGET_LEASE" in str(exc), exc
        else:
            raise AssertionError(
                "vng boot without a lease was not refused"
            )
        helper.subprocess.Popen = real_popen
        code, _output = helper.run_owned(
            [sys.executable, "-c", "pass"], stage, 60,
            log_name="control.log",
        )
        assert code == 0, code
    finally:
        helper.subprocess.Popen = real_popen
        if saved is not None:
            os.environ["MOJOBPF_TARGET_LEASE"] = saved
        shutil.rmtree(stage, ignore_errors=True)


def test_harness_load_without_lease_refuses():
    # bpf_test_run refuses before the load without a target
    # lease: no load command runs and the record is a setup
    # refusal, never a pass.
    harness = _load_harness()
    root = tempfile.mkdtemp(prefix="lease-harness-")
    try:
        owned_root = os.path.join(root, "owned")
        os.makedirs(os.path.join(owned_root, "ltok"))
        obj = os.path.join(root, "obj.bpf.o")
        with open(obj, "wb") as handle:
            handle.write(b"\x7fELF-fake-object")
        data_in = os.path.join(root, "data.bin")
        with open(data_in, "wb") as handle:
            handle.write(b"\x00" * 60)
        fake = os.path.join(root, "fake_bpftool.py")
        _write_executable(
            fake,
            "#!%s\nimport sys\n"
            "if sys.argv[1:] == ['version']:\n"
            "    print('fake 0.0')\n"
            "else:\n"
            "    print('Return value: 1')\n" % sys.executable,
        )
        out = os.path.join(root, "out.json")
        argv = [
            "--object", obj, "--expect-action", "1",
            "--data-in", data_in,
            "--pin-path", os.path.join(owned_root, "ltok", "pin"),
            "--ownership-token", "ltok", "--owned-root", owned_root,
            "--bpftool", fake, "--bpftool-sha256", _sha256_of(fake),
            "--bpftool-version", "fake 0.0",
            "--output", out, "--timeout", "30",
        ]
        calls = []
        real_run_command = harness.run_command

        def _spy(argv_, timeout):
            calls.append(list(argv_))
            return real_run_command(argv_, timeout)

        harness.run_command = _spy
        saved = os.environ.pop("MOJOBPF_TARGET_LEASE", None)
        try:
            code = harness.main(argv)
        finally:
            harness.run_command = real_run_command
            if saved is not None:
                os.environ["MOJOBPF_TARGET_LEASE"] = saved
        assert code == 6, (code, calls)
        with open(out, encoding="utf-8") as handle:
            record = json.loads(handle.read())
        assert record["classification"] == "setup", record
        assert "target lease" in (record["note"] or ""), record
        assert not any("load" in call for call in calls), calls
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _tmp_xdp_stages():
    return set(
        name for name in os.listdir("/tmp")
        if name.startswith("mojo-xdp-")
    )


def _clear_tmp_xdp_stages(before):
    for name in sorted(_tmp_xdp_stages() - before):
        shutil.rmtree(
            os.path.join("/tmp", name), ignore_errors=True
        )


def test_xdp_build_failure_discards_stages():
    # Injected frontend rejection: every attempt's stage is
    # discarded at finish; none survive in /tmp.
    suite = _load_suite("tests/kernel/test_mojo_xdp.py")
    before = _tmp_xdp_stages()
    real_build = suite.build_object
    real_which = suite.shutil.which
    suite.shutil.which = lambda tool: "/fake/" + tool

    def _rejected(source, workdir, name):
        raise AssertionError("injected frontend rejection")

    suite.build_object = _rejected
    saved_cache = dict(suite._CACHED)
    suite._CACHED.clear()
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer):
            code = suite.main()
    finally:
        suite.build_object = real_build
        suite.shutil.which = real_which
        suite._CACHED.clear()
        suite._CACHED.update(saved_cache)
    leftover = _tmp_xdp_stages() - before
    _clear_tmp_xdp_stages(before)
    assert code == 1, (code, buffer.getvalue()[-500:])
    assert not leftover, sorted(leftover)


def test_xdp_finish_discards_cached_stage():
    # A successful finish removes the cached guest stage once
    # the terminal record is emitted.
    suite = _load_suite("tests/kernel/test_mojo_xdp.py")
    helper = suite.guest_proc
    mkstage = getattr(helper, "owned_stage", tempfile.mkdtemp)
    names = sorted(
        key for key in vars(suite) if key.startswith("test_")
    )
    with _harness_path():
        rec = helper.SuiteRecorder(
            suite_id="kernel-xdp", suite_path=suite.__file__,
            case_ids=names, lane_release="v6.12")
        for name in names:
            rec.begin_case(name)
            rec.end_case_pass(name)
        stage = mkstage(prefix="mojo-xdp-probe-")
        assert os.path.isdir(stage)
        saved_cache = dict(suite._CACHED)
        suite._CACHED["run"] = {
            "stage": stage, "output": "probe transcript",
        }
        buffer = io.StringIO()
        try:
            with contextlib.redirect_stdout(buffer):
                code = suite._finish(rec)
            assert code == 0, (code, buffer.getvalue()[-500:])
            assert not os.path.isdir(stage), stage
        finally:
            suite._CACHED.clear()
            suite._CACHED.update(saved_cache)
            shutil.rmtree(stage, ignore_errors=True)


def test_failed_stage_deletion_fails_the_terminal():
    # A stage removal failure lands in the terminal (never a
    # PASS with forgotten residue): the last case carries the
    # residue, the verdict is not PASS, and the failed stage
    # stays registered for the post-finish retry.
    helper = _load_helper()
    stage = helper.owned_stage(prefix="teardown-probe-")
    assert os.path.isdir(stage)
    with _harness_path():
        rec = _make_recorder(helper, ["test_probe"])
        rec.begin_case("test_probe")
        rec.end_case_pass("test_probe")
        real_rmtree = shutil.rmtree

        def _refusing(path, *args, **kwargs):
            if os.path.abspath(path) == os.path.abspath(stage):
                raise PermissionError("injected removal refusal")
            return real_rmtree(path, *args, **kwargs)

        shutil.rmtree = _refusing
        try:
            exit_code, lines = _finish_lines(rec)
        finally:
            shutil.rmtree = real_rmtree
    assert exit_code != 0, lines
    _plan, parsed, suite = _parse_emitted(lines)
    assert suite.decision["verdict"] != "PASS", suite.decision
    assert parsed[0].outcome == "INFRA_ERROR", parsed[0].to_dict()
    assert parsed[0].failure_stage == "CLEANUP", parsed[0].to_dict()
    assert parsed[0].cleanup["status"] == "RESIDUE", (
        parsed[0].to_dict()
    )
    assert any(
        stage in entry for entry in parsed[0].cleanup["residue"]
    ), parsed[0].to_dict()
    assert stage in helper._OWNED_STAGES, "failed stage forgotten"
    assert os.path.isdir(stage), "failed stage vanished anyway"
    # The post-finish retry still removes it.
    helper.discard_owned_stages()
    assert not os.path.isdir(stage), stage
    assert stage not in helper._OWNED_STAGES


def test_failed_packet_unlink_is_cleanup_error():
    # A refused packet unlink fails the run as a cleanup error
    # (environment/unload), never pass with cleanup_ok.
    harness = _load_harness()
    root = tempfile.mkdtemp(prefix="packet-unlink-")
    try:
        owned_root = os.path.join(root, "owned")
        os.makedirs(os.path.join(owned_root, "ptok"))
        obj = os.path.join(root, "obj.bpf.o")
        with open(obj, "wb") as handle:
            handle.write(b"\x7fELF-fake-object")
        fake = os.path.join(root, "fake_bpftool.py")
        _write_executable(
            fake,
            "#!%s\nimport sys\n"
            "if sys.argv[1:] == ['version']:\n"
            "    print('fake 0.0')\n"
            "else:\n"
            "    print('Return value: 2')\n" % sys.executable,
        )
        out = os.path.join(root, "out.json")
        census_dir = os.path.join(root, "tmp")
        os.makedirs(census_dir)
        argv = [
            "--object", obj, "--expect-action", "2",
            "--pin-path", os.path.join(owned_root, "ptok", "pin"),
            "--ownership-token", "ptok", "--owned-root", owned_root,
            "--bpftool", fake, "--bpftool-sha256", _sha256_of(fake),
            "--bpftool-version", "fake 0.0",
            "--output", out, "--timeout", "30",
        ]
        real_unlink = os.unlink

        def _refusing(path):
            if os.path.basename(path).startswith("bpf_test_run_"):
                raise PermissionError("injected unlink refusal")
            return real_unlink(path)

        saved_env = dict(os.environ)
        os.environ["TMPDIR"] = census_dir
        os.unlink = _refusing
        try:
            with _simulated_admission_env():
                code = harness.main(argv)
        finally:
            os.unlink = real_unlink
            os.environ.clear()
            os.environ.update(saved_env)
        assert code == 3, code
        with open(out, encoding="utf-8") as handle:
            record = json.loads(handle.read())
        assert record["classification"] == "environment", record
        assert record["stage"] == "unload", record
        assert record["cleanup_ok"] is False, record
        assert "unlink failed" in (record["note"] or ""), record
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_negative_path_packet_unlink_is_cleanup_error():
    # An action mismatch with a refused packet unlink reports
    # the cleanup error (environment/unload, exit 3), never a
    # consumable runtime negative with cleanup_ok: the owned
    # packet unlinks before ANY terminal, and the residue
    # cannot satisfy an expected denial.
    helper = _load_helper()
    harness = _load_harness()
    root = tempfile.mkdtemp(prefix="packet-unlink-neg-")
    try:
        owned_root = os.path.join(root, "owned")
        os.makedirs(os.path.join(owned_root, "ntok"))
        obj = os.path.join(root, "obj.bpf.o")
        with open(obj, "wb") as handle:
            handle.write(b"\x7fELF-fake-object")
        fake = os.path.join(root, "fake_bpftool.py")
        _write_executable(
            fake,
            "#!%s\nimport sys\n"
            "if sys.argv[1:] == ['version']:\n"
            "    print('fake 0.0')\n"
            "else:\n"
            "    print('Return value: 7')\n" % sys.executable,
        )
        out = os.path.join(root, "out.json")
        census_dir = os.path.join(root, "tmp")
        os.makedirs(census_dir)
        argv = [
            "--object", obj, "--expect-action", "4",
            "--pin-path", os.path.join(owned_root, "ntok", "pin"),
            "--ownership-token", "ntok", "--owned-root", owned_root,
            "--bpftool", fake, "--bpftool-sha256", _sha256_of(fake),
            "--bpftool-version", "fake 0.0",
            "--output", out, "--timeout", "30",
        ]
        real_unlink = os.unlink

        def _refusing(path):
            if os.path.basename(path).startswith("bpf_test_run_"):
                raise PermissionError("injected unlink refusal")
            return real_unlink(path)

        saved_env = dict(os.environ)
        os.environ["TMPDIR"] = census_dir
        os.unlink = _refusing
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                with _simulated_admission_env():
                    code = harness.main(argv)
        finally:
            os.unlink = real_unlink
            os.environ.clear()
            os.environ.update(saved_env)
        assert code == 3, (code, err.getvalue()[-500:])
        with open(out, encoding="utf-8") as handle:
            record = json.loads(handle.read())
        assert record["classification"] == "environment", record
        assert record["stage"] == "unload", record
        assert record["cleanup_ok"] is False, record
        assert "unlink failed" in (record["note"] or ""), record
        # The stale-object denial shape must not consume this
        # record as its expected negative: it raises into the
        # infrastructure bucket instead of returning a FAIL
        # hint at a wire stage.
        try:
            helper.check_harness_exit(
                "stale-object", exit=code,
                classification=record["classification"],
                stage=record["stage"],
                contract_version=record["contract_version"],
                note=record["note"], expect=1)
        except helper.HarnessEnvironment as exc:
            assert exc.stage == "CLEANUP", exc.stage
        else:
            raise AssertionError(
                "unlink failure was consumable as a negative"
            )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_uprobe_invalid_lane_emits_terminal():
    # An invalid lane refuses with a typed all-NOT_RUN terminal
    # (exit 2), never a bare exit without records.
    suite = _load_suite("tests/kernel/test_uprobe_register.py")
    saved_env = dict(os.environ)
    for var in ("MOJOBPF_VNG_RELEASE", "MOJOBPF_TARGET_MANIFEST",
                "MOJOBPF_PLAN_COMMIT", "MOJOBPF_PLAN_TOOL"):
        os.environ.pop(var, None)
    os.environ["MOJOBPF_VNG_RELEASE"] = "bogus-lane-99"
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer):
            code = suite.main()
    finally:
        os.environ.clear()
        os.environ.update(saved_env)
    text = buffer.getvalue()
    assert code == 2, (code, text[-500:])
    assert "MOJOBPF_SUITE_RESULT " in text, text[-500:]
    _plan, parsed, terminal = _parse_emitted(text.splitlines())
    assert terminal.decision["verdict"] == "INCOMPLETE", (
        terminal.decision
    )
    assert parsed, text[-500:]
    assert all(
        result.outcome == "NOT_RUN" for result in parsed
    ), [result.outcome for result in parsed]


def test_xdp_unleased_run_reports_not_run_terminal():
    # An unleased run refuses every guest boot before any
    # process starts and finishes with a typed all-NOT_RUN
    # terminal (exit 3), never the success tail and never a
    # bare escape.
    suite = _load_suite("tests/kernel/test_mojo_xdp.py")
    real_build = suite.build_object
    real_which = suite.shutil.which
    real_popen = suite.guest_proc.subprocess.Popen
    suite.shutil.which = lambda tool: "/fake/" + tool

    def _fake_build(source, workdir, name):
        path = os.path.join(workdir, name + ".bpf.o")
        with open(path, "wb") as handle:
            handle.write(b"fake-object:" + name.encode())
        return path

    suite.build_object = _fake_build
    calls = []

    def _spy(*args, **kwargs):
        argv = args[0] if args else []
        if argv and os.path.basename(argv[0]) == "vng":
            calls.append(list(argv))
            raise FileNotFoundError(
                "no vng boot in the lease drill"
            )
        return real_popen(*args, **kwargs)

    suite.guest_proc.subprocess.Popen = _spy
    saved_cache = dict(suite._CACHED)
    suite._CACHED.clear()
    saved_lease = os.environ.pop("MOJOBPF_TARGET_LEASE", None)
    before = _tmp_xdp_stages()
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer):
            code = suite.main()
    finally:
        suite.build_object = real_build
        suite.shutil.which = real_which
        suite.guest_proc.subprocess.Popen = real_popen
        suite._CACHED.clear()
        suite._CACHED.update(saved_cache)
        if saved_lease is not None:
            os.environ["MOJOBPF_TARGET_LEASE"] = saved_lease
    leftover = _tmp_xdp_stages() - before
    _clear_tmp_xdp_stages(before)
    text = buffer.getvalue()
    assert calls == [], calls
    assert code == 3, (code, text[-500:])
    assert "MOJOBPF_SUITE_RESULT " in text, text[-500:]
    _plan, parsed, terminal = _parse_emitted(text.splitlines())
    assert terminal.decision["verdict"] == "INCOMPLETE", (
        terminal.decision
    )
    assert parsed, text[-500:]
    assert all(
        result.outcome == "NOT_RUN" for result in parsed
    ), [result.outcome for result in parsed]
    assert all(
        result.applicability == "TARGET_RESOURCE_ABSENT"
        for result in parsed
    ), [result.applicability for result in parsed]
    assert not leftover, sorted(leftover)


def test_xdp_frontend_timeout_is_typed():
    # A hung frontend surfaces as infrastructure failure with a
    # terminal record, never an untyped escape from main().
    suite = _load_suite("tests/kernel/test_mojo_xdp.py")
    before = _tmp_xdp_stages()
    real_build = suite.build_object
    real_which = suite.shutil.which
    suite.shutil.which = lambda tool: "/fake/" + tool

    def _hung(source, workdir, name):
        raise subprocess.TimeoutExpired(cmd=["mojo"], timeout=600)

    suite.build_object = _hung
    saved_cache = dict(suite._CACHED)
    suite._CACHED.clear()
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer):
            code = suite.main()
    finally:
        suite.build_object = real_build
        suite.shutil.which = real_which
        suite._CACHED.clear()
        suite._CACHED.update(saved_cache)
        _clear_tmp_xdp_stages(before)
    text = buffer.getvalue()
    assert code == 2, (code, text[-500:])
    assert "MOJOBPF_SUITE_RESULT " in text, text[-500:]
    _plan, parsed, terminal = _parse_emitted(text.splitlines())
    assert terminal.decision["verdict"] == "INCOMPLETE", (
        terminal.decision
    )
    assert parsed[0].outcome == "INFRA_ERROR", parsed[0].outcome
    assert parsed[0].failure_stage == "INFRA", (
        parsed[0].failure_stage
    )
    assert parsed[0].applicability == "TOOLCHAIN_UNAVAILABLE", (
        parsed[0].applicability
    )


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
