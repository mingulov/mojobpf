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
                # needs the Mojo toolchain. The probe script
                # is pre-staged, mirroring the fixture's
                # pre-begin handoff (guest_exec never writes
                # scripts itself since A1M2-2).
                suite._FIXTURE.clear()
                suite._FIXTURE["stage"] = stage
                with open(
                    os.path.join(stage, "wrap_probe.sh"), "w",
                    encoding="utf-8",
                ) as handle:
                    handle.write("exit 0\n")
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
        assert b"test_recorder_pass_emits_verifying_terminal" in rec.consume_absolute(source)
        rec.note_transcript("guest", "guest did work")
        rec.end_case_pass("test_alpha")
        rec.begin_case("test_denial")
        assert b"test_recorder_pass_emits_verifying_terminal" in rec.consume_absolute(source)
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
        assert b"test_sealed_plan_ignores_posthoc_denial" in rec.consume_absolute(source)
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
            assert b"test_post_completion_object_swap_fails_closed" in rec.consume_absolute(source)
            assert rec.consume_staged("probe.bpf.o", stage) == b"original-object-bytes-v1"
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
            assert b"test_post_completion_object_swap_fails_closed" in rec.consume_absolute(source)
            assert rec.consume_staged("probe.bpf.o", control) == b"stable-object-bytes"
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
            assert rec.consume_absolute(empty) == b""
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
        sealed = helper._sealed()
        real_remove = sealed.rmtree_owned
        pinned = helper._OWNED_STAGE_IDS[os.path.abspath(stage)]

        def _refusing(parent_fd, name, want):
            if want == pinned:
                raise PermissionError("injected removal refusal")
            return real_remove(parent_fd, name, want)

        sealed.rmtree_owned = _refusing
        try:
            exit_code, lines = _finish_lines(rec)
        finally:
            sealed.rmtree_owned = real_remove
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


def test_mid_case_staged_swap_fails_closed():
    # A staged input swapped mid-case -- after begin_case, before
    # end_case_pass -- must fail closed: the case-start seal no
    # longer matches, so the case attests FAIL at TEST_RUN
    # (never the unexecuted replacement with PASS) with the
    # swap as residue. The failed case pins the consumed
    # original, never the finish-time replacement. Fresh
    # variant of the round-3 #1 probe: a staged corpus entry
    # swapped immediately after begin. An unswapped control run
    # still passes.
    import hashlib

    helper = _load_helper()
    source = os.path.abspath(__file__)
    original = b"original-corpus-bytes-v1"
    replacement = b"replacement-corpus-bytes-v2"
    stage = helper.owned_stage(prefix="midcase-probe-")
    try:
        target = os.path.join(stage, "corpus.pcap")
        with open(target, "wb") as handle:
            handle.write(original)
        inputs = {
            "test_probe": {
                "sources": [source],
                "objects": [],
                "corpus": [("stage", "corpus.pcap")],
            }
        }
        with _harness_path():
            rec = _make_recorder(
                helper, ["test_probe"], inputs=inputs
            )
            rec.begin_case("test_probe")
            assert b"test_mid_case_staged_swap_fails_closed" in rec.consume_absolute(source)
            assert rec.consume_staged("corpus.pcap", stage) == original
            with open(target, "wb") as handle:
                handle.write(replacement)
            rec.end_case_pass("test_probe")
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
            "changed during the case" in entry
            for entry in parsed[0].cleanup["residue"]
        ), parsed[0].to_dict()
        attested = parsed[0].identities["workload"]["corpus_sha256"]
        assert attested == hashlib.sha256(
            original + b"\x00"
        ).hexdigest(), parsed[0].to_dict()
    finally:
        helper.discard_owned_stages()
        shutil.rmtree(stage, ignore_errors=True)
    control = helper.owned_stage(prefix="midcase-control-")
    try:
        target = os.path.join(control, "corpus.pcap")
        with open(target, "wb") as handle:
            handle.write(b"stable-corpus-bytes")
        inputs = {
            "test_probe": {
                "sources": [source],
                "objects": [],
                "corpus": [("stage", "corpus.pcap")],
            }
        }
        with _harness_path():
            rec = _make_recorder(
                helper, ["test_probe"], inputs=inputs
            )
            rec.begin_case("test_probe")
            assert b"test_mid_case_staged_swap_fails_closed" in rec.consume_absolute(source)
            assert rec.consume_staged("corpus.pcap", control) == b"stable-corpus-bytes"
            rec.end_case_pass("test_probe")
            exit_code, lines = _finish_lines(rec, stage_dir=control)
        assert exit_code == 0, lines
        _plan, parsed, suite = _parse_emitted(lines)
        assert suite.decision["verdict"] == "PASS", suite.decision
    finally:
        helper.discard_owned_stages()
        shutil.rmtree(control, ignore_errors=True)


def test_finish_single_read_defeats_hash_verify_straddle():
    # Fault injection that serves replacement bytes for the
    # first finish-time read of an input and restores the
    # original afterwards must not attest the replacement with
    # PASS: attestation reads nothing at finish (it pins the
    # logged consumption bytes), and the seal verification
    # keeps one read per path, so the faulted read mismatches
    # the seal and fails at TEST_RUN. Fresh variant of the
    # round-3 #2 probe: an absolute-path source with a
    # first-read (not phase-window) fault.
    import hashlib

    helper = _load_helper()
    original = b"original-source-bytes-v1"
    replacement = b"replacement-source-bytes-v2"
    root = tempfile.mkdtemp(prefix="straddle-probe-")
    try:
        target = os.path.join(root, "input.src")
        with open(target, "wb") as handle:
            handle.write(original)
        inputs = {
            "test_probe": {
                "sources": [target],
                "objects": [],
                "corpus": [],
            }
        }
        with _harness_path():
            rec = _make_recorder(
                helper, ["test_probe"], inputs=inputs
            )
            rec.begin_case("test_probe")
            assert rec.consume_absolute(target) == original
            rec.end_case_pass("test_probe")
            import builtins

            real_open = builtins.open
            opens = []

            def _straddling(path, *args, **kwargs):
                mode = args[0] if args else kwargs.get("mode", "r")
                if (
                    isinstance(path, str)
                    and path == target
                    and isinstance(mode, str)
                    and "b" in mode
                ):
                    opens.append(path)
                    if len(opens) == 1:
                        return io.BytesIO(replacement)
                return real_open(path, *args, **kwargs)

            builtins.open = _straddling
            try:
                exit_code, lines = _finish_lines(rec)
            finally:
                builtins.open = real_open
        assert opens == [target], opens
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
        attested = parsed[0].identities["source_sha256"]
        assert attested == hashlib.sha256(
            original + b"\x00"
        ).hexdigest(), parsed[0].to_dict()
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_census_concealment_with_combined_denials_fails_closed():
    # Combined census denials against a live owned child must
    # fail closed: the census is refused (None), never a clean
    # snapshot missing the child, and a case ending under the
    # denial becomes INFRA_ERROR at CLEANUP instead of PASS.
    # Two fresh variants of the round-3 #3 probe, each denying
    # the child's directory metadata plus a different stat
    # failure: (a) denied stat read, (b) truncated stat bytes
    # through the former silent-skip path.
    _require_tools("sleep")
    helper = _load_helper()
    import builtins

    for mode in ("denied-read", "truncated-read"):
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
                real_open = builtins.open
                real_stat = os.stat
                denied_stat = "/proc/%d/stat" % child.pid
                denied_dir = "/proc/%d" % child.pid

                def _denying_open(path, *args, **kwargs):
                    if isinstance(path, str) and path == denied_stat:
                        if mode == "denied-read":
                            raise PermissionError(
                                "injected stat denial"
                            )
                        return io.StringIO("")
                    return real_open(path, *args, **kwargs)

                def _denying_stat(path, *args, **kwargs):
                    if path == denied_dir:
                        raise PermissionError(
                            "injected metadata denial"
                        )
                    return real_stat(path, *args, **kwargs)

                builtins.open = _denying_open
                os.stat = _denying_stat
                try:
                    assert helper.census_snapshot() is None, mode
                    assert helper.census_leaks(baseline) is None, mode
                    assert child.poll() is None, mode
                    rec = _make_recorder(helper, ["test_probe"])
                    rec.begin_case("test_probe")
                    rec.end_case_pass("test_probe")
                    exit_code, lines = _finish_lines(rec)
                finally:
                    builtins.open = real_open
                    os.stat = real_stat
                assert exit_code != 0, (mode, lines)
                _plan, parsed, suite = _parse_emitted(lines)
                assert suite.decision["verdict"] != "PASS", (
                    mode, suite.decision,
                )
                assert parsed[0].outcome == "INFRA_ERROR", (
                    mode, parsed[0].to_dict(),
                )
                assert parsed[0].failure_stage == "CLEANUP", (
                    mode, parsed[0].to_dict(),
                )
                assert parsed[0].cleanup["status"] == "NOT_CHECKED", (
                    mode, parsed[0].to_dict(),
                )
            finally:
                try:
                    child.kill()
                except ProcessLookupError:
                    pass
                child.wait()


def test_late_staged_inputs_never_seal_after_execution():
    # Inputs first observed after begin_case -- staged mid-case
    # or unreadable at the begin seal -- must never seal at case
    # end as the executed bytes: a PASS over them attests bytes
    # the seal never saw. Fresh variant of the round-4 #1 probe
    # (a staged objects entry, not the XDP declarations):
    # (a) begin before staging, consume bytes A, swap to B;
    # (b) bytes A staged first but the begin-seal read denied,
    # then consumed and swapped to B. Both must fail closed at
    # TEST_RUN; a pre-staged unswapped control still passes.
    import hashlib

    helper = _load_helper()
    source = os.path.abspath(__file__)
    original = b"late-seal-executed-bytes-A"
    replacement = b"late-seal-replacement-bytes-B"

    def _inputs():
        return {
            "test_probe": {
                "sources": [source],
                "objects": [("stage", "late-seal-swap.bpf.o")],
                "corpus": [],
            }
        }

    def _consume(path):
        with open(path, "rb") as handle:
            return handle.read()

    # Variant (a): the stage does not exist at begin_case; the
    # stand-in creates and consumes A, then swaps to B. Nothing
    # was consumed through the recorder, so the failed case
    # pins zeros for the late entry.
    stage = helper.owned_stage(prefix="lateseal-probe-")
    try:
        target = os.path.join(stage, "late-seal-swap.bpf.o")
        with _harness_path():
            rec = _make_recorder(
                helper, ["test_probe"], inputs=_inputs()
            )
            rec.begin_case("test_probe")
            assert not os.path.exists(target)
            with open(target, "wb") as handle:
                handle.write(original)
            assert _consume(target) == original
            with open(target, "wb") as handle:
                handle.write(replacement)
            rec.end_case_pass("test_probe")
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
            "never observed before execution" in entry
            for entry in parsed[0].cleanup["residue"]
        ), parsed[0].to_dict()
        attested = parsed[0].identities["object_sha256"]
        assert attested == helper.ZERO_SHA256, parsed[0].to_dict()
    finally:
        helper.discard_owned_stages()
        shutil.rmtree(stage, ignore_errors=True)

    # Variant (b): bytes A exist before begin_case, but the
    # begin-seal read is denied, so the seal observes nothing;
    # the stand-in then consumes A and swaps to B.
    stage = helper.owned_stage(prefix="lateseal-denied-")
    try:
        target = os.path.join(stage, "late-seal-swap.bpf.o")
        with open(target, "wb") as handle:
            handle.write(original)
        real_read = helper._read_owned_entry

        def _denying_read(read_stage, name):
            if os.path.join(read_stage, name) == target:
                return None
            return real_read(read_stage, name)

        with _harness_path():
            rec = _make_recorder(
                helper, ["test_probe"], inputs=_inputs()
            )
            helper._read_owned_entry = _denying_read
            try:
                rec.begin_case("test_probe")
            finally:
                helper._read_owned_entry = real_read
            assert _consume(target) == original
            with open(target, "wb") as handle:
                handle.write(replacement)
            rec.end_case_pass("test_probe")
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
            "never observed before execution" in entry
            for entry in parsed[0].cleanup["residue"]
        ), parsed[0].to_dict()
    finally:
        helper._read_owned_entry = real_read
        helper.discard_owned_stages()
        shutil.rmtree(stage, ignore_errors=True)

    # Control: bytes staged before begin_case and never swapped
    # still pass.
    control = helper.owned_stage(prefix="lateseal-control-")
    try:
        target = os.path.join(control, "late-seal-swap.bpf.o")
        with open(target, "wb") as handle:
            handle.write(b"stable-late-seal-bytes")
        with _harness_path():
            rec = _make_recorder(
                helper, ["test_probe"], inputs=_inputs()
            )
            rec.begin_case("test_probe")
            assert b"test_late_staged_inputs_never_seal_after_execution" in rec.consume_absolute(source)
            assert rec.consume_staged("late-seal-swap.bpf.o", control) == b"stable-late-seal-bytes"
            rec.end_case_pass("test_probe")
            exit_code, lines = _finish_lines(
                rec, stage_dir=control
            )
        assert exit_code == 0, lines
        _plan, parsed, suite = _parse_emitted(lines)
        assert suite.decision["verdict"] == "PASS", suite.decision
    finally:
        helper.discard_owned_stages()
        shutil.rmtree(control, ignore_errors=True)


def test_cleanup_closure_preparation_order_refuses_late_scripts():
    # A1M2-2: cleanup's repeat closure (guest script + harness
    # copy) must be staged before begin_case seals the inputs;
    # script bytes first observed mid-case can never back a
    # PASS. Mirrors the repeat case's staged declarations.
    helper = _load_helper()
    source = os.path.abspath(__file__)

    def _inputs():
        return {
            "test_probe": {
                "sources": [
                    source,
                    ("stage", "guest_repeat.sh"),
                    ("stage", "bpf_test_run.py"),
                ],
                "objects": [],
                "corpus": [],
            }
        }

    # Variant (a): absent at begin, staged mid-case -> FAIL
    # naming the never-observed scripts.
    stage = helper.owned_stage(prefix="preporder-late-")
    try:
        with _harness_path():
            rec = _make_recorder(
                helper, ["test_probe"], inputs=_inputs()
            )
            rec.begin_case("test_probe")
            assert not os.path.exists(
                os.path.join(stage, "guest_repeat.sh")
            )
            for name in ("guest_repeat.sh", "bpf_test_run.py"):
                with open(os.path.join(stage, name), "wb") as handle:
                    handle.write(b"late-script-bytes")
            rec.end_case_pass("test_probe")
            exit_code, lines = _finish_lines(rec, stage_dir=stage)
        assert exit_code == 1, lines
        _plan, parsed, suite = _parse_emitted(lines)
        assert suite.decision["verdict"] == "FAIL", suite.decision
        assert any(
            "never observed before execution" in entry
            for entry in parsed[0].cleanup["residue"]
        ), parsed[0].to_dict()
    finally:
        helper.discard_owned_stages()
        shutil.rmtree(stage, ignore_errors=True)

    # Variant (b) control: staged before begin, consumed, never
    # rewritten -> PASS.
    stage = helper.owned_stage(prefix="preporder-early-")
    try:
        for name in ("guest_repeat.sh", "bpf_test_run.py"):
            with open(os.path.join(stage, name), "wb") as handle:
                handle.write(b"early-script-bytes")
        with _harness_path():
            rec = _make_recorder(
                helper, ["test_probe"], inputs=_inputs()
            )
            rec.begin_case("test_probe")
            assert b"preparation_order" in rec.consume_absolute(source)
            assert rec.consume_staged(
                "guest_repeat.sh", stage
            ) == b"early-script-bytes"
            assert rec.consume_staged(
                "bpf_test_run.py", stage
            ) == b"early-script-bytes"
            rec.end_case_pass("test_probe")
            exit_code, lines = _finish_lines(rec, stage_dir=stage)
        assert exit_code == 0, lines
        _plan, parsed, suite = _parse_emitted(lines)
        assert suite.decision["verdict"] == "PASS", suite.decision
    finally:
        helper.discard_owned_stages()
        shutil.rmtree(stage, ignore_errors=True)


def test_lifecycle_preflight_compares_consumed_object_identity():
    # A1M3-3: the failsafe preflights must verify consumed,
    # declared object bytes. The three cases declare their
    # staged objects; the comparison passes when the record
    # carries the consumed digest and refuses a swapped
    # identity. (The negative-controls case captures no
    # object and stays undeclared by design.)
    suite = _load_suite("tests/kernel/test_tracing_lifecycle.py")
    helper = suite.guest_proc
    for case_id, names in (
        ("test_failsafe_map_preflight", ("counter-prefail.bpf.o",)),
        ("test_failsafe_arena_lane_verdict", ("counter-prefail.bpf.o",)),
        ("test_failsafe_event_preflight",
         ("counter-prefail.bpf.o", "emitter-prefail.bpf.o")),
    ):
        for name in names:
            assert ("stage", name) in suite.CASE_INPUTS[case_id]["objects"], (
                case_id, name,
            )
    # Seed the preflight cache with synthetic staged bytes
    # (no toolchain): the comparison itself is what is
    # exercised here; the guest matrix proves the staging.
    stage = helper.owned_stage(prefix="prefail-probe-")
    try:
        counter = os.path.join(stage, "counter-prefail.bpf.o")
        with open(counter, "wb") as handle:
            handle.write(b"counter-bytes")
        saved = dict(suite._PREFLIGHT)
        suite._PREFLIGHT.update({"stage": stage, "counter": counter})
        try:
            with _harness_path():
                rec = _make_recorder(helper, ["test_probe"])
                helper.set_active_recorder(rec)
                try:
                    helper.stage_consumed_for_guest(
                        rec, stage, ("counter-prefail.bpf.o",)
                    )
                    digest = rec.consumed_staged_digest(
                        "counter-prefail.bpf.o", stage
                    )
                    suite.check_preflight_object(
                        {"object": {"sha256": digest}},
                        "counter-prefail.bpf.o",
                    )
                    with pytest.raises(AssertionError):
                        suite.check_preflight_object(
                            {"object": {"sha256": helper.ZERO_SHA256}},
                            "counter-prefail.bpf.o",
                        )
                finally:
                    helper.clear_active_recorder()
        finally:
            suite._PREFLIGHT.clear()
            suite._PREFLIGHT.update(saved)
    finally:
        helper.disarm_staged_handoffs(stage)
        helper.discard_owned_stages()


def test_migrated_suite_preserves_failed_attempt_without_rerun(tmp_path):
    # A1M3-4: a failed guest attempt must preserve its stage
    # (set at creation, not only on success) and record its
    # failure, so finish finalizes the recorded attempt
    # instead of rerunning the guest solely to recover
    # evidence. Exercised on the tracepoint suite with
    # stubbed builds and an injected guest failure.
    suite = _load_suite("tests/kernel/test_tracepoint_counter.py")
    helper = suite.guest_proc
    workdir = str(tmp_path)
    fake_obj = os.path.join(workdir, "fake-trace.bpf.o")
    with open(fake_obj, "wb") as handle:
        handle.write(b"fake-object")
    fake_bin = os.path.join(workdir, "fake-workload")
    with open(fake_bin, "wb") as handle:
        handle.write(b"fake-binary")
    calls = []

    def _fake_build_object(source, outdir, tag, want_hash):
        return fake_obj

    def _fake_build_harness(source, output, extra=()):
        with open(output, "wb") as handle:
            handle.write(b"fake-binary")
        return output

    def _failing_guest(argv, stage, timeout, release):
        calls.append((argv, stage))
        raise suite.ProofFailure("injected guest failure")

    saved = (
        suite.build_object, suite.build_harness, suite._run_guest,
        suite.check_tools, suite.vng_release,
        suite._RESULT, suite._STAGE,
    )
    saved_error = getattr(suite, "_ATTEMPT_ERROR", None)
    had_error = hasattr(suite, "_ATTEMPT_ERROR")
    suite.build_object = _fake_build_object
    suite.build_harness = _fake_build_harness
    suite._run_guest = _failing_guest
    # A1M4-5: tool discovery and lane selection are stubbed
    # alongside the builds and the runner, so the control
    # needs no installed product tools.
    suite.check_tools = lambda *tools: None
    suite.vng_release = lambda: "v6.12"
    suite._RESULT = None
    suite._STAGE = None
    try:
        with pytest.raises(suite.ProofFailure):
            suite.executed()
        assert suite._STAGE is not None, (
            "failed attempt preserved no stage"
        )
        assert os.path.isdir(suite._STAGE), suite._STAGE
        with pytest.raises(suite.ProofFailure):
            suite.executed()
        assert len(calls) == 1, (
            "finish evidence must not rerun the guest: %d runs"
            % len(calls)
        )
    finally:
        (suite.build_object, suite.build_harness, suite._run_guest,
         suite.check_tools, suite.vng_release,
         suite._RESULT, suite._STAGE) = saved
        if had_error:
            suite._ATTEMPT_ERROR = saved_error
        elif hasattr(suite, "_ATTEMPT_ERROR"):
            del suite._ATTEMPT_ERROR
        helper.discard_owned_stages()


def _drive_main_with_failing_guest(
    relpath, tmp_path, error, builders, runner_name,
    obj_bytes=b"fake-object",
):
    """Drive ``main()`` with stubbed builds and a failing guest.

    ``error`` is raised (once recorded) by the stubbed guest
    runner; ``builders`` maps builder attribute names to
    ``"obj"`` (return the fake object path) or ``"bin"``
    (return the fake binary path). Tool discovery and lane
    selection are stubbed too (A1M4-5: no installed product
    tools). Returns ``(code, lines, calls, suite)``; ``calls``
    records every stubbed-runner invocation, so attempt
    counting filters on the guest argv (direct-runner host
    controls invoke the same helper legitimately).
    """
    suite = _load_suite(relpath)
    harness = suite.guest_proc
    workdir = str(tmp_path)
    fake_obj = os.path.join(workdir, "fake-main.bpf.o")
    with open(fake_obj, "wb") as handle:
        handle.write(obj_bytes)
    fake_bin = os.path.join(workdir, "fake-main-workload")
    with open(fake_bin, "wb") as handle:
        handle.write(b"fake-binary")
    calls = []

    def _fake_obj_builder(*args, **kwargs):
        return fake_obj

    def _fake_bin_builder(*args, **kwargs):
        return fake_bin

    def _failing_guest(*args):
        calls.append(args)
        raise error

    saved = {}
    for name in (
        list(builders) + [
            runner_name, "check_tools", "vng_release",
            "_RESULT", "_STAGE",
        ]
    ):
        saved[name] = getattr(suite, name)
    saved_fixture = (
        dict(suite._FIXTURE) if hasattr(suite, "_FIXTURE") else None
    )
    saved_preflight = (
        dict(suite._PREFLIGHT) if hasattr(suite, "_PREFLIGHT") else None
    )
    saved_error = getattr(suite, "_ATTEMPT_ERROR", None)
    for name, kind in builders.items():
        setattr(
            suite, name,
            _fake_obj_builder if kind == "obj" else _fake_bin_builder,
        )
    setattr(suite, runner_name, _failing_guest)
    suite.check_tools = lambda *tools: None
    suite.vng_release = lambda: "v6.12"
    suite._RESULT = None
    suite._STAGE = None
    suite._ATTEMPT_ERROR = None
    if saved_fixture is not None:
        suite._FIXTURE.clear()
    if saved_preflight is not None:
        suite._PREFLIGHT.clear()
    try:
        with _harness_path():
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = suite.main()
            lines = buffer.getvalue().splitlines()
        return code, lines, calls, suite
    finally:
        for name, value in saved.items():
            setattr(suite, name, value)
        suite._ATTEMPT_ERROR = saved_error
        if saved_fixture is not None:
            suite._FIXTURE.clear()
            suite._FIXTURE.update(saved_fixture)
        if saved_preflight is not None:
            suite._PREFLIGHT.clear()
            suite._PREFLIGHT.update(saved_preflight)
        harness.clear_active_recorder()
        harness.discard_owned_stages()


def _attempt_runs(calls):
    """Count stubbed invocations that boot the guest attempt."""
    return sum(
        1 for args in calls
        if args and args[0] and args[0][0] == "vng"
    )


def test_tracepoint_main_finalizes_cached_assertion_failure(tmp_path):
    # A1M4-4: a handoff refusal (AssertionError) cached by
    # executed() must finalize through main/finish as a formal
    # FAIL on the preserved attempt, never escape before case
    # recording, and never rerun the guest.
    injected = AssertionError("injected handoff refusal")
    code, lines, calls, suite = _drive_main_with_failing_guest(
        "tests/kernel/test_tracepoint_counter.py", tmp_path,
        injected,
        {"build_object": "obj", "build_harness": "bin"},
        "_run_guest",
    )
    assert code == 1, lines
    _plan, parsed, terminal = _parse_emitted(lines)
    assert terminal.decision["verdict"] == "FAIL", terminal.decision
    assert _attempt_runs(calls) == 1, (
        "guest reran for finish evidence: %d" % len(calls)
    )
    assert parsed[0].outcome == "FAIL", parsed[0].to_dict()


def test_tracepoint_main_finalizes_cached_lease_refusal(tmp_path):
    # A1M4-4: a cached lease refusal must finalize through
    # main/finish as lease-gated unavailable outcomes on the
    # preserved attempt, never escape _finish, and never rerun
    # the guest.
    suite_probe = _load_suite("tests/kernel/test_tracepoint_counter.py")
    injected = suite_probe.guest_proc.TargetLeaseRequired(
        "injected lease refusal"
    )
    code, lines, calls, _suite = _drive_main_with_failing_guest(
        "tests/kernel/test_tracepoint_counter.py", tmp_path,
        injected,
        {"build_object": "obj", "build_harness": "bin"},
        "_run_guest",
    )
    assert code == 3, lines
    _plan, parsed, terminal = _parse_emitted(lines)
    assert terminal.decision["verdict"] == "INCOMPLETE", (
        terminal.decision
    )
    assert _attempt_runs(calls) == 1, (
        "guest reran for finish evidence: %d" % len(calls)
    )
    assert parsed, "no case records emitted"
    assert all(
        item.outcome == "NOT_RUN" for item in parsed
    ), [item.to_dict() for item in parsed]


def _parsed_outcomes(parsed):
    return {
        item.to_dict()["case_id"]: item.to_dict()["outcome"]
        for item in parsed
    }


def test_lifecycle_main_finalizes_cached_assertion_failure(tmp_path):
    # A1M4-4 regression pin: lifecycle already records
    # per-case failures through main/finish; the cached
    # assertion must finalize as a formal FAIL with one guest
    # attempt across warmup, preflights, cases and finish
    # (host-only controls run their own direct invocations).
    injected = AssertionError("injected handoff refusal")
    code, lines, calls, _suite = _drive_main_with_failing_guest(
        "tests/kernel/test_tracing_lifecycle.py", tmp_path,
        injected,
        {"build_object": "obj", "build_harness": "bin"},
        "run_guest",
    )
    assert code == 1, lines
    _plan, parsed, terminal = _parse_emitted(lines)
    assert terminal.decision["verdict"] == "FAIL", terminal.decision
    assert _attempt_runs(calls) == 1, (
        "guest reran for finish evidence: %d" % len(calls)
    )


def test_lifecycle_main_finalizes_cached_lease_refusal(tmp_path):
    # A1M4-4: a cached lease refusal must finalize through
    # main/finish as lease-gated unavailable outcomes on the
    # preserved attempt, never escape _finish, and never rerun
    # the guest attempt. Pure-host validation controls (no
    # guest entry) still pass; every guest-dependent case
    # records NOT_RUN.
    suite_probe = _load_suite("tests/kernel/test_tracing_lifecycle.py")
    injected = suite_probe.guest_proc.TargetLeaseRequired(
        "injected lease refusal"
    )
    code, lines, calls, _suite = _drive_main_with_failing_guest(
        "tests/kernel/test_tracing_lifecycle.py", tmp_path,
        injected,
        {"build_object": "obj", "build_harness": "bin"},
        "run_guest",
    )
    assert code == 3, lines
    _plan, parsed, terminal = _parse_emitted(lines)
    assert terminal.decision["verdict"] == "INCOMPLETE", (
        terminal.decision
    )
    assert _attempt_runs(calls) == 1, (
        "guest reran for finish evidence: %d" % len(calls)
    )
    outcomes = _parsed_outcomes(parsed)
    assert outcomes, "no case records emitted"
    pure_host = {
        "test_failsafe_negative_controls",
        "test_midrun_oracle_rejects_completed_workload",
        # Boots only a sleeper through the direct runner: the
        # injected refusal aborts the boot inside the matrix
        # runner, and the nothing-survives assertions hold
        # trivially (reaping itself is proven by the real
        # suite runs, not by this failure injection).
        "test_matrix_timeout_reaps_detached_guest",
    }
    for case_id, outcome in outcomes.items():
        if case_id in pure_host:
            assert outcome == "PASS", (case_id, outcome)
        else:
            assert outcome == "NOT_RUN", (case_id, outcome)


def _synthetic_license_object():
    """Parseable fake fixture bytes (shared ELF builder)."""
    sys.path.insert(
        0, os.path.join(os.path.dirname(os.path.abspath(__file__)))
    )
    import test_verify

    image, _license = test_verify._synthetic_elf()
    return image


def test_licenses_main_finalizes_cached_assertion_failure(tmp_path):
    # A1M4-4 regression pin: licenses already records
    # per-case failures through main/finish; the cached
    # assertion must finalize as a formal FAIL with one guest
    # attempt across warmup, cases and finish. Fixture bytes
    # are a synthetic parseable ELF so the pure-host gate
    # cases exercise their real parsing paths (recording
    # deterministic outcomes) instead of crashing main.
    injected = AssertionError("injected handoff refusal")
    code, lines, calls, _suite = _drive_main_with_failing_guest(
        "tests/verifier/test_helper_licenses.py", tmp_path,
        injected,
        {"build_control": "obj", "build_counter": "obj"},
        "run_guest",
        obj_bytes=_synthetic_license_object(),
    )
    assert code == 1, lines
    _plan, parsed, terminal = _parse_emitted(lines)
    assert terminal.decision["verdict"] == "FAIL", terminal.decision
    assert _attempt_runs(calls) == 1, (
        "guest reran for finish evidence: %d" % len(calls)
    )
    outcomes = _parsed_outcomes(parsed)
    assert outcomes["test_kernel_rejects_gpl_only_helper"] == "FAIL"
    assert outcomes["test_guest_provenance"] == "FAIL"


def test_licenses_main_finalizes_cached_lease_refusal(tmp_path):
    # A1M4-4: a cached lease refusal must finalize through
    # main/finish as lease-gated unavailable outcomes on the
    # preserved attempt, never escape _finish, and never rerun
    # the guest attempt. The guest-dependent cases record
    # NOT_RUN; the gate cases run their real inspection paths
    # against the synthetic bytes and record deterministic
    # FAILs, so the terminal is FAIL (FAIL dominates), not
    # INCOMPLETE -- the unavailable path itself is proven by
    # the NOT_RUN records plus the tracepoint/lifecycle
    # INCOMPLETE terminals.
    suite_probe = _load_suite("tests/verifier/test_helper_licenses.py")
    injected = suite_probe.guest_proc.TargetLeaseRequired(
        "injected lease refusal"
    )
    code, lines, calls, _suite = _drive_main_with_failing_guest(
        "tests/verifier/test_helper_licenses.py", tmp_path,
        injected,
        {"build_control": "obj", "build_counter": "obj"},
        "run_guest",
        obj_bytes=_synthetic_license_object(),
    )
    assert code == 1, lines
    _plan, parsed, terminal = _parse_emitted(lines)
    assert terminal.decision["verdict"] == "FAIL", terminal.decision
    assert _attempt_runs(calls) == 1, (
        "guest reran for finish evidence: %d" % len(calls)
    )
    outcomes = _parsed_outcomes(parsed)
    assert outcomes["test_kernel_rejects_gpl_only_helper"] == "NOT_RUN"
    assert outcomes["test_guest_provenance"] == "NOT_RUN"


def test_tree_kill_scanners_propagate_unreadable_stats():
    # A failed stat read on a living pid must surface as
    # residue/uncertainty from both tree-kill scanners, never as
    # a clean empty list. Fresh variant of the round-4 #2 probe:
    # a truncated stat on a plain (non-session-leader) owned
    # child plus a denied read on a session leader, asserted at
    # both the scan level (None while the child lives) and the
    # kill level (non-empty unverified residue under a fast
    # clock). No owned child, pipe, or lease survives this test.
    _require_tools("sleep")
    import builtins

    helper = _load_helper()
    runner = _load_matrix_runner()

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

    def _visible(pid):
        helper_table = helper._scan_processes()
        runner_table = runner._scan_processes()
        assert helper_table is not None
        assert runner_table is not None
        return (
            pid in helper_table and pid in runner_table
        )

    plain = subprocess.Popen(
        ["sleep", "120"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    leader = subprocess.Popen(
        ["sleep", "120"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            if _visible(plain.pid) and _visible(leader.pid):
                break
            time.sleep(0.1)
        assert _visible(plain.pid), "plain child invisible"
        assert _visible(leader.pid), "leader child invisible"
        real_open = builtins.open
        plain_stat = "/proc/%d/stat" % plain.pid
        leader_stat = "/proc/%d/stat" % leader.pid

        def _failing_open(path, *args, **kwargs):
            if isinstance(path, str) and path == plain_stat:
                return io.StringIO("")
            if isinstance(path, str) and path == leader_stat:
                raise PermissionError("injected stat denial")
            return real_open(path, *args, **kwargs)

        builtins.open = _failing_open
        try:
            assert plain.poll() is None
            assert leader.poll() is None
            assert helper._scan_processes() is None, (
                "guest scan skipped an unreadable owned stat"
            )
            assert runner._scan_processes() is None, (
                "matrix scan skipped an unreadable owned stat"
            )
        finally:
            builtins.open = real_open
        assert _visible(plain.pid)
        assert _visible(leader.pid)
    finally:
        for child in (plain, leader):
            try:
                child.kill()
            except OSError:
                pass
        for child in (plain, leader):
            child.wait(timeout=30)
            for pipe in (child.stdout, child.stderr):
                try:
                    pipe.close()
                except (OSError, ValueError):
                    pass

    # Kill level: with the stat unreadable, neither kill loop
    # may report a clean empty list, even on a fast clock.
    for module, kill, stat_mode in (
        (helper, helper.kill_guest_tree, "denied-read"),
        (runner, runner._kill_suite_tree, "truncated-read"),
    ):
        victim = subprocess.Popen(
            ["sleep", "120"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            deadline = time.time() + 10
            while time.time() < deadline:
                table = module._scan_processes()
                if table is not None and victim.pid in table:
                    break
                time.sleep(0.1)
            assert victim.pid in (
                module._scan_processes() or {}
            ), "victim invisible to the kill scan"
            real_open = builtins.open
            real_time = module.time
            victim_stat = "/proc/%d/stat" % victim.pid

            def _victim_open(path, *args, **kwargs):
                if isinstance(path, str) and path == victim_stat:
                    if stat_mode == "denied-read":
                        raise PermissionError(
                            "injected stat denial"
                        )
                    return io.StringIO("")
                return real_open(path, *args, **kwargs)

            builtins.open = _victim_open
            module.time = _FastClock()
            try:
                residue = kill(victim.pid)
            finally:
                builtins.open = real_open
                module.time = real_time
            assert residue != [], (stat_mode, residue)
            assert any(
                "unverified" in entry or "unreadable" in entry
                for entry in residue
            ), (stat_mode, residue)
        finally:
            try:
                victim.kill()
            except OSError:
                pass
            victim.wait(timeout=30)
            for pipe in (victim.stdout, victim.stderr):
                try:
                    pipe.close()
                except (OSError, ValueError):
                    pass


def test_proc_scanners_tolerate_non_utf8_comm():
    # A foreign comm may hold arbitrary non-UTF-8 bytes (the
    # kernel only forbids NUL and "/"): every process-table
    # scanner must still attribute the numeric tail instead
    # of crashing its run (v6.6 lifecycle NO_TERMINAL on a
    # foreign 0xff comm).
    import builtins
    from mojobpf import verify as verify_mod
    helper = _load_helper()
    runner = _load_matrix_runner()
    with open("/proc/1/stat", "rb") as handle:
        raw = handle.read()
    start = raw.index(b"(") + 1
    end = raw.rindex(b")")
    weird = raw[:start] + b"\xff\xfeforeign" + raw[end:]

    def _weird_open(path, *args, **kwargs):
        if isinstance(path, str) and path == "/proc/1/stat":
            return io.TextIOWrapper(
                io.BytesIO(weird),
                encoding=kwargs.get("encoding", "utf-8"),
                errors=kwargs.get("errors", "strict"),
            )
        return real_open(path, *args, **kwargs)

    real_open = builtins.open
    builtins.open = _weird_open
    try:
        helper_table = helper._scan_processes()
        runner_table = runner._scan_processes()
        assert helper_table is not None and 1 in helper_table, (
            "helper scan dropped the non-UTF-8 entry"
        )
        assert runner_table is not None and 1 in runner_table, (
            "matrix scan dropped the non-UTF-8 entry"
        )
        helper._scan_census()
        verify_mod._group_members(os.getpgrp())
    finally:
        builtins.open = real_open


_HANDOFF_CLASSES = (
    ("source", "input.mojo"),
    ("object", "input.bpf.o"),
    ("helper", "probe_helper.py"),
    ("corpus", "input.bin"),
    ("script", "guest_case.sh"),
)


def _handoff_stage(helper, tmp_path, payloads=None):
    """Stage one file per input class; return (stage, rec, names)."""
    stage = os.path.join(str(tmp_path), "stage")
    os.makedirs(stage)
    names = []
    for _klass, name in _HANDOFF_CLASSES:
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(
                (payloads or {}).get(name, b"captured-" + name.encode())
            )
        names.append(name)
    rec = _make_recorder(
        helper, ["case"], denials={}, inputs={
            "case": {"sources": [], "objects": [], "corpus": []},
        },
    )
    return stage, rec, names


@pytest.mark.parametrize(
    "klass,name", _HANDOFF_CLASSES, ids=[k for k, _ in _HANDOFF_CLASSES],
)
def test_staged_handoff_refuses_replacement(tmp_path, klass, name):
    helper = _load_helper()
    stage, rec, names = _handoff_stage(helper, tmp_path)
    try:
        digests = helper.stage_consumed_for_guest(rec, stage, names)
        assert digests[name] is not None
        # A same-uid replacement must first re-open write
        # permission; the permission change itself is a
        # watched event, so the attack cannot slip through.
        os.chmod(os.path.join(stage, name), 0o644)
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(b"substituted-" + name.encode())
        mismatches = helper.verify_staged_handoffs_now()
        assert any(name in item for item in mismatches), mismatches
    finally:
        helper.disarm_staged_handoffs(stage)


@pytest.mark.parametrize(
    "klass,name", _HANDOFF_CLASSES, ids=[k for k, _ in _HANDOFF_CLASSES],
)
def test_staged_handoff_refuses_change_and_restore(tmp_path, klass, name):
    # Restoring the captured bytes before the check must not
    # launder the transient: the window still executed foreign
    # bytes, so the handoff refuses.
    helper = _load_helper()
    stage, rec, names = _handoff_stage(helper, tmp_path)
    path = os.path.join(stage, name)
    try:
        helper.stage_consumed_for_guest(rec, stage, names)
        with open(path, "rb") as handle:
            captured = handle.read()
        os.chmod(path, 0o644)
        with open(path, "wb") as handle:
            handle.write(b"transient-" + name.encode())
        with open(path, "wb") as handle:
            handle.write(captured)
        os.chmod(path, 0o444)
        mismatches = helper.verify_staged_handoffs_now()
        assert any(name in item for item in mismatches), mismatches
    finally:
        helper.disarm_staged_handoffs(stage)


def test_staged_handoff_detaches_preexisting_writable_mapping(tmp_path):
    # A1M2-1: chmod cannot revoke a mapping established before
    # the handoff, and inotify does not report mmap stores. The
    # handoff therefore installs the captured buffer under a
    # fresh inode: a retained writable mapping refers only to
    # the displaced inode, so change-and-restore through it
    # executes captured bytes.
    import mmap
    helper = _load_helper()
    stage, rec, names = _handoff_stage(helper, tmp_path)
    path = os.path.join(stage, "input.bpf.o")
    captured = b"captured-input.bpf.o"
    ino_before = os.stat(path).st_ino
    fd = os.open(path, os.O_RDWR)
    try:
        mapping = mmap.mmap(fd, 0, access=mmap.ACCESS_WRITE)
        try:
            helper.stage_consumed_for_guest(rec, stage, names)
            assert os.stat(path).st_ino != ino_before, (
                "handoff must install fresh backing"
            )
            mapping[0:8] = b"ATTACK!!"
            mapping.flush()
            with open(path, "rb") as handle:
                assert handle.read() == captured, (
                    "mapping store reached guest-visible bytes"
                )
            mapping[0:8] = captured[0:8]
            mapping.flush()
            assert helper.verify_staged_handoffs_now() == []
            with open(path, "rb") as handle:
                assert handle.read() == captured
        finally:
            mapping.close()
    finally:
        os.close(fd)
        helper.disarm_staged_handoffs(stage)


def test_staged_handoff_refuses_prelinked_temporary(tmp_path):
    # A1M3-1: a predictable temporary opened with "wb" lets an
    # attacker pre-link it to the input, turning os.replace into
    # a same-inode no-op (rename(2)) that preserves a writable
    # mapping. The handoff must install genuinely fresh backing
    # even then: after the handoff the guest-visible path must
    # sit on a different inode, and stores through a mapping
    # retained on the old inode must not reach it.
    import mmap
    helper = _load_helper()
    stage, rec, names = _handoff_stage(helper, tmp_path)
    path = os.path.join(stage, "input.bpf.o")
    captured = b"captured-input.bpf.o"
    ino_before = os.stat(path).st_ino
    tmp_name = "%s.handoff-%d" % (path, os.getpid())
    os.link(path, tmp_name)
    fd = os.open(path, os.O_RDWR)
    try:
        mapping = mmap.mmap(fd, 0, access=mmap.ACCESS_WRITE)
        try:
            helper.stage_consumed_for_guest(rec, stage, names)
            assert os.stat(path).st_ino != ino_before, (
                "handoff reused the pre-linked inode"
            )
            mapping[0:8] = b"ATTACK!!"
            mapping.flush()
            with open(path, "rb") as handle:
                assert handle.read() == captured, (
                    "mapping store reached guest-visible bytes"
                )
        finally:
            mapping.close()
    finally:
        os.close(fd)
        helper.disarm_staged_handoffs(stage)


def test_staged_handoff_ignores_attacker_temporary_name(tmp_path):
    # A1M3-1: a colliding attacker entry at the temporary
    # pathname (here a symlink to the input, which "wb" would
    # follow) must not disturb the handoff: the guest-visible
    # path stays a regular file on a fresh inode with the
    # captured bytes.
    helper = _load_helper()
    stage, rec, names = _handoff_stage(helper, tmp_path)
    path = os.path.join(stage, "input.bpf.o")
    captured = b"captured-input.bpf.o"
    ino_before = os.stat(path).st_ino
    os.symlink(path, "%s.handoff-%d" % (path, os.getpid()))
    try:
        helper.stage_consumed_for_guest(rec, stage, names)
        assert not os.path.islink(path), (
            "handoff left a symlink behind"
        )
        assert os.stat(path).st_ino != ino_before, (
            "handoff reused attacker-controlled backing"
        )
        with open(path, "rb") as handle:
            assert handle.read() == captured
        assert helper.verify_staged_handoffs_now() == []
    finally:
        helper.disarm_staged_handoffs(stage)


def test_staged_handoff_never_publishes_writable(tmp_path):
    # A1M3-1: backing published writable before chmod lets
    # another process acquire a surviving writable mapping in
    # the window. A racer attempting O_RDWR opens across many
    # handoffs must never succeed: the published inode is
    # sealed from birth.
    import threading
    helper = _load_helper()
    stage, rec, names = _handoff_stage(helper, tmp_path)
    path = os.path.join(stage, "input.bpf.o")
    # Pre-seal the not-yet-handed-off original: it is
    # legitimately writable (its mappings are displaced at
    # install), and the racer must only be able to reach
    # published inodes from here on.
    for name in names:
        os.chmod(os.path.join(stage, name), 0o444)
    stop = threading.Event()
    opened = []
    barrier = threading.Barrier(2)

    def _race():
        barrier.wait()
        while not stop.is_set():
            try:
                fd = os.open(path, os.O_RDWR)
            except OSError:
                continue
            opened.append(fd)

    racer = threading.Thread(target=_race)
    racer.start()
    try:
        barrier.wait()
        for _ in range(200):
            helper.stage_consumed_for_guest(rec, stage, names)
            # A re-install over an armed handoff is refused by
            # design (it looks like a mutation); disarm so the
            # next iteration opens a genuine fresh window.
            helper.disarm_staged_handoffs(stage)
    finally:
        stop.set()
        racer.join()
        for fd in opened:
            os.close(fd)
        helper.disarm_staged_handoffs(stage)
    assert opened == [], (
        "racer acquired %d writable opens during handoff" % len(opened)
    )


def test_staged_handoff_refuses_prearm_directory_alias(tmp_path):
    # A1M3-2: the owned stage is recorded by pathname only, and
    # the watch follows the pathname. Renaming the stage away
    # and symlinking its name back before arming would let the
    # watch monitor the old directory while consumption routes
    # through an unmonitored clone. The handoff must refuse a
    # stage whose directory identity no longer matches the
    # owned record instead of arming through the alias.
    helper = _load_helper()
    stage = helper.owned_stage(
        prefix="alias-probe-", dir=str(tmp_path),
    )
    target = os.path.join(stage, "input.bpf.o")
    with open(target, "wb") as handle:
        handle.write(b"captured-input.bpf.o")
    rec = _make_recorder(
        helper, ["case"], denials={}, inputs={
            "case": {"sources": [], "objects": [], "corpus": []},
        },
    )
    relocated = stage + ".relocated"
    os.rename(stage, relocated)
    os.symlink(relocated, stage)
    try:
        try:
            helper.stage_consumed_for_guest(
                rec, stage, ("input.bpf.o",),
            )
        except (AssertionError, helper.HarnessEnvironment):
            pass
        else:
            raise AssertionError(
                "handoff armed through a directory alias"
            )
    finally:
        os.unlink(stage)
        os.rename(relocated, stage)
        helper.disarm_staged_handoffs(stage)
        helper.discard_owned_stages()


def test_staged_handoff_voids_midrun_directory_swap(tmp_path):
    # A1M3-2 regression pin: renaming the stage away and back
    # mid-run restores its identity but diverts path-based
    # consumption in between. The armed watch observes the
    # directory's own move (IN_MOVE_SELF is fatal), so verify
    # must report the handoff voided even though the bytes
    # and the directory identity are unchanged at check time.
    helper = _load_helper()
    stage = helper.owned_stage(
        prefix="swap-probe-", dir=str(tmp_path),
    )
    target = os.path.join(stage, "input.bpf.o")
    with open(target, "wb") as handle:
        handle.write(b"captured-input.bpf.o")
    rec = _make_recorder(
        helper, ["case"], denials={}, inputs={
            "case": {"sources": [], "objects": [], "corpus": []},
        },
    )
    try:
        helper.stage_consumed_for_guest(rec, stage, ("input.bpf.o",))
        assert helper.verify_staged_handoffs_now() == []
        relocated = stage + ".relocated"
        os.rename(stage, relocated)
        os.rename(relocated, stage)
        mismatches = helper.verify_staged_handoffs_now()
        assert mismatches != [], (
            "directory swap escaped the handoff monitor"
        )
    finally:
        helper.disarm_staged_handoffs(stage)
        helper.discard_owned_stages()


def test_staged_watch_binds_checked_inode_across_midarm_swap(tmp_path):
    # A1M4-2: the watch must observe the checked directory even
    # when the pathname is redirected between the identity
    # check and the watch installation (then restored). The
    # monitor is installed through the held descriptor, so it
    # observes the original inode: an event there taints the
    # handoff.
    from mojobpf import sealed_fs

    helper = _load_helper()
    stage = helper.owned_stage(
        prefix="midarm-probe-", dir=str(tmp_path),
    )
    target = os.path.join(stage, "input.bpf.o")
    with open(target, "wb") as handle:
        handle.write(b"captured-input.bpf.o")
    rec = _make_recorder(
        helper, ["case"], denials={}, inputs={
            "case": {"sources": [], "objects": [], "corpus": []},
        },
    )
    relocated = stage + ".relocated"
    real_watch = sealed_fs.NameWatch
    swapped = []
    constructions = []

    def _swapping_watch(directory):
        # The install's publication gate constructs the
        # first watch (A1M7-1); the redirect targets the
        # arm, which is the second construction here.
        constructions.append(directory)
        if len(constructions) == 2:
            swapped.append(True)
            os.rename(stage, relocated)
            os.mkdir(stage)
            # The substitute carries a decoy name: if the
            # watch were installed through the pathname, its
            # events could only void without the handed-off
            # filename, and the restored re-hash would match.
            with open(os.path.join(stage, "decoy.o"), "wb") as handle:
                handle.write(b"substituted-bytes")
        return real_watch(directory)

    sealed_fs.NameWatch = _swapping_watch
    try:
        helper.stage_consumed_for_guest(rec, stage, ("input.bpf.o",))
    finally:
        sealed_fs.NameWatch = real_watch
    assert swapped, "watch installation seam never fired"
    assert len(constructions) == 2, constructions
    # The original inode now lives at `relocated`; touch it
    # through that path WITHOUT restoring the name first (a
    # second rename would itself be fatal to the monitor
    # mask and hide the name event). The full verify would
    # stop at its pathname-alias gate, so the control checks
    # the installed monitor directly: only a watch bound to
    # the checked inode observes the touch (a
    # pathname-installed watch observes the untouched
    # substitute and stays clean).
    try:
        path = os.path.join(relocated, "input.bpf.o")
        with open(path, "rb") as handle:
            original = handle.read()
        os.chmod(path, 0o644)
        with open(path, "wb") as handle:
            handle.write(b"changed-bytes")
        with open(path, "wb") as handle:
            handle.write(original)
        os.chmod(path, 0o444)
        entry = helper._STAGE_WATCHES[os.path.abspath(stage)]
        try:
            entry["watch"].check(names=["input.bpf.o"])
        except OSError:
            pass
        else:
            raise AssertionError(
                "watch missed the touch on the checked inode"
            )
        assert entry["watch"].tainted_name == "input.bpf.o", (
            entry["watch"].tainted,
            entry["watch"].tainted_name,
        )
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        if os.path.isdir(relocated):
            os.rename(relocated, stage)
        helper.disarm_staged_handoffs(stage)
        helper.discard_owned_stages()


def test_staged_handoff_refuses_prearm_substitution(tmp_path):
    # A1M5-1: a substitution after install verification but
    # before watch creation predates all observation; the
    # handoff must re-verify the sealed inode and its bytes
    # under the monitor and refuse. Byte-identical backing
    # defeats a byte comparison, so the refusal is on
    # identity.
    from mojobpf import sealed_fs

    helper = _load_helper()
    stage = helper.owned_stage(
        prefix="prearm-probe-", dir=str(tmp_path),
    )
    target = os.path.join(stage, "input.bpf.o")
    with open(target, "wb") as handle:
        handle.write(b"captured-input.bpf.o")
    rec = _make_recorder(
        helper, ["case"], denials={}, inputs={
            "case": {"sources": [], "objects": [], "corpus": []},
        },
    )
    real_watch = sealed_fs.NameWatch
    swapped = []
    constructions = []

    def _swapping_watch(directory):
        # The install's publication gate constructs the
        # first watch (A1M7-1); the substitution targets
        # the arm, which is the second construction here.
        constructions.append(directory)
        if len(constructions) == 2:
            swapped.append(True)
            with open(target, "rb") as handle:
                original = handle.read()
            substitute = target + ".substitute"
            with open(substitute, "wb") as handle:
                handle.write(original)
            os.rename(substitute, target)
        return real_watch(directory)

    sealed_fs.NameWatch = _swapping_watch
    try:
        with pytest.raises(AssertionError):
            helper.stage_consumed_for_guest(
                rec, stage, ("input.bpf.o",)
            )
        # A refused handoff retains no watch entry (no
        # leaked monitor or descriptor for a later verify).
        assert os.path.abspath(stage) not in helper._STAGE_WATCHES
    finally:
        sealed_fs.NameWatch = real_watch
        helper.disarm_staged_handoffs(stage)
        helper.discard_owned_stages()
    assert swapped, "watch installation seam never fired"
    assert len(constructions) == 2, constructions


def test_staged_handoff_refuses_postinstall_substitution(tmp_path):
    # A1M6-1: a byte-identical, pre-mapped replacement
    # inserted after installation returns but before the
    # baseline is adopted must not become the expected
    # identity: the baseline comes from the
    # installer-held inode, never a later pathname read.
    import mmap as _mmap

    from mojobpf import sealed_fs

    helper = _load_helper()
    stage = helper.owned_stage(
        prefix="postinstall-probe-", dir=str(tmp_path),
    )
    target = os.path.join(stage, "input.bpf.o")
    with open(target, "wb") as handle:
        handle.write(b"captured-input.bpf.o")
    rec = _make_recorder(
        helper, ["case"], denials={}, inputs={
            "case": {"sources": [], "objects": [], "corpus": []},
        },
    )
    real_install = sealed_fs.install_sealed
    swapped = []
    mappings = []

    def _swapping_install(dirfd, name, data, seal):
        out = real_install(dirfd, name, data, seal)
        if not swapped:
            swapped.append(True)
            blob = bytes(data)
            sub = os.path.join(stage, name + ".substitute")
            with open(sub, "wb") as handle:
                handle.write(blob)
            fd = os.open(sub, os.O_RDWR)
            mappings.append((_mmap.mmap(fd, len(blob)), fd))
            os.rename(sub, os.path.join(stage, name))
        return out

    sealed_fs.install_sealed = _swapping_install
    try:
        with pytest.raises(AssertionError):
            helper.stage_consumed_for_guest(
                rec, stage, ("input.bpf.o",)
            )
        assert os.path.abspath(stage) not in helper._STAGE_WATCHES
    finally:
        sealed_fs.install_sealed = real_install
        for mapping, fd in mappings:
            mapping.close()
            os.close(fd)
        helper.disarm_staged_handoffs(stage)
        helper.discard_owned_stages()
    assert swapped, "install seam never fired"


def test_staged_handoff_refuses_postinstall_chmod(tmp_path):
    # A1M6-1: the sealed mode is part of the attested
    # baseline: re-arming writability after installation
    # returns (but before adoption) refuses, even with
    # identical bytes on the same inode.
    from mojobpf import sealed_fs

    helper = _load_helper()
    stage = helper.owned_stage(
        prefix="postinstall-chmod-", dir=str(tmp_path),
    )
    target = os.path.join(stage, "input.bpf.o")
    with open(target, "wb") as handle:
        handle.write(b"captured-input.bpf.o")
    rec = _make_recorder(
        helper, ["case"], denials={}, inputs={
            "case": {"sources": [], "objects": [], "corpus": []},
        },
    )
    real_install = sealed_fs.install_sealed
    touched = []

    def _touching_install(dirfd, name, data, seal):
        out = real_install(dirfd, name, data, seal)
        if not touched:
            touched.append(True)
            os.chmod(os.path.join(stage, name), 0o644)
        return out

    sealed_fs.install_sealed = _touching_install
    try:
        with pytest.raises(AssertionError):
            helper.stage_consumed_for_guest(
                rec, stage, ("input.bpf.o",)
            )
        assert os.path.abspath(stage) not in helper._STAGE_WATCHES
    finally:
        sealed_fs.install_sealed = real_install
        helper.disarm_staged_handoffs(stage)
        helper.discard_owned_stages()
    assert touched, "install seam never fired"


def test_staged_handoff_refuses_postinstall_swap_on_extend(tmp_path):
    # A1M6-1: the extension path adopts no baseline from
    # a pathname either: a byte-identical swap after the
    # second installation returns refuses on the
    # installer-held identity.
    from mojobpf import sealed_fs

    helper = _load_helper()
    stage = helper.owned_stage(
        prefix="postinstall-extend-", dir=str(tmp_path),
    )
    with open(os.path.join(stage, "input.bpf.o"), "wb") as handle:
        handle.write(b"captured-input.bpf.o")
    with open(os.path.join(stage, "second.bpf.o"), "wb") as handle:
        handle.write(b"captured-second.bpf.o")
    rec = _make_recorder(
        helper, ["case"], denials={}, inputs={
            "case": {"sources": [], "objects": [], "corpus": []},
        },
    )
    helper.stage_consumed_for_guest(rec, stage, ("input.bpf.o",))
    real_install = sealed_fs.install_sealed
    swapped = []

    def _swapping_install(dirfd, name, data, seal):
        out = real_install(dirfd, name, data, seal)
        if not swapped:
            swapped.append(True)
            sub = os.path.join(stage, name + ".substitute")
            with open(sub, "wb") as handle:
                handle.write(bytes(data))
            os.rename(sub, os.path.join(stage, name))
        return out

    sealed_fs.install_sealed = _swapping_install
    try:
        with pytest.raises(AssertionError):
            helper.stage_consumed_for_guest(
                rec, stage, ("second.bpf.o",)
            )
    finally:
        sealed_fs.install_sealed = real_install
        helper.disarm_staged_handoffs(stage)
        helper.discard_owned_stages()
    assert swapped, "install seam never fired"


def test_staged_handoff_refuses_inwindow_mapping_acquisition(tmp_path):
    # A1M7-1: a chmod+mmap+restore between publication and
    # the installer's snapshot refuses at install time:
    # the snapshot must not bless a mapped inode whose
    # later flips leave no event and no ctime move.
    import mmap as _mmap

    from mojobpf import sealed_fs

    helper = _load_helper()
    stage = helper.owned_stage(
        prefix="inwindow-map-", dir=str(tmp_path),
    )
    target = os.path.join(stage, "input.bpf.o")
    with open(target, "wb") as handle:
        handle.write(b"captured-input.bpf.o")
    rec = _make_recorder(
        helper, ["case"], denials={}, inputs={
            "case": {"sources": [], "objects": [], "corpus": []},
        },
    )
    real_verify = sealed_fs._verify_install
    held = []

    def _attacking_verify(dirfd, name, tmpfd, data):
        if not held:
            path = os.path.join(stage, name)
            before = os.stat(path)
            os.chmod(path, 0o644)
            wfd = os.open(path, os.O_RDWR)
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
        with pytest.raises(AssertionError):
            helper.stage_consumed_for_guest(
                rec, stage, ("input.bpf.o",)
            )
        assert os.path.abspath(stage) not in helper._STAGE_WATCHES
    finally:
        sealed_fs._verify_install = real_verify
        helper.disarm_staged_handoffs(stage)
        helper.discard_owned_stages()
    assert held, "verify seam never fired"
    held[0].close()


def test_staged_handoff_refuses_inwindow_mapping_on_extend(tmp_path):
    # A1M7-1: the extension path refuses the same window:
    # the install raises before forgive_names could
    # swallow the in-window chmod as a trusted event.
    import mmap as _mmap

    from mojobpf import sealed_fs

    helper = _load_helper()
    stage = helper.owned_stage(
        prefix="inwindow-extend-", dir=str(tmp_path),
    )
    with open(os.path.join(stage, "input.bpf.o"), "wb") as handle:
        handle.write(b"captured-input.bpf.o")
    with open(os.path.join(stage, "second.bpf.o"), "wb") as handle:
        handle.write(b"captured-second.bpf.o")
    rec = _make_recorder(
        helper, ["case"], denials={}, inputs={
            "case": {"sources": [], "objects": [], "corpus": []},
        },
    )
    helper.stage_consumed_for_guest(rec, stage, ("input.bpf.o",))
    real_verify = sealed_fs._verify_install
    held = []

    def _attacking_verify(dirfd, name, tmpfd, data):
        if not held:
            path = os.path.join(stage, name)
            before = os.stat(path)
            os.chmod(path, 0o644)
            wfd = os.open(path, os.O_RDWR)
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
        with pytest.raises(AssertionError):
            helper.stage_consumed_for_guest(
                rec, stage, ("second.bpf.o",)
            )
    finally:
        sealed_fs._verify_install = real_verify
        helper.disarm_staged_handoffs(stage)
        helper.discard_owned_stages()
    assert held, "verify seam never fired"
    held[0].close()


def test_staged_consume_refuses_symlink(tmp_path):
    # A1M4-2: a staged symlink is not a readable input. The
    # bound read refuses to follow it (fail closed) instead of
    # consuming its target's bytes under the link's name.
    helper = _load_helper()
    stage, rec, names = _handoff_stage(helper, tmp_path)
    path = os.path.join(stage, "input.bpf.o")
    os.unlink(path)
    outside = os.path.join(str(tmp_path), "outside")
    with open(outside, "wb") as handle:
        handle.write(b"outside-bytes")
    os.symlink(outside, path)
    assert rec.consume_staged("input.bpf.o", stage) is None
    assert helper._read_owned_entry(stage, "input.bpf.o") is None


def test_owned_removal_refuses_midop_substitution(tmp_path):
    # A1M4-2: a directory substituted between the identity
    # check and the removal must survive with its content;
    # the owned stage stays registered with a recorded error
    # instead of a silent clean.
    from mojobpf import sealed_fs

    helper = _load_helper()
    stage = helper.owned_stage(
        prefix="midop-probe-", dir=str(tmp_path),
    )
    with open(os.path.join(stage, "input.bpf.o"), "wb") as handle:
        handle.write(b"captured-input.bpf.o")
    relocated = stage + ".relocated"
    real_remove = sealed_fs.rmtree_owned

    def _swapping_remove(parent_fd, name, want):
        os.rename(stage, relocated)
        os.mkdir(stage)
        with open(os.path.join(stage, "foreign"), "wb") as handle:
            handle.write(b"foreign-bytes")
        return real_remove(parent_fd, name, want)

    sealed_fs.rmtree_owned = _swapping_remove
    try:
        discarded, errors = helper._discard_owned_stages_collected()
    finally:
        sealed_fs.rmtree_owned = real_remove
    assert stage not in discarded, discarded
    assert any(stage in item[0] for item in errors), errors
    with open(os.path.join(stage, "foreign"), "rb") as handle:
        assert handle.read() == b"foreign-bytes"
    assert stage in helper._OWNED_STAGES, (
        "substituted stage lost its registration"
    )
    shutil.rmtree(stage, ignore_errors=True)
    if os.path.isdir(relocated):
        os.rename(relocated, stage)
    helper.discard_owned_stages()


def test_owned_removal_refuses_absent_stage_as_clean(tmp_path):
    # A1M5-2: an owned stage renamed away during cleanup
    # survives elsewhere; pathname absence alone must not
    # establish CLEAN. The stage stays registered with a
    # recorded error, and restoring it allows a clean
    # discard.
    helper = _load_helper()
    stage = helper.owned_stage(
        prefix="absent-probe-", dir=str(tmp_path),
    )
    with open(os.path.join(stage, "input.bpf.o"), "wb") as handle:
        handle.write(b"captured-input.bpf.o")
    relocated = stage + ".relocated"
    os.rename(stage, relocated)
    try:
        discarded, errors = helper._discard_owned_stages_collected()
        assert stage not in discarded, discarded
        assert any(stage in item[0] for item in errors), errors
        assert stage in helper._OWNED_STAGES, (
            "vanished stage lost its registration"
        )
        os.rename(relocated, stage)
        discarded, errors = helper._discard_owned_stages_collected()
        assert stage in discarded, (discarded, errors)
        assert not errors, errors
        assert not os.path.lexists(stage)
    finally:
        if os.path.isdir(relocated):
            os.rename(relocated, stage)
        helper.discard_owned_stages()
        shutil.rmtree(stage, ignore_errors=True)
        shutil.rmtree(relocated, ignore_errors=True)


def test_staged_handoff_clean_path_keeps_digests(tmp_path):
    helper = _load_helper()
    stage, rec, names = _handoff_stage(helper, tmp_path)
    # Staged executables keep +x under the seal (the guest
    # executes helpers; stripping it breaks the run).
    os.chmod(os.path.join(stage, "probe_helper.py"), 0o755)
    try:
        digests = helper.stage_consumed_for_guest(rec, stage, names)
        assert helper.verify_staged_handoffs_now() == []
        for name in names:
            with open(os.path.join(stage, name), "rb") as handle:
                data = handle.read()
            assert helper._sha256_bytes(data) == digests[name]
            mode = os.stat(os.path.join(stage, name)).st_mode & 0o777
            want = 0o555 if name == "probe_helper.py" else 0o444
            assert mode == want, (name, oct(mode))
    finally:
        helper.disarm_staged_handoffs(stage)


def test_staged_handoff_ignores_unrelated_stage_files(tmp_path):
    # Host outputs written after handoff (guest transcripts)
    # share the stage directory but are not handed-off inputs.
    helper = _load_helper()
    stage, rec, names = _handoff_stage(helper, tmp_path)
    try:
        helper.stage_consumed_for_guest(rec, stage, names)
        transcript = os.path.join(stage, "guest_transcript.log")
        with open(transcript, "w", encoding="utf-8") as handle:
            handle.write("output\n")
        with open(transcript, "a", encoding="utf-8") as handle:
            handle.write("more\n")
        assert helper.verify_staged_handoffs_now() == []
    finally:
        helper.disarm_staged_handoffs(stage)


def test_end_case_fails_on_handoff_tamper(tmp_path):
    helper = _load_helper()
    stage, rec, names = _handoff_stage(helper, tmp_path)
    try:
        rec.begin_case("case")
        helper.stage_consumed_for_guest(rec, stage, names)
        victim = os.path.join(stage, names[1])
        os.chmod(victim, 0o644)
        with open(victim, "wb") as handle:
            handle.write(b"tampered")
        rec.end_case_pass("case")
        record = rec._cases["case"]
        assert record["outcome"] == "FAIL", record
        assert record["failure_stage"] == "TEST_RUN", record
        assert any(
            "input.bpf.o" in entry for entry in record["cleanup"]["residue"]
        ), record
    finally:
        helper.disarm_staged_handoffs(stage)


@pytest.mark.parametrize(
    "name",
    ["input.bpf.o", "probe_helper.py", "frame_s00.bin"],
    ids=["object", "helper", "frame"],
)
def test_require_handed_digests_refuses_missing(tmp_path, name):
    # A1M-3: under a recorder, a missing handoff digest is
    # refused before launch, never substituted with a fresh
    # filesystem hash.
    import re
    helper = _load_helper()
    handed = {"other.bin": "b" * 64}
    with pytest.raises(AssertionError, match=re.escape(name)):
        helper.require_handed_digests(handed, ("other.bin", name))
    assert helper.require_handed_digests(handed, ("other.bin",)) == {
        "other.bin": "b" * 64
    }


def test_accounting_stages_frames_from_verified_buffers(tmp_path):
    # A1M2-4: a payload substituted into an original frame after
    # manifest validation must not reach the stage: staging
    # writes the validated buffers, never reopens originals.
    import shutil
    suite = _load_suite("tests/kernel/test_xdp_accounting.py")
    corpus = os.path.join(str(tmp_path), "corpus")
    shutil.copytree(suite.CORPUS_DIR, corpus)
    seeded = os.path.join(str(tmp_path), "seeded_manifest.json")
    shutil.copyfile(suite.SEEDED_MANIFEST, seeded)
    regressions = os.path.join(str(tmp_path), "regressions")
    shutil.copytree(suite.REGRESSION_DIR, regressions)
    saved = (
        suite.CORPUS_DIR, suite.SPEC_MANIFEST, suite.SEEDED_MANIFEST,
        suite.REGRESSION_DIR, suite.REGRESSION_MANIFEST,
    )
    suite.CORPUS_DIR = corpus
    suite.SPEC_MANIFEST = os.path.join(corpus, "manifest.json")
    suite.SEEDED_MANIFEST = seeded
    suite.REGRESSION_DIR = regressions
    suite.REGRESSION_MANIFEST = os.path.join(regressions, "manifest.json")
    try:
        frames = suite.load_corpus()
        assert len(frames) == 68
        validated = dict(frames)
        victim = os.path.join(corpus, frames[0][0])
        with open(victim, "r+b") as handle:
            first = handle.read(1)
            handle.seek(0)
            handle.write(bytes([first[0] ^ 0xFF]))
        stage = os.path.join(str(tmp_path), "stage")
        os.makedirs(stage)
        staged = suite.stage_verified_frames(stage, frames)
        for name, raw in frames:
            with open(staged[name], "rb") as handle:
                assert handle.read() == raw == validated[name], name
        with open(victim, "rb") as handle:
            assert handle.read() != validated[frames[0][0]]
    finally:
        (suite.CORPUS_DIR, suite.SPEC_MANIFEST, suite.SEEDED_MANIFEST,
         suite.REGRESSION_DIR, suite.REGRESSION_MANIFEST) = saved


def _r5_consume(recorder, path, staged=None):
    """Version-adaptive consumption read for round-5 regressions.

    Uses the recorder's consumption reader when it exists
    (fixed code: the read is logged as consumption), else a
    plain open (d98cd0a, where any consumption is invisible to
    the recorder). ``staged`` is the stage directory for staged
    entries, else ``path`` is absolute.
    """
    if staged is None:
        func = getattr(recorder, "consume_absolute", None)
        if func is not None:
            return func(path)
        with open(path, "rb") as handle:
            return handle.read()
    func = getattr(recorder, "consume_staged", None)
    if func is not None:
        return func(path, staged)
    with open(os.path.join(staged, path), "rb") as handle:
        return handle.read()


def test_consumption_sandwich_between_reads_fails_closed():
    # Round-5 #2, fresh variant: an input consumed with
    # different bytes across observations -- sealed A, consumed
    # B, restored A (the between-reads sandwich, absolute
    # source, staged object, and staged corpus) -- must fail
    # closed: no single digest can attest two executed
    # byte-strings. On d98cd0a the sandwich is invisible (plain
    # reads) and the run passes attesting A; with the
    # consumption reader the disagreement fails at TEST_RUN.
    import hashlib

    helper = _load_helper()
    cases = (
        ("absolute-source", "sources", "sandwich-src.mojo", False),
        ("staged-object", "objects", "sandwich.bpf.o", True),
        ("staged-corpus", "corpus", "sandwich.bin", True),
    )
    for label, _class, leaf, staged in cases:
        original = b"%s-original-bytes" % label.encode()
        replacement = b"%s-replacement-bytes" % label.encode()
        if staged:
            stage = helper.owned_stage(prefix="r5-sandwich-")
            target = os.path.join(stage, leaf)
            entry = ("stage", leaf)
        else:
            stage = tempfile.mkdtemp(prefix="r5-sandwich-abs-")
            target = os.path.join(stage, leaf)
            entry = target
        try:
            with open(target, "wb") as handle:
                handle.write(original)
            with _harness_path():
                rec = _make_recorder(
                    helper,
                    ["test_probe"],
                    inputs={
                        "test_probe": {
                            "sources": [],
                            "objects": [],
                            "corpus": [],
                            _class: [entry],
                        }
                    },
                )
                rec.begin_case("test_probe")
                if staged:
                    assert _r5_consume(rec, leaf, stage) == original
                else:
                    assert _r5_consume(rec, target) == original
                with open(target, "wb") as handle:
                    handle.write(replacement)
                if staged:
                    assert _r5_consume(rec, leaf, stage) == replacement
                else:
                    assert _r5_consume(rec, target) == replacement
                with open(target, "wb") as handle:
                    handle.write(original)
                rec.end_case_pass("test_probe")
                exit_code, lines = _finish_lines(
                    rec, stage_dir=stage if staged else None
                )
            _plan, parsed, suite = _parse_emitted(lines)
            if _class == "corpus":
                attested = parsed[0].identities["workload"][
                    "corpus_sha256"
                ]
            else:
                key = {
                    "sources": "source_sha256",
                    "objects": "object_sha256",
                }[_class]
                attested = parsed[0].identities[key]
            assert exit_code != 0, (label, exit_code, attested, lines)
            assert suite.decision["verdict"] != "PASS", (
                label,
                suite.decision,
                "attested",
                attested,
                "consumed",
                sorted({
                    hashlib.sha256(original).hexdigest(),
                    hashlib.sha256(replacement).hexdigest(),
                }),
            )
            assert parsed[0].outcome == "FAIL", parsed[0].to_dict()
            assert parsed[0].failure_stage == "TEST_RUN", (
                parsed[0].to_dict()
            )
            assert attested == helper.ZERO_SHA256, parsed[0].to_dict()
        finally:
            helper.discard_owned_stages()
            shutil.rmtree(stage, ignore_errors=True)


def test_consumption_swap_without_restore_still_fails_closed():
    # The same sandwich without the restore: the seal tripwire
    # already failed this on d98cd0a; the consumption reader
    # must fail it too (no behavior change, both layers agree).
    helper = _load_helper()
    original = b"sandwich-norestore-original"
    replacement = b"sandwich-norestore-replacement"
    stage = helper.owned_stage(prefix="r5-sandwich-nr-")
    try:
        target = os.path.join(stage, "sandwich-nr.bpf.o")
        with open(target, "wb") as handle:
            handle.write(original)
        with _harness_path():
            rec = _make_recorder(
                helper,
                ["test_probe"],
                inputs={
                    "test_probe": {
                        "sources": [],
                        "objects": [("stage", "sandwich-nr.bpf.o")],
                        "corpus": [],
                    }
                },
            )
            rec.begin_case("test_probe")
            assert _r5_consume(
                rec, "sandwich-nr.bpf.o", stage
            ) == original
            with open(target, "wb") as handle:
                handle.write(replacement)
            assert _r5_consume(
                rec, "sandwich-nr.bpf.o", stage
            ) == replacement
            rec.end_case_pass("test_probe")
            exit_code, lines = _finish_lines(rec, stage_dir=stage)
        _plan, parsed, suite = _parse_emitted(lines)
        assert exit_code != 0, (exit_code, lines)
        assert suite.decision["verdict"] != "PASS", suite.decision
        assert parsed[0].outcome == "FAIL", parsed[0].to_dict()
        assert parsed[0].failure_stage == "TEST_RUN", (
            parsed[0].to_dict()
        )
    finally:
        helper.discard_owned_stages()
        shutil.rmtree(stage, ignore_errors=True)


def test_consumption_before_first_observation_attests_consumed():
    # Bytes swapped in before the first observation are the
    # consumed bytes: attesting them is identity, not a
    # bypass. Guards against over-refusal in both versions.
    import hashlib

    helper = _load_helper()
    replacement = b"sandwich-prefirst-replacement"
    stage = helper.owned_stage(prefix="r5-sandwich-pre-")
    try:
        target = os.path.join(stage, "sandwich-pre.bpf.o")
        with open(target, "wb") as handle:
            handle.write(replacement)
        with _harness_path():
            rec = _make_recorder(
                helper,
                ["test_probe"],
                inputs={
                    "test_probe": {
                        "sources": [],
                        "objects": [("stage", "sandwich-pre.bpf.o")],
                        "corpus": [],
                    }
                },
            )
            rec.begin_case("test_probe")
            assert _r5_consume(
                rec, "sandwich-pre.bpf.o", stage
            ) == replacement
            rec.end_case_pass("test_probe")
            exit_code, lines = _finish_lines(rec, stage_dir=stage)
        assert exit_code == 0, lines
        _plan, parsed, suite = _parse_emitted(lines)
        assert suite.decision["verdict"] == "PASS", suite.decision
        attested = parsed[0].identities["object_sha256"]
        assert attested == hashlib.sha256(
            replacement + b"\x00"
        ).hexdigest(), parsed[0].to_dict()
    finally:
        helper.discard_owned_stages()
        shutil.rmtree(stage, ignore_errors=True)


def test_consumption_multi_read_control_still_passes():
    # Positive control for round-5 #2: legitimate multi-read
    # execution (every consumption observation agrees) still
    # passes and attests the consumed bytes. No over-refusal.
    import hashlib

    helper = _load_helper()
    original = b"sandwich-control-bytes"
    stage = helper.owned_stage(prefix="r5-sandwich-ctl-")
    try:
        target = os.path.join(stage, "sandwich-ctl.bpf.o")
        with open(target, "wb") as handle:
            handle.write(original)
        with _harness_path():
            rec = _make_recorder(
                helper,
                ["test_probe"],
                inputs={
                    "test_probe": {
                        "sources": [],
                        "objects": [("stage", "sandwich-ctl.bpf.o")],
                        "corpus": [],
                    }
                },
            )
            rec.begin_case("test_probe")
            for _ in range(3):
                assert _r5_consume(
                    rec, "sandwich-ctl.bpf.o", stage
                ) == original
            rec.end_case_pass("test_probe")
            exit_code, lines = _finish_lines(rec, stage_dir=stage)
        assert exit_code == 0, lines
        _plan, parsed, suite = _parse_emitted(lines)
        assert suite.decision["verdict"] == "PASS", suite.decision
        attested = parsed[0].identities["object_sha256"]
        assert attested == hashlib.sha256(
            original + b"\x00"
        ).hexdigest(), parsed[0].to_dict()
    finally:
        helper.discard_owned_stages()
        shutil.rmtree(stage, ignore_errors=True)


def test_finish_from_unconsumed_stage_rejects():
    # Round-5 #3, fresh variant: three owned stages; the case
    # seals and consumes A in stage one, then finish presents
    # stage two (B). Bytes no case consumed must never be
    # attested: the executing case fails at TEST_RUN pinning
    # zeros. On d98cd0a the run passes attesting B. A control
    # finishing from the consumed stage still passes.
    helper = _load_helper()
    first = helper.owned_stage(prefix="r5-finish-one-")
    second = helper.owned_stage(prefix="r5-finish-two-")
    third = helper.owned_stage(prefix="r5-finish-three-")
    try:
        original = b"finish-one-bytes"
        with open(os.path.join(first, "finish.bpf.o"), "wb") as fh:
            fh.write(original)
        with open(os.path.join(second, "finish.bpf.o"), "wb") as fh:
            fh.write(b"finish-two-bytes")
        with open(os.path.join(third, "finish.bpf.o"), "wb") as fh:
            fh.write(b"finish-three-bytes")
        with _harness_path():
            rec = _make_recorder(
                helper,
                ["test_probe"],
                inputs={
                    "test_probe": {
                        "sources": [],
                        "objects": [("stage", "finish.bpf.o")],
                        "corpus": [],
                    }
                },
            )
            rec.begin_case("test_probe")
            assert _r5_consume(rec, "finish.bpf.o", first) == original
            rec.end_case_pass("test_probe")
            exit_code, lines = _finish_lines(rec, stage_dir=second)
        _plan, parsed, suite = _parse_emitted(lines)
        attested = parsed[0].identities["object_sha256"]
        assert exit_code != 0, (exit_code, attested, lines)
        assert suite.decision["verdict"] != "PASS", (
            suite.decision,
            "attested",
            attested,
        )
        assert parsed[0].outcome == "FAIL", parsed[0].to_dict()
        assert parsed[0].failure_stage == "TEST_RUN", (
            parsed[0].to_dict()
        )
        assert attested == helper.ZERO_SHA256, parsed[0].to_dict()
        residue = parsed[0].to_dict()["cleanup"]["residue"]
        assert any(
            "never consumed from the finish stage" in entry
            for entry in residue
        ), residue

        # Control: finishing from the consumed stage passes and
        # attests the consumed bytes (the first finish discarded
        # the stages, so rebuild the consumed one).
        first = helper.owned_stage(prefix="r5-finish-one-ctl-")
        with open(os.path.join(first, "finish.bpf.o"), "wb") as fh:
            fh.write(original)
        with _harness_path():
            rec = _make_recorder(
                helper,
                ["test_probe"],
                inputs={
                    "test_probe": {
                        "sources": [],
                        "objects": [("stage", "finish.bpf.o")],
                        "corpus": [],
                    }
                },
            )
            rec.begin_case("test_probe")
            assert _r5_consume(rec, "finish.bpf.o", first) == original
            rec.end_case_pass("test_probe")
            exit_code, lines = _finish_lines(rec, stage_dir=first)
        assert exit_code == 0, lines
        _plan, parsed, suite = _parse_emitted(lines)
        assert suite.decision["verdict"] == "PASS", suite.decision
    finally:
        helper.discard_owned_stages()
        for stage in (first, second, third):
            shutil.rmtree(stage, ignore_errors=True)


def test_warmup_consumption_seals_before_first_begin():
    # Round-5 #1, fresh variant (map suite instead of XDP): a
    # stand-in fixture that consumes the base object A during the
    # pre-begin warmup, reports hashes, then replaces the base
    # path with mutant bytes B must not pass attesting B for
    # executions of A. Nothing consumable may execute before
    # its bytes seal: the suite-mode recorder requires
    # pre-begin explicit consumption records, which a fixture
    # that reads outside the recorder never creates. On d98cd0a
    # this run exits 0 with PASS attesting B; fixed, every
    # staged-declaring executing case fails at TEST_RUN.
    import hashlib

    suite = _load_suite("tests/kernel/test_map_roundtrip.py")
    helper = suite.guest_proc
    original = b"map-warmup-base-bytes-A"
    replacement = b"map-warmup-mutant-bytes-B"
    consumed = {}

    def _map_body(tag, after_hex):
        lines = [
            "load_exit=0",
            "mapinfo_exit=0",
            "init_exit=0",
            "before_exit=0",
            "run_exit=0",
            "after_exit=0",
            "map_found=1",
            "map_type=array",
            "map_key=4",
            "map_value=8",
            "map_entries=1",
            "unload_ok=1",
            "--- %s before ---" % tag,
            "key: 00 00 00 00",
            "value: %s" % " ".join(
                suite.hexle(suite.INIT_VALUE)[i:i + 2]
                for i in range(0, 16, 2)
            ),
            "--- %s run ---" % tag,
            "Return value: %d" % suite.XDP_PASS,
            "--- %s after ---" % tag,
            "key: 00 00 00 00",
            "value: %s" % " ".join(
                after_hex[i:i + 2] for i in range(0, 16, 2)
            ),
        ]
        return "\n".join(lines)

    def _neg_record(log_line):
        return {
            "exit": 4,
            "body": json.dumps({
                "contract_version": 2,
                "stage": "load",
                "classification": "verifier",
                "note": "kernel verifier rejected the load",
                "commands": [
                    {
                        "argv": ["bpftool", "prog", "load"],
                        "exit_code": 1,
                        "stdout": "",
                        "stderr": "Error: %s" % log_line,
                    }
                ],
            }),
        }

    def _standin():
        stage = helper.owned_stage(prefix="r5-map-warmup-")
        with open(os.path.join(stage, "base.bpf.o"), "wb") as fh:
            fh.write(original)
        with open(
            os.path.join(stage, "mutated.bpf.o"), "wb"
        ) as fh:
            fh.write(replacement)
        with open(os.path.join(stage, "oob.bpf.o"), "wb") as fh:
            fh.write(b"map-warmup-oob-bytes")
        with open(
            os.path.join(stage, "unchecked.bpf.o"), "wb"
        ) as fh:
            fh.write(b"map-warmup-unchecked-bytes")
        with open(os.path.join(stage, "data.bin"), "wb") as fh:
            fh.write(bytes(60))
        with open(suite.HARNESS, "rb") as handle:
            harness_bytes = handle.read()
        with open(
            os.path.join(stage, "bpf_test_run.py"), "wb"
        ) as handle:
            handle.write(harness_bytes)
        # Warmup consumption, outside the recorder (plain reads,
        # like a fixture that never routes through it).
        for tag, leaf in (
            ("base", "base.bpf.o"),
            ("mut", "mutated.bpf.o"),
            ("stale", "base.bpf.o"),
        ):
            with open(os.path.join(stage, leaf), "rb") as handle:
                consumed[tag] = handle.read()
        assert consumed["base"] == original
        assert consumed["stale"] == original
        assert consumed["mut"] == replacement
        expected = suite.lane_lock.expected_kernel_release(
            suite.REPO_ROOT, suite.VNG_RELEASE
        )
        lines = [
            "guest-kernel: %s" % expected,
            "pin absent (unloaded)",
        ]
        for name in (
            "bpf_test_run.py",
            "base.bpf.o",
            "mutated.bpf.o",
            "oob.bpf.o",
            "unchecked.bpf.o",
            "data.bin",
        ):
            with open(os.path.join(stage, name), "rb") as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()
            lines.append("%s  %s" % (digest, name))
        output = "\n".join(lines) + "\n"
        # Replace the consumed base path with the mutant bytes
        # before returning (the pre-seal swap).
        with open(os.path.join(stage, "base.bpf.o"), "wb") as fh:
            fh.write(replacement)
        return {
            "stage": stage,
            "output": output,
            "results": {
                "base": {
                    "exit": None,
                    "body": _map_body(
                        "base", suite.hexle(suite.BASE_VALUE)
                    ),
                },
                "mut": {
                    "exit": None,
                    "body": _map_body(
                        "mut", suite.hexle(suite.MUTATED_VALUE)
                    ),
                },
                "stale": {
                    "exit": None,
                    "body": _map_body(
                        "stale", suite.hexle(suite.BASE_VALUE)
                    ),
                },
                "oob": _neg_record(suite.OOB_LOG_LINE),
                "unchecked": _neg_record(
                    suite.UNCHECKED_LOG_LINE
                ),
            },
        }

    real_run = suite.guest_run
    real_popen = suite.guest_proc.subprocess.Popen
    saved_cache = dict(suite._CACHED)
    suite._CACHED.clear()
    vng_calls = []

    def _spy(*args, **kwargs):
        argv = args[0] if args else []
        if argv and os.path.basename(argv[0]) == "vng":
            vng_calls.append(list(argv))
            raise FileNotFoundError("no vng boot in the warmup drill")
        return real_popen(*args, **kwargs)

    suite.guest_run = _standin
    suite.guest_proc.subprocess.Popen = _spy
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer):
            code = suite.main()
    finally:
        suite.guest_run = real_run
        suite.guest_proc.subprocess.Popen = real_popen
        suite._CACHED.clear()
        suite._CACHED.update(saved_cache)
        getattr(helper, "clear_active_recorder", lambda: None)()
        helper.discard_owned_stages()
    text = buffer.getvalue()
    _plan, parsed, terminal = _parse_emitted(text.splitlines())
    by_id = {result.case_id: result for result in parsed}
    base = by_id["test_map_roundtrip_42"]
    attested = base.identities["object_sha256"]
    assert vng_calls == [], vng_calls
    assert code != 0, (code, text[-800:])
    assert terminal.decision["verdict"] != "PASS", (
        terminal.decision,
        "attested",
        attested,
        "consumed-base",
        hashlib.sha256(consumed["base"]).hexdigest(),
    )
    assert base.outcome == "FAIL", base.to_dict()
    assert base.failure_stage == "TEST_RUN", base.to_dict()
    residue = base.to_dict()["cleanup"]["residue"]
    assert any(
        "was never consumed before execution" in entry
        for entry in residue
    ), residue


def test_consumption_sweep_covers_leased_suites():
    # Every leased suite main must activate its recorder (so
    # fixture reads route through it from the warmup on), and
    # every staged-input fixture must hand its staged bytes to
    # the guest through consume-then-restage before executing
    # (A1: the handoff helper, not the legacy scan).
    # Structural guard for the round-5 #1 sweep: 25 mains,
    # 25 fixture files (26 fixture functions: lifecycle stages
    # both its guest closure and its preflight objects).
    import ast

    mains = [
        "tests/kernel/test_%s.py" % name
        for name in (
            "array_maps", "cleanup", "core_layouts",
            "generalized_arrays", "hash_maps", "map_roundtrip",
            "mojo_percpu", "mojo_xdp", "packet_sdk",
            "parse_checksum_sdk", "percpu_maps", "ringbuf_reserve",
            "subprog_calls", "tracepoint_counter",
            "tracepoint_events", "tracing_lifecycle",
            "uprobe_register", "xdp_accounting",
        )
    ] + [
        "tests/verifier/test_helper_licenses.py",
        "tests/verifier/test_subset_kernel.py",
    ] + [
        "tests/packaging/test_%s_consumer.py" % name
        for name in (
            "external", "hash", "reserve", "subprog", "uprobe"
        )
    ]
    assert len(mains) == 25, len(mains)
    fixtures = {
        "tests/kernel/test_array_maps.py": ("guest_run",),
        "tests/kernel/test_cleanup.py": ("fixture",),
        "tests/kernel/test_core_layouts.py": ("guest_run",),
        "tests/kernel/test_generalized_arrays.py": ("guest_run",),
        "tests/kernel/test_hash_maps.py": ("guest_run",),
        "tests/kernel/test_map_roundtrip.py": ("guest_run",),
        "tests/kernel/test_mojo_percpu.py": ("guest_run",),
        "tests/kernel/test_mojo_xdp.py": ("guest_run",),
        "tests/kernel/test_packet_sdk.py": ("guest_run",),
        "tests/kernel/test_parse_checksum_sdk.py": ("guest_run",),
        "tests/kernel/test_percpu_maps.py": ("guest_run",),
        "tests/kernel/test_ringbuf_reserve.py": ("_execute_once",),
        "tests/kernel/test_subprog_calls.py": ("guest_run",),
        "tests/kernel/test_tracepoint_events.py": ("_execute_once",),
        "tests/kernel/test_tracepoint_counter.py": ("_executed_once",),
        "tests/kernel/test_tracing_lifecycle.py": (
            "_executed_once", "preflight_objects",
        ),
        "tests/kernel/test_uprobe_register.py": ("executed",),
        "tests/verifier/test_helper_licenses.py": ("_executed_once",),
        "tests/kernel/test_xdp_accounting.py": ("guest_run",),
        "tests/verifier/test_subset_kernel.py": ("guest_run",),
        "tests/packaging/test_external_consumer.py": ("guest_run",),
        "tests/packaging/test_hash_consumer.py": ("guest_run",),
        "tests/packaging/test_reserve_consumer.py": ("guest_run",),
        "tests/packaging/test_subprog_consumer.py": ("guest_run",),
        "tests/packaging/test_uprobe_consumer.py": ("guest_run",),
    }
    assert len(fixtures) == 25, len(fixtures)
    assert sum(len(funcs) for funcs in fixtures.values()) == 26, (
        sum(len(funcs) for funcs in fixtures.values())
    )
    for relpath in mains:
        with open(os.path.join(REPO_ROOT, relpath)) as handle:
            tree = ast.parse(handle.read())
        mains_found = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "main"
        ]
        assert len(mains_found) == 1, relpath
        dump = ast.dump(mains_found[0])
        assert "set_active_recorder" in dump, relpath
    for relpath, funcs in fixtures.items():
        with open(os.path.join(REPO_ROOT, relpath)) as handle:
            tree = ast.parse(handle.read())
        for func in funcs:
            found = [
                node for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef)
                and node.name == func
            ]
            assert len(found) == 1, (relpath, func)
            dump = ast.dump(found[0])
            assert "stage_consumed_for_guest" in dump, (relpath, func)


_R6_CLASSES = (
    ("sources", "source_sha256", "input.mojo"),
    ("objects", "object_sha256", "input.bpf.o"),
    ("corpus", "corpus_sha256", "input.bin"),
)


@contextlib.contextmanager
def _r6_path(helper, path):
    """Replay the same handoff against f6f3e88 and the redesign."""
    if hasattr(helper, "consumed_path"):
        with helper.consumed_path(path) as snapshot:
            yield snapshot
    else:
        yield helper.note_consumed(path)


def _r6_digest(result, identity):
    if identity == "corpus_sha256":
        return result.identities["workload"][identity]
    return result.identities[identity]


def _r6_inputs(kind, entry):
    return {"test_probe": {"sources": [], "objects": [], "corpus": [],
                           kind: [entry]}}


@pytest.mark.parametrize("kind,identity,leaf", _R6_CLASSES)
@pytest.mark.parametrize("declaration", ("absolute", "staged"))
def test_r6_path_handoff_uses_logged_buffer(kind, identity, leaf, declaration):
    # A path-only consumer must see the one logged read, even if
    # the original name changes between the handoff and its open.
    # On f6f3e88 this reports PASS/CLEAN attesting A after using B.
    import hashlib

    helper = _load_helper()
    stage = helper.owned_stage(prefix="r6-handoff-")
    target = os.path.join(stage, leaf)
    original, replacement = b"reject-A", b"accept-B"
    try:
        with open(target, "wb") as handle:
            handle.write(original)
        entry = target if declaration == "absolute" else ("stage", leaf)
        with _harness_path():
            rec = _make_recorder(helper, ["test_probe"],
                                 inputs=_r6_inputs(kind, entry))
            helper.set_active_recorder(rec)
            assert helper.read_consumed(target) == original
            rec.begin_case("test_probe")
            with _r6_path(helper, target) as downstream:
                with open(target, "wb") as handle:
                    handle.write(replacement)
                with open(downstream, "rb") as handle:
                    used = handle.read()
                with open(target, "wb") as handle:
                    handle.write(original)
            if used == replacement:
                rec.end_case_pass("test_probe")
            else:
                rec.end_case_fail("test_probe", "TEST_RUN")
            code, lines = _finish_lines(rec, stage_dir=stage)
        _plan, results, terminal = _parse_emitted(lines)
        result = results[0]
        exact = hashlib.sha256(used + b"\x00").hexdigest()
        assert _r6_digest(result, identity) == exact, (
            "consumption mismatch", used, code, terminal.decision,
            result.to_dict(),
        )
        assert used == original, "consumer reopened the mutable input"
        assert code == 1 and result.outcome == "FAIL"
    finally:
        helper.clear_active_recorder()
        helper.discard_owned_stages()


@pytest.mark.parametrize("kind,identity,leaf", _R6_CLASSES)
@pytest.mark.parametrize("declaration", ("absolute", "staged"))
@pytest.mark.parametrize("phase", ("case", "finish"))
def test_r6_alias_contradiction_fails(kind, identity, leaf, declaration, phase):
    # Both directions: absolute declaration read via its staged
    # alias, and staged declaration read via its absolute alias.
    helper = _load_helper()
    stage = helper.owned_stage(prefix="r6-alias-")
    target = os.path.join(stage, leaf)
    original, replacement = b"sealed-A", b"consumed-B"
    try:
        with open(target, "wb") as handle:
            handle.write(original)
        entry = target if declaration == "absolute" else ("stage", leaf)
        with _harness_path():
            rec = _make_recorder(helper, ["test_probe"],
                                 inputs=_r6_inputs(kind, entry))
            helper.set_active_recorder(rec)
            assert helper.read_consumed(target) == original
            rec.begin_case("test_probe")
            if phase == "finish":
                rec.end_case_pass("test_probe")
            with open(target, "wb") as handle:
                handle.write(replacement)
            if declaration == "absolute":
                used = helper.read_consumed(target)
            else:
                used = rec.consume_absolute(target)
            assert used == replacement
            with open(target, "wb") as handle:
                handle.write(original)
            if phase == "case":
                rec.end_case_pass("test_probe")
            code, lines = _finish_lines(rec, stage_dir=stage)
        _plan, results, terminal = _parse_emitted(lines)
        assert code == 1, (code, terminal.decision, results[0].to_dict())
        assert results[0].outcome == "FAIL"
        assert results[0].failure_stage == "TEST_RUN"
        assert _r6_digest(results[0], identity) == helper.ZERO_SHA256
    finally:
        helper.clear_active_recorder()
        helper.discard_owned_stages()


@pytest.mark.parametrize("kind,identity,leaf", _R6_CLASSES)
@pytest.mark.parametrize("declaration", ("absolute", "staged"))
@pytest.mark.parametrize("prefirst", (False, True))
def test_r6_multi_read_exact_control(kind, identity, leaf, declaration, prefirst):
    import hashlib

    helper = _load_helper()
    stage = helper.owned_stage(prefix="r6-control-")
    target = os.path.join(stage, leaf)
    data = b"first version"
    try:
        with open(target, "wb") as handle:
            handle.write(data)
        if prefirst:
            data = b"replacement before any observation"
            with open(target, "wb") as handle:
                handle.write(data)
        entry = target if declaration == "absolute" else ("stage", leaf)
        with _harness_path():
            rec = _make_recorder(helper, ["test_probe"],
                                 inputs=_r6_inputs(kind, entry))
            helper.set_active_recorder(rec)
            assert helper.read_consumed(target) == data
            rec.begin_case("test_probe")
            for _ in range(3):
                assert rec.consume_absolute(target) == data
                assert rec.consume_staged(leaf, stage) == data
                with _r6_path(helper, target) as snapshot:
                    with open(snapshot, "rb") as handle:
                        assert handle.read() == data
            rec.end_case_pass("test_probe")
            code, lines = _finish_lines(rec, stage_dir=stage)
        _plan, results, terminal = _parse_emitted(lines)
        assert code == 0, (terminal.decision, results[0].to_dict())
        assert results[0].cleanup == {"status": "CLEAN", "residue": []}
        assert _r6_digest(results[0], identity) == hashlib.sha256(
            data + b"\x00"
        ).hexdigest()
    finally:
        helper.clear_active_recorder()
        helper.discard_owned_stages()


@pytest.mark.parametrize("declaration", ("absolute", "staged"))
def test_r6_real_inspector_handoff(declaration, monkeypatch):
    # Exercise the unchanged real inspector through the hash suite.
    # Synthetic valid B is offered only at the downstream open;
    # the original malformed A is restored before the case ends.
    from mojobpf import inspect as inspector

    suite = _load_suite("tests/kernel/test_hash_maps.py")
    helper = suite.guest_proc
    elf = _load_suite("tests/elf/test_artifact_contract.py")
    valid = elf._clean_builder().build()
    invalid = b"malformed object A"
    stage = helper.owned_stage(prefix="r6-inspector-")
    targets = [os.path.join(stage, name) for name in
               ("hash_rmw.bpf.o", "hash_del.bpf.o")]
    try:
        for target in targets:
            with open(target, "wb") as handle:
                handle.write(invalid)
        monkeypatch.setattr(suite, "executed", lambda: {"stage": stage})
        real_read = inspector._read_object_bytes
        used = []

        def substitute(path):
            for target in targets:
                with open(target, "wb") as handle:
                    handle.write(valid)
            try:
                data = real_read(path)
                used.append(data)
                return data
            finally:
                for target in targets:
                    with open(target, "wb") as handle:
                        handle.write(invalid)

        entries = targets if declaration == "absolute" else [
            ("stage", os.path.basename(path)) for path in targets
        ]
        with _harness_path():
            rec = _make_recorder(helper, ["test_probe"], inputs={
                "test_probe": {"sources": [], "objects": entries, "corpus": []}
            })
            helper.set_active_recorder(rec)
            for target in targets:
                helper.read_consumed(target)
            rec.begin_case("test_probe")
            with monkeypatch.context() as patch:
                patch.setattr(inspector, "_read_object_bytes", substitute)
                try:
                    suite.test_license_gate_agrees()
                except AssertionError:
                    rec.end_case_fail("test_probe", "TEST_RUN")
                else:
                    rec.end_case_pass("test_probe")
            code, lines = _finish_lines(rec, stage_dir=stage)
        _plan, results, terminal = _parse_emitted(lines)
        assert code == 1, (code, terminal.decision, results[0].to_dict())
        assert used == [invalid], "the inspector consumed substituted B"
        assert results[0].outcome == "FAIL"
    finally:
        helper.clear_active_recorder()
        helper.discard_owned_stages()


@pytest.mark.parametrize("kind,identity", (("sources", "source_sha256"),
                                          ("corpus", "corpus_sha256")))
@pytest.mark.parametrize("declaration", ("absolute", "staged"))
def test_r6_xdp_fixture_read_is_recorded(kind, identity, declaration, monkeypatch):
    import builtins

    suite = _load_suite("tests/kernel/test_mojo_xdp.py")
    helper = suite.guest_proc
    stage = helper.owned_stage(prefix="r6-xdp-fixture-")
    target = os.path.join(stage, "pkt_drop.bin")
    correct = bytes(14) + b"\x01" + bytes(45)
    sealed = bytes(60)
    try:
        for name, data in (("pkt_drop.bin", sealed),
                           ("pkt_pass.bin", bytes(60)),
                           ("pkt_short.bin", bytes(10))):
            with open(os.path.join(stage, name), "wb") as handle:
                handle.write(data)
        monkeypatch.setattr(suite, "EXAMPLE_DIR", stage)
        monkeypatch.setattr(suite, "executed", lambda: {"packets": {
            "pkt_drop.bin": correct, "pkt_pass.bin": bytes(60),
            "pkt_short.bin": bytes(10),
        }})
        entry = target if declaration == "absolute" else ("stage", "pkt_drop.bin")
        real_open = builtins.open
        reads = []

        def substitute(path, mode="r", *args, **kwargs):
            if os.fspath(path) == target and mode == "rb":
                reads.append(correct)
                return io.BytesIO(correct)
            return real_open(path, mode, *args, **kwargs)

        with _harness_path():
            rec = _make_recorder(helper, ["test_probe"],
                                 inputs=_r6_inputs(kind, entry))
            helper.set_active_recorder(rec)
            helper.read_consumed(target)
            rec.begin_case("test_probe")
            with monkeypatch.context() as patch:
                patch.setattr(builtins, "open", substitute)
                suite.test_fixture_bytes()
            rec.end_case_pass("test_probe")
            code, lines = _finish_lines(rec, stage_dir=stage)
        _plan, results, terminal = _parse_emitted(lines)
        assert reads == [correct]
        assert code == 1, (code, terminal.decision, results[0].to_dict())
        assert _r6_digest(results[0], identity) == helper.ZERO_SHA256
    finally:
        helper.clear_active_recorder()
        helper.discard_owned_stages()


@pytest.mark.parametrize("kind,identity,leaf", _R6_CLASSES)
@pytest.mark.parametrize("declaration", ("absolute", "staged"))
@pytest.mark.parametrize("active", (False, True))
def test_r6_preflight_does_not_prove_consumption(kind, identity, leaf, declaration, active):
    helper = _load_helper()
    stage = helper.owned_stage(prefix="r6-preflight-")
    target = os.path.join(stage, leaf)
    try:
        with open(target, "wb") as handle:
            handle.write(b"observed but never executed")
        entry = target if declaration == "absolute" else ("stage", leaf)
        with _harness_path():
            rec = _make_recorder(helper, ["test_probe"],
                                 inputs=_r6_inputs(kind, entry))
            if active:
                helper.set_active_recorder(rec)
            rec.consume_declared(stage)
            rec.begin_case("test_probe")
            rec.end_case_pass("test_probe")
            code, lines = _finish_lines(rec, stage_dir=stage)
        _plan, results, terminal = _parse_emitted(lines)
        assert code == 1, (code, terminal.decision, results[0].to_dict())
        assert _r6_digest(results[0], identity) == helper.ZERO_SHA256
    finally:
        helper.clear_active_recorder()
        helper.discard_owned_stages()


_R6_HOST_SUITES = [
    "tests/kernel/test_%s.py" % name for name in (
        "arch_portability", "array_maps", "cleanup", "core_layouts",
        "generalized_arrays", "hash_maps", "map_roundtrip", "mojo_percpu",
        "mojo_xdp", "packet_sdk", "parse_checksum_sdk", "percpu_maps",
        "ringbuf_reserve", "subprog_calls", "tracepoint_counter",
        "tracepoint_events", "tracing_lifecycle", "uprobe_register",
        "xdp_accounting",
    )
] + ["tests/verifier/test_helper_licenses.py",
     "tests/verifier/test_subset_kernel.py"] + [
    "tests/packaging/test_%s_consumer.py" % name
    for name in ("external", "hash", "reserve", "subprog", "uprobe")
]


@pytest.mark.parametrize("suite_path", _R6_HOST_SUITES)
def test_r6_host_hash_consumer_logs_its_actual_read(suite_path, monkeypatch):
    import builtins
    import hashlib

    suite = _load_suite(suite_path)
    helper = suite.guest_proc
    stage = helper.owned_stage(prefix="r6-host-hash-")
    target = os.path.join(stage, "input.bpf.o")
    try:
        with open(target, "wb") as handle:
            handle.write(b"A")
        with _harness_path():
            rec = _make_recorder(helper, ["test_probe"],
                                 inputs=_r6_inputs("objects", target))
            helper.set_active_recorder(rec)
            helper.read_consumed(target)
            rec.begin_case("test_probe")
            real_open = builtins.open

            def substitute(path, mode="r", *args, **kwargs):
                if os.fspath(path) == target and mode == "rb":
                    return io.BytesIO(b"B")
                return real_open(path, mode, *args, **kwargs)

            read_hash = getattr(suite, "sha256_file", None) or suite._sha256_file
            with monkeypatch.context() as patch:
                patch.setattr(builtins, "open", substitute)
                assert read_hash(target) == hashlib.sha256(b"B").hexdigest()
            rec.end_case_pass("test_probe")
            code, lines = _finish_lines(rec, stage_dir=stage)
        _plan, results, terminal = _parse_emitted(lines)
        assert code == 1, (suite_path, terminal.decision, results[0].to_dict())
        assert results[0].identities["object_sha256"] == helper.ZERO_SHA256
    finally:
        helper.clear_active_recorder()
        helper.discard_owned_stages()


@pytest.mark.parametrize("suite_path", [path for path in _R6_HOST_SUITES if
                         path.startswith("tests/kernel/") and
                         not path.endswith("test_percpu_maps.py")])
def test_r6_host_compiler_gets_logged_source(suite_path, monkeypatch):
    # Stop at the first frontend consumption. This invokes no compiler,
    # process, guest or network and uses only synthetic source bytes.
    import hashlib
    import inspect

    suite = _load_suite(suite_path)
    helper = suite.guest_proc
    stage = helper.owned_stage(prefix="r6-host-compiler-")
    target = os.path.join(stage, "input.mojo")
    used = []

    class Consumed(Exception):
        pass

    def frontend(argv, **kwargs):
        with open(target, "wb") as handle:
            handle.write(b"source-B")
        try:
            source = next(arg for arg in argv if arg.endswith(".mojo"))
            with open(source, "rb") as handle:
                used.append(handle.read())
        finally:
            with open(target, "wb") as handle:
                handle.write(b"source-A")
        raise Consumed()

    try:
        with open(target, "wb") as handle:
            handle.write(b"source-A")
        monkeypatch.setattr(suite, "run_step", frontend)
        compiler = getattr(suite, "build_object", None) or suite.build_mojo
        arguments = {"source": target, "workdir": stage, "name": "probe",
                     "tag": "probe", "want_hash": None,
                     "include_sdk": False, "use_sdk": False}
        kwargs = {name: arguments[name] for name in inspect.signature(compiler).parameters}
        with _harness_path():
            rec = _make_recorder(helper, ["test_probe"],
                                 inputs=_r6_inputs("sources", target))
            helper.set_active_recorder(rec)
            helper.read_consumed(target)
            rec.begin_case("test_probe")
            with pytest.raises(Consumed):
                compiler(**kwargs)
            rec.end_case_pass("test_probe")
            code, lines = _finish_lines(rec, stage_dir=stage)
        _plan, results, terminal = _parse_emitted(lines)
        assert code == 0, (terminal.decision, results[0].to_dict())
        assert results[0].identities["source_sha256"] == hashlib.sha256(
            used[0] + b"\x00"
        ).hexdigest(), (suite_path, used, terminal.decision)
        assert used == [b"source-A"]
    finally:
        helper.clear_active_recorder()
        helper.discard_owned_stages()


def test_r6_snapshot_is_single_read_sealed_and_scoped(monkeypatch):
    helper = _load_helper()
    with tempfile.TemporaryDirectory(prefix="r6-snapshot-") as root:
        target = os.path.join(root, "input.mojo")
        with open(target, "wb") as handle:
            handle.write(b"logged bytes")
        with _harness_path():
            rec = _make_recorder(helper, ["test_probe"],
                                 inputs=_r6_inputs("sources", target))
        helper.set_active_recorder(rec)
        read = helper._read_file_bytes
        calls = []

        def counted(path):
            calls.append(path)
            return read(path)

        monkeypatch.setattr(helper, "_read_file_bytes", counted)
        descriptors = set(os.listdir("/proc/self/fd"))
        try:
            with pytest.raises(RuntimeError, match="consumer error"):
                with _r6_path(helper, target) as snapshot:
                    assert calls == [target]
                    for _ in range(3):
                        with open(snapshot, "rb") as handle:
                            assert handle.read() == b"logged bytes"
                    fd = os.open(snapshot, os.O_WRONLY)
                    try:
                        with pytest.raises(PermissionError):
                            os.write(fd, b"different bytes")
                        with pytest.raises(PermissionError):
                            os.ftruncate(fd, 0)
                    finally:
                        os.close(fd)
                    raise RuntimeError("consumer error")
            assert not os.path.lexists(snapshot)
            if not snapshot.startswith("/proc/%d/fd/" % os.getpid()):
                assert not os.path.exists(os.path.dirname(snapshot))
            assert set(os.listdir("/proc/self/fd")) == descriptors
            assert calls == [target]
        finally:
            helper.clear_active_recorder()


@pytest.mark.parametrize("kind,identity,leaf", _R6_CLASSES)
@pytest.mark.parametrize("declaration", ("absolute", "staged"))
def test_snapshot_entry_replacement_cannot_change_consumption(
        kind, identity, leaf, declaration):
    # A sealed backing inode does not protect a replaceable directory
    # entry. Try the actual same-UID unlink/relink between log and use.
    import hashlib

    helper = _load_helper()
    stage = helper.owned_stage(prefix="snapshot-entry-")
    target, other = (os.path.join(stage, name) for name in (leaf, "other"))
    original, replacement = b"reject original", b"accept replacement"
    try:
        with open(target, "wb") as handle:
            handle.write(original)
        with open(other, "wb") as handle:
            handle.write(replacement)
        entry = target if declaration == "absolute" else ("stage", leaf)
        with _harness_path():
            rec = _make_recorder(helper, ["test_probe"],
                                 inputs=_r6_inputs(kind, entry))
            helper.set_active_recorder(rec)
            rec.begin_case("test_probe")
            with helper.consumed_path(target) as snapshot:
                try:
                    os.unlink(snapshot)
                    os.symlink(other, snapshot)
                except OSError:
                    pass
                with open(snapshot, "rb") as handle:
                    used = handle.read()
            rec.end_case_pass("test_probe")
            code, lines = _finish_lines(rec, stage_dir=stage)
        _plan, results, terminal = _parse_emitted(lines)
        assert used == original, (used, terminal.decision)
        assert _r6_digest(results[0], identity) == hashlib.sha256(
            used + b"\x00"
        ).hexdigest()
        assert code == 0 and terminal.decision["verdict"] == "PASS"
    finally:
        helper.clear_active_recorder()
        helper.discard_owned_stages()


@pytest.mark.parametrize("declaration", ("absolute", "staged"))
def test_inspector_cannot_accept_replacement_for_malformed_snapshot(
        declaration, monkeypatch):
    from mojobpf import inspect as inspector

    suite = _load_suite("tests/kernel/test_hash_maps.py")
    helper = suite.guest_proc
    elf = _load_suite("tests/elf/test_artifact_contract.py")
    valid = elf._clean_builder().build()
    invalid = b"malformed original ELF"
    stage = helper.owned_stage(prefix="snapshot-inspector-")
    targets = [os.path.join(stage, name) for name in
               ("hash_rmw.bpf.o", "hash_del.bpf.o")]
    other = os.path.join(stage, "valid.bpf.o")
    try:
        for target, data in [(other, valid)] + [(p, invalid) for p in targets]:
            with open(target, "wb") as handle:
                handle.write(data)
        monkeypatch.setattr(suite, "executed", lambda: {"stage": stage})
        real_read = inspector._read_object_bytes
        used = []

        def substitute(path):
            try:
                os.unlink(path)
                os.symlink(other, path)
            except OSError:
                pass
            data = real_read(path)
            used.append(data)
            return data

        entries = targets if declaration == "absolute" else [
            ("stage", os.path.basename(path)) for path in targets
        ]
        with _harness_path():
            rec = _make_recorder(helper, ["test_probe"], inputs={
                "test_probe": {"sources": [], "objects": entries, "corpus": []}
            })
            helper.set_active_recorder(rec)
            for target in targets:
                helper.read_consumed(target)
            rec.begin_case("test_probe")
            with monkeypatch.context() as patch:
                patch.setattr(inspector, "_read_object_bytes", substitute)
                try:
                    suite.test_license_gate_agrees()
                except AssertionError:
                    rec.end_case_fail("test_probe", "TEST_RUN")
                else:
                    rec.end_case_pass("test_probe")
            code, lines = _finish_lines(rec, stage_dir=stage)
        _plan, results, terminal = _parse_emitted(lines)
        assert used == [invalid], (used, code, terminal.decision)
        assert code == 1 and results[0].outcome == "FAIL"
    finally:
        helper.clear_active_recorder()
        helper.discard_owned_stages()


@pytest.mark.parametrize("failure", ("create", "write", "fdopen", "seal", "alias"))
def test_snapshot_setup_failure_emits_infra_and_cleans_immediately(
        failure, monkeypatch):
    import ctypes
    import errno

    suite = _load_suite("tests/kernel/test_mojo_xdp.py")
    helper = suite.guest_proc
    stages = []

    def host_warmup():
        stage = helper.owned_stage(prefix="snapshot-setup-")
        stages.append(stage)
        suite.build_object(suite.BASE_SOURCE, stage, "base")
        raise AssertionError("the injected snapshot failure was bypassed")

    for name in list(vars(suite)):
        if name.startswith("test_"):
            monkeypatch.delattr(suite, name)
    monkeypatch.setattr(suite, "test_snapshot_setup", host_warmup, raising=False)
    monkeypatch.setattr(suite, "executed", host_warmup)
    monkeypatch.setattr(suite, "CASE_DENIALS", {})
    monkeypatch.setattr(suite, "CASE_INPUTS", {
        "test_snapshot_setup": {"sources": [suite.BASE_SOURCE],
                                "objects": [], "corpus": []}
    })
    real_create = helper.os.memfd_create
    real_dup = helper.os.dup
    real_fdopen = helper.os.fdopen
    real_fcntl = helper.fcntl.fcntl
    real_temp = helper.tempfile.mkdtemp

    def refuse(*args, **kwargs):
        raise OSError(errno.EMFILE, "snapshot setup exhausted descriptors")

    def seal(fd, command, *args):
        if command == helper.fcntl.F_ADD_SEALS:
            return refuse()
        return real_fcntl(fd, command, *args)

    def stream(fd, *args, **kwargs):
        if "mojobpf-consumed" in os.readlink("/proc/self/fd/%d" % fd):
            return refuse()
        return real_fdopen(fd, *args, **kwargs)

    if failure == "create":
        monkeypatch.setattr(helper.os, "memfd_create", refuse)
    elif failure == "write":
        monkeypatch.setattr(helper.os, "dup", refuse)
    elif failure == "fdopen":
        monkeypatch.setattr(helper.os, "fdopen", stream)
    elif failure == "seal":
        monkeypatch.setattr(helper.fcntl, "fcntl", seal)
    else:
        def directory(*args, **kwargs):
            if kwargs.get("prefix") == "mojobpf-consumed-":
                return refuse()
            return real_temp(*args, **kwargs)

        monkeypatch.setattr(helper.tempfile, "mkdtemp", directory)
    def descriptors():
        result = {}
        for fd in os.listdir("/proc/self/fd"):
            try:
                result[fd] = os.readlink("/proc/self/fd/" + fd)
            except FileNotFoundError:
                pass
        return result

    before = descriptors()
    output = io.StringIO()
    escaped = None
    try:
        with _harness_path(), contextlib.redirect_stdout(output):
            try:
                code = suite.main()
            except OSError as exc:
                escaped = exc
                code = None
        active_after = helper.active_recorder()
        owned_after = set(helper._OWNED_STAGES)
    finally:
        monkeypatch.setattr(helper.os, "memfd_create", real_create)
        monkeypatch.setattr(helper.os, "dup", real_dup)
        monkeypatch.setattr(helper.os, "fdopen", real_fdopen)
        monkeypatch.setattr(helper.fcntl, "fcntl", real_fcntl)
        monkeypatch.setattr(helper.tempfile, "mkdtemp", real_temp)
        helper.clear_active_recorder()
        helper.discard_owned_stages()
    assert escaped is None, (failure, repr(escaped), output.getvalue())
    _plan, results, terminal = _parse_emitted(output.getvalue().splitlines())
    assert code == 2 and terminal.decision["verdict"] == "INCOMPLETE"
    assert results[0].outcome == "INFRA_ERROR"
    assert results[0].failure_stage == "INFRA"
    assert stages and not any(os.path.exists(path) for path in stages)
    assert not owned_after and active_after is None
    assert descriptors() == before


def test_finish_resolution_failure_cleans_owned_state(monkeypatch):
    helper = _load_helper()
    stage = helper.owned_stage(prefix="finish-resolution-")
    with _harness_path():
        rec = _make_recorder(helper, ["test_probe"])
    helper.set_active_recorder(rec)

    def refuse():
        raise ValueError("invalid terminal identity")

    monkeypatch.setattr(rec, "_resolve_revisions", refuse)
    try:
        with pytest.raises(ValueError, match="invalid terminal identity"):
            rec.finish()
        assert helper.active_recorder() is None
        assert stage not in helper._OWNED_STAGES and not os.path.exists(stage)
    finally:
        helper.clear_active_recorder()
        helper.discard_owned_stages()


def test_snapshot_descriptor_teardown_error_is_typed(monkeypatch):
    import errno

    helper = _load_helper()
    with tempfile.TemporaryDirectory(prefix="snapshot-close-") as root:
        target = os.path.join(root, "input.bin")
        with open(target, "wb") as handle:
            handle.write(b"immutable input")
        with _harness_path():
            rec = _make_recorder(helper, ["test_probe"],
                                 inputs=_r6_inputs("sources", target))
        helper.set_active_recorder(rec)
        before = set(os.listdir("/proc/self/fd"))
        real_close = helper.os.close

        def failed_close(fd):
            owned = "mojobpf-consumed" in os.readlink("/proc/self/fd/%d" % fd)
            real_close(fd)
            if owned:
                raise OSError(errno.EIO, "snapshot descriptor teardown failed")

        try:
            with pytest.raises(helper.HarnessEnvironment) as caught:
                with helper.consumed_path(target) as snapshot:
                    with open(snapshot, "rb") as handle:
                        assert handle.read() == b"immutable input"
                    monkeypatch.setattr(helper.os, "close", failed_close)
            assert caught.value.stage == "CLEANUP"
        finally:
            monkeypatch.setattr(helper.os, "close", real_close)
            helper.clear_active_recorder()
        assert set(os.listdir("/proc/self/fd")) == before


@pytest.mark.parametrize("handoff", ("wrapper", "argv"))
@pytest.mark.parametrize("attack", ("replace_restore", "atomic_replace_restore",
                                    "unlink_only", "rename_directory",
                                    "replace_directory"))
def test_compiler_alias_mutation_cannot_back_pass(handoff, attack):
    helper = _load_helper()
    stage = helper.owned_stage(prefix="compiler-alias-")
    target, other = (os.path.join(stage, name) for name in
                     ("input.mojo", "other.mojo"))
    used = []
    try:
        for path, data in ((target, b"original source"),
                           (other, b"replacement source")):
            with open(path, "wb") as handle:
                handle.write(data)
        with _harness_path():
            rec = _make_recorder(helper, ["test_probe"],
                                 inputs=_r6_inputs("sources", target))
            helper.set_active_recorder(rec)
            rec.begin_case("test_probe")

            def compiler(path):
                if attack == "replace_restore":
                    saved = os.readlink(path)
                    os.unlink(path)
                    os.symlink(other, path)
                    try:
                        with open(path, "rb") as handle:
                            used.append(handle.read())
                    finally:
                        os.unlink(path)
                        os.symlink(saved, path)
                elif attack == "atomic_replace_restore":
                    saved = os.readlink(path)
                    offered = path + ".offered"
                    os.symlink(other, offered)
                    os.replace(offered, path)
                    try:
                        with open(path, "rb") as handle:
                            used.append(handle.read())
                    finally:
                        os.symlink(saved, offered)
                        os.replace(offered, path)
                elif attack == "unlink_only":
                    saved = os.readlink(path)
                    os.unlink(path)
                    with open(saved, "rb") as handle:
                        used.append(handle.read())
                else:
                    parent = os.path.dirname(path)
                    directory = (os.readlink(parent) if parent.startswith("/proc/")
                                 else parent)
                    moved = directory + ".moved"
                    os.rename(directory, moved)
                    try:
                        if attack == "replace_directory":
                            os.mkdir(directory)
                            os.symlink(other, os.path.join(directory,
                                                          os.path.basename(path)))
                        # The pinned directory remains readable; its move
                        # must still invalidate the pathname boundary.
                        if parent.startswith("/proc/"):
                            with open(path, "rb") as handle:
                                used.append(handle.read())
                    finally:
                        if attack == "replace_directory":
                            os.unlink(os.path.join(directory, os.path.basename(path)))
                            os.rmdir(directory)
                        os.rename(moved, directory)
                return 0

            try:
                if handoff == "wrapper":
                    helper.consumes_source(compiler)(target)
                else:
                    helper.compile_consumed(lambda argv: compiler(argv[-1]),
                                            ["compiler", target], target)
            except helper.HarnessEnvironment as exc:
                rec.end_case_infra("test_probe", exc.stage, exc.availability)
            else:
                rec.end_case_pass("test_probe")
            code, lines = _finish_lines(rec, stage_dir=stage)
        _plan, results, terminal = _parse_emitted(lines)
        assert code != 0, (used, terminal.decision)
        assert terminal.decision["verdict"] != "PASS"
        assert results[0].outcome == "INFRA_ERROR"
    finally:
        helper.clear_active_recorder()
        helper.discard_owned_stages()


@pytest.mark.parametrize("attack", ("permanent_move", "replacement_directory"))
def test_compiler_alias_unresolved_cleanup_preserves_replacement(attack):
    import shutil

    helper = _load_helper()
    stage = helper.owned_stage(prefix="alias-cleanup-")
    target = os.path.join(stage, "input.mojo")
    with open(target, "wb") as handle:
        handle.write(b"original source")
    with _harness_path():
        rec = _make_recorder(helper, ["test_probe"],
                             inputs=_r6_inputs("sources", target))
    paths = {}

    def compiler(path):
        directory = os.readlink(os.path.dirname(path))
        moved = directory + ".moved"
        paths.update(root=directory, moved=moved)
        os.rename(directory, moved)
        if attack == "replacement_directory":
            os.mkdir(directory)
            sentinel = os.path.join(directory, "preserve-me")
            with open(sentinel, "wb") as handle:
                handle.write(b"replacement belongs to its creator")
            paths["sentinel"] = sentinel
        with open(path, "rb") as handle:
            assert handle.read() == b"original source"
        return 0

    helper.set_active_recorder(rec)
    rec.begin_case("test_probe")
    rejected = None
    try:
        try:
            helper.consumes_source(compiler)(target)
        except helper.HarnessEnvironment as exc:
            rejected = exc
            rec.end_case_infra("test_probe", exc.stage, exc.availability)
        else:
            rec.end_case_pass("test_probe")
        with _harness_path():
            code, lines = _finish_lines(rec, stage_dir=stage)
        _plan, results, terminal = _parse_emitted(lines)
        if attack == "replacement_directory":
            with open(paths["sentinel"], "rb") as handle:
                assert handle.read() == b"replacement belongs to its creator"
        assert results[0].cleanup["status"] == "RESIDUE", results[0].to_dict()
        assert rejected is not None and rejected.stage == "CLEANUP"
        assert rejected.availability == "UNKNOWN"
        assert results[0].outcome == "INFRA_ERROR"
        assert code == 1 and terminal.decision["verdict"] == "FAIL"
        assert not os.path.lexists(os.path.join(paths["moved"], "input.mojo"))
        assert not os.path.exists(stage) and helper.active_recorder() is None
    finally:
        helper.clear_active_recorder()
        helper.discard_owned_stages()
        for path in (paths.get("root"), paths.get("moved")):
            if path and os.path.exists(path):
                shutil.rmtree(path)


@pytest.mark.parametrize("mode", ("honest", "move_after_stat",
                                  "replacement_contents", "postcondition_unreadable"))
def test_compiler_alias_cleanup_proves_owned_inode_removal(mode, monkeypatch):
    # Successful rmdir of the last observed pathname must not qualify a
    # different, still-linked inode held by our directory descriptor.
    import ctypes
    import errno
    import shutil

    helper = _load_helper()
    stage = helper.owned_stage(prefix="alias-postcondition-")
    target = os.path.join(stage, "input.mojo")
    with open(target, "wb") as handle:
        handle.write(b"original source")
    with _harness_path():
        rec = _make_recorder(helper, ["test_probe"],
                             inputs=_r6_inputs("sources", target))
    paths = {}
    real_rmdir, real_fstat = helper.os.rmdir, helper.os.fstat
    before = set(os.listdir("/proc/self/fd"))

    def consumer(path):
        directory = os.path.dirname(path)
        paths.update(root=os.readlink(directory), fd=int(os.path.basename(directory)))
        with open(path, "rb") as handle:
            assert handle.read() == b"original source"
        return 0

    def remove(path, *args, **kwargs):
        if os.fspath(path) == paths.get("root"):
            if mode in ("move_after_stat", "replacement_contents"):
                moved = paths["root"] + ".moved"
                os.rename(path, moved)
                paths["moved"] = moved
                os.mkdir(path)
                if mode == "replacement_contents":
                    sentinel = os.path.join(path, "preserve-me")
                    with open(sentinel, "wb") as handle:
                        handle.write(b"replacement contents")
                    paths["sentinel"] = sentinel
            result = real_rmdir(path, *args, **kwargs)
            paths["removed"] = True
            return result
        return real_rmdir(path, *args, **kwargs)

    def stat(fd):
        if (mode == "postcondition_unreadable" and paths.get("removed") and
                fd == paths.get("fd")):
            raise OSError(errno.EIO, "owned directory postcondition unreadable")
        return real_fstat(fd)

    helper.set_active_recorder(rec)
    rec.begin_case("test_probe")
    rejected = None
    try:
        with monkeypatch.context() as patch:
            patch.setattr(helper.os, "rmdir", remove)
            patch.setattr(helper.os, "fstat", stat)
            try:
                helper.consumes_source(consumer)(target)
            except helper.HarnessEnvironment as exc:
                rejected = exc
                rec.end_case_infra("test_probe", exc.stage, exc.availability)
            else:
                rec.end_case_pass("test_probe")
        with _harness_path():
            code, lines = _finish_lines(rec, stage_dir=stage)
        _plan, results, terminal = _parse_emitted(lines)
        if mode == "honest":
            assert rejected is None and code == 0
            assert terminal.decision["verdict"] == "PASS"
            assert results[0].cleanup["status"] == "CLEAN"
            assert not os.path.exists(paths["root"])
        else:
            assert rejected is not None and rejected.stage == "CLEANUP", (
                mode, results[0].to_dict())
            assert rejected.availability == "UNKNOWN"
            assert results[0].outcome == "INFRA_ERROR"
            assert results[0].cleanup["status"] == "RESIDUE"
            assert code == 1 and terminal.decision["verdict"] == "FAIL"
            if mode == "postcondition_unreadable":
                assert not os.path.exists(paths["root"])
            else:
                assert os.path.isdir(paths["moved"])
                assert not os.path.lexists(os.path.join(paths["moved"], "input.mojo"))
                if mode == "replacement_contents":
                    with open(paths["sentinel"], "rb") as handle:
                        assert handle.read() == b"replacement contents"
        assert not os.path.exists(stage) and helper.active_recorder() is None
        assert not helper._OWNED_STAGES
        assert set(os.listdir("/proc/self/fd")) == before
    finally:
        helper.clear_active_recorder()
        helper.discard_owned_stages()
        for path in (paths.get("root"), paths.get("moved")):
            if path and os.path.exists(path):
                shutil.rmtree(path)


@pytest.mark.parametrize("fault", ("overflow", "watch_lost", "truncated",
                                   "read_error", "teardown_error"))
def test_compiler_alias_monitor_uncertainty_fails_closed(fault, monkeypatch):
    import errno
    import struct

    helper = _load_helper()
    with tempfile.TemporaryDirectory(prefix="compiler-monitor-") as root:
        target = os.path.join(root, "input.mojo")
        with open(target, "wb") as handle:
            handle.write(b"original source")
        with _harness_path():
            rec = _make_recorder(helper, ["test_probe"],
                                 inputs=_r6_inputs("sources", target))
        helper.set_active_recorder(rec)
        before = set(os.listdir("/proc/self/fd"))
        real_read, real_close = helper.os.read, helper.os.close
        injected = []

        def compiler(path):
            with open(path, "rb") as handle:
                assert handle.read() == b"original source"
            watched = set()
            for entry in os.listdir("/proc/self/fd"):
                try:
                    if os.readlink("/proc/self/fd/" + entry) == "anon_inode:inotify":
                        watched.add(int(entry))
                except FileNotFoundError:
                    continue

            def unreadable(fd, size):
                if fd in watched:
                    injected.append(fd)
                    if fault == "read_error":
                        raise OSError(errno.EIO, "input monitor read failed")
                    if fault == "truncated":
                        return b"short event"
                    mask = 0x4000 if fault == "overflow" else 0x8000
                    return struct.pack("=iIII", -1, mask, 0, 0)
                return real_read(fd, size)

            def close(fd):
                real_close(fd)
                if fd in watched:
                    injected.append(fd)
                    raise OSError(errno.EIO, "input monitor teardown failed")

            if fault == "teardown_error":
                monkeypatch.setattr(helper.os, "close", close)
            else:
                monkeypatch.setattr(helper.os, "read", unreadable)
            return 0

        try:
            with pytest.raises(helper.HarnessEnvironment):
                helper.consumes_source(compiler)(target)
            assert injected, "no monitored pathname boundary was exercised"
        finally:
            monkeypatch.setattr(helper.os, "read", real_read)
            monkeypatch.setattr(helper.os, "close", real_close)
            helper.clear_active_recorder()
        assert set(os.listdir("/proc/self/fd")) == before


@pytest.mark.parametrize("record", ("honest", "mutated_source", "second_mutated_source",
                                    "mutated_manifest", "malformed_json", "deep_json",
                                    "missing", "duplicate_source", "duplicate_key",
                                    "bad_size", "wrong_path", "wrong_schema"))
def test_manifest_build_reconciles_each_captured_input(record, monkeypatch):
    import hashlib
    from types import SimpleNamespace
    from mojobpf.evidence import EVIDENCE_SCHEMA_VERSION

    suite = _load_suite("tests/kernel/test_cleanup.py")
    helper = suite.guest_proc
    case = "test_reproducible_manifest_build"
    used = []
    originals = {}
    for name in ("mojobpf.toml", "canary.mojo"):
        with open(os.path.join(suite.CONSUMER_DIR, name), "rb") as handle:
            originals[name] = handle.read()
    suffix = b"\n# changed only during compiler capture\n"

    def build(argv, **kwargs):
        manifest = argv[argv.index("--manifest") + 1]
        project = os.path.dirname(manifest)
        changed_source = (record == "mutated_source" or
                          record == "second_mutated_source" and len(used) >= 2)
        modified = ("canary.mojo" if changed_source else
                    "mojobpf.toml" if record == "mutated_manifest" else None)
        if modified:
            with open(os.path.join(project, modified), "wb") as handle:
                handle.write(originals[modified] + suffix)
        try:
            captured = {}
            for name in originals:
                with open(os.path.join(project, name), "rb") as handle:
                    data = handle.read()
                used.append((name, data))
                captured[name] = {"path": name,
                                  "sha256": hashlib.sha256(data).hexdigest(),
                                  "size": len(data)}
        finally:
            if modified:
                with open(os.path.join(project, modified), "wb") as handle:
                    handle.write(originals[modified])
        doc = {"schema_version": EVIDENCE_SCHEMA_VERSION, "success": True,
               "inputs": {"manifest": captured["mojobpf.toml"],
                          "source": [captured["canary.mojo"]]}}
        if record == "missing":
            del doc["inputs"]["source"]
        elif record == "duplicate_source":
            doc["inputs"]["source"].append(captured["canary.mojo"])
        elif record == "bad_size":
            doc["inputs"]["manifest"]["size"] = True
        elif record == "wrong_path":
            doc["inputs"]["source"][0]["path"] = "unrelated.mojo"
        elif record == "wrong_schema":
            doc["schema_version"] = EVIDENCE_SCHEMA_VERSION + 1
        raw = json.dumps(doc).encode()
        if record == "duplicate_key":
            raw = raw.replace(b'"success": true', b'"success": false, "success": true')
        elif record == "malformed_json":
            raw = b'{"inputs":'
        elif record == "deep_json":
            raw = b"[" * 2000 + b"0" + b"]" * 2000
        out = argv[argv.index("--out-dir") + 1]
        os.makedirs(out)
        with open(os.path.join(out, "canary.bpf.o"), "wb") as handle:
            handle.write(b"stand-in reproducible object")
        with open(os.path.join(out, "canary.evidence.json"), "wb") as handle:
            handle.write(raw)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(suite, "check_tools", lambda: None)
    monkeypatch.setattr(suite, "cli_env", lambda: {})
    monkeypatch.setattr(suite, "run_step", build)
    with _harness_path():
        rec = _make_recorder(helper, [case], inputs={case: suite.CASE_INPUTS[case]})
        helper.set_active_recorder(rec)
        rec.begin_case(case)
        try:
            try:
                suite.test_reproducible_manifest_build()
            except helper.HarnessEnvironment as exc:
                rec.end_case_infra(case, exc.stage, exc.availability)
            else:
                rec.end_case_pass(case)
            code, lines = _finish_lines(rec)
        finally:
            helper.clear_active_recorder()
    _plan, results, terminal = _parse_emitted(lines)
    if record == "honest":
        assert code == 0 and terminal.decision["verdict"] == "PASS"
        assert len(used) == 4
    else:
        assert code != 0 and terminal.decision["verdict"] != "PASS", (
            record, used, results[0].to_dict())
        assert results[0].outcome == "INFRA_ERROR"
    if record in ("mutated_source", "second_mutated_source", "mutated_manifest"):
        assert any(data == originals[name] + suffix for name, data in used)


@pytest.mark.parametrize('handoff', ('descriptor', 'compiler'))
@pytest.mark.parametrize('fault', ('write_before_seal', 'append_before_seal',
                                  'truncate_before_seal', 'writable_mmap',
                                  'old_writer_after_seal'))
def test_sealed_buffer_agrees_with_logged_bytes(handoff, fault, monkeypatch):
    import errno
    import mmap

    helper = _load_helper()
    stage = helper.owned_stage(prefix='sealed-buffer-')
    target = os.path.join(stage, 'input.mojo')
    original = b'original input bytes'
    with open(target, 'wb') as handle:
        handle.write(original)
    with _harness_path():
        rec = _make_recorder(helper, ['test_probe'],
                             inputs=_r6_inputs('sources', target))
    writer, mapping = [], []
    real_fcntl = helper.fcntl.fcntl

    def seal(fd, command, *args):
        if command == helper.fcntl.F_ADD_SEALS:
            writer.append(os.open('/proc/self/fd/%d' % fd, os.O_RDWR))
            if fault == 'write_before_seal':
                os.pwrite(writer[0], b'changed', 0)
            elif fault == 'append_before_seal':
                os.pwrite(writer[0], b'appended', len(original))
            elif fault == 'truncate_before_seal':
                os.ftruncate(writer[0], 1)
            elif fault == 'writable_mmap':
                mapping.append(mmap.mmap(writer[0], 0, access=mmap.ACCESS_WRITE))
        return real_fcntl(fd, command, *args)

    def consume(path):
        if fault == 'old_writer_after_seal':
            with pytest.raises(OSError) as denied:
                os.pwrite(writer[0], b'changed', 0)
            assert denied.value.errno == errno.EPERM
        with open(path, 'rb') as handle:
            return handle.read()

    helper.set_active_recorder(rec)
    rec.begin_case('test_probe')
    used, rejected = None, None
    try:
        with monkeypatch.context() as patch:
            patch.setattr(helper.fcntl, 'fcntl', seal)
            try:
                if handoff == 'compiler':
                    used = helper.consumes_source(consume)(target)
                else:
                    with helper.consumed_path(target) as snapshot:
                        used = consume(snapshot)
            except helper.HarnessEnvironment as exc:
                rejected = exc
                rec.end_case_infra('test_probe', exc.stage, exc.availability)
            else:
                rec.end_case_pass('test_probe')
        for view in mapping:
            view.close()
        for fd in writer:
            os.close(fd)
        mapping.clear()
        writer.clear()
        with _harness_path():
            code, lines = _finish_lines(rec, stage_dir=stage)
        _plan, results, terminal = _parse_emitted(lines)
        if fault == 'old_writer_after_seal':
            assert used == original and code == 0
            assert terminal.decision['verdict'] == 'PASS'
        else:
            assert rejected is not None, (fault, used, terminal.decision)
            assert code == 2 and results[0].outcome == 'INFRA_ERROR'
            assert terminal.decision['verdict'] == 'INCOMPLETE'
        assert not os.path.exists(stage) and stage not in helper._OWNED_STAGES
        assert helper.active_recorder() is None
    finally:
        for view in mapping:
            view.close()
        for fd in writer:
            os.close(fd)
        helper.clear_active_recorder()
        helper.discard_owned_stages()


def test_manifest_capture_parser_exhaustion_is_typed(monkeypatch):
    from types import SimpleNamespace

    helper = _load_helper()

    def refuse(*args, **kwargs):
        raise RecursionError("nested build capture exceeded parser depth")

    monkeypatch.setattr(helper, "json", SimpleNamespace(loads=refuse))
    with pytest.raises(helper.HarnessEnvironment) as caught:
        helper.verify_captured_project_inputs(
            b"[]", manifest=("mojobpf.toml", b"manifest"),
            sources=[("canary.mojo", b"source")],
        )
    assert caught.value.stage == "TEST_RUN"


def test_stage_consumed_returns_attestable_digests():
    # A1: consuming staged bytes through the guest handoff must
    # establish attestable digests, so guest-reported hashes have
    # a consumed identity to compare against (the F4 gap was
    # observation-only reads + a digest comparison that could
    # never succeed).
    helper = _load_helper()
    stage = helper.owned_stage(prefix="a1-handoff-")
    try:
        payloads = {
            "probe.bpf.o": b"a1-probe-bytes",
            "guest_probe.sh": b"#!/bin/sh\necho ok\n",
        }
        for name, data in payloads.items():
            with open(os.path.join(stage, name), "wb") as handle:
                handle.write(data)
        with _harness_path():
            rec = _make_recorder(
                helper,
                ["test_probe"],
                inputs={
                    "test_probe": {
                        "sources": [],
                        "objects": [("stage", "probe.bpf.o")],
                        "corpus": [("stage", "guest_probe.sh")],
                    }
                },
            )
            helper.set_active_recorder(rec)
            try:
                digests = helper.stage_consumed_for_guest(
                    rec, stage, ("probe.bpf.o", "guest_probe.sh")
                )
            finally:
                helper.clear_active_recorder(rec)
            import hashlib
            for name, data in payloads.items():
                assert digests[name] == hashlib.sha256(data).hexdigest()
                assert rec.consumed_staged_digest(name, stage) == (
                    digests[name]
                )
    finally:
        helper.discard_owned_stages()


def test_stage_consumed_without_recorder_reads_nothing():
    # Like consume_declared_inputs: without an attestation context
    # the handoff is a no-op returning no digests (standalone/pytest
    # runs never crash on it).
    helper = _load_helper()
    assert helper.stage_consumed_for_guest(None, "/tmp", ("a",)) == {}


def test_staged_digest_binds_consumed_bytes_not_current_file():
    # A1 negative anchor: after the handoff, the attested identity
    # stays the consumed buffer even if the staged file is swapped;
    # a guest reporting the swapped bytes mismatches and fails
    # closed (this is the tripwire the suite comparisons rely on).
    # The swap itself requires re-opening write permission on the
    # sealed file, which the handoff monitor observes and voids.
    helper = _load_helper()
    stage = helper.owned_stage(prefix="a1-bind-")
    try:
        path = os.path.join(stage, "bound.bpf.o")
        with open(path, "wb") as handle:
            handle.write(b"a1-bound-bytes")
        with _harness_path():
            rec = _make_recorder(
                helper,
                ["test_probe"],
                inputs={
                    "test_probe": {
                        "sources": [],
                        "objects": [("stage", "bound.bpf.o")],
                        "corpus": [],
                    }
                },
            )
            helper.set_active_recorder(rec)
            try:
                first = helper.stage_consumed_for_guest(
                    rec, stage, ("bound.bpf.o",)
                )
            finally:
                helper.clear_active_recorder(rec)
            os.chmod(path, 0o644)
            with open(path, "wb") as handle:
                handle.write(b"a1-swapped-bytes")
            import hashlib
            assert first["bound.bpf.o"] == hashlib.sha256(
                b"a1-bound-bytes"
            ).hexdigest()
            assert rec.consumed_staged_digest(
                "bound.bpf.o", stage
            ) == first["bound.bpf.o"]
            mismatches = helper.verify_staged_handoffs_now()
            assert any(
                "bound.bpf.o" in item for item in mismatches
            ), mismatches
    finally:
        helper.discard_owned_stages()


def test_stage_consumed_rewrites_from_buffer():
    # A1: the staged file must hold the consumed buffer afterwards
    # (hashed bytes == staged bytes); a later swap voids the
    # handoff at the next extension or case close, never
    # silently adopted.
    helper = _load_helper()
    stage = helper.owned_stage(prefix="a1-rewrite-")
    try:
        path = os.path.join(stage, "swap.bpf.o")
        with open(path, "wb") as handle:
            handle.write(b"a1-original-bytes")
        with _harness_path():
            rec = _make_recorder(
                helper,
                ["test_probe"],
                inputs={
                    "test_probe": {
                        "sources": [],
                        "objects": [("stage", "swap.bpf.o")],
                        "corpus": [],
                    }
                },
            )
            helper.set_active_recorder(rec)
            try:
                first = helper.stage_consumed_for_guest(
                    rec, stage, ("swap.bpf.o",)
                )
                # The sealed file must be re-opened for writing
                # before it can be swapped; the monitor observes
                # that permission change.
                os.chmod(path, 0o644)
                with open(path, "wb") as handle:
                    handle.write(b"a1-swapped-bytes")
                # Re-handing off after the swap refuses at once:
                # the first handoff already spans this window,
                # so its pending events void the extension
                # instead of adopting the new bytes.
                with pytest.raises(
                    AssertionError, match="voided before extension"
                ):
                    helper.stage_consumed_for_guest(
                        rec, stage, ("swap.bpf.o",)
                    )
            finally:
                helper.clear_active_recorder(rec)
            import hashlib
            assert first["swap.bpf.o"] == hashlib.sha256(
                b"a1-original-bytes"
            ).hexdigest()
            rec.begin_case("test_probe")
            rec.end_case_pass("test_probe")
            record = rec._cases.get("test_probe", {})
            assert record.get("outcome") != "PASS", record
    finally:
        helper.discard_owned_stages()


def test_impl_entry_needs_no_explicit_consumption():
    # A1: Python implementation code (executed before any recorder
    # exists) takes the ("impl", path) role: sealed as evidence,
    # never demandable as executed bytes.
    helper = _load_helper()
    with _harness_path():
        rec = _make_recorder(
            helper,
            ["test_probe"],
            inputs={
                "test_probe": {
                    "sources": [("impl", os.path.abspath(__file__))],
                    "objects": [],
                    "corpus": [],
                }
            },
        )
        rec.begin_case("test_probe")
        rec.end_case_pass("test_probe")
        record = rec._cases["test_probe"]
        assert record["outcome"] == "PASS", record
        assert record["cleanup"]["status"] == "CLEAN", record


def test_impl_entry_hashes_from_seal():
    # A1: impl-only classes bind the sealed evidence digest into
    # the class hash (deterministic, no fresh reads), never zeros
    # (missing) and never an execution attestation.
    helper = _load_helper()
    import hashlib
    path = os.path.abspath(__file__)
    with open(path, "rb") as handle:
        sealed = hashlib.sha256(handle.read()).hexdigest()
    with _harness_path():
        rec = _make_recorder(
            helper,
            ["test_probe"],
            inputs={
                "test_probe": {
                    "sources": [("impl", path)],
                    "objects": [],
                    "corpus": [],
                }
            },
        )
        got = rec._hash_inputs(None)
        want = hashlib.sha256(
            bytes.fromhex(sealed) + b"\x00"
        ).hexdigest()
        assert got["test_probe"]["sources"] == want, got
        assert got["test_probe"]["objects"] != (
            "0" * 64
        ), got


def test_impl_entry_rejects_bad_spelling():
    # A1: malformed impl entries fail at construction, like every
    # other input kind.
    helper = _load_helper()
    with _harness_path():
        for bad in (
            ("impl", "relative/path.py"),
            ("impl", ""),
            ("impl",),
            ("impl", "/abs.py", "extra"),
        ):
            try:
                _make_recorder(
                    helper,
                    ["test_probe"],
                    inputs={
                        "test_probe": {
                            "sources": [bad],
                            "objects": [],
                            "corpus": [],
                        }
                    },
                )
            except ValueError:
                continue
            raise AssertionError(
                "impl entry %r must be rejected" % (bad,)
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
