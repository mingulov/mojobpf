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


def test_reap_zombie_children():
    helper = _load_helper()
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
