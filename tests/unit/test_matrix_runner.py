# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the VM matrix runner's suite discipline.

Pins ``ci/run_vm_tests.py`` verdicts against fake suites: a quick
pass, and a timeout that must kill the whole suite process group
(child and grandchild) while still reporting ``timeout``. Nothing
here boots a guest: the live matrix runs in CI.

The verdict pins cover the structured result protocol: honest
suites (built on the real suite recorder) are accepted by their
recomputed terminal verdict, while forged PASS lines, missing or
truncated terminals, plan drift, wrong revisions/targets/hashes,
broken attempt chains and no-op workloads all fail closed with
their retries kept. Timeouts and signal deaths keep their signed
exits and fail; only a recomputed INCOMPLETE with an env exit
reports ``envfail``.

Deterministic on any host: only the standard library plus pytest's
plain function collection.

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3
tests/unit/test_matrix_runner.py``).
"""

import ast
import importlib.util
import json
import importlib.machinery
import os
import py_compile
import shutil
import signal
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf import validation as validation_mod  # noqa: E402


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

_LANE = {
    "id": "test-lane",
    "release": "v9.99",
    "accelerator": "tcg",
    "kernel_release": "9.99-test",
}

_FAKE_COMMIT = "a" * 40


def _run_fake(runner, source, timeout, extra_env=None, farm=None,
              case_ids=("test_fake_case",), commit=_FAKE_COMMIT):
    root = tempfile.mkdtemp(prefix="mojobpf-matrix-unit-")
    out_dir = os.path.join(root, "out")
    os.makedirs(out_dir)
    suite_path = os.path.join(root, "fake_suite.py")
    with open(suite_path, "w", encoding="utf-8") as handle:
        handle.write(source)
    saved_root = runner.REPO_ROOT
    saved_env = dict(os.environ)
    saved_pins = runner.SUITE_CASES.get("fake-suite")
    runner.REPO_ROOT = root
    runner.SUITE_CASES["fake-suite"] = list(case_ids)
    try:
        if extra_env:
            os.environ.update(extra_env)
        record = runner.run_suite(
            "fake-suite", "fake_suite.py", _LANE, out_dir,
            timeout, commit, None, farm,
        )
    finally:
        runner.REPO_ROOT = saved_root
        if saved_pins is None:
            del runner.SUITE_CASES["fake-suite"]
        else:
            runner.SUITE_CASES["fake-suite"] = saved_pins
        os.environ.clear()
        os.environ.update(saved_env)
    return root, out_dir, record


def _typed_source(case_ids, mode="pass", prelude=""):
    """Build an honest fake suite on the real suite recorder.

    ``mode`` selects the per-case ending: ``pass`` ends every
    case passing; ``infra`` ends the first case in infrastructure
    failure and aborts (the rest stay unrun); ``notrun`` ends
    the first case not-run and finishes unavailable; ``fail``
    ends the first case failed. Inputs pin the fake file
    itself (real, non-empty) in every class.
    """
    body = []
    for case_id in case_ids:
        body.append("rec.begin_case(%r)" % case_id)
        if mode == "pass":
            body.append("print(%r)" % ("PASS " + case_id,))
            body.append("rec.end_case_pass(%r)" % case_id)
        elif mode == "fail" and case_id == case_ids[0]:
            body.append("print(%r)" % ("FAIL " + case_id,))
            body.append("rec.end_case_fail(%r)" % case_id)
        elif mode == "infra" and case_id == case_ids[0]:
            body.append(
                "print(%r)"
                % ("ENVIRONMENT FAILURE in " + case_id,)
            )
            body.append(
                "rec.end_case_infra(%r, 'INFRA', 'UNKNOWN')"
                % case_id
            )
        elif mode == "notrun" and case_id == case_ids[0]:
            body.append(
                "print('REQUIRED-UNAVAILABLE %s: no lease')" % case_id
            )
            body.append(
                "rec.end_case_not_run(%r, 'TARGET_RESOURCE_ABSENT')"
                % case_id
            )
        else:
            body.append("print(%r)" % ("PASS " + case_id,))
            body.append("rec.end_case_pass(%r)" % case_id)
    tail = "sys.exit(rec.finish())"
    if mode == "notrun":
        tail = "sys.exit(rec.finish(unavailable_seen=True))"
    return (
        "import sys\n"
        "sys.path.insert(0, %r)\n"
        "import guest_proc\n"
        "%s\n"
        "rec = guest_proc.SuiteRecorder(\n"
        "    suite_id='fake-suite', suite_path=__file__, \n"
        "    case_ids=%r, lane_release='v9.99',\n"
        "    inputs={case: {'sources': [__file__], "
        "'objects': [__file__], 'corpus': [__file__]} "
        "for case in %r})\n"
        "assert b'fake transcript' in rec.consume_absolute(__file__)\n"
        "rec.note_transcript('guest', 'fake transcript')\n"
        "%s\n"
        "%s\n"
        % (
            os.path.join(REPO_ROOT, "tests", "harness"),
            prelude, list(case_ids), list(case_ids),
            "\n".join(body), tail,
        )
    )


def _craft_documents(case_ids, commit=_FAKE_COMMIT, manifest=None,
                     mutate=None, remangle=None, attempts=(1,),
                     expected_attempts=1, tool="run_vm_tests",
                     source_sha="11" * 32, object_sha="22" * 32,
                     corpus_sha="33" * 32):
    """Craft plan/results/suite documents in-test.

    Builds a PASS plan over ``case_ids`` with the matrix lane
    target and a fixed consumer, emitting ``attempts`` per case.
    ``mutate`` rewrites the plan/results objects before the
    terminal record is recomputed; ``remangle`` rewrites the
    serialized mappings afterwards (forged terminals). Returns
    ``(plan_doc, result_docs, suite_doc)`` as mappings.
    """
    runner = _load_runner()
    if manifest is None:
        manifest = runner.lane_target_manifest(_LANE)
    target = validation_mod.TargetManifest.from_dict(manifest)
    consumer = {
        "name": "fake-suite",
        "version": commit,
        "artifact_sha256": "0" * 64,
    }
    cases = []
    for case_id in case_ids:
        cases.append({
            "case_id": case_id,
            "fixture_id": "fx-fake-suite-%s" % case_id,
            "targets": [target.fingerprint],
            "expectation": "positive",
            "required": True,
            "consumers": [dict(consumer)],
            "source_sha256": source_sha,
            "object_sha256": object_sha,
            "corpus_sha256": corpus_sha,
            "expected_attempts": expected_attempts,
        })
    revisions = {
        "repository_commit": commit,
        "package": "mojobpf@" + commit,
        "tool": tool,
    }
    plan = validation_mod.plan(cases, [manifest], revisions)
    results = []
    for case_id in case_ids:
        for attempt in attempts:
            results.append(validation_mod.CaseResult.from_dict({
                "schema_version": 1,
                "run_id": "craft-run",
                "case_id": case_id,
                "target_fingerprint": target.fingerprint,
                "attempt": attempt,
                "plan_hash": plan.plan_hash,
                "identities": {
                    "repository_commit": commit,
                    "package": "mojobpf@" + commit,
                    "tool": tool,
                    "consumer": dict(consumer),
                    "object_sha256": object_sha,
                    "source_sha256": source_sha,
                    "workload": {
                        "fixture_id": "fx-fake-suite-%s" % case_id,
                        "corpus_sha256": corpus_sha,
                    },
                },
                "applicability": "APPLICABLE",
                "required": True,
                "expected": {
                    "outcome": "PASS", "failure_stage": None
                },
                "observed": {
                    "outcome": "PASS", "failure_stage": None
                },
                "outcome": "PASS",
                "failure_stage": None,
                "evidence": [{
                    "path": "suite:fake_suite.py",
                    "sha256": "44" * 32,
                    "bytes": 128,
                }],
                "cleanup": {"status": "CLEAN", "residue": []},
            }))
    if mutate is not None:
        mutate(plan, results)
    decision = validation_mod.aggregate(plan, results)
    docs = (
        plan.to_dict(),
        [result.to_dict() for result in results],
        decision.to_suite_dict(),
    )
    if remangle is not None:
        remangle(*docs)
    return docs


def _accept_output(runner, case_ids, plan_doc, result_docs, suite_doc,
                   exit_code=0, commit=_FAKE_COMMIT,
                   suite_sha256="0" * 64, manifest=None,
                   expected_denials=None):
    """Judge crafted documents through the real acceptance."""
    if manifest is None:
        manifest = runner.lane_target_manifest(_LANE)
    lines = []
    if plan_doc is not None:
        lines.append(
            "MOJOBPF_RUN_PLAN " + json.dumps(plan_doc, sort_keys=True)
        )
    for doc in result_docs:
        lines.append(
            "MOJOBPF_CASE_RESULT " + json.dumps(doc, sort_keys=True)
        )
    if suite_doc is not None:
        lines.append(
            "MOJOBPF_SUITE_RESULT "
            + json.dumps(suite_doc, sort_keys=True)
        )
    # Pre-obligation runners take no denial pins; call the arity
    # the loaded runner actually supports.
    extra = (
        [expected_denials]
        if runner.accept_suite_output.__code__.co_argcount > 7
        else []
    )
    return runner.accept_suite_output(
        "fake-suite", list(case_ids), "\n".join(lines) + "\n",
        exit_code, commit, manifest, suite_sha256, *extra,
    )


def _craft_mixed_documents(specs, commit=_FAKE_COMMIT, manifest=None,
                           tool="run_vm_tests"):
    """Craft plan/results/suite documents with per-case obligations.

    Each spec names ``case_id`` plus optional ``expectation``
    ("positive"/"denial"), ``required``, ``denies``, ``stage``
    (for denials), ``observed`` (an (outcome, stage) pair),
    ``applicability``, input hashes, ``evidence`` and
    ``cleanup``. The plan is sealed and the terminal record
    recomputed, so the documents are correctly resealed for
    their (possibly forged) obligations.
    """
    runner = _load_runner()
    if manifest is None:
        manifest = runner.lane_target_manifest(_LANE)
    target = validation_mod.TargetManifest.from_dict(manifest)
    consumer = {
        "name": "fake-suite",
        "version": commit,
        "artifact_sha256": "0" * 64,
    }
    cases = []
    for spec in specs:
        entry = {
            "case_id": spec["case_id"],
            "fixture_id": "fx-fake-suite-%s" % spec["case_id"],
            "targets": [target.fingerprint],
            "expectation": spec.get("expectation", "positive"),
            "required": spec.get("required", True),
            "consumers": [dict(consumer)],
            "source_sha256": spec.get("source_sha", "11" * 32),
            "object_sha256": spec.get("object_sha", "22" * 32),
            "corpus_sha256": spec.get("corpus_sha", "33" * 32),
            "expected_attempts": 1,
        }
        if entry["expectation"] == "denial":
            entry["denies"] = spec["denies"]
            entry["expected"] = {
                "outcome": "FAIL",
                "failure_stage": spec["stage"],
            }
        cases.append(entry)
    revisions = {
        "repository_commit": commit,
        "package": "mojobpf@" + commit,
        "tool": tool,
    }
    plan = validation_mod.plan(cases, [manifest], revisions)
    results = []
    for spec in specs:
        observed = spec.get("observed", ("PASS", None))
        if spec.get("expectation") == "denial":
            expected = {
                "outcome": "FAIL",
                "failure_stage": spec["stage"],
            }
        else:
            expected = {"outcome": "PASS", "failure_stage": None}
        results.append(validation_mod.CaseResult.from_dict({
            "schema_version": 1,
            "run_id": "craft-mixed-run",
            "case_id": spec["case_id"],
            "target_fingerprint": target.fingerprint,
            "attempt": 1,
            "plan_hash": plan.plan_hash,
            "identities": {
                "repository_commit": commit,
                "package": "mojobpf@" + commit,
                "tool": tool,
                "consumer": dict(consumer),
                "object_sha256": spec.get("object_sha", "22" * 32),
                "source_sha256": spec.get("source_sha", "11" * 32),
                "workload": {
                    "fixture_id":
                        "fx-fake-suite-%s" % spec["case_id"],
                    "corpus_sha256": spec.get(
                        "corpus_sha", "33" * 32),
                },
            },
            "applicability": spec.get("applicability", "APPLICABLE"),
            "required": spec.get("required", True),
            "expected": expected,
            "observed": {
                "outcome": observed[0], "failure_stage": observed[1]
            },
            "outcome": observed[0],
            "failure_stage": observed[1],
            "evidence": spec.get("evidence", [{
                "path": "suite:fake_suite.py",
                "sha256": "44" * 32,
                "bytes": 128,
            }]),
            "cleanup": spec.get(
                "cleanup", {"status": "CLEAN", "residue": []}
            ),
        }))
    decision = validation_mod.aggregate(plan, results)
    return (
        plan.to_dict(),
        [result.to_dict() for result in results],
        decision.to_suite_dict(),
    )


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
    root, out_dir, record = _run_fake(
        runner, _typed_source(["test_fake_case"]), 120
    )
    try:
        assert record["outcome"] == "pass", record
        assert record["exit_code"] == 0, record
        assert record["verdict"] == "PASS", record
        assert record["passes"] == 1, record
        assert record["failures"] == 0, record
        assert record["timed_out"] is False, record
        assert record["commit"] == _FAKE_COMMIT, record
        assert record["run_id"], record
        assert record["plan_hash"], record
        assert os.path.isfile(
            os.path.join(out_dir, "test-lane.fake-suite.log")
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_forged_pass_lines_without_records_fail():
    # PASS lines are evidence, never the verdict: a suite that
    # prints PASS and exits 0 without emitting a terminal
    # record fails.
    runner = _load_runner()
    root, _out, record = _run_fake(runner, _FAKE_PASS, 120)
    try:
        assert record["exit_code"] == 0, record
        assert record["passes"] == 1, record
        assert record["outcome"] == "fail", record
        assert "run plan" in record["note"], record
        assert record["verdict"] == "NO_TERMINAL", record
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
    # Lines are not authoritative: exit 0 with an ENVIRONMENT
    # FAILURE line but no terminal record fails (an env exit
    # needs its INCOMPLETE terminal to report envfail).
    runner = _load_runner()
    root, _out, record = _run_fake(runner, _FAKE_ENVLINE_EXIT_ZERO, 120)
    try:
        assert record["exit_code"] == 0, record
        assert record["passes"] == 1, record
        assert record["envfailures"] == 1, record
        assert record["outcome"] == "fail", record
        assert "run plan" in record["note"], record
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
    saved_pins = runner.SUITE_CASES.get("fake-suite")
    runner.REPO_ROOT = root
    runner.SUITE_CASES["fake-suite"] = ["test_fake_case"]
    os.environ["MOJOBPF_FAKE_PIDFILE"] = pidfile
    subprocess.Popen = _InterruptOnce
    try:
        try:
            runner.run_suite(
                "fake-suite", "fake_suite.py", _LANE, out_dir,
                120, _FAKE_COMMIT, None,
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
        if saved_pins is None:
            del runner.SUITE_CASES["fake-suite"]
        else:
            runner.SUITE_CASES["fake-suite"] = saved_pins
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
        "v6.12-kvm", "v6.6-kvm", "v7.0.14-kvm",
        "v7.2-kvm", "v7.4-rc1-kvm", "v6.12-tcg",
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


def test_load_lock_rejects_non_string_deb_fields():
    runner = _load_runner()
    for field, bad in (
        ("file", 7),
        ("sha256", 7),
        ("file", ["a.deb"]),
        ("sha256", {"h": 1}),
    ):
        lane = _lane(lane_id="a", release="v9.1")
        lane["kernel_debs"] = [
            {"file": "a.deb", "sha256": "b" * 64}
        ]
        lane["kernel_debs"][0][field] = bad
        lock = _lock([lane, _lane(lane_id="b", release="v9.2")])
        message = _assert_setup_failure(
            _load_lock_text, runner, lock
        )
        assert "file+sha256 must be strings" in message, (
            field, bad, message,
        )
    print("PASS load lock rejects non-string deb fields")


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


def test_load_lock_rejects_non_dict_document():
    runner = _load_runner()
    for bad in (["lanes"], "lanes", 7, None):
        message = _assert_setup_failure(
            _load_lock_text, runner, bad
        )
        assert "must be a JSON object" in message, (bad, message)
    print("PASS load lock rejects non-dict document")


def test_load_lock_rejects_deeply_nested_document():
    runner = _load_runner()
    root = tempfile.mkdtemp(prefix="mojobpf-lock-unit-")
    path = os.path.join(root, "lock.json")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("[" * 1000000 + "]" * 1000000)
    try:
        message = _assert_setup_failure(runner.load_lock, path)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    assert "unreadable" in message, message
    print("PASS load lock rejects deeply nested document")


def test_load_lock_rejects_non_dict_lane():
    runner = _load_runner()
    lock = _lock([
        ["not", "a", "dict"],
        _lane(lane_id="b", release="v9.2"),
    ])
    message = _assert_setup_failure(_load_lock_text, runner, lock)
    assert "not an object" in message, message
    print("PASS load lock rejects non-dict lane")


def test_load_lock_rejects_non_string_lane_id():
    runner = _load_runner()
    lane = _lane(lane_id="a", release="v9.1")
    lane["id"] = ["a"]
    lock = _lock([lane, _lane(lane_id="b", release="v9.2")])
    message = _assert_setup_failure(_load_lock_text, runner, lock)
    assert "id must be a non-empty string" in message, message
    print("PASS load lock rejects non-string lane id")


def test_load_lock_rejects_non_list_kernel_debs():
    runner = _load_runner()
    for bad in (7, {"file": "a.deb"}):
        lane = _lane(lane_id="a", release="v9.1")
        lane["kernel_debs"] = bad
        lock = _lock([lane, _lane(lane_id="b", release="v9.2")])
        message = _assert_setup_failure(
            _load_lock_text, runner, lock
        )
        assert "pins no kernel debs" in message, (bad, message)
    print("PASS load lock rejects non-list kernel debs")


def test_load_lock_rejects_non_list_argv_prefix():
    runner = _load_runner()
    for bad in (7, {"vng": True}):
        lane = _lane(lane_id="a", release="v9.1")
        lane["vng_argv_prefix"] = bad
        lock = _lock([lane, _lane(lane_id="b", release="v9.2")])
        message = _assert_setup_failure(
            _load_lock_text, runner, lock
        )
        assert "argv prefix is not a list" in message, (bad, message)
    print("PASS load lock rejects non-list argv prefix")


def test_load_lock_rejects_non_string_release():
    runner = _load_runner()
    lane = _lane(lane_id="a", release="v9.1")
    lane["release"] = 7
    lock = _lock([lane, _lane(lane_id="b", release="v9.2")])
    message = _assert_setup_failure(_load_lock_text, runner, lock)
    assert "release must be a non-empty string" in message, message
    print("PASS load lock rejects non-string release")


def test_load_lock_rejects_non_string_kernel_release():
    runner = _load_runner()
    lane = _lane(lane_id="a", release="v9.1")
    lane["kernel_release"] = 7
    lock = _lock([lane, _lane(lane_id="b", release="v9.2")])
    message = _assert_setup_failure(_load_lock_text, runner, lock)
    assert "kernel_release must be a non-empty string" in message, (
        message,
    )
    print("PASS load lock rejects non-string kernel release")


def test_load_lock_rejects_empty_lane_id():
    runner = _load_runner()
    lock = _lock([
        _lane(lane_id="", release="v9.1"),
        _lane(lane_id="b", release="v9.2"),
    ])
    message = _assert_setup_failure(_load_lock_text, runner, lock)
    assert "non-empty" in message, message
    print("PASS load lock rejects empty lane id")


def test_load_lock_rejects_empty_release():
    runner = _load_runner()
    lane = _lane(lane_id="a", release="v9.1")
    lane["release"] = ""
    lane["vng_argv_prefix"] = ["vng", "--run", "", "--disable-kvm"]
    lock = _lock([lane, _lane(lane_id="b", release="v9.2")])
    message = _assert_setup_failure(_load_lock_text, runner, lock)
    assert "release must be a non-empty string" in message, message
    print("PASS load lock rejects empty release")


def test_load_lock_rejects_empty_kernel_release():
    runner = _load_runner()
    lane = _lane(lane_id="a", release="v9.1")
    lane["kernel_release"] = ""
    lock = _lock([lane, _lane(lane_id="b", release="v9.2")])
    message = _assert_setup_failure(_load_lock_text, runner, lock)
    assert "kernel_release must be a non-empty string" in message, (
        message,
    )
    print("PASS load lock rejects empty kernel release")


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


def _write_shadow_module(path, marker):
    """Stage a shadow module proving it executed via a marker."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("open(%r, 'w').write('shadow')\n" % marker)


def _import_with_path(code, python_path):
    """Run a snippet with exactly the given PYTHONPATH (control).

    ``-P`` keeps the current directory out of ``sys.path`` so
    selection depends only on the given roots (3.11+ floor).
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(python_path)
    proc = subprocess.run(
        [sys.executable, "-P", "-c", code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        env=env,
    )
    return proc.returncode


def test_earlier_root_shadow_dependency_refused_without_marker():
    """A shadow dependency on an earlier declared root is refused
    before any probe: metadata lookup alone does not bind import
    selection, so the earlier root's bytes -- which the probe
    would import -- reject with module-mismatch and no marker."""
    runner = _load_runner()
    tree = _runner_tree()
    marker = os.path.join(tree["root"], "SHADOW_DEP.marker")
    evil = os.path.join(tree["root"], "evil")
    _write_shadow_module(
        os.path.join(evil, "matrix_dep", "__init__.py"), marker
    )
    lock = _lock_with_distribution(tree, _fixture_distribution(tree))
    lock["runner"]["python_path"] = [evil, tree["pkgdir"]]
    # Positive control: the earlier root wins import selection.
    assert _import_with_path(
        "import matrix_dep", [evil, tree["pkgdir"]]
    ) == 0
    assert os.path.exists(marker), "shadow fixture cannot emit"
    os.unlink(marker)
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "distribution refused" in message, message
        assert "shadowed" in message, message
        assert not os.path.exists(marker), "shadow bytes executed"
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_stdlib_shadow_on_declared_root_refused_without_marker():
    """A json.py on a declared root would shadow the standard
    library inside every probe (PYTHONPATH precedes it), so the
    root is refused at static admission with module-mismatch
    and no marker."""
    runner = _load_runner()
    tree = _runner_tree()
    marker = os.path.join(tree["root"], "SHADOW_JSON.marker")
    evil = os.path.join(tree["root"], "evil")
    _write_shadow_module(os.path.join(evil, "json.py"), marker)
    lock = _pinned_runner_lock(tree)
    lock["runner"]["python_path"] = [evil, tree["pkgdir"]]
    # Positive control: the declared root shadows the stdlib.
    assert _import_with_path("import json", [evil]) == 0
    assert os.path.exists(marker), "shadow fixture cannot emit"
    os.unlink(marker)
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "admission refused" in message, message
        assert "shadows the admitted interpreter's" in message, message
        assert not os.path.exists(marker), "shadow bytes executed"
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_parent_package_shadow_refused_without_marker():
    """A shadow parent package on an earlier root hijacks the
    whole subtree: the pinned submodule's bytes verify, but the
    interpreter would resolve its parent (and the submodule
    under it) from the earlier root. Refused with
    module-mismatch and no marker."""
    runner = _load_runner()
    tree = _runner_tree()
    marker = os.path.join(tree["root"], "SHADOW_PARENT.marker")
    evil = os.path.join(tree["root"], "evil")
    _write_shadow_module(
        os.path.join(evil, "matrix_vng_pkg", "__init__.py"), marker
    )
    lock = _pinned_runner_lock(tree)
    lock["runner"]["python_path"] = [evil, tree["pkgdir"]]
    # Pin only the submodule: its bytes verify on the later
    # root while the shadowed parent escapes a leaf-only check.
    modules = lock["runner"]["package"]["modules"]
    del modules["matrix_vng_pkg"]
    # Positive control: the earlier root wins the parent.
    assert _import_with_path(
        "import matrix_vng_pkg", [evil, tree["pkgdir"]]
    ) == 0
    assert os.path.exists(marker), "shadow fixture cannot emit"
    os.unlink(marker)
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "admission refused" in message, message
        assert "shadowed" in message, message
        assert not os.path.exists(marker), "shadow bytes executed"
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def _write_shadow_package_pyc(package_dir, marker):
    """Stage a legacy-layout sourceless ``__init__.pyc`` shadow.

    Compiles a marker-emitting module and places the bytecode as
    ``package_dir/__init__.pyc`` (no source beside it), which the
    import system loads via SourcelessFileLoader.
    """
    os.makedirs(package_dir, exist_ok=True)
    target = os.path.join(package_dir, "__init__.pyc")
    src = os.path.join(package_dir, "_stage_src.py")
    _write_shadow_module(src, marker)
    try:
        py_compile.compile(src, cfile=target, doraise=True)
    finally:
        if os.path.exists(src):
            os.unlink(src)
    return target


def _find_extension_donor():
    """Return a loadable stdlib extension path, or None."""
    for name in ("_datetime", "_socket", "math", "_struct"):
        spec = importlib.util.find_spec(name)
        if spec and spec.origin and spec.origin.endswith(".so"):
            return spec.origin
    return None


def _write_shadow_package_ext_so(package_dir):
    """Stage an ``__init__.<ext>.so`` shadow from a real extension.

    Copies a loadable standard-library extension under the
    platform's first extension suffix so the file finder selects
    it. Skips when this host links extensions statically.
    """
    suffix = importlib.machinery.EXTENSION_SUFFIXES[0]
    os.makedirs(package_dir, exist_ok=True)
    target = os.path.join(package_dir, "__init__" + suffix)
    donor = _find_extension_donor()
    if donor is None:
        _skip_direct_or_pytest(
            "no loadable stdlib extension on this host"
        )
    shutil.copyfile(donor, target)
    return target


def _write_shadow_module_ext_so(directory, stem):
    """Stage a ``stem.<ext>.so`` shadow from a real extension.

    Copies a loadable standard-library extension beside the
    verified source so the file finder selects the extension.
    Skips when this host links extensions statically.
    """
    suffix = importlib.machinery.EXTENSION_SUFFIXES[0]
    os.makedirs(directory, exist_ok=True)
    target = os.path.join(directory, stem + suffix)
    donor = _find_extension_donor()
    if donor is None:
        _skip_direct_or_pytest(
            "no loadable stdlib extension on this host"
        )
    shutil.copyfile(donor, target)
    return target


def _find_spec_origin(dotted, roots):
    """Resolve a module spec origin in a hermetic subprocess.

    Reports what the import system would select for ``dotted``
    under exactly ``roots`` (``-P`` keeps the current directory
    out), without importing it.
    """
    lines = ["import sys", "import importlib.util"]
    for root in reversed(roots):
        lines.append("sys.path.insert(0, %r)" % (root,))
    lines.append(
        "print(importlib.util.find_spec(%r).origin)" % (dotted,)
    )
    proc = subprocess.run(
        [sys.executable, "-P", "-c", "\n".join(lines)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        env=dict(os.environ),
    )
    assert proc.returncode == 0, proc.stderr.decode()[-500:]
    return proc.stdout.decode().strip()


def _run_entry_with_path(entry, roots):
    """Run a console entry with exactly the given PYTHONPATH."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(roots)
    return subprocess.run(
        [entry],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        env=env,
    )


def test_stdlib_shadow_package_init_pyc_refused_without_marker():
    """A json/__init__.pyc on a declared root shadows the stdlib
    (sourceless bytecode imports as the package), so the root is
    refused at static admission with module-mismatch and no
    marker."""
    runner = _load_runner()
    tree = _runner_tree()
    marker = os.path.join(tree["root"], "SHADOW_JSON_PYC.marker")
    evil = os.path.join(tree["root"], "evil")
    _write_shadow_package_pyc(os.path.join(evil, "json"), marker)
    lock = _pinned_runner_lock(tree)
    lock["runner"]["python_path"] = [evil, tree["pkgdir"]]
    # Positive control: the sourceless package wins selection.
    assert _import_with_path("import json", [evil]) == 0
    assert os.path.exists(marker), "shadow fixture cannot emit"
    os.unlink(marker)
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "admission refused" in message, message
        assert "shadows the admitted interpreter's" in message, message
        assert not os.path.exists(marker), "shadow bytes executed"
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_stdlib_shadow_package_init_ext_so_refused():
    """A json/__init__.<ext>.so on a declared root diverts import
    selection away from the verified stdlib, so the root is
    refused at static admission with module-mismatch before any
    probe executes."""
    runner = _load_runner()
    tree = _runner_tree()
    evil = os.path.join(tree["root"], "evil")
    _write_shadow_package_ext_so(os.path.join(evil, "json"))
    lock = _pinned_runner_lock(tree)
    lock["runner"]["python_path"] = [evil, tree["pkgdir"]]
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "admission refused" in message, message
        assert "shadows the admitted interpreter's" in message, message
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_earlier_root_shadow_package_init_pyc_refused_without_marker():
    """A parent package shadowed as __init__.pyc on an earlier
    root hijacks the pinned submodule: the submodule's bytes
    verify on the later root, but the interpreter would select
    the sourceless parent (and fail the submodule beneath it)
    from the earlier root. Refused with module-mismatch and no
    marker."""
    runner = _load_runner()
    tree = _runner_tree()
    marker = os.path.join(tree["root"], "SHADOW_PARENT_PYC.marker")
    evil = os.path.join(tree["root"], "evil")
    _write_shadow_package_pyc(
        os.path.join(evil, "matrix_vng_pkg"), marker
    )
    lock = _pinned_runner_lock(tree)
    lock["runner"]["python_path"] = [evil, tree["pkgdir"]]
    # Pin only the submodule: its bytes verify on the later
    # root while the shadowed parent escapes a leaf-only check.
    modules = lock["runner"]["package"]["modules"]
    del modules["matrix_vng_pkg"]
    # Positive control: the earlier root wins the parent.
    assert _import_with_path(
        "import matrix_vng_pkg", [evil, tree["pkgdir"]]
    ) == 0
    assert os.path.exists(marker), "shadow fixture cannot emit"
    os.unlink(marker)
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "admission refused" in message, message
        assert "shadowed" in message, message
        assert not os.path.exists(marker), "shadow bytes executed"
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_same_root_extension_module_beats_verified_source_refused():
    """A run.<ext>.so beside the verified run.py wins import
    selection (extensions beat source), so the pinned module is
    refused before any probe with module-mismatch."""
    runner = _load_runner()
    tree = _runner_tree()
    _write_shadow_module_ext_so(tree["package"], "run")
    lock = _pinned_runner_lock(tree)
    # Positive control: the file finder selects the extension.
    origin = _find_spec_origin(
        "matrix_vng_pkg.run", [tree["pkgdir"]]
    )
    assert origin.endswith(".so"), origin
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "admission refused" in message, message
        assert "shadowed" in message, message
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_same_root_extension_init_beats_verified_init_refused():
    """An __init__.<ext>.so beside the verified __init__.py wins
    import selection, so the pinned package is refused before
    any probe with module-mismatch."""
    runner = _load_runner()
    tree = _runner_tree()
    _write_shadow_package_ext_so(tree["package"])
    lock = _pinned_runner_lock(tree)
    # Positive control: the file finder selects the extension.
    origin = _find_spec_origin("matrix_vng_pkg", [tree["pkgdir"]])
    assert origin.endswith(".so"), origin
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "admission refused" in message, message
        assert "shadowed" in message, message
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_same_root_package_beats_verified_module_refused_without_marker():
    """A run/ package beside the verified run.py wins import
    selection (packages beat modules), so the pinned module is
    refused before any probe with module-mismatch and the
    shadow main never executes."""
    runner = _load_runner()
    tree = _runner_tree()
    marker = os.path.join(tree["root"], "SHADOW_RUN_PKG.marker")
    run_pkg = os.path.join(tree["package"], "run")
    os.makedirs(run_pkg)
    with open(os.path.join(run_pkg, "__init__.py"), "w") as handle:
        handle.write(
            "open(%r, 'w').write('shadow')\n"
            "def main():\n"
            "    print(%r)\n"
            "    return 0\n" % (marker, _VNG_FIXTURE_VERSION)
        )
    lock = _pinned_runner_lock(tree)
    # Positive control: a spawn executes the shadow package.
    proc = _run_entry_with_path(tree["entry"], [tree["pkgdir"]])
    assert proc.returncode == 0, proc.stderr.decode()[-500:]
    assert _VNG_FIXTURE_VERSION in proc.stdout.decode()
    assert os.path.exists(marker), "shadow fixture cannot emit"
    os.unlink(marker)
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "admission refused" in message, message
        assert "shadowed" in message, message
        assert not os.path.exists(marker), "shadow bytes executed"
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_same_root_sourceless_parent_shadow_refused_without_marker():
    """A parent kept only as __init__.pyc executes unadmitted
    bytecode on every import of the pinned submodule beneath
    it, so admission is refused before any probe with
    module-mismatch and no marker."""
    runner = _load_runner()
    tree = _runner_tree()
    marker = os.path.join(tree["root"], "SHADOW_SAME_PARENT.marker")
    lock = _pinned_runner_lock(tree)
    os.unlink(os.path.join(tree["package"], "__init__.py"))
    _write_shadow_package_pyc(tree["package"], marker)
    # Pin only the submodule: its bytes verify while the
    # sourceless parent escapes a leaf-only check.
    modules = lock["runner"]["package"]["modules"]
    del modules["matrix_vng_pkg"]
    # Positive control: a spawn executes the shadow parent,
    # then the verified submodule beneath it.
    proc = _run_entry_with_path(tree["entry"], [tree["pkgdir"]])
    assert proc.returncode == 0, proc.stderr.decode()[-500:]
    assert _VNG_FIXTURE_VERSION in proc.stdout.decode()
    assert os.path.exists(marker), "shadow fixture cannot emit"
    os.unlink(marker)
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "admission refused" in message, message
        assert "shadowed" in message, message
        assert not os.path.exists(marker), "shadow bytes executed"
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_same_root_losing_siblings_still_admit():
    """Siblings that lose import selection change nothing: legacy
    bytecode beside verified source, and a module extension
    beside a verified package, all lose, so admission still
    succeeds."""
    runner = _load_runner()
    tree = _runner_tree()
    for stem in ("run", "__init__"):
        src = os.path.join(tree["package"], "_benign_%s.py" % stem)
        with open(src, "w") as handle:
            handle.write("VALUE = 1\n")
        try:
            py_compile.compile(
                src,
                cfile=os.path.join(
                    tree["package"], stem + ".pyc"
                ),
                doraise=True,
            )
        finally:
            os.unlink(src)
    # Positive control: source still wins over the bytecode.
    origin = _find_spec_origin(
        "matrix_vng_pkg.run", [tree["pkgdir"]]
    )
    assert origin.endswith("run.py"), origin
    _write_shadow_module_ext_so(tree["pkgdir"], "matrix_vng_pkg")
    # Positive control: the package still wins over the module
    # extension.
    origin = _find_spec_origin("matrix_vng_pkg", [tree["pkgdir"]])
    assert origin.endswith("__init__.py"), origin
    lock = _pinned_runner_lock(tree)
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        record = runner.check_runner(
            lock, farm_parent=tree["root"]
        )
        shutil.rmtree(record["farm"], ignore_errors=True)
        assert record["version"] == _VNG_FIXTURE_VERSION, record
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_distribution_same_root_extension_init_refused():
    """An __init__.<ext>.so beside the RECORD-verified
    __init__.py wins import selection, so the distribution is
    refused before any probe with module-mismatch."""
    runner = _load_runner()
    tree = _runner_tree()
    lock = _lock_with_distribution(tree, _fixture_distribution(tree))
    _write_shadow_package_ext_so(
        os.path.join(tree["pkgdir"], "matrix_dep")
    )
    # Positive control: the file finder selects the extension.
    origin = _find_spec_origin("matrix_dep", [tree["pkgdir"]])
    assert origin.endswith(".so"), origin
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "distribution refused" in message, message
        assert "shadowed" in message, message
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_distribution_same_root_losing_siblings_still_admit():
    """Siblings that lose import selection change nothing: a
    module source, module bytecode and module extension beside
    a RECORD-verified package all lose to the package, so
    admission still succeeds."""
    runner = _load_runner()
    tree = _runner_tree()
    lock = _lock_with_distribution(tree, _fixture_distribution(tree))
    with open(
        os.path.join(tree["pkgdir"], "matrix_dep.py"), "w"
    ) as handle:
        handle.write("VALUE = 2\n")
    src = os.path.join(tree["pkgdir"], "_benign_dep.py")
    with open(src, "w") as handle:
        handle.write("VALUE = 3\n")
    try:
        py_compile.compile(
            src,
            cfile=os.path.join(
                tree["pkgdir"], "matrix_dep.pyc"
            ),
            doraise=True,
        )
    finally:
        os.unlink(src)
    _write_shadow_module_ext_so(tree["pkgdir"], "matrix_dep")
    # Positive control: the verified package still wins.
    origin = _find_spec_origin("matrix_dep", [tree["pkgdir"]])
    assert origin.endswith("__init__.py"), origin
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        record = runner.check_runner(
            lock, farm_parent=tree["root"]
        )
        shutil.rmtree(record["farm"], ignore_errors=True)
        assert record["version"] == _VNG_FIXTURE_VERSION, record
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_distribution_sourceless_verified_beaten_by_source_refused():
    """A RECORD-verified legacy .pyc loses import selection to a
    same-stem .py source, so the distribution is refused before
    any probe: the verified bytecode would never execute."""
    runner = _load_runner()
    tree = _runner_tree()
    stage_src = os.path.join(tree["root"], "_smod_stage.py")
    with open(stage_src, "w") as handle:
        handle.write("VALUE = 1\n")
    stage_pyc = os.path.join(tree["root"], "_smod_stage.pyc")
    py_compile.compile(stage_src, cfile=stage_pyc, doraise=True)
    with open(stage_pyc, "rb") as handle:
        pyc_bytes = handle.read()
    os.unlink(stage_src)
    os.unlink(stage_pyc)
    metadata_digest, record_digest = _write_dep_dist(
        tree["pkgdir"],
        "matrix_smod",
        "1.0",
        {"matrix_smod.pyc": pyc_bytes},
    )
    lock = _pinned_runner_lock(tree)
    lock["distribution"] = {
        "runner": {
            "dependencies": [
                {
                    "name": "matrix_smod",
                    "version": "1.0",
                    "metadata_sha256": metadata_digest,
                    "record_sha256": record_digest,
                },
            ],
        },
        "emulator": {"qemu_version": _QEMU_FIXTURE_VERSION},
    }
    with open(
        os.path.join(tree["pkgdir"], "matrix_smod.py"), "w"
    ) as handle:
        handle.write("VALUE = 2\n")
    # Positive control: the source wins over the verified
    # bytecode.
    assert _import_with_path(
        "import matrix_smod, sys; "
        "sys.exit(0 if matrix_smod.VALUE == 2 else 1)",
        [tree["pkgdir"]],
    ) == 0
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "distribution refused" in message, message
        assert "shadowed" in message, message
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def _lock_with_dep_dist(tree, name, version, files):
    """Pin a fixture distribution built from ``files``."""
    metadata_digest, record_digest = _write_dep_dist(
        tree["pkgdir"], name, version, files
    )
    lock = _pinned_runner_lock(tree)
    lock["distribution"] = {
        "runner": {
            "dependencies": [
                {
                    "name": name,
                    "version": version,
                    "metadata_sha256": metadata_digest,
                    "record_sha256": record_digest,
                },
            ],
        },
        "emulator": {"qemu_version": _QEMU_FIXTURE_VERSION},
    }
    return lock


def _admitted_runner_version(runner, lock, tree):
    """Admit the fixture runner; return its probed version."""
    record = runner.check_runner(lock, farm_parent=tree["root"])
    try:
        assert record["version"] == _VNG_FIXTURE_VERSION, record
    finally:
        shutil.rmtree(record["farm"], ignore_errors=True)
    return record["version"]


def _donor_extension_bytes():
    """Read a loadable stdlib extension, skipping without one."""
    donor = _find_extension_donor()
    if donor is None:
        _skip_direct_or_pytest(
            "no loadable stdlib extension on this host"
        )
    with open(donor, "rb") as handle:
        return handle.read()


def test_distribution_verified_extension_beats_verified_source_admits():
    """A RECORD-verified extension beside a RECORD-verified
    source is dual shipment, not a hijack: the file finder
    selects the extension and its bytes are verified, so the
    distribution admits (the executed bytes are verified
    bytes)."""
    donor_bytes = _donor_extension_bytes()
    runner = _load_runner()
    tree = _runner_tree()
    suffix = importlib.machinery.EXTENSION_SUFFIXES[0]
    lock = _lock_with_dep_dist(
        tree,
        "matrix_dual",
        "1.0",
        {
            "matrix_dual.py": "VALUE = 1\n",
            "matrix_dual" + suffix: donor_bytes,
        },
    )
    # Positive control: the file finder selects the extension.
    origin = _find_spec_origin("matrix_dual", [tree["pkgdir"]])
    assert origin.endswith(".so"), origin
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        _admitted_runner_version(runner, lock, tree)
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_distribution_unverified_extension_beats_verified_source_refused():
    """A same-stem extension outside RECORD beside a
    RECORD-verified source wins import selection with
    unverified bytes, so the distribution is refused before any
    probe with module-mismatch."""
    runner = _load_runner()
    tree = _runner_tree()
    lock = _lock_with_dep_dist(
        tree,
        "matrix_dual",
        "1.0",
        {"matrix_dual.py": "VALUE = 1\n"},
    )
    _write_shadow_module_ext_so(tree["pkgdir"], "matrix_dual")
    # Positive control: the file finder selects the extension.
    origin = _find_spec_origin("matrix_dual", [tree["pkgdir"]])
    assert origin.endswith(".so"), origin
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "distribution refused" in message, message
        assert "shadowed" in message, message
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_distribution_second_unverified_extension_refuses():
    """A verified extension beside a verified source still
    refuses when a second same-stem extension is unverified,
    under both directory orders: loader precedence (not
    listdir order) picks the winner, so any unverified
    sibling fails the stem closed. The foreign sibling uses
    a real first-precedence suffix, and a positive control
    proves the file finder would select it: this pins
    order-independent refusal of a genuinely winnable
    sibling. (Pre/post discrimination for the stem-closure
    change lives in the package-init tests: the module
    extension-rel exhaustive loop already refused this shape
    pre-fix.)"""
    from unittest import mock  # noqa: E402

    suffixes = importlib.machinery.EXTENSION_SUFFIXES
    if len(suffixes) < 2:
        _skip_direct_or_pytest("needs two real extension suffixes")
    donor_bytes = _donor_extension_bytes()
    runner = _load_runner()
    tree = _runner_tree()
    first_suffix, second_suffix = suffixes[0], suffixes[1]
    verified_name = "matrix_dual" + second_suffix
    foreign_name = "matrix_dual" + first_suffix
    lock = _lock_with_dep_dist(
        tree,
        "matrix_dual",
        "1.0",
        {
            "matrix_dual.py": "VALUE = 1\n",
            verified_name: donor_bytes,
        },
    )
    with open(
        os.path.join(tree["pkgdir"], foreign_name), "wb"
    ) as handle:
        handle.write(b"unverified-native-bytes")
    # Positive control: the foreign sibling genuinely wins
    # import selection (first suffix precedence).
    origin = _find_spec_origin("matrix_dual", [tree["pkgdir"]])
    assert origin.endswith(foreign_name), origin
    pkgdir = os.path.realpath(tree["pkgdir"])
    real_listdir = os.listdir

    def _pinned_order(path, first):
        entries = real_listdir(path)
        if os.path.realpath(path) == pkgdir:
            rest = sorted(e for e in entries if e != first)
            entries = [first] + rest
        return entries

    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        for first in (verified_name, foreign_name):
            with mock.patch.object(
                os, "listdir",
                side_effect=lambda path, _first=first: (
                    _pinned_order(path, _first)
                ),
            ):
                message = _assert_setup_failure(
                    runner.check_runner, lock
                )
            assert "distribution refused" in message, (
                first, message,
            )
            assert "shadowed" in message, (first, message)
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_distribution_package_init_shadowed_by_unverified_extension_refuses():
    """A verified package init beside a verified extension init
    still refuses when a second init extension is unverified:
    first-match order would admit the verified one while the
    unverified sibling can win selection, so the stem must
    close over every init spelling. The foreign sibling uses
    a real first-precedence suffix with a positive control
    proving selection; directory order is pinned
    verified-first so the old rule would admit (RED)."""
    from unittest import mock  # noqa: E402

    suffixes = importlib.machinery.EXTENSION_SUFFIXES
    if len(suffixes) < 2:
        _skip_direct_or_pytest("needs two real extension suffixes")
    donor_bytes = _donor_extension_bytes()
    runner = _load_runner()
    tree = _runner_tree()
    first_suffix, second_suffix = suffixes[0], suffixes[1]
    verified_name = "__init__" + second_suffix
    foreign_name = "__init__" + first_suffix
    lock = _lock_with_dep_dist(
        tree,
        "matrix_plus",
        "1.0",
        {
            "matrix_plus.py": "VALUE = 1\n",
            "matrix_plus/__init__.py": "VALUE = 2\n",
            "matrix_plus/" + verified_name: donor_bytes,
        },
    )
    with open(
        os.path.join(tree["pkgdir"], "matrix_plus", foreign_name),
        "wb",
    ) as handle:
        handle.write(b"unverified-native-bytes")
    # Positive control: the foreign init genuinely wins
    # import selection (first suffix precedence).
    origin = _find_spec_origin(
        "matrix_plus", [tree["pkgdir"]]
    )
    assert origin.endswith(foreign_name), origin
    pkgdir = os.path.realpath(tree["pkgdir"])
    subdir = os.path.join(pkgdir, "matrix_plus")
    real_listdir = os.listdir

    def _verified_first(path):
        entries = real_listdir(path)
        current = os.path.realpath(path)
        if current == subdir:
            rest = sorted(
                e for e in entries if e != verified_name
            )
            entries = [verified_name] + rest
        return entries

    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        with mock.patch.object(
            os, "listdir", side_effect=_verified_first
        ):
            message = _assert_setup_failure(
                runner.check_runner, lock
            )
        assert "distribution refused" in message, message
        assert "shadowed" in message, message
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_distribution_sourceless_extension_init_pair_refuses():
    """A RECORD listing only an extension init still refuses
    when a second init extension sits beside it unverified:
    the early precedence return must not skip the sibling
    enumeration, or a sourceless-only package admits blind.
    The foreign sibling uses a real first-precedence suffix
    with a positive control proving selection."""
    suffixes = importlib.machinery.EXTENSION_SUFFIXES
    if len(suffixes) < 2:
        _skip_direct_or_pytest("needs two real extension suffixes")
    donor_bytes = _donor_extension_bytes()
    runner = _load_runner()
    tree = _runner_tree()
    first_suffix, second_suffix = suffixes[0], suffixes[1]
    verified_name = "__init__" + second_suffix
    foreign_name = "__init__" + first_suffix
    lock = _lock_with_dep_dist(
        tree,
        "matrix_solo",
        "1.0",
        {
            "matrix_solo/" + verified_name: donor_bytes,
        },
    )
    with open(
        os.path.join(tree["pkgdir"], "matrix_solo", foreign_name),
        "wb",
    ) as handle:
        handle.write(b"unverified-native-bytes")
    # Positive control: the foreign init genuinely wins
    # import selection (first suffix precedence).
    origin = _find_spec_origin(
        "matrix_solo", [tree["pkgdir"]]
    )
    assert origin.endswith(foreign_name), origin
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "distribution refused" in message, message
        assert "shadowed" in message, message
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_distribution_sourceless_extension_init_alone_admits():
    """A RECORD listing a lone extension init admits when no
    sibling init spelling exists: nothing competes for
    selection, so the verified bytes execute."""
    donor_bytes = _donor_extension_bytes()
    runner = _load_runner()
    tree = _runner_tree()
    suffix = importlib.machinery.EXTENSION_SUFFIXES[0]
    lock = _lock_with_dep_dist(
        tree,
        "matrix_solo",
        "1.0",
        {
            "matrix_solo/__init__"
            + suffix: donor_bytes,
        },
    )
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        _admitted_runner_version(runner, lock, tree)
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_stem_level_importables_enumerates_winners():
    """The stem set collects every file that could win import
    selection: module spellings plus package-init spellings
    for module beaters, init spellings only for package
    beaters (parent module spellings lose to packages)."""
    from mojobpf import execution as execution_mod  # noqa: E402

    workdir = tempfile.mkdtemp(prefix="stem-level-")
    try:
        pkgdir = os.path.join(workdir, "pkg")
        os.makedirs(os.path.join(pkgdir, "mod", "sub"))
        for rel in (
            "mod.py",
            "mod.zzz-tag.so",
            "mod/sub.py",
            "mod/__init__.py",
            "mod/__init__.zzz-tag.so",
            "other.py",
        ):
            with open(os.path.join(pkgdir, rel), "w") as handle:
                handle.write("VALUE = 1\n")
        assert execution_mod._stem_level_importables(
            pkgdir, "mod.zzz-tag.so"
        ) == [
            "mod.py",
            "mod.zzz-tag.so",
            "mod/__init__.py",
            "mod/__init__.zzz-tag.so",
        ]
        assert execution_mod._stem_level_importables(
            pkgdir, "mod/__init__.py"
        ) == [
            "mod/__init__.py",
            "mod/__init__.zzz-tag.so",
        ]
        assert execution_mod._stem_level_importables(
            pkgdir, "sub.py"
        ) == []
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_distribution_verified_extension_init_beats_verified_init_admits():
    """A RECORD-verified package extension init beside a
    RECORD-verified __init__.py admits: the winner is verified
    bytes."""
    donor_bytes = _donor_extension_bytes()
    runner = _load_runner()
    tree = _runner_tree()
    suffix = importlib.machinery.EXTENSION_SUFFIXES[0]
    lock = _lock_with_dep_dist(
        tree,
        "matrix_dualpkg",
        "1.0",
        {
            "matrix_dualpkg/__init__.py": "VALUE = 1\n",
            "matrix_dualpkg/__init__"
            + suffix: donor_bytes,
        },
    )
    # Positive control: the file finder selects the extension.
    origin = _find_spec_origin("matrix_dualpkg", [tree["pkgdir"]])
    assert origin.endswith(".so"), origin
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        _admitted_runner_version(runner, lock, tree)
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_distribution_verified_source_beats_verified_bytecode_admits():
    """A RECORD listing both stem.py and legacy stem.pyc admits:
    the source wins import selection and its bytes are
    verified; the losing bytecode never executes."""
    runner = _load_runner()
    tree = _runner_tree()
    stage_src = os.path.join(tree["root"], "_dmod_stage.py")
    with open(stage_src, "w") as handle:
        handle.write("VALUE = 1\n")
    stage_pyc = os.path.join(tree["root"], "_dmod_stage.pyc")
    py_compile.compile(stage_src, cfile=stage_pyc, doraise=True)
    with open(stage_pyc, "rb") as handle:
        pyc_bytes = handle.read()
    os.unlink(stage_src)
    os.unlink(stage_pyc)
    lock = _lock_with_dep_dist(
        tree,
        "matrix_dmod",
        "1.0",
        {
            "matrix_dmod.py": "VALUE = 2\n",
            "matrix_dmod.pyc": pyc_bytes,
        },
    )
    # Positive control: the source wins over the bytecode.
    assert _import_with_path(
        "import matrix_dmod, sys; "
        "sys.exit(0 if matrix_dmod.VALUE == 2 else 1)",
        [tree["pkgdir"]],
    ) == 0
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        _admitted_runner_version(runner, lock, tree)
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_distribution_verified_extension_init_at_ancestor_admits():
    """A RECORD-verified package extension init at an ancestor
    level admits: the submodule beneath still resolves under
    the verified package and every executed init is verified
    bytes."""
    donor_bytes = _donor_extension_bytes()
    runner = _load_runner()
    tree = _runner_tree()
    suffix = importlib.machinery.EXTENSION_SUFFIXES[0]
    lock = _lock_with_dep_dist(
        tree,
        "matrix_ancpkg",
        "1.0",
        {
            "matrix_ancpkg/__init__.py": "VALUE = 1\n",
            "matrix_ancpkg/__init__"
            + suffix: donor_bytes,
            "matrix_ancpkg/child.py": "VALUE = 3\n",
        },
    )
    # Positive control: the file finder selects the extension
    # init for the package.
    origin = _find_spec_origin("matrix_ancpkg", [tree["pkgdir"]])
    assert origin.endswith(".so"), origin
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        _admitted_runner_version(runner, lock, tree)
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_later_root_namespace_fallback_shadow_refused_without_marker():
    """A bare parent on the verified root falls back to a later
    root's regular package (regular beats namespace portions),
    so the pinned submodule's verified bytes never execute: a
    later root carrying the parent is refused with
    module-mismatch and no marker."""
    runner = _load_runner()
    tree = _runner_tree()
    marker = os.path.join(tree["root"], "SHADOW_FALLBACK.marker")
    lock = _pinned_runner_lock(tree)
    # Bare the verified parent: no regular spelling remains.
    os.unlink(os.path.join(tree["package"], "__init__.py"))
    modules = lock["runner"]["package"]["modules"]
    del modules["matrix_vng_pkg"]
    later = os.path.join(tree["root"], "later")
    later_pkg = os.path.join(later, "matrix_vng_pkg")
    os.makedirs(later_pkg)
    with open(os.path.join(later_pkg, "__init__.py"), "w") as handle:
        handle.write("")
    with open(os.path.join(later_pkg, "run.py"), "w") as handle:
        handle.write(
            "open(%r, 'w').write('shadow')\n"
            "def main():\n"
            "    print(%r)\n"
            "    return 0\n" % (marker, _VNG_FIXTURE_VERSION)
        )
    lock["runner"]["python_path"] = [tree["pkgdir"], later]
    # Positive control: the later root wins through fallback.
    proc = _run_entry_with_path(
        tree["entry"], [tree["pkgdir"], later]
    )
    assert proc.returncode == 0, proc.stderr.decode()[-500:]
    assert _VNG_FIXTURE_VERSION in proc.stdout.decode()
    assert os.path.exists(marker), "shadow fixture cannot emit"
    os.unlink(marker)
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "admission refused" in message, message
        assert "shadowed" in message, message
        assert not os.path.exists(marker), "shadow bytes executed"
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_distribution_later_root_namespace_fallback_refused():
    """A RECORD-verified leaf under a bare parent falls back to
    a later root's regular package, so the distribution is
    refused before any probe with module-mismatch."""
    runner = _load_runner()
    tree = _runner_tree()
    metadata_digest, record_digest = _write_dep_dist(
        tree["pkgdir"],
        "matrix_dep",
        "1.0",
        {"matrix_dep/sub.py": "VALUE = 1\n"},
    )
    lock = _pinned_runner_lock(tree)
    lock["distribution"] = {
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
    later = os.path.join(tree["root"], "later")
    later_pkg = os.path.join(later, "matrix_dep")
    os.makedirs(later_pkg)
    with open(os.path.join(later_pkg, "__init__.py"), "w") as handle:
        handle.write("")
    with open(os.path.join(later_pkg, "sub.py"), "w") as handle:
        handle.write("VALUE = 2\n")
    lock["runner"]["python_path"] = [tree["pkgdir"], later]
    # Positive control: the later root wins through fallback.
    assert _import_with_path(
        "import matrix_dep.sub, sys; "
        "sys.exit(0 if matrix_dep.sub.VALUE == 2 else 1)",
        [tree["pkgdir"], later],
    ) == 0
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "distribution refused" in message, message
        assert "shadowed" in message, message
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_distribution_shadow_package_init_pyc_refused_without_marker():
    """A matrix_dep/__init__.pyc on an earlier root is caught on
    the distribution path: the record-derived stem carries the
    __init__ leaf, so the legacy bytecode spelling refuses with
    module-mismatch before any probe and no marker."""
    runner = _load_runner()
    tree = _runner_tree()
    marker = os.path.join(tree["root"], "SHADOW_DIST_PYC.marker")
    evil = os.path.join(tree["root"], "evil")
    _write_shadow_package_pyc(
        os.path.join(evil, "matrix_dep"), marker
    )
    lock = _lock_with_distribution(tree, _fixture_distribution(tree))
    lock["runner"]["python_path"] = [evil, tree["pkgdir"]]
    # Positive control: the earlier root wins import selection.
    assert _import_with_path(
        "import matrix_dep", [evil, tree["pkgdir"]]
    ) == 0
    assert os.path.exists(marker), "shadow fixture cannot emit"
    os.unlink(marker)
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "distribution refused" in message, message
        assert "shadowed" in message, message
        assert not os.path.exists(marker), "shadow bytes executed"
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_distribution_shadow_package_init_ext_so_refused():
    """A matrix_dep/__init__.<ext>.so on an earlier root is
    caught on the distribution path: the record-derived stem
    carries the __init__ leaf, so the extension spelling
    refuses with module-mismatch before any probe."""
    runner = _load_runner()
    tree = _runner_tree()
    evil = os.path.join(tree["root"], "evil")
    _write_shadow_package_ext_so(os.path.join(evil, "matrix_dep"))
    lock = _lock_with_distribution(tree, _fixture_distribution(tree))
    lock["runner"]["python_path"] = [evil, tree["pkgdir"]]
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "distribution refused" in message, message
        assert "shadowed" in message, message
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def test_earlier_root_shadow_package_init_ext_so_refused():
    """A parent package shadowed as __init__.<ext>.so on an
    earlier root diverts import selection away from the verified
    submodule bytes, so admission is refused before any probe
    with module-mismatch."""
    runner = _load_runner()
    tree = _runner_tree()
    evil = os.path.join(tree["root"], "evil")
    _write_shadow_package_ext_so(
        os.path.join(evil, "matrix_vng_pkg")
    )
    lock = _pinned_runner_lock(tree)
    lock["runner"]["python_path"] = [evil, tree["pkgdir"]]
    # Pin only the submodule: its bytes verify on the later
    # root while the shadowed parent escapes a leaf-only check.
    modules = lock["runner"]["package"]["modules"]
    del modules["matrix_vng_pkg"]
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = tree["root"] + os.pathsep + saved_path
    try:
        message = _assert_setup_failure(runner.check_runner, lock)
        assert "admission refused" in message, message
        assert "shadowed" in message, message
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(tree["root"], ignore_errors=True)


def _write_dep_dist(pkgdir, name, version, files):
    """Stage a fixture distribution; return (metadata, record) digests.

    ``files`` maps root-relative paths (``pkg/__init__.py``) to
    text content, or bytes for binary entries (``.pyc``,
    ``.so``). Writes the package files, the ``.dist-info``
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
        if isinstance(text, bytes):
            with open(path, "wb") as handle:
                handle.write(text)
        else:
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
                runner,
                _typed_source(
                    ["test_fake_case"],
                    prelude=(
                        "import os\n"
                        "print('PATH=' + "
                        "os.environ.get('PATH', ''))\n"
                        "print('PYTHONPATH=' + os.environ.get("
                        "'PYTHONPATH', '<absent>'))"
                    ),
                ),
                120,
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


def test_matrix_propagates_but_never_synthesizes_the_lease():
    # The matrix carries the incoming target lease verbatim to
    # the suite: absent stays absent, "0" stays "0", and only
    # an externally granted "1" arrives leased (here the test
    # process stands in for that external disposable-target
    # approval). The matrix never assigns a lease of its own.
    runner = _load_runner()
    prelude = (
        "import os\n"
        "print('LEASE=' + "
        "os.environ.get('MOJOBPF_TARGET_LEASE', '<absent>'))\n"
    )
    for incoming, want in ((None, "<absent>"), ("0", "0"), ("1", "1")):
        saved = os.environ.pop("MOJOBPF_TARGET_LEASE", None)
        try:
            if incoming is None:
                extra = None
            else:
                extra = {"MOJOBPF_TARGET_LEASE": incoming}
            root, _out, record = _run_fake(
                runner,
                _typed_source(["test_fake_case"], prelude=prelude),
                120,
                extra_env=extra,
            )
        finally:
            if saved is None:
                os.environ.pop("MOJOBPF_TARGET_LEASE", None)
            else:
                os.environ["MOJOBPF_TARGET_LEASE"] = saved
        try:
            assert record["outcome"] == "pass", record
            with open(record["log"], encoding="utf-8") as handle:
                log = handle.read()
            line = next(
                line for line in log.splitlines()
                if line.startswith("LEASE=")
            )
            assert line == "LEASE=" + want, (incoming, line)
        finally:
            shutil.rmtree(root, ignore_errors=True)


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
            # The signed exit survives the timeout (fail-closed,
            # never a silent None): the killed suite reports its
            # signal.
            assert record["exit_code"] is not None, record
            assert record["exit_code"] < 0, record
            assert "timed out" in record["note"], record
            assert record["kill_residue"] == [], record
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
    # Host-only parser bounds (no guest, stubbed bpftool).
    "tests/kernel/test_btf_dualshape_bounds.py": "host-only",
}


def _guest_suite_files():
    """Every guest-backed suite file by directory convention.

    ``tests/kernel/`` boots a guest in every suite except the
    host-only bounds shell;
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
    # Every wired suite needs its pinned case list (and board
    # suites their board case) or the acceptance cannot bind
    # plans to expectations.
    for suite_id in ids:
        assert suite_id in runner.SUITE_CASES, suite_id
        assert runner.SUITE_CASES[suite_id], suite_id
    for suite_id in runner.BOARD_CASES:
        assert suite_id in runner.SUITE_CASES, suite_id
        assert runner.BOARD_CASES[suite_id] in (
            runner.SUITE_CASES[suite_id]
        ), suite_id


def test_typed_fail_verdict_is_fail():
    runner = _load_runner()
    root, _out, record = _run_fake(
        runner, _typed_source(["test_fake_case"], mode="fail"), 120
    )
    try:
        assert record["outcome"] == "fail", record
        assert record["exit_code"] == 1, record
        assert record["verdict"] == "FAIL", record
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_typed_infra_abort_is_envfail():
    runner = _load_runner()
    root, _out, record = _run_fake(
        runner,
        _typed_source(
            ["test_first", "test_second"], mode="infra"
        ),
        120,
        case_ids=["test_first", "test_second"],
    )
    try:
        assert record["outcome"] == "envfail", record
        assert record["exit_code"] == 2, record
        assert record["verdict"] == "INCOMPLETE", record
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_typed_unavailable_is_envfail_exit_3():
    runner = _load_runner()
    root, _out, record = _run_fake(
        runner, _typed_source(["test_fake_case"], mode="notrun"),
        120,
    )
    try:
        assert record["outcome"] == "envfail", record
        assert record["exit_code"] == 3, record
        assert record["verdict"] == "INCOMPLETE", record
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_signal_death_without_timeout_is_fail():
    runner = _load_runner()
    source = (
        "import os, signal\n"
        "print('PASS fake-suite-proof')\n"
        "import sys; sys.stdout.flush()\n"
        "os.kill(os.getpid(), signal.SIGTERM)\n"
    )
    root, _out, record = _run_fake(runner, source, 120)
    try:
        assert record["outcome"] == "fail", record
        assert record["exit_code"] == -signal.SIGTERM, record
        assert record["timed_out"] is False, record
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_unpinned_suite_fails_without_spawning():
    runner = _load_runner()
    root = tempfile.mkdtemp(prefix="mojobpf-matrix-unit-")
    out_dir = os.path.join(root, "out")
    os.makedirs(out_dir)
    with open(
        os.path.join(root, "fake_suite.py"), "w", encoding="utf-8"
    ) as handle:
        handle.write("print('must not run')\n")
    saved_root = runner.REPO_ROOT
    runner.REPO_ROOT = root
    try:
        assert "nope-suite" not in runner.SUITE_CASES
        record = runner.run_suite(
            "nope-suite", "fake_suite.py", _LANE, out_dir,
            120, _FAKE_COMMIT, None,
        )
    finally:
        runner.REPO_ROOT = saved_root
        shutil.rmtree(root, ignore_errors=True)
    assert record["outcome"] == "fail", record
    assert "no pinned case list" in record["note"], record
    assert record["log"] is None, record


def test_accept_honest_documents_passes():
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha", "test_beta"]
    )
    outcome, note, detail = _accept_output(
        runner, ["test_alpha", "test_beta"], plan_doc,
        result_docs, suite_doc, exit_code=0,
    )
    assert outcome == "pass", (outcome, note)
    assert detail["verdict"] == "PASS", detail
    assert detail["run_id"] == "craft-run", detail


def test_accept_missing_terminal_fails():
    runner = _load_runner()
    plan_doc, result_docs, _suite_doc = _craft_documents(
        ["test_alpha"]
    )
    outcome, note, detail = _accept_output(
        runner, ["test_alpha"], plan_doc, result_docs, None,
        exit_code=0,
    )
    assert outcome == "fail", (outcome, note)
    assert "terminal" in note, note
    assert detail["verdict"] == "NO_TERMINAL", detail


def test_accept_missing_plan_fails():
    runner = _load_runner()
    _plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"]
    )
    outcome, note, _detail = _accept_output(
        runner, ["test_alpha"], None, result_docs, suite_doc,
        exit_code=0,
    )
    assert outcome == "fail", (outcome, note)
    assert "run plan" in note, note


def test_accept_missing_results_fails():
    runner = _load_runner()
    plan_doc, _result_docs, suite_doc = _craft_documents(
        ["test_alpha"]
    )
    outcome, note, _detail = _accept_output(
        runner, ["test_alpha"], plan_doc, [], suite_doc,
        exit_code=0,
    )
    assert outcome == "fail", (outcome, note)
    assert "no case results" in note, note


def test_accept_duplicate_terminal_fails():
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"]
    )
    line = "MOJOBPF_SUITE_RESULT " + json.dumps(
        suite_doc, sort_keys=True
    )
    output = (
        "MOJOBPF_RUN_PLAN "
        + json.dumps(plan_doc, sort_keys=True) + "\n"
        + "".join(
            "MOJOBPF_CASE_RESULT "
            + json.dumps(doc, sort_keys=True) + "\n"
            for doc in result_docs
        )
        + line + "\n" + line + "\n"
    )
    manifest = runner.lane_target_manifest(_LANE)
    outcome, note, _detail = runner.accept_suite_output(
        "fake-suite", ["test_alpha"], output, 0, _FAKE_COMMIT,
        manifest, "0" * 64,
    )
    assert outcome == "fail", (outcome, note)
    assert "exactly one terminal" in note, note


def test_accept_truncated_json_fails():
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"]
    )
    text = json.dumps(suite_doc, sort_keys=True)
    output = (
        "MOJOBPF_RUN_PLAN "
        + json.dumps(plan_doc, sort_keys=True) + "\n"
        + "".join(
            "MOJOBPF_CASE_RESULT "
            + json.dumps(doc, sort_keys=True) + "\n"
            for doc in result_docs
        )
        + "MOJOBPF_SUITE_RESULT " + text[: len(text) // 2] + "\n"
    )
    manifest = runner.lane_target_manifest(_LANE)
    outcome, note, _detail = runner.accept_suite_output(
        "fake-suite", ["test_alpha"], output, 0, _FAKE_COMMIT,
        manifest, "0" * 64,
    )
    assert outcome == "fail", (outcome, note)
    assert "malformed terminal" in note, note


def test_accept_deeply_nested_record_fails_suite():
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"]
    )
    deep = "[" * 1000000 + "]" * 1000000
    manifest = runner.lane_target_manifest(_LANE)
    kinds = (
        (
            "MOJOBPF_RUN_PLAN " + deep,
            "MOJOBPF_CASE_RESULT "
            + json.dumps(result_docs[0], sort_keys=True),
            "MOJOBPF_SUITE_RESULT "
            + json.dumps(suite_doc, sort_keys=True),
            "malformed run plan",
        ),
        (
            "MOJOBPF_RUN_PLAN "
            + json.dumps(plan_doc, sort_keys=True),
            "MOJOBPF_CASE_RESULT " + deep,
            "MOJOBPF_SUITE_RESULT "
            + json.dumps(suite_doc, sort_keys=True),
            "malformed case result",
        ),
        (
            "MOJOBPF_RUN_PLAN "
            + json.dumps(plan_doc, sort_keys=True),
            "MOJOBPF_CASE_RESULT "
            + json.dumps(result_docs[0], sort_keys=True),
            "MOJOBPF_SUITE_RESULT " + deep,
            "malformed terminal",
        ),
    )
    for plan_line, result_line, suite_line, needle in kinds:
        output = "\n".join(
            (plan_line, result_line, suite_line)
        ) + "\n"
        outcome, note, _detail = runner.accept_suite_output(
            "fake-suite", ["test_alpha"], output, 0, _FAKE_COMMIT,
            manifest, "0" * 64,
        )
        assert outcome == "fail", (needle, outcome, note)
        assert needle in note, (needle, note)
    print("PASS accept deeply nested record fails suite")


def _deep_value(depth=800):
    value = None
    for _ in range(depth):
        value = [value]
    return value


def test_accept_deeply_nested_behavior_fails_suite():
    # A behavior value deep enough to overflow the
    # recursive comparison (but shallow enough to load)
    # fails the suite instead of crashing the matrix.
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"]
    )
    deep = _deep_value()
    result_docs[0]["expected"]["value"] = deep
    result_docs[0]["observed"]["value"] = deep
    output = "\n".join((
        "MOJOBPF_RUN_PLAN "
        + json.dumps(plan_doc, sort_keys=True),
        "MOJOBPF_CASE_RESULT "
        + json.dumps(result_docs[0], sort_keys=True),
        "MOJOBPF_SUITE_RESULT "
        + json.dumps(suite_doc, sort_keys=True),
    )) + "\n"
    manifest = runner.lane_target_manifest(_LANE)
    outcome, note, _detail = runner.accept_suite_output(
        "fake-suite", ["test_alpha"], output, 0, _FAKE_COMMIT,
        manifest, "0" * 64,
    )
    assert outcome == "fail", (outcome, note)
    assert "too deeply nested" in note, note
    print("PASS accept deeply nested behavior fails suite")


def test_accept_recursion_failure_fails_suite():
    # Routing pin: a RecursionError from any validation
    # step (plan/case/terminal parse, aggregate, verify)
    # fails the suite instead of crashing the matrix.
    # (Only the case site is reachable with crafted
    # documents — see the behavior test above; the rest
    # is defensive routing for direct library use.)
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"]
    )
    patches = (
        (
            validation_mod.RunPlan, "from_dict",
            "run plan too deeply nested",
        ),
        (
            validation_mod.CaseResult, "from_dict",
            "case result #0 too deeply nested",
        ),
        (
            validation_mod.SuiteResult, "from_dict",
            "terminal suite record too deeply nested",
        ),
        (
            validation_mod, "aggregate",
            "aggregation too deeply nested",
        ),
        (
            runner, "verify_suite_result",
            "terminal record too deeply nested",
        ),
    )
    for obj, name, needle in patches:
        real = getattr(obj, name)

        def _boom(*args, **kwargs):
            raise RecursionError("routing probe")

        setattr(obj, name, _boom)
        try:
            outcome, note, _detail = _accept_output(
                runner, ["test_alpha"],
                plan_doc, result_docs, suite_doc,
            )
        finally:
            setattr(obj, name, real)
        assert outcome == "fail", (name, outcome, note)
        assert needle in note, (name, needle, note)
    print("PASS accept recursion failure fails suite")


def test_accept_plan_case_drift_fails():
    runner = _load_runner()
    # Extra plan case the pins do not know.
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha", "test_sneaky"]
    )
    outcome, note, _detail = _accept_output(
        runner, ["test_alpha"], plan_doc, result_docs,
        suite_doc, exit_code=0,
    )
    assert outcome == "fail", (outcome, note)
    assert "test_sneaky" in note, note
    # Missing plan case the pins require.
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"]
    )
    outcome, note, _detail = _accept_output(
        runner, ["test_alpha", "test_missing"], plan_doc,
        result_docs, suite_doc, exit_code=0,
    )
    assert outcome == "fail", (outcome, note)
    assert "test_missing" in note, note


def test_accept_wrong_commit_fails():
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"], commit="b" * 40
    )
    outcome, note, _detail = _accept_output(
        runner, ["test_alpha"], plan_doc, result_docs,
        suite_doc, exit_code=0, commit=_FAKE_COMMIT,
    )
    assert outcome == "fail", (outcome, note)
    assert "revisions" in note, note


def test_accept_wrong_tool_fails():
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"], tool="standalone"
    )
    outcome, note, _detail = _accept_output(
        runner, ["test_alpha"], plan_doc, result_docs,
        suite_doc, exit_code=0,
    )
    assert outcome == "fail", (outcome, note)
    assert "revisions" in note, note


def test_accept_wrong_target_fails():
    runner = _load_runner()
    other_lane = dict(
        _LANE, id="other-lane", release="v9.98",
        kernel_release="9.98-test",
    )
    other_manifest = runner.lane_target_manifest(other_lane)
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"], manifest=other_manifest
    )
    outcome, note, _detail = _accept_output(
        runner, ["test_alpha"], plan_doc, result_docs,
        suite_doc, exit_code=0,
    )
    assert outcome == "fail", (outcome, note)
    assert "target" in note, note


def test_accept_wrong_consumer_fails():
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"]
    )
    outcome, note, _detail = _accept_output(
        runner, ["test_alpha"], plan_doc, result_docs,
        suite_doc, exit_code=0, suite_sha256="f" * 64,
    )
    assert outcome == "fail", (outcome, note)
    assert "consumer" in note, note


def test_accept_duplicate_results_rejected():
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"]
    )
    outcome, note, _detail = _accept_output(
        runner, ["test_alpha"], plan_doc,
        result_docs + result_docs, suite_doc, exit_code=0,
    )
    assert outcome == "fail", (outcome, note)
    # Recomputation spots the duplicate and records a reject the
    # honest suite never listed, so the terminal disagrees.
    assert "rejected_digests" in note, note


def test_accept_broken_attempt_chain_rejected():
    # Attempt 2 without attempt 1: retries must be kept, all of
    # them, or the chain is rejected.
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"], attempts=(2,), expected_attempts=2
    )
    outcome, note, _detail = _accept_output(
        runner, ["test_alpha"], plan_doc, result_docs,
        suite_doc, exit_code=0,
    )
    assert outcome == "fail", (outcome, note)
    # The orphan attempt is rejected AND preserved: rejected
    # attempts stay in the transcript, never silently dropped.
    assert "rejected attempt" in note, note


def test_accept_attempts_kept_pass():
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"], attempts=(1, 2), expected_attempts=2
    )
    outcome, note, detail = _accept_output(
        runner, ["test_alpha"], plan_doc, result_docs,
        suite_doc, exit_code=0,
    )
    assert outcome == "pass", (outcome, note)
    assert detail["verdict"] == "PASS", detail

    def fail_first(plan, results):
        doc = results[0].to_dict()
        doc["observed"] = {"outcome": "FAIL", "failure_stage": "RUNTIME"}
        doc["outcome"] = "FAIL"
        doc["failure_stage"] = "RUNTIME"
        results[0] = validation_mod.CaseResult.from_dict(doc)

    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"], attempts=(1, 2), expected_attempts=2,
        mutate=fail_first,
    )
    outcome, note, detail = _accept_output(
        runner, ["test_alpha"], plan_doc, result_docs,
        suite_doc, exit_code=0,
    )
    # A failed first attempt kept alongside the passing retry
    # still passes: the retry history is preserved, not hidden.
    assert outcome == "pass", (outcome, note)
    assert detail["verdict"] == "PASS", detail


def test_accept_forged_terminal_rejected():
    runner = _load_runner()

    def forge(_plan_doc, _result_docs, suite_doc):
        suite_doc["result_digests"] = ["0" * 64]

    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"], remangle=forge
    )
    outcome, note, _detail = _accept_output(
        runner, ["test_alpha"], plan_doc, result_docs,
        suite_doc, exit_code=0,
    )
    assert outcome == "fail", (outcome, note)
    assert "disagrees with recomputation" in note, note


def test_accept_noop_empty_sources_rejected():
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"], source_sha=runner.EMPTY_SHA256
    )
    outcome, note, _detail = _accept_output(
        runner, ["test_alpha"], plan_doc, result_docs,
        suite_doc, exit_code=0,
    )
    assert outcome == "fail", (outcome, note)
    assert "no-op workload" in note, note


def test_accept_noop_missing_inputs_rejected():
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"], object_sha="0" * 64
    )
    outcome, note, _detail = _accept_output(
        runner, ["test_alpha"], plan_doc, result_docs,
        suite_doc, exit_code=0,
    )
    assert outcome == "fail", (outcome, note)
    assert "no-op workload" in note, note


def test_accept_noop_zero_evidence_rejected():
    runner = _load_runner()

    def strip_evidence(plan, results):
        doc = results[0].to_dict()
        doc["evidence"] = [{
            "path": "suite:fake_suite.py",
            "sha256": "44" * 32,
            "bytes": 0,
        }]
        results[0] = validation_mod.CaseResult.from_dict(doc)

    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"], mutate=strip_evidence
    )
    outcome, note, _detail = _accept_output(
        runner, ["test_alpha"], plan_doc, result_docs,
        suite_doc, exit_code=0,
    )
    assert outcome == "fail", (outcome, note)
    assert "no-op workload" in note, note


def test_accept_board_without_sources_passes():
    # Board cases verify the transcript itself (evidence-bound);
    # the matrix exempts its known board case from the sources
    # rule instead of letting suites self-exempt.
    runner = _load_runner()
    saved_boards = dict(runner.BOARD_CASES)
    runner.BOARD_CASES["fake-suite"] = "board"
    try:
        plan_doc, result_docs, suite_doc = _craft_documents(
            ["board"], source_sha=runner.EMPTY_SHA256
        )
        outcome, note, detail = _accept_output(
            runner, ["board"], plan_doc, result_docs,
            suite_doc, exit_code=0,
        )
    finally:
        runner.BOARD_CASES.clear()
        runner.BOARD_CASES.update(saved_boards)
    assert outcome == "pass", (outcome, note)
    assert detail["verdict"] == "PASS", detail


def _craft_not_run(case_ids):
    def skip_all(plan, results):
        for index, result in enumerate(results):
            doc = result.to_dict()
            doc["applicability"] = "TARGET_RESOURCE_ABSENT"
            doc["observed"] = {
                "outcome": "NOT_RUN", "failure_stage": "INFRA"
            }
            doc["outcome"] = "NOT_RUN"
            doc["failure_stage"] = "INFRA"
            doc["cleanup"] = {"status": "NOT_CHECKED", "residue": []}
            results[index] = validation_mod.CaseResult.from_dict(doc)

    return _craft_documents(case_ids, mutate=skip_all)


def _craft_fail(case_ids):
    def fail_all(plan, results):
        for index, result in enumerate(results):
            doc = result.to_dict()
            doc["observed"] = {
                "outcome": "FAIL", "failure_stage": "RUNTIME"
            }
            doc["outcome"] = "FAIL"
            doc["failure_stage"] = "RUNTIME"
            results[index] = validation_mod.CaseResult.from_dict(doc)

    return _craft_documents(case_ids, mutate=fail_all)


def test_accept_exit_disagreement_fails():
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_documents(
        ["test_alpha"]
    )
    outcome, note, detail = _accept_output(
        runner, ["test_alpha"], plan_doc, result_docs,
        suite_doc, exit_code=1,
    )
    assert outcome == "fail", (outcome, note)
    assert "disagrees" in note, note
    assert detail["verdict"] == "PASS", detail
    plan_doc, result_docs, suite_doc = _craft_not_run(
        ["test_alpha"]
    )
    outcome, note, detail = _accept_output(
        runner, ["test_alpha"], plan_doc, result_docs,
        suite_doc, exit_code=0,
    )
    assert outcome == "fail", (outcome, note)
    assert "disagrees" in note, note
    assert detail["verdict"] == "INCOMPLETE", detail


def test_accept_fail_verdict_with_any_exit_is_fail():
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_fail(["test_alpha"])
    for exit_code in (1, 2, 0, -9):
        outcome, note, detail = _accept_output(
            runner, ["test_alpha"], plan_doc, result_docs,
            suite_doc, exit_code=exit_code,
        )
        assert outcome == "fail", (exit_code, outcome, note)
        assert detail["verdict"] == "FAIL", detail


def test_accept_incomplete_env_exit_is_envfail():
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_not_run(
        ["test_alpha"]
    )
    for exit_code in (2, 3):
        outcome, note, detail = _accept_output(
            runner, ["test_alpha"], plan_doc, result_docs,
            suite_doc, exit_code=exit_code,
        )
        assert outcome == "envfail", (exit_code, outcome, note)
        assert detail["verdict"] == "INCOMPLETE", detail


def test_lane_target_manifest_shape():
    runner = _load_runner()
    manifest = runner.lane_target_manifest(_LANE)
    target = validation_mod.TargetManifest.from_dict(manifest)
    assert target.data["kernel"]["release"] == "9.99-test", manifest
    assert manifest["image"]["digest"] == "vng:v9.99:tcg", manifest
    assert manifest["cpu"]["architecture"] == "x86-64", manifest
    assert manifest["execution_mode"] == "tcg", manifest
    assert manifest["fingerprint"] == target.fingerprint
    kvm_lane = dict(_LANE, accelerator="kvm")
    kvm_lane["id"] = "kvm-lane"
    assert runner.lane_target_manifest(kvm_lane)[
        "execution_mode"] == "hardware-vm"
    message = _assert_setup_failure(
        runner.lane_target_manifest, dict(_LANE, arch="arm64")
    )
    assert "x86-64 lanes only" in message, message
    message = _assert_setup_failure(
        runner.lane_target_manifest,
        dict(_LANE, accelerator="bogus"),
    )
    assert "execution mode" in message, message


def test_load_lock_lanes_all_manifest():
    # Lock loading does not gate arch/accelerator (the manifest
    # call does, above): every committed-lock lane must still
    # produce a manifest, so a lock edit that breaks the target
    # recording fails here instead of at matrix run time.
    runner = _load_runner()
    lock = runner.load_lock(
        os.path.join(REPO_ROOT, "ci", "kernels.lock.json")
    )
    assert lock["lanes"], lock
    for lane in lock["lanes"]:
        manifest = runner.lane_target_manifest(lane)
        assert manifest["kernel"]["release"], lane
        assert manifest["fingerprint"], lane


def _suite_case_names(relpath):
    """Read a suite's case names: CASE_NAMES or sorted test_*."""
    with open(
        os.path.join(REPO_ROOT, relpath), encoding="utf-8"
    ) as handle:
        tree = ast.parse(handle.read())
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "CASE_NAMES"
            and isinstance(node.value, (ast.Tuple, ast.List))
        ):
            return sorted(
                element.value
                for element in node.value.elts
                if isinstance(element, ast.Constant)
            )
    return sorted(
        node.name for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name.startswith("test_")
    )


def test_accept_optional_weakening_rejected():
    # A resealed plan that narrows a mandatory case to optional
    # (reported NOT_RUN) must fail, never pass without it.
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_mixed_documents([
        {"case_id": "test_mandatory"},
        {"case_id": "test_weakened", "required": False,
         "observed": ("NOT_RUN", "INFRA"),
         "applicability": "TARGET_RESOURCE_ABSENT"},
    ])
    outcome, note, _detail = _accept_output(
        runner, ["test_mandatory", "test_weakened"],
        plan_doc, result_docs, suite_doc, exit_code=0,
        expected_denials={},
    )
    assert outcome == "fail", (outcome, note)
    assert "weakens coverage" in note, note


def test_accept_denial_to_positive_flip_rejected():
    # A resealed plan that flips a pinned denial to a positive
    # expectation (with a matching PASS record) must fail.
    runner = _load_runner()
    plan_doc, result_docs, suite_doc = _craft_mixed_documents([
        {"case_id": "test_guarded"},
        {"case_id": "test_denial", "expectation": "positive",
         "observed": ("PASS", None)},
    ])
    outcome, note, _detail = _accept_output(
        runner, ["test_guarded", "test_denial"],
        plan_doc, result_docs, suite_doc, exit_code=0,
        expected_denials={"test_denial": ("test_guarded", "VERIFY")},
    )
    assert outcome == "fail", (outcome, note)
    assert "obligation drift" in note, note


def test_accept_satisfied_denial_needs_workload():
    # A counted denial over missing inputs with zero-byte
    # evidence proves nothing and must fail the no-op rule.
    runner = _load_runner()
    zero = "0" * 64
    plan_doc, result_docs, suite_doc = _craft_mixed_documents([
        {"case_id": "test_guarded"},
        {"case_id": "test_denial", "expectation": "denial",
         "denies": "test_guarded", "stage": "VERIFY",
         "observed": ("FAIL", "VERIFY"),
         "source_sha": zero, "object_sha": zero,
         "corpus_sha": zero,
         "evidence": [{
             "path": "transcript:ghost",
             "sha256": "55" * 32,
             "bytes": 0,
         }]},
    ])
    outcome, note, _detail = _accept_output(
        runner, ["test_guarded", "test_denial"],
        plan_doc, result_docs, suite_doc, exit_code=0,
        expected_denials={"test_denial": ("test_guarded", "VERIFY")},
    )
    assert outcome == "fail", (outcome, note)
    assert "no-op workload" in note, note


def _lock_releases():
    with open(
        os.path.join(REPO_ROOT, "ci", "kernels.lock.json"),
        encoding="utf-8",
    ) as handle:
        lock = json.load(handle)
    return sorted({lane["release"] for lane in lock["lanes"]})


def _effective_suite_denials(relpath, release):
    """Import the suite file fresh with VNG_RELEASE=release.

    Returns the effective CASE_DENIALS for that release,
    honoring any release-conditional entries the suite
    computes at import.
    """
    prev = os.environ.get("MOJOBPF_VNG_RELEASE")
    os.environ["MOJOBPF_VNG_RELEASE"] = release
    try:
        spec = importlib.util.spec_from_file_location(
            "suite_denials_probe",
            os.path.join(REPO_ROOT, relpath),
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return dict(module.CASE_DENIALS)
    finally:
        if prev is None:
            del os.environ["MOJOBPF_VNG_RELEASE"]
        else:
            os.environ["MOJOBPF_VNG_RELEASE"] = prev


def test_suite_denial_pins_sync():
    # The matrix denial pins are the independent expectation:
    # they must equal each suite's CASE_DENIALS, so changing a
    # suite's obligations without updating the pin fails loudly
    # instead of silently redefining the verdict. Suites with
    # lane-scoped overrides pin a different effective map per
    # release; those are validated per locked release instead
    # of against the static literal.
    runner = _load_runner()
    by_id = {
        suite_id: relpath
        for suite_id, relpath, _timeout in runner.SUITES
    }
    assert set(by_id) == set(runner.SUITE_DENIALS), (
        sorted(set(by_id) ^ set(runner.SUITE_DENIALS))
    )
    releases = _lock_releases()
    assert releases, "kernels lock lists no releases"
    override_suites = set()
    for suite_id, release in runner.SUITE_DENIAL_OVERRIDES:
        assert suite_id in by_id, (suite_id, "orphan override")
        assert release in releases, (suite_id, release)
        override_suites.add(suite_id)
    for suite_id, relpath in sorted(by_id.items()):
        if suite_id in override_suites:
            for release in releases:
                effective = _effective_suite_denials(
                    relpath, release
                )
                want = runner.SUITE_DENIAL_OVERRIDES.get(
                    (suite_id, release),
                    runner.SUITE_DENIALS[suite_id],
                )
                assert want == effective, (suite_id, release)
                for denial, (denies, _stage) in effective.items():
                    assert denial in runner.SUITE_CASES[suite_id], (
                        suite_id, release, denial,
                    )
                    assert denies in runner.SUITE_CASES[suite_id], (
                        suite_id, release, denies,
                    )
            continue
        with open(
            os.path.join(REPO_ROOT, relpath), encoding="utf-8"
        ) as handle:
            tree = ast.parse(handle.read())
        found = None
        for node in tree.body:
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "CASE_DENIALS"
            ):
                found = ast.literal_eval(node.value)
        assert found is not None, (suite_id, "no CASE_DENIALS")
        assert runner.SUITE_DENIALS[suite_id] == found, suite_id
        for denial, (denies, _stage) in found.items():
            assert denial in runner.SUITE_CASES[suite_id], (
                suite_id, denial,
            )
            assert denies in runner.SUITE_CASES[suite_id], (
                suite_id, denies,
            )


def test_suite_case_pins_sync():
    # The matrix pins are the independent expectation: they must
    # equal each suite's own case list (plus the matrix-known
    # board case), so adding a test without updating the pin
    # fails loudly instead of silently narrowing the plan.
    runner = _load_runner()
    by_id = {
        suite_id: relpath
        for suite_id, relpath, _timeout in runner.SUITES
    }
    assert set(by_id) == set(runner.SUITE_CASES), (
        sorted(set(by_id) ^ set(runner.SUITE_CASES))
    )
    for suite_id, relpath in sorted(by_id.items()):
        names = _suite_case_names(relpath)
        board = runner.BOARD_CASES.get(suite_id)
        if board is not None:
            names = names + [board]
        assert sorted(runner.SUITE_CASES[suite_id]) == sorted(
            names
        ), suite_id
    # Explicit-loop suites must keep their list at module level
    # where this sync (and reviewers) can see it.
    for relpath in (
        "tests/kernel/test_tracing_lifecycle.py",
        "tests/verifier/test_helper_licenses.py",
        "tests/kernel/test_tracepoint_counter.py",
    ):
        with open(
            os.path.join(REPO_ROOT, relpath), encoding="utf-8"
        ) as handle:
            tree = ast.parse(handle.read())
        assert any(
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "CASE_NAMES"
            for node in tree.body
        ), relpath


def _shard_report(lane_id, commit="abc123", outcomes=(("s1", "pass"),),
                  digest="d" * 64):
    return {
        "tool": "run_vm_tests",
        "commit": commit,
        "python": {
            "executable": "/usr/bin/python3",
            "version": "3.14.8",
        },
        "consumer_path": [],
        "runner": {
            "version": "virtme-ng 1.41",
            "realpath": "/usr/bin/vng",
            "digest": digest,
        },
        "lanes": [
            {
                "id": lane_id,
                "release": "vX",
                "accelerator": "kvm",
                "kernel_release": "1.0-test",
                "cache": {},
            }
        ],
        "results": [
            {
                "lane": lane_id,
                "suite": name,
                "commit": commit,
                "outcome": outcome,
                "exit_code": 0,
                "verdict": (
                    "PASS" if outcome == "pass" else "FAIL"
                ),
                "passes": 1,
                "failures": 0,
                "envfailures": 0,
                "elapsed_secs": 1.0,
            }
            for name, outcome in outcomes
        ],
        "elapsed_secs": 1.0,
    }


def _write_report(workdir, name, report):
    path = os.path.join(workdir, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle)
    return path


def _full_outcomes(runner, failed=(), skip=()):
    # One passing outcome per matrix suite: only full-lane
    # shards merge, so accept-path fixtures cover SUITES.
    return tuple(
        (suite_id, "fail" if suite_id in failed else "pass")
        for suite_id, _, _ in runner.SUITES
        if suite_id not in skip
    )


def test_merge_shards_combines_lanes_and_results():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json",
            _shard_report("lane-a", outcomes=_full_outcomes(runner)),
        )
        second = os.path.join(workdir, "b.json")
        with open(second, "w", encoding="utf-8") as handle:
            json.dump(
                _shard_report(
                    "lane-b", outcomes=_full_outcomes(runner),
                ),
                handle,
            )
        out = os.path.join(workdir, "merged")
        assert runner.main(
            ["--merge", first, second, "--out-dir", out]
        ) == 0
        with open(
            os.path.join(out, "matrix-report.json"), encoding="utf-8"
        ) as handle:
            merged = json.load(handle)
        assert merged["tool"] == "run_vm_tests"
        assert merged["commit"] == "abc123"
        assert [lane["id"] for lane in merged["lanes"]] == [
            "lane-a", "lane-b",
        ]
        assert len(merged["results"]) == 2 * len(runner.SUITES)
        assert merged["merged_from"] == [first, second]
        print("PASS merge combines shards")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_shard_failure_fails_merged():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json",
            _shard_report("lane-a", outcomes=_full_outcomes(runner)),
        )
        failed_id = runner.SUITES[0][0]
        second = _write_report(
            workdir, "b.json",
            _shard_report(
                "lane-b",
                outcomes=_full_outcomes(runner, failed=(failed_id,)),
            ),
        )
        out = os.path.join(workdir, "merged")
        assert runner.main(
            ["--merge", first, second, "--out-dir", out]
        ) == 1
        assert os.path.isfile(
            os.path.join(out, "matrix-report.json")
        )
        print("PASS merge failure fails merged")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_records_non_pass_outcome_vocabulary():
    # The producer vocabulary beyond pass/fail merges:
    # timeout and envfail outcomes (and any other
    # non-empty outcome string) fail the merge (exit 1)
    # and are recorded verbatim, never refused and never
    # a pass.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        suite_ids = [suite_id for suite_id, _, _ in runner.SUITES]
        assert len(suite_ids) >= 3, suite_ids
        outcomes = tuple(
            (suite_id, outcome)
            for suite_id, outcome in zip(
                suite_ids,
                ["timeout", "envfail", "bogus"] + ["pass"] * len(
                    suite_ids
                ),
            )
        )
        first = _write_report(
            workdir, "a.json",
            _shard_report("lane-a", outcomes=outcomes),
        )
        second = _write_report(
            workdir, "b.json",
            _shard_report(
                "lane-b", outcomes=_full_outcomes(runner)
            ),
        )
        out = os.path.join(workdir, "merged")
        assert runner.main(
            ["--merge", first, second, "--out-dir", out]
        ) == 1
        with open(
            os.path.join(out, "matrix-report.json"),
            encoding="utf-8",
        ) as handle:
            merged = json.load(handle)
        seen = {
            (item["suite"], item["outcome"])
            for item in merged["results"]
            if item["lane"] == "lane-a"
        }
        assert (suite_ids[0], "timeout") in seen, seen
        assert (suite_ids[1], "envfail") in seen, seen
        assert (suite_ids[2], "bogus") in seen, seen
        print("PASS merge records non-pass outcome vocabulary")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_commit_mismatch():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json", _shard_report("lane-a", commit="aaa")
        )
        second = _write_report(
            workdir, "b.json", _shard_report("lane-b", commit="bbb")
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out],
            out,
        )
        assert "disagrees on 'commit'" in message, message
        print("PASS merge refuses commit mismatch")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_lane_overlap():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json", _shard_report("lane-a")
        )
        second = _write_report(
            workdir, "b.json", _shard_report("lane-a")
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out],
            out,
        )
        assert "covered more than once" in message, message
        print("PASS merge refuses lane overlap")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_runner_mismatch():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json",
            _shard_report(
                "lane-a", outcomes=_full_outcomes(runner),
                digest="d" * 64,
            ),
        )
        second = _write_report(
            workdir, "b.json",
            _shard_report(
                "lane-b", outcomes=_full_outcomes(runner),
                digest="e" * 64,
            ),
        )
        out = os.path.join(workdir, "merged")
        assert runner.main(
            ["--merge", first, second, "--out-dir", out]
        ) == 2
        print("PASS merge refuses runner mismatch")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_accepts_distinct_farm_paths():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first_report = _shard_report(
            "lane-a", outcomes=_full_outcomes(runner)
        )
        first_report["runner"]["farm"] = "/tmp/mojobpf-farm-aaaa"
        second_report = _shard_report(
            "lane-b", outcomes=_full_outcomes(runner)
        )
        second_report["runner"]["farm"] = "/tmp/mojobpf-farm-bbbb"
        first = _write_report(workdir, "a.json", first_report)
        second = _write_report(workdir, "b.json", second_report)
        out = os.path.join(workdir, "merged")
        assert runner.main(
            ["--merge", first, second, "--out-dir", out]
        ) == 0
        print("PASS merge accepts distinct farm paths")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_scrubs_ephemeral_farm_from_board():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first_report = _shard_report(
            "lane-a", outcomes=_full_outcomes(runner)
        )
        first_report["runner"]["farm"] = "/tmp/mojobpf-farm-aaaa"
        second_report = _shard_report(
            "lane-b", outcomes=_full_outcomes(runner)
        )
        second_report["runner"]["farm"] = "/tmp/mojobpf-farm-bbbb"
        first = _write_report(workdir, "a.json", first_report)
        second = _write_report(workdir, "b.json", second_report)
        out = os.path.join(workdir, "merged")
        assert runner.main(
            ["--merge", first, second, "--out-dir", out]
        ) == 0
        with open(
            os.path.join(out, "matrix-report.json"), encoding="utf-8"
        ) as handle:
            merged = json.load(handle)
        assert "farm" not in merged["runner"], merged["runner"]
        print("PASS merge scrubs farm from board")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_farm_plus_digest_mismatch_still_refuses():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first_report = _shard_report(
            "lane-a", outcomes=_full_outcomes(runner),
            digest="d" * 64,
        )
        first_report["runner"]["farm"] = "/tmp/mojobpf-farm-aaaa"
        second_report = _shard_report(
            "lane-b", outcomes=_full_outcomes(runner),
            digest="e" * 64,
        )
        second_report["runner"]["farm"] = "/tmp/mojobpf-farm-bbbb"
        first = _write_report(workdir, "a.json", first_report)
        second = _write_report(workdir, "b.json", second_report)
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out],
            out,
        )
        assert "disagrees on 'runner'" in message, message
        print("PASS merge farm+digest mismatch refuses")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_cell_from_foreign_lane():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        # Swap one cell between shards: pairs stay unique and
        # per-lane coverage stays full, so only the
        # cell-membership check can refuse.
        first_report = _shard_report(
            "lane-a", outcomes=_full_outcomes(runner)
        )
        second_report = _shard_report(
            "lane-b", outcomes=_full_outcomes(runner)
        )
        first_report["results"][0]["lane"] = "lane-b"
        second_report["results"][0]["lane"] = "lane-a"
        first = _write_report(workdir, "a.json", first_report)
        second = _write_report(workdir, "b.json", second_report)
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out],
            out,
        )
        assert "outside its own lanes" in message, message
        print("PASS merge refuses foreign-lane cell")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_cell_commit_mismatch():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first_report = _shard_report(
            "lane-a", outcomes=_full_outcomes(runner)
        )
        first_report["results"][0]["commit"] = "zzz999"
        first = _write_report(workdir, "a.json", first_report)
        second = _write_report(
            workdir, "b.json",
            _shard_report(
                "lane-b", outcomes=_full_outcomes(runner)
            ),
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out],
            out,
        )
        assert "not the shard commit" in message, message
        print("PASS merge refuses cell commit mismatch")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_pass_with_bad_exit_or_verdict():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        for field, bad in (
            ("exit_code", 1), ("verdict", "FAIL"),
        ):
            first_report = _shard_report(
                "lane-a", outcomes=_full_outcomes(runner)
            )
            first_report["results"][0][field] = bad
            first = _write_report(workdir, "a.json", first_report)
            second = _write_report(
                workdir, "b.json",
                _shard_report(
                    "lane-b", outcomes=_full_outcomes(runner)
                ),
            )
            out = os.path.join(workdir, "merged")
            message = _merge_rejection_text(
                runner, ["--merge", first, second, "--out-dir", out],
                out,
            )
            assert "claims pass with" in message, (
                field, message,
            )
        print("PASS merge refuses incoherent pass cells")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_malformed_lane_without_traceback():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        bad_report = _shard_report(
            "lane-a", outcomes=_full_outcomes(runner)
        )
        bad_report["lanes"].append(
            {
                "id": None,
                "release": "vX",
                "accelerator": "kvm",
                "kernel_release": "9.9-test",
                "cache": {},
            }
        )
        first = _write_report(workdir, "a.json", bad_report)
        second = _write_report(
            workdir, "b.json",
            _shard_report(
                "lane-b", outcomes=_full_outcomes(runner)
            ),
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out],
            out,
        )
        assert "malformed lanes" in message, message
        assert "Traceback" not in message, message
        print("PASS merge refuses malformed lane cleanly")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _merge_rejection_text(runner, args, out_dir, must_not_exist=True):
    """Run a merge expecting refusal; return its stderr text.

    Pins the refusal contract: exit 2, exactly one stderr
    line (no traceback, no blank padding) carrying the tool
    prefix, and no emitted board directory (refused merges
    leave no trace, barring cleanup failure). Pass
    must_not_exist=False when the out path pre-exists (e.g.
    out_dir-is-a-file): the refusal shape is still pinned,
    but there is nothing to not-emit.
    """
    import io
    from contextlib import redirect_stderr

    buffer = io.StringIO()
    with redirect_stderr(buffer):
        code = runner.main(args)
    assert code == 2, code
    message = buffer.getvalue()
    assert message.startswith("run_vm_tests:"), message
    assert message.count("\n") == 1, message
    assert message.endswith("\n"), message
    if must_not_exist:
        assert not os.path.exists(out_dir), out_dir
    return message


def test_merge_refuses_malformed_result_values():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        for field, bad in (
            ("lane", ["lane-a"]),
            ("suite", ["s1"]),
            ("lane", None),
            ("suite", None),
            ("lane", 7),
            ("suite", 7),
            ("lane", ""),
            ("suite", ""),
            ("outcome", ["pass"]),
            ("outcome", 7),
            ("outcome", ""),
        ):
            bad_report = _shard_report(
                "lane-a", outcomes=_full_outcomes(runner)
            )
            bad_report["results"][0][field] = bad
            first = _write_report(
                workdir, "a.json", bad_report
            )
            second = _write_report(
                workdir, "b.json",
                _shard_report(
                    "lane-b", outcomes=_full_outcomes(runner)
                ),
            )
            out = os.path.join(workdir, "merged")
            message = _merge_rejection_text(
                runner, ["--merge", first, second,
                         "--out-dir", out],
                out,
            )
            assert "malformed results" in message, (
                field, bad, message,
            )
        for missing in ("lane", "suite", "outcome"):
            missing_report = _shard_report(
                "lane-a", outcomes=_full_outcomes(runner)
            )
            del missing_report["results"][0][missing]
            first = _write_report(
                workdir, "c.json", missing_report
            )
            second = _write_report(
                workdir, "d.json",
                _shard_report(
                    "lane-b", outcomes=_full_outcomes(runner)
                ),
            )
            out = os.path.join(workdir, "merged")
            message = _merge_rejection_text(
                runner, ["--merge", first, second,
                         "--out-dir", out],
                out,
            )
            assert "malformed results" in message, (
                missing, message,
            )
        print("PASS merge refuses malformed result values")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_direct_run_records_skip():
    if not _skip_exceptions():
        raise _DirectSkip("direct-run skip probe needs pytest")
    import pytest

    marker = "direct_skip_probe_for_direct_one"

    def _raiser():
        pytest.skip("probe")

    globals()[marker] = _raiser
    try:
        assert _direct_one(marker) == "skip"
    finally:
        del globals()[marker]
    print("PASS direct run records skip")


def test_direct_one_records_direct_skip():
    marker = "direct_directskip_probe_for_direct_one"

    def _raiser():
        raise _DirectSkip("probe")

    globals()[marker] = _raiser
    try:
        assert _direct_one(marker) == "skip"
    finally:
        del globals()[marker]
    print("PASS direct run records direct skip")


def test_direct_one_propagates_abort():
    if not _skip_exceptions():
        raise _DirectSkip("abort-propagation probe needs pytest")
    import pytest

    for signal in (KeyboardInterrupt(), SystemExit(3)):
        marker = "direct_abort_probe_for_direct_one"

        def _raiser(_signal=signal):
            raise _signal

        globals()[marker] = _raiser
        try:
            with pytest.raises(type(signal)):
                _direct_one(marker)
        finally:
            del globals()[marker]
    print("PASS direct run propagates abort")


def test_merge_refuses_malformed_elapsed_secs():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        for bad in ("junk", None, True, float("nan"),
                    float("inf"), 10 ** 1000, -5.0):
            bad_report = _shard_report(
                "lane-a", outcomes=_full_outcomes(runner)
            )
            bad_report["elapsed_secs"] = bad
            first = _write_report(
                workdir, "a.json", bad_report
            )
            second = _write_report(
                workdir, "b.json",
                _shard_report(
                    "lane-b", outcomes=_full_outcomes(runner)
                ),
            )
            out = os.path.join(workdir, "merged")
            message = _merge_rejection_text(
                runner, ["--merge", first, second,
                         "--out-dir", out],
                out,
            )
            assert "malformed elapsed_secs" in message, (
                bad, message,
            )
        missing_report = _shard_report(
            "lane-a", outcomes=_full_outcomes(runner)
        )
        del missing_report["elapsed_secs"]
        first = _write_report(workdir, "c.json", missing_report)
        second = _write_report(
            workdir, "d.json",
            _shard_report(
                "lane-b", outcomes=_full_outcomes(runner)
            ),
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out],
            out,
        )
        assert "malformed elapsed_secs" in message, message
        print("PASS merge refuses malformed elapsed_secs")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_elapsed_sum_overflow():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first_report = _shard_report(
            "lane-a", outcomes=_full_outcomes(runner)
        )
        first_report["elapsed_secs"] = 1e308
        second_report = _shard_report(
            "lane-b", outcomes=_full_outcomes(runner)
        )
        second_report["elapsed_secs"] = 1e308
        first = _write_report(workdir, "a.json", first_report)
        second = _write_report(workdir, "b.json", second_report)
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out],
            out,
        )
        assert "overflowed" in message, message
        print("PASS merge refuses elapsed sum overflow")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_default_out_dir_refusal_cleans_up():
    # A refused merge without --out-dir leaves no trace: the
    # default mkdtemp dir is removed on the refusal path
    # (barring cleanup failure, pinned separately).
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    created = []
    real_mkdtemp = tempfile.mkdtemp

    def _captive_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, dir=workdir, **kwargs)
        created.append(path)
        return path

    tempfile.mkdtemp = _captive_mkdtemp
    try:
        first = _write_report(
            workdir, "a.json", _shard_report("lane-a", commit="aaa")
        )
        second = _write_report(
            workdir, "b.json", _shard_report("lane-b", commit="bbb")
        )
        import io
        from contextlib import redirect_stderr

        buffer = io.StringIO()
        with redirect_stderr(buffer):
            code = runner.main(["--merge", first, second])
        assert code == 2, code
        message = buffer.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "disagrees on 'commit'" in message, message
        assert len(created) == 1, created
        assert not os.path.exists(created[0]), created
        print("PASS merge default out-dir refusal cleans up")
    finally:
        tempfile.mkdtemp = real_mkdtemp
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_default_out_dir_success_keeps_board():
    # The success path keeps the default board: cleanup runs
    # on refusal only, never on a merged board.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    created = []
    real_mkdtemp = tempfile.mkdtemp

    def _captive_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, dir=workdir, **kwargs)
        created.append(path)
        return path

    tempfile.mkdtemp = _captive_mkdtemp
    try:
        first = _write_report(
            workdir, "a.json",
            _shard_report(
                "lane-a", outcomes=_full_outcomes(runner)
            ),
        )
        second = _write_report(
            workdir, "b.json",
            _shard_report(
                "lane-b", outcomes=_full_outcomes(runner)
            ),
        )
        assert runner.main(["--merge", first, second]) == 0
        assert len(created) == 1, created
        assert os.path.isfile(
            os.path.join(created[0], "matrix-report.json")
        ), created
        print("PASS merge default out-dir success keeps board")
    finally:
        tempfile.mkdtemp = real_mkdtemp
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_out_dir_is_a_file():
    # An out path that exists as a file refuses (exit 2,
    # single line) instead of an uncaught traceback; the
    # file itself is untouched.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json",
            _shard_report(
                "lane-a", outcomes=_full_outcomes(runner)
            ),
        )
        second = _write_report(
            workdir, "b.json",
            _shard_report(
                "lane-b", outcomes=_full_outcomes(runner)
            ),
        )
        out = os.path.join(workdir, "merged")
        with open(out, "w", encoding="utf-8") as handle:
            handle.write("not a dir\n")
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out],
            out, must_not_exist=False,
        )
        assert "cannot create out dir" in message, message
        assert os.path.isfile(out), out
        print("PASS merge refuses out-dir-is-a-file")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_undumpable_board():
    # A board that loads but cannot be serialized (deep
    # nesting past the dump limit) refuses (exit 2,
    # single line) instead of an uncaught traceback.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        report = _shard_report(
            "lane-a", outcomes=_full_outcomes(runner)
        )
        report["lanes"][0]["cache"] = "CACHE_MARKER"
        first = os.path.join(workdir, "a.json")
        with open(first, "w", encoding="utf-8") as handle:
            handle.write(
                json.dumps(report).replace(
                    '"CACHE_MARKER"',
                    "[" * 10000 + "]" * 10000,
                    1,
                )
            )
        second = _write_report(
            workdir, "b.json",
            _shard_report(
                "lane-b", outcomes=_full_outcomes(runner)
            ),
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out],
            out, must_not_exist=False,
        )
        assert "cannot write report" in message, message
        assert not os.path.isfile(
            os.path.join(out, "matrix-report.json")
        ), out
        print("PASS merge refuses undumpable board")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_unwritable_report():
    # A validated merge whose board cannot be written
    # refuses (exit 2, single line) instead of an uncaught
    # traceback; no board file appears.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json",
            _shard_report(
                "lane-a", outcomes=_full_outcomes(runner)
            ),
        )
        second = _write_report(
            workdir, "b.json",
            _shard_report(
                "lane-b", outcomes=_full_outcomes(runner)
            ),
        )
        out = os.path.join(workdir, "merged")
        os.makedirs(os.path.join(out, "matrix-report.json"))
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out],
            out, must_not_exist=False,
        )
        assert "cannot write report" in message, message
        assert not os.path.isfile(
            os.path.join(out, "matrix-report.json")
        ), out
        assert os.path.isdir(out), out
        print("PASS merge refuses unwritable report")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_default_out_dir_write_failure_cleans_up():
    # A default out dir whose board cannot be written is
    # removed on the refusal path, like any other refusal.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    created = []
    real_mkdtemp = tempfile.mkdtemp

    def _captive_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, dir=workdir, **kwargs)
        os.makedirs(os.path.join(path, "matrix-report.json"))
        created.append(path)
        return path

    tempfile.mkdtemp = _captive_mkdtemp
    try:
        first = _write_report(
            workdir, "a.json",
            _shard_report(
                "lane-a", outcomes=_full_outcomes(runner)
            ),
        )
        second = _write_report(
            workdir, "b.json",
            _shard_report(
                "lane-b", outcomes=_full_outcomes(runner)
            ),
        )
        import io
        from contextlib import redirect_stderr

        buffer = io.StringIO()
        with redirect_stderr(buffer):
            code = runner.main(["--merge", first, second])
        assert code == 2, code
        message = buffer.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "cannot write report" in message, message
        assert len(created) == 1, created
        assert not os.path.exists(created[0]), created
        print("PASS merge default out-dir write failure cleans up")
    finally:
        tempfile.mkdtemp = real_mkdtemp
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_default_out_dir_failure_keeps_board():
    # The third default-dir outcome: a failed board (exit 1)
    # keeps its dir — cleanup runs on refusal only.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    created = []
    real_mkdtemp = tempfile.mkdtemp

    def _captive_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, dir=workdir, **kwargs)
        created.append(path)
        return path

    tempfile.mkdtemp = _captive_mkdtemp
    try:
        failed_id = runner.SUITES[0][0]
        first = _write_report(
            workdir, "a.json",
            _shard_report(
                "lane-a",
                outcomes=_full_outcomes(
                    runner, failed=(failed_id,)
                ),
            ),
        )
        second = _write_report(
            workdir, "b.json",
            _shard_report(
                "lane-b", outcomes=_full_outcomes(runner)
            ),
        )
        assert runner.main(["--merge", first, second]) == 1
        assert len(created) == 1, created
        assert os.path.isfile(
            os.path.join(created[0], "matrix-report.json")
        ), created
        print("PASS merge default out-dir failure keeps board")
    finally:
        tempfile.mkdtemp = real_mkdtemp
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_default_dir_creation_failure():
    # A default out dir that cannot be created refuses
    # (exit 2, single line) instead of an uncaught
    # traceback.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    real_mkdtemp = tempfile.mkdtemp

    def _boom(*args, **kwargs):
        raise NotADirectoryError("mkdtemp probe")

    tempfile.mkdtemp = _boom
    try:
        first = _write_report(
            workdir, "a.json", _shard_report("lane-a")
        )
        second = _write_report(
            workdir, "b.json", _shard_report("lane-b")
        )
        import io
        from contextlib import redirect_stderr

        buffer = io.StringIO()
        with redirect_stderr(buffer):
            code = runner.main(["--merge", first, second])
        assert code == 2, code
        message = buffer.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "cannot create default out dir" in message, message
        print("PASS merge refuses default-dir creation failure")
    finally:
        tempfile.mkdtemp = real_mkdtemp
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refusal_survives_cleanup_failure():
    # Cleanup is best-effort: a failing rmtree still
    # refuses (exit 2, single line); the leftover dir is
    # the trace of a failed cleanup (see the module
    # docstring), not a crash.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    created = []
    real_mkdtemp = tempfile.mkdtemp
    real_rmtree = runner.shutil.rmtree

    def _captive_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, dir=workdir, **kwargs)
        created.append(path)
        return path

    def _boom(*args, **kwargs):
        raise OSError("rmtree probe")

    tempfile.mkdtemp = _captive_mkdtemp
    runner.shutil.rmtree = _boom
    try:
        first = _write_report(
            workdir, "a.json", _shard_report("lane-a", commit="aaa")
        )
        second = _write_report(
            workdir, "b.json", _shard_report("lane-b", commit="bbb")
        )
        import io
        from contextlib import redirect_stderr

        buffer = io.StringIO()
        with redirect_stderr(buffer):
            code = runner.main(["--merge", first, second])
        assert code == 2, code
        message = buffer.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "disagrees on 'commit'" in message, message
        assert len(created) == 1, created
        assert os.path.isdir(created[0]), created
        print("PASS merge refusal survives cleanup failure")
    finally:
        tempfile.mkdtemp = real_mkdtemp
        runner.shutil.rmtree = real_rmtree
        shutil.rmtree(workdir, ignore_errors=True)


def _stubbed_direct_runner(runner, workdir):
    # Heavy direct-run setup (git/qemu/suites) stubbed on
    # the fresh module; the out-dir and report-write
    # branches under test are real. All cells excluded so
    # no suite runs.
    lock = _lock(
        [
            _lane(lane_id="solo-a", release="v9.1"),
            _lane(lane_id="solo-b", release="v9.2"),
        ]
    )
    lock_path = os.path.join(workdir, "lock.json")
    with open(lock_path, "w", encoding="utf-8") as handle:
        json.dump(lock, handle)
    all_suites = tuple(
        suite_id for suite_id, _, _ in runner.SUITES
    )
    assert all_suites, "SUITES fixture empty"

    def _boom(*args, **kwargs):
        raise AssertionError("suite ran despite full exclusion")

    runner.git_head = lambda: "abc123"
    runner.git_clean = lambda: ""
    runner.check_runner = lambda *a, **k: {
        "farm": os.path.join(workdir, "farm"),
        "version": "virtme-ng test",
        "realpath": "/nonexistent/vng",
        "digest": "d" * 64,
        "qemu_binary": "qemu-test",
        "qemu_path": "/nonexistent/qemu",
        "qemu_version": "QEMU test",
        "virtme_run_path": "/nonexistent/virtme-run",
        "virtme_run_version": "virtme-run test",
    }
    runner.check_lane_cache = lambda lane: {}
    runner.check_consumer_vng_shadow = lambda *a, **k: None
    runner.check_consumer_qemu_shadow = lambda *a, **k: None
    runner.check_consumer_virtme_run_shadow = (
        lambda *a, **k: None
    )
    runner.run_suite = _boom
    runner.runner_report = lambda value: {"stubbed": True}
    runner.LANE_SUITE_EXCLUSIONS = {
        "solo-a": all_suites,
        "solo-b": all_suites,
    }
    return lock_path


def test_main_setup_refusal_collapses_newline_lock():
    # A newline-bearing --lock refuses as one line: the
    # setup handler collapses like every other refusal
    # site. No stubs needed (the lock load fails first).
    import io
    from contextlib import redirect_stderr

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-direct-io-")
    try:
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            code = runner.main(
                ["--lock", os.path.join(workdir, "a\nb.json")]
            )
        assert code == 2, code
        message = buffer.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "lockfile not found" in message, message
        print("PASS main setup refusal collapses newline lock")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_setup_refusal_collapses_newline_flag():
    # Newline-bearing --lane/--suite/--consumer-path
    # refuse as one line each (live-probed, not inferred).
    import contextlib
    import io
    from contextlib import redirect_stderr

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-direct-io-")
    try:
        lock_path = _stubbed_direct_runner(runner, workdir)
        cases = (
            (["--lane", "a\nb"], "unknown lane"),
            (["--suite", "x\ny"], "unknown suite"),
            (
                ["--consumer-path", os.path.join(workdir, "n\no")],
                "not a directory",
            ),
        )
        for extra, needle in cases:
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout):
                with redirect_stderr(stderr):
                    code = runner.main(
                        ["--lock", lock_path] + extra
                    )
            assert code == 2, (extra, code, stdout.getvalue())
            message = stderr.getvalue()
            assert message.startswith("run_vm_tests:"), (
                extra, message,
            )
            assert message.count("\n") == 1, (
                extra, message,
            )
            assert message.endswith("\n"), (extra, message)
            assert needle in message, (extra, message)
        print("PASS main setup refusal collapses newline flag")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_setup_refusal_collapses_git_failure():
    # Multi-line git failure text collapses to one line:
    # only the dirt list keeps multi-line stderr.
    import contextlib
    import io
    from contextlib import redirect_stderr

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-direct-io-")
    try:
        lock_path = _stubbed_direct_runner(runner, workdir)

        def _boom():
            raise runner.SetupFailure(
                "cannot inspect the worktree: a\nb"
            )

        runner.git_clean = _boom
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with redirect_stderr(stderr):
                code = runner.main(["--lock", lock_path])
        assert code == 2, (code, stdout.getvalue())
        message = stderr.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "cannot inspect the worktree" in message, message
        print("PASS main setup refusal collapses git failure")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_setup_dirt_stays_multiline():
    # Carve-out guard: the dirt list intentionally stays
    # multi-line stderr (the collapse must not eat it).
    import contextlib
    import io
    from contextlib import redirect_stderr

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-direct-io-")
    try:
        lock_path = _stubbed_direct_runner(runner, workdir)
        runner.git_clean = lambda: " M foo\n M bar"
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with redirect_stderr(stderr):
                code = runner.main(["--lock", lock_path])
        assert code == 2, (code, stdout.getvalue())
        message = stderr.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert "worktree is dirty" in message, message
        assert message.count("\n") == 3, message
        assert message.endswith("\n"), message
        print("PASS main setup dirt stays multiline")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_refuses_out_dir_is_a_file():
    # A direct-run out path that exists as a file refuses
    # (exit 2, single line) instead of an uncaught
    # traceback; the file itself is untouched.
    import contextlib
    import io
    from contextlib import redirect_stderr

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-direct-io-")
    try:
        lock_path = _stubbed_direct_runner(runner, workdir)
        out = os.path.join(workdir, "out")
        with open(out, "w", encoding="utf-8") as handle:
            handle.write("not a dir\n")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with redirect_stderr(stderr):
                code = runner.main(
                    ["--lock", lock_path, "--out-dir", out]
                )
        assert code == 2, (code, stdout.getvalue())
        message = stderr.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "cannot create out dir" in message, message
        assert os.path.isfile(out), out
        print("PASS main refuses out-dir-is-a-file")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_refuses_unwritable_report():
    # A direct-run board that cannot be written refuses
    # (exit 2, single line) instead of an uncaught
    # traceback; no board file appears.
    import contextlib
    import io
    from contextlib import redirect_stderr

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-direct-io-")
    try:
        lock_path = _stubbed_direct_runner(runner, workdir)
        out = os.path.join(workdir, "out")
        os.makedirs(os.path.join(out, "matrix-report.json"))
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with redirect_stderr(stderr):
                code = runner.main(
                    ["--lock", lock_path, "--out-dir", out]
                )
        assert code == 2, (code, stdout.getvalue())
        message = stderr.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "cannot write report" in message, message
        assert not os.path.isfile(
            os.path.join(out, "matrix-report.json")
        ), out
        print("PASS main refuses unwritable report")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_refuses_default_dir_creation_failure():
    # A direct-run default out dir that cannot be created
    # refuses (exit 2, single line) instead of an uncaught
    # traceback.
    import contextlib
    import io
    from contextlib import redirect_stderr

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-direct-io-")
    real_mkdtemp = tempfile.mkdtemp

    def _boom(*args, **kwargs):
        raise NotADirectoryError("mkdtemp probe")

    tempfile.mkdtemp = _boom
    try:
        lock_path = _stubbed_direct_runner(runner, workdir)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with redirect_stderr(stderr):
                code = runner.main(["--lock", lock_path])
        assert code == 2, (code, stdout.getvalue())
        message = stderr.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "cannot create default out dir" in message, message
        print("PASS main refuses default-dir creation failure")
    finally:
        tempfile.mkdtemp = real_mkdtemp
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_default_out_dir_keeps_board():
    # Direct-run default dir: the board lands in the minted
    # dir and the dir is kept (no cleanup concept on the
    # direct path; failures keep their evidence too).
    import contextlib
    import io

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-direct-io-")
    created = []
    real_mkdtemp = tempfile.mkdtemp

    def _captive_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, dir=workdir, **kwargs)
        created.append(path)
        return path

    tempfile.mkdtemp = _captive_mkdtemp
    try:
        lock_path = _stubbed_direct_runner(runner, workdir)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = runner.main(["--lock", lock_path])
        assert code == 2, (code, stdout.getvalue())
        assert "refusing an empty board" in stdout.getvalue()
        assert len(created) == 1, created
        assert os.path.isfile(
            os.path.join(created[0], "matrix-report.json")
        ), created
        print("PASS main default out-dir keeps board")
    finally:
        tempfile.mkdtemp = real_mkdtemp
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_default_out_dir_write_failure_keeps_dir():
    # Direct-run default dir without cleanup: a board that
    # cannot be written refuses (exit 2, single line) and
    # the minted dir stays (unlike merge, which cleans
    # its default dir on refusal).
    import contextlib
    import io
    from contextlib import redirect_stderr

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-direct-io-")
    created = []
    real_mkdtemp = tempfile.mkdtemp

    def _captive_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, dir=workdir, **kwargs)
        os.makedirs(os.path.join(path, "matrix-report.json"))
        created.append(path)
        return path

    tempfile.mkdtemp = _captive_mkdtemp
    try:
        lock_path = _stubbed_direct_runner(runner, workdir)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with redirect_stderr(stderr):
                code = runner.main(["--lock", lock_path])
        assert code == 2, (code, stdout.getvalue())
        message = stderr.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "cannot write report" in message, message
        assert len(created) == 1, created
        assert os.path.isdir(created[0]), created
        print("PASS main default out-dir write failure keeps dir")
    finally:
        tempfile.mkdtemp = real_mkdtemp
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_default_out_dir_keeps_success_board():
    # Direct-run exit-0 board with a default dir: the
    # minted dir and its board are kept.
    import contextlib
    import io

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-direct-io-")
    created = []
    real_mkdtemp = tempfile.mkdtemp

    def _captive_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, dir=workdir, **kwargs)
        created.append(path)
        return path

    def _passing(
        suite_id, relpath, lane, *args, **kwargs
    ):
        return {
            "lane": lane["id"],
            "suite": suite_id,
            "commit": "abc123",
            "outcome": "pass",
            "exit_code": 0,
            "verdict": "PASS",
            "passes": 1,
            "failures": 0,
            "envfailures": 0,
            "elapsed_secs": 0.1,
        }

    tempfile.mkdtemp = _captive_mkdtemp
    try:
        lock_path = _stubbed_direct_runner(runner, workdir)
        runner.LANE_SUITE_EXCLUSIONS = {}
        runner.run_suite = _passing
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = runner.main(["--lock", lock_path])
        assert code == 0, (code, stdout.getvalue())
        assert len(created) == 1, created
        assert os.path.isfile(
            os.path.join(created[0], "matrix-report.json")
        ), created
        print("PASS main default out-dir keeps success board")
    finally:
        tempfile.mkdtemp = real_mkdtemp
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_default_out_dir_keeps_failure_board():
    # Direct-run exit-1 board with a default dir: the
    # minted dir and its board are kept (failures keep
    # their evidence).
    import contextlib
    import io

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-direct-io-")
    created = []
    real_mkdtemp = tempfile.mkdtemp

    def _captive_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, dir=workdir, **kwargs)
        created.append(path)
        return path

    calls = []

    def _one_failure(
        suite_id, relpath, lane, *args, **kwargs
    ):
        calls.append((lane["id"], suite_id))
        failed = len(calls) == 1
        return {
            "lane": lane["id"],
            "suite": suite_id,
            "commit": "abc123",
            "outcome": "fail" if failed else "pass",
            "exit_code": 1 if failed else 0,
            "verdict": "FAIL" if failed else "PASS",
            "passes": 0 if failed else 1,
            "failures": 1 if failed else 0,
            "envfailures": 0,
            "elapsed_secs": 0.1,
        }

    tempfile.mkdtemp = _captive_mkdtemp
    try:
        lock_path = _stubbed_direct_runner(runner, workdir)
        runner.LANE_SUITE_EXCLUSIONS = {}
        runner.run_suite = _one_failure
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = runner.main(["--lock", lock_path])
        assert code == 1, (code, stdout.getvalue())
        assert len(created) == 1, created
        assert os.path.isfile(
            os.path.join(created[0], "matrix-report.json")
        ), created
        print("PASS main default out-dir keeps failure board")
    finally:
        tempfile.mkdtemp = real_mkdtemp
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_refuses_undumpable_board():
    # A direct-run board that cannot be serialized
    # refuses (exit 2, single line) instead of an
    # uncaught traceback; no board file appears.
    import contextlib
    import io
    from contextlib import redirect_stderr

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-direct-io-")
    try:
        lock_path = _stubbed_direct_runner(runner, workdir)
        runner.LANE_SUITE_EXCLUSIONS = {}
        value = None
        for _ in range(10000):
            value = [value]

        def _deep(suite_id, relpath, lane, *args, **kwargs):
            return {
                "lane": lane["id"],
                "suite": suite_id,
                "commit": "abc123",
                "outcome": "pass",
                "exit_code": 0,
                "verdict": "PASS",
                "passes": 1,
                "failures": 0,
                "envfailures": 0,
                "elapsed_secs": 0.1,
                "deep": value,
            }

        runner.run_suite = _deep
        out = os.path.join(workdir, "out")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with redirect_stderr(stderr):
                code = runner.main(
                    ["--lock", lock_path, "--out-dir", out]
                )
        assert code == 2, (code, stdout.getvalue())
        message = stderr.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "cannot write report" in message, message
        assert not os.path.isfile(
            os.path.join(out, "matrix-report.json")
        ), out
        print("PASS main refuses undumpable board")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_intra_shard_duplicate_lane():
    # A shard listing one lane twice refuses with an
    # accurate message: the lane is covered more than
    # once, not "by more than one shard".
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        report = _shard_report("lane-a")
        report["lanes"].append(dict(report["lanes"][0]))
        first = _write_report(workdir, "a.json", report)
        second = _write_report(
            workdir, "b.json", _shard_report("lane-b")
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out],
            out,
        )
        assert "covered more than once" in message, message
        assert "more than one shard" not in message, message
        print("PASS merge refuses intra-shard duplicate lane")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_duplicate_lane_suite_cell():
    # Two results for one lane-suite cell refuse, even
    # within a single shard.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        report = _shard_report("lane-a")
        report["results"].append(dict(report["results"][0]))
        first = _write_report(workdir, "a.json", report)
        second = _write_report(
            workdir, "b.json", _shard_report("lane-b")
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out],
            out,
        )
        assert "covered more than once" in message, message
        print("PASS merge refuses duplicate lane-suite cell")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_refuse_collapses_to_one_line():
    # The refusal emitter guarantees one prefixed stderr
    # line even for multi-line messages.
    import io
    from contextlib import redirect_stderr

    runner = _load_runner()
    buffer = io.StringIO()
    with redirect_stderr(buffer):
        code = runner._refuse("first\nsecond\rthird")
    assert code == 2, code
    message = buffer.getvalue()
    assert message == "run_vm_tests: first second third\n", message
    print("PASS refuse collapses to one line")


def test_merge_refusal_collapses_newline_path():
    # A shard path containing a newline still refuses as
    # one line: the emitter collapses, never a traceback
    # shape, never multi-line stderr.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "c.json",
            _shard_report("lane-a", commit="aaa"),
        )
        second = _write_report(
            workdir, "a\nb.json",
            _shard_report("lane-b", commit="bbb"),
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out],
            out,
        )
        assert "disagrees on 'commit'" in message, message
        print("PASS merge refusal collapses newline path")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_mkdtemp_multiline_oserror_stays_one_line():
    # A multi-line OSError from the default-dir minting
    # refuses as one line.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    real_mkdtemp = tempfile.mkdtemp

    def _boom(*args, **kwargs):
        raise OSError("first\nsecond")

    tempfile.mkdtemp = _boom
    try:
        first = _write_report(
            workdir, "a.json", _shard_report("lane-a")
        )
        second = _write_report(
            workdir, "b.json", _shard_report("lane-b")
        )
        import io
        from contextlib import redirect_stderr

        buffer = io.StringIO()
        with redirect_stderr(buffer):
            code = runner.main(["--merge", first, second])
        assert code == 2, code
        message = buffer.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "cannot create default out dir" in message, message
        print("PASS merge mkdtemp multiline OSError stays one line")
    finally:
        tempfile.mkdtemp = real_mkdtemp
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_makedirs_multiline_oserror_stays_one_line():
    # A newline-bearing out path that is a file refuses as
    # one line on the direct path.
    import contextlib
    import io
    from contextlib import redirect_stderr

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-direct-io-")
    try:
        lock_path = _stubbed_direct_runner(runner, workdir)
        out = os.path.join(workdir, "o\nut")
        with open(out, "w", encoding="utf-8") as handle:
            handle.write("not a dir\n")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with redirect_stderr(stderr):
                code = runner.main(
                    ["--lock", lock_path, "--out-dir", out]
                )
        assert code == 2, (code, stdout.getvalue())
        message = stderr.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "cannot create out dir" in message, message
        print("PASS main makedirs multiline OSError stays one line")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_report_multiline_oserror_stays_one_line():
    # A newline-bearing out dir with a blocked report
    # refuses as one line on the direct path.
    import contextlib
    import io
    from contextlib import redirect_stderr

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-direct-io-")
    try:
        lock_path = _stubbed_direct_runner(runner, workdir)
        out = os.path.join(workdir, "o\nut")
        os.makedirs(os.path.join(out, "matrix-report.json"))
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with redirect_stderr(stderr):
                code = runner.main(
                    ["--lock", lock_path, "--out-dir", out]
                )
        assert code == 2, (code, stdout.getvalue())
        message = stderr.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "cannot write report" in message, message
        print("PASS main report multiline OSError stays one line")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_mkdtemp_multiline_oserror_stays_one_line():
    # A multi-line OSError from the direct default-dir
    # minting refuses as one line.
    import contextlib
    import io
    from contextlib import redirect_stderr

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-direct-io-")
    real_mkdtemp = tempfile.mkdtemp

    def _boom(*args, **kwargs):
        raise OSError("first\nsecond")

    tempfile.mkdtemp = _boom
    try:
        lock_path = _stubbed_direct_runner(runner, workdir)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with redirect_stderr(stderr):
                code = runner.main(["--lock", lock_path])
        assert code == 2, (code, stdout.getvalue())
        message = stderr.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "cannot create default out dir" in message, message
        print("PASS main mkdtemp multiline OSError stays one line")
    finally:
        tempfile.mkdtemp = real_mkdtemp
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_vacuous_shard():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        empty = _shard_report("lane-a", outcomes=())
        first = _write_report(workdir, "a.json", empty)
        second = _write_report(
            workdir, "b.json", _shard_report("lane-b")
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out],
            out,
        )
        assert "vacuous shard never merges" in message, message
        print("PASS merge refuses vacuous shard")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_missing_expected_lane():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json", _shard_report("lane-a")
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, "--out-dir", out,
                     "--expect-lanes", "lane-a,lane-b"],
            out,
        )
        assert "do not cover the expected set" in message, message
        assert "missing" in message, message
        print("PASS merge refuses missing expected lane")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_accepts_exact_expected_lanes():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json",
            _shard_report("lane-a", outcomes=_full_outcomes(runner)),
        )
        second = _write_report(
            workdir, "b.json",
            _shard_report("lane-b", outcomes=_full_outcomes(runner)),
        )
        out = os.path.join(workdir, "merged")
        assert runner.main(
            ["--merge", first, second, "--out-dir", out,
             "--expect-lanes", "lane-a,lane-b"]
        ) == 0
        print("PASS merge accepts exact expected lanes")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_partial_suite_coverage():
    # A manually subsetted shard (--suite) never merges green:
    # every merged lane must cover the full SUITES set, so a
    # partial board refuses instead of reporting "2/2 passed".
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json",
            _shard_report("lane-a", outcomes=(("s1", "pass"),)),
        )
        second = _write_report(
            workdir, "b.json",
            _shard_report("lane-b", outcomes=(("s1", "pass"),)),
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out,
                     "--expect-lanes", "lane-a,lane-b"],
            out,
        )
        assert "only pinned exclusions excuse" in message, message
        print("PASS merge refuses partial suite coverage")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_accepts_pinned_exclusions():
    # A lane missing exactly its pinned exclusions merges: the
    # exclusion map (not silence) explains the absent cells.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json",
            _shard_report(
                "v6.12-kvm",
                outcomes=_full_outcomes(
                    runner, skip=("kernel-joint",)
                ),
            ),
        )
        second = _write_report(
            workdir, "b.json",
            _shard_report(
                "v7.2-kvm",
                outcomes=_full_outcomes(
                    runner,
                    skip=("kernel-joint", "kernel-core-layouts"),
                ),
            ),
        )
        out = os.path.join(workdir, "merged")
        assert runner.main(
            ["--merge", first, second, "--out-dir", out,
             "--expect-lanes", "v6.12-kvm,v7.2-kvm"]
        ) == 0
        print("PASS merge accepts pinned exclusions")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_beyond_pinned_exclusions():
    # A lane missing more than its pinned exclusions refuses:
    # the map excuses exactly its cells, never a wider hole.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json",
            _shard_report(
                "v6.12-kvm",
                outcomes=_full_outcomes(
                    runner,
                    skip=("kernel-joint", "kernel-xdp"),
                ),
            ),
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, "--out-dir", out,
                     "--expect-lanes", "v6.12-kvm"],
            out,
        )
        assert "only pinned exclusions excuse" in message, message
        print("PASS merge refuses beyond pinned exclusions")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_malformed_report():
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        bad = os.path.join(workdir, "bad.json")
        with open(bad, "w", encoding="utf-8") as handle:
            handle.write('{"tool": "run_vm_tests"}')
        good = _write_report(
            workdir, "good.json", _shard_report("lane-a")
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", bad, good, "--out-dir", out],
            out,
        )
        assert "lacks 'commit'" in message, message
        print("PASS merge refuses malformed report")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_shard_identity_mismatch():
    # Beyond the commit, the interpreter and consumer path
    # are shard identity too: each mismatch refuses.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        variants = {
            "python": {
                "executable": "/other/python3",
                "version": "3.14.8",
            },
            "consumer_path": ["/other/consumer"],
        }
        for key, other in variants.items():
            first = _write_report(
                workdir, "a-%s.json" % key,
                _shard_report("lane-a"),
            )
            altered = _shard_report("lane-b")
            altered[key] = other
            second = _write_report(
                workdir, "b-%s.json" % key, altered
            )
            out = os.path.join(workdir, "merged-%s" % key)
            message = _merge_rejection_text(
                runner,
                ["--merge", first, second, "--out-dir", out],
                out,
            )
            assert "disagrees on %r" % key in message, (
                key, message,
            )
        print("PASS merge refuses shard identity mismatch")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_expect_lanes_refusal_cleans_default_dir():
    # An expect-lanes refusal without --out-dir removes
    # its minted directory like any other refusal.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    created = []
    real_mkdtemp = tempfile.mkdtemp

    def _captive_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, dir=workdir, **kwargs)
        created.append(path)
        return path

    tempfile.mkdtemp = _captive_mkdtemp
    try:
        first = _write_report(
            workdir, "a.json", _shard_report("lane-a")
        )
        second = _write_report(
            workdir, "b.json", _shard_report("lane-b")
        )
        import io
        from contextlib import redirect_stderr

        buffer = io.StringIO()
        with redirect_stderr(buffer):
            code = runner.main(
                ["--merge", first, second,
                 "--expect-lanes", "lane-a"]
            )
        assert code == 2, code
        message = buffer.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "do not cover the expected set" in message, message
        assert len(created) == 1, created
        assert not os.path.exists(created[0]), created
        print("PASS merge expect-lanes refusal cleans default dir")
    finally:
        tempfile.mkdtemp = real_mkdtemp
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_write_failure_survives_cleanup_failure():
    # Cleanup-failure variant on a write-failure refusal:
    # the refusal still lands exit-2 and the leftover dir
    # stays as the trace of the failed cleanup.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    created = []
    real_mkdtemp = tempfile.mkdtemp
    real_rmtree = runner.shutil.rmtree

    def _captive_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, dir=workdir, **kwargs)
        os.makedirs(os.path.join(path, "matrix-report.json"))
        created.append(path)
        return path

    def _boom(*args, **kwargs):
        raise OSError("rmtree probe")

    tempfile.mkdtemp = _captive_mkdtemp
    runner.shutil.rmtree = _boom
    try:
        first = _write_report(
            workdir, "a.json",
            _shard_report(
                "lane-a", outcomes=_full_outcomes(runner)
            ),
        )
        second = _write_report(
            workdir, "b.json",
            _shard_report(
                "lane-b", outcomes=_full_outcomes(runner)
            ),
        )
        import io
        from contextlib import redirect_stderr

        buffer = io.StringIO()
        with redirect_stderr(buffer):
            code = runner.main(["--merge", first, second])
        assert code == 2, code
        message = buffer.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "cannot write report" in message, message
        assert len(created) == 1, created
        assert os.path.isdir(created[0]), created
        print("PASS merge write failure survives cleanup failure")
    finally:
        tempfile.mkdtemp = real_mkdtemp
        runner.shutil.rmtree = real_rmtree
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_extra_expected_lane():
    # Expected lanes must match exactly: an extra merged
    # lane refuses, not just a missing one.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json", _shard_report("lane-a")
        )
        second = _write_report(
            workdir, "b.json", _shard_report("lane-b")
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out,
                     "--expect-lanes", "lane-a"],
            out,
        )
        assert "do not cover the expected set" in message, message
        assert "extra" in message, message
        print("PASS merge refuses extra expected lane")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_unknown_suite_exclusion():
    # The exclusion map must name real suites only: an
    # unknown suite refuses instead of excusing anything.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        runner.LANE_SUITE_EXCLUSIONS = dict(
            runner.LANE_SUITE_EXCLUSIONS,
            **{"lane-a": ("bogus-suite",)},
        )
        first = _write_report(
            workdir, "a.json", _shard_report("lane-a")
        )
        second = _write_report(
            workdir, "b.json", _shard_report("lane-b")
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", first, second, "--out-dir", out],
            out,
        )
        assert "unknown suite" in message, message
        print("PASS merge refuses unknown suite exclusion")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_ignores_unknown_exclusion_lane():
    # Exclusion keys for unknown lanes are inert lookup
    # misses, never excuses: a full board still merges,
    # and a lane missing a real suite still refuses
    # despite the bogus entry. (Merge-time lane-key
    # validation would false-refuse partial merges, so
    # committed-map typos are caught by the exact
    # contract pin and run-path startup validation
    # instead.)
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        runner.LANE_SUITE_EXCLUSIONS = dict(
            runner.LANE_SUITE_EXCLUSIONS,
            **{"bogus-lane": (runner.SUITES[0][0],)},
        )
        full_first = _write_report(
            workdir, "a.json",
            _shard_report(
                "lane-a", outcomes=_full_outcomes(runner)
            ),
        )
        full_second = _write_report(
            workdir, "b.json",
            _shard_report(
                "lane-b", outcomes=_full_outcomes(runner)
            ),
        )
        out = os.path.join(workdir, "merged")
        assert runner.main(
            ["--merge", full_first, full_second,
             "--out-dir", out]
        ) == 0
        part_first = _write_report(
            workdir, "c.json",
            _shard_report("lane-a", outcomes=(("s1", "pass"),)),
        )
        part_second = _write_report(
            workdir, "d.json",
            _shard_report("lane-b", outcomes=(("s1", "pass"),)),
        )
        partial = os.path.join(workdir, "partial")
        message = _merge_rejection_text(
            runner, ["--merge", part_first, part_second,
                     "--out-dir", partial,
                     "--expect-lanes", "lane-a,lane-b"],
            partial,
        )
        assert "only pinned exclusions excuse" in message, message
        print("PASS merge ignores unknown exclusion lane")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_non_dict_runner():
    # Runner blocks must be mappings: identical junk
    # blocks across shards refuse instead of merging a
    # board with a junk runner.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        for junk in ("evil", None, [1]):
            first_report = _shard_report("lane-a")
            first_report["runner"] = junk
            first = _write_report(
                workdir, "a.json", first_report
            )
            second_report = _shard_report("lane-b")
            second_report["runner"] = junk
            second = _write_report(
                workdir, "b.json", second_report
            )
            out = os.path.join(workdir, "merged")
            message = _merge_rejection_text(
                runner,
                ["--merge", first, second, "--out-dir", out],
                out,
            )
            assert "malformed runner" in message, (
                junk, message,
            )
        print("PASS merge refuses non-dict runner")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_accepts_path_entries():
    # Library callers may pass pathlib.Path entries:
    # merged_from records them as strings.
    import json
    import pathlib

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json",
            _shard_report(
                "lane-a", outcomes=_full_outcomes(runner)
            ),
        )
        second = _write_report(
            workdir, "b.json",
            _shard_report(
                "lane-b", outcomes=_full_outcomes(runner)
            ),
        )
        out = os.path.join(workdir, "merged")
        assert runner.merge_reports(
            [pathlib.Path(first), pathlib.Path(second)], out
        ) == 0
        with open(
            os.path.join(out, "matrix-report.json"),
            encoding="utf-8",
        ) as handle:
            merged = json.load(handle)
        assert merged["merged_from"] == [first, second], merged
        assert all(
            isinstance(entry, str)
            for entry in merged["merged_from"]
        ), merged
        print("PASS merge accepts path entries")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_unloadable_shard():
    # A shard path that cannot load refuses (exit 2,
    # single line), never a traceback.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        missing = os.path.join(workdir, "no-such.json")
        good = _write_report(
            workdir, "good.json", _shard_report("lane-a")
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", missing, good, "--out-dir", out],
            out,
        )
        assert "cannot load shard report" in message, message
        print("PASS merge refuses unloadable shard")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_deeply_nested_shard():
    # A shard whose JSON nests past the recursion limit
    # refuses (exit 2, single line): RecursionError is a
    # load failure, not an uncaught traceback.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        deep = os.path.join(workdir, "deep.json")
        with open(deep, "w", encoding="utf-8") as handle:
            handle.write("[" * 1000000 + "]" * 1000000)
        good = _write_report(
            workdir, "good.json", _shard_report("lane-a")
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", deep, good, "--out-dir", out],
            out,
        )
        assert "cannot load shard report" in message, message
        print("PASS merge refuses deeply nested shard")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_non_board_shard():
    # Valid JSON that is not a run_vm_tests board refuses.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        foreign = os.path.join(workdir, "foreign.json")
        with open(foreign, "w", encoding="utf-8") as handle:
            handle.write('{"tool": "other-tool"}\n')
        good = _write_report(
            workdir, "good.json", _shard_report("lane-a")
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", foreign, good, "--out-dir", out],
            out,
        )
        assert "not a run_vm_tests board" in message, message
        print("PASS merge refuses non-board shard")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_non_list_lanes():
    # A shard whose lanes block is not a list refuses as
    # malformed lanes.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        report = _shard_report("lane-a")
        report["lanes"] = {"id": "lane-a"}
        bad = _write_report(workdir, "bad.json", report)
        good = _write_report(
            workdir, "good.json", _shard_report("lane-b")
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", bad, good, "--out-dir", out],
            out,
        )
        assert "malformed lanes" in message, message
        print("PASS merge refuses non-list lanes")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_refuses_non_list_results():
    # A shard whose results block is not a list refuses as
    # malformed results.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        report = _shard_report("lane-a")
        report["results"] = {"lane-a": "pass"}
        bad = _write_report(workdir, "bad.json", report)
        good = _write_report(
            workdir, "good.json", _shard_report("lane-b")
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner, ["--merge", bad, good, "--out-dir", out],
            out,
        )
        assert "malformed results" in message, message
        print("PASS merge refuses non-list results")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_reports_refuses_empty_shard_list():
    # merge_reports([]) refuses directly: the CLI cannot
    # express it (nargs=+), so only a direct call pins it.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        out = os.path.join(workdir, "merged")
        try:
            runner.merge_reports([], out)
        except runner.SetupFailure as exc:
            assert "at least one shard" in str(exc), exc
        else:
            raise AssertionError("empty shard list merged")
        assert not os.path.exists(out), out
        print("PASS merge reports refuses empty shard list")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_refuses_merge_with_lock_or_consumer_path():
    # --merge reads neither --lock nor --consumer-path:
    # passing either refuses instead of silently
    # ignoring it.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json", _shard_report("lane-a")
        )
        for extra in (
            ["--lock", os.path.join(workdir, "lock.json")],
            ["--consumer-path", os.path.join(workdir, "c")],
        ):
            out = os.path.join(
                workdir, "merged-%s" % extra[0].lstrip("-")
            )
            message = _merge_rejection_text(
                runner,
                ["--merge", first, "--out-dir", out] + extra,
                out,
            )
            assert "--merge takes no" in message, (
                extra, message,
            )
        print("PASS main refuses merge with lock/consumer-path")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_refuses_merge_with_run_flags():
    # --merge takes no --lane/--suite/--timeout: each
    # combination refuses (exit 2, single prefixed line)
    # before any directory is created.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json", _shard_report("lane-a")
        )
        for extra in (
            ["--lane", "lane-a"],
            ["--suite", "s1"],
            ["--timeout", "5"],
        ):
            out = os.path.join(
                workdir, "merged-%s" % extra[0].lstrip("-")
            )
            message = _merge_rejection_text(
                runner,
                ["--merge", first, "--out-dir", out] + extra,
                out,
            )
            assert "--merge takes no" in message, (
                extra, message,
            )
        print("PASS main refuses merge with run flags")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_refuses_non_positive_timeout():
    # --timeout needs a positive number of seconds: 0
    # must not silently fall back, negatives must not
    # become instant timeouts. Each refuses exit-2.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-timeout-")
    try:
        for flag in ("0", "-5"):
            out = os.path.join(workdir, "merged-%s" % flag)
            if flag.startswith("-"):
                args = ["--timeout=%s" % flag, "--out-dir", out]
            else:
                args = ["--timeout", flag, "--out-dir", out]
            message = _merge_rejection_text(
                runner, args, out,
            )
            assert "positive number of seconds" in message, (
                flag, message,
            )
        print("PASS main refuses non-positive timeout")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_refuses_merge_with_zero_timeout():
    # --merge takes no --timeout, including 0: the guard
    # tests presence, not truthiness.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json", _shard_report("lane-a")
        )
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner,
            ["--merge", first, "--out-dir", out,
             "--timeout", "0"],
            out,
        )
        assert "--merge takes no" in message, message
        print("PASS main refuses merge with zero timeout")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_positive_timeout_passes_validation():
    # A positive --timeout passes validation and reaches
    # later checks (here: the --expect-lanes pairing
    # refusal).
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-timeout-")
    try:
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner,
            ["--expect-lanes", "lane-a", "--out-dir", out,
             "--timeout", "5"],
            out,
        )
        assert "--expect-lanes needs --merge" in message, message
        print("PASS main positive timeout passes validation")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_refuses_expect_lanes_without_merge():
    # --expect-lanes without --merge refuses (exit 2,
    # single prefixed line) with no side effects.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        out = os.path.join(workdir, "merged")
        message = _merge_rejection_text(
            runner,
            ["--expect-lanes", "lane-a", "--out-dir", out],
            out,
        )
        assert "--expect-lanes needs --merge" in message, message
        print("PASS main refuses expect-lanes without merge")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_merge_expect_lanes_parsing_edges():
    # --expect-lanes parsing edges: whitespace-only refuses
    # (nothing expected, lanes extra), while empty and
    # duplicated spellings behave as absent and exact.
    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-merge-")
    try:
        first = _write_report(
            workdir, "a.json",
            _shard_report(
                "lane-a", outcomes=_full_outcomes(runner)
            ),
        )
        second = _write_report(
            workdir, "b.json",
            _shard_report(
                "lane-b", outcomes=_full_outcomes(runner)
            ),
        )
        blank = os.path.join(workdir, "merged-blank")
        message = _merge_rejection_text(
            runner, ["--merge", first, second,
                     "--out-dir", blank,
                     "--expect-lanes", "  "],
            blank,
        )
        assert "extra" in message, message
        empty = os.path.join(workdir, "merged-empty")
        assert runner.main(
            ["--merge", first, second, "--out-dir", empty,
             "--expect-lanes", ""]
        ) == 0
        assert os.path.isfile(
            os.path.join(empty, "matrix-report.json")
        )
        dupes = os.path.join(workdir, "merged-dupes")
        assert runner.main(
            ["--merge", first, second, "--out-dir", dupes,
             "--expect-lanes", "lane-a,lane-b,lane-a"]
        ) == 0
        assert os.path.isfile(
            os.path.join(dupes, "matrix-report.json")
        )
        print("PASS merge expect-lanes parsing edges")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_runner_docstring_discloses_pinned_exclusions():
    # The module contract statement must disclose the exclusion
    # map: "Skips never occur" went stale when
    # LANE_SUITE_EXCLUSIONS started skipping ruled cells loudly
    # by design.
    runner = _load_runner()
    doc = runner.__doc__ or ""
    assert "LANE_SUITE_EXCLUSIONS" in doc, doc
    assert "Skips never occur" not in doc, doc


def test_main_refuses_unknown_exclusion_lane():
    # A direct run whose exclusion map names an unknown
    # lane refuses (exit 2, single line) at startup.
    import contextlib
    import io
    from contextlib import redirect_stderr

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-direct-io-")
    try:
        lock_path = _stubbed_direct_runner(runner, workdir)
        runner.LANE_SUITE_EXCLUSIONS = {
            "bogus-lane": ("s1",),
        }
        out = os.path.join(workdir, "out")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with redirect_stderr(stderr):
                code = runner.main(
                    ["--lock", lock_path, "--out-dir", out]
                )
        assert code == 2, (code, stdout.getvalue())
        message = stderr.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "unknown lane" in message, message
        print("PASS main refuses unknown exclusion lane")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_refuses_unknown_exclusion_suite():
    # A direct run whose exclusion map names an unknown
    # suite refuses (exit 2, single line) at startup.
    import contextlib
    import io
    from contextlib import redirect_stderr

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-direct-io-")
    try:
        lock_path = _stubbed_direct_runner(runner, workdir)
        runner.LANE_SUITE_EXCLUSIONS = {
            "solo-a": ("bogus-suite",),
        }
        out = os.path.join(workdir, "out")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with redirect_stderr(stderr):
                code = runner.main(
                    ["--lock", lock_path, "--out-dir", out]
                )
        assert code == 2, (code, stdout.getvalue())
        message = stderr.getvalue()
        assert message.startswith("run_vm_tests:"), message
        assert message.count("\n") == 1, message
        assert message.endswith("\n"), message
        assert "unknown suite" in message, message
        print("PASS main refuses unknown exclusion suite")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_main_refuses_empty_board_when_all_cells_excluded():
    # Every (lane, suite) cell pinned-excluded: main writes the
    # empty board and refuses it (EXIT_SETUP), never a vacuous
    # pass. Heavy setup (git/qemu/suites) is stubbed on the
    # fresh module; the verdict branch is real.
    import contextlib
    import io
    from contextlib import redirect_stderr

    runner = _load_runner()
    workdir = tempfile.mkdtemp(prefix="matrix-empty-board-")
    try:
        lock_path = _stubbed_direct_runner(runner, workdir)
        out_dir = os.path.join(workdir, "out")
        all_suites = tuple(
            suite_id for suite_id, _, _ in runner.SUITES
        )
        assert all_suites, "SUITES fixture empty"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with redirect_stderr(stderr):
                code = runner.main(
                    ["--lock", lock_path, "--out-dir", out_dir]
                )
        text = stdout.getvalue()
        assert code == runner.EXIT_SETUP, (code, text)
        assert "refusing an empty board" in text, text
        assert stderr.getvalue() == "", stderr.getvalue()
        assert "(%d pinned-excluded cells)" % (
            2 * len(all_suites)
        ) in text, text
        with open(
            os.path.join(out_dir, "matrix-report.json"),
            encoding="utf-8",
        ) as handle:
            report = json.load(handle)
        assert report["results"] == [], report
        assert [lane["id"] for lane in report["lanes"]] == [
            "solo-a",
            "solo-b",
        ], report
        print("PASS main refuses the empty board")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _direct_names():
    return sorted(
        name
        for name in globals()
        if name.startswith("test_") and callable(globals()[name])
    )


def _skip_exceptions():
    """pytest skip outcome for direct execution (no spawn).

    Returns a tuple suitable for ``except``: the pytest skip
    outcome when pytest is importable, else an empty tuple
    that matches nothing (tests needing pytest then fail on
    their own import, as before).
    """
    try:
        import pytest
    except ImportError:
        return ()
    return (pytest.skip.Exception,)


class _DirectSkip(Exception):
    """Direct-run skip signal, usable without pytest installed."""


def _skip_direct_or_pytest(reason):
    """Skip under pytest; signal skip under no-pytest direct-run.

    Always raises: pytest's skip outcome when pytest is
    importable, else _DirectSkip (which _direct_one records
    as skipped instead of failed).
    """
    if not _skip_exceptions():
        raise _DirectSkip(reason)
    import pytest

    pytest.skip(reason)


def _direct_one(name):
    """Run one test for direct execution; return ok/skip/fail."""
    try:
        globals()[name]()
    except _skip_exceptions():
        print("skip %s" % name)
        return "skip"
    except _DirectSkip as exc:
        print("skip %s (%s)" % (name, exc))
        return "skip"
    except Exception:
        print("FAIL %s" % name)
        import traceback

        traceback.print_exc()
        return "fail"
    else:
        print("ok %s" % name)
        return "ok"


def _direct_run():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    for name in _direct_names():
        if _direct_one(name) == "fail":
            failures += 1
    print("%d tests, %d failures" % (len(_direct_names()), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_direct_run())
