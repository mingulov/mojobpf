# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""In-kernel proof for the Mojo-built XDP classifier.

Builds ``examples/xdp_pass/xdp_pass.mojo`` and its single-line mutation
through the genuine pipeline (``mojo build --emit llvm`` ->
``compiler/mojo_ir_adapter.py`` -> ``llc -mtriple=bpfel -mcpu=v3``), then
boots one disposable Linux guest and executes the kernel test-run entry
(``tests/harness/bpf_test_run.py``, contract revision 2, used as-is)
against three packet
fixtures. An independent reimplementation of the specified rule predicts
every expectation: drop (1) when the frame holds at least 15 bytes and bit
0 of byte 14 is set, else pass (2).

The run proves three things: both base fixtures produce their predicted
distinct actions; rebuilding from the mutated source changes the observed
behavior; and the stale base object fails the new expectations. Staged file
hashes are re-verified inside the guest so the observed actions are tied to
the exact bytes built here.

Requires a working Mojo compiler, LLVM ``llc``, and ``vng`` (virtme-ng)
with a cached guest image on PATH (default release v6.12;
MOJOBPF_VNG_RELEASE selects the matrix lane). Missing tools fail loudly as
environment failures, never as passes.

Runnable directly (``python3 tests/kernel/test_mojo_xdp.py``) or under any
``test_``-style runner. Standard library only. The guest boot takes a few
minutes under software emulation; all cases share a single boot.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(
    0, os.path.join(REPO_ROOT, "tests", "harness")
)
import lane_lock  # noqa: E402
import guest_proc  # noqa: E402
EXAMPLE_DIR = os.path.join(REPO_ROOT, "examples", "xdp_pass")
BASE_SOURCE = os.path.join(EXAMPLE_DIR, "xdp_pass.mojo")
MUTATED_SOURCE = os.path.join(EXAMPLE_DIR, "xdp_pass_mutated.mojo")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")

XDP_DROP = 1
XDP_PASS = 2
# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = 900

FIXTURES = ("pkt_drop.bin", "pkt_pass.bin", "pkt_short.bin")


class EnvironmentFailure(Exception):
    """The toolchain or VM needed by this test is missing or broken."""


def classify(frame):
    """Independent prediction of the specified base rule."""
    if len(frame) >= 15 and (frame[14] & 1) == 1:
        return XDP_DROP
    return XDP_PASS


def classify_mutated(frame):
    """Independent prediction of the inverted-bit mutation."""
    if len(frame) >= 15 and (frame[14] & 1) == 0:
        return XDP_DROP
    return XDP_PASS


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_step(argv, timeout=600):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def build_object(source, workdir, name):
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(["mojo", "build", "--emit", "llvm", "-o", raw_path, source])
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise AssertionError(
            "frontend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    if "error:" in proc.stderr.lower() or "warning:" in proc.stderr.lower():
        raise AssertionError(
            "frontend diagnostics for %s:\n%s" % (source, proc.stderr)
        )
    proc = run_step(
        [sys.executable, ADAPTER, "--input", raw_path, "--output", adapted_path]
    )
    if proc.returncode != 0 or not os.path.isfile(adapted_path):
        raise AssertionError(
            "adapter failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    proc = run_step(
        [
            "llc",
            "-mtriple=bpfel",
            "-mcpu=v3",
            "-filetype=obj",
            adapted_path,
            "-o",
            object_path,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "backend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    return object_path


GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin guest_xdp ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
bpftool version | head -2
echo "=== staged hashes ==="
sha256sum bpf_test_run.py base.bpf.o mutated.bpf.o pkt_drop.bin pkt_pass.bin pkt_short.bin
run_case() {{
  tag="$1"; obj="$2"; expect="$3"; data="$4"
  out="/tmp/xdp-$tag.json"
  python3 bpf_test_run.py --object "$obj" --expect-action "$expect" \\
    --data-in "$data" --output "$out" >/tmp/xdp-$tag.stdout 2>/tmp/xdp-$tag.stderr
  code=$?
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
if ls /sys/fs/bpf/mojobpf_control 2>&1; then echo "PIN STILL PRESENT"; else echo "pin absent (unloaded)"; fi
echo "=== end guest_xdp ==="
"""

CASES = (
    # tag, object, expectation fn, packet, required harness exit
    ("base-drop", "base.bpf.o", classify, "pkt_drop.bin", 0),
    ("base-pass", "base.bpf.o", classify, "pkt_pass.bin", 0),
    ("base-short", "base.bpf.o", classify, "pkt_short.bin", 0),
    ("mut-drop", "mutated.bpf.o", classify_mutated, "pkt_drop.bin", 0),
    ("mut-pass", "mutated.bpf.o", classify_mutated, "pkt_pass.bin", 0),
    ("mut-short", "mutated.bpf.o", classify_mutated, "pkt_short.bin", 0),
    ("stale-drop", "base.bpf.o", classify_mutated, "pkt_drop.bin", 1),
    ("stale-pass", "base.bpf.o", classify_mutated, "pkt_pass.bin", 1),
)


def _run_guest(argv, stage, timeout):
    """Run the guest command; return (exit code, output text).

    Thin mapping over the shared owned runner
    (tests/harness/guest_proc.py): a timeout surfaces as
    EnvironmentFailure carrying the partial output.
    """
    try:
        return guest_proc.run_owned(argv, stage, timeout)
    except guest_proc.GuestTimeout as exc:
        raise EnvironmentFailure(
            "vng guest run timed out after %ds (stage %s):\n%s"
            % (timeout, stage, exc.output[-4000:])
        )


def guest_run():
    """Build both objects, boot one guest, return parsed case results."""
    for tool in ("mojo", "llc", "vng"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (BASE_SOURCE, MUTATED_SOURCE, ADAPTER, HARNESS):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    for fixture in FIXTURES:
        if not os.path.isfile(os.path.join(EXAMPLE_DIR, fixture)):
            raise EnvironmentFailure("missing fixture: %s" % fixture)
    stage = guest_proc.owned_stage(prefix="mojo-xdp-", dir="/tmp")
    packets = {}
    for fixture in FIXTURES:
        with open(os.path.join(EXAMPLE_DIR, fixture), "rb") as handle:
            packets[fixture] = handle.read()
    base_obj = build_object(BASE_SOURCE, stage, "base")
    mutated_obj = build_object(MUTATED_SOURCE, stage, "mutated")
    staged = {
        "bpf_test_run.py": HARNESS,
        "base.bpf.o": base_obj,
        "mutated.bpf.o": mutated_obj,
    }
    for fixture in FIXTURES:
        staged[fixture] = os.path.join(EXAMPLE_DIR, fixture)
    for name, src in staged.items():
        with open(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    commands = []
    for tag, obj, expect_fn, packet, _ in CASES:
        commands.append(
            'run_case %s %s %d %s' % (tag, obj, expect_fn(packets[packet]), packet)
        )
    script = GUEST_SCRIPT.format(stage=stage, commands="\n".join(commands))
    script_path = os.path.join(stage, "guest_xdp.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["guest_xdp.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    returncode, output = _run_guest(
        ["vng", "--run", VNG_RELEASE, "--disable-kvm",
        "--exec", "bash %s" % script_path],
        stage, VNG_TIMEOUT,
    )
    results = {}
    for match in re.finditer(
        r"=== BEGIN (\S+) exit=(\d+) ===\n(.*?)\n=== END \1 ===",
        output,
        re.DOTALL,
    ):
        tag, exit_code, body = match.groups()
        try:
            record = json.loads(body)
        except ValueError:
            raise guest_proc.GuestMissing(
                "guest case %s produced invalid JSON (stage %s):\n%s"
                % (tag, stage, body[-1000:])
            )
        record["_harness_exit"] = int(exit_code)
        results[tag] = record
    verdict = guest_proc.classify_guest_exit(
        returncode, output,
        records=list(results.values()),
        progress_banner="=== begin guest_xdp ===",
    )
    if verdict == "proof":
        raise AssertionError(
            "vng guest run failed with proof evidence (exit %d, "
            "stage %s):\n%s"
            % (returncode, stage, output[-4000:])
        )
    if verdict == "env":
        raise EnvironmentFailure(
            "vng guest run failed (exit %d, stage %s):\n%s"
            % (returncode, stage, output[-4000:])
        )
    missing = [tag for tag, _, _, _, _ in CASES if tag not in results]
    if missing:
        raise guest_proc.GuestMissing(
            "guest output lacks cases %s (stage %s):\n%s"
            % (", ".join(missing), stage, output[-4000:])
        )
    return {
        "stage": stage,
        "output": output,
        "packets": packets,
        "results": results,
    }


_CACHED = {}


def executed():
    if "run" not in _CACHED:
        _CACHED["run"] = guest_run()
    return _CACHED["run"]


def test_fixture_bytes():
    for fixture, size, byte14 in (
        ("pkt_drop.bin", 60, 0x01),
        ("pkt_pass.bin", 60, 0x00),
        ("pkt_short.bin", 10, None),
    ):
        with open(os.path.join(EXAMPLE_DIR, fixture), "rb") as handle:
            frame = handle.read()
        assert len(frame) == size, "%s has %d bytes" % (fixture, len(frame))
        if byte14 is None:
            assert frame == bytes(size), "%s must be zero bytes" % fixture
        else:
            assert frame[14] == byte14, "%s byte 14 mismatch" % fixture
            assert frame[:14] == bytes(14) and frame[15:] == bytes(size - 15), (
                "%s must be zero outside byte 14" % fixture
            )
    assert classify(executed()["packets"]["pkt_drop.bin"]) == XDP_DROP
    assert classify(executed()["packets"]["pkt_pass.bin"]) == XDP_PASS
    assert classify(executed()["packets"]["pkt_short.bin"]) == XDP_PASS


def test_base_packet_actions():
    run = executed()
    observed = {}
    for tag in ("base-drop", "base-pass", "base-short"):
        record = run["results"][tag]
        guest_proc.check_harness_exit(
            tag, exit=record["_harness_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=0)
        observed[tag] = record["actual_action"]
    assert observed["base-drop"] == XDP_DROP, "drop fixture must drop"
    assert observed["base-pass"] == XDP_PASS, "pass fixture must pass"
    assert observed["base-short"] == XDP_PASS, "short fixture must pass"
    assert observed["base-drop"] != observed["base-pass"], (
        "the two full-size fixtures must produce distinct actions"
    )


def test_mutation_changes_behavior():
    run = executed()
    for tag in ("mut-drop", "mut-pass", "mut-short"):
        record = run["results"][tag]
        guest_proc.check_harness_exit(
            tag, exit=record["_harness_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=0)
    assert run["results"]["mut-drop"]["actual_action"] == XDP_PASS
    assert run["results"]["mut-pass"]["actual_action"] == XDP_DROP
    assert run["results"]["mut-short"]["actual_action"] == XDP_PASS
    assert run["results"]["mut-drop"]["actual_action"] != run["results"][
        "base-drop"
    ]["actual_action"], "rebuilt mutant must change the drop action"
    assert run["results"]["mut-pass"]["actual_action"] != run["results"][
        "base-pass"
    ]["actual_action"], "rebuilt mutant must change the pass action"


def test_stale_object_fails():
    run = executed()
    hints = []
    for tag, old_action in (("stale-drop", XDP_DROP), ("stale-pass", XDP_PASS)):
        record = run["results"][tag]
        hints.append(guest_proc.check_harness_exit(
            tag, exit=record["_harness_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=1))
        assert record["classification"] == "runtime", (
            "%s: expected runtime classification, got %r"
            % (tag, record.get("classification"))
        )
        assert record["actual_action"] == old_action, (
            "%s: stale object must still produce its old action %d, got %r"
            % (tag, old_action, record.get("actual_action"))
        )
    return guest_proc.combine_outcomes(*hints)


def test_guest_provenance():
    run = executed()
    try:
        observed_kernel = lane_lock.booted_kernel_from_output(run["output"])
        lane_lock.check_booted_kernel(
            observed_kernel, REPO_ROOT, VNG_RELEASE
        )
    except lane_lock.LaneLockError as exc:
        raise AssertionError("guest kernel must be locked: %s" % exc)
    assert "pin absent (unloaded)" in run["output"], "pin must be removed"
    assert "PIN STILL PRESENT" not in run["output"], "pin must be removed"
    for tag, _, _, _, want_exit in CASES:
        record = run["results"][tag]
        guest_proc.check_harness_exit(
            tag, exit=record["_harness_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=want_exit)
        assert record.get("cleanup_ok") is True, (
            "%s: harness must report cleanup_ok" % tag
        )
    for name in (
        "bpf_test_run.py",
        "base.bpf.o",
        "mutated.bpf.o",
        "pkt_drop.bin",
        "pkt_pass.bin",
        "pkt_short.bin",
    ):
        expected = sha256_file(os.path.join(run["stage"], name))
        assert expected in run["output"], (
            "guest must re-verify staged hash of %s" % name
        )


# The stale-object case is a denial: it expects the wire-derived
# FAIL at RUNTIME (the old object mismatching the new rule) and
# passes only its own cell when the denial is observed with
# evidence and clean cleanup. It guards the mutation oracle:
# the mutant must change behavior (positive) while the stale
# base must observably not match (denial), proving the oracle
# is not vacuous.
CASE_DENIALS = {
    "test_stale_object_fails": (
        "test_mutation_changes_behavior", "RUNTIME"
    ),
}


def _packet_paths():
    return [os.path.join(EXAMPLE_DIR, name) for name in FIXTURES]


# Durable inputs per case: absolute repo paths plus ("stage",
# basename) entries resolved against the guest stage at finish.
# Every non-board case pins the sources it depends on; a class
# with any missing file digests to zeros and can never back a
# PASS.
CASE_INPUTS = {
    "test_fixture_bytes": {
        "sources": _packet_paths(),
        "objects": [],
        "corpus": _packet_paths(),
    },
    "test_base_packet_actions": {
        "sources": [BASE_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": _packet_paths(),
    },
    "test_mutation_changes_behavior": {
        "sources": [MUTATED_SOURCE],
        "objects": [("stage", "mutated.bpf.o")],
        "corpus": _packet_paths(),
    },
    "test_stale_object_fails": {
        "sources": [BASE_SOURCE, MUTATED_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": _packet_paths(),
    },
    "test_guest_provenance": {
        "sources": [BASE_SOURCE, MUTATED_SOURCE, HARNESS],
        "objects": [
            ("stage", "base.bpf.o"), ("stage", "mutated.bpf.o")
        ],
        "corpus": _packet_paths(),
    },
}


def _finish(rec, unavailable_seen=False):
    """Attach the guest transcript and finish the typed suite."""
    stage = None
    try:
        run = executed()
        stage = run["stage"]
        rec.note_transcript("guest", run["output"])
    except (
        EnvironmentFailure, guest_proc.HarnessEnvironment,
        AssertionError, subprocess.TimeoutExpired,
    ):
        pass
    code = rec.finish(
        stage_dir=stage, unavailable_seen=unavailable_seen
    )
    guest_proc.discard_owned_stages()
    return code


def main():
    names = sorted(k for k in globals() if k.startswith("test_"))
    rec = guest_proc.SuiteRecorder(
        suite_id="kernel-xdp", suite_path=__file__,
        case_ids=names, denials=CASE_DENIALS, inputs=CASE_INPUTS,
        lane_release=VNG_RELEASE)
    if not __debug__:
        return rec.finish_unrun(
            "must not run under python -O (asserts stripped)"
        )
    failures = 0
    unavailable_seen = False
    # Stage before any begin_case: the begin seals must observe
    # the staged input bytes (bytes first seen after begin can
    # never back a PASS), so warm the cached run here. A warm
    # failure is ignored: each case body retries and records it
    # per case below.
    try:
        executed()
    except (
        EnvironmentFailure, guest_proc.HarnessEnvironment,
        AssertionError, subprocess.TimeoutExpired,
        guest_proc.TargetLeaseRequired,
    ):
        pass
    for name in names:
        func = globals()[name]
        rec.begin_case(name)
        try:
            hint = func()
        except guest_proc.HarnessEnvironment as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            rec.end_case_infra(name, exc.stage, exc.availability)
            return _finish(rec, unavailable_seen)
        except EnvironmentFailure as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            rec.end_case_infra(name, "INFRA", "UNKNOWN")
            return _finish(rec, unavailable_seen)
        except subprocess.TimeoutExpired as exc:
            print("ENVIRONMENT FAILURE in %s: timed out: %s" % (name, exc))
            rec.end_case_infra(name, "INFRA", "TOOLCHAIN_UNAVAILABLE")
            return _finish(rec, unavailable_seen)
        except guest_proc.TargetLeaseRequired as exc:
            print("REQUIRED-UNAVAILABLE %s: %s" % (name, exc))
            rec.end_case_not_run(name, "TARGET_RESOURCE_ABSENT")
            unavailable_seen = True
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            rec.end_case_fail(name)
            failures += 1
        else:
            print("PASS %s" % name)
            rec.end_case_hint(name, hint)
    if failures or unavailable_seen:
        return _finish(rec, unavailable_seen)
    print("mojo xdp: guest behavior, mutation, and stale checks passed")
    print("guest stage: %s (removed after the run)" % executed()["stage"])
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
