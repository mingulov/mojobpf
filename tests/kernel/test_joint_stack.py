# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Joint stack proof: MojoBPF-built object driven via libbpf-mojo.

Builds ``tests/compile/map_roundtrip.mojo`` and its plus-two mutation
through the genuine pipeline (``mojo build --emit llvm`` with the
packaged SDK on the import path -> ``compiler/mojo_ir_adapter.py`` ->
``llc -mtriple=bpfel -mcpu=v3``), then boots one disposable Linux guest
on the WP-5 joint lane and executes the bpftool baseline legs
(load type xdp, userspace init key 0 to 41, one kernel test-run,
independent read-back): base must observe 42, the rebuilt mutant 43,
and the stale base object its old 42. The guest also reports the
kernel-observed map and program names (``joint.map_name`` /
``joint.prog_name``) that the Task 3 joint driver consumes as argv,
so the driver leg can never pass against names the kernel did not
report. Task 3 adds the driver leg (load + map + test-run through
the independent libbpf-mojo consumer) and Task 4 the bpftool
cross-check on the same object; until then
``test_joint_driver_reports_42`` fails by design.

Requires a working Mojo compiler, LLVM ``llc``, and ``vng`` (virtme-ng)
with a cached guest image on PATH (joint lane default v7.0.14 per the
WP-5 Task 1 decision; MOJOBPF_VNG_RELEASE selects another lane).
Missing tools fail loudly as environment failures, never as passes.

Runnable directly (``python3 tests/kernel/test_joint_stack.py``) or under
any ``test_``-style runner. Standard library only. The guest boot takes
a few minutes under software emulation; all cases share one boot.
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
import tool_admission  # noqa: E402
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402
COMPILE_DIR = os.path.join(REPO_ROOT, "tests", "compile")
BASE_SOURCE = os.path.join(COMPILE_DIR, "map_roundtrip.mojo")
MUTATED_SOURCE = os.path.join(COMPILE_DIR, "map_roundtrip_mutated.mojo")
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

XDP_PASS = 2
# Joint lane under test (WP-5 Task 1 pins v7.0.14). The VM matrix
# selects the lane through MOJOBPF_VNG_RELEASE; standalone runs
# keep the joint default.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v7.0.14")
VNG_TIMEOUT = 900

INIT_VALUE = 41
BASE_VALUE = 42
MUTATED_VALUE = 43
MAP_NAME = "mojobpf_map0"


class EnvironmentFailure(Exception):
    """The toolchain or VM needed by this test is missing or broken."""


def hexle(value):
    """Lowercase hex of a u64 value without spaces (bpftool byte order)."""
    return "".join(
        "%02x" % byte for byte in value.to_bytes(8, byteorder="little")
    )


def sha256_file(path):
    digest = hashlib.sha256()
    with guest_proc.open_consumed(path, "rb") as handle:
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


@guest_proc.consumes_source
def build_object(source, workdir, name):
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(
        [
            "mojo",
            "build",
            "--emit",
            "llvm",
            *FRONTEND_TARGET_FLAGS,
            "-I",
            SDK_INCLUDE,
            "-o",
            raw_path,
            source,
        ]
    )
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
{bpftool_prologue}
echo "=== begin guest_joint ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "=== staged hashes ==="
sha256sum base.bpf.o mutated.bpf.o data.bin guest_joint.sh
map_case() {{
  tag="$1"; obj="$2"
  pin="/sys/fs/bpf/mojobpf_joint_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  "$BPFTOOL" prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  python3 - "$out" "$pin" >/tmp/xdp-$tag.mapinfo 2>&1 <<'PYEOF'
import json
import subprocess
import sys
fields = sys.argv[1]
pin = sys.argv[2]
info = {{"map_found": "0"}}
joint = {{}}
try:
    raw = subprocess.run(
        [{bpftool_argv0}, "-j", "map", "show"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    for entry in json.loads(raw.stdout or "[]"):
        if entry.get("name") == "{map_name}":
            info = {{
                "map_found": "1",
                "map_id": str(entry.get("id")),
                "map_type": str(entry.get("type")),
                "map_key": str(entry.get("bytes_key")),
                "map_value": str(entry.get("bytes_value")),
                "map_entries": str(entry.get("max_entries")),
            }}
            joint["joint.map_name"] = str(entry.get("name"))
except Exception as exc:
    info = {{"map_found": "0", "map_error": str(exc)}}
try:
    praw = subprocess.run(
        [{bpftool_argv0}, "-j", "prog", "show", "pinned", pin],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    pentry = json.loads(praw.stdout or "null")
    if isinstance(pentry, list):
        pentry = pentry[0] if pentry else {{}}
    joint["joint.prog_json_keys"] = ",".join(sorted(pentry.keys()))
    if pentry.get("name"):
        joint["joint.prog_name"] = str(pentry.get("name"))
except Exception as exc:
    joint["joint.prog_error"] = str(exc)
with open(fields, "a") as handle:
    for key in sorted(info):
        handle.write("%s=%s\\n" % (key, info[key]))
    for key in sorted(joint):
        handle.write("%s=%s\\n" % (key, joint[key]))
PYEOF
  echo "mapinfo_exit=$?" >> "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  "$BPFTOOL" map update id "$map_id" key 0 0 0 0 value {init} 0 0 0 0 0 0 0 >/tmp/xdp-$tag.update 2>&1
  echo "init_exit=$?" >> "$out"
  "$BPFTOOL" map lookup id "$map_id" key 0 0 0 0 > /tmp/xdp-$tag.before 2>&1
  echo "before_exit=$?" >> "$out"
  "$BPFTOOL" prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run 2>&1
  echo "run_exit=$?" >> "$out"
  "$BPFTOOL" map lookup id "$map_id" key 0 0 0 0 > /tmp/xdp-$tag.after 2>&1
  echo "after_exit=$?" >> "$out"
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag before ---"
  cat /tmp/xdp-$tag.before
  echo "--- $tag run ---"
  cat /tmp/xdp-$tag.run
  echo "--- $tag after ---"
  cat /tmp/xdp-$tag.after
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
stray=0
for pin in /sys/fs/bpf/mojobpf_joint_*; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; stray=1; fi
done
if [ "$stray" -eq 0 ]; then echo "pin absent (unloaded)"; fi
echo "=== end guest_joint ==="
"""

# tag, object name (bpftool baseline legs; the joint driver leg
# lands in Task 3 and the cross-check in Task 4).
CASES = (
    ("base", "base.bpf.o"),
    ("mut", "mutated.bpf.o"),
    ("stale", "base.bpf.o"),
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
    """Build all objects, boot one guest, return parsed case results."""
    for tool in ("mojo", "llc", "vng"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (BASE_SOURCE, MUTATED_SOURCE, ADAPTER):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK directory: %s" % SDK_INCLUDE)
    stage = guest_proc.owned_stage(prefix="mojo-joint-", dir="/tmp")
    staged = {
        "base.bpf.o": build_object(BASE_SOURCE, stage, "base"),
        "mutated.bpf.o": build_object(MUTATED_SOURCE, stage, "mutated"),
    }
    with open(os.path.join(stage, "data.bin"), "wb") as handle:
        handle.write(bytes(60))
    for name, src in staged.items():
        with guest_proc.open_consumed(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    commands = []
    for tag, obj in CASES:
        commands.append("map_case %s %s" % (tag, obj))
    # Lease before staging, after builds: the build drills
    # run unleased and must reach their injected failures, while
    # an unleased run must still refuse here, never as an
    # admission failure.
    guest_proc.require_target_lease("guest_run")
    try:
        pins = tool_admission.stage_tool_pins(
            {"PATH": os.environ.get("PATH", "")}
        )
    except tool_admission.ToolMissingError as exc:
        raise EnvironmentFailure(str(exc))
    script = GUEST_SCRIPT.format(
        stage=stage,
        commands="\n".join(commands),
        map_name=MAP_NAME,
        init=INIT_VALUE,
        bpftool_prologue=(
            tool_admission.render_prologue(pins)
            + "\n"
            + tool_admission.render_guest_mount()
        ),
        bpftool_argv0=json.dumps(pins["path"]),
    )
    script_path = os.path.join(stage, "guest_joint.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["data.bin", "guest_joint.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    # A1 guest handoff: consume the staged bytes through the recorder
    # and re-stage from the consumed buffers, so the guest-reported
    # hashes compare against an attested identity.
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        tuple(staged) + ("data.bin", "guest_joint.sh"),
    )
    returncode, output = _run_guest(
        ["vng", "--run", VNG_RELEASE, "--disable-kvm",
        "--exec", "bash %s" % script_path],
        stage, VNG_TIMEOUT,
    )
    results = {}
    for match in re.finditer(
        r"=== BEGIN (\S+)(?: exit=(\d+))? ===\n(.*?)\n=== END \1 ===",
        output,
        re.DOTALL,
    ):
        tag, exit_code, body = match.groups()
        results[tag] = {
            "exit": int(exit_code) if exit_code is not None else None,
            "body": body,
        }
    verdict = guest_proc.classify_guest_exit(
        returncode, output,
        records=list(results.values()),
        progress_banner="=== begin guest_joint ===",
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
    missing = [tag for tag, _ in CASES if tag not in results]
    if missing:
        raise guest_proc.GuestMissing(
            "guest output lacks cases %s (stage %s):\n%s"
            % (", ".join(missing), stage, output[-4000:])
        )
    return {"stage": stage, "output": output, "results": results}


_CACHED = {}


def executed():
    if "run" not in _CACHED:
        _CACHED["run"] = guest_run()
    return _CACHED["run"]


def parse_fields(body):
    fields = {}
    for line in body.splitlines():
        if "=" in line and not line.startswith(("key:", "---", "Return")):
            key, _, value = line.partition("=")
            key = key.strip()
            if key and " " not in key:
                fields[key] = value.strip()
    return fields


def parse_lookup_hex(body, marker):
    """Extract the looked-up value bytes as compact lowercase hex."""
    section = body.split(marker, 1)[1]
    match = re.search(r"value:\s*([0-9a-fA-F ]+)", section)
    assert match, "no bpftool value line after %r" % marker
    return match.group(1).replace(" ", "").lower()


def parse_run_action(body):
    match = re.search(r"Return value:\s*(\d+)", body)
    assert match, "no bpftool return-value line in run output"
    return int(match.group(1))


def check_map_case(tag, expect_after):
    run = executed()
    body = run["results"][tag]["body"]
    fields = parse_fields(body)
    for key in (
        "load_exit",
        "mapinfo_exit",
        "init_exit",
        "before_exit",
        "run_exit",
        "after_exit",
    ):
        assert fields.get(key) == "0", "%s: %s=%r" % (tag, key, fields.get(key))
    assert fields.get("map_found") == "1", "%s: map not found" % tag
    assert fields.get("map_type") == "array", "%s: not an array map" % tag
    assert fields.get("map_key") == "4", "%s: key size is not u32" % tag
    assert fields.get("map_value") == "8", "%s: value size is not u64" % tag
    assert fields.get("map_entries") == "1", "%s: not one entry" % tag
    assert fields.get("unload_ok") == "1", "%s: pin was not removed" % tag
    assert fields.get("joint.map_name") == MAP_NAME, (
        "%s: kernel must report map name %r, got %r"
        % (tag, MAP_NAME, fields.get("joint.map_name"))
    )
    assert fields.get("joint.prog_name"), (
        "%s: kernel must report a program name, got %r (keys=%r err=%r)"
        % (tag, fields.get("joint.prog_name"),
           fields.get("joint.prog_json_keys"), fields.get("joint.prog_error"))
    )
    before = parse_lookup_hex(body, "before ---")
    after = parse_lookup_hex(body, "after ---")
    assert before == hexle(INIT_VALUE), (
        "%s: userspace init must read back %d first, got %s" % (tag, INIT_VALUE, before)
    )
    action = parse_run_action(body)
    assert action == XDP_PASS, "%s: test-run action %d" % (tag, action)
    assert after == expect_after, (
        "%s: expected map value %s, observed %s" % (tag, expect_after, after)
    )
    return after


def test_joint_baseline_42():
    check_map_case("base", hexle(BASE_VALUE))


def test_joint_mutation_changes_value():
    run = executed()
    after_mut = check_map_case("mut", hexle(MUTATED_VALUE))
    body = run["results"]["base"]["body"]
    after_base = parse_lookup_hex(body, "after ---")
    assert after_mut != after_base, (
        "rebuilt mutant must change the observed value"
    )
    assert after_base == hexle(BASE_VALUE), "base must still observe 42"


def test_joint_stale_object_fails():
    run = executed()
    body = run["results"]["stale"]["body"]
    fields = parse_fields(body)
    assert fields.get("load_exit") == "0", "stale object must load"
    assert fields.get("run_exit") == "0", "stale object must run"
    after = parse_lookup_hex(body, "after ---")
    assert after == hexle(BASE_VALUE), (
        "stale object must still produce its old value 42, got %s" % after
    )
    assert after != hexle(MUTATED_VALUE), (
        "stale object must fail the new 43 expectation"
    )


def test_joint_driver_reports_42():
    run = executed()
    assert "joint" in run["results"], (
        "joint driver leg not staged yet (lands in Task 3)"
    )


def test_guest_provenance():
    run = executed()
    try:
        observed_kernel = lane_lock.booted_kernel_from_output(run["output"])
        lane_lock.check_booted_kernel(
            observed_kernel, REPO_ROOT, VNG_RELEASE
        )
    except lane_lock.LaneLockError as exc:
        raise AssertionError("guest kernel must be locked: %s" % exc)
    assert "pin absent (unloaded)" in run["output"], "pins must be removed"
    assert "PIN STILL PRESENT" not in run["output"], "pins must be removed"
    rec = guest_proc.active_recorder()
    reported = guest_proc.parse_reported_hashes(run["output"])
    for name in (
        "base.bpf.o",
        "mutated.bpf.o",
        "data.bin",
        "guest_joint.sh",
    ):
        if rec is None:
            # No attestation context (standalone/pytest run):
            # fall back to the legacy post-hoc comparison.
            expected = sha256_file(
                os.path.join(run["stage"], name)
            )
            assert expected in run["output"], (
                "guest must re-verify staged hash of %s" % name
            )
            continue
        expected = rec.consumed_staged_digest(name, run["stage"])
        assert expected is not None, (
            "staged bytes missing for %s" % name
        )
        assert reported.get(name) == expected, (
            "guest must report the consumed bytes of %s" % name
        )


# No denials: the joint legs are positive-only (load + map + run
# must observably succeed); the stale leg is a sensitivity check,
# not a denial cell.
CASE_DENIALS = {}


# Durable inputs per case: absolute repo paths plus ("stage",
# basename) entries resolved against the guest stage at finish.
# Every non-board case pins the sources it depends on; a class
# with any missing file digests to zeros and can never back a
# PASS.
CASE_INPUTS = {
    "test_joint_baseline_42": {
        "sources": [BASE_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": [],
    },
    "test_joint_mutation_changes_value": {
        "sources": [MUTATED_SOURCE],
        "objects": [("stage", "mutated.bpf.o")],
        "corpus": [],
    },
    "test_joint_stale_object_fails": {
        "sources": [BASE_SOURCE, MUTATED_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": [],
    },
    "test_joint_driver_reports_42": {
        "sources": [BASE_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": [("stage", "data.bin")],
    },
    "test_guest_provenance": {
        "sources": [BASE_SOURCE, MUTATED_SOURCE,
                    ("stage", "guest_joint.sh")],
        "objects": [
            ("stage", "base.bpf.o"), ("stage", "mutated.bpf.o"),
        ],
        "corpus": [("stage", "data.bin")],
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
        tool_admission.ToolAdmissionError, AssertionError,
        subprocess.TimeoutExpired,
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
        suite_id="kernel-joint", suite_path=__file__,
        case_ids=names, denials=CASE_DENIALS, inputs=CASE_INPUTS,
        lane_release=VNG_RELEASE)
    # Attestation context: fixture consumption reads route
    # through this recorder from here (warmup included).
    guest_proc.set_active_recorder(rec)
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
        tool_admission.ToolAdmissionError, AssertionError,
        subprocess.TimeoutExpired, guest_proc.TargetLeaseRequired,
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
        except tool_admission.ToolAdmissionError as exc:
            print("ADMISSION FAILURE in %s: %s" % (name, exc))
            rec.end_case_fail(name, "INFRA")
            failures += 1
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
    print("joint stack: baseline, mutation, and stale checks passed")
    print("guest stage: %s (removed after the run)" % executed()["stage"])
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
