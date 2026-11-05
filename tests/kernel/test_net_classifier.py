# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Kernel proof for the Mojo-built TC classifier.

Builds the TC example program and its inverted-bit mutant
through the genuine pipeline (``mojo build --emit llvm`` with
the packaged SDK on the import path ->
``compiler/mojo_ir_adapter.py`` -> ``llc -mtriple=bpfel
-mcpu=v3``), stages both objects plus the example frame corpus
into one disposable Linux guest (6.12 lane default;
MOJOBPF_VNG_RELEASE selects another lane), and executes the
bpftool legs: load each object as a TC classifier, run every
corpus frame through ``bpftool prog run``, and compare each
observed return value against the corpus manifest verdict. The
base program must return 0 for the 0x2A frame and the short
frame and 2 for the 0x2B frame. The rebuilt mutant must observe
the flipped verdicts, and the stale base object its old ones
(failing the mutant expectation).

Socket execution is proven separately: the socket-filter
verifier rejects direct context reads, so the socket program
reads packets through the skb-load helper instead.

Requires a working Mojo compiler, LLVM ``llc``, and ``vng``
(virtme-ng) with a cached guest image on PATH. Missing tools fail
loudly as environment failures, never as passes.

Runnable directly (``python3 tests/kernel/test_net_classifier.py``)
or under any ``test_``-style runner. Standard library only. The
guest boot takes a few minutes under software emulation; all
cases share one boot.
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
TC_DIR = os.path.join(REPO_ROOT, "examples", "tc_classifier")
TC_SOURCE = os.path.join(TC_DIR, "tc.mojo")
TC_MUTATED = os.path.join(TC_DIR, "tc_mutated.mojo")
TC_CORPUS = os.path.join(TC_DIR, "corpus")
TC_MANIFEST = os.path.join(TC_CORPUS, "manifest.json")
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

# Net lane under test (6.12 default). The VM matrix selects the
# lane through MOJOBPF_VNG_RELEASE; standalone runs keep the
# 6.12 default.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = 900


class EnvironmentFailure(Exception):
    """The toolchain or VM needed by this test is missing or broken."""


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


def load_manifest(path):
    with guest_proc.open_consumed(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    frames = document.get("frames")
    if not isinstance(frames, list) or not frames:
        raise AssertionError(
            "corpus manifest %s must list a nonempty frame array" % path
        )
    for entry in frames:
        for key in ("file", "length", "byte14", "verdict", "sha256"):
            if key not in entry:
                raise AssertionError(
                    "corpus entry lacks %r in %s" % (key, path)
                )
        if not isinstance(entry["verdict"], int):
            raise AssertionError(
                "corpus verdict must be an int in %s" % path
            )
    return frames


GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
{bpftool_prologue}
echo "=== begin guest_net ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "=== staged hashes ==="
sha256sum {staged_list}
net_case() {{
  tag="$1"; obj="$2"; progtype="$3"; shift 3
  pin="/sys/fs/bpf/mojobpf_net_$tag"
  echo "=== BEGIN $tag ==="
  "$BPFTOOL" prog load "$obj" "$pin" type "$progtype" >/tmp/net-$tag.load 2>&1
  echo "load_exit=$?"
  idx=0
  for f in "$@"; do
    echo "--- $tag run $idx $f ---"
    "$BPFTOOL" prog run pinned "$pin" data_in "$f" repeat 1 2>&1 | grep -i "return value"
    echo "run_exit_${{idx}}=${{PIPESTATUS[0]}}"
    idx=$((idx + 1))
  done
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0"; else echo "unload_ok=1"; fi
  echo "=== END $tag ==="
}}
{commands}
echo "=== end guest_net ==="
if ls /sys/fs/bpf/mojobpf_net_* >/dev/null 2>&1; then
  echo "PIN STILL PRESENT"
else
  echo "pin absent (unloaded)"
fi
"""

# Legs: (tag, staged object, bpftool program type, corpus frames key).
# TC only: the socket-filter verifier rejects direct context
# reads, so socket execution is proven separately with
# helper-mediated packet reads; the socket corpus, mutant, and
# verdicts committed alongside are that proof's inputs.
LEGS = (
    ("tc_base", "tc.bpf.o", "classifier", TC_MANIFEST),
    ("tc_mut", "tc_mutated.bpf.o", "classifier", TC_MANIFEST),
    ("tc_stale", "tc.bpf.o", "classifier", TC_MANIFEST),
)


def _run_guest(argv, stage, timeout):
    try:
        return guest_proc.run_owned(argv, stage, timeout)
    except guest_proc.GuestTimeout as exc:
        raise EnvironmentFailure(
            "vng guest run timed out after %ds (stage %s):\n%s"
            % (timeout, stage, exc.output[-4000:])
        )


def guest_run():
    """Build all objects, boot one guest, return parsed case results."""
    for tool in ("mojo", "llc", "vng", "git"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (
        TC_SOURCE, TC_MUTATED, TC_MANIFEST, ADAPTER,
    ):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK directory: %s" % SDK_INCLUDE)
    tc_frames = load_manifest(TC_MANIFEST)
    for corpus_dir, frames in ((TC_CORPUS, tc_frames),):
        for entry in frames:
            frame_path = os.path.join(corpus_dir, entry["file"])
            if not os.path.isfile(frame_path):
                raise EnvironmentFailure(
                    "missing corpus frame: %s" % frame_path
                )
            with open(frame_path, "rb") as handle:
                body = handle.read()
            if len(body) != entry["length"]:
                raise AssertionError(
                    "frame %s length %d, manifest says %d"
                    % (entry["file"], len(body), entry["length"])
                )
            digest = hashlib.sha256(body).hexdigest()
            if digest != entry["sha256"]:
                raise AssertionError(
                    "frame %s hash %s, manifest says %s"
                    % (entry["file"], digest, entry["sha256"])
                )
    stage = guest_proc.owned_stage(prefix="mojo-net-", dir="/tmp")
    staged = {
        "tc.bpf.o": build_object(TC_SOURCE, stage, "tc"),
        "tc_mutated.bpf.o": build_object(TC_MUTATED, stage, "tc_mutated"),
    }
    for name, src in staged.items():
        with guest_proc.open_consumed(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    staged_frames = []
    for entry in tc_frames:
        staged_name = "t_%s" % entry["file"]
        with guest_proc.open_consumed(
            os.path.join(TC_CORPUS, entry["file"]), "rb"
        ) as handle:
            data = handle.read()
        with open(os.path.join(stage, staged_name), "wb") as handle:
            handle.write(data)
        staged_frames.append(staged_name)
    with guest_proc.open_consumed(TC_MANIFEST, "rb") as handle:
        tc_manifest_bytes = handle.read()
    with open(os.path.join(stage, "tc_manifest.json"), "wb") as handle:
        handle.write(tc_manifest_bytes)
    commands = []
    for tag, obj, progtype, _manifest in LEGS:
        frame_args = " ".join(
            "t_%s" % entry["file"] for entry in tc_frames
        )
        commands.append(
            "net_case %s %s %s %s" % (tag, obj, progtype, frame_args)
        )
    # Lease before staging, after builds: the build drills run
    # unleased and must reach their injected failures, while an
    # unleased run must still refuse here.
    guest_proc.require_target_lease("guest_run")
    try:
        pins = tool_admission.stage_tool_pins(
            {"PATH": os.environ.get("PATH", "")}
        )
    except tool_admission.ToolMissingError as exc:
        raise EnvironmentFailure(str(exc))
    staged_names = (
        sorted(staged)
        + sorted(staged_frames)
        + ["tc_manifest.json", "guest_net.sh"]
    )
    script = GUEST_SCRIPT.format(
        stage=stage,
        commands="\n".join(commands),
        staged_list=" ".join(staged_names),
        bpftool_prologue=(
            tool_admission.render_prologue(pins)
            + "\n"
            + tool_admission.render_guest_mount()
        ),
    )
    script_path = os.path.join(stage, "guest_net.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in staged_names:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    # A1 guest handoff: consume the staged bytes through the
    # recorder and re-stage from the consumed buffers, so the
    # guest-reported hashes compare against an attested identity.
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage, tuple(staged_names),
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
        results[match.group(1)] = match.group(3)
    return {
        "returncode": returncode,
        "output": output,
        "results": results,
        "stage": stage,
    }


_CACHED = {}


def executed():
    if "run" not in _CACHED:
        _CACHED["run"] = guest_run()
    return _CACHED["run"]


def parse_fields(body):
    fields = {}
    for line in body.splitlines():
        if "=" in line and not line.startswith((" ", "-", "=")):
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip()
    return fields


def parse_frame_verdicts(body, tag, count):
    """Return [(frame, verdict)] in run order for one leg.

    Each run section prints its marker line, one bpftool
    "Return value: N" line, and its run_exit line; anything else
    (missing marker, missing or doubled verdict lines, nonzero
    run exit) refuses instead of guessing.
    """
    sections = re.split(
        r"^--- %s run (\d+) (\S+) ---$" % re.escape(tag),
        body,
        flags=re.MULTILINE,
    )
    # Split yields [preamble, idx, file, section, ...]; preamble
    # holds the load line and carries no verdict.
    if len(sections) < 4:
        raise AssertionError(
            "%s: no frame run sections found" % tag
        )
    verdicts = []
    parts = sections[1:]
    while parts:
        idx, fname, section = parts[0], parts[1], parts[2]
        parts = parts[3:]
        if int(idx) != len(verdicts):
            raise AssertionError(
                "%s: run sections out of order at %s" % (tag, idx)
            )
        found = re.findall(
            r"[Rr]eturn value:\s*(\d+)", section
        )
        if len(found) != 1:
            raise AssertionError(
                "%s run %s: expected exactly one return value, got %r"
                % (tag, idx, found)
            )
        if "run_exit_%s=0" % idx not in section:
            raise AssertionError(
                "%s run %s: bpftool prog run must exit 0" % (tag, idx)
            )
        verdicts.append((fname, int(found[0])))
    if len(verdicts) != count:
        raise AssertionError(
            "%s: expected %d frame runs, got %d"
            % (tag, count, len(verdicts))
        )
    return verdicts


def check_net_leg(tag, manifest_path, flip):
    """Check one leg's verdicts against its corpus manifest.

    ``flip`` False expects the manifest verdicts; True expects
    every verdict flipped (pass/drop swapped), which is what the
    inverted-bit mutant must observe.
    """
    run = executed()
    if tag not in run["results"]:
        raise AssertionError("guest output lacks the %s leg" % tag)
    body = run["results"][tag]
    fields = parse_fields(body)
    if fields.get("load_exit") != "0":
        raise AssertionError(
            "%s: bpftool prog load must exit 0, got %r"
            % (tag, fields.get("load_exit"))
        )
    if fields.get("unload_ok") != "1":
        raise AssertionError("%s: pin was not removed" % tag)
    frames = load_manifest(manifest_path)
    verdicts = parse_frame_verdicts(body, tag, len(frames))
    for entry, (fname, observed) in zip(frames, verdicts):
        if fname != "t_%s" % entry["file"]:
            raise AssertionError(
                "%s: frame order drift: ran %s, manifest has %s"
                % (tag, fname, entry["file"])
            )
        want = entry["verdict"]
        if flip and entry["length"] >= 15:
            # The mutant flips only the bit test; the length
            # guard still passes short frames.
            want = 0 if want == 2 else 2
        if observed != want:
            raise AssertionError(
                "%s frame %s (byte14=%r): expected verdict %d%s, "
                "observed %d"
                % (tag, entry["file"], entry["byte14"], want,
                   " (flipped)" if flip else "", observed)
            )
    return verdicts


def test_tc_baseline_verdicts():
    check_net_leg("tc_base", TC_MANIFEST, False)


def test_tc_mutation_flips_verdicts():
    run = executed()
    mut_verdicts = check_net_leg("tc_mut", TC_MANIFEST, True)
    body = run["results"]["tc_base"]
    base_verdicts = parse_frame_verdicts(
        body, "tc_base", len(mut_verdicts)
    )
    base_values = [value for _, value in base_verdicts]
    mut_values = [value for _, value in mut_verdicts]
    if base_values == mut_values:
        raise AssertionError(
            "rebuilt mutant must change the observed verdicts"
        )
    frames = load_manifest(TC_MANIFEST)
    for entry, value in zip(frames, base_values):
        if value != entry["verdict"]:
            raise AssertionError(
                "base must still observe its manifest verdicts"
            )


def test_tc_stale_object_fails():
    check_net_leg("tc_stale", TC_MANIFEST, False)
    run = executed()
    body = run["results"]["tc_stale"]
    frames = load_manifest(TC_MANIFEST)
    verdicts = parse_frame_verdicts(body, "tc_stale", len(frames))
    for entry, (_, observed) in zip(frames, verdicts):
        if entry["length"] < 15:
            continue
        flipped = 0 if entry["verdict"] == 2 else 2
        if observed == flipped:
            raise AssertionError(
                "stale object must fail the flipped %d expectation "
                "on %s" % (flipped, entry["file"])
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
    staged_names = (
        "tc.bpf.o",
        "tc_mutated.bpf.o",
        "tc_manifest.json",
        "guest_net.sh",
    )
    tc_frames = load_manifest(TC_MANIFEST)
    staged_names = (
        staged_names
        + tuple("t_%s" % e["file"] for e in tc_frames)
    )
    rec = guest_proc.active_recorder()
    reported = guest_proc.parse_reported_hashes(run["output"])
    for name in staged_names:
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


# No denials: the net legs are positive-only (load + run must
# observably succeed); the stale legs are sensitivity checks,
# not denial cells.
CASE_DENIALS = {}


# Durable inputs per case: absolute repo paths plus ("stage",
# basename) entries resolved against the guest stage at finish.
# Every non-board case pins the sources it depends on; a class
# with any missing file digests to zeros and can never back a
# PASS.
CASE_INPUTS = {
    "test_tc_baseline_verdicts": {
        "sources": [TC_SOURCE],
        "objects": [("stage", "tc.bpf.o")],
        "corpus": [("stage", "tc_manifest.json")],
    },
    "test_tc_mutation_flips_verdicts": {
        "sources": [TC_MUTATED],
        "objects": [("stage", "tc_mutated.bpf.o")],
        "corpus": [("stage", "tc_manifest.json")],
    },
    "test_tc_stale_object_fails": {
        "sources": [TC_SOURCE, TC_MUTATED],
        "objects": [("stage", "tc.bpf.o")],
        "corpus": [("stage", "tc_manifest.json")],
    },
    "test_guest_provenance": {
        "sources": [TC_SOURCE, TC_MUTATED,
                    ("stage", "guest_net.sh"),
                    ("stage", "tc_manifest.json")],
        "objects": [
            ("stage", "tc.bpf.o"), ("stage", "tc_mutated.bpf.o"),
        ],
        "corpus": [],
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
        suite_id="kernel-net", suite_path=__file__,
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
    print("net classifier: tc verdicts, mutant, stale checks passed")
    print("guest stage: %s (removed after the run)" % executed()["stage"])
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
