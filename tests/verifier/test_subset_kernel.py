# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""In-kernel proof for the verifier-sensitive language subset.

Builds the subset fixtures (``tests/compile/subset/subset_*.mojo``)
through the genuine pipeline (``mojo build --emit llvm`` with the
packaged SDK on the import path -> ``compiler/mojo_ir_adapter.py`` ->
``llc -mtriple=bpfel -mcpu=v3``), then boots one disposable Linux
guest and executes the kernel test-run entry
(``tests/harness/bpf_test_run.py``, contract revision 2, used as-is)
against crafted frames. An independent reimplementation of each
program's specified rule predicts every expectation; short frames
prove the guard path by taking it.

Shapes and rules (XDP_DROP is 1, XDP_PASS is 2; every guard fails
closed to XDP_DROP):

* loop_sum: drop when the frame holds at least 18 bytes and bytes
  14-17 (summed by a bounded ``for`` loop) exceed 100, else pass --
  on lanes whose verifier accepts this back-edge shape (v6.12); on
  the v6.6 lane the verifier rejects the shape at load with a pinned
  log line, which the suite asserts instead (a version boundary, not
  a skip);
* call_inline: drop when the frame holds at least 22 bytes and
  bytes 20-21 read 0xAA55 little-endian through a plain helper the
  frontend inlines, else pass;
* stack_array: drop when the frame holds at least 18 bytes and
  bytes 14-17 (staged through an initialized fixed stack array)
  sum past 200, else pass;
* casts: drop when the frame holds at least 18 bytes and bytes
  14-17 reconstruct 0x12345678 through an explicit
  narrow/widen round trip, else pass;
* checked_arith: drop when the frame holds at least 18 bytes and
  either doubling byte 14 in u8 wraps (detected against a widened
  multiply) or the u32 word at byte 14 leaves less than 200 of
  headroom, else pass;
* loop_pressure: drop when the frame holds at least 54 bytes and
  the 40-accumulator bounded mixing loop folds to an odd total,
  else pass.

The out-of-bounds store fixture passes the compile pipeline and
must be rejected by the kernel verifier at load with its predicted
log line: it writes past the end of the 8-byte map value, whose
size only the verifier knows. Staged file hashes are re-verified
inside the guest so the observed actions are tied to the exact
bytes built here.

Requires a working Mojo compiler, LLVM ``llc``, and ``vng``
(virtme-ng) with a cached guest image on PATH (default release
v6.12; MOJOBPF_VNG_RELEASE selects the matrix lane). Missing tools
fail loudly as environment failures, never as passes.

Runnable directly (``python3 tests/verifier/test_subset_kernel.py``)
or under any ``test_``-style runner. Standard library only. The
guest boot takes a few minutes under software emulation; all cases
share a single boot.
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
import guest_proc  # noqa: E402
import lane_lock  # noqa: E402
import tool_admission  # noqa: E402
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402
SUBSET_DIR = os.path.join(REPO_ROOT, "tests", "compile", "subset")
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")

XDP_DROP = 1
XDP_PASS = 2
# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = 900
MASK64 = (1 << 64) - 1

# Per-lane loop_sum verdict. The shape's bounded-``for`` back edge
# needs a 6.12-era verifier; the 6.6 verifier rejects it at load
# ("back-edge from insn 18 to 19", observed). A lane not listed here
# fails loudly until its verdict is pinned with evidence -- a new
# lane never silently inherits either branch.
LOOP_SUM_LANE = {
    "v6.12": "pass",
    "v6.6": "reject",
}
LOOP_SUM_REJECT_LOG = "back-edge from insn 18 to 19"

SHAPES = (
    "subset_loop_sum",
    "subset_call_inline",
    "subset_stack_array",
    "subset_casts",
    "subset_checked_arith",
    "subset_loop_pressure",
)

# Negative (shape, guest tag, predicted verifier log line) triple:
# the object compiles through the genuine pipeline and passes the
# IR audit, but the kernel verifier must refuse it at load.
NEGATIVES = (
    ("subset_oob_store", "oob-store",
     "invalid access to map value, value_size=8 off=8 size=8"),
)


class EnvironmentFailure(Exception):
    """The toolchain or VM needed by this test is missing or broken."""


def frame(size, patches):
    """Zero frame of `size` bytes with {offset: value} applied."""
    buf = bytearray(size)
    for offset, value in patches.items():
        buf[offset] = value
    return bytes(buf)


def loop_pressure_action(data):
    """Independent replica of the 40-accumulator mixing loop."""
    if len(data) < 54:
        return XDP_DROP
    acc = [(data[14 + k] + k) & MASK64 for k in range(40)]
    count = (len(data) & 7) + 1
    for i in range(count):
        for k in range(40):
            acc[k] = (
                acc[k] ^ (((acc[k] >> 13) + i + (k * 7 + 1)) & MASK64)
            ) & MASK64
    if (sum(acc) & MASK64) & 1 == 1:
        return XDP_DROP
    return XDP_PASS


def classify(shape, data):
    """Independent prediction of the specified rule for a shape."""
    if shape == "subset_loop_sum":
        if len(data) < 18:
            return XDP_DROP
        if sum(data[14:18]) > 100:
            return XDP_DROP
        return XDP_PASS
    if shape == "subset_call_inline":
        if len(data) < 22:
            return XDP_DROP
        if int.from_bytes(data[20:22], "little") == 0xAA55:
            return XDP_DROP
        return XDP_PASS
    if shape == "subset_stack_array":
        if len(data) < 18:
            return XDP_DROP
        if sum(data[14:18]) > 200:
            return XDP_DROP
        return XDP_PASS
    if shape == "subset_casts":
        if len(data) < 18:
            return XDP_DROP
        if int.from_bytes(data[14:18], "little") == 0x12345678:
            return XDP_DROP
        return XDP_PASS
    if shape == "subset_checked_arith":
        if len(data) < 18:
            return XDP_DROP
        byte = data[14]
        if ((byte * 2) & 0xFF) != ((byte * 2) & 0xFFFF):
            return XDP_DROP
        word = int.from_bytes(data[14:18], "little")
        if word > 0xFFFFFFFF - 200:
            return XDP_DROP
        return XDP_PASS
    if shape == "subset_loop_pressure":
        return loop_pressure_action(data)
    raise AssertionError("unknown shape: %s" % shape)


# frame key -> (size, {offset: value}).
FRAMES = {
    "ls-drop": (60, {14: 40, 15: 40, 16: 40, 17: 0}),
    "ls-pass": (60, {14: 10, 15: 10, 16: 10, 17: 10}),
    "ls-guard": (10, {}),
    "ci-drop": (60, {20: 0x55, 21: 0xAA}),
    "ci-pass": (60, {}),
    "ci-guard": (10, {}),
    "sa-drop": (60, {14: 0xFF, 15: 0xFF, 16: 0xFF, 17: 0xFF}),
    "sa-pass": (60, {14: 10, 15: 10, 16: 10, 17: 10}),
    "sa-guard": (10, {}),
    "c-drop": (60, {14: 0x78, 15: 0x56, 16: 0x34, 17: 0x12}),
    "c-pass": (60, {}),
    "c-guard": (10, {}),
    "k-pass": (60, {14: 10}),
    "k-wrap": (60, {14: 200}),
    "k-head": (60, {14: 100, 15: 0xFF, 16: 0xFF, 17: 0xFF}),
    "k-both": (60, {14: 0xFF, 15: 0xFF, 16: 0xFF, 17: 0xFF}),
    "k-guard": (10, {}),
    "p-pass": (60, {}),
    "p-drop": (100, {50: 1}),
    "p-guard": (10, {}),
}

# tag -> (shape, frame key). The tag doubles as the staged file stem.
CASES = {
    "ls-drop": ("subset_loop_sum", "ls-drop"),
    "ls-pass": ("subset_loop_sum", "ls-pass"),
    "ls-guard": ("subset_loop_sum", "ls-guard"),
    "ci-drop": ("subset_call_inline", "ci-drop"),
    "ci-pass": ("subset_call_inline", "ci-pass"),
    "ci-guard": ("subset_call_inline", "ci-guard"),
    "sa-drop": ("subset_stack_array", "sa-drop"),
    "sa-pass": ("subset_stack_array", "sa-pass"),
    "sa-guard": ("subset_stack_array", "sa-guard"),
    "c-drop": ("subset_casts", "c-drop"),
    "c-pass": ("subset_casts", "c-pass"),
    "c-guard": ("subset_casts", "c-guard"),
    "k-pass": ("subset_checked_arith", "k-pass"),
    "k-wrap": ("subset_checked_arith", "k-wrap"),
    "k-head": ("subset_checked_arith", "k-head"),
    "k-both": ("subset_checked_arith", "k-both"),
    "k-guard": ("subset_checked_arith", "k-guard"),
    "p-pass": ("subset_loop_pressure", "p-pass"),
    "p-drop": ("subset_loop_pressure", "p-drop"),
    "p-guard": ("subset_loop_pressure", "p-guard"),
}

# Tags whose frames are too short for the shape's loads: the observed
# action must come from the guard path.
GUARD_TAGS = (
    "ls-guard",
    "ci-guard",
    "sa-guard",
    "c-guard",
    "k-guard",
    "p-guard",
)

# tag prefix -> shape test name, for per-shape assertions.
SHAPE_TAGS = {
    "subset_loop_sum": ("ls-", "test_loop_sum"),
    "subset_call_inline": ("ci-", "test_call_inline"),
    "subset_stack_array": ("sa-", "test_stack_array"),
    "subset_casts": ("c-", "test_casts"),
    "subset_checked_arith": ("k-", "test_checked_arith"),
    "subset_loop_pressure": ("p-", "test_loop_pressure"),
}


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
echo "=== begin guest_subset ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "=== staged hashes ==="
sha256sum {hash_files}
run_case() {{
  tag="$1"; obj="$2"; expect="$3"; data="$4"
  out="/tmp/sub-$tag.json"
  pin="/sys/fs/bpf/mojobpf-sub-$tag/prog"
  mkdir -p "/sys/fs/bpf/mojobpf-sub-$tag"
  python3 bpf_test_run.py --object "$obj" --expect-action "$expect" \\
    --data-in "$data" {harness_flags} --output "$out" >/tmp/sub-$tag.stdout 2>/tmp/sub-$tag.stderr
  code=$?
  rm -f "$pin"
  rmdir "/sys/fs/bpf/mojobpf-sub-$tag" 2>/dev/null
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
if ls /sys/fs/bpf/mojobpf_control 2>&1; then echo "PIN STILL PRESENT"; else echo "pin absent (unloaded)"; fi
for pin in /sys/fs/bpf/mojobpf-sub-*; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; fi
done
echo "=== end guest_subset ==="
"""


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
    for path in (ADAPTER, HARNESS):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    for shape in list(SHAPES) + [neg[0] for neg in NEGATIVES]:
        source = os.path.join(SUBSET_DIR, shape + ".mojo")
        if not os.path.isfile(source):
            raise EnvironmentFailure("missing fixture: %s" % source)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK directory: %s" % SDK_INCLUDE)
    stage = guest_proc.owned_stage(prefix="mojo-subset-", dir="/tmp")
    staged = {"bpf_test_run.py": HARNESS}
    for shape in list(SHAPES) + [neg[0] for neg in NEGATIVES]:
        source = os.path.join(SUBSET_DIR, shape + ".mojo")
        staged[shape + ".bpf.o"] = build_object(source, stage, shape)
    packets = {}
    for key, (size, patches) in FRAMES.items():
        packets[key] = frame(size, patches)
    for key, data in packets.items():
        with open(os.path.join(stage, key + ".bin"), "wb") as handle:
            handle.write(data)
    for name, src in staged.items():
        with guest_proc.open_consumed(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    commands = []
    for tag in sorted(CASES):
        shape, key = CASES[tag]
        commands.append(
            "run_case %s %s.bpf.o %d %s.bin"
            % (tag, shape, classify(shape, packets[key]), key)
        )
    for neg_shape, neg_tag, _log in NEGATIVES:
        commands.append(
            "run_case %s %s.bpf.o %d ls-pass.bin"
            % (neg_tag, neg_shape, XDP_PASS)
        )
    hash_files = " ".join(
        ["bpf_test_run.py"]
        + [shape + ".bpf.o" for shape in list(SHAPES) + [neg[0] for neg in NEGATIVES]]
        + [key + ".bin" for key in sorted(packets)]
        + ["guest_subset.sh"]
    )
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
        stage=stage, commands="\n".join(commands), hash_files=hash_files,
        bpftool_prologue=(
            tool_admission.render_prologue(pins)
            + "\n"
            + tool_admission.render_guest_mount()
        ),
        harness_flags=tool_admission.render_harness_flags(
            pins, pin_path="$pin", owned_root="/sys/fs/bpf",
            ownership_token="mojobpf-sub-$tag",
        ),
    )
    script_path = os.path.join(stage, "guest_subset.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + [key + ".bin" for key in packets]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(os.path.join(stage, "guest_subset.sh"), 0o644)
    os.chmod(stage, 0o755)
    # A1 guest handoff: consume the staged bytes through the recorder
    # and re-stage from the consumed buffers, so the guest-reported
    # hashes compare against an attested identity.
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        tuple(staged) + tuple(key + ".bin" for key in packets)
        + ("guest_subset.sh",),
    )
    returncode, output = _run_guest(
        ["vng", "--run", VNG_RELEASE, *guest_proc.vng_accelerator_argv(),
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
        progress_banner="=== begin guest_subset ===",
    )
    if verdict == "proof":
        raise AssertionError(
            "vng guest run failed with proof evidence "
            "(exit %d, stage %s):\n%s"
            % (returncode, stage, output[-4000:])
        )
    if verdict == "env":
        raise EnvironmentFailure(
            "vng guest run failed (exit %d, stage %s):\n%s"
            % (returncode, stage, output[-4000:])
        )
    # Retain the raw guest transcript (per-case BEGIN/END JSON)
    # alongside the staged inputs so observed actions stay auditable
    # after the run; the stage directory is never cleaned by the
    # suite itself.
    transcript_path = os.path.join(stage, "guest_transcript.log")
    with open(transcript_path, "w", encoding="utf-8") as handle:
        handle.write(output)
    print("guest transcript: %s" % transcript_path)
    missing = [tag for tag in list(CASES) + [neg[1] for neg in NEGATIVES]
               if tag not in results]
    if missing:
        raise guest_proc.GuestMissing(
            "guest run missed cases %r (stage %s)" % (missing, stage)
        )
    return {"results": results, "output": output, "stage": stage,
            "packets": packets}


_EXECUTED = None


def executed():
    global _EXECUTED
    if _EXECUTED is None:
        _EXECUTED = guest_run()
    return _EXECUTED


def check_shape(shape):
    run = executed()
    prefix = SHAPE_TAGS[shape][0]
    matched = 0
    for tag in sorted(CASES):
        if not tag.startswith(prefix):
            continue
        case_shape, key = CASES[tag]
        assert case_shape == shape
        expected = classify(shape, run["packets"][key])
        record = run["results"][tag]
        guest_proc.check_harness_exit(
            tag, exit=record["_harness_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=0)
        assert record.get("actual_action") == expected, (
            "%s: observed %r, predicted %r"
            % (tag, record.get("actual_action"), expected)
        )
        if tag in GUARD_TAGS:
            assert expected == XDP_DROP, (
                "%s: guard path must fail closed" % tag
            )
        matched += 1
    assert matched > 0, "no cases matched shape %s" % shape
    print("PASS %s: %d/%d predicted==observed" % (shape, matched, matched))
    return matched


def check_rejected(shape, log_line):
    """Assert every case of `shape` fails at load with `log_line`."""
    run = executed()
    prefix = SHAPE_TAGS[shape][0]
    matched = 0
    for tag in sorted(CASES):
        if not tag.startswith(prefix):
            continue
        case_shape, _key = CASES[tag]
        assert case_shape == shape
        record = run["results"][tag]
        guest_proc.check_harness_exit(
            tag, exit=record["_harness_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=4)
        assert record.get("stage") == "load", (
            "%s: expected load stage" % tag
        )
        assert record.get("classification") == "verifier", (
            "%s: expected verifier classification, got %r"
            % (tag, record.get("classification"))
        )
        blob = json.dumps(record.get("commands", []))
        assert log_line in blob, (
            "%s: kernel verifier log must contain %r" % (tag, log_line)
        )
        matched += 1
    assert matched > 0, "no cases matched shape %s" % shape
    print(
        "PASS %s: %d/%d rejected by verifier (%r)"
        % (shape, matched, matched, log_line)
    )
    return matched


def test_loop_sum():
    mode = LOOP_SUM_LANE.get(VNG_RELEASE)
    if mode is None:
        raise EnvironmentFailure(
            "pin the loop_sum verdict for release %s with evidence; "
            "refusing to guess" % VNG_RELEASE
        )
    if mode == "pass":
        assert check_shape("subset_loop_sum") == 3
    else:
        assert (
            check_rejected("subset_loop_sum", LOOP_SUM_REJECT_LOG) == 3
        )


def test_call_inline():
    assert check_shape("subset_call_inline") == 3


def test_stack_array():
    assert check_shape("subset_stack_array") == 3


def test_casts():
    assert check_shape("subset_casts") == 3


def test_checked_arith():
    assert check_shape("subset_checked_arith") == 5


def test_loop_pressure():
    assert check_shape("subset_loop_pressure") == 3


def test_oob_store_rejected_by_verifier():
    """A write past the map value: only the verifier knows its size."""
    run = executed()
    _shape, tag, log_line = NEGATIVES[0]
    record = run["results"][tag]
    hint = guest_proc.check_harness_exit(
        tag, exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=4)
    assert record.get("stage") == "load", "%s: expected load stage" % tag
    assert record.get("classification") == "verifier", (
        "%s: expected verifier classification, got %r"
        % (tag, record.get("classification"))
    )
    blob = json.dumps(record.get("commands", []))
    assert log_line in blob, (
        "%s: kernel verifier log must contain %r" % (tag, log_line)
    )
    print("PASS %s rejected by verifier (%r)" % (tag, log_line))
    return hint


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
    for tag in [neg[1] for neg in NEGATIVES]:
        record = run["results"][tag]
        assert record.get("contract_version") == 2, (
            "%s: harness contract must be revision 2" % tag
        )
        assert record.get("cleanup_ok") is None, (
            "%s: harness must leave cleanup_ok unset" % tag
        )
    for tag in sorted(CASES):
        record = run["results"][tag]
        assert record.get("contract_version") == 2, (
            "%s: harness contract must be revision 2" % tag
        )
    names = (
        ["bpf_test_run.py"]
        + [shape + ".bpf.o" for shape in list(SHAPES) + [neg[0] for neg in NEGATIVES]]
        + [key + ".bin" for key in sorted(run["packets"])]
        + ["guest_subset.sh"]
    )
    rec = guest_proc.active_recorder()
    reported = guest_proc.parse_reported_hashes(run["output"])
    for name in names:
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
    print("PASS guest provenance (%d hashes)" % len(names))


# The out-of-bounds store case is a denial: it expects the
# wire-derived FAIL at VERIFY and passes only its own cell when
# the rejection is observed with evidence. It guards a
# representative positive load on the same harness path: the
# lane must accept good shapes while observably rejecting the
# bad one, proving the verifier oracle is not vacuous.
CASE_DENIALS = {
    "test_oob_store_rejected_by_verifier": (
        "test_call_inline", "VERIFY"
    ),
}


def _shape_source(shape):
    return os.path.join(SUBSET_DIR, shape + ".mojo")


def _shape_bins(shape):
    prefix = SHAPE_TAGS[shape][0]
    return [
        ("stage", CASES[tag][1] + ".bin")
        for tag in sorted(CASES)
        if tag.startswith(prefix)
    ]


def _all_shapes():
    return list(SHAPES) + [neg[0] for neg in NEGATIVES]


# Durable inputs per case: shape sources plus the staged objects
# and packet frames each case consumes (resolved against the
# guest stage at finish).
CASE_INPUTS = {
    "test_loop_sum": {
        "sources": [_shape_source("subset_loop_sum")],
        "objects": [("stage", "subset_loop_sum.bpf.o")],
        "corpus": _shape_bins("subset_loop_sum"),
    },
    "test_call_inline": {
        "sources": [_shape_source("subset_call_inline")],
        "objects": [("stage", "subset_call_inline.bpf.o")],
        "corpus": _shape_bins("subset_call_inline"),
    },
    "test_stack_array": {
        "sources": [_shape_source("subset_stack_array")],
        "objects": [("stage", "subset_stack_array.bpf.o")],
        "corpus": _shape_bins("subset_stack_array"),
    },
    "test_casts": {
        "sources": [_shape_source("subset_casts")],
        "objects": [("stage", "subset_casts.bpf.o")],
        "corpus": _shape_bins("subset_casts"),
    },
    "test_checked_arith": {
        "sources": [_shape_source("subset_checked_arith")],
        "objects": [("stage", "subset_checked_arith.bpf.o")],
        "corpus": _shape_bins("subset_checked_arith"),
    },
    "test_loop_pressure": {
        "sources": [_shape_source("subset_loop_pressure")],
        "objects": [("stage", "subset_loop_pressure.bpf.o")],
        "corpus": _shape_bins("subset_loop_pressure"),
    },
    "test_oob_store_rejected_by_verifier": {
        "sources": [_shape_source("subset_oob_store")],
        "objects": [("stage", "subset_oob_store.bpf.o")],
        "corpus": [("stage", "ls-pass.bin")],
    },
    "test_guest_provenance": {
        "sources": [
            _shape_source(shape) for shape in _all_shapes()
        ] + [HARNESS, ("stage", "guest_subset.sh")],
        "objects": [
            ("stage", shape + ".bpf.o") for shape in _all_shapes()
        ],
        "corpus": [
            ("stage", key + ".bin") for key in sorted(FRAMES)
        ],
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
        suite_id="verifier-subset", suite_path=__file__,
        case_ids=names,
        denials=CASE_DENIALS, inputs=CASE_INPUTS,
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
    matched = 0
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
            matched += 1
    if failures or unavailable_seen:
        return _finish(rec, unavailable_seen)
    if LOOP_SUM_LANE.get(VNG_RELEASE) == "reject":
        print(
            "subset kernel: %d tests green, 17/17 predicted==observed, "
            "4/4 verifier rejections (3 loop_sum lane pins + oob)"
            % matched
        )
    else:
        print(
            "subset kernel: %d tests green, 20/20 predicted==observed, "
            "1/1 verifier rejection" % matched
        )
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
