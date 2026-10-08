# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Kernel proof for the single-subprogram call shape (vng guest suite).

Builds the decision program (``examples/subprog_call/decision.mojo``,
callee defined first), the entry-first twin
(``tests/compile/subprog_entry_first.mojo``), and the call-free
inverted mutant (``examples/subprog_call/decision_mutated.mojo``)
through the genuine pipeline (``mojo build --emit llvm`` with the
packaged SDK on the import path -> ``compiler/mojo_ir_adapter.py``
-> ``llc -mtriple=bpfel -mcpu=v3``), stages the objects with the
frozen ``bpf_test_run`` harness plus the three packet fixtures,
and executes ten load/test-run/unload cases plus a verifier-log
capture, one kernel-negative load, and a residue sweep in one
disposable vng guest.

The suite proves, per lane it runs on:

* the base board: the drop fixture returns 1 (XDP_DROP), the
  pass and short fixtures return 2 (XDP_PASS), with distinct
  actions across the two full-size fixtures, so the callee
  computes an input-dependent result through the call rather
  than dead code;
* the mutant board: the rebuilt call-free mutant returns 2/1/2
  on the same fixtures, so removing the call changes the
  observed behavior on both full-size frames;
* the entry-first twin matches the base rule on both full-size
  fixtures, so both definition orders execute, not just
  validate;
* staleness: the base object under mutated expectations fails
  with a runtime mismatch (exit 1), proving the suite notices;
* the verifier log (captured with ``bpftool -d prog load`` on a
  successful load) shows the subprogram: ``func#0``/``func#1``,
  the relocated ``call pc+1`` against the ``decide`` subprogram,
  and the caller/callee frames; the translated dump carries
  both functions;
* the kernel negative: a post-adapter mutant of the decision
  object with a null-pointer load hand-injected into the callee
  (test provenance, never adapter-emitted) clears host-side
  inspection, and the kernel verifier rejects it at load with a
  program-load log naming the invalid-access class after
  descending into the callee (libbpf relays the kernel log, so
  libbpf itself clears); the raw log is preserved for
  independent review;
* FD lifecycle: every case reports ``cleanup_ok``, both pins
  are absent afterwards, and the final program/map listing
  carries none of our names;
* provenance: the guest kernel matches the requested release,
  staged hashes re-verify in-guest, and the staged object bytes
  equal the ELF-suite pins (both build paths agree);
* the license gate agrees with the kernel: the call objects
  inspect clean under ``linux-bpfel-v3-subprog`` and are refused
  under the base profile, the empty helper set preflights, the
  helper-35 witness stays refused, and the call-free mutant
  inspects clean under the base profile.

The guest release comes from ``MOJOBPF_VNG_RELEASE`` (``v6.12``
by default); the suite runs unmodified on every x86 lane by
direct runs. Only the vng guest performs BPF loads; the host
only builds objects and parses transcripts. The guest boots as
a session leader, so a timeout kills the whole owned guest
tree, never just the direct child.

Runnable directly
(``python3 tests/kernel/test_subprog_calls.py``) or under any
``test_``-style runner. The 16-entry CI matrix in
``ci/run_vm_tests.py`` is frozen: this suite is proven by
direct runs and is not wired there. Standard library only.
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
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf.inspect import (  # noqa: E402
    inspect_object,
    preflight_helper_licenses,
)

APACHE = "Apache-2.0 WITH LLVM-exception"
BASE_PROFILE = "linux-bpfel-v3"
SUBPROG_PROFILE = "linux-bpfel-v3-subprog"

EXAMPLE_DIR = os.path.join(REPO_ROOT, "examples", "subprog_call")
BASE_SOURCE = os.path.join(EXAMPLE_DIR, "decision.mojo")
MUTATED_SOURCE = os.path.join(EXAMPLE_DIR, "decision_mutated.mojo")
ENTRY_FIRST_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "subprog_entry_first.mojo"
)
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")
FIXTURES = ("pkt_drop.bin", "pkt_pass.bin", "pkt_short.bin")

# Object pins: the decision and entry-first objects must equal the
# ELF-suite pins byte-for-byte (both build paths agree); the
# mutant object is pinned here (no ELF-suite entry exists).
DECISION_OBJECT_HASH = (
    "6bc42a7e1cbd90befb7f01a2a4a2a4d0442561792f46248cce9afb3e404b8b56"
)
ENTRY_FIRST_OBJECT_HASH = (
    "c62683ac82ac5f62cf704f9e921855d218459e663bff1a504b2b887d1d583115"
)
MUTATED_OBJECT_HASH = (
    "126f2bcb619e1f7e5ef3ab334172ca247b99452e4ee93f91a44272b2e3e915fe"
)
ADV_NULL_LOAD_OBJECT_HASH = (
    "71bfe3282891cc79d00aac2d3749c65c6b139c8fd3bc395fb29fbccfadca6479"
)

# Kernel-negative provenance: (tag, [(old, new, expected_count)]).
# The null-load mutant is a post-adapter textual mutation of the
# pinned-good adapted IR: the F1 bypass shape (a constant-operand
# load in the callee) hand-injected after the adapter ran. The
# adapter never emits it -- post-fix the audit refuses the
# pre-adapter shape (pinned by the subprog_callee_load_null.ll
# corpus fixture), so this IR is unreachable from the genuine
# path. Counts are asserted so silent IR drift fails loudly.
ADV_MUTANT = (
    "callee-null-load",
    [
        (
            "  %4 = select i1 %3, i64 1, i64 2\n"
            "  ret i64 %4\n",
            "  %4 = select i1 %3, i64 1, i64 2\n"
            "  %5 = load i64, ptr null\n"
            "  %6 = add i64 %4, %5\n"
            "  ret i64 %6\n",
            1,
        ),
    ],
)

# High-level kernel rejection class for the null-load mutant (never
# a whole message, per the spec): the verifier must name an invalid
# memory access. Observed on both lanes; the raw log is preserved
# in the record for independent review.
ADV_NULL_REJECT_CLASS = "invalid mem access"

VNG_TIMEOUT = 1500
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")

XDP_DROP = 1
XDP_PASS = 2


class EnvironmentFailure(Exception):
    """The toolchain or guest needed by this test is missing."""


def check_release():
    release = VNG_RELEASE
    if not re.fullmatch(r"v6\.\d+", release or ""):
        raise EnvironmentFailure(
            "MOJOBPF_VNG_RELEASE must look like v6.12, got %r" % release
        )
    return release


def run_step(argv, timeout=600):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_object(source, workdir, name):
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(
        [
            "mojo", "build", "--emit", "llvm",
            "-I", SDK_INCLUDE, "-o", raw_path, source,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise AssertionError(
            "frontend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    if proc.stderr != "":
        raise AssertionError(
            "frontend stderr must be empty for %s, got %r"
            % (source, proc.stderr[:500])
        )
    proc = run_step(
        [sys.executable, ADAPTER, "--input", raw_path,
         "--output", adapted_path]
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


def build_mutant_object(source, workdir, name):
    """Build the kernel-negative object from hand-mutated IR.

    Runs the genuine frontend and adapter, then applies the
    ADV_MUTANT textual replacement to a copy of the adapted IR
    (counts asserted) and compiles the mutant with llc. The
    mutant IR never passes through the adapter: it is test
    provenance, not a tool output.
    """
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    mutant_path = os.path.join(workdir, name + ".mutant.bpf.ll")
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(
        [
            "mojo", "build", "--emit", "llvm",
            "-I", SDK_INCLUDE, "-o", raw_path, source,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise AssertionError(
            "frontend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    if proc.stderr != "":
        raise AssertionError(
            "frontend stderr must be empty for %s, got %r"
            % (source, proc.stderr[:500])
        )
    proc = run_step(
        [sys.executable, ADAPTER, "--input", raw_path,
         "--output", adapted_path]
    )
    if proc.returncode != 0 or not os.path.isfile(adapted_path):
        raise AssertionError(
            "adapter failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    with open(adapted_path, encoding="utf-8") as handle:
        adapted = handle.read()
    tag, replacements = ADV_MUTANT
    for old, new, expected in replacements:
        found = adapted.count(old)
        assert found == expected, (
            "mutant %s: anchor found %d times, expected %d "
            "(adapted IR drifted)" % (tag, found, expected)
        )
        adapted = adapted.replace(old, new)
    assert "load i64, ptr null" in adapted, (
        "mutant %s: injected load missing" % tag
    )
    with open(mutant_path, "w", encoding="utf-8") as handle:
        handle.write(adapted)
    proc = run_step(
        [
            "llc",
            "-mtriple=bpfel",
            "-mcpu=v3",
            "-filetype=obj",
            mutant_path,
            "-o",
            object_path,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "backend failed for mutant %s (exit %d):\n%s\n%s"
            % (tag, proc.returncode, proc.stdout, proc.stderr)
        )
    return object_path


def classify(frame):
    if len(frame) < 15:
        return XDP_PASS
    if frame[14] & 1:
        return XDP_DROP
    return XDP_PASS


def classify_mutated(frame):
    if len(frame) < 15:
        return XDP_PASS
    if frame[14] & 1:
        return XDP_PASS
    return XDP_DROP


GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin guest_subprog ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
bpftool version | head -2
echo "=== staged hashes ==="
sha256sum bpf_test_run.py base.bpf.o mutated.bpf.o entry_first.bpf.o adv_null_load.bpf.o pkt_drop.bin pkt_pass.bin pkt_short.bin
run_case() {{
  tag="$1"; obj="$2"; expect="$3"; data="$4"
  out="/tmp/subprog-$tag.json"
  python3 bpf_test_run.py --object "$obj" --expect-action "$expect" \\
    --data-in "$data" --output "$out" >/tmp/subprog-$tag.stdout 2>/tmp/subprog-$tag.stderr
  code=$?
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
run_vlog() {{
  bpftool -d prog load base.bpf.o /sys/fs/bpf/mojobpf_vlog >/tmp/vlog.load 2>&1
  code=$?
  bpftool prog dump xlated pinned /sys/fs/bpf/mojobpf_vlog >/tmp/vlog.xlated 2>&1
  bpftool prog show pinned /sys/fs/bpf/mojobpf_vlog >/tmp/vlog.show 2>&1
  rm -f /sys/fs/bpf/mojobpf_vlog
  python3 - "$code" <<'PYEOF'
import json
import sys
code = int(sys.argv[1])
def slurp(path):
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()
load = slurp("/tmp/vlog.load")
xlated = slurp("/tmp/vlog.xlated")
show = slurp("/tmp/vlog.show")
record = {{
  "load_exit": code,
  "markers": {{
    "func0": "func#0 @0" in load,
    "func1": "func#1 @" in load,
    "caller_callee": ("caller:" in load and "callee:" in load),
    "frame1": "frame1:" in load,
    "returning": "returning from callee:" in load,
    "relocated": "points to subprog 'decide'" in load,
    "added_subprog": "from sub-prog 'decide'" in load,
    "call_pc1": "(85) call pc+1" in load,
  }},
  "xlated_has_callee": ("r1 &= 1" in xlated),
  "xlated_has_call": ("call pc+1" in xlated),
  "xlated": xlated,
  "show": show,
  "log_tail": load[-3000:],
}}
with open("/tmp/subprog-vlog.json", "w", encoding="utf-8") as handle:
    handle.write(json.dumps(record, indent=2, sort_keys=True) + chr(10))
PYEOF
  echo "=== BEGIN vlog exit=$code ==="
  cat /tmp/subprog-vlog.json
  echo "=== END vlog ==="
}}
run_adv_null() {{
  bpftool prog load adv_null_load.bpf.o /sys/fs/bpf/mojobpf_adv_null >/tmp/adv-null.log 2>&1
  code=$?
  rm -f /sys/fs/bpf/mojobpf_adv_null
  python3 - "$code" <<'PYEOF'
import json
import sys
code = int(sys.argv[1])
with open("/tmp/adv-null.log", encoding="utf-8", errors="replace") as handle:
    load = handle.read()
record = {{
  "load_exit": code,
  "markers": {{
    "reject_class": "__REJECT_CLASS__" in load,
    "in_callee": "callee:" in load,
    "verifier_log": "-- BEGIN PROG LOAD LOG --" in load,
  }},
  "log_tail": load[-3000:],
}}
with open("/tmp/subprog-adv-null.json", "w", encoding="utf-8") as handle:
    handle.write(json.dumps(record, indent=2, sort_keys=True) + chr(10))
PYEOF
  echo "=== BEGIN adv-null exit=$code ==="
  cat /tmp/subprog-adv-null.json
  echo "=== END adv-null ==="
}}
run_residue() {{
  bpftool prog show >/tmp/residue.prog 2>&1
  bpftool map show >/tmp/residue.map 2>&1
  python3 - <<'PYEOF'
import json
def slurp(path):
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()
record = {{
  "prog_show": slurp("/tmp/residue.prog"),
  "map_show": slurp("/tmp/residue.map"),
}}
with open("/tmp/subprog-residue.json", "w", encoding="utf-8") as handle:
    handle.write(json.dumps(record, indent=2, sort_keys=True) + chr(10))
PYEOF
  echo "=== BEGIN residue exit=0 ==="
  cat /tmp/subprog-residue.json
  echo "=== END residue ==="
}}
{commands}
echo "=== pin check ==="
if ls /sys/fs/bpf/mojobpf_control 2>&1; then echo "PIN STILL PRESENT"; else echo "pin absent (unloaded)"; fi
if ls /sys/fs/bpf/mojobpf_vlog 2>&1; then echo "VLOG PIN STILL PRESENT"; else echo "vlog pin absent (unloaded)"; fi
if ls /sys/fs/bpf/mojobpf_adv_null 2>&1; then echo "ADV PIN STILL PRESENT"; else echo "adv pin absent (unloaded)"; fi
echo "=== end guest_subprog ==="
"""

CASES = (
    # tag, object, expectation fn, packet, required harness exit
    ("base-drop", "base.bpf.o", classify, "pkt_drop.bin", 0),
    ("base-pass", "base.bpf.o", classify, "pkt_pass.bin", 0),
    ("base-short", "base.bpf.o", classify, "pkt_short.bin", 0),
    ("mut-drop", "mutated.bpf.o", classify_mutated, "pkt_drop.bin", 0),
    ("mut-pass", "mutated.bpf.o", classify_mutated, "pkt_pass.bin", 0),
    ("mut-short", "mutated.bpf.o", classify_mutated, "pkt_short.bin", 0),
    ("order-drop", "entry_first.bpf.o", classify, "pkt_drop.bin", 0),
    ("order-pass", "entry_first.bpf.o", classify, "pkt_pass.bin", 0),
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
            "guest run timed out after %ds (stage kept at %s):\n%s"
            % (timeout, stage, exc.output[-4000:])
        )


def guest_run():
    """Build all objects, boot one guest, return parsed results."""
    release = check_release()
    for tool in ("mojo", "llc", "vng"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (
        BASE_SOURCE, MUTATED_SOURCE, ENTRY_FIRST_SOURCE,
        ADAPTER, SDK_INCLUDE, HARNESS,
    ):
        if not os.path.exists(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    for fixture in FIXTURES:
        if not os.path.isfile(os.path.join(EXAMPLE_DIR, fixture)):
            raise EnvironmentFailure("missing fixture: %s" % fixture)
    stage = tempfile.mkdtemp(prefix="subprog-calls-", dir="/tmp")
    packets = {}
    for fixture in FIXTURES:
        with open(os.path.join(EXAMPLE_DIR, fixture), "rb") as handle:
            packets[fixture] = handle.read()
    base_obj = build_object(BASE_SOURCE, stage, "base")
    mutated_obj = build_object(MUTATED_SOURCE, stage, "mutated")
    entry_first_obj = build_object(ENTRY_FIRST_SOURCE, stage, "entry_first")
    adv_null_obj = build_mutant_object(
        BASE_SOURCE, stage, "adv_null_load"
    )
    staged = {
        "bpf_test_run.py": HARNESS,
        "base.bpf.o": base_obj,
        "mutated.bpf.o": mutated_obj,
        "entry_first.bpf.o": entry_first_obj,
        "adv_null_load.bpf.o": adv_null_obj,
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
            'run_case %s %s %d %s'
            % (tag, obj, expect_fn(packets[packet]), packet)
        )
    commands.append("run_vlog")
    commands.append("run_adv_null")
    commands.append("run_residue")
    script = GUEST_SCRIPT.format(
        stage=stage, commands="\n".join(commands)
    ).replace("__REJECT_CLASS__", ADV_NULL_REJECT_CLASS)
    script_path = os.path.join(stage, "guest_subprog.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["guest_subprog.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    exit_code, output = _run_guest(
        [
            "vng", "--run", release, "--disable-kvm",
            "--exec", "bash %s" % script_path,
        ],
        stage,
        VNG_TIMEOUT,
    )
    if exit_code != 0:
        raise EnvironmentFailure(
            "vng guest run failed (exit %d, stage kept at %s):\n%s"
            % (exit_code, stage, output[-4000:])
        )
    results = {}
    for match in re.finditer(
        r"=== BEGIN (\S+) exit=(\d+) ===\n(.*?)\n=== END \1 ===",
        output,
        re.DOTALL,
    ):
        tag, exit_text, body = match.groups()
        try:
            record = json.loads(body)
        except ValueError:
            raise EnvironmentFailure(
                "guest case %s produced invalid JSON (stage %s):\n%s"
                % (tag, stage, body[-1000:])
            )
        record["_harness_exit"] = int(exit_text)
        results[tag] = record
    wanted = (
        [tag for tag, _, _, _, _ in CASES]
        + ["vlog", "adv-null", "residue"]
    )
    missing = [tag for tag in wanted if tag not in results]
    if missing:
        raise EnvironmentFailure(
            "guest output lacks cases %s (stage kept at %s):\n%s"
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


def _case_record(tag):
    record = executed()["results"][tag]
    assert record["_harness_exit"] == 0, (
        "%s: harness exit %d (%s/%s)"
        % (
            tag,
            record["_harness_exit"],
            record.get("stage"),
            record.get("classification"),
        )
    )
    return record


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
    observed = {}
    for tag in ("base-drop", "base-pass", "base-short"):
        observed[tag] = _case_record(tag)["actual_action"]
    assert observed["base-drop"] == XDP_DROP, "drop fixture must drop"
    assert observed["base-pass"] == XDP_PASS, "pass fixture must pass"
    assert observed["base-short"] == XDP_PASS, "short fixture must pass"
    assert observed["base-drop"] != observed["base-pass"], (
        "the two full-size fixtures must produce distinct actions"
    )


def test_mutation_changes_behavior():
    run = executed()
    for tag in ("mut-drop", "mut-pass", "mut-short"):
        _case_record(tag)
    assert run["results"]["mut-drop"]["actual_action"] == XDP_PASS
    assert run["results"]["mut-pass"]["actual_action"] == XDP_DROP
    assert run["results"]["mut-short"]["actual_action"] == XDP_PASS
    assert run["results"]["mut-drop"]["actual_action"] != run["results"][
        "base-drop"
    ]["actual_action"], "rebuilt mutant must change the drop action"
    assert run["results"]["mut-pass"]["actual_action"] != run["results"][
        "base-pass"
    ]["actual_action"], "rebuilt mutant must change the pass action"


def test_entry_first_matches_base():
    run = executed()
    for tag in ("order-drop", "order-pass"):
        _case_record(tag)
    assert run["results"]["order-drop"]["actual_action"] == XDP_DROP
    assert run["results"]["order-pass"]["actual_action"] == XDP_PASS


def test_stale_object_fails():
    run = executed()
    for tag, old_action in (("stale-drop", XDP_DROP), ("stale-pass", XDP_PASS)):
        record = run["results"][tag]
        assert record["_harness_exit"] == 1, (
            "%s: stale object must fail with a runtime mismatch (exit 1), "
            "got exit %d (%s/%s)"
            % (
                tag,
                record["_harness_exit"],
                record.get("stage"),
                record.get("classification"),
            )
        )
        assert record["classification"] == "runtime", (
            "%s: expected runtime classification, got %r"
            % (tag, record.get("classification"))
        )
        assert record["actual_action"] == old_action, (
            "%s: stale object must still produce its old action %d, got %r"
            % (tag, old_action, record.get("actual_action"))
        )


def test_verifier_log_shows_subprogram():
    record = executed()["results"]["vlog"]
    assert record["_harness_exit"] == 0, (
        "verifier-log load must succeed, got exit %d" % record["_harness_exit"]
    )
    assert record["load_exit"] == 0, "bpftool load must succeed"
    for marker, present in sorted(record["markers"].items()):
        assert present is True, (
            "verifier log lacks the %r subprogram marker:\n%s"
            % (marker, record["log_tail"])
        )
    assert record["xlated_has_callee"] is True, (
        "translated dump lacks the callee body:\n%s" % record["log_tail"]
    )
    assert record["xlated_has_call"] is True, (
        "translated dump lacks the static call:\n%s" % record["log_tail"]
    )
    assert "r1 &= 1" in record["xlated"], (
        "retained dump must show the callee body"
    )
    assert "call pc+1" in record["xlated"], (
        "retained dump must show the static call"
    )
    assert "xdp_entry" in record["show"], (
        "program show must name the entrypoint: %r" % record["show"]
    )


def test_kernel_rejects_callee_null_load():
    run = executed()
    path = os.path.join(run["stage"], "adv_null_load.bpf.o")
    report = inspect_object(path, SUBPROG_PROFILE)
    assert report.ok, (
        "the null-load mutant must clear host-side inspection "
        "so the kernel verifier is its first rejecting layer",
        report.structural + report.unsupported + report.license,
    )
    record = run["results"]["adv-null"]
    assert record["_harness_exit"] != 0, (
        "the null-load mutant must fail to load"
    )
    assert record["load_exit"] != 0, (
        "bpftool load must fail for the null-load mutant"
    )
    for marker, present in sorted(record["markers"].items()):
        assert present is True, (
            "null-load rejection lacks the %r marker:\n%s"
            % (marker, record["log_tail"])
        )


def test_fd_lifecycle_and_residue():
    run = executed()
    for tag, _, _, _, _ in CASES:
        record = run["results"][tag]
        assert record.get("cleanup_ok") is True, (
            "%s: harness must report cleanup_ok" % tag
        )
    assert "pin absent (unloaded)" in run["output"], "pin must be removed"
    assert "vlog pin absent (unloaded)" in run["output"], (
        "vlog pin must be removed"
    )
    assert "adv pin absent (unloaded)" in run["output"], (
        "adv pin must be removed"
    )
    assert "PIN STILL PRESENT" not in run["output"], "pin must be removed"
    assert "VLOG PIN STILL PRESENT" not in run["output"], (
        "vlog pin must be removed"
    )
    assert "ADV PIN STILL PRESENT" not in run["output"], (
        "adv pin must be removed"
    )
    residue = run["results"]["residue"]
    for field in ("prog_show", "map_show"):
        for name in ("xdp_entry", "decide", "mojobpf"):
            assert name not in residue[field], (
                "residue %s still names %r:\n%s"
                % (field, name, residue[field])
            )


def test_guest_provenance():
    run = executed()
    try:
        observed_kernel = lane_lock.booted_kernel_from_output(run["output"])
        lane_lock.check_booted_kernel(
            observed_kernel, REPO_ROOT, check_release()
        )
    except lane_lock.LaneLockError as exc:
        raise AssertionError("guest kernel must be locked: %s" % exc)
    for tag, _, _, _, _ in CASES:
        record = run["results"][tag]
        assert record.get("contract_version") == 2, (
            "%s: harness contract must be revision 2" % tag
        )
    for name in (
        "bpf_test_run.py",
        "base.bpf.o",
        "mutated.bpf.o",
        "entry_first.bpf.o",
        "adv_null_load.bpf.o",
        "pkt_drop.bin",
        "pkt_pass.bin",
        "pkt_short.bin",
    ):
        expected = sha256_file(os.path.join(run["stage"], name))
        assert expected in run["output"], (
            "guest must re-verify staged hash of %s" % name
        )


def test_object_hashes():
    run = executed()
    assert sha256_file(os.path.join(run["stage"], "base.bpf.o")) == (
        DECISION_OBJECT_HASH
    )
    assert sha256_file(
        os.path.join(run["stage"], "entry_first.bpf.o")
    ) == ENTRY_FIRST_OBJECT_HASH
    assert sha256_file(os.path.join(run["stage"], "mutated.bpf.o")) == (
        MUTATED_OBJECT_HASH
    )
    assert sha256_file(
        os.path.join(run["stage"], "adv_null_load.bpf.o")
    ) == ADV_NULL_LOAD_OBJECT_HASH


def test_license_gate_agrees():
    run = executed()
    for name in ("base.bpf.o", "entry_first.bpf.o"):
        path = os.path.join(run["stage"], name)
        report = inspect_object(path, SUBPROG_PROFILE)
        assert report.ok, (
            name,
            report.structural + report.unsupported + report.license,
        )
        report = inspect_object(path, BASE_PROFILE)
        assert not report.ok, name
        codes = sorted(item.code for item in report.unsupported)
        assert codes == ["MBPF406", "MBPF407"], (name, codes)
    mutant = os.path.join(run["stage"], "mutated.bpf.o")
    report = inspect_object(mutant, BASE_PROFILE)
    assert report.ok, (
        "call-free mutant must inspect clean under the base profile",
        report.structural + report.unsupported + report.license,
    )
    assert (
        preflight_helper_licenses([], APACHE, SUBPROG_PROFILE) is None
    )
    try:
        preflight_helper_licenses([35], APACHE, SUBPROG_PROFILE)
    except Exception as exc:  # noqa: BLE001 - witness must refuse
        assert exc.diagnostic.code == "MBPF709", exc.diagnostic
        assert exc.diagnostic.stage == "inspect.license", exc.diagnostic
    else:
        raise AssertionError("helper-35 witness must stay refused")


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    for name, func in sorted(
        [(k, v) for k, v in globals().items() if k.startswith("test_")]
    ):
        try:
            func()
        except EnvironmentFailure as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            return 2
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
        else:
            print("PASS %s" % name)
    if failures:
        return 1
    print("subprogram calls: guest behavior, log, and residue checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
