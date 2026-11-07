# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Q-NATIVE/F-ISA/jmp/uncond: unconditional jumps execute.

Amendment A2: no admitted Mojo source emits JA (twelve probe
shapes fold to fall-through, merge, or refuse at the adapter),
so this suite executes the stock-C two-call diamond
(``tests/reference_c/jmp_ref.bpf.c``, expecting XDP_PASS) and
the hand-IR oracle diamond (``oracle-jmp-run.ll`` via pinned
llc directly, which must agree), plus a single-constant C
mutant (-DGATE_ADD=300, expecting XDP_DROP) and a stale-object
leg (base object against the mutant expectation, which must
fail at RUNTIME), with an independent packet oracle and
guest-side hash re-verification of every staged byte. The
executed objects' bytes are decoded host-side over the xdp
section to prove the JA words (exact words with verified
pc+off+1 targets onto join work) and the no-loop corollary
(no off-bearing jump with a backward offset). The admitted
Mojo diamond exhibit is pinned JA-free by the host suite, not
executed here.

Standalone: ``python3 tests/kernel/test_jmp_qual.py`` (exit 0 on
proof, exit 2 on environment failure; MOJOBPF_VNG_RELEASE selects
the matrix lane). Missing tools fail loudly as environment failures
before any guest boots.
"""
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys

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

from mojobpf.toolchain import admit_tools  # noqa: E402

SUITE_ID = "kernel-isa-jmp"
FIX_DIR = os.path.join(REPO_ROOT, "tests", "fixtures", "isa", "jmp")
C_SOURCE = os.path.join(REPO_ROOT, "tests", "reference_c",
                        "jmp_ref.bpf.c")
ORACLE_SOURCE = os.path.join(FIX_DIR, "oracle-jmp-run.ll")
PACKET = os.path.join(FIX_DIR, "pkt_zero60.bin")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")

XDP_DROP = 1
XDP_PASS = 2

# Byte-exact JA words (observed at RED from the staged builds,
# decode-verified: each target lands on join work inside xdp).
# Placeholders until the RED run observes them.
JA_C_WORD = 0x0
JA_C_SLOT = -1
JA_ORACLE_WORD = 0x0
JA_ORACLE_SLOT = -1


def _signed_off(word):
    off = (word >> 16) & 0xFFFF
    return off - 0x10000 if off >= 0x8000 else off


def _off_bearing_jumps(words):
    # J-class words carrying a 16-bit offset: JA + Jcc. Calls
    # (0x85) and exits (0x95) share the class bits but carry no
    # offset. JA32 (0x06) is out of this slice.
    return [(slot, word) for slot, word in enumerate(words)
            if word & 0x07 == 0x05
            and word & 0xFF not in (0x85, 0x95)]


# (tag, object key, expected action, want harness exit)
CASES = (
    ("base", "base.bpf.o", XDP_PASS, 0),
    ("oracle", "oracle.bpf.o", XDP_PASS, 0),
    ("mut", "mutated.bpf.o", XDP_DROP, 0),
    ("stale", "base.bpf.o", XDP_DROP, 1),
)

VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = int(os.environ.get("MOJOBPF_VNG_TIMEOUT", "1500"))


class EnvironmentFailure(AssertionError):
    """The lane cannot run honestly (missing tool/fixture/lease)."""


def run_step(argv):
    try:
        return subprocess.run(argv, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True,
                              check=False)
    except OSError as exc:
        raise EnvironmentFailure(
            "cannot execute %s: %s" % (argv[0], exc))


@guest_proc.consumes_source
def build_c(source, workdir, name, extra=()):
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(
        ["clang", "--target=bpf", "-mcpu=v3", "-O2", "-g",
         *extra, "-c", source, "-o", object_path]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "C reference build failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    if "warning:" in proc.stderr.lower() or "error:" in proc.stderr.lower():
        raise AssertionError(
            "C reference build diagnostics for %s:\n%s"
            % (source, proc.stderr)
        )
    return object_path


@guest_proc.consumes_source
def build_oracle(source, workdir):
    object_path = os.path.join(workdir, "oracle.bpf.o")
    proc = run_step(
        ["llc", "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
         source, "-o", object_path]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "oracle build failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    return object_path


GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
{bpftool_prologue}
echo "=== begin guest_isa_jmp ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "=== staged hashes ==="
sha256sum bpf_test_run.py base.bpf.o mutated.bpf.o oracle.bpf.o pkt_zero60.bin guest_isa_jmp.sh
run_case() {{
  tag="$1"; obj="$2"; expect="$3"; data="$4"
  out="/tmp/isa-jmp-$tag.json"
  pin="/sys/fs/bpf/mojobpf-isa-jmp-$tag/prog"
  mkdir -p "/sys/fs/bpf/mojobpf-isa-jmp-$tag"
  python3 bpf_test_run.py --object "$obj" --expect-action "$expect" \\
    --data-in "$data" {harness_flags} --output "$out" --repeat 3 >/tmp/isa-jmp-$tag.stdout 2>/tmp/isa-jmp-$tag.stderr
  code=$?
  rm -f "$pin"
  rmdir "/sys/fs/bpf/mojobpf-isa-jmp-$tag" 2>/dev/null
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
if ls /sys/fs/bpf/mojobpf_control 2>&1; then echo "PIN STILL PRESENT"; else echo "pin absent (unloaded)"; fi
for pin in /sys/fs/bpf/mojobpf-isa-jmp-*; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; fi
done
echo "=== end guest_isa_jmp ==="
"""


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    admitted, diagnostics = admit_tools(
        lockfile_path=os.path.join(REPO_ROOT, "toolchains.lock.json"),
        names=("llc",),
    )
    if sorted(admitted) != ["llc"]:
        raise EnvironmentFailure(
            "pinned llc admission failed: %s"
            % "; ".join("%s %s" % (item.code, item.explanation)
                        for item in diagnostics)
        )
    print("pinned tools admitted: llc=%s" % admitted["llc"].version)
    for tool in ("clang", "vng"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (C_SOURCE, ORACLE_SOURCE, PACKET, HARNESS):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    stage = guest_proc.owned_stage(prefix="mojo-isa-jmp-", dir="/tmp")
    with guest_proc.open_consumed(PACKET, "rb") as handle:
        packet = handle.read()
    base_obj = build_c(C_SOURCE, stage, "base")
    mutated_obj = build_c(C_SOURCE, stage, "mutated",
                          extra=("-DGATE_ADD=300",))
    oracle_obj = build_oracle(ORACLE_SOURCE, stage)
    staged = {
        "bpf_test_run.py": HARNESS,
        "base.bpf.o": base_obj,
        "mutated.bpf.o": mutated_obj,
        "oracle.bpf.o": oracle_obj,
        "pkt_zero60.bin": PACKET,
    }
    for name, src in staged.items():
        with guest_proc.open_consumed(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    commands = []
    for tag, obj, expect, _ in CASES:
        commands.append(
            "run_case %s %s %d pkt_zero60.bin" % (tag, obj, expect)
        )
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
        bpftool_prologue=(
            tool_admission.render_prologue(pins)
            + "\n"
            + tool_admission.render_guest_mount()
        ),
        harness_flags=tool_admission.render_harness_flags(
            pins, pin_path="$pin", owned_root="/sys/fs/bpf",
            ownership_token="mojobpf-isa-jmp-$tag",
        ),
    )
    script_path = os.path.join(stage, "guest_isa_jmp.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["guest_isa_jmp.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        tuple(staged) + ("guest_isa_jmp.sh",),
    )
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
        progress_banner="=== begin guest_isa_jmp ===",
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
    missing = [tag for tag, _, _, _ in CASES if tag not in results]
    if missing:
        raise guest_proc.GuestMissing(
            "guest output lacks cases %s (stage %s):\n%s"
            % (", ".join(missing), stage, output[-4000:])
        )
    return {"stage": stage, "output": output, "packet": packet,
            "results": results}


_CACHED = {}


def executed():
    if "run" not in _CACHED:
        _CACHED["run"] = guest_run()
    return _CACHED["run"]


def test_fixture_bytes():
    with guest_proc.open_consumed(PACKET, "rb") as handle:
        frame = handle.read()
    assert len(frame) == 60, "packet fixture has %d bytes" % len(frame)
    assert frame == bytes(60), "packet fixture must be zero bytes"
    assert executed()["packet"] == frame


def _staged_section_words(stage, name, section):
    with open(os.path.join(stage, name), "rb") as handle:
        data = handle.read()
    assert data[:4] == b"\x7fELF" and len(data) >= 64
    (e_shoff,) = struct.unpack_from("<Q", data, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    assert e_shentsize == 64 and 0 < e_shnum <= 256
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + index * 64)
            for index in range(e_shnum)]
    base = rows[e_shstrndx][4]
    for row in rows:
        end = data.index(b"\x00", base + row[0])
        if data[base + row[0]:end] == section.encode():
            text = data[row[4]:row[4] + row[5]]
            assert len(text) % 8 == 0
            return [word for (word,) in struct.iter_unpack("<Q", text)]
    raise AssertionError(
        "%s section missing in staged %s" % (section, name))


def test_jmp_guest_object_admits_ja():
    stage = executed()["stage"]
    base_xdp = _staged_section_words(stage, "base.bpf.o", "xdp")
    mut_xdp = _staged_section_words(stage, "mutated.bpf.o", "xdp")
    oracle_xdp = _staged_section_words(stage, "oracle.bpf.o", "xdp")
    assert JA_C_WORD != 0x0, "pin JA_C_WORD at RED"
    assert JA_ORACLE_WORD != 0x0, "pin JA_ORACLE_WORD at RED"
    for tag, words, pin_word, pin_slot in (
        ("base", base_xdp, JA_C_WORD, JA_C_SLOT),
        ("mutant", mut_xdp, JA_C_WORD, JA_C_SLOT),
        ("oracle", oracle_xdp, JA_ORACLE_WORD, JA_ORACLE_SLOT),
    ):
        found = [(slot, word) for slot, word in enumerate(words)
                 if word & 0xFF == 0x05]
        assert found == [(pin_slot, pin_word)], (
            "executed %s must carry exactly the pinned JA, got %r"
            % (tag, [(slot, hex(word)) for slot, word in found],)
        )
        target = pin_slot + _signed_off(pin_word) + 1
        assert 0 <= target < len(words), (
            "executed %s JA target %d lands outside" % (tag, target)
        )
        assert _signed_off(pin_word) >= 0, (
            "executed %s JA must jump forward" % (tag,)
        )
        for slot, word in _off_bearing_jumps(words):
            off = _signed_off(word)
            assert off >= 0, (
                "executed %s has a backward jump at %d (off %d): "
                "no-loop corollary violated" % (tag, slot, off)
            )
            assert 0 <= slot + off + 1 < len(words), (
                "executed %s jump at %d lands outside" % (tag, slot)
            )
        assert words[-1] == 0x95, (
            "executed %s must trail an exit" % (tag,)
        )
    assert len(mut_xdp) == len(base_xdp), "mutant must not move layout"
    diff = [index for index, (ours, theirs)
            in enumerate(zip(base_xdp, mut_xdp))
            if ours != theirs]
    assert len(diff) == 1, (
        "mutant must differ in exactly one xdp word, got %r" % (diff,)
    )


def test_jmp_base_returns_pass():
    record = executed()["results"]["base"]
    guest_proc.check_harness_exit(
        "base", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_PASS, (
        "jmp base object must return XDP_PASS, got %r"
        % (record.get("actual_action"),)
    )


def test_jmp_oracle_matches_base():
    run = executed()
    record = run["results"]["oracle"]
    guest_proc.check_harness_exit(
        "oracle", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_PASS, (
        "hand-IR oracle diamond must return XDP_PASS, got %r"
        % (record.get("actual_action"),)
    )
    assert record["actual_action"] == run["results"]["base"][
        "actual_action"], "same input bytes must agree"


def test_jmp_mutation_changes_action():
    run = executed()
    record = run["results"]["mut"]
    guest_proc.check_harness_exit(
        "mut", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["actual_action"] == XDP_DROP
    assert record["actual_action"] != run["results"]["base"][
        "actual_action"], "rebuilt mutant must change the action"


def test_jmp_stale_object_fails():
    record = executed()["results"]["stale"]
    hint = guest_proc.check_harness_exit(
        "stale", exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=1)
    assert record["classification"] == "runtime", (
        "stale: expected runtime classification, got %r"
        % (record.get("classification"),)
    )
    assert record["actual_action"] == XDP_PASS, (
        "stale object must still produce its old action 2, got %r"
        % (record.get("actual_action"),)
    )
    return guest_proc.combine_outcomes(hint)


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
    for tag, _, _, want_exit in CASES:
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
    rec = guest_proc.active_recorder()
    reported = guest_proc.parse_reported_hashes(run["output"])
    for name in ("bpf_test_run.py", "base.bpf.o", "mutated.bpf.o",
                 "oracle.bpf.o", "pkt_zero60.bin", "guest_isa_jmp.sh"):
        if rec is None:
            expected = sha256_file(os.path.join(run["stage"], name))
            assert expected in run["output"], (
                "guest must re-verify staged hash of %s" % name
            )
            continue
        expected = rec.consumed_staged_digest(name, run["stage"])
        assert expected is not None, "staged bytes missing for %s" % name
        assert reported.get(name) == expected, (
            "guest must report the consumed bytes of %s" % name
        )


CASE_DENIALS = {
    "test_jmp_stale_object_fails": (
        "test_jmp_mutation_changes_action", "RUNTIME"
    ),
}

CASE_INPUTS = {
    "test_fixture_bytes": {
        "sources": [PACKET],
        "objects": [],
        "corpus": [PACKET],
    },
    "test_jmp_base_returns_pass": {
        "sources": [C_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": [PACKET],
    },
    "test_jmp_oracle_matches_base": {
        "sources": [ORACLE_SOURCE],
        "objects": [("stage", "oracle.bpf.o")],
        "corpus": [PACKET],
    },
    "test_jmp_guest_object_admits_ja": {
        "sources": [C_SOURCE, ORACLE_SOURCE],
        "objects": [("stage", "base.bpf.o"),
                    ("stage", "mutated.bpf.o"),
                    ("stage", "oracle.bpf.o")],
        "corpus": [],
    },
    "test_jmp_mutation_changes_action": {
        "sources": [C_SOURCE],
        "objects": [("stage", "mutated.bpf.o")],
        "corpus": [PACKET],
    },
    "test_jmp_stale_object_fails": {
        "sources": [C_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": [PACKET],
    },
    "test_guest_provenance": {
        "sources": [C_SOURCE, ORACLE_SOURCE, HARNESS,
                    ("stage", "guest_isa_jmp.sh")],
        "objects": [("stage", "base.bpf.o"),
                    ("stage", "mutated.bpf.o"),
                    ("stage", "oracle.bpf.o")],
        "corpus": [PACKET],
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
        suite_id=SUITE_ID, suite_path=__file__,
        case_ids=names, denials=CASE_DENIALS, inputs=CASE_INPUTS,
        lane_release=VNG_RELEASE)
    guest_proc.set_active_recorder(rec)
    if not __debug__:
        return rec.finish_unrun(
            "must not run under python -O (asserts stripped)"
        )
    failures = 0
    unavailable_seen = False
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
    print("isa jmp: guest behavior, oracle agreement, mutation, and stale checks passed")
    print("guest stage: %s (removed after the run)" % executed()["stage"])
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
