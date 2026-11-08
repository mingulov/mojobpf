# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Q-NATIVE/F-ISA/legacy/refusal: the XDP verifier refuses legacy loads.

Legacy cBPF loads (LD_ABS/LD_IND/LD_LEN/LDX_MSH) have no
lowering rule and no llc selection path, so this slim suite
pins their live kernel refusal: four hand-assembled legacy
words load-refused by both lanes' XDP verifiers (exit 4,
`verifier` classification, exact pinned messages), with
staged-bytes decode proving each object carries exactly its
legacy word (else the refusal is vacuous), guest-side hash
re-verification of every staged byte, and provenance
(cleanup unset on refused legs per the array/hash-maps
precedent, pins absent). Fail-open: a future accepting
kernel turns the legs RED by design.
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
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "tests", "harness"))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

import guest_proc  # noqa: E402
import tool_admission  # noqa: E402
import lane_lock  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_jmp_qual import (  # noqa: E402  (sibling qual module)
    _assert_acyclic,
)

SUITE_ID = "kernel-isa-legacy"
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = int(os.environ.get("MOJOBPF_VNG_TIMEOUT", "1500"))


class EnvironmentFailure(AssertionError):
    """The lane cannot run honestly (missing tool/fixture/lease)."""


ABS_SOURCE = os.path.join(REPO_ROOT, "tests", "fixtures", "isa",
                          "legacy", "legacy_abs.s")
IND_SOURCE = os.path.join(REPO_ROOT, "tests", "fixtures", "isa",
                          "legacy", "legacy_ind.s")
LEN_SOURCE = os.path.join(REPO_ROOT, "tests", "fixtures", "isa",
                          "legacy", "legacy_len.s")
MSH_SOURCE = os.path.join(REPO_ROOT, "tests", "fixtures", "isa",
                          "legacy", "legacy_msh.s")
PACKET = os.path.join(REPO_ROOT, "tests", "fixtures", "isa",
                      "legacy", "pkt_zero64.bin")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")

XDP_ABORTED = 0

# Exact verifier messages, observed pre-seal on both lanes.
ABS_IND_MESSAGE = (
    "BPF_LD_[ABS|IND] instructions not allowed for this program type"
)
LEN_MESSAGE = "unknown opcode 80"
MSH_MESSAGE = "BPF_LDX uses reserved fields"

# Byte-exact legacy words per staged object: (slot, word).
LEGACY_WORDS = {
    "abs": (0, 0x20),
    "ind": (0, 0x800006040),
    "len": (0, 0x80),
    "msh": (0, 0xB1),
}

CASES = [
    ("abs", "abs.bpf.o", XDP_ABORTED, 4, "pkt_zero64.bin"),
    ("ind", "ind.bpf.o", XDP_ABORTED, 4, "pkt_zero64.bin"),
    ("len", "len.bpf.o", XDP_ABORTED, 4, "pkt_zero64.bin"),
    ("msh", "msh.bpf.o", XDP_ABORTED, 4, "pkt_zero64.bin"),
]


def run_step(argv, timeout=900):
    return subprocess.run(argv, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True,
                          timeout=timeout)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _staged_section_words(stage, name, section):
    with open(os.path.join(stage, name), "rb") as handle:
        data = handle.read()
    assert data[:4] == b"\x7fELF" and len(data) >= 64
    (e_shoff,) = struct.unpack_from("<Q", data, 40)
    _, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + index * 64)
            for index in range(e_shnum)]
    base = rows[e_shstrndx][4]
    for row in rows:
        end = data.index(b"\x00", base + row[0])
        if data[base + row[0]:end] == section.encode():
            text = data[row[4]:row[4] + row[5]]
            assert len(text) % 8 == 0
            return [word for (word,) in struct.iter_unpack("<Q", text)]
    raise AssertionError("%s section missing in %s" % (section, name))


@guest_proc.consumes_source
def build_asm(source, workdir, name):
    object_path = os.path.join(workdir, name + ".bpf.o")
    proc = run_step(
        ["clang", "--target=bpf", "-mcpu=v3",
         "-c", source, "-o", object_path]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "asm build failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    return object_path


GUEST_SCRIPT = """#!/bin/bash
set -u
cd "{stage}"
{bpftool_prologue}
echo "=== begin guest_isa_legacy ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "=== staged hashes ==="
sha256sum bpf_test_run.py abs.bpf.o ind.bpf.o len.bpf.o msh.bpf.o pkt_zero64.bin guest_isa_legacy.sh
run_case() {{
  tag="$1"; obj="$2"; expect="$3"; data="$4"
  out="/tmp/isa-legacy-$tag.json"
  pin="/sys/fs/bpf/mojobpf-isa-legacy-$tag/prog"
  mkdir -p "/sys/fs/bpf/mojobpf-isa-legacy-$tag"
  python3 bpf_test_run.py --object "$obj" --expect-action "$expect" \\
    --data-in "$data" {harness_flags} --output "$out" --repeat 3 >/tmp/isa-legacy-$tag.stdout 2>/tmp/isa-legacy-$tag.stderr
  code=$?
  rm -f "$pin"
  rmdir "/sys/fs/bpf/mojobpf-isa-legacy-$tag" 2>/dev/null
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
if ls /sys/fs/bpf/mojobpf_control 2>&1; then echo "PIN STILL PRESENT"; else echo "pin absent (unloaded)"; fi
for pin in /sys/fs/bpf/mojobpf-isa-legacy-*; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; fi
done
echo "=== end guest_isa_legacy ==="
"""


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
    for tool in ("clang", "vng"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (ABS_SOURCE, IND_SOURCE, LEN_SOURCE, MSH_SOURCE,
                 PACKET, HARNESS):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    stage = guest_proc.owned_stage(prefix="mojo-isa-legacy-", dir="/tmp")
    with guest_proc.open_consumed(PACKET, "rb") as handle:
        packet = handle.read()
    abs_obj = build_asm(ABS_SOURCE, stage, "abs")
    ind_obj = build_asm(IND_SOURCE, stage, "ind")
    len_obj = build_asm(LEN_SOURCE, stage, "len")
    msh_obj = build_asm(MSH_SOURCE, stage, "msh")
    staged = {
        "bpf_test_run.py": HARNESS,
        "abs.bpf.o": abs_obj,
        "ind.bpf.o": ind_obj,
        "len.bpf.o": len_obj,
        "msh.bpf.o": msh_obj,
        "pkt_zero64.bin": PACKET,
    }
    for name, src in staged.items():
        with guest_proc.open_consumed(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    commands = []
    for tag, obj, expect, _, data in CASES:
        commands.append(
            "run_case %s %s %d %s" % (tag, obj, expect, data)
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
            ownership_token="mojobpf-isa-legacy-$tag",
        ),
    )
    script_path = os.path.join(stage, "guest_isa_legacy.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["guest_isa_legacy.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        tuple(staged) + ("guest_isa_legacy.sh",),
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
        progress_banner="=== begin guest_isa_legacy ===",
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
    print("inputs: pkt_zero64.bin sha256=%s"
          % (hashlib.sha256(packet).hexdigest(),))
    return {"stage": stage, "output": output, "packet": packet,
            "results": results}


_CACHED = {}


def executed():
    if "run" not in _CACHED:
        _CACHED["run"] = guest_run()
    return _CACHED["run"]


def _load_stderr(record):
    for command in record.get("commands", []):
        argv = command.get("argv", [])
        if len(argv) >= 3 and argv[1:3] == ["prog", "load"]:
            return command.get("stderr", "")
    raise AssertionError("harness record carries no prog load command")


def _refused(tag, message):
    record = executed()["results"][tag]
    hint = guest_proc.check_harness_exit(
        tag, exit=record["_harness_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=4)
    assert record["classification"] == "verifier", (
        "%s: expected verifier classification, got %r"
        % (tag, record.get("classification"),)
    )
    stderr = _load_stderr(record)
    assert message in stderr, (
        "%s: expected %r in load stderr, got %r"
        % (tag, message, stderr[-500:],)
    )
    return hint


def test_legacy_abs_refused():
    return guest_proc.combine_outcomes(
        _refused("abs", ABS_IND_MESSAGE))


def test_legacy_ind_refused():
    return guest_proc.combine_outcomes(
        _refused("ind", ABS_IND_MESSAGE))


def test_legacy_len_refused():
    return guest_proc.combine_outcomes(_refused("len", LEN_MESSAGE))


def test_legacy_msh_refused():
    return guest_proc.combine_outcomes(_refused("msh", MSH_MESSAGE))


def test_legacy_guest_objects_carry_legacy():
    stage = executed()["stage"]
    for tag, _, _, _, _ in CASES:
        words = _staged_section_words(stage, tag + ".bpf.o", "xdp")
        slot, want = LEGACY_WORDS[tag]
        assert words == [want, 0x95], (
            "staged %s must be exactly [legacy word, exit], got %r"
            % (tag, [hex(word) for word in words],)
        )
        assert words[slot] == want, (tag, hex(words[slot]))
        _assert_acyclic(tag, words)


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
    for tag, _, _, want_exit, _ in CASES:
        record = run["results"][tag]
        guest_proc.check_harness_exit(
            tag, exit=record["_harness_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=want_exit)
        # Load-refused legs never pin: the harness leaves
        # cleanup_ok unset (array/hash-maps precedent); the
        # global pin-absence checks above prove no residue.
        assert record.get("cleanup_ok") is None, (
            "%s: harness must leave cleanup_ok unset" % tag
        )
    rec = guest_proc.active_recorder()
    reported = guest_proc.parse_reported_hashes(run["output"])
    for name in ("bpf_test_run.py", "abs.bpf.o", "ind.bpf.o",
                 "len.bpf.o", "msh.bpf.o", "pkt_zero64.bin",
                 "guest_isa_legacy.sh"):
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


CASE_DENIALS = {}

CASE_INPUTS = {
    "test_legacy_abs_refused": {
        "sources": [ABS_SOURCE],
        "objects": [("stage", "abs.bpf.o")],
        "corpus": [PACKET],
    },
    "test_legacy_ind_refused": {
        "sources": [IND_SOURCE],
        "objects": [("stage", "ind.bpf.o")],
        "corpus": [PACKET],
    },
    "test_legacy_len_refused": {
        "sources": [LEN_SOURCE],
        "objects": [("stage", "len.bpf.o")],
        "corpus": [PACKET],
    },
    "test_legacy_msh_refused": {
        "sources": [MSH_SOURCE],
        "objects": [("stage", "msh.bpf.o")],
        "corpus": [PACKET],
    },
    "test_legacy_guest_objects_carry_legacy": {
        "sources": [ABS_SOURCE, IND_SOURCE, LEN_SOURCE, MSH_SOURCE],
        "objects": [("stage", "abs.bpf.o"),
                    ("stage", "ind.bpf.o"),
                    ("stage", "len.bpf.o"),
                    ("stage", "msh.bpf.o")],
        "corpus": [],
    },
    "test_guest_provenance": {
        "sources": [ABS_SOURCE, IND_SOURCE, LEN_SOURCE, MSH_SOURCE,
                    HARNESS, ("stage", "guest_isa_legacy.sh")],
        "objects": [("stage", "abs.bpf.o"),
                    ("stage", "ind.bpf.o"),
                    ("stage", "len.bpf.o"),
                    ("stage", "msh.bpf.o")],
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
    print("isa legacy: verifier refusals pinned on both lanes")
    print("guest stage: %s (removed after the run)" % executed()["stage"])
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
