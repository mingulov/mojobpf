# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""In-kernel proof for the Mojo-built map round trip.

Builds ``tests/compile/map_roundtrip.mojo`` and its plus-two mutation
through the genuine pipeline (``mojo build --emit llvm`` with the
packaged SDK on the import path -> ``compiler/mojo_ir_adapter.py`` ->
``llc -mtriple=bpfel -mcpu=v3``), then boots one disposable Linux guest
and drives the map lifecycle with unmodified bpftool: load the program,
read the libbpf-created map parameters, initialize key 0 to 41 from
userspace, execute one kernel test-run, and read key 0 back
independently. The base program must observe 42 (41 + 1 computed in the
kernel); the rebuilt mutant must observe 43; the stale base object must
still observe its old 42 and so fail the new expectation.

The two kernel-layer negatives go through the load/test-run entry
(``tests/harness/bpf_test_run.py``, contract revision 2, used as-is):
the out-of-bounds value fixture and the unchecked-dereference fixture
both pass the compile pipeline and must be rejected by the kernel
verifier at load. The harness reports those rejections with the
verifier label (explicit verifier evidence takes precedence over the
EACCES substrings a denial surfaces with); the tests additionally pin
the rejecting layer with the kernel verifier's own log lines.

Requires a working Mojo compiler, LLVM ``llc``, and ``vng`` (virtme-ng)
with a cached guest image on PATH (default release v6.12;
MOJOBPF_VNG_RELEASE selects the matrix lane). Missing tools fail loudly as
environment failures, never as passes. MOJOBPF_GUEST_ROUTE=parsed
(with ``mojobpf-lower`` via MOJOBPF_LOWER or PATH) builds the same
objects through the parsed lowering for route-equivalence runs; the
default lane-a keeps the committed pins.

Runnable directly (``python3 tests/kernel/test_map_roundtrip.py``) or
under any ``test_``-style runner. Standard library only. The guest boot
takes a few minutes under software emulation; all cases share one boot.
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
OOB_SOURCE = os.path.join(COMPILE_DIR, "map_oob.mojo")
UNCHECKED_SOURCE = os.path.join(COMPILE_DIR, "map_unchecked.mojo")
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")

XDP_PASS = 2
# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = 900
# Guest object route. The matrix default keeps Lane-A (the
# committed kernel-behavior pins); MOJOBPF_GUEST_ROUTE=parsed
# builds through the parsed lowering with the permissive proof
# (the same flags the build service uses) for
# route-equivalence runs. Anything else fails loudly: a new
# route must earn its own builder.
GUEST_ROUTE = os.environ.get("MOJOBPF_GUEST_ROUTE", "lane-a")
# Lowering model contract, pinned with
# compiler/adapter_service.py LOWER_MODEL_ID; a skew fails
# loudly at spec parse, never as a silent mismatch.
GUEST_MODEL_ID = "mojo-1.1.0-x86_64-bpfel-v3-minimal-v1"

INIT_VALUE = 41
BASE_VALUE = 42
MUTATED_VALUE = 43
MAP_NAME = "mojobpf_map0"

OOB_LOG_LINE = "invalid access to map value"
UNCHECKED_LOG_LINE = "invalid mem access 'map_value_or_null'"

# Verifier-generation gate for the unchecked negative. The 6.x
# verifier rejects the possibly-null dereference; the 7.x verifier
# refines single-entry-array key-0 lookups as never-null and accepts
# the same object (sound: the program is genuinely safe there). The
# gate keys off the lane release the matrix (and the lock's booted
# kernel check) already uses. Unknown releases fail loudly: a new
# kernel must earn its own expectation, never inherit one.
SIX_X_RELEASES = ("v6.12", "v6.6")
SEVEN_X_RELEASES = ("v7.0.14",)


def _unchecked_release_kind(release):
    """Map a lane release to the unchecked expectation: reject/accept."""
    if release in SIX_X_RELEASES:
        return "reject"
    if release in SEVEN_X_RELEASES:
        return "accept"
    raise AssertionError(
        "unchecked negative has no expectation for release %r" % (release,)
    )


class EnvironmentFailure(Exception):
    """The toolchain or VM needed by this test is missing or broken."""


def _resolve_lower():
    """Locate mojobpf-lower for the parsed guest route."""
    explicit = os.environ.get("MOJOBPF_LOWER")
    if explicit:
        if not (os.path.isfile(explicit) and os.access(explicit, os.X_OK)):
            raise EnvironmentFailure(
                "MOJOBPF_LOWER is not executable: %s" % explicit
            )
        return explicit
    found = shutil.which("mojobpf-lower")
    if found is None:
        raise EnvironmentFailure(
            "parsed guest route needs mojobpf-lower "
            "(MOJOBPF_LOWER or PATH)"
        )
    return found


def _parsed_spec(workdir, name, entries):
    """Write the single-map lowering spec the C++ tool consumes."""
    spec = {
        "schema_version": 1,
        "model_id": GUEST_MODEL_ID,
        "profile_id": "linux-bpfel-v3",
        "entry": "xdp_entry",
        "program_type": "xdp",
        "section": "xdp",
        "kernel_license": "Apache-2.0 WITH LLVM-exception",
        "map": {
            "symbol": "mojobpf_map0",
            "type": 2,
            "key_bits": 32,
            "value_bits": 64,
            "max_entries": entries,
            "flags": 0,
        },
    }
    path = os.path.join(workdir, name + ".spec.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(spec, handle)
    return path


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
def build_object(source, workdir, name, entries=1):
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
    if GUEST_ROUTE == "lane-a":
        proc = run_step(
            [
                sys.executable,
                ADAPTER,
                "--input",
                raw_path,
                "--output",
                adapted_path,
            ]
        )
    elif GUEST_ROUTE == "parsed":
        spec_path = _parsed_spec(workdir, name, entries)
        report_path = os.path.join(workdir, name + ".report.json")
        proc = run_step(
            [
                _resolve_lower(),
                "--mode",
                "lower",
                "--permissive-proof",
                "--input",
                raw_path,
                "--spec",
                spec_path,
                "--report",
                report_path,
                "--output",
                adapted_path,
                "--emit",
                "llvm",
            ]
        )
    else:
        raise EnvironmentFailure(
            "unknown MOJOBPF_GUEST_ROUTE %r (want lane-a or parsed)"
            % (GUEST_ROUTE,)
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
echo "=== begin guest_map ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "=== staged hashes ==="
sha256sum bpf_test_run.py base.bpf.o mutated.bpf.o oob.bpf.o unchecked.bpf.o data.bin guest_map.sh
map_case() {{
  tag="$1"; obj="$2"
  pin="/sys/fs/bpf/mojobpf_map_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  "$BPFTOOL" prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  python3 - "$out" >/tmp/xdp-$tag.mapinfo 2>&1 <<'PYEOF'
import json
import subprocess
import sys
fields = sys.argv[1]
info = {{"map_found": "0"}}
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
except Exception as exc:
    info = {{"map_found": "0", "map_error": str(exc)}}
with open(fields, "a") as handle:
    for key in sorted(info):
        handle.write("%s=%s\\n" % (key, info[key]))
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
neg_case() {{
  tag="$1"; obj="$2"
  out="/tmp/xdp-$tag.json"
  pin="/sys/fs/bpf/mojobpf-neg-$tag/prog"
  mkdir -p "/sys/fs/bpf/mojobpf-neg-$tag"
  python3 bpf_test_run.py --object "$obj" --expect-action {action} \\
    --data-in data.bin {harness_flags} --output "$out" >/tmp/xdp-$tag.stdout 2>/tmp/xdp-$tag.stderr
  code=$?
  rm -f "$pin"
  rmdir "/sys/fs/bpf/mojobpf-neg-$tag" 2>/dev/null
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
stray=0
for pin in /sys/fs/bpf/mojobpf_map_* /sys/fs/bpf/mojobpf-neg-* /sys/fs/bpf/mojobpf_control; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; stray=1; fi
done
if [ "$stray" -eq 0 ]; then echo "pin absent (unloaded)"; fi
echo "=== end guest_map ==="
"""

# tag, object name, kind (map lifecycle vs harness negative)
CASES = (
    ("base", "base.bpf.o", "map"),
    ("mut", "mutated.bpf.o", "map"),
    ("stale", "base.bpf.o", "map"),
    ("oob", "oob.bpf.o", "neg"),
    ("unchecked", "unchecked.bpf.o", "neg"),
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
    for path in (
        BASE_SOURCE,
        MUTATED_SOURCE,
        OOB_SOURCE,
        UNCHECKED_SOURCE,
        ADAPTER,
        HARNESS,
    ):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK directory: %s" % SDK_INCLUDE)
    stage = guest_proc.owned_stage(prefix="mojo-map-", dir="/tmp")
    staged = {
        "bpf_test_run.py": HARNESS,
        "base.bpf.o": build_object(BASE_SOURCE, stage, "base"),
        "mutated.bpf.o": build_object(MUTATED_SOURCE, stage, "mutated"),
        "oob.bpf.o": build_object(OOB_SOURCE, stage, "oob"),
        "unchecked.bpf.o": build_object(UNCHECKED_SOURCE, stage, "unchecked"),
    }
    with open(os.path.join(stage, "data.bin"), "wb") as handle:
        handle.write(bytes(60))
    for name, src in staged.items():
        with guest_proc.open_consumed(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    commands = []
    for tag, obj, kind in CASES:
        if kind == "map":
            commands.append("map_case %s %s" % (tag, obj))
        else:
            commands.append("neg_case %s %s" % (tag, obj))
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
        action=XDP_PASS,
        bpftool_prologue=(
            tool_admission.render_prologue(pins)
            + "\n"
            + tool_admission.render_guest_mount()
        ),
        bpftool_argv0=json.dumps(pins["path"]),
        harness_flags=tool_admission.render_harness_flags(
            pins, pin_path="$pin", owned_root="/sys/fs/bpf",
            ownership_token="mojobpf-neg-$tag",
        ),
    )
    script_path = os.path.join(stage, "guest_map.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["data.bin", "guest_map.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    # A1 guest handoff: consume the staged bytes through the recorder
    # and re-stage from the consumed buffers, so the guest-reported
    # hashes compare against an attested identity.
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        tuple(staged) + ("data.bin", "guest_map.sh"),
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
        progress_banner="=== begin guest_map ===",
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
    missing = [tag for tag, _, _ in CASES if tag not in results]
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
        if line.startswith("--- "):
            # Preamble only: stdout/stderr sections below must never
            # overwrite (or supply) attested fields.
            break
        if "=" in line and not line.startswith(("key:", "---", "Return")):
            key, _, value = line.partition("=")
            key = key.strip()
            if key and " " not in key:
                if key in fields:
                    raise AssertionError(
                        "duplicate preamble field %r" % key
                    )
                fields[key] = value.strip()
    return fields


def parse_lookup_hex(body, marker):
    """Extract the looked-up value bytes as compact lowercase hex.

    bpftool prints the legacy hex dump for maps without BTF
    key/value types and pretty-printed JSON once the object
    carries modern BTF key/value types; both spellings attest
    the same u64 value, so the parser accepts either (the JSON
    spelling first: the run section also contains a bare
    ``value:`` line that the legacy pattern would misread).
    """
    section = body.split(marker, 1)[1]
    pretty = re.search(r'"value":\s*(\d+)', section)
    if pretty:
        return hexle(int(pretty.group(1)))
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


def test_map_roundtrip_42():
    check_map_case("base", hexle(BASE_VALUE))


def test_mutation_changes_value():
    run = executed()
    after_mut = check_map_case("mut", hexle(MUTATED_VALUE))
    body = run["results"]["base"]["body"]
    after_base = parse_lookup_hex(body, "after ---")
    assert after_mut != after_base, (
        "rebuilt mutant must change the observed value"
    )
    assert after_base == hexle(BASE_VALUE), "base must still observe 42"


def test_stale_object_fails():
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


def check_verifier_rejection(tag, log_line):
    run = executed()
    record = run["results"][tag]
    try:
        doc = json.loads(record["body"])
    except ValueError:
        raise guest_proc.GuestMissing(
            "%s: harness did not emit JSON:\n%s" % (tag, record["body"][-500:])
        )
    hint = guest_proc.check_harness_exit(
        tag, exit=record["exit"],
        classification=doc.get("classification"),
        stage=doc.get("stage"),
        contract_version=doc.get("contract_version"),
        note=doc.get("note"), expect=4)
    assert doc.get("stage") == "load", "%s: expected load stage" % tag
    assert doc.get("classification") == "verifier", (
        "%s: expected verifier classification, got %r"
        % (tag, doc.get("classification"))
    )
    blob = json.dumps(doc.get("commands", []))
    assert log_line in blob, (
        "%s: kernel verifier log must contain %r" % (tag, log_line)
    )
    return guest_proc.combine_outcomes(hint)


def test_oob_rejected_by_verifier():
    """Wrong value size: first rejecting layer is the kernel verifier."""
    return check_verifier_rejection("oob", OOB_LOG_LINE)


def check_unchecked_accepted():
    """7.x leg: the verifier refines key-0 lookups and accepts.

    The acceptance pins behavior, not silence: the record must show
    a full load+run pass (exit 0, run stage, XDP_PASS returned, pin
    cleaned). The reason (never-null refinement of single-entry-array
    key-0 lookups) is documented at SIX_X_RELEASES above.
    """
    run = executed()
    record = run["results"]["unchecked"]
    try:
        doc = json.loads(record["body"])
    except ValueError:
        raise guest_proc.GuestMissing(
            "unchecked: harness did not emit JSON:\n%s"
            % record["body"][-500:]
        )
    hint = guest_proc.check_harness_exit(
        "unchecked", exit=record["exit"],
        classification=doc.get("classification"),
        stage=doc.get("stage"),
        contract_version=doc.get("contract_version"),
        note=doc.get("note"), expect=0)
    assert doc.get("stage") == "run", (
        "unchecked: expected run stage, got %r" % doc.get("stage")
    )
    assert doc.get("actual_action") == XDP_PASS, (
        "unchecked: expected XDP_PASS return, got %r"
        % doc.get("actual_action")
    )
    assert doc.get("cleanup_ok") is True, (
        "unchecked: harness must report a clean unload"
    )
    return guest_proc.combine_outcomes(hint)


def test_unchecked_verifier_outcome():
    """Unchecked deref: 6.x verifier rejects; 7.x refines and accepts."""
    if _unchecked_release_kind(VNG_RELEASE) == "accept":
        return check_unchecked_accepted()
    check_verifier_rejection("unchecked", UNCHECKED_LOG_LINE)
    return None


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
    for tag in ("oob", "unchecked"):
        record = run["results"][tag]
        body = record["body"]
        try:
            doc = json.loads(body)
        except ValueError:
            raise guest_proc.GuestMissing(
                "%s: harness did not emit JSON:\n%s" % (tag, body[-500:])
            )
        accepted = (
            tag == "unchecked"
            and _unchecked_release_kind(VNG_RELEASE) == "accept"
        )
        guest_proc.check_harness_exit(
            tag, exit=record["exit"],
            classification=doc.get("classification"),
            stage=doc.get("stage"),
            contract_version=doc.get("contract_version"),
            note=doc.get("note"), expect=0 if accepted else 4)
        assert doc.get("contract_version") == 2, (
            "%s: harness contract must be revision 2" % tag
        )
        if accepted:
            # 7.x accepts (see SIX_X_RELEASES): the load pinned and
            # ran, so the unload must be clean and reported.
            assert doc.get("cleanup_ok") is True, (
                "%s: harness must report a clean unload" % tag
            )
            continue
        # Load-stage failures pin nothing, so there is nothing to clean.
        assert doc.get("cleanup_ok") is None, (
            "%s: harness must leave cleanup_ok unset" % tag
        )
    rec = guest_proc.active_recorder()
    reported = guest_proc.parse_reported_hashes(run["output"])
    for name in (
        "bpf_test_run.py",
        "base.bpf.o",
        "mutated.bpf.o",
        "oob.bpf.o",
        "unchecked.bpf.o",
        "data.bin",
        "guest_map.sh",
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


# The verifier negatives are denials: each expects the wire-derived
# FAIL at VERIFY (the bad object observably rejected at load) and
# passes only its own cell when the denial is observed with
# evidence. They guard the round trip: the base object must load
# and run (positive) while the bad objects must observably not
# load (denials), proving the load observation is not vacuous.
# The unchecked deref is no longer a denial: 7.x soundly accepts
# it (see SIX_X_RELEASES), so test_unchecked_verifier_outcome is a
# version-conditional positive asserting rejection on 6.x and a
# pinned acceptance on 7.x.
CASE_DENIALS = {
    "test_oob_rejected_by_verifier": (
        "test_map_roundtrip_42", "VERIFY"
    ),
}


# Durable inputs per case: absolute repo paths plus ("stage",
# basename) entries resolved against the guest stage at finish.
# Every non-board case pins the sources it depends on; a class
# with any missing file digests to zeros and can never back a
# PASS.
CASE_INPUTS = {
    "test_map_roundtrip_42": {
        "sources": [BASE_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": [],
    },
    "test_mutation_changes_value": {
        "sources": [MUTATED_SOURCE],
        "objects": [("stage", "mutated.bpf.o")],
        "corpus": [],
    },
    "test_stale_object_fails": {
        "sources": [BASE_SOURCE, MUTATED_SOURCE],
        "objects": [("stage", "base.bpf.o")],
        "corpus": [],
    },
    "test_oob_rejected_by_verifier": {
        "sources": [OOB_SOURCE],
        "objects": [("stage", "oob.bpf.o")],
        "corpus": [],
    },
    "test_unchecked_verifier_outcome": {
        "sources": [UNCHECKED_SOURCE],
        "objects": [("stage", "unchecked.bpf.o")],
        "corpus": [],
    },
    "test_guest_provenance": {
        "sources": [BASE_SOURCE, MUTATED_SOURCE, OOB_SOURCE,
                    UNCHECKED_SOURCE, HARNESS,
                    ("stage", "guest_map.sh")],
        "objects": [
            ("stage", "base.bpf.o"), ("stage", "mutated.bpf.o"),
            ("stage", "oob.bpf.o"), ("stage", "unchecked.bpf.o"),
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
        suite_id="kernel-map", suite_path=__file__,
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
    print("map round trip: guest behavior, mutation, and stale checks passed")
    print("guest stage: %s (removed after the run)" % executed()["stage"])
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
