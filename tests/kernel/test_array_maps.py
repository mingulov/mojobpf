# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""In-kernel proof for the array map SDK slice.

Builds ``tests/compile/maps_roundtrip_named.mojo`` (the round trip
through the named ``BPF_ANY`` spelling) plus the out-of-bounds and
unchecked negatives through the genuine pipeline (``mojo build --emit
llvm`` with the packaged SDK on the import path ->
``compiler/mojo_ir_adapter.py`` -> ``llc -mtriple=bpfel -mcpu=v3``),
then boots one disposable Linux guest and drives the one-entry array
map lifecycle with unmodified bpftool:

* lifecycle: load the program, read the libbpf-created map parameters,
  initialize key 0 to 41 from userspace, execute one kernel test-run,
  and read key 0 back independently (must observe 42);
* exact counts: from a fresh load initialized to 1000, a 10-repeat run
  must observe exactly 1010 and five further runs exactly 1015, with
  exact little-endian bytes and byte sums;
* key behavior: key 0 is the first and the last key (iteration past it
  fails); invalid keys, invalid key/value sizes, and element deletion
  are refused by the kernel instead of misdecoded;
* the out-of-bounds fixture is rejected by the kernel verifier at load
  (layout mismatch is never silently misdecoded);
* the unchecked-dereference fixture is rejected by the kernel verifier
  at load (the missing-null-check negative).

The two kernel-layer negatives go through the load/test-run entry
(``tests/harness/bpf_test_run.py``, contract revision 2, used as-is).

Requires a working Mojo compiler, LLVM ``llc``, and ``vng`` (virtme-ng)
with a cached guest image on PATH (default release v6.12;
MOJOBPF_VNG_RELEASE selects the matrix lane). Missing tools fail loudly as
environment failures, never as passes.

Runnable directly (``python3 tests/kernel/test_array_maps.py``) or
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
ARRAY_SOURCE = os.path.join(COMPILE_DIR, "maps_roundtrip_named.mojo")
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

INIT_VALUE = 41
AFTER_VALUE = 42
COUNT_INIT = 1000
COUNT_FIRST_REPEAT = 10
COUNT_FIRST_VALUE = COUNT_INIT + COUNT_FIRST_REPEAT
COUNT_SECOND_REPEAT = 5
COUNT_SECOND_VALUE = COUNT_FIRST_VALUE + COUNT_SECOND_REPEAT
MAP_NAME = "mojobpf_map0"

OOB_LOG_LINE = "invalid access to map value"
UNCHECKED_LOG_LINE = "invalid mem access 'map_value_or_null'"


class EnvironmentFailure(Exception):
    """The toolchain or VM needed by this test is missing or broken."""


def hexle(value):
    """Lowercase hex of a u64 value without spaces (bpftool byte order)."""
    return "".join(
        "%02x" % byte for byte in value.to_bytes(8, byteorder="little")
    )


def byte_sum(value):
    """Sum of the 8 little-endian bytes of a u64 value."""
    return sum(value.to_bytes(8, byteorder="little"))


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
echo "=== begin guest_array ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "=== staged hashes ==="
sha256sum bpf_test_run.py array.bpf.o oob.bpf.o unchecked.bpf.o data.bin guest_array.sh
map_info() {{
  out="$1"
  python3 - "$out" >/tmp/xdp-mapinfo.stderr 2>&1 <<'PYEOF'
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
}}
life_case() {{
  tag="$1"; obj="$2"
  pin="/sys/fs/bpf/mojobpf_array_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  "$BPFTOOL" prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  "$BPFTOOL" map update id "$map_id" key 0 0 0 0 value {init_bytes} >/tmp/xdp-$tag.update 2>&1
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
count_case() {{
  tag="count"; obj="array.bpf.o"
  pin="/sys/fs/bpf/mojobpf_array_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  "$BPFTOOL" prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  "$BPFTOOL" map update id "$map_id" key 0 0 0 0 value {count_init_bytes} >/tmp/xdp-$tag.update 2>&1
  echo "init_exit=$?" >> "$out"
  "$BPFTOOL" prog run pinned "$pin" data_in data.bin repeat {first_repeat} > /tmp/xdp-$tag.run1 2>&1
  echo "run1_exit=$?" >> "$out"
  "$BPFTOOL" map lookup id "$map_id" key 0 0 0 0 > /tmp/xdp-$tag.after1 2>&1
  echo "after1_exit=$?" >> "$out"
  "$BPFTOOL" prog run pinned "$pin" data_in data.bin repeat {second_repeat} > /tmp/xdp-$tag.run2 2>&1
  echo "run2_exit=$?" >> "$out"
  "$BPFTOOL" map lookup id "$map_id" key 0 0 0 0 > /tmp/xdp-$tag.after2 2>&1
  echo "after2_exit=$?" >> "$out"
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag run1 ---"
  cat /tmp/xdp-$tag.run1
  echo "--- $tag after1 ---"
  cat /tmp/xdp-$tag.after1
  echo "--- $tag run2 ---"
  cat /tmp/xdp-$tag.run2
  echo "--- $tag after2 ---"
  cat /tmp/xdp-$tag.after2
  echo "=== END $tag ==="
}}
keyprobe_case() {{
  tag="keys"; obj="array.bpf.o"
  pin="/sys/fs/bpf/mojobpf_array_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  "$BPFTOOL" prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  "$BPFTOOL" map lookup id "$map_id" key 0 0 0 0 > /tmp/xdp-$tag.first 2>&1
  echo "first_exit=$?" >> "$out"
  "$BPFTOOL" map getnext id "$map_id" key 0 0 0 0 > /tmp/xdp-$tag.getnext 2>&1
  echo "getnext_exit=$?" >> "$out"
  "$BPFTOOL" map lookup id "$map_id" key 1 0 0 0 > /tmp/xdp-$tag.badkey 2>&1
  echo "badkey_exit=$?" >> "$out"
  "$BPFTOOL" map update id "$map_id" key 1 0 0 0 value 1 0 0 0 0 0 0 0 > /tmp/xdp-$tag.badupdate 2>&1
  echo "badupdate_exit=$?" >> "$out"
  "$BPFTOOL" map update id "$map_id" key 0 0 value 1 0 0 0 0 0 0 0 > /tmp/xdp-$tag.shortkey 2>&1
  echo "shortkey_exit=$?" >> "$out"
  "$BPFTOOL" map update id "$map_id" key 0 0 0 0 value 1 0 0 0 > /tmp/xdp-$tag.shortval 2>&1
  echo "shortval_exit=$?" >> "$out"
  "$BPFTOOL" map delete id "$map_id" key 0 0 0 0 > /tmp/xdp-$tag.delete 2>&1
  echo "delete_exit=$?" >> "$out"
  "$BPFTOOL" map lookup id "$map_id" key 0 0 0 0 > /tmp/xdp-$tag.still 2>&1
  echo "still_exit=$?" >> "$out"
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
  echo "=== BEGIN $tag ==="
  cat "$out"
  for probe in first getnext badkey badupdate shortkey shortval delete still; do
    echo "--- $tag $probe ---"
    cat /tmp/xdp-$tag.$probe
  done
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
for pin in /sys/fs/bpf/mojobpf_array_* /sys/fs/bpf/mojobpf-neg-* /sys/fs/bpf/mojobpf_control; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; stray=1; fi
done
if [ "$stray" -eq 0 ]; then echo "pin absent (unloaded)"; fi
echo "=== end guest_array ==="
"""

CASES = (
    ("life", "array.bpf.o", "life"),
    ("count", "array.bpf.o", "count"),
    ("keys", "array.bpf.o", "keys"),
    ("oob", "oob.bpf.o", "neg"),
    ("unchecked", "unchecked.bpf.o", "neg"),
)


def value_bytes(value):
    """Space-separated LE bytes of a u64 for bpftool value arguments."""
    return " ".join(
        "%d" % byte for byte in value.to_bytes(8, byteorder="little")
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
        ARRAY_SOURCE,
        OOB_SOURCE,
        UNCHECKED_SOURCE,
        ADAPTER,
        HARNESS,
    ):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK directory: %s" % SDK_INCLUDE)
    stage = guest_proc.owned_stage(prefix="mojo-array-", dir="/tmp")
    staged = {
        "bpf_test_run.py": HARNESS,
        "array.bpf.o": build_object(ARRAY_SOURCE, stage, "array"),
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
        if kind == "life":
            commands.append("life_case %s %s" % (tag, obj))
        elif kind == "count":
            commands.append("count_case")
        elif kind == "keys":
            commands.append("keyprobe_case")
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
        init_bytes=value_bytes(INIT_VALUE),
        count_init_bytes=value_bytes(COUNT_INIT),
        first_repeat=COUNT_FIRST_REPEAT,
        second_repeat=COUNT_SECOND_REPEAT,
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
    script_path = os.path.join(stage, "guest_array.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["data.bin", "guest_array.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    # A1 guest handoff: consume the staged bytes through the recorder
    # and re-stage from the consumed buffers, so the guest-reported
    # hashes compare against an attested identity.
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        tuple(staged) + ("data.bin", "guest_array.sh"),
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
        progress_banner="=== begin guest_array ===",
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


def parse_run_action(body, marker="run ---"):
    section = body.split(marker, 1)[1]
    match = re.search(r"Return value:\s*(\d+)", section)
    assert match, "no bpftool return-value line after %r" % marker
    return int(match.group(1))


def check_map_identity(tag):
    """Assert the libbpf-created map is the declared one-entry array."""
    body = executed()["results"][tag]["body"]
    fields = parse_fields(body)
    assert fields.get("load_exit") == "0", "%s: load failed" % tag
    assert fields.get("mapinfo_exit") == "0", "%s: mapinfo failed" % tag
    assert fields.get("map_found") == "1", "%s: map not found" % tag
    assert fields.get("map_type") == "array", "%s: not an array map" % tag
    assert fields.get("map_key") == "4", "%s: key size is not u32" % tag
    assert fields.get("map_value") == "8", "%s: value size is not u64" % tag
    assert fields.get("map_entries") == "1", "%s: not one entry" % tag
    return fields


def test_lifecycle_init_run_observe():
    fields = check_map_identity("life")
    for key in ("init_exit", "before_exit", "run_exit", "after_exit"):
        assert fields.get(key) == "0", "life: %s=%r" % (
            key, fields.get(key))
    assert fields.get("unload_ok") == "1", "life: pin was not removed"
    body = executed()["results"]["life"]["body"]
    before = parse_lookup_hex(body, "before ---")
    after = parse_lookup_hex(body, "after ---")
    assert before == hexle(INIT_VALUE), (
        "userspace init must read back %d first, got %s"
        % (INIT_VALUE, before)
    )
    assert parse_run_action(body) == XDP_PASS, "test-run action must be PASS"
    assert after == hexle(AFTER_VALUE), (
        "expected map value %s, observed %s" % (hexle(AFTER_VALUE), after)
    )


def test_exact_counts_after_quiescence():
    fields = check_map_identity("count")
    for key in ("init_exit", "run1_exit", "after1_exit",
                "run2_exit", "after2_exit"):
        assert fields.get(key) == "0", "count: %s=%r" % (
            key, fields.get(key))
    assert fields.get("unload_ok") == "1", "count: pin was not removed"
    body = executed()["results"]["count"]["body"]
    assert parse_run_action(body, "run1 ---") == XDP_PASS
    assert parse_run_action(body, "run2 ---") == XDP_PASS
    after1 = parse_lookup_hex(body, "after1 ---")
    after2 = parse_lookup_hex(body, "after2 ---")
    assert after1 == hexle(COUNT_FIRST_VALUE), (
        "after %d runs expected %s, observed %s"
        % (COUNT_FIRST_REPEAT, hexle(COUNT_FIRST_VALUE), after1)
    )
    assert after2 == hexle(COUNT_SECOND_VALUE), (
        "after %d more runs expected %s, observed %s"
        % (COUNT_SECOND_REPEAT, hexle(COUNT_SECOND_VALUE), after2)
    )
    assert byte_sum(COUNT_FIRST_VALUE) == sum(
        int(after1[i:i + 2], 16) for i in range(0, 16, 2)
    ), "first byte sum must match the exact bytes"
    assert byte_sum(COUNT_SECOND_VALUE) == sum(
        int(after2[i:i + 2], 16) for i in range(0, 16, 2)
    ), "second byte sum must match the exact bytes"


def probe_text(body, probe):
    """Return the transcript section of one named key probe."""
    section = body.split("--- keys %s ---" % probe, 1)[1]
    end = section.find("--- keys ")
    if end != -1:
        section = section[:end]
    end = section.find("=== END")
    if end != -1:
        section = section[:end]
    return section


def test_first_and_last_key():
    fields = check_map_identity("keys")
    assert fields.get("first_exit") == "0", "key 0 lookup must succeed"
    assert fields.get("getnext_exit") != "0", (
        "iteration past key 0 must fail (key 0 is the last key)"
    )
    body = executed()["results"]["keys"]["body"]
    first = parse_lookup_hex(body, "first ---")
    assert first == hexle(0), (
        "a fresh array entry must read back zero, got %s" % first
    )
    assert "No such file or directory" in probe_text(body, "getnext"), (
        "iteration past the last key must report ENOENT"
    )


def test_invalid_keys_refused():
    body = executed()["results"]["keys"]["body"]
    fields = parse_fields(body)
    assert fields.get("badkey_exit") != "0", (
        "lookup of key 1 must fail on a one-entry array"
    )
    assert fields.get("badupdate_exit") != "0", (
        "update of key 1 must fail on a one-entry array"
    )
    assert "Not found" in probe_text(body, "badkey"), (
        "out-of-range lookup must report a miss, never a value"
    )
    assert "Argument list too long" in probe_text(body, "badupdate"), (
        "out-of-range update must report E2BIG"
    )


def test_invalid_sizes_refused():
    body = executed()["results"]["keys"]["body"]
    fields = parse_fields(body)
    assert fields.get("shortkey_exit") != "0", (
        "update with a short key must fail"
    )
    assert fields.get("shortval_exit") != "0", (
        "update with a short value must fail"
    )
    assert "expected 8 bytes got 4" in probe_text(body, "shortval"), (
        "short value update must name the size mismatch"
    )


def test_delete_refused_and_entry_survives():
    body = executed()["results"]["keys"]["body"]
    fields = parse_fields(body)
    assert fields.get("delete_exit") != "0", (
        "array element deletion must fail (elements are preallocated)"
    )
    assert "Invalid argument" in probe_text(body, "delete"), (
        "array element deletion must report EINVAL"
    )
    assert fields.get("still_exit") == "0", (
        "key 0 must still read after the refused delete"
    )
    assert fields.get("unload_ok") == "1", "keys: pin was not removed"


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


def test_unchecked_rejected_by_verifier():
    """Unchecked dereference: first rejecting layer is the kernel verifier."""
    return check_verifier_rejection("unchecked", UNCHECKED_LOG_LINE)


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
        guest_proc.check_harness_exit(
            tag, exit=record["exit"],
            classification=doc.get("classification"),
            stage=doc.get("stage"),
            contract_version=doc.get("contract_version"),
            note=doc.get("note"), expect=4)
        assert doc.get("contract_version") == 2, (
            "%s: harness contract must be revision 2" % tag
        )
        assert doc.get("cleanup_ok") is None, (
            "%s: harness must leave cleanup_ok unset" % tag
        )
    rec = guest_proc.active_recorder()
    reported = guest_proc.parse_reported_hashes(run["output"])
    for name in (
        "bpf_test_run.py",
        "array.bpf.o",
        "oob.bpf.o",
        "unchecked.bpf.o",
        "data.bin",
        "guest_array.sh",
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
# evidence. They guard the lifecycle: the array object must load
# and run (positive) while the bad objects must observably not
# load (denials), proving the load observation is not vacuous.
CASE_DENIALS = {
    "test_oob_rejected_by_verifier": (
        "test_lifecycle_init_run_observe", "VERIFY"
    ),
    "test_unchecked_rejected_by_verifier": (
        "test_lifecycle_init_run_observe", "VERIFY"
    ),
}


# Durable inputs per case: absolute repo paths plus ("stage",
# basename) entries resolved against the guest stage at finish.
# Every non-board case pins the sources it depends on; a class
# with any missing file digests to zeros and can never back a
# PASS.
CASE_INPUTS = {
    "test_lifecycle_init_run_observe": {
        "sources": [ARRAY_SOURCE],
        "objects": [("stage", "array.bpf.o")],
        "corpus": [],
    },
    "test_exact_counts_after_quiescence": {
        "sources": [ARRAY_SOURCE],
        "objects": [("stage", "array.bpf.o")],
        "corpus": [],
    },
    "test_first_and_last_key": {
        "sources": [ARRAY_SOURCE],
        "objects": [("stage", "array.bpf.o")],
        "corpus": [],
    },
    "test_invalid_keys_refused": {
        "sources": [ARRAY_SOURCE],
        "objects": [("stage", "array.bpf.o")],
        "corpus": [],
    },
    "test_invalid_sizes_refused": {
        "sources": [ARRAY_SOURCE],
        "objects": [("stage", "array.bpf.o")],
        "corpus": [],
    },
    "test_delete_refused_and_entry_survives": {
        "sources": [ARRAY_SOURCE],
        "objects": [("stage", "array.bpf.o")],
        "corpus": [],
    },
    "test_oob_rejected_by_verifier": {
        "sources": [OOB_SOURCE],
        "objects": [("stage", "oob.bpf.o")],
        "corpus": [],
    },
    "test_unchecked_rejected_by_verifier": {
        "sources": [UNCHECKED_SOURCE],
        "objects": [("stage", "unchecked.bpf.o")],
        "corpus": [],
    },
    "test_guest_provenance": {
        "sources": [ARRAY_SOURCE, OOB_SOURCE, UNCHECKED_SOURCE, HARNESS,
                    ("stage", "guest_array.sh")],
        "objects": [
            ("stage", "array.bpf.o"),
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
        suite_id="kernel-array", suite_path=__file__,
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
    print("array maps: lifecycle, count, key and negative checks passed")
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
