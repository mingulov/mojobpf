# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""In-kernel proof for the generalized array map shapes.

Builds the multi-pair round trips (2, 3, and 4 pairs) and the
delete probes (1 to 4 deletions) through the genuine pipeline
(``mojo build --emit llvm`` with the packaged SDK on the import
path -> ``compiler/mojo_ir_adapter.py`` -> ``llc -mtriple=bpfel
-mcpu=v3``), then boots one disposable Linux guest and proves the
behavior per shape:

* read-modify-write lifecycle per entry (41 to 42) with the
  XDP_PASS action on every shape;
* exact per-entry counts after repeated runs (no lost or doubled
  updates on any entry);
* first/last/invalid keys per count: key 0 and key N-1 read back
  zero on a fresh map, a userspace get-next-key walk visits 0 to
  N-1 and reports ENOENT past the last key (the kernel offers no
  from-program iteration helper, so the walk is observed from
  userspace), out-of-range lookup reports a miss and
  out-of-range update reports E2BIG, short keys and values are
  refused;
* delete probes observe -EINVAL on every key (the XDP_PASS
  action) and every entry still reads back zero.

Staged file hashes are re-verified inside the guest so every
observation is tied to the exact bytes built here.

Requires a working Mojo compiler, LLVM ``llc``, ``bpftool``, and
``vng`` (virtme-ng) with a cached guest image on PATH
(default release v6.12; MOJOBPF_VNG_RELEASE selects the matrix lane).
Missing tools fail loudly as environment failures, never as
passes. MOJOBPF_GUEST_ROUTE=parsed (with ``mojobpf-lower`` via
MOJOBPF_LOWER or PATH) builds the same objects through the parsed
lowering for route-equivalence runs; the default lane-a keeps the
committed pins.

Runnable directly (``python3
tests/kernel/test_generalized_arrays.py``) or under any
``test_``-style runner. Standard library only. The guest boot
plus the case runs take several minutes under software emulation;
all cases share a single boot.
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

from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402
COMPILE_DIR = os.path.join(REPO_ROOT, "tests", "compile")
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

XDP_PASS = 2
# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = 1500
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

MAP_NAME = "mojobpf_map0"
INIT_VALUE = 41
HIT_VALUE = 42
COUNT_INIT = 7
COUNT_FIRST_REPEAT = 5
COUNT_SECOND_REPEAT = 9

RMW_SOURCES = {
    2: os.path.join(COMPILE_DIR, "maps_rmw2.mojo"),
    3: os.path.join(COMPILE_DIR, "maps_rmw3.mojo"),
    4: os.path.join(COMPILE_DIR, "maps_rmw4.mojo"),
}
DELETE_SOURCES = {
    count: os.path.join(COMPILE_DIR, "maps_delete%d.mojo" % count)
    for count in (1, 2, 3, 4)
}


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
        ["mojo", "build", "--emit", "llvm", *FRONTEND_TARGET_FLAGS,
         "-I", SDK_INCLUDE, "-o", raw_path, source]
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
echo "=== begin guest_genarray ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
bpftool version | head -2
echo "=== staged hashes ==="
sha256sum {staged_names} data.bin guest_genarray.sh
le32() {{
  printf '%d 0 0 0' "$1"
}}
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
        ["bpftool", "-j", "map", "show"],
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
rmw_life() {{
  tag="$1"; obj="$2"; entries="$3"
  pin="/sys/fs/bpf/mojobpf_gen_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  bpftool prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  k=0
  while [ "$k" -lt "$entries" ]; do
    bpftool map update id "$map_id" key $(le32 "$k") value {init_bytes} >/tmp/xdp-$tag.init$k 2>&1
    echo "init${{k}}_exit=$?" >> "$out"
    k=$((k + 1))
  done
  bpftool prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run 2>&1
  echo "run_exit=$?" >> "$out"
  k=0
  while [ "$k" -lt "$entries" ]; do
    bpftool map lookup id "$map_id" key $(le32 "$k") > /tmp/xdp-$tag.key$k 2>&1
    echo "key${{k}}_exit=$?" >> "$out"
    k=$((k + 1))
  done
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag run ---"
  cat /tmp/xdp-$tag.run
  k=0
  while [ "$k" -lt "$entries" ]; do
    echo "--- $tag key$k ---"
    cat /tmp/xdp-$tag.key$k
    k=$((k + 1))
  done
  echo "=== END $tag ==="
}}
rmw_count() {{
  tag="$1"; obj="$2"; entries="$3"
  pin="/sys/fs/bpf/mojobpf_gen_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  bpftool prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  k=0
  while [ "$k" -lt "$entries" ]; do
    bpftool map update id "$map_id" key $(le32 "$k") value {count_init_bytes} >/tmp/xdp-$tag.init$k 2>&1
    echo "init${{k}}_exit=$?" >> "$out"
    k=$((k + 1))
  done
  bpftool prog run pinned "$pin" data_in data.bin repeat {first_repeat} > /tmp/xdp-$tag.run1 2>&1
  echo "run1_exit=$?" >> "$out"
  k=0
  while [ "$k" -lt "$entries" ]; do
    bpftool map lookup id "$map_id" key $(le32 "$k") > /tmp/xdp-$tag.after1key$k 2>&1
    echo "after1key${{k}}_exit=$?" >> "$out"
    k=$((k + 1))
  done
  bpftool prog run pinned "$pin" data_in data.bin repeat {second_repeat} > /tmp/xdp-$tag.run2 2>&1
  echo "run2_exit=$?" >> "$out"
  k=0
  while [ "$k" -lt "$entries" ]; do
    bpftool map lookup id "$map_id" key $(le32 "$k") > /tmp/xdp-$tag.after2key$k 2>&1
    echo "after2key${{k}}_exit=$?" >> "$out"
    k=$((k + 1))
  done
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag run1 ---"
  cat /tmp/xdp-$tag.run1
  k=0
  while [ "$k" -lt "$entries" ]; do
    echo "--- $tag after1key$k ---"
    cat /tmp/xdp-$tag.after1key$k
    k=$((k + 1))
  done
  echo "--- $tag run2 ---"
  cat /tmp/xdp-$tag.run2
  k=0
  while [ "$k" -lt "$entries" ]; do
    echo "--- $tag after2key$k ---"
    cat /tmp/xdp-$tag.after2key$k
    k=$((k + 1))
  done
  echo "=== END $tag ==="
}}
rmw_keys() {{
  tag="$1"; obj="$2"; entries="$3"
  pin="/sys/fs/bpf/mojobpf_gen_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  bpftool prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  last=$((entries - 1))
  bpftool map lookup id "$map_id" key $(le32 0) > /tmp/xdp-$tag.first 2>&1
  echo "first_exit=$?" >> "$out"
  bpftool map lookup id "$map_id" key $(le32 "$last") > /tmp/xdp-$tag.last 2>&1
  echo "last_exit=$?" >> "$out"
  k=0
  while [ "$k" -lt "$last" ]; do
    bpftool map getnext id "$map_id" key $(le32 "$k") > /tmp/xdp-$tag.walk$k 2>&1
    echo "walk${{k}}_exit=$?" >> "$out"
    k=$((k + 1))
  done
  bpftool map getnext id "$map_id" key $(le32 "$last") > /tmp/xdp-$tag.pastend 2>&1
  echo "pastend_exit=$?" >> "$out"
  bpftool map lookup id "$map_id" key $(le32 "$entries") > /tmp/xdp-$tag.badkey 2>&1
  echo "badkey_exit=$?" >> "$out"
  bpftool map update id "$map_id" key $(le32 "$entries") value 1 0 0 0 0 0 0 0 > /tmp/xdp-$tag.badupdate 2>&1
  echo "badupdate_exit=$?" >> "$out"
  bpftool map update id "$map_id" key 0 0 value 1 0 0 0 0 0 0 0 > /tmp/xdp-$tag.shortkey 2>&1
  echo "shortkey_exit=$?" >> "$out"
  bpftool map update id "$map_id" key 0 0 0 0 value 1 0 0 0 > /tmp/xdp-$tag.shortval 2>&1
  echo "shortval_exit=$?" >> "$out"
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag first ---"
  cat /tmp/xdp-$tag.first
  echo "--- $tag last ---"
  cat /tmp/xdp-$tag.last
  k=0
  while [ "$k" -lt "$last" ]; do
    echo "--- $tag walk$k ---"
    cat /tmp/xdp-$tag.walk$k
    k=$((k + 1))
  done
  echo "--- $tag pastend ---"
  cat /tmp/xdp-$tag.pastend
  for probe in badkey badupdate shortkey shortval; do
    echo "--- $tag $probe ---"
    cat /tmp/xdp-$tag.$probe
  done
  echo "=== END $tag ==="
}}
op_probe() {{
  tag="$1"; obj="$2"; entries="$3"
  pin="/sys/fs/bpf/mojobpf_gen_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  bpftool prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  map_info "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  bpftool prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run 2>&1
  echo "run_exit=$?" >> "$out"
  k=0
  while [ "$k" -lt "$entries" ]; do
    bpftool map lookup id "$map_id" key $(le32 "$k") > /tmp/xdp-$tag.key$k 2>&1
    echo "key${{k}}_exit=$?" >> "$out"
    k=$((k + 1))
  done
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag run ---"
  cat /tmp/xdp-$tag.run
  k=0
  while [ "$k" -lt "$entries" ]; do
    echo "--- $tag key$k ---"
    cat /tmp/xdp-$tag.key$k
    k=$((k + 1))
  done
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
stray=0
for pin in /sys/fs/bpf/mojobpf_gen_*; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; stray=1; fi
done
if [ "$stray" -eq 0 ]; then echo "pin absent (unloaded)"; fi
echo "=== end guest_genarray ==="
"""

CASES = (
    ("life2", "rmw2.bpf.o", "rmw_life", 2),
    ("life3", "rmw3.bpf.o", "rmw_life", 3),
    ("life4", "rmw4.bpf.o", "rmw_life", 4),
    ("count2", "rmw2.bpf.o", "rmw_count", 2),
    ("count3", "rmw3.bpf.o", "rmw_count", 3),
    ("count4", "rmw4.bpf.o", "rmw_count", 4),
    ("keys2", "rmw2.bpf.o", "rmw_keys", 2),
    ("keys3", "rmw3.bpf.o", "rmw_keys", 3),
    ("keys4", "rmw4.bpf.o", "rmw_keys", 4),
    ("del1", "del1.bpf.o", "op_probe", 1),
    ("del2", "del2.bpf.o", "op_probe", 2),
    ("del3", "del3.bpf.o", "op_probe", 3),
    ("del4", "del4.bpf.o", "op_probe", 4),
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
    sources = (
        list(RMW_SOURCES.values())
        + list(DELETE_SOURCES.values())
        + [ADAPTER]
    )
    for path in sources:
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK directory: %s" % SDK_INCLUDE)
    stage = guest_proc.owned_stage(prefix="mojo-genarray-", dir="/tmp")
    staged = {}
    for entries, source in RMW_SOURCES.items():
        staged["rmw%d.bpf.o" % entries] = build_object(
            source, stage, "rmw%d" % entries, entries
        )
    for entries, source in DELETE_SOURCES.items():
        staged["del%d.bpf.o" % entries] = build_object(
            source, stage, "del%d" % entries, entries
        )
    with open(os.path.join(stage, "data.bin"), "wb") as handle:
        handle.write(bytes(60))
    for name, src in staged.items():
        with guest_proc.open_consumed(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    commands = []
    for tag, obj, kind, entries in CASES:
        commands.append("%s %s %s %d" % (kind, tag, obj, entries))
    script = GUEST_SCRIPT.format(
        stage=stage,
        staged_names=" ".join(sorted(staged)),
        commands="\n".join(commands),
        map_name=MAP_NAME,
        init_bytes=value_bytes(INIT_VALUE),
        count_init_bytes=value_bytes(COUNT_INIT),
        first_repeat=COUNT_FIRST_REPEAT,
        second_repeat=COUNT_SECOND_REPEAT,
    )
    script_path = os.path.join(stage, "guest_genarray.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["data.bin", "guest_genarray.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    # A1 guest handoff: consume the staged bytes through the recorder
    # and re-stage from the consumed buffers, so the guest-reported
    # hashes compare against an attested identity.
    guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        tuple(staged) + ("data.bin", "guest_genarray.sh"),
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
        progress_banner="=== begin guest_genarray ===",
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


def parse_run_action(body, marker="run ---"):
    section = body.split(marker, 1)[1]
    match = re.search(r"Return value:\s*(\d+)", section)
    assert match, "no bpftool return-value line after %r" % marker
    return int(match.group(1))


def parse_walk_key(body, marker):
    """Extract the getnext-reported next key as an int.

    The parser matches the ``next key:`` line specifically:
    bpftool echoes the query key on a ``key:`` line first, and
    matching that line would report the input instead of the
    step result.
    """
    section = body.split(marker, 1)[1]
    match = re.search(r"next key:\s*([0-9a-fA-F ]+)", section)
    assert match, "no bpftool next-key line after %r" % marker
    raw = bytes(int(part, 16) for part in match.group(1).split())
    return int.from_bytes(raw, byteorder="little")


def hexle(value):
    return value.to_bytes(8, byteorder="little").hex()


def sha256_file(path):
    digest = hashlib.sha256()
    with guest_proc.open_consumed(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_map_identity(tag, entries):
    """Assert the libbpf-created map is the declared N-entry array."""
    body = executed()["results"][tag]["body"]
    fields = parse_fields(body)
    assert fields.get("load_exit") == "0", "%s: load failed" % tag
    assert fields.get("mapinfo_exit") == "0", "%s: mapinfo failed" % tag
    assert fields.get("map_found") == "1", "%s: map not found" % tag
    assert fields.get("map_type") == "array", "%s: not an array map" % tag
    assert fields.get("map_key") == "4", "%s: key size is not u32" % tag
    assert fields.get("map_value") == "8", (
        "%s: value size is not u64" % tag
    )
    assert fields.get("map_entries") == str(entries), (
        "%s: not %d entries" % (tag, entries)
    )
    return fields


def check_rmw_lifecycle(entries):
    tag = "life%d" % entries
    fields = check_map_identity(tag, entries)
    for key in range(entries):
        assert fields.get("init%d_exit" % key) == "0", (
            "%s: init%d failed" % (tag, key)
        )
        assert fields.get("key%d_exit" % key) == "0", (
            "%s: key%d lookup failed" % (tag, key)
        )
    assert fields.get("run_exit") == "0", "%s: run failed" % tag
    assert fields.get("unload_ok") == "1", "%s: pin was not removed" % tag
    body = executed()["results"][tag]["body"]
    assert parse_run_action(body) == XDP_PASS, (
        "%s: test-run action must be PASS" % tag
    )
    for key in range(entries):
        observed = parse_lookup_hex(body, "key%d ---" % key)
        assert observed == hexle(HIT_VALUE), (
            "%s: entry %d must read 42 after one run, got %s"
            % (tag, key, observed)
        )


def test_rmw_lifecycle_two_entries():
    check_rmw_lifecycle(2)


def test_rmw_lifecycle_three_entries():
    check_rmw_lifecycle(3)


def test_rmw_lifecycle_four_entries():
    check_rmw_lifecycle(4)


def check_rmw_counts(entries):
    tag = "count%d" % entries
    fields = check_map_identity(tag, entries)
    for key in range(entries):
        assert fields.get("init%d_exit" % key) == "0", (
            "%s: init%d failed" % (tag, key)
        )
        assert fields.get("after1key%d_exit" % key) == "0", (
            "%s: after1key%d failed" % (tag, key)
        )
        assert fields.get("after2key%d_exit" % key) == "0", (
            "%s: after2key%d failed" % (tag, key)
        )
    assert fields.get("run1_exit") == "0", "%s: run1 failed" % tag
    assert fields.get("run2_exit") == "0", "%s: run2 failed" % tag
    assert fields.get("unload_ok") == "1", "%s: pin was not removed" % tag
    body = executed()["results"][tag]["body"]
    assert parse_run_action(body, "run1 ---") == XDP_PASS
    assert parse_run_action(body, "run2 ---") == XDP_PASS
    first_value = COUNT_INIT + COUNT_FIRST_REPEAT
    second_value = first_value + COUNT_SECOND_REPEAT
    for key in range(entries):
        after1 = parse_lookup_hex(body, "after1key%d ---" % key)
        after2 = parse_lookup_hex(body, "after2key%d ---" % key)
        assert after1 == hexle(first_value), (
            "%s: entry %d after %d runs must be %d, got %s"
            % (tag, key, COUNT_FIRST_REPEAT, first_value, after1)
        )
        assert after2 == hexle(second_value), (
            "%s: entry %d after %d more runs must be %d, got %s"
            % (tag, key, COUNT_SECOND_REPEAT, second_value, after2)
        )
        assert byte_sum(first_value) == sum(
            int(after1[i:i + 2], 16) for i in range(0, 16, 2)
        ), "%s: entry %d first byte sum must match" % (tag, key)
        assert byte_sum(second_value) == sum(
            int(after2[i:i + 2], 16) for i in range(0, 16, 2)
        ), "%s: entry %d second byte sum must match" % (tag, key)


def byte_sum(value):
    return sum(value.to_bytes(8, byteorder="little"))


def test_rmw_exact_counts_two_entries():
    check_rmw_counts(2)


def test_rmw_exact_counts_three_entries():
    check_rmw_counts(3)


def test_rmw_exact_counts_four_entries():
    check_rmw_counts(4)


def probe_text(body, tag, probe):
    section = body.split("--- %s %s ---" % (tag, probe), 1)[1]
    end = section.find("--- %s " % tag)
    if end != -1:
        section = section[:end]
    end = section.find("=== END")
    if end != -1:
        section = section[:end]
    return section


def check_first_last_walk(entries):
    tag = "keys%d" % entries
    fields = check_map_identity(tag, entries)
    assert fields.get("first_exit") == "0", "%s: key 0 lookup failed" % tag
    assert fields.get("last_exit") == "0", (
        "%s: key %d lookup failed" % (tag, entries - 1)
    )
    body = executed()["results"][tag]["body"]
    first = parse_lookup_hex(body, "first ---")
    last = parse_lookup_hex(body, "last ---")
    assert first == hexle(0), "%s: fresh key 0 must read zero" % tag
    assert last == hexle(0), "%s: fresh last key must read zero" % tag
    for key in range(entries - 1):
        assert fields.get("walk%d_exit" % key) == "0", (
            "%s: getnext from key %d must succeed" % (tag, key)
        )
        observed = parse_walk_key(body, "walk%d ---" % key)
        assert observed == key + 1, (
            "%s: next key after %d must be %d, got %d"
            % (tag, key, key + 1, observed)
        )
    assert fields.get("pastend_exit") != "0", (
        "%s: iteration past key %d must fail" % (tag, entries - 1)
    )
    assert "No such file or directory" in probe_text(body, tag, "pastend"), (
        "%s: iteration past the last key must report ENOENT" % tag
    )


def test_first_last_walk_two_entries():
    check_first_last_walk(2)


def test_first_last_walk_three_entries():
    check_first_last_walk(3)


def test_first_last_walk_four_entries():
    check_first_last_walk(4)


def check_invalid_keys_sizes(entries):
    tag = "keys%d" % entries
    body = executed()["results"][tag]["body"]
    fields = parse_fields(body)
    assert fields.get("badkey_exit") != "0", (
        "%s: lookup of key %d must fail" % (tag, entries)
    )
    assert fields.get("badupdate_exit") != "0", (
        "%s: update of key %d must fail" % (tag, entries)
    )
    assert "Not found" in probe_text(body, tag, "badkey"), (
        "%s: out-of-range lookup must report a miss" % tag
    )
    assert "Argument list too long" in probe_text(body, tag, "badupdate"), (
        "%s: out-of-range update must report E2BIG" % tag
    )
    assert fields.get("shortkey_exit") != "0", (
        "%s: update with a short key must fail" % tag
    )
    assert fields.get("shortval_exit") != "0", (
        "%s: update with a short value must fail" % tag
    )
    assert "expected 8 bytes got 4" in probe_text(body, tag, "shortval"), (
        "%s: short value update must name the size mismatch" % tag
    )
    assert fields.get("unload_ok") == "1", "%s: pin was not removed" % tag


def test_invalid_keys_sizes_two_entries():
    check_invalid_keys_sizes(2)


def test_invalid_keys_sizes_three_entries():
    check_invalid_keys_sizes(3)


def test_invalid_keys_sizes_four_entries():
    check_invalid_keys_sizes(4)


def check_op_probe(prefix, entries):
    tag = "%s%d" % (prefix, entries)
    fields = check_map_identity(tag, entries)
    assert fields.get("run_exit") == "0", "%s: run failed" % tag
    for key in range(entries):
        assert fields.get("key%d_exit" % key) == "0", (
            "%s: key%d lookup failed" % (tag, key)
        )
    assert fields.get("unload_ok") == "1", "%s: pin was not removed" % tag
    body = executed()["results"][tag]["body"]
    assert parse_run_action(body) == XDP_PASS, (
        "%s: test-run action must be PASS" % tag
    )
    for key in range(entries):
        observed = parse_lookup_hex(body, "key%d ---" % key)
        assert observed == hexle(0), (
            "%s: entry %d must still read zero, got %s"
            % (tag, key, observed)
        )


def test_delete_refused_one_entry():
    check_op_probe("del", 1)


def test_delete_refused_two_entries():
    check_op_probe("del", 2)


def test_delete_refused_three_entries():
    check_op_probe("del", 3)


def test_delete_refused_four_entries():
    check_op_probe("del", 4)


def test_guest_provenance_and_cleanup():
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
        "rmw2.bpf.o",
        "rmw3.bpf.o",
        "rmw4.bpf.o",
        "del1.bpf.o",
        "del2.bpf.o",
        "del3.bpf.o",
        "del4.bpf.o",
        "data.bin",
        "guest_genarray.sh",
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


# No denials: no harness records flow through this suite (bpftool
# field blocks only), so there are no expected-failure wire
# cases. Refusals (invalid keys, sizes, deletes) are asserted
# positively from the transcript.
CASE_DENIALS = {}


def _rmw_inputs(entries):
    return {
        "sources": [RMW_SOURCES[entries]],
        "objects": [("stage", "rmw%d.bpf.o" % entries)],
        "corpus": [],
    }


def _del_inputs(entries):
    return {
        "sources": [DELETE_SOURCES[entries]],
        "objects": [("stage", "del%d.bpf.o" % entries)],
        "corpus": [],
    }


# Durable inputs per case: absolute repo paths plus ("stage",
# basename) entries resolved against the guest stage at finish.
# Every non-board case pins the sources it depends on; a class
# with any missing file digests to zeros and can never back a
# PASS.
CASE_INPUTS = {
    "test_rmw_lifecycle_two_entries": _rmw_inputs(2),
    "test_rmw_lifecycle_three_entries": _rmw_inputs(3),
    "test_rmw_lifecycle_four_entries": _rmw_inputs(4),
    "test_rmw_exact_counts_two_entries": _rmw_inputs(2),
    "test_rmw_exact_counts_three_entries": _rmw_inputs(3),
    "test_rmw_exact_counts_four_entries": _rmw_inputs(4),
    "test_first_last_walk_two_entries": _rmw_inputs(2),
    "test_first_last_walk_three_entries": _rmw_inputs(3),
    "test_first_last_walk_four_entries": _rmw_inputs(4),
    "test_invalid_keys_sizes_two_entries": _rmw_inputs(2),
    "test_invalid_keys_sizes_three_entries": _rmw_inputs(3),
    "test_invalid_keys_sizes_four_entries": _rmw_inputs(4),
    "test_delete_refused_one_entry": _del_inputs(1),
    "test_delete_refused_two_entries": _del_inputs(2),
    "test_delete_refused_three_entries": _del_inputs(3),
    "test_delete_refused_four_entries": _del_inputs(4),
    "test_guest_provenance_and_cleanup": {
        "sources": ([RMW_SOURCES[n] for n in (2, 3, 4)]
                    + [DELETE_SOURCES[n] for n in (1, 2, 3, 4)]
                    + [("stage", "guest_genarray.sh")]),
        "objects": ([("stage", "rmw%d.bpf.o" % n) for n in (2, 3, 4)]
                    + [("stage", "del%d.bpf.o" % n)
                       for n in (1, 2, 3, 4)]),
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
        suite_id="kernel-generalized", suite_path=__file__,
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
    print("generalized arrays: lifecycle, count, key and probe checks passed")
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())

