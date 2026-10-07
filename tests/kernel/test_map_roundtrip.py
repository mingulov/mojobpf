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
environment failures, never as passes.

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
GUEST_KERNEL_PREFIX = (
    VNG_RELEASE[1:] if VNG_RELEASE.startswith("v") else VNG_RELEASE
)
VNG_TIMEOUT = 900

INIT_VALUE = 41
BASE_VALUE = 42
MUTATED_VALUE = 43
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
    proc = run_step(
        [
            "mojo",
            "build",
            "--emit",
            "llvm",
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
echo "=== begin guest_map ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
bpftool version | head -2
echo "=== staged hashes ==="
sha256sum bpf_test_run.py base.bpf.o mutated.bpf.o oob.bpf.o unchecked.bpf.o data.bin
map_case() {{
  tag="$1"; obj="$2"
  pin="/sys/fs/bpf/mojobpf_map_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  bpftool prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  python3 - "$out" >/tmp/xdp-$tag.mapinfo 2>&1 <<'PYEOF'
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
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  bpftool map update id "$map_id" key 0 0 0 0 value {init} 0 0 0 0 0 0 0 >/tmp/xdp-$tag.update 2>&1
  echo "init_exit=$?" >> "$out"
  bpftool map lookup id "$map_id" key 0 0 0 0 > /tmp/xdp-$tag.before 2>&1
  echo "before_exit=$?" >> "$out"
  bpftool prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run 2>&1
  echo "run_exit=$?" >> "$out"
  bpftool map lookup id "$map_id" key 0 0 0 0 > /tmp/xdp-$tag.after 2>&1
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
  python3 bpf_test_run.py --object "$obj" --expect-action {action} \\
    --data-in data.bin --output "$out" >/tmp/xdp-$tag.stdout 2>/tmp/xdp-$tag.stderr
  code=$?
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
stray=0
for pin in /sys/fs/bpf/mojobpf_map_* /sys/fs/bpf/mojobpf_control; do
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
    stage = tempfile.mkdtemp(prefix="mojo-map-", dir="/tmp")
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
        with open(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    commands = []
    for tag, obj, kind in CASES:
        if kind == "map":
            commands.append("map_case %s %s" % (tag, obj))
        else:
            commands.append("neg_case %s %s" % (tag, obj))
    script = GUEST_SCRIPT.format(
        stage=stage,
        commands="\n".join(commands),
        map_name=MAP_NAME,
        init=INIT_VALUE,
        action=XDP_PASS,
    )
    script_path = os.path.join(stage, "guest_map.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["data.bin", "guest_map.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    try:
        proc = subprocess.run(
            ["vng", "--run", VNG_RELEASE, "--disable-kvm",
             "--exec", "bash %s" % script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=VNG_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise EnvironmentFailure(
            "vng guest run timed out after %ds (stage kept at %s):\n%s"
            % (VNG_TIMEOUT, stage, (exc.stdout or "") + (exc.stderr or ""))
        )
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "vng guest run failed (exit %d, stage kept at %s):\n%s"
            % (proc.returncode, stage, output[-4000:])
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
    missing = [tag for tag, _, _ in CASES if tag not in results]
    if missing:
        raise EnvironmentFailure(
            "guest output lacks cases %s (stage kept at %s):\n%s"
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
        raise AssertionError(
            "%s: harness did not emit JSON:\n%s" % (tag, record["body"][-500:])
        )
    assert record["exit"] == 4, (
        "%s: harness must exit 4 on the verifier rejection, got %r"
        % (tag, record["exit"])
    )
    assert doc.get("stage") == "load", "%s: expected load stage" % tag
    assert doc.get("classification") == "verifier", (
        "%s: expected verifier classification, got %r"
        % (tag, doc.get("classification"))
    )
    blob = json.dumps(doc.get("commands", []))
    assert log_line in blob, (
        "%s: kernel verifier log must contain %r" % (tag, log_line)
    )


def test_oob_rejected_by_verifier():
    """Wrong value size: first rejecting layer is the kernel verifier."""
    check_verifier_rejection("oob", OOB_LOG_LINE)


def test_unchecked_rejected_by_verifier():
    """Unchecked dereference: first rejecting layer is the kernel verifier."""
    check_verifier_rejection("unchecked", UNCHECKED_LOG_LINE)


def test_guest_provenance():
    run = executed()
    assert "guest-kernel: %s" % GUEST_KERNEL_PREFIX in run["output"], (
        "guest kernel must be v%s" % GUEST_KERNEL_PREFIX
    )
    assert "pin absent (unloaded)" in run["output"], "pins must be removed"
    assert "PIN STILL PRESENT" not in run["output"], "pins must be removed"
    for tag in ("oob", "unchecked"):
        body = run["results"][tag]["body"]
        doc = json.loads(body)
        assert doc.get("contract_version") == 2, (
            "%s: harness contract must be revision 2" % tag
        )
        # Load-stage failures pin nothing, so there is nothing to clean.
        assert doc.get("cleanup_ok") is None, (
            "%s: harness must leave cleanup_ok unset" % tag
        )
    for name in (
        "bpf_test_run.py",
        "base.bpf.o",
        "mutated.bpf.o",
        "oob.bpf.o",
        "unchecked.bpf.o",
        "data.bin",
    ):
        expected = sha256_file(os.path.join(run["stage"], name))
        assert expected in run["output"], (
            "guest must re-verify staged hash of %s" % name
        )


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
    print("map round trip: guest behavior, mutation, and stale checks passed")
    print("guest stage kept at: %s" % executed()["stage"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
