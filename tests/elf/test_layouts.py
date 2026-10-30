# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""ABI layout and coherence proof for the classifier programs.

Checks every numeric claim in ``tests/elf/abi_layouts.json`` (the
single coherence record tying SDK source behavior to LLVM type
layouts and decoder assumptions) against genuine build artifacts
from four independent legs:

* Mojo: ``tests/elf/layouts_probe.mojo`` built with the pinned
  compiler reports ``size_of``/``align_of`` for every SDK value
  type and dumps known struct values byte by byte;
* C: ``tests/reference_c/sdk_layouts.c`` built with the system C
  compiler reports ``sizeof``/``_Alignof``/``offsetof`` for the
  mirrored declarations (an independent control sharing no code
  with the SDK);
* LLVM: the frontend IR gives the host data layout, the adapted
  IR gives the exact kernel-visible BPF triple and data layout,
  and the C fixture compiled with ``clang --target=bpf`` gives
  the BPF-target struct layout computed from its type records;
* IR scan: every classifier's adapted IR is scanned to prove no
  packed-struct cast exists (each packet-rooted load is a single
  byte), each context-rooted load is a 32-bit word at offset 0
  or 4, the record's guard needs are present and fail closed,
  and the entry signature stays ``i32 @xdp_entry(ptr)``.

One classifier object is also checked for the decoder row: no
BTF sections (classifiers carry no maps) and the exact license
bytes. Map BTF and map decoding belong to the map contract
suite and are referenced, not duplicated, here.

Requires the pinned Mojo compiler, LLVM ``llc``, a system C
compiler, and ``clang`` with the BPF target on PATH. Missing
tools fail loudly as environment failures; any mismatch is a
proof failure. Neither ever passes.

Runnable directly (``python3 tests/elf/test_layouts.py``) or
under any ``test_``-style runner. Standard library only.
"""

import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402

COMPILE_DIR = os.path.join(REPO_ROOT, "tests", "compile")
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
SDK_DIR = os.path.join(SDK_INCLUDE, "mojobpf")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
LAYOUT_PROBE = os.path.join(REPO_ROOT, "tests", "elf", "layouts_probe.mojo")
C_FIXTURE = os.path.join(
    REPO_ROOT, "tests", "reference_c", "sdk_layouts.c"
)
RECORD_PATH = os.path.join(REPO_ROOT, "tests", "elf", "abi_layouts.json")

sys.path.insert(0, os.path.join(REPO_ROOT, "compiler"))
import audit  # noqa: E402

EM_BPF = 247
ET_REL = 1
LICENSE_BYTES = b"Apache-2.0 WITH LLVM-exception\x00"

SSA = r"%?[A-Za-z0-9_.$-]+"
DEFINE_RE = re.compile(r"^define\s+\S+\s+i32\s+@xdp_entry\(ptr[^)]*\)")
ASM_RE = re.compile(r"^%(\S+)\s*=\s*call\s+ptr\s+asm\s+\"\",\s*\"=r,0\"")
GEP_RE = re.compile(
    r"^%([A-Za-z0-9_.$-]+)\s*=\s*getelementptr\s+inbounds\s+"
    r"(i\d+),\s*ptr\s+(" + SSA + r")\s*,\s*(.*)$"
)
LOAD_RE = re.compile(
    r"^%([A-Za-z0-9_.$-]+)\s*=\s*load\s+(i\d+),\s*ptr\s+(" + SSA + r")"
)
ICMP_RE = re.compile(
    r"^%([A-Za-z0-9_.$-]+)\s*=\s*icmp\s+ugt\s+i64\s+("
    + SSA
    + r")\s*,\s*("
    + SSA
    + r")"
)
ADD_RE = re.compile(
    r"^%([A-Za-z0-9_.$-]+)\s*=\s*add\s+i64\s+("
    + SSA
    + r")\s*,\s*("
    + SSA
    + r")"
)
SUB_RE = re.compile(
    r"^%([A-Za-z0-9_.$-]+)\s*=\s*sub\s+i64\s+("
    + SSA
    + r")\s*,\s*("
    + SSA
    + r")"
)
BRCOND_RE = re.compile(
    r"^br\s+i1\s+("
    + SSA
    + r")\s*,\s*label\s+("
    + SSA
    + r")\s*,\s*label\s+("
    + SSA
    + r")"
)
LABEL_RE = re.compile(r"^%?([A-Za-z0-9_.$-]+):$")
ASM_FULL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+ptr\s+asm\s+\"\",\s*\"=r,0\""
    r"\(i64\s+(" + SSA + r")\)$"
)
ADD_DEF_RE = re.compile(r"^%(\S+)\s*=\s*add\s+i64\b")
ZEXT_DEF_RE = re.compile(r"^%(\S+)\s*=\s*zext\s+i32\s+\S+\s+to\s+i64$")
STRUCT_RE = re.compile(r"^%struct\.(\S+)\s*=\s*type\s*\{\s*(.*?)\s*\}$")
TRIPLE_RE = re.compile(r"^target triple = \"([^\"]+)\"$")
DATALAYOUT_RE = re.compile(r"^target datalayout = \"([^\"]+)\"$")


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def run_step(argv, timeout=600):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def load_record():
    with open(RECORD_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def build_ir(name):
    """Frontend -> frozen audit -> adapter; return (raw, adapted)."""
    source = os.path.join(COMPILE_DIR, name + ".mojo")
    if not os.path.isfile(source):
        raise EnvironmentFailure("missing fixture: %s" % source)
    workdir = tempfile.mkdtemp(prefix="mojo-layout-")
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    proc = run_step(
        ["mojo", "build", "--emit", "llvm", *FRONTEND_TARGET_FLAGS, "-I", SDK_INCLUDE,
         "-o", raw_path, source]
    )
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise AssertionError(
            "frontend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    if "error:" in proc.stderr.lower() or "warning:" in proc.stderr.lower():
        raise AssertionError(
            "frontend reported diagnostics for %s:\n%s" % (source, proc.stderr)
        )
    with open(raw_path, "r", encoding="utf-8") as handle:
        raw_ir = handle.read()
    try:
        mode = audit.validate(raw_ir)
    except audit.AuditError as exc:
        raise AssertionError(
            "frozen audit rejected %s: %s" % (source, exc)
        )
    assert mode == "classifier", (
        "%s must validate as the classifier shape, got %r" % (source, mode)
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
    with open(adapted_path, "r", encoding="utf-8") as handle:
        adapted = handle.read()
    return raw_ir, adapted


_CACHED = {}


def built(name):
    if name not in _CACHED:
        for tool in ("mojo", "llc"):
            if shutil.which(tool) is None:
                raise EnvironmentFailure("%s not found on PATH" % tool)
        if not os.path.isdir(SDK_INCLUDE):
            raise EnvironmentFailure("missing SDK dir: %s" % SDK_INCLUDE)
        if not os.path.isfile(ADAPTER):
            raise EnvironmentFailure("missing adapter: %s" % ADAPTER)
        _CACHED[name] = build_ir(name)
    return _CACHED[name]


def classifier_fixtures():
    record = load_record()
    needs = record["classifier_loads"]["start_needs"]
    shapes = record["classifier_loads"]["address_shapes"]
    negs = record["classifier_loads"]["unguarded"]
    return sorted(set(needs) | set(shapes) | set(negs))


def body_lines(ir_text):
    """Comment-stripped body lines between define and close."""
    lines = []
    in_body = False
    for raw in ir_text.splitlines():
        line = audit.strip_comment(raw).strip()
        if line.startswith("define "):
            in_body = True
            continue
        if line == "}":
            in_body = False
            continue
        if in_body and line and not line.startswith("!"):
            lines.append(line)
    return lines


def norm(token):
    return "%" + token.lstrip("%")


def gep_offset(operands, elem_width):
    """Byte offset of a one-index GEP, or None when variable."""
    parts = [part.strip() for part in operands.split(",")]
    if not parts:
        return None
    atoms = parts[-1].split()
    if len(atoms) == 2 and atoms[1].lstrip("-").isdigit():
        try:
            return int(atoms[1]) * elem_width // 8
        except ValueError:
            return None
    return None


def load_inventory(lines):
    """Classify every load by root: packet, context, or other.

    Returns (asm_count, packet, context, other) where packet holds
    (ssa, width_bits, byte_offset_or_None) per packet-rooted load,
    context holds (ssa, width_bits, byte_offset) per
    context-rooted load, and other holds raw lines no root owns.
    """
    packet_roots = set()
    asm_count = 0
    for line in lines:
        match = ASM_RE.match(line)
        if match:
            asm_count += 1
            packet_roots.add("%" + match.group(1))
    ctx_roots = {"%0"}
    offsets = {}
    changed = True
    while changed:
        changed = False
        for line in lines:
            match = GEP_RE.match(line)
            if not match:
                continue
            target = "%" + match.group(1)
            elem_width = int(match.group(2)[1:])
            base = norm(match.group(3))
            if base not in packet_roots and base not in ctx_roots:
                continue
            if target in packet_roots or target in ctx_roots:
                continue
            if base in packet_roots:
                packet_roots.add(target)
            else:
                ctx_roots.add(target)
            changed = True
            offsets[target] = gep_offset(match.group(4), elem_width)
    packet, context, other = [], [], []
    for line in lines:
        match = LOAD_RE.match(line)
        if not match:
            continue
        width = int(match.group(2)[1:])
        operand = norm(match.group(3))
        if operand in packet_roots:
            packet.append((match.group(1), width, offsets.get(operand, 0)))
        elif operand in ctx_roots:
            offset = offsets.get(operand, 0)
            context.append((match.group(1), width, offset))
        else:
            other.append(line)
    return asm_count, packet, context, other


def const_guards(lines):
    """Start-based guards: (need, cond_ssa, true_label) per guard."""
    adds = {}
    for line in lines:
        match = ADD_RE.match(line)
        if match:
            _name, left, right = match.groups()
            for token in (left, right):
                if token.lstrip("-").isdigit():
                    adds["%" + match.group(1)] = int(token)
    guards = []
    for line in lines:
        match = ICMP_RE.match(line)
        if match and norm(match.group(2)) in adds:
            guards.append(
                (adds[norm(match.group(2))], match.group(1), None)
            )
    branches = {}
    for line in lines:
        match = BRCOND_RE.match(line)
        if match:
            branches[match.group(1).lstrip("%")] = match.group(2)
    return [
        (need, cond, branches.get(cond)) for need, cond, _ in guards
    ]


def guard_returns_drop(lines, cond, true_label):
    """The guard's tripped branch must return XDP_DROP (1)."""
    assert cond is not None and true_label is not None, (
        "guard compare has no conditional branch"
    )
    blocks = {}
    current = None
    for line in lines:
        match = LABEL_RE.match(line)
        if match:
            current = match.group(1)
            blocks[current] = []
        elif current is not None:
            blocks[current].append(line)
    target = true_label.lstrip("%")
    assert target in blocks, "guard target block %%%s missing" % target
    assert len(blocks[target]) == 1 and blocks[target][0].startswith("br "), (
        "guard block %%%s must only forward, got %r" % (target, blocks[target])
    )
    dest = blocks[target][0].split()[-1].lstrip("%")
    assert dest in blocks, "guard exit block %%%s missing" % dest
    for line in blocks[dest]:
        if line.startswith("%") and " phi " in line:
            assert ("[ 1, %%%s ]" % target) in line, (
                "guard exit must return 1 on the tripped path: %r" % line
            )
            return
    raise AssertionError("guard exit block %%%s has no phi" % dest)


def masked_addr_chain(lines):
    """Variable offset masked to six bits feeding a checked address."""
    masked = set()
    for line in lines:
        match = re.match(r"^%(\S+)\s*=\s*and\s+i64\s+\S+,\s*63$", line)
        if match:
            masked.add("%" + match.group(1))
    if not masked:
        return False
    shared = set()
    for line in lines:
        match = ADD_RE.match(line)
        if not match:
            continue
        _name, left, right = match.groups()
        if {norm(left), norm(right)} & masked:
            shared.add("%" + match.group(1))
    if not shared:
        return False
    checked = set()
    for line in lines:
        match = ADD_RE.match(line)
        if not match:
            continue
        _name, left, right = match.groups()
        if ({norm(left), norm(right)} & shared) and (
            left == "1" or right == "1"
        ):
            checked.add("%" + match.group(1))
    for line in lines:
        match = ICMP_RE.match(line)
        if match and norm(match.group(2)) in checked:
            return True
    return False


def unmasked_addr_chain(lines):
    """Length-minus-one offset feeding a checked address, unmasked."""
    decremented = set()
    for line in lines:
        match = SUB_RE.match(line)
        if match and match.group(3) == "1":
            decremented.add("%" + match.group(1))
    if not decremented:
        return False
    shared = set()
    for line in lines:
        match = ADD_RE.match(line)
        if not match:
            continue
        _name, left, right = match.groups()
        if {norm(left), norm(right)} & decremented:
            shared.add("%" + match.group(1))
    if not shared:
        return False
    checked = set()
    for line in lines:
        match = ADD_RE.match(line)
        if not match:
            continue
        _name, left, right = match.groups()
        if ({norm(left), norm(right)} & shared) and (
            left == "1" or right == "1"
        ):
            checked.add("%" + match.group(1))
    for line in lines:
        match = ICMP_RE.match(line)
        if match and norm(match.group(2)) in checked:
            return True
    return False


def asm_input_def_kind(lines):
    """How the reinterpreted address is computed: add, zext, or None.

    Start-guarded shapes reinterpret the packet start (a zero-extended
    context word; the plus-zero folds away). Address shapes
    reinterpret the shared address add. Anything else is a new shape
    this suite does not know.
    """
    operand = None
    for line in lines:
        match = ASM_FULL_RE.match(line)
        if match:
            assert operand is None, "two reinterpretations in one body"
            operand = norm(match.group(2))
    if operand is None:
        return None
    for line in lines:
        match = ADD_DEF_RE.match(line)
        if match and "%" + match.group(1) == operand:
            return "add"
        match = ZEXT_DEF_RE.match(line)
        if match and "%" + match.group(1) == operand:
            return "zext"
    return None


def mojo_facts():
    """Build and run the Mojo layout probe; return its fact lines."""
    if "mojo" not in _CACHED:
        if shutil.which("mojo") is None:
            raise EnvironmentFailure("mojo not found on PATH")
        if not os.path.isfile(LAYOUT_PROBE):
            raise EnvironmentFailure("missing probe: %s" % LAYOUT_PROBE)
        workdir = tempfile.mkdtemp(prefix="mojo-layouts-")
        binary = os.path.join(workdir, "layouts_probe")
        proc = run_step(
            ["mojo", "build", "-I", SDK_INCLUDE, "-o", binary, LAYOUT_PROBE]
        )
        if proc.returncode != 0 or not os.path.isfile(binary):
            raise AssertionError(
                "layout probe build failed (exit %d):\n%s\n%s"
                % (proc.returncode, proc.stdout, proc.stderr)
            )
        if "error:" in proc.stderr.lower() or "warning:" in proc.stderr.lower():
            raise AssertionError(
                "layout probe build diagnostics:\n%s" % proc.stderr
            )
        proc = run_step([binary], timeout=120)
        if proc.returncode != 0 or proc.stderr:
            raise AssertionError(
                "layout probe run failed (exit %d):\n%s\n%s"
                % (proc.returncode, proc.stdout, proc.stderr)
            )
        _CACHED["mojo"] = proc.stdout.splitlines()
    return _CACHED["mojo"]


def c_facts():
    """Build and run the C layout fixture; return its fact lines."""
    if "c" not in _CACHED:
        if shutil.which("cc") is None:
            raise EnvironmentFailure("cc not found on PATH")
        if not os.path.isfile(C_FIXTURE):
            raise EnvironmentFailure("missing fixture: %s" % C_FIXTURE)
        workdir = tempfile.mkdtemp(prefix="mojo-layouts-c-")
        binary = os.path.join(workdir, "sdk_layouts")
        proc = run_step(
            ["cc", "-std=c11", "-O2", "-Wall", "-Wextra",
             "-o", binary, C_FIXTURE]
        )
        if proc.returncode != 0 or not os.path.isfile(binary):
            raise AssertionError(
                "C fixture build failed (exit %d):\n%s\n%s"
                % (proc.returncode, proc.stdout, proc.stderr)
            )
        if proc.stderr.strip():
            raise AssertionError(
                "C fixture build diagnostics:\n%s" % proc.stderr
            )
        proc = run_step([binary], timeout=120)
        if proc.returncode != 0 or proc.stderr:
            raise AssertionError(
                "C fixture run failed (exit %d):\n%s\n%s"
                % (proc.returncode, proc.stdout, proc.stderr)
            )
        _CACHED["c"] = proc.stdout.splitlines()
    return _CACHED["c"]


def fact_map(lines, kinds):
    """Parse SIZE/ALIGN/OFF lines into {(kind, name): value}."""
    facts = {}
    for line in lines:
        parts = line.split(" ")
        assert len(parts) == 3, "malformed fact line: %r" % line
        assert parts[0] in kinds, "unknown fact kind: %r" % line
        facts[(parts[0], parts[1])] = int(parts[2])
    return facts


def clang_bpf_ir():
    """Compile the C fixture to LLVM IR for the BPF target."""
    if "clang" not in _CACHED:
        if shutil.which("clang") is None:
            raise EnvironmentFailure("clang not found on PATH")
        workdir = tempfile.mkdtemp(prefix="mojo-layouts-bpf-")
        out = os.path.join(workdir, "sdk_layouts.bpf.ll")
        proc = run_step(
            ["clang", "--target=bpf", "-DBPF_TYPE_EMIT", "-S",
             "-emit-llvm", "-o", out, C_FIXTURE]
        )
        if proc.returncode != 0 or not os.path.isfile(out):
            raise AssertionError(
                "clang BPF emit failed (exit %d):\n%s\n%s"
                % (proc.returncode, proc.stdout, proc.stderr)
            )
        with open(out, "r", encoding="utf-8") as handle:
            _CACHED["clang"] = handle.read()
    return _CACHED["clang"]


def llvm_struct_layout(field_types, ptr_size=8):
    """Offsets/size/align for a struct from LLVM field types."""
    widths = {"i8": 1, "i16": 2, "i32": 4, "i64": 8, "ptr": ptr_size}
    offsets = []
    cursor = 0
    align = 1
    for field in field_types:
        width = widths[field.strip()]
        align = max(align, width)
        if cursor % width:
            cursor += width - cursor % width
        offsets.append(cursor)
        cursor += width
    if cursor % align:
        cursor += align - cursor % align
    return offsets, cursor, align


def test_record_self_consistent():
    record = load_record()
    assert record["record"] == "mojobpf-abi-layouts"
    assert record["schema_version"] == 1
    for name, spec in record["integers"].items():
        assert spec["size"] == spec["align"], (
            "%s: scalar size %d != align %d"
            % (name, spec["size"], spec["align"])
        )
    for name, spec in record["structs"].items():
        for field, decl in spec["fields"].items():
            ftype = record["integers"].get(decl["type"], {"size": 8})
            assert decl["offset"] + ftype["size"] <= spec["size"], (
                "%s.%s overruns the struct size" % (name, field)
            )
    needs = record["classifier_loads"]["start_needs"]
    shapes = record["classifier_loads"]["address_shapes"]
    negs = record["classifier_loads"]["unguarded"]
    assert set(shapes) | set(negs) <= set(needs) | {
        "packet_var_offset", "packet_unguarded",
    }, "address/negative shapes must be known fixtures"
    for shape, kind in shapes.items():
        assert kind in ("masked", "unmasked"), (shape, kind)


def test_sdk_constants_match_record():
    record = load_record()
    with open(os.path.join(SDK_DIR, "packet.mojo"), "r",
              encoding="utf-8") as handle:
        packet_src = handle.read()
    with open(os.path.join(SDK_DIR, "maps.mojo"), "r",
              encoding="utf-8") as handle:
        maps_src = handle.read()

    def comptime(src, name):
        match = re.search(
            r"^comptime %s = (\d+)$" % re.escape(name), src, re.MULTILINE
        )
        assert match, "SDK constant %s not found" % name
        return int(match.group(1))

    actions = record["actions"]
    assert comptime(packet_src, "XDP_DROP") == actions["drop"]
    assert comptime(packet_src, "XDP_PASS") == actions["pass"]
    assert actions["guard_action_is_drop"] is True
    match = re.search(
        r"^comptime GUARD_ACTION = (\w+)$", packet_src, re.MULTILINE
    )
    assert match and match.group(1) == "XDP_DROP", (
        "GUARD_ACTION must name XDP_DROP"
    )
    assert actions["return_width_bits"] == 32
    slots = record["map_slots"]
    assert comptime(maps_src, "MAP_KEY_SIZE") == slots["key_bytes"]
    assert comptime(maps_src, "MAP_VALUE_SIZE") == slots["value_bytes"]
    assert comptime(maps_src, "MAP_MAX_ENTRIES") == slots["max_entries"]
    assert (
        comptime(maps_src, "MAP_MAX_ENTRIES_COMBINED")
        == slots["combined_max_entries"]
    )


def test_mojo_sizes_aligns_match_record():
    record = load_record()
    facts = fact_map(
        [line for line in mojo_facts() if not line.startswith(("XDUMP", "CDUMP", "CADDR"))],
        ("SIZE", "ALIGN"),
    )
    for name, spec in record["integers"].items():
        assert facts[("SIZE", name)] == spec["size"], (
            "Mojo SIZE %s: record %d, probe %d"
            % (name, spec["size"], facts[("SIZE", name)])
        )
        assert facts[("ALIGN", name)] == spec["align"], (
            "Mojo ALIGN %s: record %d, probe %d"
            % (name, spec["align"], facts[("ALIGN", name)])
        )
    for name, spec in record["structs"].items():
        assert facts[("SIZE", name)] == spec["size"], (
            "Mojo SIZE %s: record %d, probe %d"
            % (name, spec["size"], facts[("SIZE", name)])
        )
        assert facts[("ALIGN", name)] == spec["align"], (
            "Mojo ALIGN %s: record %d, probe %d"
            % (name, spec["align"], facts[("ALIGN", name)])
        )


def test_mojo_dumps_match_record():
    record = load_record()
    lines = mojo_facts()
    xdumps = [line for line in lines if line.startswith("XDUMP ")]
    cdumps = [line for line in lines if line.startswith("CDUMP ")]
    caddrs = [line for line in lines if line.startswith("CADDR ")]
    assert len(xdumps) == 1 and len(cdumps) == 1 and len(caddrs) == 1, (
        "want one XDUMP/CDUMP/CADDR line, got %d/%d/%d"
        % (len(xdumps), len(cdumps), len(caddrs))
    )
    xbytes = [int(token) for token in xdumps[0].split(" ")[1:]]
    xdp = record["structs"]["xdp_ctx"]
    assert len(xbytes) == xdp["size"], (
        "XDUMP holds %d bytes, record size is %d" % (len(xbytes), xdp["size"])
    )
    words = (0x04030201, 0x08070605, 0x0C0B0A09)
    for (field, decl), word in zip(
        (("data", xdp["fields"]["data"]),
         ("data_end", xdp["fields"]["data_end"]),
         ("data_meta", xdp["fields"]["data_meta"])),
        words,
    ):
        off = decl["offset"]
        assert bytes(xbytes[off : off + 4]) == word.to_bytes(4, "little"), (
            "XDUMP field %s at %d is not %08x little-endian"
            % (field, off, word)
        )
    cbytes = [int(token) for token in cdumps[0].split(" ")[1:]]
    cursor = record["structs"]["cursor"]
    assert len(cbytes) == cursor["size"], (
        "CDUMP holds %d bytes, record size is %d"
        % (len(cbytes), cursor["size"])
    )
    addr = int(caddrs[0].split(" ")[1])
    base_off = cursor["fields"]["base"]["offset"]
    assert bytes(cbytes[base_off : base_off + 8]) == addr.to_bytes(8, "little"), (
        "CDUMP base field is not the printed address little-endian"
    )
    off_off = cursor["fields"]["off"]["offset"]
    assert bytes(cbytes[off_off : off_off + 8]) == (
        0x0807060504030201
    ).to_bytes(8, "little"), "CDUMP off field is not 01..08 little-endian"


def test_c_fixture_matches_record():
    record = load_record()
    facts = fact_map(c_facts(), ("SIZE", "ALIGN", "OFF"))
    for name, spec in record["integers"].items():
        assert facts[("SIZE", name)] == spec["size"], (
            "C SIZE %s: record %d, fixture %d"
            % (name, spec["size"], facts[("SIZE", name)])
        )
        assert facts[("ALIGN", name)] == spec["align"], (
            "C ALIGN %s: record %d, fixture %d"
            % (name, spec["align"], facts[("ALIGN", name)])
        )
    for name, spec in record["structs"].items():
        assert facts[("SIZE", name)] == spec["size"], (
            "C SIZE %s: record %d, fixture %d"
            % (name, spec["size"], facts[("SIZE", name)])
        )
        assert facts[("ALIGN", name)] == spec["align"], (
            "C ALIGN %s: record %d, fixture %d"
            % (name, spec["align"], facts[("ALIGN", name)])
        )
        for field, decl in spec["fields"].items():
            key = ("OFF", "%s.%s" % (name, field))
            assert facts[key] == decl["offset"], (
                "C OFF %s.%s: record %d, fixture %d"
                % (name, field, decl["offset"], facts[key])
            )


def test_target_layouts_match_record():
    record = load_record()
    raw_ir, adapted = built("packet_fixed_byte")
    triple = datalayout = None
    for line in raw_ir.splitlines():
        match = TRIPLE_RE.match(line.strip())
        if match:
            triple = match.group(1)
        match = DATALAYOUT_RE.match(line.strip())
        if match:
            datalayout = match.group(1)
    assert triple is not None and datalayout is not None, (
        "frontend IR lacks target triple/datalayout"
    )
    frontend = record["targets"]["frontend"]
    assert triple.startswith(frontend["triple_prefix"]), (
        "frontend triple %r lacks prefix %r"
        % (triple, frontend["triple_prefix"])
    )
    assert frontend["little_endian"] is True
    assert datalayout.startswith("e-"), (
        "frontend datalayout is not little-endian: %r" % datalayout
    )
    triple = datalayout = None
    for line in adapted.splitlines():
        match = TRIPLE_RE.match(line.strip())
        if match:
            triple = match.group(1)
        match = DATALAYOUT_RE.match(line.strip())
        if match:
            datalayout = match.group(1)
    kernel = record["targets"]["kernel"]
    assert triple == kernel["triple"], (
        "adapted triple %r is not %r" % (triple, kernel["triple"])
    )
    assert datalayout == kernel["datalayout"], (
        "adapted datalayout %r is not %r" % (datalayout, kernel["datalayout"])
    )


def test_bpf_struct_layout_matches_record():
    record = load_record()
    text = clang_bpf_ir()
    datalayout = None
    for line in text.splitlines():
        match = DATALAYOUT_RE.match(line.strip())
        if match:
            datalayout = match.group(1)
    assert datalayout == record["targets"]["kernel"]["datalayout"], (
        "clang BPF datalayout %r is not the kernel layout" % datalayout
    )
    structs = {}
    for line in text.splitlines():
        match = STRUCT_RE.match(line.strip())
        if match:
            structs[match.group(1)] = [
                field.strip() for field in match.group(2).split(",")
            ]
    want = {
        "mojo_xdp_ctx": "xdp_ctx",
        "mojo_cursor": "cursor",
    }
    for clang_name, record_name in want.items():
        assert clang_name in structs, (
            "clang BPF IR lacks struct %s" % clang_name
        )
        offsets, size, align = llvm_struct_layout(structs[clang_name])
        spec = record["structs"][record_name]
        assert size == spec["size"] and align == spec["align"], (
            "BPF %s: computed (%d, %d), record (%d, %d)"
            % (record_name, size, align, spec["size"], spec["align"])
        )
        fields = list(spec["fields"])
        assert [spec["fields"][f]["offset"] for f in fields] == offsets, (
            "BPF %s: computed offsets %r, record %r"
            % (record_name, offsets, fields)
        )


def test_no_packed_struct_cast():
    """Every packet-rooted load in every classifier is one byte."""
    record = load_record()
    packet_width = record["classifier_loads"]["packet_width_bits"]
    context_width = record["classifier_loads"]["context_width_bits"]
    context_offsets = record["classifier_loads"]["context_offsets"]
    for name in classifier_fixtures():
        _raw, adapted = built(name)
        defines = [
            line.strip()
            for line in adapted.splitlines()
            if line.strip().startswith("define ")
        ]
        assert len(defines) == 1, "%s: %d defines" % (name, len(defines))
        assert DEFINE_RE.match(defines[0]), (
            "%s: entry is not i32 @xdp_entry(ptr...): %r"
            % (name, defines[0])
        )
        lines = body_lines(adapted)
        asm_count, packet, context, other = load_inventory(lines)
        assert asm_count == 1, (
            "%s: want exactly one reinterpretation, found %d"
            % (name, asm_count)
        )
        assert packet, "%s: no packet-rooted loads found" % name
        for _ssa, width, _off in packet:
            assert width == packet_width, (
                "%s: packet-rooted load is %d bits, not a byte "
                "(packed-struct cast)" % (name, width)
            )
        assert context, "%s: no context-rooted loads found" % name
        for _ssa, width, off in context:
            assert width == context_width, (
                "%s: context-rooted load is %d bits, not a word"
                % (name, width)
            )
            assert off in context_offsets, (
                "%s: context-rooted load at byte %r, want one of %r"
                % (name, off, context_offsets)
            )
        assert not other, (
            "%s: loads outside the packet/context roots:\n%s"
            % (name, "\n".join(other))
        )


def test_guard_needs_match_record():
    """Recorded guard needs are present and fail closed to drop."""
    record = load_record()
    needs = record["classifier_loads"]["start_needs"]
    shapes = record["classifier_loads"]["address_shapes"]
    for name, want in sorted(needs.items()):
        _raw, adapted = built(name)
        lines = body_lines(adapted)
        guards = const_guards(lines)
        # The address chain's plus-one check shares the syntactic
        # shape of a start-based guard with need 1; the chain-shape
        # tests below prove it is the address check, not a second
        # start guard.
        expect = sorted(want + ([1] if name in shapes else []))
        assert sorted(need for need, _, _ in guards) == expect, (
            "%s: guard needs %r, record %r"
            % (name, sorted(need for need, _, _ in guards), expect)
        )
        for _need, cond, label in guards:
            guard_returns_drop(lines, cond, label)
    for name in sorted(record["classifier_loads"]["unguarded"]):
        _raw, adapted = built(name)
        assert not const_guards(body_lines(adapted)), (
            "%s: negative must lack start-based guards" % name
        )
    _raw, adapted = built("packet_var_offset")
    vo_guards = const_guards(body_lines(adapted))
    assert sorted(need for need, _, _ in vo_guards) == [1], (
        "packet_var_offset must carry only its chain plus-one check, "
        "found %r" % (sorted(need for need, _, _ in vo_guards),)
    )
    for _need, cond, label in vo_guards:
        guard_returns_drop(body_lines(adapted), cond, label)
    assert masked_addr_chain(body_lines(adapted)), (
        "packet_var_offset lacks the masked address chain"
    )
    assert not unmasked_addr_chain(body_lines(adapted)), (
        "packet_var_offset must not match the unmasked chain"
    )
    _raw, adapted = built("scalar_addr_edge")
    assert masked_addr_chain(body_lines(adapted)) is False
    assert unmasked_addr_chain(body_lines(adapted)), (
        "scalar_addr_edge lacks the unmasked address chain"
    )
    for name in sorted(shapes):
        _raw, adapted = built(name)
        lines = body_lines(adapted)
        # The reinterpreted address is the shared address add, not
        # the folded packet start: variability lives in the base.
        assert asm_input_def_kind(lines) == "add", (
            "%s: address shape must reinterpret an address add" % name
        )
        _asm, packet, _ctx, _other = load_inventory(lines)
        assert len(packet) == 1, (
            "%s: want exactly one packet load, found %d"
            % (name, len(packet))
        )
        assert packet[0][2] == 0, (
            "%s: address-shape load must sit at offset 0, found %r"
            % (name, packet[0][2])
        )
    for name in sorted(needs):
        if name in shapes:
            continue
        _raw, adapted = built(name)
        assert asm_input_def_kind(body_lines(adapted)) == "zext", (
            "%s: start-guarded shape must reinterpret the packet start"
            % name
        )


def test_packet_offsets_within_needs():
    """Constant packet offsets stay below the covering need."""
    record = load_record()
    needs = record["classifier_loads"]["start_needs"]
    for name, want in sorted(needs.items()):
        if name in record["classifier_loads"]["address_shapes"]:
            continue
        _raw, adapted = built(name)
        _asm, packet, _ctx, _other = load_inventory(body_lines(adapted))
        for _ssa, _width, off in packet:
            assert off is not None, (
                "%s: start-guarded shape has a variable load" % name
            )
            assert 0 <= off < max(want), (
                "%s: packet offset %d outside need %r" % (name, off, want)
            )


def object_sections(image):
    """Section names and bytes for a 64-bit little-endian relocatable."""
    assert image[:4] == b"\x7fELF"
    (_e_type, e_machine, _e_version) = struct.unpack_from("<HHI", image, 16)
    assert e_machine == EM_BPF, "not an EM_BPF object"
    (e_shoff,) = struct.unpack_from("<Q", image, 40)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", image, 58)
    sections = []
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        (sh_name, _sh_type, _sh_flags, _sh_addr, sh_offset, sh_size) = (
            struct.unpack_from("<IIQQQQ", image, off)[:6]
        )
        sections.append((sh_name, sh_offset, sh_size))
    str_off = sections[e_shstrndx][1]
    named = {}
    for name_off, sec_off, sec_size in sections:
        end = image.index(b"\x00", str_off + name_off)
        name = image[str_off + name_off : end].decode("ascii")
        named[name] = image[sec_off : sec_off + sec_size]
    return named


def test_classifier_object_decoder_row():
    """No BTF sections on a classifier; license bytes exact."""
    if shutil.which("llc") is None:
        raise EnvironmentFailure("llc not found on PATH")
    _raw, adapted = built("scalar_endian")
    workdir = tempfile.mkdtemp(prefix="mojo-layout-obj-")
    adapted_path = os.path.join(workdir, "scalar_endian.bpf.ll")
    object_path = os.path.join(workdir, "scalar_endian.bpf.o")
    with open(adapted_path, "w", encoding="utf-8") as handle:
        handle.write(adapted)
    proc = run_step(
        ["llc", "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
         adapted_path, "-o", object_path]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "backend failed for scalar_endian (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    with open(object_path, "rb") as handle:
        image = handle.read()
    sections = object_sections(image)
    assert "xdp" in sections, "classifier lacks the xdp section"
    assert "license" in sections, "classifier lacks the license section"
    assert sections["license"] == LICENSE_BYTES, (
        "license bytes %r are not %r" % (sections["license"], LICENSE_BYTES)
    )
    btf = [name for name in sections if "BTF" in name or "btf" in name]
    assert not btf, "classifier must carry no BTF sections, found %r" % (btf,)


def comparison_table():
    """Human-readable layout table across the Mojo/C/BPF legs."""
    record = load_record()
    mojo = fact_map(
        [line for line in mojo_facts() if not line.startswith(("XDUMP", "CDUMP", "CADDR"))],
        ("SIZE", "ALIGN"),
    )
    cfacts = fact_map(c_facts(), ("SIZE", "ALIGN", "OFF"))
    rows = [("type", "mojo", "c", "record")]
    for name in list(record["integers"]) + list(record["structs"]):
        if name in record["integers"]:
            spec = record["integers"][name]
        else:
            spec = record["structs"][name]
        rows.append(
            (
                name,
                "%d/%d" % (mojo[("SIZE", name)], mojo[("ALIGN", name)]),
                "%d/%d" % (cfacts[("SIZE", name)], cfacts[("ALIGN", name)]),
                "%d/%d" % (spec["size"], spec["align"]),
            )
        )
    for name, spec in record["structs"].items():
        for field, decl in spec["fields"].items():
            rows.append(
                (
                    "%s.%s" % (name, field),
                    "dump-proved",
                    "%d" % cfacts[("OFF", "%s.%s" % (name, field))],
                    "%d" % decl["offset"],
                )
            )
    width = max(len(cells[0]) for cells in rows)
    return "\n".join(
        "  %-*s  %-9s  %-9s  %-9s" % (width, *cells) for cells in rows
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
    print("layout comparison table (size/align, offsets):")
    print(comparison_table())
    print("fixtures scanned: %s" % ", ".join(classifier_fixtures()))
    return 0


if __name__ == "__main__":
    sys.exit(main())