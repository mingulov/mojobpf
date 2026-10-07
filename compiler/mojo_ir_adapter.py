# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Retarget genuine Mojo-emitted host IR to little-endian BPF.

Pipeline position: ``mojo build --emit llvm`` (raw host IR) -> this adapter
-> ``llc -mtriple=bpfel -mcpu=v3 -filetype=obj`` (BPF object). The adapter
input must be real frontend output; the raw file is preserved alongside the
adapted file so reviewers can diff them.

All checks live in ``compiler/audit.py``; this module owns only the
enumerated transform below and delegates every validation to it. The
transform makes exactly these edits, each by exact match on known
lines (any mismatch fails loudly, so a reviewer can enumerate every
possible edit; there is no pattern rewriting):

1. host ``target datalayout`` -> the little-endian BPF data layout;
2. host ``target triple`` -> ``bpfel-unknown-none``;
3. the entrypoint definition line gains its section: ``@xdp_entry``
   gains ``section "xdp"`` and ``@trace_entry`` gains
   ``section "tracepoint/syscalls/sys_enter_getpid"``;
4. the entrypoint ``attributes #0`` line (host ``target-cpu``/
   ``target-features``) -> ``attributes #0 = { "target-cpu"="v3" }``;
5. for each admitted helper pseudo-call (one lookup plus one
   update per pair, one deletion per deleted key, the
   tracepoint filter/pair/PID-TID calls, or the event
   filter/pairs/PID-TID/clock/CPU/output calls), the callee
   operand alone is replaced with the ordinary BPF helper-call
   representation: ``@__mojobpf_lookup_v1`` becomes
   ``inttoptr (i64 1 to ptr)``, ``@__mojobpf_update_v1`` becomes
   ``inttoptr (i64 2 to ptr)``, ``@__mojobpf_delete_elem_v1``
   becomes ``inttoptr (i64 3 to ptr)``,
   ``@__mojobpf_get_pid_tgid_v1`` becomes
   ``inttoptr (i64 14 to ptr)``, ``@__mojobpf_ktime_get_ns_v1``
   becomes ``inttoptr (i64 5 to ptr)``,
   ``@__mojobpf_get_smp_processor_id_v1`` becomes
   ``inttoptr (i64 8 to ptr)``, and
   ``@__mojobpf_ringbuf_output_v1`` becomes
   ``inttoptr (i64 130 to ptr)``. Function type, argument
   SSA values, result, and position are preserved (there is no
   iteration callee: the kernel offers no from-program
   map-iteration helper; there is no reservation callee either:
   copy-output only);
6. the now-unreferenced reserved helper declarations (one per used
   helper) are removed;
7. appended: for the classifier shape, a ``license`` section global
   declaring the project license plus the ``llvm.compiler.used``
   marker that keeps it (both mirror what Clang emits for a
   section-attributed license global); for map shapes, the same
   license global with a three-entry used marker naming the map
   and the XDP entrypoint, plus the standard ``.maps`` global and
   the 97-line ``.BTF`` assembler block describing the N-entry
   array or per-CPU array map (both mirror the bytes of a
   Clang-built reference object; the map kind comes from the
   program's kind tags and the entry count from its dense key
   coverage; the independent map/BTF checks live in
   ``tests/elf/test_map_btf.py`` and
   ``tests/elf/test_combined_struct.py``); for the tracepoint
   shape, the same map block with the three-entry used marker
   naming the map and the tracepoint entrypoint (checked in
   ``tests/elf/test_tracepoint_struct.py``); for the event shape,
   the two-map block (the array map plus the ring-buffer map
   sized by the audited size tag) with the four-entry used marker
   naming both maps and the tracepoint entrypoint, plus the
   two-map ``.BTF`` block describing the array map and the
   ring-buffer map (checked in
   ``tests/elf/test_event_struct.py``).

Outside edits 1-7 the instruction graph is byte-identical; the
adapter re-verifies this after transforming (post-lowering audit)
and rejects its own output on any other drift. The lookup and
update operations are explicitly selected in Mojo (the SDK wrappers
call the reserved declarations); the adapter introduces only their
BPF ABI representation, the register effects ordinary call
lowering provides, and declared metadata. It invents no lookups,
increments, conditions, retries, replacement results, or
application algorithms.

The admitted program shapes are the classifier (one tied
register-reinterpretation cast, nothing else), the map round trip
(one reinterpretation, two map-address loads, two key-slot and one
value-slot preparations, one lookup call, one update call), the
combined packet workload (three reinterpretations, four
map-address loads, two key-0 slots, two key-1 slots, two
value-slot preparations, two lookup calls, two update calls),
the tracepoint counter (two reinterpretations, three map-address
loads, one key-0 slot, two key-1 slots, one value-slot
preparation, two lookup calls, one update call, one PID/TID
call), the event emitter (four reinterpretations, seven
map-address loads, one key-0 slot, two key-1 slots, four
key-2/3 slots, three value-slot preparations, one ring-buffer
map-address load, one ring-size tag, two event-slot
preparations, six event field views, four lookup calls, three
update calls, two PID/TID
calls, one clock call, one CPU call, one output call), and the
map count families over dense keys 0..N-1: N read-modify-write
pairs or N deletions. Anything else — including helper
invocations through inline assembly, which cannot model the
call contract — is rejected.
Production use of any broader transform must move to LLVM APIs;
this exact-match adapter is deliberately limited to the known
single-entrypoint shapes.
"""

import argparse
import os
import sys


def _load_audit():
    """Import the sibling audit module under its canonical name.

    Plain ``import audit`` works when this directory is on ``sys.path``
    (command-line use, test runners); otherwise the module is loaded
    from this file's directory and registered as ``audit`` so every
    importer shares one module object either way.
    """
    try:
        import audit as audit_module

        return audit_module
    except ImportError:
        pass
    import importlib.util

    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "audit.py")
    spec = importlib.util.spec_from_file_location("audit", path)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load audit module: %s" % path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["audit"] = module
    spec.loader.exec_module(module)
    return module


audit = _load_audit()

# Rejections carry the audit's stable MBPF3xx codes; the historical
# AdapterError name stays as an alias for existing callers.
AdapterError = audit.AuditError

# Validation shapes shared with the audit (single definitions live
# in audit.py; the names below keep working for existing importers).
ASM_CALL_RE = audit.ASM_CALL_RE
MAPADDR_CALL_RE = audit.MAPADDR_CALL_RE
KEYSLOT_CALL_RE = audit.KEYSLOT_CALL_RE
KEYSLOT1_CALL_RE = audit.KEYSLOT1_CALL_RE
KEYSLOTN_CALL_RE = audit.KEYSLOTN_CALL_RE
KINDTAG_CALL_RE = audit.KINDTAG_CALL_RE
VALSLOT_CALL_RE = audit.VALSLOT_CALL_RE
RBMAPADDR_CALL_RE = audit.RBMAPADDR_CALL_RE
RBSIZE_CALL_RE = audit.RBSIZE_CALL_RE
EVENTSLOT_CALL_RE = audit.EVENTSLOT_CALL_RE
EVENTSLOTN_CALL_RE = audit.EVENTSLOTN_CALL_RE
LOOKUP_CALL_RE = audit.LOOKUP_CALL_RE
UPDATE_CALL_RE = audit.UPDATE_CALL_RE
DELETE_CALL_RE = audit.DELETE_CALL_RE
PID_CALL_RE = audit.PID_CALL_RE
KTIME_CALL_RE = audit.KTIME_CALL_RE
CPU_CALL_RE = audit.CPU_CALL_RE
OUTPUT_CALL_RE = audit.OUTPUT_CALL_RE
ASM_SHAPES = audit.ASM_SHAPES
CLASSIFIER_COUNTS = audit.CLASSIFIER_COUNTS
MAP_COUNTS = audit.MAP_COUNTS
COMBINED_COUNTS = audit.COMBINED_COUNTS
TRACEPOINT_COUNTS = audit.TRACEPOINT_COUNTS
EVENT_COUNTS = audit.EVENT_COUNTS
DEFINE_RE = audit.DEFINE_RE
ENTRY_SYMBOLS = audit.ENTRY_SYMBOLS

HOST_DATALAYOUT = (
    'target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-'
    'i128:128-f80:128-n8:16:32:64-S128"'
)
BPF_DATALAYOUT = (
    'target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"'
)
HOST_TRIPLE = 'target triple = "x86_64-unknown-linux-gnu"'
BPF_TRIPLE = 'target triple = "bpfel-unknown-none"'
ENTRY_DEFINE = "define dso_local i32 @xdp_entry(ptr noundef %0) #0 {"
ENTRY_DEFINE_SECTIONED = (
    'define dso_local i32 @xdp_entry(ptr noundef %0) #0 section "xdp" {'
)
# The tracepoint counter entrypoint and its libbpf section. The
# manifest names the same section string, the profile allows the
# pair, and the audit ties the entry symbol to the tracepoint
# count vector, so the section below is selected by the audited
# entry symbol, never guessed.
TRACE_ENTRY_DEFINE = (
    "define dso_local i32 @trace_entry(ptr noundef %0) #0 {"
)
TRACE_ENTRY_DEFINE_SECTIONED = (
    'define dso_local i32 @trace_entry(ptr noundef %0) #0 '
    'section "tracepoint/syscalls/sys_enter_getpid" {'
)
TRACEPOINT_ELF_SECTION = "tracepoint/syscalls/sys_enter_getpid"
HOST_ATTRS = (
    'attributes #0 = { "target-cpu"="znver4" "target-features"="+adx,+aes,'
    "+avx,+avx2,+avx512bf16,+avx512bitalg,+avx512bw,+avx512cd,+avx512dq,"
    "+avx512f,+avx512ifma,+avx512vbmi,+avx512vbmi2,+avx512vl,+avx512vnni,"
    "+avx512vpopcntdq,+bmi,+bmi2,+clflushopt,+clwb,+clzero,+crc32,+cx16,+cx8,"
    "+f16c,+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,+mmx,+movbe,+mwaitx,"
    "+pclmul,+pku,+popcnt,+prfchw,+rdpid,+rdpru,+rdrnd,+rdseed,+sahf,+sha,"
    "+shstk,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+sse4a,+ssse3,+vaes,+vpclmulqdq,"
    '+wbnoinvd,+x87,+xsave,+xsavec,+xsaveopt,+xsaves" }'
)
BPF_ATTRS = 'attributes #0 = { "target-cpu"="v3" }'
LICENSE_BLOCK = (
    '@_license = dso_local global [31 x i8] '
    'c"Apache-2.0 WITH LLVM-exception\\00", section "license", align 1\n'
    "@llvm.compiler.used = appending global [2 x ptr] "
    '[ptr @_license, ptr @xdp_entry], section "llvm.metadata"'
)
MAP_LICENSE_BLOCK = (
    '@_license = dso_local global [31 x i8] '
    'c"Apache-2.0 WITH LLVM-exception\\00", section "license", align 1\n'
    "@llvm.compiler.used = appending global [3 x ptr] "
    '[ptr @_license, ptr @xdp_entry, ptr @mojobpf_map0], '
    'section "llvm.metadata"'
)
TRACEPOINT_MAP_LICENSE_BLOCK = (
    '@_license = dso_local global [31 x i8] '
    'c"Apache-2.0 WITH LLVM-exception\\00", section "license", align 1\n'
    "@llvm.compiler.used = appending global [3 x ptr] "
    '[ptr @_license, ptr @trace_entry, ptr @mojobpf_map0], '
    'section "llvm.metadata"'
)
# Event-shape license block: the four-entry used marker names the
# license, the tracepoint entrypoint, and both maps.
EVENT_MAP_LICENSE_BLOCK = (
    '@_license = dso_local global [31 x i8] '
    'c"Apache-2.0 WITH LLVM-exception\\00", section "license", align 1\n'
    "@llvm.compiler.used = appending global [4 x ptr] "
    '[ptr @_license, ptr @trace_entry, ptr @mojobpf_map0, '
    'ptr @mojobpf_map1], section "llvm.metadata"'
)
MAP_BLOCK = (
    "%struct.mojobpf_map_def = type { ptr, ptr, ptr, ptr }\n"
    "@mojobpf_map0 = global %struct.mojobpf_map_def zeroinitializer, "
    'section ".maps", align 8'
)
# Event-shape map block: the array state map plus the ring-buffer
# output map. The ring-buffer definition holds the two BTF-bound
# attributes (type, max_entries); key and value sizes are
# implicitly zero, matching the kernel ring-buffer contract.
MAP_BLOCK_EVENT = (
    "%struct.mojobpf_map_def = type { ptr, ptr, ptr, ptr }\n"
    "%struct.mojobpf_ringbuf_def = type { ptr, ptr }\n"
    "@mojobpf_map0 = global %struct.mojobpf_map_def zeroinitializer, "
    'section ".maps", align 8\n'
    "@mojobpf_map1 = global %struct.mojobpf_ringbuf_def "
    'zeroinitializer, section ".maps", align 8'
)
# Fixed .BTF assembler block: 24-byte header, 13 type records (integer
# attributes type=2, key=4, value=8, entries=1, then the map struct, var
# and datasec), and the string table. The datasec entry references the
# map symbol so the assembler emits the standard BTF relocation.
BTF_ASM_LINES = (
    '.section .BTF,"",@progbits',
    '.short 60319',
    '.byte 1',
    '.byte 0',
    '.long 24',
    '.long 0',
    '.long 276',
    '.long 276',
    '.long 97',
    '.long 0',
    '.long 33554432',
    '.long 3',
    '.long 1',
    '.long 16777216',
    '.long 4',
    '.long 16777248',
    '.long 0',
    '.long 50331648',
    '.long 0',
    '.long 2',
    '.long 4',
    '.long 2',
    '.long 5',
    '.long 16777216',
    '.long 4',
    '.long 32',
    '.long 0',
    '.long 33554432',
    '.long 6',
    '.long 0',
    '.long 50331648',
    '.long 0',
    '.long 2',
    '.long 4',
    '.long 4',
    '.long 0',
    '.long 33554432',
    '.long 8',
    '.long 0',
    '.long 50331648',
    '.long 0',
    '.long 2',
    '.long 4',
    '.long 8',
    '.long 0',
    '.long 33554432',
    '.long 10',
    '.long 0',
    '.long 50331648',
    '.long 0',
    '.long 2',
    '.long 4',
    # The max_entries array bound (tuple index 52): 1 for the
    # one-entry map block, flipped to 2 for the two-entry block.
    '.long 1',
    '.long 25',
    '.long 67108868',
    '.long 32',
    '.long 41',
    '.long 1',
    '.long 0',
    '.long 46',
    '.long 5',
    '.long 64',
    '.long 55',
    '.long 7',
    '.long 128',
    '.long 66',
    '.long 9',
    '.long 192',
    '.long 78',
    '.long 234881024',
    '.long 11',
    '.long 1',
    '.long 91',
    '.long 251658241',
    '.long 0',
    '.long 12',
    '.long mojobpf_map0',
    '.long 32',
    '.byte 0',
    '.ascii "int"',
    '.byte 0',
    '.ascii "__ARRAY_SIZE_TYPE__"',
    '.byte 0',
    '.ascii "mojobpf_map_def"',
    '.byte 0',
    '.ascii "type"',
    '.byte 0',
    '.ascii "key_size"',
    '.byte 0',
    '.ascii "value_size"',
    '.byte 0',
    '.ascii "max_entries"',
    '.byte 0',
    '.ascii "mojobpf_map0"',
    '.byte 0',
    '.ascii ".maps"',
    '.byte 0',
)

# Tuple indices of the map-type and max_entries array bounds inside
# BTF_ASM_LINES. The two-entry block flips exactly the entries word
# from 1 to 2; per-CPU blocks flip exactly the type word from 2
# (array) to 6 (per-CPU array); every other line (header, type
# records, string table) is shared.
BTF_TYPE_INDEX = 21
BTF_ENTRIES_INDEX = 52

assert BTF_ASM_LINES[BTF_TYPE_INDEX] == ".long 2"
assert BTF_ASM_LINES[BTF_ENTRIES_INDEX] == ".long 1"
assert len(BTF_ASM_LINES) == 97

BTF_ASM_LINES_TWO = (
    BTF_ASM_LINES[:BTF_ENTRIES_INDEX]
    + (".long 2",)
    + BTF_ASM_LINES[BTF_ENTRIES_INDEX + 1 :]
)

# Map-type bounds the BTF emitter accepts: 2 is the array map type,
# 6 the per-CPU array map type. Any other type fails loudly.
BTF_MAP_TYPES = (2, 6)

# Ring-buffer map type bound the event BTF emitter writes (27).
# Any other ring-buffer type fails loudly.
BTF_RINGBUF_TYPE = 27

# Splice points inside BTF_ASM_LINES for the event (two-map) BTF
# block. Type records 1..12 (the array map description) occupy
# indices 9..71; the single-map DATASEC record occupies 72..77;
# the string table occupies 78... The event block reuses records
# 1..12 verbatim, appends the ring-buffer records plus a two-entry
# DATASEC, and extends the string table with the two new names.
BTF_EVENT_PREFIX_END = 72
BTF_EVENT_STRINGS_START = 78

# Existing string-table offsets the ring-buffer records reuse,
# plus the two appended names and their computed offsets.
BTF_STR_TYPE = 41
BTF_STR_MAX_ENTRIES = 66
BTF_STR_MAPS = 91
BTF_RINGBUF_DEF_NAME = "mojobpf_ringbuf_def"
BTF_RINGBUF_MAP_NAME = "mojobpf_map1"
BTF_STR_RINGBUF_DEF = 97
BTF_STR_RINGBUF_MAP = 117

# Type IDs inside the event BTF block: records 1..12 are the
# shared array description, 13..18 the ring-buffer description,
# 19 the two-entry DATASEC.
BTF_EVENT_RB_PTR = 13
BTF_EVENT_RB_TYPE_ARR = 14
BTF_EVENT_RB_ENTRIES_PTR = 15
BTF_EVENT_RB_ENTRIES_ARR = 16
BTF_EVENT_RB_STRUCT = 17
BTF_EVENT_RB_VAR = 18
BTF_EVENT_DATASEC = 19

assert BTF_ASM_LINES[8] == ".long 97"
assert BTF_ASM_LINES[56] == ".long 41"
assert BTF_ASM_LINES[65] == ".long 66"
assert BTF_ASM_LINES[72] == ".long 91"
assert BTF_ASM_LINES[73] == ".long 251658241"
assert (
    BTF_STR_RINGBUF_MAP
    == BTF_STR_RINGBUF_DEF + len(BTF_RINGBUF_DEF_NAME) + 1
)

# Shared module-metadata replacements. The entrypoint definition
# line is replaced separately in adapt(), selected by the audited
# entry symbol (XDP or tracepoint section).
REPLACEMENTS = (
    (HOST_DATALAYOUT, BPF_DATALAYOUT),
    (HOST_TRIPLE, BPF_TRIPLE),
    (HOST_ATTRS, BPF_ATTRS),
)

# Entrypoint definition lines, keyed by audited entry symbol.
ENTRY_DEFINES = {
    "xdp_entry": (ENTRY_DEFINE, ENTRY_DEFINE_SECTIONED),
    "trace_entry": (TRACE_ENTRY_DEFINE, TRACE_ENTRY_DEFINE_SECTIONED),
}

# Map-mode license blocks, keyed by audited entry symbol.
MAP_LICENSE_BLOCKS = {
    "xdp_entry": MAP_LICENSE_BLOCK,
    "trace_entry": TRACEPOINT_MAP_LICENSE_BLOCK,
}

RESERVED_CALLEES = (
    ("lookup", "@" + audit.LOOKUP_NAME),
    ("update", "@" + audit.UPDATE_NAME),
    ("delete", "@" + audit.DELETE_NAME),
    ("pid", "@" + audit.PID_NAME),
    ("ktime", "@" + audit.KTIME_NAME),
    ("cpu", "@" + audit.CPU_NAME),
    ("output", "@" + audit.OUTPUT_NAME),
)


def strip_comment(line):
    """Cut an LLVM ``;`` comment, keeping quoted strings intact."""
    return audit.strip_comment(line)


def match_shape(line):
    """Return the admitted call-shape name for a line, or None."""
    return audit.match_shape(line)


def validate(text):
    """Audit raw frontend IR; return the program mode.

    Returns ``"classifier"``, ``"map"``, ``"combined"``,
    ``"tracepoint"``, or ``"event"``. Raises AdapterError (the
    audit rejection, carrying its stable MBPF3xx code) naming the
    first violated check.
    """
    return audit.validate(text)


def _render_btf_block(directives):
    """Render BTF assembler directives as IR module-asm lines."""
    lines = []
    for directive in directives:
        escaped = directive.replace('"', "\\22")
        lines.append('module asm "\\09%s"' % escaped)
    return "\n".join(lines)


def btf_block(map_type=2, entries=1):
    """Render the fixed .BTF assembler block as IR module-asm lines.

    ``map_type`` selects the array (2) or per-CPU array (6) type
    bound and ``entries`` the max_entries array bound; any other
    type, a non-integer count, or a count outside the 32-bit
    max_entries field fails loudly.
    """
    if map_type not in BTF_MAP_TYPES:
        raise _fail(
            "unsupported map type %r: only 2 (array) and 6 "
            "(per-CPU array)" % (map_type,)
        )
    if (
        not isinstance(entries, int)
        or isinstance(entries, bool)
        or not 1 <= entries <= 0xFFFFFFFF
    ):
        raise _fail(
            "unsupported map entry count %r: only 1..4294967295"
            % (entries,)
        )
    directives = list(BTF_ASM_LINES)
    directives[BTF_TYPE_INDEX] = ".long %d" % map_type
    directives[BTF_ENTRIES_INDEX] = ".long %d" % entries
    return _render_btf_block(directives)


def btf_event_directives(array_entries=4, ring_size=131072):
    """Return the event (two-map) .BTF block as assembler directives.

    The block reuses type records 1..12 of :data:`BTF_ASM_LINES`
    verbatim (the array map description, with ``array_entries``
    in its max_entries bound), appends the ring-buffer map
    description (a two-member struct holding the type bound 27
    and the ``ring_size`` bound, mirroring the Clang reference
    shape), and closes with a two-entry ``.maps`` DATASEC plus
    the extended string table. Any array count outside the
    32-bit max_entries field, or any ring size outside the
    qualified ring-buffer sizes, fails loudly.
    """
    if (
        not isinstance(array_entries, int)
        or isinstance(array_entries, bool)
        or not 1 <= array_entries <= 0xFFFFFFFF
    ):
        raise _fail(
            "unsupported map entry count %r: only 1..4294967295"
            % (array_entries,)
        )
    if ring_size not in audit.RINGBUF_SIZES:
        raise _fail(
            "unsupported ring-buffer size %r: only %s"
            % (
                ring_size,
                ", ".join(str(size) for size in audit.RINGBUF_SIZES),
            )
        )
    prefix = list(BTF_ASM_LINES[9:BTF_EVENT_PREFIX_END])
    prefix[BTF_ENTRIES_INDEX - 9] = ".long %d" % array_entries
    rb_records = [
        # [13] PTR to the type bound.
        ".long 0",
        ".long 33554432",
        ".long %d" % BTF_EVENT_RB_TYPE_ARR,
        # [14] ARRAY bound: the ring-buffer map type.
        ".long 0",
        ".long 50331648",
        ".long 0",
        ".long 2",
        ".long 4",
        ".long %d" % BTF_RINGBUF_TYPE,
        # [15] PTR to the max_entries bound.
        ".long 0",
        ".long 33554432",
        ".long %d" % BTF_EVENT_RB_ENTRIES_ARR,
        # [16] ARRAY bound: the ring size in bytes.
        ".long 0",
        ".long 50331648",
        ".long 0",
        ".long 2",
        ".long 4",
        ".long %d" % ring_size,
        # [17] STRUCT mojobpf_ringbuf_def, two members, 16 bytes.
        ".long %d" % BTF_STR_RINGBUF_DEF,
        ".long 67108866",
        ".long 16",
        ".long %d" % BTF_STR_TYPE,
        ".long %d" % BTF_EVENT_RB_PTR,
        ".long 0",
        ".long %d" % BTF_STR_MAX_ENTRIES,
        ".long %d" % BTF_EVENT_RB_ENTRIES_PTR,
        ".long 64",
        # [18] VAR mojobpf_map1.
        ".long %d" % BTF_STR_RINGBUF_MAP,
        ".long 234881024",
        ".long %d" % BTF_EVENT_RB_STRUCT,
        ".long 1",
    ]
    datasec = [
        # [19] DATASEC .maps with both map entries.
        ".long %d" % BTF_STR_MAPS,
        ".long 251658242",
        ".long 0",
        ".long 12",
        ".long mojobpf_map0",
        ".long 32",
        ".long %d" % BTF_EVENT_RB_VAR,
        ".long mojobpf_map1",
        ".long 16",
    ]
    strings = list(BTF_ASM_LINES[BTF_EVENT_STRINGS_START:])
    strings += [
        '.ascii "%s"' % BTF_RINGBUF_DEF_NAME,
        ".byte 0",
        '.ascii "%s"' % BTF_RINGBUF_MAP_NAME,
        ".byte 0",
    ]
    type_len = 4 * (len(prefix) + len(rb_records) + len(datasec))
    str_len = 97 + len(BTF_RINGBUF_DEF_NAME) + 1 + len(
        BTF_RINGBUF_MAP_NAME
    ) + 1
    header = list(BTF_ASM_LINES[:9])
    header[6] = ".long %d" % type_len
    header[7] = ".long %d" % type_len
    header[8] = ".long %d" % str_len
    return header + prefix + rb_records + datasec + strings


def btf_block_event(array_entries=4, ring_size=131072):
    """Render the event (two-map) .BTF block as IR module-asm lines."""
    return _render_btf_block(
        btf_event_directives(
            array_entries=array_entries, ring_size=ring_size
        )
    )


def _fail(message):
    return AdapterError(
        audit.CODE_FALLBACK,
        message,
        location=None,
        remedy="report this adapter failure as a bug",
    )


def _lower_helper_calls(text, raw_lines, program):
    """Substitute the helper callees; drop their declarations.

    Each used helper is declared exactly once and lowered at every
    call site: pair families lower N lookups and N updates, delete
    families N deletions, the tracepoint shape its two lookups,
    one update, and one PID/TID call, and the event shape its
    four lookups, three updates, two PID/TID calls, one clock
    call, one CPU call, and one output call. Returns (lowered
    text, {raw call line: lowered call line}).
    """
    want_calls = {
        shape: program.counts[shape]
        for shape, _ in RESERVED_CALLEES
    }
    dropped = {shape: 0 for shape, _ in RESERVED_CALLEES}
    decl_line = {
        "lookup": audit.LOOKUP_DECL_LINE,
        "update": audit.UPDATE_DECL_LINE,
        "delete": audit.DELETE_DECL_LINE,
        "pid": audit.PID_DECL_LINE,
        "ktime": audit.KTIME_DECL_LINE,
        "cpu": audit.CPU_DECL_LINE,
        "output": audit.OUTPUT_DECL_LINE,
    }
    kept = []
    for raw in text.splitlines(keepends=True):
        stripped = audit.strip_comment(raw).strip()
        for shape in dropped:
            if stripped == decl_line[shape]:
                dropped[shape] += 1
                break
        else:
            kept.append(raw)
    want_dropped = {
        shape: 1 if want_calls[shape] else 0 for shape in dropped
    }
    if dropped != want_dropped:
        raise _fail(
            "expected one declaration per used helper, found %r "
            "(calls %r)" % (dropped, want_calls)
        )
    text = "".join(kept)
    lowered = {}
    callee_of = dict(RESERVED_CALLEES)
    for shape in want_calls:
        found = text.count(callee_of[shape])
        if found != want_calls[shape]:
            raise _fail(
                "expected exactly %d %s call site(s), found %d"
                % (want_calls[shape], shape, found)
            )
        text = text.replace(callee_of[shape], audit.LOWERED_CALLEE[shape])
    for lineno, shape, _ in program.calls:
        if shape in want_calls:
            raw_line = audit.strip_comment(
                raw_lines[lineno - 1]
            ).strip()
            lowered[raw_line] = raw_line.replace(
                callee_of[shape], audit.LOWERED_CALLEE[shape]
            )
    if len(lowered) != sum(want_calls.values()):
        raise _fail(
            "expected %d lowered helper call lines, found %d"
            % (sum(want_calls.values()), len(lowered))
        )
    return text, lowered


def adapt(text):
    """Apply the enumerated transform; audit the lowered result."""
    program = audit.scan(text)
    mode = program.mode
    raw_lines = text.splitlines()
    for old, new in REPLACEMENTS:
        found = text.count(old)
        if found != 1:
            raise _fail(
                "expected exactly one occurrence of %r, found %d"
                % (old[:72], found)
            )
        text = text.replace(old, new)
    try:
        entry_old, entry_new = ENTRY_DEFINES[program.entry]
    except KeyError:
        raise _fail(
            "audited entry symbol %r has no sectioned definition"
            % (program.entry,)
        ) from None
    found = text.count(entry_old)
    if found != 1:
        raise _fail(
            "expected exactly one occurrence of %r, found %d"
            % (entry_old[:72], found)
        )
    text = text.replace(entry_old, entry_new)
    if "@_license" in text or "@llvm.compiler.used" in text:
        raise _fail("input already contains license metadata")
    lowered = {}
    if mode in ("map", "combined", "tracepoint", "event"):
        text, lowered = _lower_helper_calls(text, raw_lines, program)
    else:
        for _, callee in RESERVED_CALLEES:
            if callee in text:
                raise _fail(
                    "classifier input references %s" % callee
                )
    raw_body = audit.body_lines("\n".join(raw_lines))
    if mode == "event":
        if program.ring_size is None:
            raise _fail("event input carries no ring-size tag")
        block = (
            EVENT_MAP_LICENSE_BLOCK
            + "\n"
            + MAP_BLOCK_EVENT
            + "\n\n"
            + btf_block_event(
                array_entries=program.entries,
                ring_size=program.ring_size,
            )
        )
        markers = (
            EVENT_MAP_LICENSE_BLOCK,
            MAP_BLOCK_EVENT,
            'module asm "\\09.section .BTF,\\22\\22,@progbits"',
            'module asm "\\09.ascii \\22.maps\\22"',
        )
    elif mode in ("map", "combined", "tracepoint"):
        try:
            license_block = MAP_LICENSE_BLOCKS[program.entry]
        except KeyError:
            raise _fail(
                "audited entry symbol %r has no license block"
                % (program.entry,)
            ) from None
        map_type = 6 if program.percpu else 2
        block = (
            license_block
            + "\n"
            + MAP_BLOCK
            + "\n\n"
            + btf_block(map_type=map_type, entries=program.entries)
        )
        markers = (
            license_block,
            MAP_BLOCK,
            'module asm "\\09.section .BTF,\\22\\22,@progbits"',
            'module asm "\\09.ascii \\22.maps\\22"',
        )
    else:
        block = LICENSE_BLOCK
        markers = (LICENSE_BLOCK,)
    text = text.rstrip("\n") + "\n\n" + block + "\n"
    for marker in (
        (BPF_DATALAYOUT, BPF_TRIPLE, entry_new, BPF_ATTRS)
        + markers
    ):
        if marker not in text:
            raise _fail("postcondition failed for %r" % marker[:48])
    audit.audit_post(text, mode)
    audit.check_graph_preserved(
        raw_body, audit.body_lines(text), lowered
    )
    return text


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Retarget genuine Mojo host IR to BPF (exact-match)."
    )
    parser.add_argument("--input", required=True, help="raw Mojo IR file")
    parser.add_argument("--output", required=True, help="adapted IR file")
    args = parser.parse_args(argv)
    try:
        with open(args.input, "r", encoding="utf-8") as handle:
            raw = handle.read()
        validate(raw)
        adapted = adapt(raw)
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(adapted)
    except OSError as exc:
        sys.stderr.write("adapter I/O error: %s\n" % exc)
        return 1
    except AdapterError as exc:
        sys.stderr.write("adapter rejected input: %s\n" % exc)
        return 1
    program = audit.scan(raw)
    if program.mode == "classifier":
        sys.stderr.write(
            "adapted %s -> %s (metadata retarget, license "
            "appended)\n" % (args.input, args.output)
        )
    elif program.mode == "event":
        calls = sum(
            program.counts[shape]
            for shape in (
                "lookup", "update", "delete", "pid", "ktime",
                "cpu", "output",
            )
        )
        sys.stderr.write(
            "adapted %s -> %s (metadata retarget, %d helper calls "
            "lowered, %d-entry array + %d-byte ringbuf map+BTF "
            "appended)\n"
            % (
                args.input, args.output, calls, program.entries,
                program.ring_size,
            )
        )
    else:
        calls = sum(
            program.counts[shape]
            for shape in ("lookup", "update", "delete", "pid")
        )
        kind = "per-CPU array" if program.percpu else "array"
        sys.stderr.write(
            "adapted %s -> %s (metadata retarget, %d helper calls "
            "lowered, %d-entry %s map+BTF appended)\n"
            % (args.input, args.output, calls, program.entries, kind)
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
