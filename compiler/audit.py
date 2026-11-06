# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Pre- and post-lowering audit for the Mojo IR adapter.

This module is the single home of every IR check at the adapter
boundary; ``mojo_ir_adapter.py`` owns the enumerated transform and
delegates all validation here. The split keeps the checks reviewable
apart from the rewriting: this file detects and classifies, it never
edits IR, while the adapter edits only through exact-match
replacements and re-verifies the result with :func:`audit_post`.

Every rejection carries a stable ``MBPF3xx`` diagnostic code (family
``MBPF3xx``: unsupported source/IR behavior), the stage
``adapter.audit``, an explanation quoting the offending line, an IR
line location, and an actionable remedy. Checks run in a fixed order
and the first violation wins, so verdicts are deterministic.

Checked model (pre-lowering, on genuine frontend output):

* exactly one complete ``i32`` entrypoint definition, either
  ``@xdp_entry(ptr...)``, ``@trace_entry(ptr...)``,
  ``@uprobe_entry(ptr...)``, ``@socket_entry(ptr...)``, or
  ``@tc_entry(ptr...)``, plus, in the subprogram shape only,
  exactly one complete ``i64``
  subprogram definition with the fixed one-argument scalar
  signature ``(i64) -> i64`` under a plain C-identifier name;
* module scope limited to ``source_filename``, the target lines,
  attribute group ``#0`` (plus attribute group ``#1`` in the
  subprogram shape only, where the two functions need two
  attribute sets), and at most the twelve reserved declarations
  below (ten helper declarations plus two relocation
  declarations; no globals, no other declarations, no
  module-level assembly);
* body calls limited to twelve exact inline-assembly shapes
  (register reinterpretation, map-address load, key-slot
  preparation for key 0, key-slot preparation for key 1,
  key-slot preparation for keys 2 and above, the per-CPU kind
  tag, the hash kind tag, value-slot preparation, the ring-buffer
  map-address load, the ring-size tag, event-slot preparation,
  and event field views) plus direct calls to the ten reserved
  helper declarations and the two reserved relocation
  declarations, plus, in the subprogram shape only, tail calls
  from the entrypoint body to the one subprogram (the subprogram
  body itself admits no calls at all);
* exactly one of the classifier, the map round trip, the combined
  packet workload, the tracepoint counter, the event emitter, the
  reservation submitter, the reservation discarder, the core
  relocation probe, or the uprobe register counter count vector
  (all frozen), the classifier
  vector plus one subprogram definition with at least one call
  site (the subprogram shape), or one map count family over
  dense keys 0..N-1: N read-modify-write pairs (one lookup plus
  one update per key) or N deletions (one per key).
  The tracepoint vector is one filter read (key 0), one
  current-PID/TID call, and one count pair (key 1), and its entry
  parameter stays unused: tracepoint programs read no context
  payload fields. The event vector is one filter read (key 0),
  one filter PID/TID call, one sequence pair (key 1), one CPU
  call, one clock call, one record PID/TID call, one copy-output
  call through the ring-buffer map, one success pair (key 2),
  and one failure pair (key 3), and its entry parameter stays
  unused for the same reason. Each reservation vector is the
  event shape with the scratch encoder and the copy-output call
  replaced by one reservation call, one record reinterpretation,
  seven reservation-relative word stores covering the 32 record
  bytes, and one terminus (submit for the submitter, discard for
  the discarder); the entry parameter stays unused for the same
  reason. The core vector is one lookup through key 0, one
  relocated field read of the checked value, and one
  optional-field check; the committed probe leaves its entry
  parameter unused (map bytes and loader metadata only). The
  uprobe vector is one filter read (key 0) and one count pair
  (key 1) with no helper-ID call, plus exactly one pinned
  context-word read: the entry parameter feeds one address
  computation only, the x86-64 first-argument register word
  (``pt_regs`` word 14, ``rdi`` at byte 112), loaded once as
  ``i64``; any other context access is refused;
* helper-call operands: the map address comes from a map load, the
  key/value pointers come from the prepared slots, update flags are
  the literal ``0``, and the PID/TID, clock, and CPU calls take no
  operands; the output call takes the size-tagged ring-buffer
  address, the prepared event slot, the literal size ``32``, and
  the literal flags ``0``; the reservation call takes the
  size-tagged ring-buffer address, the literal size ``32``, and
  the literal flags ``0``, and each terminus takes the record
  reinterpretation of the reservation result plus the literal
  flags ``0``; in multi-pair shapes the i-th lookup and the
  i-th update reference the same key, while the tracepoint
  shape reads key 0 then pairs key 1, the uprobe shape reads
  key 0 then pairs key 1, and the event and
  reservation shapes read key 0 then pair keys 1, 2, and 3 in
  order; the six event field views carry exactly the record
  field offsets; the reservation stores carry exactly the
  record field offsets and widths relative to the reservation,
  each once, all before the terminus; the relocation read takes
  the checked reinterpretation of the lookup result and the
  existence check takes no operands;
* no value defined before a lookup or update call is used after
  it (cross-call liveness), except in the combined vector, whose
  action selector and frame length necessarily cross helper calls,
  in the tracepoint vector, whose filter value and PID/TID result
  necessarily meet at the comparison after their producing calls,
  in the uprobe vector, whose filter value and extracted
  register value necessarily meet at the comparison after their
  producing calls, in the event vector, whose filter value,
  helper results, and sequence necessarily meet after their
  producing calls, and in the reservation vectors, which share
  the event shape with reservation-relative stores (only lookup
  and update calls are liveness roots: delete, PID/TID, clock,
  CPU, output, reservation, and terminus calls never are;
  kernel-address stores stay rejected by the pointer-store
  dataflow check in every mode; subprogram call sites are not
  helper calls, so values may cross them: the backend spills
  around the real call);
* every key-consuming lookup, update, and delete proves the key
  buffer's value at the call (key freshness): all key-slot
  shapes share the single r10-4 stack cell, so the consumed
  preparation must reach the call along a pure execution chain
  (each block entered through its sole predecessor from that
  predecessor's sole successor edge) with no other key-slot
  preparation and no store through the shared cell between them
  in execution order, addressed directly or through a derived
  or ambiguously-aliased pointer; stores through the other
  audited slots stay exempt only when their width provably
  avoids the key cell, and unprovable stores fail closed; the
  liveness exemptions never exempt key freshness;
* in the subprogram shape, the subprogram definition references
  the ``noinline`` attribute set and the entrypoint definition
  references the plain set (the call survives the frontend only
  under that wiring; any other wiring is refused);
* in the subprogram shape, the subprogram body is pure scalar
  computation: no calls, no loads, and no stores (it holds no
  addressable memory, so any memory operation is outside the
  shape);
* every used SSA value is defined on its own function's define
  line or an earlier body line of the same function, except bare
  block references (undefined roots; SSA names are scoped per
  function, so the entrypoint and the subprogram never share
  values);
* no store writes a lookup-derived (kernel-address) value or any
  pointer-typed value: only loaded values and computed scalars
  may be stored (pointer-store dataflow);
* none of the prohibited reachable behaviors: runtime or allocator
  calls, unwinding, TLS, constructors, intrinsics, floating-point or
  unsupported vector operations, indirect calls, helper inline
  assembly, indirect branches, stack allocation, recursion,
  poison/undef operands, or pointer/integer erasure.

One-lane integer vectors (``<1 x iN>``) are explicitly allowed: they
are the scalar representation the frontend folds, and the lowering
proof shows they reach the backend as supported scalar operations.
Multi-lane, scalable, and floating-point vectors are rejected.

Post-lowering, on the adapted text, the audit requires that every
helper callee is exactly ``inttoptr (i64 ID to ptr)`` with ``ID``
1, 2, 3, 5, 8, 14, 130, 131, 132, or 133 and the registered
signature, that no reserved pseudo-call reference remains, and
that the instruction graph is otherwise byte-identical to the
validated input, except in the core mode, where each relocation
call expands into its exact backend pattern (five lines for the
field read, two for the existence check) with threaded SSA names
and nothing else. In the subprogram mode the single subprogram
definition and its call sites pass through byte-identical (the
backend lowers the static call itself); only the module metadata
changes. The kernel offers no ``map_get_next_key``-style helper and
``for_each_map_elem`` is outside the subset's scope, so no iteration
callee exists.

Standard library only.
"""

import json
import re

STAGE_AUDIT = "adapter.audit"

# Diagnostic codes. MBPF301 is the coarse fallback for adapter-side
# failures without a narrower code (kept for wire compatibility);
# MBPF302-MBPF321 name the violated check.
CODE_FALLBACK = "MBPF301"
CODE_ENTRY = "MBPF302"
CODE_EXTERNAL = "MBPF303"
CODE_RUNTIME = "MBPF304"
CODE_NUMERIC = "MBPF305"
CODE_CALL_FORM = "MBPF306"
CODE_MAP_SHAPE = "MBPF307"
CODE_LIVENESS = "MBPF308"
CODE_MODULE = "MBPF309"
CODE_STACK = "MBPF310"
CODE_POISON = "MBPF311"
CODE_RECURSION = "MBPF312"
CODE_PSEUDO = "MBPF313"
CODE_OPERANDS = "MBPF314"
CODE_UNDEFINED = "MBPF315"
CODE_PTRSTORE = "MBPF316"
CODE_CONTEXT = "MBPF317"
CODE_KEYFRESH = "MBPF318"
CODE_CYCLE = "MBPF319"
CODE_BUDGET = "MBPF320"
CODE_OPCODE = "MBPF321"
CODE_ATOMIC = "MBPF322"

CODE_RE = re.compile(r"^MBPF3[0-9]{2}$")

# Reserved helper pseudo-calls. The SDK wrappers select these names
# through ``external_call``; the frontend must emit direct calls to
# exactly the declarations below, and the adapter lowers only the
# callee operand to the ordinary BPF helper-call representation.
# (The shorter guessed spellings ``__mojobpf_delete_v1`` and
# ``__mojobpf_nextkey_v1`` are not reserved and stay refused, as is
# any ``__mojobpf_get_next_key_v1`` spelling: the kernel offers no
# from-program map-iteration helper, so no iteration pseudo-call
# can qualify. The qualified delete spelling is the
# kernel-faithful long name below. The PID/TID spelling is the
# shared tracing spelling versioned into the SDK events module;
# the frozen counter example keeps its own identical local
# spelling so its qualified bytes stay untouched. The three
# ring-buffer reservation spellings below qualify alongside the
# copy-output spelling: one reserve plus one terminus
# (submit or discard) per reservation program, with the store
# coverage and ordering the reservation checks pin.)
#
# Reserved relocation pseudo-calls. The SDK core wrappers select
# these names through ``external_call``; unlike the helper names,
# they never lower to a kernel helper ID. The adapter expands
# each call site into the backend's preserve-access-index
# pattern, so the backend emits genuine CO-RE relocation
# records. The admitted (type, field, kind) identity is pinned
# in the names themselves: the field read resolves
# ``task_struct.pid`` (one FIELD_BYTE_OFFSET relocation) and the
# existence check resolves ``task_struct.scx`` (one FIELD_EXISTS
# relocation). Any other ``__mojobpf_core_*`` spelling (another
# type, another field, a guarded read of the optional field) is
# not reserved and stays refused.
LOOKUP_NAME = "__mojobpf_lookup_v1"
UPDATE_NAME = "__mojobpf_update_v1"
DELETE_NAME = "__mojobpf_delete_elem_v1"
PID_NAME = "__mojobpf_get_pid_tgid_v1"
KTIME_NAME = "__mojobpf_ktime_get_ns_v1"
CPU_NAME = "__mojobpf_get_smp_processor_id_v1"
OUTPUT_NAME = "__mojobpf_ringbuf_output_v1"
RESERVE_NAME = "__mojobpf_ringbuf_reserve_v1"
SUBMIT_NAME = "__mojobpf_ringbuf_submit_v1"
DISCARD_NAME = "__mojobpf_ringbuf_discard_v1"
COREREAD_NAME = "__mojobpf_core_read_task_pid_v1"
COREEXISTS_NAME = "__mojobpf_core_exists_task_scx_v1"
SKBLOAD_NAME = "__mojobpf_skb_load_bytes_v1"
SKBSTORE_NAME = "__mojobpf_skb_store_bytes_v1"
RESERVED_NAMES = (
    LOOKUP_NAME,
    UPDATE_NAME,
    DELETE_NAME,
    PID_NAME,
    KTIME_NAME,
    CPU_NAME,
    OUTPUT_NAME,
    RESERVE_NAME,
    SUBMIT_NAME,
    DISCARD_NAME,
    COREREAD_NAME,
    COREEXISTS_NAME,
    SKBLOAD_NAME,
    SKBSTORE_NAME,
)
LOOKUP_DECL_LINE = "declare i64 @__mojobpf_lookup_v1(i64, ptr) #0"
UPDATE_DECL_LINE = "declare i64 @__mojobpf_update_v1(i64, ptr, ptr, i64) #0"
DELETE_DECL_LINE = "declare i64 @__mojobpf_delete_elem_v1(i64, ptr) #0"
PID_DECL_LINE = "declare i64 @__mojobpf_get_pid_tgid_v1() #0"
KTIME_DECL_LINE = "declare i64 @__mojobpf_ktime_get_ns_v1() #0"
CPU_DECL_LINE = "declare i64 @__mojobpf_get_smp_processor_id_v1() #0"
OUTPUT_DECL_LINE = (
    "declare i64 @__mojobpf_ringbuf_output_v1(i64, ptr, i64, i64) #0"
)
RESERVE_DECL_LINE = (
    "declare i64 @__mojobpf_ringbuf_reserve_v1(i64, i64, i64) #0"
)
SUBMIT_DECL_LINE = (
    "declare i64 @__mojobpf_ringbuf_submit_v1(ptr, i64) #0"
)
DISCARD_DECL_LINE = (
    "declare i64 @__mojobpf_ringbuf_discard_v1(ptr, i64) #0"
)
COREREAD_DECL_LINE = (
    "declare i32 @__mojobpf_core_read_task_pid_v1(ptr) #0"
)
COREEXISTS_DECL_LINE = (
    "declare i32 @__mojobpf_core_exists_task_scx_v1() #0"
)
SKBLOAD_DECL_LINE = (
    "declare i64 @__mojobpf_skb_load_bytes_v1(ptr, i32, ptr, i32) #0"
)
SKBSTORE_DECL_LINE = (
    "declare i64 @__mojobpf_skb_store_bytes_v1"
    "(ptr, i32, ptr, i32, i64) #0"
)
DECL_LINES = {
    "lookup": LOOKUP_DECL_LINE,
    "update": UPDATE_DECL_LINE,
    "delete": DELETE_DECL_LINE,
    "pid": PID_DECL_LINE,
    "ktime": KTIME_DECL_LINE,
    "cpu": CPU_DECL_LINE,
    "output": OUTPUT_DECL_LINE,
    "reserve": RESERVE_DECL_LINE,
    "submit": SUBMIT_DECL_LINE,
    "discard": DISCARD_DECL_LINE,
    "coreread": COREREAD_DECL_LINE,
    "coreexists": COREEXISTS_DECL_LINE,
    "skbload": SKBLOAD_DECL_LINE,
    "skbstore": SKBSTORE_DECL_LINE,
}
# Ordinary BPF helper-call callees the adapter substitutes (helper
# IDs 1, 2, 3, 5, 8, 9, 14, 26, 130, 131, 132, and 133 with the
# registered signatures). The relocation declarations have no entry
# here: they never lower to a helper ID (the adapter expands their
# call sites instead).
LOWERED_CALLEE = {
    "lookup": "inttoptr (i64 1 to ptr)",
    "update": "inttoptr (i64 2 to ptr)",
    "delete": "inttoptr (i64 3 to ptr)",
    "pid": "inttoptr (i64 14 to ptr)",
    "ktime": "inttoptr (i64 5 to ptr)",
    "cpu": "inttoptr (i64 8 to ptr)",
    "output": "inttoptr (i64 130 to ptr)",
    "reserve": "inttoptr (i64 131 to ptr)",
    "submit": "inttoptr (i64 132 to ptr)",
    "discard": "inttoptr (i64 133 to ptr)",
    "skbload": "inttoptr (i64 26 to ptr)",
    "skbstore": "inttoptr (i64 9 to ptr)",
}

# Admitted subprogram (BPF-to-BPF call) definition. One program
# carries at most one callee: a ``dso_local`` C-ABI export with the
# fixed one-argument scalar signature ``(i64) -> i64`` under a
# plain C-identifier name (never an entrypoint symbol, a reserved
# helper name, or an ``llvm.`` spelling; the scan excludes those
# before routing). The attribute index follows definition order:
# 0 when the callee is defined before the entrypoint, 1 when
# after. Group 1 is the callee name, group 2 the attribute index.
# The parameter spelling mirrors the entrypoint header (one ``i64``
# value, attributes unpinned); the wiring check pins which
# attribute set each index must carry.
CALLEE_DEFINE_RE = re.compile(
    r"^define dso_local i64 @([A-Za-z_][A-Za-z0-9_]*)"
    r"\(i64\s+[^,)]+\) #(0|1) \{$"
)
# Admitted subprogram call sites in the entrypoint body: exactly
# the ``tail call`` spelling with one ``i64`` operand (an SSA value
# or a decimal literal), defining the ``i64`` result. Group 1 is
# the result SSA name, group 2 the callee name, group 3 the
# operand. The scan admits only sites naming the one defined
# callee; any other callee name refuses as an unexpected call.
SUBPROG_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*tail call i64 @([A-Za-z_][A-Za-z0-9_]*)"
    r"\(i64\s+(%[A-Za-z0-9_.$-]+|-?\d+)\)$"
)
# The same call without the ``tail`` marker: refused with the
# call-form code, never silently accepted as the admitted shape.
SUBPROG_CALL_NOTAIL_RE = re.compile(
    r"^%(\S+)\s*=\s*call i64 @([A-Za-z_][A-Za-z0-9_]*)"
    r"\(i64\s+(%[A-Za-z0-9_.$-]+|-?\d+)\)$"
)

# Qualified ring-buffer sizes in bytes. The ring-size tag carries
# exactly one of these literals; the adapter emits it into the
# ring-buffer BTF and the build reconciles it against the manifest.
# Must equal the target profile's allowed ring-buffer sizes; the
# build-command suite cross-checks the two spellings.
RINGBUF_SIZES = (4096, 131072)

# Admitted body-call shapes. The twelve assembly shapes are exact
# single lines (see the adapter contract); the ten helper shapes
# and the two relocation shapes are direct calls to the reserved
# declarations with exactly the signatures above, no attributes,
# and no operand bundles.
# Group 1 of every shape below is the result SSA name; the helper
# shapes add one group per operand in order (the PID/TID, clock,
# and CPU calls take none), the keyslotN shape adds the key literal
# as group 2, the ring-size tag adds the map address as group 2
# and the size literal as group 3, the eventslotN shape adds
# the slot offset as group 2, and the relocation read adds the
# value pointer as group 2 (the existence check takes none).
# The reservation call pins its size and flags literals (groups
# 3 and 4 are fixed, so no group is bound for them); each
# terminus binds its record pointer as group 2.
# The base event slot precedes the field views in match order, so
# either base line matches first.
ASM_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+ptr\s+asm\s+\"\",\s*\"=r,0\"\(i64\s+%\S+\)$"
)
MAPADDR_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+asm\s+sideeffect\s+"
    r"\"r0 = mojobpf_map0 ll\",\s*\"=\{r0\}\"\(\)$"
)
KEYSLOT_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+ptr\s+asm\s+sideeffect\s+"
    r"\"r0 = r10\\0Ar0 \+= -4\\0A\*\(u32 \*\)\(r0 \+ 0\) = r1\",\s*"
    r"\"=\{r0\},\{r1\},~\{memory\}\"\(i32 0\)$"
)
# Key-slot preparation holding key 1: the identical audited stack
# template, holding the second entry of a multi-entry map.
KEYSLOT1_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+ptr\s+asm\s+sideeffect\s+"
    r"\"r0 = r10\\0Ar0 \+= -4\\0A\*\(u32 \*\)\(r0 \+ 0\) = r1\",\s*"
    r"\"=\{r0\},\{r1\},~\{memory\}\"\(i32 1\)$"
)
# Key-slot preparation holding key 2 or above: the identical audited
# stack template with a canonical decimal literal (group 2). The
# count rule, not the spelling, binds which literals may appear.
KEYSLOTN_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+ptr\s+asm\s+sideeffect\s+"
    r"\"r0 = r10\\0Ar0 \+= -4\\0A\*\(u32 \*\)\(r0 \+ 0\) = r1\",\s*"
    r"\"=\{r0\},\{r1\},~\{memory\}\"\(i32 ([2-9][0-9]*)\)$"
)
# Per-CPU kind tag: the loaded map address tied to its result
# through an empty template, so the backend emits nothing for it.
# Present once per map-address load in per-CPU programs, absent in
# array programs. The operand must be a map-address SSA value and
# the tag result is what per-CPU helper calls take as their map
# operand (the operand provenance check enforces both); the tag's
# own value is always that address.
KINDTAG_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+asm\s+\"\",\s*\"=r,0\""
    r"\(i64\s+%(\S+)\)$"
)
# Hash kind tag: the loaded map address tied to its result
# through an empty template with the sideeffect marker, so the
# backend emits nothing for it. The sideeffect spelling is what
# distinguishes it from the per-CPU kind tag above (which has no
# marker) and from every other shape: a tag with the marker is
# always a hash tag, never a per-CPU tag. Present once per
# map-address load in hash programs, absent otherwise. The
# operand must be a map-address SSA value and the tag result is
# what hash helper calls take as their map operand (the operand
# provenance check enforces both); the tag's own value is always
# that address.
HASHTAG_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+asm\s+sideeffect\s+\"\",\s*\"=r,0\""
    r"\(i64\s+%(\S+)\)$"
)
# LRU kind tag: the loaded map address tied to its result
# through an empty template with a memory clobber, so the
# backend emits nothing for it while the audit tells it apart
# from the per-CPU tag (no side effect) and the hash tag (no
# clobber). The operand must be a map-address SSA value and the
# tag result is what LRU helper calls take as their map operand
# (the operand provenance check enforces both); the tag's own
# value is always that address.
LRUTAG_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+asm\s+sideeffect\s+\"\","
    r"\s*\"=r,0,~\{memory\}\""
    r"\(i64\s+%(\S+)\)$"
)
VALSLOT_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+ptr\s+asm\s+sideeffect\s+"
    r"\"r0 = r10\\0Ar0 \+= -16\",\s*\"=\{r0\}\"\(\)$"
)
LOOKUP_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+@__mojobpf_lookup_v1"
    r"\(i64\s+%(\S+),\s+ptr\s+%(\S+)\)$"
)
UPDATE_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+@__mojobpf_update_v1"
    r"\(i64\s+%(\S+),\s+ptr\s+%(\S+),\s+ptr\s+%(\S+),\s+i64 0\)$"
)
DELETE_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+@__mojobpf_delete_elem_v1"
    r"\(i64\s+%(\S+),\s+ptr\s+%(\S+)\)$"
)
PID_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+@__mojobpf_get_pid_tgid_v1\(\)$"
)
# Ring-buffer map-address load: the second map metadata entry.
# Only the output call takes this address (through the size tag);
# lookup/update/delete never do.
RBMAPADDR_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+asm\s+sideeffect\s+"
    r"\"r0 = mojobpf_map1 ll\",\s*\"=\{r0\},~\{memory\}\"\(\)$"
)
# Ring-size tag: the loaded ring-buffer address tied to its result
# through an empty template carrying the ring size literal, so the
# backend emits nothing for it. The adapter reads the literal into
# the ring-buffer BTF; the event slot check pins it to the
# qualified ring-buffer sizes so the profile and the audit cannot
# drift. Group 2 is the map address, group 3 the size literal.
RBSIZE_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+asm\s+\"\",\s*\"=r,0,r\""
    r"\(i64\s+%(\S+),\s+i64\s+(\d+)\)$"
)
# Event scratch buffer: the 32-byte record area at r10-64, clear
# of the key slot (r10-4) and the value slot (r10-16). The base
# view feeds the output call's data operand; the field views
# below feed the word stores. The encoder initializes all 32
# bytes before the output call.
EVENTSLOT_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+ptr\s+asm\s+sideeffect\s+"
    r"\"r0 = r10\\0Ar0 \+= -64\",\s*\"=\{r0\},~\{memory\}\"\(\)$"
)
# Event field views: typed addresses into the record area, one
# per field above the base. The version view shares the base
# line (any base line is the buffer base, so the output
# provenance stays sound); the other six carry their field
# offsets, pinned to exactly the record layout by the event
# slot check. Group 2 is the slot offset.
EVENTSLOTN_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+ptr\s+asm\s+sideeffect\s+"
    r"\"r0 = r10\\0Ar0 \+= -(\d+)\",\s*\"=\{r0\},~\{memory\}\"\(\)$"
)
# Record field-view offsets (r10-relative magnitudes, sorted):
# one per field above the base, each used exactly once.
EVENTSLOTN_OFFSETS = (40, 48, 52, 56, 60, 62)
# Monotonic clock (helper 5) and CPU number (helper 8): no
# operands, like the PID/TID call. Each exists only because its
# record field needs it.
KTIME_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+@__mojobpf_ktime_get_ns_v1\(\)$"
)
CPU_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+@__mojobpf_get_smp_processor_id_v1\(\)$"
)
# Copy-output call (helper 130): the size-tagged ring-buffer map
# address, the prepared event slot, the literal record size 32,
# and the literal flags 0. Any other size or flags value is
# refused, never rewritten.
OUTPUT_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+@__mojobpf_ringbuf_output_v1"
    r"\(i64\s+%(\S+),\s+ptr\s+%(\S+),\s+i64 32,\s+i64 0\)$"
)
# Reservation call (helper 131): the size-tagged ring-buffer map
# address, the literal record size 32, and the literal flags 0.
# The result is a nullable reservation address carried as an
# integer (0 means null). Any other size or flags value is
# refused, never rewritten.
RESERVE_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+@__mojobpf_ringbuf_reserve_v1"
    r"\(i64\s+%(\S+),\s+i64 32,\s+i64 0\)$"
)
# Reservation termini (helpers 132 and 133): the record
# reinterpretation of the reservation result plus the literal
# flags 0. The kernel reports no status (both helpers return
# void); the pseudo-call carries an unused i64 result so the
# shape stays a plain typed call. Any other flags value is
# refused, never rewritten.
SUBMIT_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+@__mojobpf_ringbuf_submit_v1"
    r"\(ptr\s+%(\S+),\s+i64 0\)$"
)
DISCARD_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+@__mojobpf_ringbuf_discard_v1"
    r"\(ptr\s+%(\S+),\s+i64 0\)$"
)
# Reservation-relative field addresses: byte offsets off the
# record reinterpretation. The frontend folds offset 0 into a
# direct store; offsets 2..24 arrive as one-word GEPs. The
# reservation store check pins the exact offset multiset, so
# this pattern only recognizes the spelling, never the layout.
RESERVE_GEP_RE = re.compile(
    r"^%(\S+)\s*=\s*getelementptr\s+inbounds\s+i8,\s*ptr\s+"
    r"%(\S+),\s*i32\s+(\d+)$"
)
# Record field stores relative to the reservation: (byte
# offset, store width), covering all 32 record bytes with no
# gaps and no overlap. Offset 0 is stored directly through the
# reinterpretation; the rest through one GEP each.
RESERVE_FIELD_STORES = (
    (0, "i16"),
    (2, "i16"),
    (4, "i32"),
    (8, "i32"),
    (12, "i32"),
    (16, "i64"),
    (24, "i64"),
)
# Relocation read (pinned ``task_struct.pid`` field access): the
# checked map value pointer, returning the relocated u32. Any
# other operand (a constant, a slot, another type) is refused,
# never rewritten.
COREREAD_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i32\s+@__mojobpf_core_read_task_pid_v1"
    r"\(ptr\s+%(\S+)\)$"
)
# Relocation existence check (pinned ``task_struct.scx`` member):
# no operands, returning 1 when the member exists, 0 otherwise.
COREEXISTS_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i32\s+@__mojobpf_core_exists_task_scx_v1\(\)$"
)
# Packet-byte load (helper 26): the skb context, the byte offset,
# the key-slot destination, and the length. Offset and length
# accept an SSA name or a decimal literal: programs choose their
# own windows, and the kernel fails the call closed on overrun.
# Groups 2..5 are skb, offset, to, length.
SKBLOAD_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+@__mojobpf_skb_load_bytes_v1"
    r"\(ptr\s+%(\S+),\s+i32\s+(%\S+|\d+),\s+ptr\s+%(\S+),"
    r"\s+i32\s+(%\S+|\d+)\)$"
)
# Packet-byte store (helper 9): the skb context, the byte offset,
# the key-slot source, the length, and the flags. Offset and
# length accept an SSA name or a decimal literal like the load;
# the flags operand is pinned to the ``i64 0`` literal (the
# UPDATE-flags precedent: the L2 store legs need no checksum or
# hash flags). Groups 2..5 are skb, offset, from, length.
SKBSTORE_CALL_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+@__mojobpf_skb_store_bytes_v1"
    r"\(ptr\s+%(\S+),\s+i32\s+(%\S+|\d+),\s+ptr\s+%(\S+),"
    r"\s+i32\s+(%\S+|\d+),\s+i64 0\)$"
)
ASM_SHAPES = (
    ("empty", ASM_CALL_RE),
    ("mapaddr", MAPADDR_CALL_RE),
    ("keyslot", KEYSLOT_CALL_RE),
    ("keyslot1", KEYSLOT1_CALL_RE),
    ("keyslotN", KEYSLOTN_CALL_RE),
    ("kindtag", KINDTAG_CALL_RE),
    ("hashtag", HASHTAG_CALL_RE),
    ("lrutag", LRUTAG_CALL_RE),
    ("valslot", VALSLOT_CALL_RE),
    ("rbmapaddr", RBMAPADDR_CALL_RE),
    ("rbsize", RBSIZE_CALL_RE),
    ("eventslot", EVENTSLOT_CALL_RE),
    ("eventslotN", EVENTSLOTN_CALL_RE),
    ("lookup", LOOKUP_CALL_RE),
    ("update", UPDATE_CALL_RE),
    ("delete", DELETE_CALL_RE),
    ("pid", PID_CALL_RE),
    ("ktime", KTIME_CALL_RE),
    ("cpu", CPU_CALL_RE),
    ("output", OUTPUT_CALL_RE),
    ("reserve", RESERVE_CALL_RE),
    ("submit", SUBMIT_CALL_RE),
    ("discard", DISCARD_CALL_RE),
    ("coreread", COREREAD_CALL_RE),
    ("coreexists", COREEXISTS_CALL_RE),
    ("skbload", SKBLOAD_CALL_RE),
    ("skbstore", SKBSTORE_CALL_RE),
)
# Key-slot shapes whose result carries a key literal (keyslot holds
# 0, keyslot1 holds 1, keyslotN holds its group-2 literal).
KEYSLOT_SHAPES = ("keyslot", "keyslot1", "keyslotN")
# Program modes admitted by validate(), in canonical order. The
# adapter service dispatches the transform per mode; unknown modes
# refuse (select_route), they never inherit a route.
ADMITTED_MODES = (
    "classifier", "classifier-loop", "map", "combined",
    "tracepoint", "event", "reserve", "subprog", "core",
    "uprobe", "skb",
)
# Modes whose release artifacts come from the parsed LLVM route.
# A mode flips only with its layout + negative evidence re-proven
# through the parsed lane plus an approved target-proof-table row
# (Lane-A amendment promotion criteria). All start false.
PARSED_QUALIFIED_MODES = frozenset({"classifier", "subprog"})


def parsed_qualified(mode):
    """True when the mode's release artifacts come from parsed."""
    return mode in PARSED_QUALIFIED_MODES


class TableError(ValueError):
    """The target-proof table is malformed or refuses a row."""


TABLE_SCHEMA_VERSION = 1
TABLE_REQUIRED_ROW_KEYS = (
    "shape", "lowering_commit", "equivalence_report_sha256",
    "approver", "date",
)


def validate_target_proof_table(raw):
    """Validate the target-proof table; return approved shapes.

    Accepts the table's JSON text. Every row needs all required
    keys with nonempty values, a known shape, a 40-hex lowering
    commit and a 64-hex equivalence digest; duplicate shapes
    refuse (monotone growth: rows are only appended). Raises
    TableError naming the first violation. Returns the approved
    shape list in row order.
    """
    try:
        table = json.loads(raw)
    except ValueError as exc:
        raise TableError("table is not JSON: %s" % exc)
    if not isinstance(table, dict):
        raise TableError("table must be an object")
    if table.get("schema_version") != TABLE_SCHEMA_VERSION:
        raise TableError(
            "table schema_version must be %d" % TABLE_SCHEMA_VERSION
        )
    rows = table.get("rows")
    if not isinstance(rows, list):
        raise TableError("table rows must be a list")
    seen = []
    for index, row in enumerate(rows):
        where = "row %d" % index
        if not isinstance(row, dict):
            raise TableError("%s must be an object" % where)
        for key in TABLE_REQUIRED_ROW_KEYS:
            value = row.get(key)
            if not isinstance(value, str) or not value:
                raise TableError(
                    "%s needs nonempty %r" % (where, key)
                )
        shape = row["shape"]
        if shape not in ADMITTED_MODES:
            raise TableError(
                "%s names unknown shape %r" % (where, shape)
            )
        if shape in seen:
            raise TableError(
                "%s duplicates shape %r" % (where, shape)
            )
        commit = row["lowering_commit"]
        if len(commit) != 40 or any(
            char not in "0123456789abcdef" for char in commit
        ):
            raise TableError(
                "%s lowering_commit must be 40 hex" % where
            )
        digest = row["equivalence_report_sha256"]
        if len(digest) != 64 or any(
            char not in "0123456789abcdef" for char in digest
        ):
            raise TableError(
                "%s equivalence_report_sha256 must be 64 hex" % where
            )
        seen.append(shape)
    return seen
# The five frozen admitted shape count vectors, keyed by shape
# name. The combined vector is the packet workload in one program:
# one packet reinterpretation plus two map read-modify-write pairs
# (entries 0 and 1), sharing the single lookup/update declaration
# pair. The tracepoint vector is the TID-filtered counter: one
# filter read through key 0, one current-PID/TID call, and one
# read-modify-write pair through key 1. The event vector is the
# TID-filtered event emitter: one filter read through key 0, one
# filter PID/TID call, one sequence pair through key 1, one CPU
# call, one clock call, one record PID/TID call, one copy-output
# call, one success pair through key 2, and one failure pair
# through key 3. Wider map shapes validate through the count
# families in _check_counts, never by editing these vectors.
CLASSIFIER_COUNTS = {
    "empty": 1,
    "mapaddr": 0,
    "keyslot": 0,
    "keyslot1": 0,
    "keyslotN": 0,
    "kindtag": 0,
    "hashtag": 0,
    "lrutag": 0,
    "valslot": 0,
    "rbmapaddr": 0,
    "rbsize": 0,
    "eventslot": 0,
    "eventslotN": 0,
    "lookup": 0,
    "update": 0,
    "delete": 0,
    "pid": 0,
    "ktime": 0,
    "cpu": 0,
    "output": 0,
    "reserve": 0,
    "submit": 0,
    "discard": 0,
    "coreread": 0,
    "coreexists": 0,
    "skbload": 0,
    "skbstore": 0,
}
MAP_COUNTS = {
    "empty": 1,
    "mapaddr": 2,
    "keyslot": 2,
    "keyslot1": 0,
    "keyslotN": 0,
    "kindtag": 0,
    "hashtag": 0,
    "lrutag": 0,
    "valslot": 1,
    "rbmapaddr": 0,
    "rbsize": 0,
    "eventslot": 0,
    "eventslotN": 0,
    "lookup": 1,
    "update": 1,
    "delete": 0,
    "pid": 0,
    "ktime": 0,
    "cpu": 0,
    "output": 0,
    "reserve": 0,
    "submit": 0,
    "discard": 0,
    "coreread": 0,
    "coreexists": 0,
    "skbload": 0,
    "skbstore": 0,
}
COMBINED_COUNTS = {
    "empty": 3,
    "mapaddr": 4,
    "keyslot": 2,
    "keyslot1": 2,
    "keyslotN": 0,
    "kindtag": 0,
    "hashtag": 0,
    "lrutag": 0,
    "valslot": 2,
    "rbmapaddr": 0,
    "rbsize": 0,
    "eventslot": 0,
    "eventslotN": 0,
    "lookup": 2,
    "update": 2,
    "delete": 0,
    "pid": 0,
    "ktime": 0,
    "cpu": 0,
    "output": 0,
    "reserve": 0,
    "submit": 0,
    "discard": 0,
    "coreread": 0,
    "coreexists": 0,
    "skbload": 0,
    "skbstore": 0,
}
TRACEPOINT_COUNTS = {
    "empty": 2,
    "mapaddr": 3,
    "keyslot": 1,
    "keyslot1": 2,
    "keyslotN": 0,
    "kindtag": 0,
    "hashtag": 0,
    "lrutag": 0,
    "valslot": 1,
    "rbmapaddr": 0,
    "rbsize": 0,
    "eventslot": 0,
    "eventslotN": 0,
    "lookup": 2,
    "update": 1,
    "delete": 0,
    "pid": 1,
    "ktime": 0,
    "cpu": 0,
    "output": 0,
    "reserve": 0,
    "submit": 0,
    "discard": 0,
    "coreread": 0,
    "coreexists": 0,
    "skbload": 0,
    "skbstore": 0,
}
EVENT_COUNTS = {
    "empty": 4,
    "mapaddr": 7,
    "keyslot": 1,
    "keyslot1": 2,
    "keyslotN": 4,
    "kindtag": 0,
    "hashtag": 0,
    "lrutag": 0,
    "valslot": 3,
    "rbmapaddr": 1,
    "rbsize": 1,
    "eventslot": 2,
    "eventslotN": 6,
    "lookup": 4,
    "update": 3,
    "delete": 0,
    "pid": 2,
    "ktime": 1,
    "cpu": 1,
    "output": 1,
    "reserve": 0,
    "submit": 0,
    "discard": 0,
    "coreread": 0,
    "coreexists": 0,
    "skbload": 0,
    "skbstore": 0,
}
# The reservation submitter is the TID-filtered event emitter
# with explicit ownership: one filter read through key 0, one
# filter PID/TID call, one sequence pair through key 1, one CPU
# call, one clock call, one record PID/TID call, one reserve
# call, seven reservation-relative word stores, one submit
# terminus, one success pair through key 2, and one failure
# pair through key 3. The fifth reinterpretation is the record
# reinterpretation of the reservation result; there are no
# scratch event slots. Any second reserve, any second terminus,
# or any terminus mix matches neither this vector nor the
# discarder below.
RESERVE_SUBMIT_COUNTS = {
    "empty": 5,
    "mapaddr": 7,
    "keyslot": 1,
    "keyslot1": 2,
    "keyslotN": 4,
    "kindtag": 0,
    "hashtag": 0,
    "lrutag": 0,
    "valslot": 3,
    "rbmapaddr": 1,
    "rbsize": 1,
    "eventslot": 0,
    "eventslotN": 0,
    "lookup": 4,
    "update": 3,
    "delete": 0,
    "pid": 2,
    "ktime": 1,
    "cpu": 1,
    "output": 0,
    "reserve": 1,
    "submit": 1,
    "discard": 0,
    "coreread": 0,
    "coreexists": 0,
    "skbload": 0,
    "skbstore": 0,
}
# The reservation discarder is the submitter with the discard
# terminus instead of the submit terminus: one reserve call,
# seven reservation-relative word stores, one discard terminus,
# and the same filter/sequence/released/failed pairs through
# keys 0, 1, 2, and 3.
RESERVE_DISCARD_COUNTS = {
    "empty": 5,
    "mapaddr": 7,
    "keyslot": 1,
    "keyslot1": 2,
    "keyslotN": 4,
    "kindtag": 0,
    "hashtag": 0,
    "lrutag": 0,
    "valslot": 3,
    "rbmapaddr": 1,
    "rbsize": 1,
    "eventslot": 0,
    "eventslotN": 0,
    "lookup": 4,
    "update": 3,
    "delete": 0,
    "pid": 2,
    "ktime": 1,
    "cpu": 1,
    "output": 0,
    "reserve": 1,
    "submit": 0,
    "discard": 1,
    "coreread": 0,
    "coreexists": 0,
    "skbload": 0,
    "skbstore": 0,
}
# The core relocation probe is the TID-free XDP observer: one
# lookup through key 0 into the single-entry map, one relocated
# field read of the checked value, and one optional-field check.
# The entry parameter stays unused (no context payload read); the
# return word is a test-run observation, not a forwarding
# decision.
CORE_COUNTS = {
    "empty": 1,
    "mapaddr": 1,
    "keyslot": 1,
    "keyslot1": 0,
    "keyslotN": 0,
    "kindtag": 0,
    "hashtag": 0,
    "lrutag": 0,
    "valslot": 0,
    "rbmapaddr": 0,
    "rbsize": 0,
    "eventslot": 0,
    "eventslotN": 0,
    "lookup": 1,
    "update": 0,
    "delete": 0,
    "pid": 0,
    "ktime": 0,
    "cpu": 0,
    "output": 0,
    "reserve": 0,
    "submit": 0,
    "discard": 0,
    "coreread": 1,
    "coreexists": 1,
    "skbload": 0,
    "skbstore": 0,
}
# The uprobe register counter is the TID-free tracing observer:
# one filter read through key 0 and one count pair through key 1
# with no helper-ID call. The call-shape counts alone match no
# other vector (two lookups with one update and no PID/TID
# call); the pinned context-word read is pinned separately by
# the uprobe context rule, which admits exactly the x86-64
# first-argument register word and refuses every other context
# access.
UPROBE_COUNTS = {
    "empty": 2,
    "mapaddr": 3,
    "keyslot": 1,
    "keyslot1": 2,
    "keyslotN": 0,
    "kindtag": 0,
    "hashtag": 0,
    "lrutag": 0,
    "valslot": 1,
    "rbmapaddr": 0,
    "rbsize": 0,
    "eventslot": 0,
    "eventslotN": 0,
    "lookup": 2,
    "update": 1,
    "delete": 0,
    "pid": 0,
    "ktime": 0,
    "cpu": 0,
    "output": 0,
    "reserve": 0,
    "submit": 0,
    "discard": 0,
    "coreread": 0,
    "coreexists": 0,
    "skbload": 0,
    "skbstore": 0,
}
# The skb vectors are the helper-based net shapes: one packet-byte
# load plus its key slot, or one packet-byte store plus its key-N
# slot. Both are mapless (no map address, no value slot); wider
# skb-plus-map shapes need their own reviewed vectors.
SKB_LOAD_COUNTS = {
    "empty": 0,
    "mapaddr": 0,
    "keyslot": 1,
    "keyslot1": 0,
    "keyslotN": 0,
    "kindtag": 0,
    "hashtag": 0,
    "lrutag": 0,
    "valslot": 0,
    "rbmapaddr": 0,
    "rbsize": 0,
    "eventslot": 0,
    "eventslotN": 0,
    "lookup": 0,
    "update": 0,
    "delete": 0,
    "pid": 0,
    "ktime": 0,
    "cpu": 0,
    "output": 0,
    "reserve": 0,
    "submit": 0,
    "discard": 0,
    "coreread": 0,
    "coreexists": 0,
    "skbload": 1,
    "skbstore": 0,
}
SKB_STORE_COUNTS = {
    "empty": 0,
    "mapaddr": 0,
    "keyslot": 0,
    "keyslot1": 0,
    "keyslotN": 1,
    "kindtag": 0,
    "hashtag": 0,
    "lrutag": 0,
    "valslot": 0,
    "rbmapaddr": 0,
    "rbsize": 0,
    "eventslot": 0,
    "eventslotN": 0,
    "lookup": 0,
    "update": 0,
    "delete": 0,
    "pid": 0,
    "ktime": 0,
    "cpu": 0,
    "output": 0,
    "reserve": 0,
    "submit": 0,
    "discard": 0,
    "coreread": 0,
    "coreexists": 0,
    "skbload": 0,
    "skbstore": 1,
}
# The loadmap vector pairs one packet-byte load with one map
# update (the TC load-into-map leg): the load buffer, the map
# key, the value slot, the map address, the update, and the
# load. Two entries admit keys 0 and 1.
SKB_LOADMAP_COUNTS = {
    "empty": 0,
    "mapaddr": 1,
    "keyslot": 1,
    "keyslot1": 1,
    "keyslotN": 0,
    "kindtag": 0,
    "hashtag": 0,
    "lrutag": 0,
    "valslot": 1,
    "rbmapaddr": 0,
    "rbsize": 0,
    "eventslot": 0,
    "eventslotN": 0,
    "lookup": 0,
    "update": 1,
    "delete": 0,
    "pid": 0,
    "ktime": 0,
    "cpu": 0,
    "output": 0,
    "reserve": 0,
    "submit": 0,
    "discard": 0,
    "coreread": 0,
    "coreexists": 0,
    "skbload": 1,
    "skbstore": 0,
}

# Admitted entrypoint symbols. The XDP programs export xdp_entry;
# the tracepoint counter exports trace_entry with the same C ABI
# (one context pointer, i32 result) and leaves the context unused;
# the uprobe register counter exports uprobe_entry with the same
# C ABI and reads exactly the pinned x86-64 first-argument
# register word through the context pointer; the socket filter
# and the TC classifier export socket_entry and tc_entry with
# the same C ABI for the mapless classifier shape only (any
# other body under those entries is refused by the entry/family
# rule, since only the classifier shape is proven in-kernel for
# the socket and TC program types).
ENTRY_SYMBOLS = (
    "xdp_entry", "trace_entry", "uprobe_entry",
    "socket_entry", "tc_entry",
)
DEFINE_RE = re.compile(
    r"^define\s+\S+\s+i32\s+@"
    r"(xdp_entry|trace_entry|uprobe_entry|socket_entry|tc_entry)"
    r"\(ptr\s+[^,)]+\)\s+#0\s*\{$"
)
# Entrypoint header in the subprogram shape only: the same C-ABI
# header, but the attribute index follows definition order (0
# when the entrypoint is defined first, 1 when the subprogram
# is). Group 1 is the entry symbol, group 2 the index.
ENTRY_DEFINE_SUBPROG_RE = re.compile(
    r"^define\s+\S+\s+i32\s+@"
    r"(xdp_entry|trace_entry|uprobe_entry|socket_entry|tc_entry)"
    r"\(ptr\s+[^,)]+\)\s+#(0|1)\s*\{$"
)
# Trailing attribute index of a routed define header.
DEFINE_ATTRS_RE = re.compile(r"#(\d+)\s*\{$")
GLOBAL_RE = re.compile(r"^@(?:\"[^\"]*\"|[A-Za-z0-9_.$]+)\s*=")
SOURCE_FILENAME_RE = re.compile(r"^source_filename\s*=\s*\"[^\"]*\"$")
TARGET_DATALAYOUT_RE = re.compile(r"^target datalayout\s*=\s*\"[^\"]*\"$")
TARGET_TRIPLE_RE = re.compile(r"^target triple\s*=\s*\"[^\"]*\"$")
ATTRS_ZERO_RE = re.compile(r"^attributes #0\s*=\s*\{.*\}$")
# Attribute group lines by index. Only #0 exists without a
# subprogram; the subprogram shape carries #0 and #1 (one plain
# set, one noinline set). The contents stay unpinned here (the
# adapter pins the exact bytes); only the noinline marker and the
# admitted indices are structural.
ATTRS_N_RE = re.compile(r"^attributes #(\d+)\s*=\s*\{(.*)\}$")
NOINLINE_MARK_RE = re.compile(r"\bnoinline\b")
DECLARE_RE = re.compile(
    r"^declare\s+(?:[^@]*?\s+)?@([A-Za-z0-9_.$]+)\s*\(.*\).*$"
)
CALL_DETECT_RE = re.compile(r"(^|\s)call\b")
CALLEE_DIRECT_RE = re.compile(r"\bcall\b[^@]*@([A-Za-z0-9_.$]+)")
CALLEE_SSA_RE = re.compile(r"\bcall\b\s+(?:\S+\s+)?%")
LABEL_USE_RE = re.compile(r"label\s+%\S+")
LABEL_DEF_RE = re.compile(r"^[A-Za-z0-9_.$-]+:$")
SSA_DEF_RE = re.compile(r"^%([A-Za-z0-9_.$-]+)\s*=")
SSA_USE_RE = re.compile(r"%([A-Za-z0-9_.$-]+)")
# Pinned uprobe context-word read (x86-64 only): the frontend
# folds the SDK's first-argument vocabulary into one address
# computation off the entry parameter plus one i64 load. Word 14
# of ``struct pt_regs`` is ``rdi`` (byte 112), the first
# function-argument register under the System V ABI; the uprobe
# fires at function entry, so the register still holds the
# caller's first argument. Group 1 of the address pattern is the
# defined SSA name, group 2 the entry parameter name; group 1 of
# the load pattern is the defined SSA name, group 2 the address
# name. Any other element type, index, loaded width, or second
# address computation is a different register and is refused.
UPROBE_CTX_GEP_RE = re.compile(
    r"^%([A-Za-z0-9_.$-]+)\s*=\s*getelementptr\s+inbounds\s+"
    r"i64,\s*ptr\s+%([A-Za-z0-9_.$-]+),\s*i32 14$"
)
UPROBE_CTX_LOAD_RE = re.compile(
    r"^%([A-Za-z0-9_.$-]+)\s*=\s*load\s+i64,\s*ptr\s+"
    r"%([A-Za-z0-9_.$-]+),\s*align 8$"
)
QUOTED_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
VECTOR_TYPE_RE = re.compile(
    r"<\s*(vscale\s+x\s+)?(\d+)\s+x\s+([A-Za-z0-9]+)\s*>"
)
ALLOWED_ONELANE_ELEMENTS = frozenset(
    ["i1", "i8", "i16", "i32", "i64", "i128"]
)

# Whole-token predicates for prohibited body constructs. Each entry
# is (compiled pattern, code, behavior label for the explanation).
FORBIDDEN_BODY = (
    (
        re.compile(
            r"\b(invoke|landingpad|resume|personality|catchpad|"
            r"catchret|cleanuppad|cleanupret|catchswitch)\b|"
            r"llvm\.global_ctors|llvm\.global_dtors|"
            r"\bthread_?local\b|"
            r"\bllvm\.[A-Za-z0-9_.$]+"
        ),
        CODE_RUNTIME,
        "unwinding, TLS, constructor, or intrinsic machinery",
    ),
    (
        re.compile(
            r"\b(fence|cmpxchg|atomicrmw|va_arg|va_start|va_end|"
            r"va_copy)\b"
        ),
        CODE_RUNTIME,
        "atomic or varargs machinery",
    ),
    (
        re.compile(
            r"\b(half|bfloat|float|double|fp128|x86_fp80|"
            r"ppc_fp80|fadd|fsub|fmul|fdiv|frem|fcmp|fneg|"
            r"fptrunc|fpext|fptosi|fptoui|sitofp|uitofp|"
            r"shufflevector)\b"
        ),
        CODE_NUMERIC,
        "floating-point or unsupported vector operation",
    ),
    (
        re.compile(r"\balloca\b"),
        CODE_STACK,
        "stack allocation",
    ),
    (
        re.compile(
            r"\b(ptrtoint|inttoptr|addrspace|poison|undef)\b"
        ),
        CODE_POISON,
        "poison/undef, address space, or pointer/integer erasure",
    ),
    (
        re.compile(r"\bcallbr\b"),
        CODE_CALL_FORM,
        "unsupported call form (callbr)",
    ),
    (
        re.compile(r"\b(indirectbr|blockaddress)\b"),
        CODE_CALL_FORM,
        "indirect control flow (indirectbr/blockaddress)",
    ),
)


class AuditError(Exception):
    """An audit rejection with a stable diagnostic code.

    ``code`` is an ``MBPF3xx`` string, ``stage`` is always
    ``adapter.audit``, ``location`` names the IR line, and ``remedy``
    tells the author how to stay inside the audited subset without
    inventing a fallback.
    """

    def __init__(self, code, explanation, location=None, remedy=None):
        assert CODE_RE.match(code), "invalid audit code: %r" % (code,)
        self.code = code
        self.stage = STAGE_AUDIT
        self.severity = "error"
        self.explanation = explanation
        self.location = location
        self.remedy = remedy
        text = "[%s] %s" % (code, explanation)
        if location is not None:
            text += " (%s)" % location
        super().__init__(text)

    def to_diagnostic(self):
        """Return the six-field diagnostic dict for this rejection."""
        return {
            "code": self.code,
            "stage": self.stage,
            "severity": self.severity,
            "explanation": self.explanation,
            "location": self.location,
            "remedy": self.remedy,
        }


def strip_comment(line):
    """Cut an LLVM ``;`` comment, keeping quoted strings intact."""
    in_string = False
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\" and in_string:
            index += 2
            continue
        if char == '"':
            in_string = not in_string
        elif char == ";" and not in_string:
            return line[:index]
        index += 1
    return line


def match_shape(line):
    """Return the admitted call-shape name for a line, or None."""
    for name, pattern in ASM_SHAPES:
        if pattern.match(line):
            return name
    return None


def _at(lineno):
    return "line %d" % lineno


class Program(object):
    """Structural model of one validated entrypoint body."""

    def __init__(self):
        self.define_lineno = 0
        # Entrypoint symbol from the define line ("xdp_entry",
        # "trace_entry", "uprobe_entry", "socket_entry", or
        # "tc_entry"; empty until the define line is scanned).
        self.entry = ""
        # Exact entrypoint header line (the wiring check reads its
        # attribute index in the subprogram shape).
        self.entry_define = ""
        # Entry parameter SSA names, in order (the context pointer).
        self.params = []
        # SSA name -> defining line (entry parameters count as
        # defined on the define line).
        self.defs = {}
        # SSA name -> sorted use lines (label operands excluded).
        self.uses = {}
        # Block names defined by label lines (phi successor operands
        # name blocks without the ``label`` keyword, so they read as
        # SSA uses and must be excluded from the roots check).
        self.labels = set()
        # Block-label line numbers in the entrypoint body, in line
        # order, plus the label name at each line (the
        # key-freshness check refuses a key preparation consumed
        # across an ambiguous control-flow edge).
        self.label_lines = []
        self.label_at = {}
        # (lineno, shape, match) for admitted calls, in line order.
        self.calls = []
        # (lineno, stripped line, raw line) for every body line, in
        # line order; the dataflow check re-reads definitions here.
        self.body = []
        # Reserved declaration counts.
        self.decl_counts = {
            "lookup": 0,
            "update": 0,
            "delete": 0,
            "pid": 0,
            "ktime": 0,
            "cpu": 0,
            "output": 0,
            "reserve": 0,
            "submit": 0,
            "discard": 0,
            "coreread": 0,
            "coreexists": 0,
            "skbload": 0,
            "skbstore": 0,
        }
        self.counts = {name: 0 for name, _ in ASM_SHAPES}
        # Key-slot SSA name -> key literal (keyslot 0, keyslot1 1,
        # keyslotN its group-2 literal).
        self.key_of = {}
        self.mode = "classifier"
        # Count family: "classifier", "map" (one or more
        # read-modify-write pairs), "combined", "delete",
        # "tracepoint" (filter read plus one count pair),
        # "event" (filter read, sequence/success/failure pairs,
        # plus the output call), "reserve" (the event shape with
        # one reservation call, reservation-relative stores, and
        # one terminus), "subprog" (the classifier vector plus
        # one subprogram definition with at least one call site),
        # or "core" (one lookup, one relocated field read, one
        # existence check), or "skb" (one skb helper call plus its
        # key slot). Map families share mode "map"; the
        # tracepoint, event, reserve, subprog, core, and skb
        # families own their modes.
        self.family = "classifier"
        # True once _check_cfg admits at least one bounded loop
        # anywhere in the module.
        self.has_bounded_loop = False
        # skb variant for the skb family: "load" (helper 26),
        # "store" (helper 9), or "loadmap" (helper 26 plus one
        # map update); empty for every other family. The
        # kernel admits store only on TC, never on socket
        # filter, so the entry rule gates the store variant
        # to tc_entry.
        self.skb_kind = ""
        # Map entry count the validated shape covers (dense keys
        # 0..entries-1); 0 for the classifier, 1 for the core
        # relocation probe (its single lookup covers key 0).
        self.entries = 0
        # Whether kind tags mark this program per-CPU.
        self.percpu = False
        # Whether hash tags mark this program hash (never set
        # together with percpu: one program defines one map of one
        # kind).
        self.hashkind = False
        # Whether LRU tags mark this program LRU (never set
        # together with percpu or hashkind: one program defines
        # one map of one kind).
        self.lrukind = False
        # Ring-buffer size in bytes from the size tag (event
        # and reserve families only; None until the tag line is
        # scanned).
        self.ring_size = None
        # Subprogram (BPF-to-BPF call) shape, empty without one.
        # ``wanted_callee`` is the pre-scan's callee candidate (the
        # first callee-spelled definition); ``callee`` is the
        # routed definition's name, ``callee_define`` its exact
        # header line (the adapter asserts it passes through
        # untouched), and ``callee_order`` is "before" when the
        # callee is defined first, "after" otherwise. SSA names
        # are scoped per function, so the callee carries its own
        # parameters, definitions, uses, labels, and body lines;
        # ``subprog_calls`` holds (lineno, match) for the
        # entrypoint's call sites, and ``attr_sets`` maps
        # attribute-group indices to whether the set carries the
        # noinline marker.
        self.wanted_callee = ""
        self.callee = ""
        self.callee_define = ""
        self.callee_define_lineno = 0
        self.callee_order = ""
        self.callee_params = []
        self.callee_defs = {}
        self.callee_uses = {}
        self.callee_labels = set()
        self.callee_body = []
        self.subprog_calls = []
        self.attr_sets = {}


def _record_def(program, name, lineno, raw):
    if name in program.defs:
        raise AuditError(
            CODE_EXTERNAL,
            "SSA value %%%s redefined (first at %s): %r"
            % (name, _at(program.defs[name]), raw.strip()),
            location=_at(lineno),
            remedy="use single-assignment values only",
        )
    program.defs[name] = lineno


def _record_uses(program, names, lineno):
    for name in names:
        program.uses.setdefault(name, []).append(lineno)


def _record_callee_def(program, name, lineno, raw):
    if name in program.callee_defs:
        raise AuditError(
            CODE_EXTERNAL,
            "SSA value %%%s redefined (first at %s): %r"
            % (name, _at(program.callee_defs[name]), raw.strip()),
            location=_at(lineno),
            remedy="use single-assignment values only",
        )
    program.callee_defs[name] = lineno


def _record_callee_uses(program, names, lineno):
    for name in names:
        program.callee_uses.setdefault(name, []).append(lineno)


def _prescan_callee(text):
    """Return the first callee-spelled definition name, or "".

    This structural pre-pass reads only ``define`` headers so the
    main scan can route bodies, admit the second attribute group,
    and match call sites against the known callee in either
    definition order. It claims nothing: entrypoint symbols,
    reserved helper names, and ``llvm.`` spellings are never
    callees, and every enforcement stays in the main scan.
    """
    for raw in text.splitlines():
        line = strip_comment(raw).strip()
        if not line.startswith("define "):
            continue
        match = CALLEE_DEFINE_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        if name in ENTRY_SYMBOLS:
            continue
        if name in RESERVED_NAMES:
            continue
        if name.startswith("llvm."):
            continue
        return name
    return ""


def ssa_operands(line):
    """SSA names used by a line (labels and strings excluded)."""
    text = QUOTED_STRING_RE.sub('""', line)
    text = LABEL_USE_RE.sub("label ", text)
    match = SSA_DEF_RE.match(text)
    if match:
        text = text[match.end():]
    return SSA_USE_RE.findall(text)


def check_vector_spelling(line, lineno, raw):
    """Reject every vector type but one-lane integer vectors."""
    for scalable, lanes, element in VECTOR_TYPE_RE.findall(line):
        if scalable:
            raise AuditError(
                CODE_NUMERIC,
                "scalable vector type is not supported: %r"
                % (raw.strip(),),
                location=_at(lineno),
                remedy="use fixed-width integer scalars only",
            )
        if lanes != "1" or element not in ALLOWED_ONELANE_ELEMENTS:
            raise AuditError(
                CODE_NUMERIC,
                "only one-lane integer vectors may appear; found "
                "<%s x %s>: %r" % (lanes, element, raw.strip()),
                location=_at(lineno),
                remedy="use fixed-width integer scalars only",
            )


# Opcodes admitted on non-call body lines: exactly the union
# observed across the 61 validating genuine emissions covering
# all 9 modes plus the one validating .ll fixture (onelane
# one-lane-vector element ops; WP-2 Task 2 corpus scans).
# `call` is deliberately absent: call lines carry their own
# shape gate, and a leaked one must fail closed here rather
# than pass as "call".
ALLOWED_BODY_OPCODES = frozenset(
    [
        "add", "and", "ashr", "br", "extractelement",
        "getelementptr", "icmp", "insertelement", "load",
        "lshr", "mul", "or", "phi", "ret", "select", "shl",
        "store", "sub", "trunc", "xor", "zext",
    ]
)


def _body_opcode(line):
    """First opcode word of a non-call body line (SSA def stripped)."""
    text = line
    if SSA_DEF_RE.match(text):
        text = text.split("=", 1)[1]
    words = text.strip().split(None, 1)
    return words[0] if words else ""


# Bare words allowed after a body line's first opcode (R1
# finding 1): LLVM accepts several instructions on one
# physical line, while counts, CFG, and lowering all model
# one instruction per line. Any other bare word starts (or
# belongs to) a second, unmodeled instruction and fails
# closed here. LLVM instruction opcodes are deliberately
# absent, as are unmodeled qualifiers (atomic/volatile die
# under MBPF322 first); new LLVM syntax fails closed here
# loudly (via the corpus) instead of slipping past. Words
# below carry their emitting construct; extend only with a
# cited justification, never to quiet a failure.
BODY_TAIL_WORDS = frozenset(
    [
        # Types: every memory and scalar operand.
        "ptr",
        "void",
        "label",
        # Operand keywords: casts (to), alignment, overflow
        # and exactness flags, bounds checks.
        "to",
        "align",
        "nsw",
        "nuw",
        "exact",
        "inbounds",
        # icmp predicates (the only comparison in the subset).
        "eq",
        "ne",
        "ugt",
        "uge",
        "ult",
        "ule",
        "sgt",
        "sge",
        "slt",
        "sle",
        # Constant spellings (zeroinitializer: one-lane vector
        # operands, e.g. insertelement <1 x i64>
        # zeroinitializer, ...).
        "true",
        "false",
        "null",
        "zeroinitializer",
        # Vector-type element separator: <4 x i32>.
        "x",
    ]
)
BODY_INT_TYPE_RE = re.compile(r"^i\d+$")
BODY_VALUE_RE = re.compile(r"%[\w$.-]+")
BODY_NUMBER_RE = re.compile(
    r"(?<![\w$.])-?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d*)?"
    r"(?:[eE][+-]?\d+)?)"
)
BODY_WORD_RE = re.compile(r"[A-Za-z][\w$.]*")
BODY_SECOND_DEF_RE = re.compile(r"%[\w$.-]+\s*=")
# Constant-expression heads (folded inline operands such as ptr
# getelementptr (...)): unmodeled operand forms, rejected with
# their own message below. (ptrtoint/inttoptr/addrspace
# normally die under the CODE_POISON denylist first; listing
# them here keeps the attribution if they ever reach this far.)
BODY_CONSTEXPR_HEADS = frozenset(
    [
        "getelementptr",
        "bitcast",
        "trunc",
        "zext",
        "sext",
        "fptrunc",
        "fpext",
        "fptoui",
        "fptosi",
        "uitofp",
        "sitofp",
        "ptrtoint",
        "inttoptr",
        "addrspacecast",
        "icmp",
        "fcmp",
        "select",
    ]
)


def _reject_trailing_instruction(line, opcode, lineno, raw):
    """Reject a second instruction on one line (MBPF321).

    Runs after the head opcode cleared the allowlist: the
    line holds one modeled instruction plus trailing text.
    A second SSA definition proves a second instruction; any
    other bare word outside the operand vocabulary starts (or
    belongs to) one, except folded constant expressions
    (word followed by a parenthesis), which are unmodeled
    operand forms with their own message. Malformed-but-
    in-vocabulary lines still die downstream at in-lane LLVM
    verification.
    """
    text = line
    leading = SSA_DEF_RE.match(text)
    if leading:
        text = text[leading.end():]
    found = BODY_SECOND_DEF_RE.search(text)
    if found:
        second = _body_opcode(text[found.end():]) or "<unparseable>"
        raise AuditError(
            CODE_OPCODE,
            "second instruction %r on one line is outside the "
            "audited opcode subset: %r" % (second, raw.strip()),
            location=_at(lineno),
            remedy="keep one instruction per line",
        )
    words = text.strip().split(None, 1)
    rest = words[1] if len(words) > 1 else ""
    scrubbed = BODY_VALUE_RE.sub(" ", rest)
    scrubbed = BODY_NUMBER_RE.sub(" ", scrubbed)
    for matched in BODY_WORD_RE.finditer(scrubbed):
        word = matched.group(0)
        if word in BODY_TAIL_WORDS or BODY_INT_TYPE_RE.match(word):
            continue
        after = scrubbed[matched.end():]
        if word in BODY_CONSTEXPR_HEADS and re.match(r"\s*\(", after):
            raise AuditError(
                CODE_OPCODE,
                "constant expression %r is outside the audited "
                "opcode subset: %r" % (word, raw.strip()),
                location=_at(lineno),
                remedy="use plain value operands",
            )
        raise AuditError(
            CODE_OPCODE,
            "word %r after the %r instruction is outside the "
            "audited opcode subset: %r"
            % (word, opcode, raw.strip()),
            location=_at(lineno),
            remedy="keep one instruction per line",
        )


def check_body_line(line, lineno, raw):
    """Reject prohibited constructs on one non-call body line."""
    for reserved in RESERVED_NAMES:
        if reserved in line:
            raise AuditError(
                CODE_PSEUDO,
                "reserved helper name used outside a direct call to "
                "its declaration (address-taking is forbidden): %r"
                % (raw.strip(),),
                location=_at(lineno),
                remedy="use the SDK helper wrappers unchanged",
            )
    check_vector_spelling(line, lineno, raw)
    for pattern, code, label in FORBIDDEN_BODY:
        found = pattern.search(line)
        if found:
            raise AuditError(
                code,
                "%s %r is not in the audited subset: %r"
                % (label, found.group(0), raw.strip()),
                location=_at(lineno),
                remedy=_remedy_for(code),
            )
    bare = line
    leading = SSA_DEF_RE.match(bare)
    if leading:
        bare = bare[leading.end():].strip()
    qualified = re.match(r"(load|store)\s+(atomic|volatile)\b", bare)
    if qualified:
        raise AuditError(
            CODE_ATOMIC,
            "%s %s is not in the audited subset (memory "
            "orderings are unqualified): %r"
            % (qualified.group(2), qualified.group(1), raw.strip()),
            location=_at(lineno),
            remedy=_remedy_for(CODE_ATOMIC),
        )
    if "asm" in line:
        raise AuditError(
            CODE_EXTERNAL,
            "inline assembly outside the known call shapes is not "
            "allowed: %r" % (raw.strip(),),
            location=_at(lineno),
            remedy=_remedy_for(CODE_EXTERNAL),
        )
    if '%"' in line:
        raise AuditError(
            CODE_EXTERNAL,
            "quoted SSA names are not in the audited subset: %r"
            % (raw.strip(),),
            location=_at(lineno),
            remedy="use plain numeric SSA values as emitted",
        )
    opcode = _body_opcode(line)
    if opcode not in ALLOWED_BODY_OPCODES:
        raise AuditError(
            CODE_OPCODE,
            "instruction %r is outside the audited opcode subset: %r"
            % (opcode if opcode else "<unparseable>", raw.strip()),
            location=_at(lineno),
            remedy="use only the audited instruction subset",
        )
    _reject_trailing_instruction(line, opcode, lineno, raw)


# Textual mirror of Audit.cpp orderedBlocks plus the Lane-A bounded-loop
# extension. The parsed lane admits a no-loop slice; Lane-A's frozen
# shapes include bounded loops (constant trip counts and header exit
# tests against loop-invariant bounds), so each CFG cycle needs a
# checkable trip-bound proof instead of outright rejection. The block
# cap and budget match TargetModel.h (MaxBlocks, DefaultAnalysisBudget);
# exhaustion fails closed with the same messages. This structural proof
# is not a termination proof; the kernel verifier remains the backstop.
CFG_MAX_BLOCKS = 128
CFG_ANALYSIS_BUDGET = 65536
CFG_LABEL_RE = re.compile(r"^([\w$.-]+):$")
CFG_EDGE_RE = re.compile(r"label\s+%([\w$.-]+)")
CFG_DEF_RE = re.compile(r"^%([\w$.-]+)\s*=")
CFG_PHI_RE = re.compile(r"^%([\w$.-]+)\s*=\s*phi\s+")
CFG_ICMP_RE = re.compile(r"^%\S+\s*=\s*icmp\s+\w+\s+i\d+\s+(\S+),\s*(\S+)$")
CFG_CONDBR_RE = re.compile(
    r"^br\s+i1\s+(%[\w$.-]+),\s*label\s+%([\w$.-]+),"
    r"\s*label\s+%([\w$.-]+)"
)
CFG_PHI_PAIR_RE = re.compile(r"\[\s*(\S+),\s*%([\w$.-]+)\s*\]")
CFG_CONST_RE = re.compile(r"^(-?\d+|true|false|null)$")
CFG_DEFINE_NAME_RE = re.compile(r"@([\w$.-]+)\(")
# Opcodes ending a block for CFG purposes. Lines after a block's first
# terminator are malformed IR (a block holds exactly one terminator, at
# its end); they contribute no CFG edges or definitions here, and the
# in-lane LLVM verification (Task 4) rejects their module outright.
CFG_TERMINATORS = frozenset(
    [
        "br",
        "switch",
        "indirectbr",
        "invoke",
        "callbr",
        "ret",
        "unreachable",
        "resume",
        "cleanupret",
        "catchret",
        "catchswitch",
    ]
)


class _CfgBudget(object):
    """Spend-down budget mirroring Audit.cpp's Budget struct."""

    def __init__(self, remaining):
        self.remaining = remaining

    def spend(self):
        if not self.remaining:
            return False
        self.remaining -= 1
        return True


def _function_segments(text):
    """Yield (name, define_lineno, define_line, body) per definition.

    Body entries are (lineno, stripped-line) pairs; comments, blank
    lines, and metadata lines are dropped like the main scan.
    """
    name = None
    define_lineno = 0
    define_line = ""
    body = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = strip_comment(raw).strip()
        if line.startswith("define "):
            matched = CFG_DEFINE_NAME_RE.search(line)
            name = matched.group(1) if matched else "?"
            define_lineno = lineno
            define_line = line
            body = []
        elif name is not None:
            if line == "}":
                yield (name, define_lineno, define_line, body)
                name = None
            elif line and not line.startswith("!"):
                body.append((lineno, line))


def _cfg_blocks(body):
    """Split one body into blocks; leading lines form block zero."""
    blocks = [
        {"label": None, "lineno": 0, "lines": [], "terminated": False}
    ]
    for lineno, line in body:
        matched = CFG_LABEL_RE.match(line)
        if matched:
            blocks.append(
                {
                    "label": matched.group(1),
                    "lineno": lineno,
                    "lines": [],
                    "terminated": False,
                }
            )
        elif not blocks[-1]["terminated"]:
            blocks[-1]["lines"].append((lineno, line))
            if _body_opcode(line) in CFG_TERMINATORS:
                blocks[-1]["terminated"] = True
    if not blocks[0]["lines"] and len(blocks) > 1:
        blocks.pop(0)
    return blocks


def _block_lineno(block):
    """Best IR line for a block: its label, else its first line."""
    if block["lineno"]:
        return block["lineno"]
    if block["lines"]:
        return block["lines"][0][0]
    return None


def _loop_has_trip_proof(header, loop, def_block, reachable,
                         label_to_block, successors, blocks,
                         latch):
    """True when the header proves a trip bound for its loop.

    One fully valid (comparison, exit, recurrence) triple
    proves the bound; anything less fails closed. The
    comparison is a scalar-integer icmp of a header phi (the
    induction variable) against a constant or a value defined
    outside the loop in reachable code (function parameters
    count as outside). The comparison must feed a conditional
    branch in the loop with exactly one successor inside the
    loop and one exit: a successor outside the loop that
    cannot reach back into it (a dead comparison proves
    nothing, and neither does a branch that rejoins the
    cycle; genuine emission tests the header comparison from
    a following block, so the branch need not sit in the
    header itself). The test block must dominate the latch,
    so the test covers every backedge traversal. The compared
    phi's loop-edge values must be loop-defined and advance
    (never the phi itself, a pinned constant, or a
    loop-external value). Nesting is rejected separately by
    the caller; stride, direction, and polarity stay unproved:
    this structural proof is not a termination proof, and the
    kernel verifier remains the backstop.
    """
    phis = {}
    for _, line in header["lines"]:
        matched = CFG_PHI_RE.match(line)
        if matched:
            phis["%" + matched.group(1)] = CFG_PHI_PAIR_RE.findall(
                line
            )
    if not phis:
        return False
    loop_labels = {
        label
        for label, index in label_to_block.items()
        if index in loop
    }
    for _, line in header["lines"]:
        matched = CFG_ICMP_RE.match(line)
        if not matched:
            continue
        defined = CFG_DEF_RE.match(line)
        if not defined:
            continue
        name = "%" + defined.group(1)
        operands = (matched.group(1), matched.group(2))
        if operands[0] not in phis and operands[1] not in phis:
            continue
        phi = operands[0] if operands[0] in phis else operands[1]
        other = operands[1] if phi == operands[0] else operands[0]
        if CFG_CONST_RE.match(other):
            bound_ok = True
        elif not other.startswith("%"):
            continue
        else:
            home = def_block.get(other)
            bound_ok = home == -1 or (
                home in reachable and home not in loop
            )
        if not bound_ok:
            continue
        if not _icmp_feeds_loop_exit(
            blocks, loop, name, label_to_block, successors, latch
        ):
            continue
        if _phi_recurrence_advances(
            phi, phis[phi], loop, loop_labels, def_block
        ):
            return True
    return False


def _icmp_feeds_loop_exit(blocks, loop, name, label_to_block,
                           successors, latch):
    """True when a loop condbr tests the comparison to an exit.

    Exactly one successor continues the loop; the other must
    leave it without re-entering (a branch back into the cycle
    is a second latch, not an exit). The test block must also
    dominate the latch, so the test covers every backedge
    traversal — a bypassable test never runs. The walks visit
    reachable blocks only, already capped at CFG_MAX_BLOCKS,
    so they need no separate budget.
    """
    for index in sorted(loop):
        for _, line in blocks[index]["lines"]:
            cond = CFG_CONDBR_RE.match(line)
            if cond is None or cond.group(1) != name:
                continue
            targets = [
                label_to_block.get(cond.group(2)),
                label_to_block.get(cond.group(3)),
            ]
            inside = [found for found in targets if found in loop]
            if len(inside) != 1:
                continue
            if not _dominates(successors, 0, index, latch):
                continue
            for found in targets:
                if (
                    found is not None
                    and found not in loop
                    and not _reaches_loop(successors, found, loop)
                ):
                    return True
    return False


def _reaches_loop(successors, start, loop):
    """True when the block reaches the loop through successors."""
    seen = set()
    work = [start]
    while work:
        current = work.pop()
        if current in seen:
            continue
        seen.add(current)
        if current in loop:
            return True
        work.extend(successors.get(current, ()))
    return False


def _dominates(successors, entry, node, target):
    """True when every entry->target path passes through node.

    Decided by removal: the target must be unreachable from
    the entry once the node is gone. Visits reachable blocks
    only (entry-rooted, already capped at CFG_MAX_BLOCKS).
    """
    if node == target:
        return True
    seen = set()
    work = [entry]
    while work:
        current = work.pop()
        if current in seen or current == node:
            continue
        seen.add(current)
        if current == target:
            return False
        work.extend(successors.get(current, ()))
    return True


def _phi_recurrence_advances(phi, pairs, loop, loop_labels,
                             def_block):
    """True when the phi's loop-edge values advance in the loop.

    Init edges (outside the loop, or naming labels the CFG
    cannot resolve) are unconstrained; malformed labels die
    downstream at in-lane LLVM verification. Every loop-edge
    value must be defined inside the loop and differ from the
    phi itself: self-fed, pinned-constant, and loop-external
    recurrences are unproved.
    """
    for value, label in pairs:
        if label not in loop_labels:
            continue
        if value == phi:
            return False
        if not value.startswith("%"):
            return False
        if def_block.get(value) not in loop:
            return False
    return True


def _check_cfg_function(name, define_line, body):
    """Reject unbounded cycles and over-budget CFGs in one body."""
    budget = _CfgBudget(CFG_ANALYSIS_BUDGET)
    blocks = _cfg_blocks(body)
    label_to_block = {}
    for index, block in enumerate(blocks):
        if block["label"] is not None:
            label_to_block.setdefault(block["label"], index)
    successors = {}
    predecessors = {}
    for index, block in enumerate(blocks):
        successors[index] = []
        for _, line in block["lines"]:
            for target in CFG_EDGE_RE.findall(line):
                found = label_to_block.get(target)
                # Edges to undefined labels are malformed IR; the
                # in-lane LLVM verification (Task 4) owns that shape.
                # Skipping them cannot hide a cycle among defined
                # blocks, which is all this check reasons about.
                if found is not None and found not in successors[index]:
                    successors[index].append(found)
    for index in successors:
        predecessors[index] = []
    for index, nexts in successors.items():
        for found in nexts:
            predecessors[found].append(index)
    def_block = {}
    for param in SSA_USE_RE.findall(
        define_line.split("(", 1)[1].rsplit(")", 1)[0]
    ):
        def_block[param] = -1
    for index, block in enumerate(blocks):
        for _, line in block["lines"]:
            matched = CFG_DEF_RE.match(line)
            if matched:
                def_block.setdefault("%" + matched.group(1), index)
    reachable = set()
    pending = [0]
    while pending:
        if not budget.spend():
            raise AuditError(
                CODE_BUDGET,
                "CFG analysis budget exhausted",
                location=None,
                remedy="shrink the program so its CFG fits the budget",
            )
        current = pending.pop()
        if current in reachable:
            continue
        reachable.add(current)
        if len(reachable) > CFG_MAX_BLOCKS:
            culprit = _block_lineno(blocks[current])
            raise AuditError(
                CODE_BUDGET,
                "CFG block limit exhausted",
                location=_at(culprit) if culprit else None,
                remedy="shrink the program to %d reachable blocks"
                % CFG_MAX_BLOCKS,
            )
        pending.extend(successors[current])
    remaining_preds = {}
    for index in reachable:
        remaining_preds[index] = sum(
            1 for pred in predecessors[index] if pred in reachable
        )
    ready = [
        index for index in reachable if not remaining_preds[index]
    ]
    ordered = []
    while ready:
        if not budget.spend():
            raise AuditError(
                CODE_BUDGET,
                "CFG ordering budget exhausted",
                location=None,
                remedy="shrink the program so its CFG fits the budget",
            )
        current = ready.pop()
        ordered.append(current)
        for found in successors[current]:
            if found in reachable:
                remaining_preds[found] -= 1
                if not remaining_preds[found]:
                    ready.append(found)
    if len(ordered) == len(reachable):
        return False
    cyclic = reachable - set(ordered)
    white, gray, black = 0, 1, 2
    color = {index: white for index in reachable}
    back_edges = []
    color[0] = gray
    stack = [(0, iter(successors[0]))]
    while stack:
        node, edges = stack[-1]
        child = None
        for candidate in edges:
            if not budget.spend():
                raise AuditError(
                    CODE_BUDGET,
                    "CFG analysis budget exhausted",
                    location=None,
                    remedy=(
                        "shrink the program so its CFG fits the budget"
                    ),
                )
            if color[candidate] == gray:
                back_edges.append((node, candidate))
            elif color[candidate] == white:
                child = candidate
                break
        if child is None:
            color[node] = black
            stack.pop()
        else:
            color[child] = gray
            stack.append((child, iter(successors[child])))
    if not back_edges:
        # Unreachable by construction (every directed cycle holds a
        # depth-first back edge); fail closed if it ever happens.
        raise AuditError(
            CODE_CYCLE,
            "cyclic CFG is outside the admitted bounded-loop slice",
            location=None,
            remedy=(
                "use only bounded loops with a header trip test "
                "against a constant or loop-invariant bound"
            ),
        )
    proven = []
    for source, header_index in back_edges:
        if header_index not in cyclic:
            continue
        loop = {header_index}
        work = [source]
        while work:
            current = work.pop()
            if current in loop:
                continue
            if not budget.spend():
                raise AuditError(
                    CODE_BUDGET,
                    "CFG analysis budget exhausted",
                    location=None,
                    remedy=(
                        "shrink the program so its CFG fits the budget"
                    ),
                )
            loop.add(current)
            work.extend(
                pred
                for pred in predecessors[current]
                if pred in reachable
            )
        header = blocks[header_index]
        for prior_header, prior_loop in proven:
            if prior_header == header_index:
                continue
            if header_index in prior_loop or prior_header in loop:
                label = header["label"] or "<entry>"
                culprit = _block_lineno(header)
                raise AuditError(
                    CODE_CYCLE,
                    "nested CFG cycle at header %%%s in @%s: the "
                    "admitted slice allows only single-level "
                    "bounded loops" % (label, name),
                    location=_at(culprit) if culprit else None,
                    remedy="flatten nested loops into sequential loops",
                )
        if _loop_has_trip_proof(
            header, loop, def_block, reachable, label_to_block,
            successors, blocks, source,
        ):
            proven.append((header_index, loop))
            continue
        label = header["label"] or "<entry>"
        culprit = _block_lineno(header)
        raise AuditError(
            CODE_CYCLE,
            "unbounded CFG cycle at header %%%s in @%s: no header "
            "trip-bound proof; the admitted slice allows only "
            "bounded loops (a header icmp of a header phi against "
            "a constant or loop-invariant bound, tested by a loop "
            "exit branch that leaves the loop, with loop-advancing "
            "recurrence)"
            % (label, name),
            location=_at(culprit) if culprit else None,
            remedy=(
                "give every loop a header trip test (an icmp of a "
                "header phi against a constant or loop-invariant "
                "bound) tested by a loop exit branch that leaves "
                "the loop"
            ),
        )
    return True


def _check_cfg(text):
    """Run the CFG check over every defined function body.

    Returns True when at least one admitted bounded loop was
    found (unbounded cycles raise before any return).
    """
    found = False
    for name, _, define_line, body in _function_segments(text):
        found = _check_cfg_function(name, define_line, body) or found
    return found


def _remedy_for(code):
    if code == CODE_EXTERNAL:
        return (
            "use only the reviewed SDK wrappers; the rejection "
            "names the first unexpected call"
        )
    if code == CODE_RUNTIME:
        return (
            "remove runtime, allocator, unwinding, TLS, "
            "constructor, and intrinsic use from the reachable graph"
        )
    if code == CODE_NUMERIC:
        return "use fixed-width integer scalars only"
    if code == CODE_STACK:
        return (
            "keep no LLVM-managed frame objects; use the audited "
            "slot shapes for key and value storage"
        )
    if code == CODE_POISON:
        return (
            "initialize every value and keep pointers typed; only "
            "the adapter introduces the lowered helper callee form"
        )
    if code == CODE_PTRSTORE:
        return (
            "store only loaded values and computed scalars; never "
            "store a lookup result, a value derived from one, or a "
            "pointer"
        )
    if code == CODE_ATOMIC:
        return "use plain non-atomic, non-volatile loads and stores"
    return "stay inside the audited program subset"


HELPER_ASM_RE = re.compile(r'asm\s+sideeffect\s+"call \d+"')


def diagnose_pseudo_call(line, lineno, raw, kind):
    """Classify a malformed reserved helper call (never returns)."""
    head = line.split("@__mojobpf_", 1)[0]
    if "[" in line or "]" in line:
        raise AuditError(
            CODE_PSEUDO,
            "reserved helper call must not carry operand bundles: "
            "%r" % (raw.strip(),),
            location=_at(lineno),
            remedy=(
                "keep helper calls plain, with conservative "
                "effects and no bundles"
            ),
        )
    if re.search(r"\b(tail|musttail|notail)\b", head):
        raise AuditError(
            CODE_PSEUDO,
            "reserved helper call must be a plain call, without "
            "tail markers: %r" % (raw.strip(),),
            location=_at(lineno),
            remedy="call the SDK helper wrappers without modifiers",
        )
    if re.search(
        r"\b(ccc|fastcc|coldcc|cc \d+|nounwind|readonly|readnone|"
        r"willreturn|nofree|nosync|speculatable|memory|returned|"
        r"inreg|signext|zeroext|align|dereferenceable)\b",
        head + line.rsplit(")", 1)[-1],
    ):
        raise AuditError(
            CODE_PSEUDO,
            "reserved helper call carries attributes or a "
            "calling convention it must not have: %r"
            % (raw.strip(),),
            location=_at(lineno),
            remedy=(
                "keep helper calls plain, with conservative "
                "effects and no bundles"
            ),
        )
    try:
        args = line.split("(", 1)[1].rsplit(")", 1)[0]
    except IndexError:
        args = ""
    parts = [part.strip() for part in args.split(",")]
    if kind == "lookup":
        _diagnose_map_key_call(
            line, lineno, raw, "lookup", parts,
            "use the SDK lookup wrapper unchanged",
        )
    elif kind == "delete":
        _diagnose_map_key_call(
            line, lineno, raw, "delete", parts,
            "use the SDK delete wrapper unchanged",
        )
    elif kind in ("pid", "ktime", "cpu"):
        _diagnose_nullary_call(line, lineno, raw, kind, parts)
    elif kind == "output":
        _diagnose_output_call(line, lineno, raw, parts)
    elif kind == "reserve":
        _diagnose_reserve_call(line, lineno, raw, parts)
    elif kind in ("submit", "discard"):
        _diagnose_terminus_call(line, lineno, raw, kind, parts)
    else:
        if len(parts) != 4:
            raise AuditError(
                CODE_OPERANDS,
                "update helper call takes (i64 map, ptr key, ptr "
                "value, i64 flags), got %d operand(s): %r"
                % (len(parts), raw.strip()),
                location=_at(lineno),
                remedy="use the SDK update wrapper unchanged",
            )
        if not parts[0].startswith("i64 %"):
            if parts[0].startswith("i64 "):
                raise AuditError(
                    CODE_MAP_SHAPE,
                    "update map address must be loaded from the map "
                    "metadata section, not a constant: %r"
                    % (raw.strip(),),
                    location=_at(lineno),
                    remedy="load the map address from its metadata",
                )
            raise AuditError(
                CODE_OPERANDS,
                "update map operand must be an i64 SSA value: %r"
                % (raw.strip(),),
                location=_at(lineno),
                remedy="use the SDK update wrapper unchanged",
            )
        if not re.match(r"^ptr\s+%\S+$", parts[1]):
            raise AuditError(
                CODE_OPERANDS,
                "update key operand must be a ptr SSA value: %r"
                % (raw.strip(),),
                location=_at(lineno),
                remedy="use the SDK update wrapper unchanged",
            )
        if not re.match(r"^ptr\s+%\S+$", parts[2]):
            raise AuditError(
                CODE_OPERANDS,
                "update value operand must be a ptr SSA value: %r"
                % (raw.strip(),),
                location=_at(lineno),
                remedy="use the SDK update wrapper unchanged",
            )
        if parts[3] != "i64 0":
            raise AuditError(
                CODE_OPERANDS,
                "update flags must be the literal i64 0: %r"
                % (raw.strip(),),
                location=_at(lineno),
                remedy="pass flags 0 (the only qualified value)",
            )
    raise AuditError(
        CODE_PSEUDO,
        "reserved helper call deviates from its exact admitted "
        "shape: %r" % (raw.strip(),),
        location=_at(lineno),
        remedy="use the SDK helper wrappers unchanged",
    )


def diagnose_core_call(line, lineno, raw, kind):
    """Classify a malformed reserved relocation call (never returns)."""
    head = line.split("@__mojobpf_core_", 1)[0]
    if "[" in line or "]" in line:
        raise AuditError(
            CODE_PSEUDO,
            "reserved relocation call must not carry operand "
            "bundles: %r" % (raw.strip(),),
            location=_at(lineno),
            remedy=(
                "keep relocation calls plain, with conservative "
                "effects and no bundles"
            ),
        )
    if re.search(r"\b(tail|musttail|notail)\b", head):
        raise AuditError(
            CODE_PSEUDO,
            "reserved relocation call must be a plain call, without "
            "tail markers: %r" % (raw.strip(),),
            location=_at(lineno),
            remedy="call the SDK core wrappers without modifiers",
        )
    if re.search(
        r"\b(ccc|fastcc|coldcc|cc \d+|nounwind|readonly|readnone|"
        r"willreturn|nofree|nosync|speculatable|memory|returned|"
        r"inreg|signext|zeroext|align|dereferenceable)\b",
        head + line.rsplit(")", 1)[-1],
    ):
        raise AuditError(
            CODE_PSEUDO,
            "reserved relocation call carries attributes or a "
            "calling convention it must not have: %r"
            % (raw.strip(),),
            location=_at(lineno),
            remedy=(
                "keep relocation calls plain, with conservative "
                "effects and no bundles"
            ),
        )
    if not re.match(r"^%\S+\s*=\s*call\s+i32\s+@", line):
        raise AuditError(
            CODE_OPERANDS,
            "reserved relocation call must return i32 into an SSA "
            "value: %r" % (raw.strip(),),
            location=_at(lineno),
            remedy="use the SDK core wrappers unchanged",
        )
    try:
        args = line.split("(", 1)[1].rsplit(")", 1)[0]
    except IndexError:
        args = ""
    parts = [part.strip() for part in args.split(",")]
    if kind == "coreexists":
        if parts != [""]:
            raise AuditError(
                CODE_OPERANDS,
                "existence check takes no operands, got %d: %r"
                % (len(parts), raw.strip()),
                location=_at(lineno),
                remedy="use the SDK core wrappers unchanged",
            )
    else:
        if len(parts) != 1 or not re.match(r"^ptr\s+%\S+$", parts[0]):
            raise AuditError(
                CODE_OPERANDS,
                "relocation read takes one ptr SSA operand, got %r: "
                "%r" % (args.strip(), raw.strip()),
                location=_at(lineno),
                remedy="use the SDK core wrappers unchanged",
            )
    raise AuditError(
        CODE_PSEUDO,
        "reserved relocation call deviates from its exact admitted "
        "shape: %r" % (raw.strip(),),
        location=_at(lineno),
        remedy="use the SDK core wrappers unchanged",
    )


def _diagnose_map_operand(part, lineno, raw, label):
    """Require a map-address SSA operand (never a constant)."""
    if not part.startswith("i64 %"):
        if part.startswith("i64 "):
            raise AuditError(
                CODE_MAP_SHAPE,
                "%s map address must be loaded from the map "
                "metadata section, not a constant: %r"
                % (label, raw.strip()),
                location=_at(lineno),
                remedy="load the map address from its metadata",
            )
        raise AuditError(
            CODE_OPERANDS,
            "%s map operand must be an i64 SSA value: %r"
            % (label, raw.strip()),
            location=_at(lineno),
            remedy="use the SDK %s wrapper unchanged" % label,
        )


def _diagnose_ptr_operand(part, lineno, raw, label, role, remedy):
    """Require a pointer SSA operand in one role."""
    if not re.match(r"^ptr\s+%\S+$", part):
        raise AuditError(
            CODE_OPERANDS,
            "%s %s operand must be a ptr SSA value: %r"
            % (label, role, raw.strip()),
            location=_at(lineno),
            remedy=remedy,
        )


def _diagnose_map_key_call(line, lineno, raw, kind, parts, remedy):
    """Classify a malformed (map, key) pseudo-call (never returns)."""
    del line
    if len(parts) != 2:
        raise AuditError(
            CODE_OPERANDS,
            "%s helper call takes (i64 map, ptr key), got "
            "%d operand(s): %r" % (kind, len(parts), raw.strip()),
            location=_at(lineno),
            remedy=remedy,
        )
    _diagnose_map_operand(parts[0], lineno, raw, kind)
    _diagnose_ptr_operand(parts[1], lineno, raw, kind, "key", remedy)


_NULLARY_REMEDIES = {
    "pid": "call the current-PID/TID helper without operands",
    "ktime": "call the monotonic-clock helper without operands",
    "cpu": "call the CPU-number helper without operands",
}


def _diagnose_nullary_call(line, lineno, raw, kind, parts):
    """Classify a malformed nullary pseudo-call (never returns)."""
    del line
    if parts != [""]:
        raise AuditError(
            CODE_OPERANDS,
            "%s helper call takes no operands, got %d "
            "operand(s): %r" % (kind, len(parts), raw.strip()),
            location=_at(lineno),
            remedy=_NULLARY_REMEDIES[kind],
        )


def _diagnose_output_call(line, lineno, raw, parts):
    """Classify a malformed copy-output pseudo-call (never returns)."""
    del line
    remedy = "use the SDK ring-buffer output wrapper unchanged"
    if len(parts) != 4:
        raise AuditError(
            CODE_OPERANDS,
            "output helper call takes (i64 map, ptr data, i64 "
            "size, i64 flags), got %d operand(s): %r"
            % (len(parts), raw.strip()),
            location=_at(lineno),
            remedy=remedy,
        )
    _diagnose_map_operand(parts[0], lineno, raw, "output")
    _diagnose_ptr_operand(parts[1], lineno, raw, "output", "data", remedy)
    if parts[2] != "i64 32":
        raise AuditError(
            CODE_OPERANDS,
            "output size must be the literal i64 32: %r"
            % (raw.strip(),),
            location=_at(lineno),
            remedy="emit exactly the 32-byte record",
        )
    if parts[3] != "i64 0":
        raise AuditError(
            CODE_OPERANDS,
            "output flags must be the literal i64 0: %r"
            % (raw.strip(),),
            location=_at(lineno),
            remedy="pass flags 0 (the only qualified value)",
        )


def _diagnose_reserve_call(line, lineno, raw, parts):
    """Classify a malformed reservation pseudo-call (never returns)."""
    del line
    remedy = "use the SDK ring-buffer reserve wrapper unchanged"
    if len(parts) != 3:
        raise AuditError(
            CODE_OPERANDS,
            "reserve helper call takes (i64 map, i64 size, i64 "
            "flags), got %d operand(s): %r"
            % (len(parts), raw.strip()),
            location=_at(lineno),
            remedy=remedy,
        )
    _diagnose_map_operand(parts[0], lineno, raw, "reserve")
    if parts[1] != "i64 32":
        raise AuditError(
            CODE_OPERANDS,
            "reserve size must be the literal i64 32: %r"
            % (raw.strip(),),
            location=_at(lineno),
            remedy="reserve exactly the 32-byte record",
        )
    if parts[2] != "i64 0":
        raise AuditError(
            CODE_OPERANDS,
            "reserve flags must be the literal i64 0: %r"
            % (raw.strip(),),
            location=_at(lineno),
            remedy="pass flags 0 (the only qualified value)",
        )


def _diagnose_terminus_call(line, lineno, raw, kind, parts):
    """Classify a malformed terminus pseudo-call (never returns)."""
    del line
    remedy = "use the SDK ring-buffer %s wrapper unchanged" % kind
    if len(parts) != 2:
        raise AuditError(
            CODE_OPERANDS,
            "%s helper call takes (ptr data, i64 flags), got "
            "%d operand(s): %r" % (kind, len(parts), raw.strip()),
            location=_at(lineno),
            remedy=remedy,
        )
    _diagnose_ptr_operand(parts[0], lineno, raw, kind, "data", remedy)
    if parts[1] != "i64 0":
        raise AuditError(
            CODE_OPERANDS,
            "%s flags must be the literal i64 0: %r"
            % (kind, raw.strip()),
            location=_at(lineno),
            remedy="pass flags 0 (the only qualified value)",
        )


def classify_call(line, lineno, raw):
    """Classify one call line: admitted shape or rejection.

    Returns (shape, match) for the six admitted shapes; any other
    call raises the AuditError naming its violated check.
    """
    for name, pattern in ASM_SHAPES:
        match = pattern.match(line)
        if match:
            return name, match
    erased = re.search(
        r"\b(ptrtoint|inttoptr|addrspace|poison|undef)\b", line
    )
    if erased:
        raise AuditError(
            CODE_POISON,
            "poison/undef, address space, or pointer/integer "
            "erasure %r is not in the audited subset: %r"
            % (erased.group(0), raw.strip()),
            location=_at(lineno),
            remedy=_remedy_for(CODE_POISON),
        )
    if "@" + LOOKUP_NAME in line:
        diagnose_pseudo_call(line, lineno, raw, "lookup")
    if "@" + UPDATE_NAME in line:
        diagnose_pseudo_call(line, lineno, raw, "update")
    if "@" + DELETE_NAME in line:
        diagnose_pseudo_call(line, lineno, raw, "delete")
    if "@" + PID_NAME in line:
        diagnose_pseudo_call(line, lineno, raw, "pid")
    if "@" + KTIME_NAME in line:
        diagnose_pseudo_call(line, lineno, raw, "ktime")
    if "@" + CPU_NAME in line:
        diagnose_pseudo_call(line, lineno, raw, "cpu")
    if "@" + OUTPUT_NAME in line:
        diagnose_pseudo_call(line, lineno, raw, "output")
    if "@" + RESERVE_NAME in line:
        diagnose_pseudo_call(line, lineno, raw, "reserve")
    if "@" + SUBMIT_NAME in line:
        diagnose_pseudo_call(line, lineno, raw, "submit")
    if "@" + DISCARD_NAME in line:
        diagnose_pseudo_call(line, lineno, raw, "discard")
    if "@" + COREREAD_NAME in line:
        diagnose_core_call(line, lineno, raw, "coreread")
    if "@" + COREEXISTS_NAME in line:
        diagnose_core_call(line, lineno, raw, "coreexists")
    for reserved in RESERVED_NAMES:
        if "@" + reserved in line or reserved in line:
            raise AuditError(
                CODE_PSEUDO,
                "reserved helper name used outside a direct call to "
                "its declaration (address-taking is forbidden): %r"
                % (raw.strip(),),
                location=_at(lineno),
                remedy="use the SDK helper wrappers unchanged",
            )
    direct = CALLEE_DIRECT_RE.search(line)
    if direct:
        callee = direct.group(1)
        if callee in ENTRY_SYMBOLS:
            raise AuditError(
                CODE_RECURSION,
                "the entrypoint must not call itself: %r"
                % (raw.strip(),),
                location=_at(lineno),
                remedy="keep the reachable graph free of recursion",
            )
        if callee.startswith("llvm."):
            raise AuditError(
                CODE_RUNTIME,
                "intrinsic call %r is not in the audited subset: %r"
                % (callee, raw.strip()),
                location=_at(lineno),
                remedy=_remedy_for(CODE_RUNTIME),
            )
        raise AuditError(
            CODE_EXTERNAL,
            "only the known call shapes are allowed; unexpected "
            "direct call to @%s: %r" % (callee, raw.strip()),
            location=_at(lineno),
            remedy=_remedy_for(CODE_EXTERNAL),
        )
    if "asm" in line:
        if HELPER_ASM_RE.search(line):
            raise AuditError(
                CODE_CALL_FORM,
                "helper invocations must use the reserved call "
                "form, never inline assembly: %r" % (raw.strip(),),
                location=_at(lineno),
                remedy="use the SDK helper wrappers unchanged",
            )
        raise AuditError(
            CODE_EXTERNAL,
            "only the known assembly shapes are allowed: %r"
            % (raw.strip(),),
            location=_at(lineno),
            remedy=_remedy_for(CODE_EXTERNAL),
        )
    if CALLEE_SSA_RE.search(line):
        raise AuditError(
            CODE_CALL_FORM,
            "indirect calls are not in the audited subset: %r"
            % (raw.strip(),),
            location=_at(lineno),
            remedy="use direct calls to the reviewed wrappers only",
        )
    raise AuditError(
        CODE_EXTERNAL,
        "only the known call shapes are allowed: %r" % (raw.strip(),),
        location=_at(lineno),
        remedy=_remedy_for(CODE_EXTERNAL),
    )


def _diagnose_subprog_call(line, lineno, raw, program):
    """Admit or refuse one direct call to the known subprogram.

    Returns the match for the exact admitted tail-call spelling;
    any other spelling of a call to the defined callee refuses
    with the call-form code (missing ``tail`` marker) or the
    operand code (arity, types, result, or operand form).
    """
    callee = program.wanted_callee
    match = SUBPROG_CALL_RE.match(line)
    if match and match.group(2) == callee:
        return match
    notail = SUBPROG_CALL_NOTAIL_RE.match(line)
    if notail and notail.group(2) == callee:
        raise AuditError(
            CODE_CALL_FORM,
            "subprogram calls must spell the tail-call marker: "
            "%r" % (raw.strip(),),
            location=_at(lineno),
            remedy=(
                "keep the single supported subprogram call shape "
                "(the frontend emits the tail-call marker)"
            ),
        )
    raise AuditError(
        CODE_OPERANDS,
        "subprogram call to @%s must spell exactly "
        "'%%R = tail call i64 @%s(i64 X)' with one i64 SSA value "
        "or decimal literal: %r" % (callee, callee, raw.strip()),
        location=_at(lineno),
        remedy=(
            "call the subprogram with exactly one 64-bit integer "
            "argument"
        ),
    )


def _refuse_callee_call(line, lineno, raw, program):
    """Refuse any call inside the subprogram body.

    The subprogram is pure scalar computation: a call to itself
    or back into the entrypoint is recursion, an intrinsic call
    or poison operand keeps its usual code, and anything else is
    an unexpected call in a body that admits none.
    """
    erased = re.search(
        r"\b(ptrtoint|inttoptr|addrspace|poison|undef)\b", line
    )
    if erased:
        raise AuditError(
            CODE_POISON,
            "poison/undef, address space, or pointer/integer "
            "erasure %r is not in the audited subset: %r"
            % (erased.group(0), raw.strip()),
            location=_at(lineno),
            remedy=_remedy_for(CODE_POISON),
        )
    direct = CALLEE_DIRECT_RE.search(line)
    if direct:
        name = direct.group(1)
        if name == program.callee:
            raise AuditError(
                CODE_RECURSION,
                "the subprogram @%s must not call itself: %r"
                % (name, raw.strip()),
                location=_at(lineno),
                remedy="keep the reachable graph free of recursion",
            )
        if name in ENTRY_SYMBOLS:
            raise AuditError(
                CODE_RECURSION,
                "the subprogram must not call back into the "
                "entrypoint @%s: %r" % (name, raw.strip()),
                location=_at(lineno),
                remedy="keep the reachable graph free of recursion",
            )
        if name.startswith("llvm."):
            raise AuditError(
                CODE_RUNTIME,
                "intrinsic call %r is not in the audited subset: %r"
                % (name, raw.strip()),
                location=_at(lineno),
                remedy=_remedy_for(CODE_RUNTIME),
            )
        raise AuditError(
            CODE_EXTERNAL,
            "the subprogram body admits no calls (no helper "
            "calls, no recursion, no calls into the entrypoint): "
            "%r" % (raw.strip(),),
            location=_at(lineno),
            remedy="keep the subprogram body free of calls",
        )
    if CALLEE_SSA_RE.search(line):
        raise AuditError(
            CODE_CALL_FORM,
            "indirect calls are not in the audited subset: %r"
            % (raw.strip(),),
            location=_at(lineno),
            remedy="keep the subprogram body free of calls",
        )
    raise AuditError(
        CODE_EXTERNAL,
        "the subprogram body admits no calls (no helper calls, "
        "no recursion, no calls into the entrypoint): %r"
        % (raw.strip(),),
        location=_at(lineno),
        remedy="keep the subprogram body free of calls",
    )


def _check_module_line(line, lineno, raw, program):
    """Classify one module-scope line (defines handled by scan)."""
    if not line.startswith("declare "):
        for reserved in RESERVED_NAMES:
            if reserved in line:
                raise AuditError(
                    CODE_PSEUDO,
                    "reserved helper name used outside its exact "
                    "declaration (definitions, aliases, and "
                    "address-taking are forbidden): %r"
                    % (raw.strip(),),
                    location=_at(lineno),
                    remedy="use the SDK helper wrappers unchanged",
                )
    if GLOBAL_RE.match(line):
        if "thread_local" in line or "threadlocal" in line:
            raise AuditError(
                CODE_RUNTIME,
                "thread-local storage is not in the audited "
                "subset: %r" % (raw.strip(),),
                location=_at(lineno),
                remedy=_remedy_for(CODE_RUNTIME),
            )
        raise AuditError(
            CODE_MODULE,
            "input must not define globals: %r" % (raw.strip(),),
            location=_at(lineno),
            remedy="keep all state in entrypoint-local values",
        )
    if line.startswith("declare "):
        for reserved, decl in (
            ("lookup", LOOKUP_DECL_LINE),
            ("update", UPDATE_DECL_LINE),
            ("delete", DELETE_DECL_LINE),
            ("pid", PID_DECL_LINE),
            ("ktime", KTIME_DECL_LINE),
            ("cpu", CPU_DECL_LINE),
            ("output", OUTPUT_DECL_LINE),
            ("reserve", RESERVE_DECL_LINE),
            ("submit", SUBMIT_DECL_LINE),
            ("discard", DISCARD_DECL_LINE),
            ("coreread", COREREAD_DECL_LINE),
            ("coreexists", COREEXISTS_DECL_LINE),
            ("skbload", SKBLOAD_DECL_LINE),
            ("skbstore", SKBSTORE_DECL_LINE),
        ):
            if line == decl:
                program.decl_counts[reserved] += 1
                return
        match = DECLARE_RE.match(line)
        if match and match.group(1) in RESERVED_NAMES:
            raise AuditError(
                CODE_PSEUDO,
                "reserved helper declaration deviates from its "
                "exact admitted signature: %r" % (raw.strip(),),
                location=_at(lineno),
                remedy="use the SDK helper wrappers unchanged",
            )
        if match and match.group(1).startswith("llvm."):
            raise AuditError(
                CODE_RUNTIME,
                "intrinsic declaration is not in the audited "
                "subset: %r" % (raw.strip(),),
                location=_at(lineno),
                remedy=_remedy_for(CODE_RUNTIME),
            )
        raise AuditError(
            CODE_EXTERNAL,
            "input must not declare externals: %r" % (raw.strip(),),
            location=_at(lineno),
            remedy=_remedy_for(CODE_EXTERNAL),
        )
    if line.startswith("module asm"):
        raise AuditError(
            CODE_MODULE,
            "module-level assembly is not allowed: %r"
            % (raw.strip(),),
            location=_at(lineno),
            remedy="keep the audited inline shapes only",
        )
    attrs = ATTRS_N_RE.match(line)
    if attrs is not None and program.wanted_callee:
        index = int(attrs.group(1))
        if index > 1:
            raise AuditError(
                CODE_MODULE,
                "unexpected module-scope syntax (only source_filename, "
                "target lines, attributes #0 and #1, and the reserved "
                "helper declarations allowed): %r" % (raw.strip(),),
                location=_at(lineno),
                remedy=(
                    "keep the module to one entrypoint, one "
                    "subprogram, plus metadata"
                ),
            )
        program.attr_sets[index] = (
            NOINLINE_MARK_RE.search(attrs.group(2)) is not None
        )
    if (
        SOURCE_FILENAME_RE.match(line)
        or TARGET_DATALAYOUT_RE.match(line)
        or TARGET_TRIPLE_RE.match(line)
        or ATTRS_ZERO_RE.match(line)
        or (attrs is not None and program.wanted_callee)
    ):
        check_vector_spelling(line, lineno, raw)
        for pattern, code, label in FORBIDDEN_BODY:
            found = pattern.search(line)
            if found:
                raise AuditError(
                    code,
                    "%s %r is not in the audited subset: %r"
                    % (label, found.group(0), raw.strip()),
                    location=_at(lineno),
                    remedy=_remedy_for(code),
                )
        return
    if program.wanted_callee:
        raise AuditError(
            CODE_MODULE,
            "unexpected module-scope syntax (only source_filename, "
            "target lines, attributes #0 and #1, and the reserved "
            "helper declarations allowed): %r" % (raw.strip(),),
            location=_at(lineno),
            remedy=(
                "keep the module to one entrypoint, one subprogram, "
                "plus metadata"
            ),
        )
    raise AuditError(
        CODE_MODULE,
        "unexpected module-scope syntax (only source_filename, "
        "target lines, attributes #0, and the reserved helper "
        "declarations allowed): %r" % (raw.strip(),),
        location=_at(lineno),
        remedy="keep the module to one entrypoint plus metadata",
    )


def scan(text):
    """Parse and audit raw frontend IR; return the program model.

    Raises AuditError naming the first violated check. Checks run in
    line order for structure and per-line behavior, then the CFG
    cycle/budget check, whole-body counts, the entry/family,
    tracepoint context, and uprobe context rules, helper
    and relocation operands, cross-call liveness, key freshness,
    undefined roots,
    and pointer-store dataflow. In the subprogram shape the scan
    additionally routes the one callee definition and its body
    (SSA names are scoped per function), admits the entrypoint's
    tail-call sites, and checks the subprogram wiring, roots, and
    purity after the shared checks.
    """
    program = Program()
    program.wanted_callee = _prescan_callee(text)
    defines = 0
    in_body = False
    in_callee = False
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = strip_comment(raw).strip()
        if not line or line.startswith("!"):
            continue
        if line.startswith("define "):
            if in_body:
                raise AuditError(
                    CODE_ENTRY,
                    "nested definition is not allowed: %r"
                    % (raw.strip(),),
                    location=_at(lineno),
                    remedy="emit exactly one entrypoint definition",
                )
            defines += 1
            for reserved in RESERVED_NAMES:
                if "@" + reserved + "(" in line:
                    raise AuditError(
                        CODE_PSEUDO,
                        "reserved helper names must never be defined: "
                        "%r" % (raw.strip(),),
                        location=_at(lineno),
                        remedy=(
                            "declare helpers only through the SDK "
                            "wrappers"
                        ),
                    )
            matched = DEFINE_RE.match(line)
            if not matched and program.wanted_callee:
                matched = ENTRY_DEFINE_SUBPROG_RE.match(line)
            if matched:
                program.define_lineno = lineno
                program.entry = matched.group(1)
                program.entry_define = line
                for param in SSA_USE_RE.findall(
                    line.split("(", 1)[1].rsplit(")", 1)[0]
                ):
                    program.params.append(param)
                    _record_def(program, param, lineno, raw)
                in_body = True
                in_callee = False
                continue
            callee_match = (
                CALLEE_DEFINE_RE.match(line)
                if program.wanted_callee
                else None
            )
            if (
                callee_match
                and callee_match.group(1) == program.wanted_callee
                and not program.callee
            ):
                program.callee = callee_match.group(1)
                program.callee_define = line
                program.callee_define_lineno = lineno
                program.callee_order = (
                    "after" if program.entry else "before"
                )
                for param in SSA_USE_RE.findall(
                    line.split("(", 1)[1].rsplit(")", 1)[0]
                ):
                    program.callee_params.append(param)
                    _record_callee_def(program, param, lineno, raw)
                in_body = True
                in_callee = True
                continue
            if program.wanted_callee:
                raise AuditError(
                    CODE_ENTRY,
                    "unexpected definition (only one complete i32 "
                    "@xdp_entry(ptr...), @trace_entry(ptr...), "
                    "@uprobe_entry(ptr...), @socket_entry(ptr...), or "
                    "@tc_entry(ptr...) "
                    "header plus one complete i64 @%s(i64) "
                    "subprogram header allowed): %r"
                    % (program.wanted_callee, raw.strip()),
                    location=_at(lineno),
                    remedy=(
                        "define exactly one entrypoint plus at most "
                        "one (i64)->i64 subprogram"
                    ),
                )
            raise AuditError(
                CODE_ENTRY,
                "unexpected definition (only one complete i32 "
                "@xdp_entry(ptr...), @trace_entry(ptr...), "
                "@uprobe_entry(ptr...), @socket_entry(ptr...), or "
                "@tc_entry(ptr...) #0 "
                "header, nothing after '{', allowed): %r"
                % (raw.strip(),),
                location=_at(lineno),
                remedy=(
                    "expose exactly one C-ABI entrypoint taking "
                    "the context pointer"
                ),
            )
        if line == "}":
            if not in_body:
                raise AuditError(
                    CODE_ENTRY,
                    "stray closing brace: %r" % (raw.strip(),),
                    location=_at(lineno),
                    remedy="emit exactly one entrypoint definition",
                )
            in_body = False
            in_callee = False
            continue
        if line.startswith("}"):
            raise AuditError(
                CODE_ENTRY,
                "text after the closing brace is not allowed: %r"
                % (raw.strip(),),
                location=_at(lineno),
                remedy="emit exactly one entrypoint definition",
            )
        if not in_body:
            _check_module_line(line, lineno, raw, program)
            continue
        if CALL_DETECT_RE.search(line):
            if in_callee:
                _refuse_callee_call(line, lineno, raw, program)
            if program.wanted_callee and "asm" not in line:
                direct = CALLEE_DIRECT_RE.search(line)
                if (
                    direct
                    and direct.group(1) == program.wanted_callee
                ):
                    sub_match = _diagnose_subprog_call(
                        line, lineno, raw, program
                    )
                    program.subprog_calls.append((lineno, sub_match))
                    program.body.append((lineno, line, raw))
                    defined = SSA_DEF_RE.match(line)
                    if defined:
                        _record_def(
                            program, defined.group(1), lineno, raw
                        )
                    _record_uses(
                        program, ssa_operands(line), lineno
                    )
                    continue
            shape, match = classify_call(line, lineno, raw)
            program.counts[shape] += 1
            program.calls.append((lineno, shape, match))
            if shape == "keyslot":
                program.key_of[match.group(1)] = 0
            elif shape == "keyslot1":
                program.key_of[match.group(1)] = 1
            elif shape == "keyslotN":
                program.key_of[match.group(1)] = int(match.group(2))
            elif shape == "rbsize":
                program.ring_size = int(match.group(3))
            program.body.append((lineno, line, raw))
            defined = SSA_DEF_RE.match(line)
            if defined:
                _record_def(program, defined.group(1), lineno, raw)
            _record_uses(program, ssa_operands(line), lineno)
            continue
        if LABEL_DEF_RE.match(line):
            if in_callee:
                program.callee_labels.add(line[:-1])
            else:
                program.labels.add(line[:-1])
                program.label_lines.append(lineno)
                program.label_at[lineno] = line[:-1]
            continue
        check_body_line(line, lineno, raw)
        if in_callee:
            if line.startswith("store "):
                raise AuditError(
                    CODE_PTRSTORE,
                    "the subprogram body is pure scalar computation "
                    "and must not store: %r" % (raw.strip(),),
                    location=_at(lineno),
                    remedy=(
                        "keep the subprogram body free of memory "
                        "operations"
                    ),
                )
            if _is_load_line(line):
                raise AuditError(
                    CODE_EXTERNAL,
                    "the subprogram body is pure scalar computation "
                    "and must not load: %r" % (raw.strip(),),
                    location=_at(lineno),
                    remedy=(
                        "keep the subprogram body free of memory "
                        "operations"
                    ),
                )
            program.callee_body.append((lineno, line, raw))
            defined = SSA_DEF_RE.match(line)
            if defined:
                _record_callee_def(
                    program, defined.group(1), lineno, raw
                )
            _record_callee_uses(
                program, ssa_operands(line), lineno
            )
            continue
        program.body.append((lineno, line, raw))
        defined = SSA_DEF_RE.match(line)
        if defined:
            _record_def(program, defined.group(1), lineno, raw)
        _record_uses(program, ssa_operands(line), lineno)
    if in_body:
        if in_callee:
            unclosed = program.callee
        else:
            unclosed = program.entry or "xdp_entry"
        raise AuditError(
            CODE_ENTRY,
            "the @%s body was never closed with '}'" % unclosed,
            location=None,
            remedy="emit exactly one entrypoint definition",
        )
    if program.wanted_callee:
        if defines != 2 or not program.entry or not program.callee:
            raise AuditError(
                CODE_ENTRY,
                "expected exactly one entrypoint definition plus "
                "one @%s subprogram definition, found %d "
                "definition(s)"
                % (program.wanted_callee, defines),
                location=None,
                remedy=(
                    "define exactly one entrypoint plus at most "
                    "one (i64)->i64 subprogram"
                ),
            )
    elif defines != 1:
        raise AuditError(
            CODE_ENTRY,
            "expected exactly one @xdp_entry, @trace_entry, "
            "@uprobe_entry, @socket_entry, or @tc_entry "
            "definition, found %d" % defines,
            location=None,
            remedy="emit exactly one entrypoint definition",
        )
    program.has_bounded_loop = _check_cfg(text)
    _check_counts(program)
    _check_entry_family(program)
    _check_tracepoint_context(program)
    _check_uprobe_context(program)
    _check_helper_operands(program)
    _check_event_slots(program)
    _check_reserve_slots(program)
    _check_core_operands(program)
    _check_liveness(program)
    _check_key_freshness(program)
    _check_roots(program)
    _check_pointer_stores(program)
    _check_callee_scopes(program)
    for name in program.uses:
        program.uses[name].sort()
    for name in program.callee_uses:
        program.callee_uses[name].sort()
    return program


def _check_decls(
    program, want_lookup, want_update, shared, want_delete=0,
    want_pid=0, want_ktime=0, want_cpu=0, want_output=0,
    want_reserve=0, want_submit=0, want_discard=0,
    want_coreread=0, want_coreexists=0,
    want_skbload=0, want_skbstore=0,
):
    """Require the declarations a matched count shape needs.

    Classifier programs declare nothing; single-pair map programs
    declare each helper once for their single call; wider shapes
    share one declaration per used helper across their calls. The
    tracepoint vector additionally declares its PID/TID call once;
    the event vector additionally declares its PID/TID, clock, CPU,
    and output calls once each; each reservation vector
    additionally declares its PID/TID, clock, CPU, reserve, and
    one terminus call once each; the core vector additionally
    declares its relocation read and existence check once each;
    each skb vector additionally declares its one skb call once.
    """
    for shape, want in (
        ("delete", want_delete),
        ("pid", want_pid),
        ("ktime", want_ktime),
        ("cpu", want_cpu),
        ("output", want_output),
        ("reserve", want_reserve),
        ("submit", want_submit),
        ("discard", want_discard),
        ("coreread", want_coreread),
        ("coreexists", want_coreexists),
        ("skbload", want_skbload),
        ("skbstore", want_skbstore),
    ):
        if program.decl_counts[shape] != want:
            if shape in ("coreread", "coreexists"):
                remedy = "use the SDK core wrappers unchanged"
                what = "relocation call"
            else:
                remedy = "use the SDK helper wrappers unchanged"
                what = "helper"
            raise AuditError(
                CODE_PSEUDO,
                "each used %s needs exactly one shared "
                "declaration (%s calls %d declaration %d)"
                % (
                    what,
                    shape,
                    program.counts[shape],
                    program.decl_counts[shape],
                ),
                location=None,
                remedy=remedy,
            )
    if (
        program.decl_counts["lookup"] == want_lookup
        and program.decl_counts["update"] == want_update
    ):
        return
    if shared:
        detail = (
            "the combined shape shares one lookup and one update "
            "declaration across its two calls of each (calls "
            "%d/%d, declarations %d/%d)"
            % (
                program.counts["lookup"],
                program.counts["update"],
                program.decl_counts["lookup"],
                program.decl_counts["update"],
            )
        )
    else:
        detail = (
            "each reserved helper call needs exactly its own "
            "declaration (calls %d/%d, declarations %d/%d)"
            % (
                program.counts["lookup"],
                program.counts["update"],
                program.decl_counts["lookup"],
                program.decl_counts["update"],
            )
        )
    raise AuditError(
        CODE_PSEUDO,
        detail,
        location=None,
        remedy="use the SDK helper wrappers unchanged",
    )


def _dense_keys(program, entries, per_key):
    """Whether the key slots cover exactly keys 0..entries-1.

    ``per_key`` is the required slot count per key (two per pair
    key, one per deleted key). Any gap, any key above entries-1,
    or any wrong multiplicity fails.
    """
    want = sorted(
        key for key in range(entries) for _ in range(per_key)
    )
    return sorted(program.key_of.values()) == want


def _match_pairs(program):
    """Accept N read-modify-write pairs over dense keys 0..N-1.

    Returns True with the program mode, family, entry count, and
    kind flags set when the counts fit; returns False without
    setting anything otherwise. The frozen single-pair vector is
    matched before this rule, so N == 1 here means per-CPU,
    hash, or LRU. Per-CPU, hash, and LRU tags never mix: one
    program defines one map of one kind.
    """
    pairs = program.counts["lookup"]
    if pairs < 1 or program.counts["update"] != pairs:
        return False
    if program.counts["delete"]:
        return False
    if program.counts["pid"]:
        return False
    if program.counts["coreread"] or program.counts["coreexists"]:
        return False
    if program.counts["skbload"] or program.counts["skbstore"]:
        return False
    if (
        program.counts["ktime"]
        or program.counts["cpu"]
        or program.counts["output"]
        or program.counts["reserve"]
        or program.counts["submit"]
        or program.counts["discard"]
        or program.counts["rbmapaddr"]
        or program.counts["rbsize"]
        or program.counts["eventslot"]
        or program.counts["eventslotN"]
    ):
        return False
    if program.counts["empty"] != pairs:
        return False
    if program.counts["mapaddr"] != 2 * pairs:
        return False
    if program.counts["valslot"] != pairs:
        return False
    if program.counts["kindtag"] not in (0, 2 * pairs):
        return False
    if program.counts["hashtag"] not in (0, 2 * pairs):
        return False
    if program.counts["lrutag"] not in (0, 2 * pairs):
        return False
    if sum((
        program.counts["kindtag"] > 0,
        program.counts["hashtag"] > 0,
        program.counts["lrutag"] > 0,
    )) > 1:
        return False
    if not _dense_keys(program, pairs, 2):
        return False
    _check_decls(program, 1, 1, pairs > 1)
    program.mode = "map"
    program.family = "map"
    program.entries = pairs
    program.percpu = program.counts["kindtag"] > 0
    program.hashkind = program.counts["hashtag"] > 0
    program.lrukind = program.counts["lrutag"] > 0
    return True


def _match_deletes(program):
    """Accept N deletions over dense keys 0..N-1 (one per key)."""
    deletes = program.counts["delete"]
    if deletes < 1:
        return False
    if program.counts["lookup"] or program.counts["update"]:
        return False
    if program.counts["pid"]:
        return False
    if program.counts["coreread"] or program.counts["coreexists"]:
        return False
    if program.counts["skbload"] or program.counts["skbstore"]:
        return False
    if (
        program.counts["ktime"]
        or program.counts["cpu"]
        or program.counts["output"]
        or program.counts["reserve"]
        or program.counts["submit"]
        or program.counts["discard"]
        or program.counts["rbmapaddr"]
        or program.counts["rbsize"]
        or program.counts["eventslot"]
        or program.counts["eventslotN"]
    ):
        return False
    if program.counts["empty"]:
        return False
    if program.counts["mapaddr"] != deletes:
        return False
    if program.counts["valslot"]:
        return False
    if program.counts["kindtag"] not in (0, deletes):
        return False
    if program.counts["hashtag"] not in (0, deletes):
        return False
    if program.counts["lrutag"] not in (0, deletes):
        return False
    if sum((
        program.counts["kindtag"] > 0,
        program.counts["hashtag"] > 0,
        program.counts["lrutag"] > 0,
    )) > 1:
        return False
    if not _dense_keys(program, deletes, 1):
        return False
    _check_decls(program, 0, 0, deletes > 1, want_delete=1)
    program.mode = "map"
    program.family = "delete"
    program.entries = deletes
    program.percpu = program.counts["kindtag"] > 0
    program.hashkind = program.counts["hashtag"] > 0
    program.lrukind = program.counts["lrutag"] > 0
    return True


def _match_combined_percpu(program):
    """Accept the combined workload marked per-CPU.

    The frozen combined count vector plus one kind tag per
    map-address load; the packet/pair rules are the combined
    ones, only the emitted map kind differs.
    """
    want = dict(COMBINED_COUNTS)
    want["kindtag"] = 4
    if program.counts != want:
        return False
    _check_decls(program, 1, 1, True)
    program.mode = "combined"
    program.family = "combined"
    program.entries = 2
    program.percpu = True
    return True


def _check_subprog_wiring(program):
    """Require the subprogram attribute wiring and definition order.

    The subprogram definition must reference the ``noinline``
    attribute set and the entrypoint definition the plain set
    (the call survives the frontend only under that wiring), and
    the indices must follow definition order (``#0`` for the
    first-defined function, ``#1`` for the second). The set
    assignment is checked before the numbering, so a collapsed
    set (a missing ``@no_inline``) names the missing marker
    rather than the numbering. Runs first in the subprogram
    count branch, so a malformed definition is reported before a
    malformed shape.
    """
    found = DEFINE_ATTRS_RE.search(program.callee_define)
    callee_index = int(found.group(1)) if found else -1
    found = DEFINE_ATTRS_RE.search(program.entry_define)
    entry_index = int(found.group(1)) if found else -1
    for index, role, lineno in (
        (callee_index, "subprogram", program.callee_define_lineno),
        (entry_index, "entrypoint", program.define_lineno),
    ):
        if index not in program.attr_sets:
            raise AuditError(
                CODE_ENTRY,
                "the %s definition references attribute set #%d "
                "but the module carries no such line"
                % (role, index),
                location=_at(lineno),
                remedy=(
                    "define exactly one entrypoint plus at most "
                    "one (i64)->i64 subprogram"
                ),
            )
    if not program.attr_sets[callee_index]:
        raise AuditError(
            CODE_ENTRY,
            "the subprogram @%s must reference the noinline "
            "attribute set (the call survives the frontend only "
            "then); attribute set #%d is plain"
            % (program.callee, callee_index),
            location=_at(program.callee_define_lineno),
            remedy=(
                "mark only the subprogram @no_inline so the call "
                "survives; the entrypoint stays plain"
            ),
        )
    if program.attr_sets[entry_index]:
        raise AuditError(
            CODE_ENTRY,
            "the entrypoint @%s must reference the plain "
            "attribute set; attribute set #%d carries noinline"
            % (program.entry, entry_index),
            location=_at(program.define_lineno),
            remedy=(
                "mark only the subprogram @no_inline so the call "
                "survives; the entrypoint stays plain"
            ),
        )
    if program.callee_order == "before":
        want_callee, want_entry = 0, 1
    else:
        want_callee, want_entry = 1, 0
    if (callee_index, entry_index) != (want_callee, want_entry):
        raise AuditError(
            CODE_ENTRY,
            "the subprogram shape numbers attribute sets in "
            "definition order (#%d for @%s, #%d for @%s), found "
            "#%d and #%d"
            % (
                want_callee,
                program.callee,
                want_entry,
                program.entry,
                callee_index,
                entry_index,
            ),
            location=None,
            remedy=(
                "define exactly one entrypoint plus at most one "
                "(i64)->i64 subprogram"
            ),
        )


def _check_callee_scopes(program):
    """Require defined roots in the subprogram body.

    Runs after the shared checks; without a subprogram it returns
    immediately. Every value the callee body uses must be defined
    by the callee's own define line or body (block names
    excluded, as in the shared roots check). Stores, loads, and
    calls never reach this check: the scan refuses them inline.
    """
    if not program.callee:
        return
    for name in sorted(
        program.callee_uses,
        key=lambda n: (min(program.callee_uses[n]), n),
    ):
        if name in program.callee_defs or name in program.callee_labels:
            continue
        used = min(program.callee_uses[name])
        raise AuditError(
            CODE_UNDEFINED,
            "SSA value %%%s is used at %s but never defined"
            % (name, _at(used)),
            location=_at(used),
            remedy="define every used value exactly once",
        )


def _check_counts(program):
    """Require one frozen vector or one map count family."""
    if program.wanted_callee:
        _check_subprog_wiring(program)
        if program.counts != CLASSIFIER_COUNTS:
            raise AuditError(
                CODE_MAP_SHAPE,
                "subprogram calls are admitted only on the "
                "classifier shape (one register "
                "reinterpretation, no map or helper calls), found "
                "%r" % (program.counts,),
                location=None,
                remedy=(
                    "call the subprogram only from a classifier "
                    "program; wider shapes need a reviewed route"
                ),
            )
        _check_decls(program, 0, 0, False)
        if not program.subprog_calls:
            raise AuditError(
                CODE_MAP_SHAPE,
                "the subprogram @%s is defined but never called "
                "(the subprogram shape needs at least one call "
                "site)" % (program.callee,),
                location=None,
                remedy=(
                    "call the defined subprogram at least once, "
                    "or remove its definition"
                ),
            )
        program.mode = "subprog"
        program.family = "subprog"
        program.entries = 0
        program.percpu = False
        program.hashkind = False
        program.lrukind = False
        return
    if program.counts == CLASSIFIER_COUNTS:
        _check_decls(program, 0, 0, False)
        if program.has_bounded_loop:
            # Bounded loops stay on the loop-preserving Lane-A
            # route: the parsed proof admits a no-loop slice
            # only. The split keeps every verdict; the loop
            # shape migrates with its own proof extension.
            program.mode = "classifier-loop"
        else:
            program.mode = "classifier"
        program.family = "classifier"
        program.entries = 0
        return
    if program.counts == MAP_COUNTS:
        _check_decls(program, 1, 1, False)
        program.mode = "map"
        program.family = "map"
        program.entries = 1
        return
    if program.counts == COMBINED_COUNTS:
        _check_decls(program, 1, 1, True)
        program.mode = "combined"
        program.family = "combined"
        program.entries = 2
        return
    if program.counts == TRACEPOINT_COUNTS:
        _check_decls(program, 1, 1, False, want_pid=1)
        program.mode = "tracepoint"
        program.family = "tracepoint"
        program.entries = 2
        program.percpu = False
        program.hashkind = False
        program.lrukind = False
        return
    if program.counts == UPROBE_COUNTS:
        _check_decls(program, 1, 1, False)
        program.mode = "uprobe"
        program.family = "uprobe"
        program.entries = 2
        program.percpu = False
        program.hashkind = False
        program.lrukind = False
        return
    if program.counts == EVENT_COUNTS:
        _check_decls(
            program, 1, 1, True, want_pid=1, want_ktime=1, want_cpu=1,
            want_output=1,
        )
        program.mode = "event"
        program.family = "event"
        program.entries = 4
        program.percpu = False
        program.hashkind = False
        program.lrukind = False
        return
    if program.counts == RESERVE_SUBMIT_COUNTS:
        _check_decls(
            program, 1, 1, True, want_pid=1, want_ktime=1, want_cpu=1,
            want_reserve=1, want_submit=1,
        )
        program.mode = "reserve"
        program.family = "reserve"
        program.entries = 4
        program.percpu = False
        program.hashkind = False
        program.lrukind = False
        return
    if program.counts == RESERVE_DISCARD_COUNTS:
        _check_decls(
            program, 1, 1, True, want_pid=1, want_ktime=1, want_cpu=1,
            want_reserve=1, want_discard=1,
        )
        program.mode = "reserve"
        program.family = "reserve"
        program.entries = 4
        program.percpu = False
        program.hashkind = False
        program.lrukind = False
        return
    if program.counts == CORE_COUNTS:
        _check_decls(
            program, 1, 0, False, want_coreread=1,
            want_coreexists=1,
        )
        program.mode = "core"
        program.family = "core"
        program.entries = 1
        program.percpu = False
        program.hashkind = False
        program.lrukind = False
        return
    if program.counts == SKB_LOAD_COUNTS:
        _check_decls(program, 0, 0, False, want_skbload=1)
        program.mode = "skb"
        program.family = "skb"
        program.skb_kind = "load"
        program.entries = 0
        program.percpu = False
        program.hashkind = False
        program.lrukind = False
        return
    if program.counts == SKB_STORE_COUNTS:
        _check_decls(program, 0, 0, False, want_skbstore=1)
        program.mode = "skb"
        program.family = "skb"
        program.skb_kind = "store"
        program.entries = 0
        program.percpu = False
        program.hashkind = False
        program.lrukind = False
        return
    if program.counts == SKB_LOADMAP_COUNTS:
        _check_decls(
            program, 0, 1, False, want_skbload=1,
        )
        program.mode = "skb"
        program.family = "skb"
        program.skb_kind = "loadmap"
        program.entries = 2
        program.percpu = False
        program.hashkind = False
        program.lrukind = False
        return
    if _match_pairs(program):
        return
    if _match_combined_percpu(program):
        return
    if _match_deletes(program):
        return
    for shape in (
        "lookup", "update", "delete", "pid", "ktime", "cpu",
        "output", "reserve", "submit", "discard",
        "coreread", "coreexists", "skbload", "skbstore",
    ):
        want = 1 if program.counts[shape] else 0
        if program.decl_counts[shape] != want:
            raise AuditError(
                CODE_PSEUDO,
                "each used helper needs exactly one shared "
                "declaration (lookup calls %d declaration %d, "
                "update calls %d declaration %d, delete calls %d "
                "declaration %d, pid calls %d declaration %d, "
                "ktime calls %d declaration %d, cpu calls %d "
                "declaration %d, output calls %d declaration %d, "
                "reserve calls %d declaration %d, submit calls %d "
                "declaration %d, discard calls %d declaration %d, "
                "coreread calls %d declaration %d, coreexists "
                "calls %d declaration %d, skbload calls %d "
                "declaration %d, skbstore calls %d "
                "declaration %d)"
                % (
                    program.counts["lookup"],
                    program.decl_counts["lookup"],
                    program.counts["update"],
                    program.decl_counts["update"],
                    program.counts["delete"],
                    program.decl_counts["delete"],
                    program.counts["pid"],
                    program.decl_counts["pid"],
                    program.counts["ktime"],
                    program.decl_counts["ktime"],
                    program.counts["cpu"],
                    program.decl_counts["cpu"],
                    program.counts["output"],
                    program.decl_counts["output"],
                    program.counts["reserve"],
                    program.decl_counts["reserve"],
                    program.counts["submit"],
                    program.decl_counts["submit"],
                    program.counts["discard"],
                    program.decl_counts["discard"],
                    program.counts["coreread"],
                    program.decl_counts["coreread"],
                    program.counts["coreexists"],
                    program.decl_counts["coreexists"],
                    program.counts["skbload"],
                    program.decl_counts["skbload"],
                    program.counts["skbstore"],
                    program.decl_counts["skbstore"],
                ),
                location=None,
                remedy="use the SDK helper wrappers unchanged",
            )
    decl_total = sum(program.decl_counts.values())
    mapish = (
        program.counts["mapaddr"]
        + program.counts["keyslot"]
        + program.counts["keyslot1"]
        + program.counts["keyslotN"]
        + program.counts["kindtag"]
        + program.counts["hashtag"]
        + program.counts["lrutag"]
        + program.counts["valslot"]
        + program.counts["rbmapaddr"]
        + program.counts["rbsize"]
        + program.counts["eventslot"]
        + program.counts["eventslotN"]
        + program.counts["lookup"]
        + program.counts["update"]
        + program.counts["delete"]
        + program.counts["pid"]
        + program.counts["ktime"]
        + program.counts["cpu"]
        + program.counts["output"]
        + program.counts["reserve"]
        + program.counts["submit"]
        + program.counts["discard"]
        + program.counts["coreread"]
        + program.counts["coreexists"]
        + program.counts["skbload"]
        + program.counts["skbstore"]
        + decl_total
    )
    if mapish:
        raise AuditError(
            CODE_MAP_SHAPE,
            "map programs need one map count family over dense "
            "keys 0..N-1 (N read-modify-write pairs or N "
            "deletions, each call with its map reference "
            "shapes), found %r" % (program.counts,),
            location=None,
            remedy=(
                "pair every helper call with its map reference "
                "shapes and cover exactly keys 0..N-1"
            ),
        )
    raise AuditError(
        CODE_EXTERNAL,
        "classifier programs need shape counts %r, found %r"
        % (CLASSIFIER_COUNTS, program.counts),
        location=None,
        remedy=_remedy_for(CODE_EXTERNAL),
    )


def _check_entry_family(program):
    """Require the entry symbol and the count family to agree.

    The tracepoint counter, the event emitter, and the
    reservation emitter export ``trace_entry``; the uprobe
    register counter exports ``uprobe_entry``; the classifier
    exports ``xdp_entry``, ``socket_entry``, or ``tc_entry``;
    every other shape (including the map, combined, delete,
    core, and subprogram shapes) exports ``xdp_entry``. A
    ``trace_entry`` program with any other body would misread the
    tracepoint context as packet metadata, and an ``xdp_entry``
    program with a tracepoint vector would publish a miscounted
    shape, so both mismatches fail closed here, as does any
    uprobe crossing (a uprobe body under another entry would
    misread that context as register words, and another body
    under ``uprobe_entry`` would misread register words as its
    own context), and as does any non-classifier non-skb body
    under a socket or TC entry (only the mapless classifier and
    skb shapes are admitted for those program types, and the
    skb store shape only under tc_entry, since helper 9 is not
    callable from socket-filter programs). Runs after
    the count rule, so the family is known.
    """
    uprobe_body = program.family == "uprobe"
    tracepoint_body = program.family in ("tracepoint", "event", "reserve")
    if uprobe_body:
        want = ("uprobe_entry",)
    elif tracepoint_body:
        want = ("trace_entry",)
    elif program.family == "classifier":
        want = ("xdp_entry", "socket_entry", "tc_entry")
    elif program.family == "skb":
        if program.skb_kind == "store":
            want = ("tc_entry",)
        else:
            want = ("socket_entry", "tc_entry")
    else:
        want = ("xdp_entry",)
    if program.entry in want:
        return
    if program.entry == "uprobe_entry":
        detail = (
            "uprobe_entry exports the uprobe register counter, "
            "but the body matches the %s shape" % program.family
        )
    elif uprobe_body:
        detail = (
            "the uprobe body must export uprobe_entry, not @%s"
            % (program.entry,)
        )
    elif program.entry == "trace_entry":
        detail = (
            "trace_entry exports the tracepoint counter, the "
            "event emitter, or the reservation emitter, but the "
            "body matches the %s shape" % program.family
        )
    elif tracepoint_body:
        detail = (
            "the %s body must export trace_entry, not @%s"
            % (program.family, program.entry)
        )
    elif program.entry in ("socket_entry", "tc_entry"):
        kind = "socket" if program.entry == "socket_entry" else "tc"
        if program.family == "skb" and program.skb_kind == "store":
            detail = (
                "socket_entry cannot export the skb store shape: "
                "helper 9 (skb_store_bytes) is not callable from "
                "socket-filter programs, only from tc_entry"
            )
        else:
            detail = (
                "%s exports the %s classifier, but the body matches "
                "the %s shape"
                % (program.entry, kind, program.family)
            )
    else:
        detail = (
            "entry @%s does not admit the %s shape"
            % (program.entry, program.family)
        )
    raise AuditError(
        CODE_ENTRY,
        "%s: %r" % (detail, program.counts),
        location=None,
        remedy=(
            "export trace_entry for the tracepoint counter, the "
            "event emitter, and the reservation emitter, "
            "uprobe_entry for the uprobe register counter, "
            "xdp_entry, socket_entry, or tc_entry for the "
            "classifier, socket_entry or tc_entry for the skb "
            "load and loadmap shapes, tc_entry for the skb store "
            "shape, xdp_entry for every other shape"
        ),
    )


def _check_tracepoint_context(program):
    """Require tracepoint programs to leave the context unused.

    Only the tracepoint, event, and reserve families are
    checked: their filters come from the current-PID/TID helper
    and map state, never from tracepoint context payload fields,
    whose layout is a separate unimplemented capability. Other
    families return early. Runs after the entry/family rule, so
    a checked program exports ``trace_entry``.
    """
    if program.family not in ("tracepoint", "event", "reserve"):
        return
    for param in program.params:
        uses = program.uses.get(param, [])
        if uses:
            raise AuditError(
                CODE_CONTEXT,
                "tracepoint programs must not read context payload "
                "fields: entry parameter %%%s is used at %s"
                % (param, _at(min(uses))),
                location=_at(min(uses)),
                remedy=(
                    "filter on the current-PID/TID helper and map "
                    "state; leave the context pointer unused"
                ),
            )


def _check_uprobe_context(program):
    """Require exactly the pinned x86-64 first-argument read.

    Only the uprobe family is checked: its entry parameter feeds
    exactly one address computation, the pinned
    ``getelementptr inbounds i64, ptr %<param>, i32 14`` word
    (``pt_regs`` word 14, ``rdi`` at byte 112 on x86-64), and
    that address feeds exactly one ``i64`` load. Any other
    element type, index, loaded width, extra address
    computation, extra parameter use, or extra address use is a
    different register and is refused. Other families return
    early (their context posture is unchanged: tracepoint
    programs leave the context unused, XDP programs keep the
    established verifier-backed packet discipline). Runs after
    the entry/family rule, so a checked program exports
    ``uprobe_entry``.
    """
    if program.family != "uprobe":
        return
    remedy = (
        "read the probed call's first argument through the SDK "
        "uprobe vocabulary (x86-64 context word 14 only); any "
        "other context access needs a reviewed route"
    )
    params = set(program.params)
    pinned = []
    for lineno, line, raw in program.body:
        if "getelementptr" not in line:
            continue
        if not any(
            name in params for name in ssa_operands(line)
        ):
            continue
        pinned.append((lineno, line, raw))
    if len(pinned) != 1:
        raise AuditError(
            CODE_CONTEXT,
            "uprobe programs must read exactly the pinned "
            "x86-64 first-argument register (context word 14): "
            "found %d entry-parameter address computations, "
            "want 1" % len(pinned),
            location=_at(pinned[0][0]) if pinned else None,
            remedy=remedy,
        )
    lineno, line, raw = pinned[0]
    match = UPROBE_CTX_GEP_RE.match(line)
    if match is None or match.group(2) not in params:
        raise AuditError(
            CODE_CONTEXT,
            "uprobe programs must read exactly the pinned "
            "x86-64 first-argument register (context word 14, "
            "rdi at byte 112): found %r" % (raw.strip(),),
            location=_at(lineno),
            remedy=remedy,
        )
    address = match.group(1)
    for param in program.params:
        extra = [
            used
            for used in program.uses.get(param, [])
            if used != lineno
        ]
        if extra:
            raise AuditError(
                CODE_CONTEXT,
                "uprobe programs must read exactly the pinned "
                "x86-64 first-argument register (context word "
                "14): entry parameter %%%s is also used at %s"
                % (param, _at(min(extra))),
                location=_at(min(extra)),
                remedy=remedy,
            )
    loads = []
    for load_lineno, load_line, load_raw in program.body:
        names = ssa_operands(load_line)
        if address not in names:
            continue
        loads.append((load_lineno, load_line, load_raw))
    if len(loads) != 1:
        raise AuditError(
            CODE_CONTEXT,
            "uprobe programs must load the pinned x86-64 "
            "first-argument register exactly once: %%%s is used "
            "at %d line(s), want 1"
            % (
                address,
                len(loads),
            ),
            location=_at(loads[0][0]) if loads else None,
            remedy=remedy,
        )
    load_lineno, load_line, load_raw = loads[0]
    load_match = UPROBE_CTX_LOAD_RE.match(load_line)
    if load_match is None or load_match.group(2) != address:
        raise AuditError(
            CODE_CONTEXT,
            "uprobe programs must load the pinned x86-64 "
            "first-argument register exactly once as i64: found "
            "%r" % (load_raw.strip(),),
            location=_at(load_lineno),
            remedy=remedy,
        )


def _def_shape(program, name):
    """The admitted call shape defining an SSA value, or None."""
    for _, shape, match in program.calls:
        if match.group(1) == name:
            return shape
    return None


def _check_helper_operands(program):
    """Require map provenance and prepared key/value storage.

    Single-pair map programs take every key from a key-0 slot;
    wider map families take each key from a key slot holding one of
    the dense key literals; combined programs take each key from a
    key-0 or key-1 slot. The i-th lookup and the i-th update must
    agree on the key, so every read-modify-write pair stays
    coherent; the tracepoint counter instead reads key 0 first and
    pairs key 1, and the event and reservation emitters read key 0
    first and pair keys 1, 2, and 3 in order. Each kind tag ties
    one map-address load to its result, as does each hash tag;
    the output call takes the size-tagged ring-buffer address
    plus the prepared event slot, the reservation call takes the
    size-tagged ring-buffer address, and each size tag ties one
    ring-buffer map-address load to its result. The termini take
    the record reinterpretation of the reservation result; that
    linkage is pinned by the reservation store check, not here.
    Each skb call takes the entry context plus an initialized key
    slot as its packet buffer.
    """
    combined = program.mode == "combined"
    for lineno, shape, match in program.calls:
        if shape == "lookup":
            expect = (("map", 2, ("mapaddr",)), ("key", 3, ("keyslot",)))
        elif shape == "update":
            expect = (
                ("map", 2, ("mapaddr",)),
                ("key", 3, ("keyslot",)),
                ("value", 4, ("valslot",)),
            )
        elif shape == "delete":
            expect = (("map", 2, ("mapaddr",)), ("key", 3, ("keyslot",)))
        elif shape == "kindtag":
            expect = (("map", 2, ("mapaddr",)),)
        elif shape == "hashtag":
            expect = (("map", 2, ("mapaddr",)),)
        elif shape == "lrutag":
            expect = (("map", 2, ("mapaddr",)),)
        elif shape == "rbsize":
            expect = (("map", 2, ("rbmapaddr",)),)
        elif shape == "output":
            expect = (
                ("map", 2, ("rbsize",)),
                ("data", 3, ("eventslot",)),
            )
        elif shape == "reserve":
            expect = (
                ("map", 2, ("rbsize",)),
            )
        elif shape == "skbload":
            expect = (
                ("skb", 2, (None,)),
                ("to", 4, KEYSLOT_SHAPES),
            )
        elif shape == "skbstore":
            expect = (
                ("skb", 2, (None,)),
                ("src", 4, KEYSLOT_SHAPES),
            )
        else:
            continue
        if combined:
            expect = tuple(
                (role, group, ("keyslot", "keyslot1"))
                if role == "key"
                else (role, group, origins)
                for role, group, origins in expect
            )
        else:
            expect = tuple(
                (role, group, KEYSLOT_SHAPES)
                if role == "key"
                else (role, group, origins)
                for role, group, origins in expect
            )
        if program.percpu and shape in (
            "lookup", "update", "delete"
        ):
            expect = tuple(
                (role, group, ("kindtag",))
                if role == "map"
                else (role, group, origins)
                for role, group, origins in expect
            )
        if program.hashkind and shape in (
            "lookup", "update", "delete"
        ):
            expect = tuple(
                (role, group, ("hashtag",))
                if role == "map"
                else (role, group, origins)
                for role, group, origins in expect
            )
        if program.lrukind and shape in (
            "lookup", "update", "delete"
        ):
            expect = tuple(
                (role, group, ("lrutag",))
                if role == "map"
                else (role, group, origins)
                for role, group, origins in expect
            )
        for role, group, origins in expect:
            name = match.group(group)
            if shape in ("skbload", "skbstore") and role == "skb":
                # The skb operand is the entry context itself, not
                # a call result and not an undefined value: the
                # (None,) origins below document the shape side,
                # this check enforces parameter identity.
                if name not in program.params:
                    raise AuditError(
                        CODE_OPERANDS,
                        "%s skb operand %%%s must be the entry "
                        "context: call at %s"
                        % (shape, name, _at(lineno)),
                        location=_at(lineno),
                        remedy=(
                            "pass the entry context to the skb call"
                        ),
                    )
                continue
            if _def_shape(program, name) not in origins:
                if role == "map":
                    if origins == ("kindtag",):
                        raise AuditError(
                            CODE_MAP_SHAPE,
                            "%s %s operand %%%s must be the per-CPU "
                            "kind tag of a map-address load, not "
                            "defined at %s: call at %s"
                            % (
                                shape,
                                role,
                                name,
                                _at(program.defs.get(name, 0)),
                                _at(lineno),
                            ),
                            location=_at(lineno),
                            remedy=(
                                "load the map address through the "
                                "per-CPU handle"
                            ),
                        )
                    if origins == ("hashtag",):
                        raise AuditError(
                            CODE_MAP_SHAPE,
                            "%s %s operand %%%s must be the hash "
                            "kind tag of a map-address load, not "
                            "defined at %s: call at %s"
                            % (
                                shape,
                                role,
                                name,
                                _at(program.defs.get(name, 0)),
                                _at(lineno),
                            ),
                            location=_at(lineno),
                            remedy=(
                                "load the map address through the "
                                "hash handle"
                            ),
                        )
                    if origins == ("lrutag",):
                        raise AuditError(
                            CODE_MAP_SHAPE,
                            "%s %s operand %%%s must be the LRU "
                            "kind tag of a map-address load, not "
                            "defined at %s: call at %s"
                            % (
                                shape,
                                role,
                                name,
                                _at(program.defs.get(name, 0)),
                                _at(lineno),
                            ),
                            location=_at(lineno),
                            remedy=(
                                "load the map address through the "
                                "LRU handle"
                            ),
                        )
                    if origins == ("rbsize",):
                        raise AuditError(
                            CODE_MAP_SHAPE,
                            "%s %s operand %%%s must be the ring-size "
                            "tag of a ring-buffer map-address load, "
                            "not defined at %s: call at %s"
                            % (
                                shape,
                                role,
                                name,
                                _at(program.defs.get(name, 0)),
                                _at(lineno),
                            ),
                            location=_at(lineno),
                            remedy=(
                                "load the ring-buffer map address "
                                "through the ring-buffer handle"
                            ),
                        )
                    if origins == ("rbmapaddr",):
                        raise AuditError(
                            CODE_MAP_SHAPE,
                            "%s %s operand %%%s must be loaded from "
                            "the ring-buffer map metadata section, "
                            "not defined at %s: call at %s"
                            % (
                                shape,
                                role,
                                name,
                                _at(program.defs.get(name, 0)),
                                _at(lineno),
                            ),
                            location=_at(lineno),
                            remedy=(
                                "load the ring-buffer map address "
                                "from its metadata"
                            ),
                        )
                    raise AuditError(
                        CODE_MAP_SHAPE,
                        "%s %s operand %%%s must be loaded from "
                        "the map metadata section (%s), not defined "
                        "at %s: call at %s"
                        % (
                            shape,
                            role,
                            name,
                            origins[0],
                            _at(program.defs.get(name, 0)),
                            _at(lineno),
                        ),
                        location=_at(lineno),
                        remedy=(
                            "load the map address from its metadata"
                        ),
                    )
                if shape == "output" and role == "data":
                    raise AuditError(
                        CODE_OPERANDS,
                        "output data operand %%%s must come from the "
                        "prepared event slot, not from %s: call at %s"
                        % (
                            name,
                            _at(program.defs.get(name, 0)),
                            _at(lineno),
                        ),
                        location=_at(lineno),
                        remedy=(
                            "pass the prepared event slot to the "
                            "output call"
                        ),
                    )
                if shape in ("skbload", "skbstore") and role in (
                    "to", "src",
                ):
                    raise AuditError(
                        CODE_OPERANDS,
                        "%s %s operand %%%s must come from an "
                        "initialized key slot, not from %s: call "
                        "at %s"
                        % (
                            shape,
                            role,
                            name,
                            _at(program.defs.get(name, 0)),
                            _at(lineno),
                        ),
                        location=_at(lineno),
                        remedy=(
                            "pass an initialized key slot to the "
                            "skb call"
                        ),
                    )
                raise AuditError(
                    CODE_OPERANDS,
                    "%s %s operand %%%s must come from the "
                    "prepared %s slot, not from %s: call at %s"
                    % (
                        shape,
                        role,
                        name,
                        role,
                        _at(program.defs.get(name, 0)),
                        _at(lineno),
                    ),
                    location=_at(lineno),
                    remedy=(
                        "pass the prepared key and value slots to "
                        "helper calls"
                    ),
                )
    if combined:
        _check_pair_keys(program)
    elif program.family == "tracepoint":
        _check_tracepoint_keys(program)
    elif program.family == "uprobe":
        _check_uprobe_keys(program)
    elif program.family in ("event", "reserve"):
        _check_event_keys(program)
    elif program.family == "map":
        _check_pair_keys_general(program)


def _check_pair_keys(program):
    """Require lookup/update key agreement within each combined pair.

    The i-th lookup and the i-th update (in line order) must take
    their keys from the same slot shape, so each pair reads and
    writes one map entry. Either entry order validates; crossing
    the keys between pairs does not.
    """
    lookups = [
        (lineno, match.group(3))
        for lineno, shape, match in program.calls
        if shape == "lookup"
    ]
    updates = [
        (lineno, match.group(3))
        for lineno, shape, match in program.calls
        if shape == "update"
    ]
    for (lookup_lineno, lookup_key), (_update_lineno, update_key) in zip(
        lookups, updates
    ):
        lookup_origin = _def_shape(program, lookup_key)
        update_origin = _def_shape(program, update_key)
        if lookup_origin != update_origin:
            raise AuditError(
                CODE_MAP_SHAPE,
                "the lookup at %s reads through %%%s (%s) but its "
                "paired update writes through %%%s (%s): each pair "
                "must reference one map entry"
                % (
                    _at(lookup_lineno),
                    lookup_key,
                    lookup_origin,
                    update_key,
                    update_origin,
                ),
                location=_at(lookup_lineno),
                remedy=(
                    "read and write each map entry through one key "
                    "slot shape"
                ),
            )


def _check_pair_keys_general(program):
    """Require lookup/update key agreement within each pair.

    The i-th lookup and the i-th update (in line order) must take
    their keys from slots holding the same key literal, so each
    pair reads and writes one map entry. Either entry order
    validates; crossing the keys between pairs does not. Runs
    after operand provenance, so every key operand is known to
    come from a key slot holding a recorded literal.
    """
    lookups = [
        (lineno, program.key_of[match.group(3)])
        for lineno, shape, match in program.calls
        if shape == "lookup"
    ]
    updates = [
        (lineno, program.key_of[match.group(3)])
        for lineno, shape, match in program.calls
        if shape == "update"
    ]
    for (lookup_lineno, lookup_key), (_update_lineno, update_key) in zip(
        lookups, updates
    ):
        if lookup_key != update_key:
            raise AuditError(
                CODE_MAP_SHAPE,
                "the lookup at %s reads key %d but its paired "
                "update writes key %d: each pair must reference "
                "one map entry" % (
                    _at(lookup_lineno),
                    lookup_key,
                    update_key,
                ),
                location=_at(lookup_lineno),
                remedy=(
                    "read and write each map entry through slots "
                    "holding one key"
                ),
            )


def _check_tracepoint_keys(program):
    """Require the tracepoint key order: filter 0, then count pair 1.

    The first lookup reads the filter through key 0; the second
    lookup and the update form the count pair through key 1. Any
    other order would count the wrong entry or filter on the
    counter. Runs after operand provenance, so every key operand
    is known to come from a key slot holding a recorded literal.
    """
    lookups = [
        (lineno, program.key_of[match.group(3)])
        for lineno, shape, match in program.calls
        if shape == "lookup"
    ]
    updates = [
        (lineno, program.key_of[match.group(3)])
        for lineno, shape, match in program.calls
        if shape == "update"
    ]
    filter_key = lookups[0][1]
    count_key = lookups[1][1]
    update_key = updates[0][1]
    if (filter_key, count_key, update_key) != (0, 1, 1):
        raise AuditError(
            CODE_MAP_SHAPE,
            "the tracepoint counter reads its filter through key 0 "
            "and counts through key 1, but the lookups read keys "
            "%d and %d with the update writing key %d"
            % (filter_key, count_key, update_key),
            location=_at(lookups[0][0]),
            remedy=(
                "read the filter through key 0 and pair the count "
                "read-modify-write through key 1"
            ),
        )


def _check_uprobe_keys(program):
    """Require the uprobe key order: filter 0, then count pair 1.

    The first lookup reads the expected argument value through
    key 0; the second lookup and the update form the count pair
    through key 1. Any other order would count the wrong entry
    or compare against the counter. Runs after operand
    provenance, so every key operand is known to come from a key
    slot holding a recorded literal.
    """
    lookups = [
        (lineno, program.key_of[match.group(3)])
        for lineno, shape, match in program.calls
        if shape == "lookup"
    ]
    updates = [
        (lineno, program.key_of[match.group(3)])
        for lineno, shape, match in program.calls
        if shape == "update"
    ]
    filter_key = lookups[0][1]
    count_key = lookups[1][1]
    update_key = updates[0][1]
    if (filter_key, count_key, update_key) != (0, 1, 1):
        raise AuditError(
            CODE_MAP_SHAPE,
            "the uprobe counter reads its expected argument "
            "through key 0 and counts through key 1, but the "
            "lookups read keys %d and %d with the update writing "
            "key %d" % (filter_key, count_key, update_key),
            location=_at(lookups[0][0]),
            remedy=(
                "read the expected argument through key 0 and pair "
                "the count read-modify-write through key 1"
            ),
        )


def _check_event_keys(program):
    """Require the event key order: filter 0, then pairs 1, 2, 3.

    The first lookup reads the filter through key 0; the second
    lookup and the first update form the sequence pair through key
    1; the third lookup and the second update form the success
    pair through key 2; the fourth lookup and the third update
    form the failure pair through key 3. Any other order would
    count attempts, successes, or failures into the wrong entry.
    Runs after operand provenance, so every key operand is known
    to come from a key slot holding a recorded literal.
    """
    lookups = [
        (lineno, program.key_of[match.group(3)])
        for lineno, shape, match in program.calls
        if shape == "lookup"
    ]
    updates = [
        (lineno, program.key_of[match.group(3)])
        for lineno, shape, match in program.calls
        if shape == "update"
    ]
    read = tuple(key for _, key in lookups)
    written = tuple(key for _, key in updates)
    if read != (0, 1, 2, 3) or written != (1, 2, 3):
        raise AuditError(
            CODE_MAP_SHAPE,
            "the event emitter reads its filter through key 0 "
            "and pairs keys 1, 2, and 3, but the lookups read "
            "keys %s with the updates writing keys %s"
            % (read, written),
            location=_at(lookups[0][0]),
            remedy=(
                "read the filter through key 0 and pair the "
                "sequence, success, and failure "
                "read-modify-writes through keys 1, 2, and 3"
            ),
        )


def _check_event_slots(program):
    """Require the qualified ring size and field-view offsets.

    Only the event family is checked: its size tag must carry one
    of the qualified ring-buffer sizes, and its six field views
    must carry exactly the record field offsets (62, 60, 56, 52,
    48, 40), each once, so every view addresses its own field
    and no view aliases the key slot, the value slot, or another
    field. Other families return early (their counts already pin
    zero size tags and field views). Runs after the count rule,
    so one size tag and six views are known present.
    """
    if program.family != "event":
        return
    if program.ring_size not in RINGBUF_SIZES:
        raise AuditError(
            CODE_MAP_SHAPE,
            "the event emitter sizes its ring buffer %r, but "
            "only ring sizes %s qualify"
            % (
                program.ring_size,
                ", ".join(str(size) for size in RINGBUF_SIZES),
            ),
            location=_at(program.calls[0][0]),
            remedy=(
                "size the ring buffer through the ring-buffer "
                "handle with a qualified size"
            ),
        )
    offsets = sorted(
        int(match.group(2))
        for _, shape, match in program.calls
        if shape == "eventslotN"
    )
    if tuple(offsets) != EVENTSLOTN_OFFSETS:
        raise AuditError(
            CODE_MAP_SHAPE,
            "the event emitter addresses its record fields "
            "through offsets %s, but the field views carry %s"
            % (list(EVENTSLOTN_OFFSETS), offsets),
            location=_at(program.calls[0][0]),
            remedy=(
                "address each record field through its own "
                "per-field view"
            ),
        )


def _check_reserve_slots(program):
    """Require the qualified ring size and the record stores.

    Only the reserve family is checked: its size tag must carry
    one of the qualified ring-buffer sizes; its terminus must
    take the record reinterpretation of the single reservation
    result (never a map slot, a GEP, or another call's result);
    its seven record stores must carry exactly the record field
    offsets and widths relative to the reservation (one direct
    i16 store at offset 0 plus one GEP-addressed store per
    remaining field, each exactly once, covering all 32 record
    bytes with no gaps and no overlap); and every
    reservation-relative store, load, and address computation
    must precede the terminus, so no use can follow the
    release.
    Other families return early (their counts already pin zero
    size tags, reservations, and termini). Runs after the count
    rule, so one size tag, one reserve, and one terminus are
    known present.
    """
    if program.family != "reserve":
        return
    if program.ring_size not in RINGBUF_SIZES:
        raise AuditError(
            CODE_MAP_SHAPE,
            "the reservation emitter sizes its ring buffer %r, "
            "but only ring sizes %s qualify"
            % (
                program.ring_size,
                ", ".join(str(size) for size in RINGBUF_SIZES),
            ),
            location=_at(program.calls[0][0]),
            remedy=(
                "size the ring buffer through the ring-buffer "
                "handle with a qualified size"
            ),
        )
    reserve_result = None
    terminus_lineno = 0
    terminus_shape = ""
    terminus_data = ""
    for lineno, shape, match in program.calls:
        if shape == "reserve":
            reserve_result = match.group(1)
        elif shape in ("submit", "discard"):
            terminus_lineno = lineno
            terminus_shape = shape
            terminus_data = match.group(2)
    reinterps = []
    for _call_lineno, shape, match in program.calls:
        if shape != "empty":
            continue
        for _, line, _raw in program.body:
            if line.startswith("%" + match.group(1) + " "):
                found = _EMPTY_OPERAND_RE.search(line)
                if found and found.group(1) == reserve_result:
                    reinterps.append(match.group(1))
    if len(reinterps) != 1:
        raise AuditError(
            CODE_OPERANDS,
            "the reservation result %%%s needs exactly one "
            "record reinterpretation, found %d: call at %s"
            % (reserve_result, len(reinterps), _at(terminus_lineno)),
            location=_at(terminus_lineno),
            remedy=(
                "convert the checked reservation result once "
                "with the SDK wrapper"
            ),
        )
    reinterp = reinterps[0]
    if terminus_data != reinterp:
        raise AuditError(
            CODE_OPERANDS,
            "%s data operand %%%s must be the record "
            "reinterpretation %%%s of the reservation result, "
            "not defined at %s: call at %s"
            % (
                terminus_shape,
                terminus_data,
                reinterp,
                _at(program.defs.get(terminus_data, 0)),
                _at(terminus_lineno),
            ),
            location=_at(terminus_lineno),
            remedy=(
                "pass the checked reservation record pointer "
                "to the terminus"
            ),
        )
    gep_offsets = {}
    for lineno, line, _raw in program.body:
        matched = RESERVE_GEP_RE.match(line)
        if matched is None or matched.group(2) != reinterp:
            continue
        if lineno > terminus_lineno:
            raise AuditError(
                CODE_OPERANDS,
                "reservation address %%%s is computed at %s, "
                "after the %s terminus at %s: nothing may use "
                "the reservation once released"
                % (
                    matched.group(1),
                    _at(lineno),
                    terminus_shape,
                    _at(terminus_lineno),
                ),
                location=_at(lineno),
                remedy=(
                    "stamp every record field before the "
                    "terminus"
                ),
            )
        gep_offsets[matched.group(1)] = int(matched.group(3))
    seen: dict[tuple[int, str], int] = {}
    for lineno, line, raw in program.body:
        if not line.startswith("store "):
            continue
        parsed = _store_operands(line)
        if parsed is None:
            continue
        stored_type, _stored_value, dest = parsed
        if dest == reinterp:
            offset = 0
        elif dest in gep_offsets:
            offset = gep_offsets[dest]
        else:
            continue
        if lineno > terminus_lineno:
            raise AuditError(
                CODE_OPERANDS,
                "reservation store at %s follows the %s "
                "terminus at %s: nothing may use the "
                "reservation once released: %r"
                % (
                    _at(lineno),
                    terminus_shape,
                    _at(terminus_lineno),
                    raw.strip(),
                ),
                location=_at(lineno),
                remedy=(
                    "stamp every record field before the "
                    "terminus"
                ),
            )
        key = (offset, stored_type)
        seen[key] = seen.get(key, 0) + 1
    for lineno, line, raw in program.body:
        if "= load " not in line:
            continue
        source = _load_source(line)
        if source is None:
            continue
        if source != reinterp and source not in gep_offsets:
            continue
        if lineno > terminus_lineno:
            raise AuditError(
                CODE_OPERANDS,
                "reservation load at %s follows the %s "
                "terminus at %s: nothing may use the "
                "reservation once released: %r"
                % (
                    _at(lineno),
                    terminus_shape,
                    _at(terminus_lineno),
                    raw.strip(),
                ),
                location=_at(lineno),
                remedy=(
                    "read every record field before the "
                    "terminus"
                ),
            )
    want = tuple(sorted(RESERVE_FIELD_STORES))
    got = tuple(sorted(seen))
    if got != want or any(count != 1 for count in seen.values()):
        raise AuditError(
            CODE_MAP_SHAPE,
            "the reservation emitter stamps its record fields "
            "through (offset, width) %s, but the stores carry "
            "%s"
            % (list(want), sorted(seen.items())),
            location=_at(terminus_lineno),
            remedy=(
                "store each record field once through the "
                "reservation record pointer"
            ),
        )


_EMPTY_OPERAND_RE = re.compile(r"\(i64\s+%(\S+)\)$")


def _check_core_operands(program):
    """Require the relocation read to take the checked map value.

    Only the core family is checked: its single relocation read
    must take the register reinterpretation of its single lookup
    result (the null-checked map value pointer), so the relocated
    load can only observe the audited map entry. Any other
    operand (a slot, a constant-derived pointer, another call's
    result) fails closed here. The existence check takes no
    operands (pinned by its call shape). Other families return
    early. Runs after the entry/family rule, so a checked program
    exports ``xdp_entry``.
    """
    if program.family != "core":
        return
    lookup_result = None
    for lineno, shape, match in program.calls:
        if shape == "lookup":
            lookup_result = match.group(1)
    for lineno, shape, match in program.calls:
        if shape != "coreread":
            continue
        name = match.group(2)
        if _def_shape(program, name) != "empty":
            raise AuditError(
                CODE_OPERANDS,
                "relocation read operand %%%s must be the checked "
                "reinterpretation of the lookup result, not defined "
                "at %s: call at %s"
                % (name, _at(program.defs.get(name, 0)), _at(lineno)),
                location=_at(lineno),
                remedy=(
                    "pass the checked map value pointer to the "
                    "relocation read"
                ),
            )
        defined = program.defs.get(name)
        origin = None
        for body_lineno, line, _raw in program.body:
            if body_lineno == defined:
                found = _EMPTY_OPERAND_RE.search(line)
                origin = found.group(1) if found else None
                break
        if origin != lookup_result:
            if origin is None:
                detail = "an unknown value"
            else:
                detail = "%%%s (defined at %s)" % (
                    origin,
                    _at(program.defs.get(origin, 0)),
                )
            raise AuditError(
                CODE_OPERANDS,
                "relocation read operand %%%s must reinterpret the "
                "lookup result %%%s, not %s: call at %s"
                % (name, lookup_result, detail, _at(lineno)),
                location=_at(lineno),
                remedy=(
                    "pass the checked map value pointer to the "
                    "relocation read"
                ),
            )


def _check_liveness(program):
    """No SSA value may be live across a lookup or update call.

    For every lookup- and update-call line, every SSA value
    defined before it must have no use after it. Operands of the
    call itself and the call result are not crossings: only a use
    strictly after the call of a value defined strictly before it
    violates the rule. Only lookup and update calls are roots:
    delete, PID/TID, clock, CPU, output, reservation, and
    terminus calls never are, so this check is vacuous for
    delete-only programs (their results are scalar statuses and
    every map address is reloaded fresh, so no kernel-derived
    value can cross there today).

    Combined programs are exempt: the packet workload's action
    selector and frame length necessarily cross helper calls, and
    SSA liveness alone cannot contain packet data anyway (values
    also cross through memory, which this check never saw). The
    tracepoint counter is exempt for the same structural reason:
    the filter value and the PID/TID result must both be live at
    their comparison, so one necessarily crosses the other's
    producing call. The uprobe counter is exempt for the same
    reason: the filter value and the extracted register value
    must both be live at their comparison, so one necessarily
    crosses the other's producing call. The event emitter is
    exempt for the same
    reason: the filter value, the helper results, and the sequence
    necessarily meet after their producing calls. The reservation
    emitter is exempt for the same reason: it shares the event
    shape with reservation-relative stores. The pointer-store
    dataflow check still rejects kernel addresses reaching stores
    in every mode, and the key-freshness check still proves every
    key buffer's value at its call in every mode: these
    exemptions never exempt either.
    """
    if program.mode in (
        "combined", "tracepoint", "event", "reserve", "uprobe",
    ):
        return
    helpers = [
        (lineno, shape)
        for lineno, shape, _ in program.calls
        if shape in ("lookup", "update")
    ]
    for call_lineno, shape in helpers:
        for name in sorted(
            program.defs, key=lambda n: (program.defs[n], n)
        ):
            defined = program.defs[name]
            if defined >= call_lineno:
                continue
            for used in sorted(program.uses.get(name, [])):
                if used > call_lineno:
                    raise AuditError(
                        CODE_LIVENESS,
                        "SSA value %%%s defined at %s is used at %s, "
                        "across the %s helper call at %s: values "
                        "must not be kept live across helper calls"
                        % (
                            name,
                            _at(defined),
                            _at(used),
                            shape,
                            _at(call_lineno),
                        ),
                        location=_at(call_lineno),
                        remedy=(
                            "recompute or reload every value used "
                            "after a helper call from state defined "
                            "after it"
                        ),
                    )


# Branch targets (``label %name`` operands on branch and switch
# lines) and phi incoming blocks (``[ value, %name ]`` entries):
# both name control-flow edges into the named block.
_EDGE_TARGET_RE = re.compile(r"label\s+%([A-Za-z0-9_.$-]+)")
_PHI_INCOMING_RE = re.compile(
    r"\[\s*[^,\[\]]+,\s*%([A-Za-z0-9_.$-]+)\s*\]"
)
# First tokens that end a block (a block whose last line carries
# none of these falls through to the next block in layout).
_TERMINATOR_TOKENS = frozenset(
    ["br", "ret", "switch", "unreachable"]
)


def _flow_graph(program):
    """Control-flow model of the entrypoint body.

    Block 0 is the entry block; block i + 1 carries the i-th
    label in line order. Successors are branch and switch
    targets plus layout fallthrough for unterminated non-empty
    blocks, with unresolvable target names kept so an unknown
    successor still breaks single-successor purity; an empty
    block is entered by fallthrough from the previous block (or
    starts the function, for an empty entry block).
    Predecessors invert those edges and add phi incoming blocks.
    A block with an unresolvable phi incoming block is impure:
    malformed control flow fails closed. Returns (succs, preds,
    impure, block_of, bounds, names).
    """
    bounds = sorted(program.label_lines)
    starts = [0] + bounds
    ends = bounds + [10 ** 18]
    names = [program.label_at[line] for line in bounds]
    succs = [set() for _ in starts]
    for index, (start, end) in enumerate(zip(starts, ends)):
        block_lines = [
            line for lineno, line, _ in program.body
            if start < lineno < end
        ]
        for line in block_lines:
            succs[index].update(_EDGE_TARGET_RE.findall(line))
        if not block_lines:
            if index:
                succs[index - 1].add(names[index - 1])
            elif names:
                succs[index].add(names[index])
        elif index + 1 < len(starts):
            first = block_lines[-1].split(None, 1)
            if not first or first[0] not in _TERMINATOR_TOKENS:
                succs[index].add(names[index])
    by_name = {name: index + 1 for index, name in enumerate(names)}
    preds = [set() for _ in starts]
    impure = set()
    for index, targets in enumerate(succs):
        for target in targets:
            if target in by_name:
                preds[by_name[target]].add(index)
    for index, (start, end) in enumerate(zip(starts, ends)):
        for lineno, line, _ in program.body:
            if start < lineno < end and "= phi " in line:
                for incoming in _PHI_INCOMING_RE.findall(line):
                    if incoming in by_name:
                        preds[index].add(by_name[incoming])
                    else:
                        impure.add(index)
    block_of = {}
    for index, (start, end) in enumerate(zip(starts, ends)):
        for lineno, _line, _raw in program.body:
            if start < lineno < end:
                block_of[lineno] = index
    return succs, preds, impure, block_of, bounds, names


# Opcodes that propagate a slot address to their result. From
# the LLVM LangRef, the admitted subset's pointer-carrying
# definitions are: getelementptr, the pointer casts (bitcast,
# addrspacecast), phi, select, and freeze (all preserve the
# operand address in the result), plus the aggregate and vector
# element opcodes (insertvalue/extractvalue,
# insertelement/extractelement), which launder a slot pointer
# through a container the matching extraction recovers. Vector
# element opcodes cannot carry a pointer here (only one-lane
# integer vectors are admitted and ptrtoint is refused), but
# they join the set defensively: if in doubt the proof fails
# closed.
_ALIAS_OPCODES = frozenset(
    [
        "getelementptr", "bitcast", "addrspacecast", "phi",
        "select", "freeze", "insertvalue", "extractvalue",
        "insertelement", "extractelement",
    ]
)


# Opcodes that provably break the address chain: loads yield the
# loaded data (never the address operand), comparisons yield
# one-bit predicates, and integer arithmetic, bitwise, and cast
# opcodes yield integers, which cannot address a store. Admitted
# calls are handled separately (they produce fresh addresses).
# Any defining opcode outside both sets is unrecognized and
# propagates conservatively (see _key_threats).
_NON_ALIAS_OPCODES = frozenset(
    [
        "load", "icmp", "fcmp", "add", "sub", "mul", "udiv",
        "sdiv", "urem", "srem", "shl", "lshr", "ashr", "and",
        "or", "xor", "trunc", "zext", "sext",
    ]
)


def _key_threats(program):
    """SSA names whose stores may write the shared key cell.

    Every key-slot preparation returns the same r10-4 cell, so a
    store through any key-slot result, or through a pointer
    derived from one, overwrites the prepared key. Pointers
    derived from the other audited slots (the value slot, the
    event views) are likewise threats: a nonzero-offset view may
    reach the key cell and this text route cannot prove
    otherwise, so ambiguous aliasing rejects conservatively.
    Only stores addressed directly through a value- or
    event-slot result are benign, and then only when the
    freshness check proves the store's width avoids the key cell
    (see _benign_slot_bases): those bases are disjoint from the
    key cell by their audited offsets, but a wide store through
    one still overlaps it.
    """
    benign = set()
    for _, shape, match in program.calls:
        if shape in ("valslot", "eventslot", "eventslotN"):
            benign.add(match.group(1))
    derived = set(program.key_of) | benign
    defs = {}
    for _, line, _raw in program.body:
        defined = SSA_DEF_RE.match(line)
        if defined:
            defs.setdefault(defined.group(1), line)
    changed = True
    while changed:
        changed = False
        for name, line in defs.items():
            if name in derived:
                continue
            if CALL_DETECT_RE.search(line):
                continue
            rhs = line.split("=", 1)[1].strip()
            opcode = rhs.split(None, 1)
            if not opcode:
                continue
            if opcode[0] not in _ALIAS_OPCODES:
                if opcode[0] in _NON_ALIAS_OPCODES:
                    continue
                # Unrecognized opcode: it may carry the slot
                # address to its result, so the proof fails
                # closed and treats it as aliasing.
            if any(op in derived for op in ssa_operands(line)):
                derived.add(name)
                changed = True
    return derived - benign


def _freshness_chain(preds, succs, impure, names, want, got):
    """Pure execution chain from block ``want`` to block ``got``.

    Execution leaving the prepared block must arrive at the
    consuming call with nothing able to run between them except
    the chain itself, whatever the layout order: every block from
    ``got`` back to ``want`` is entered through its sole
    predecessor, and that predecessor's sole successor edge
    targets the block. A sole-predecessor count alone is not
    enough: when layout differs from execution order, the counted
    edge may skip over a clobbering block laid out elsewhere. On
    success returns the intermediate blocks in execution order
    plus None; otherwise (None, failed block): a join, a
    dispatched arm entry, a loop back edge, an unreachable or
    malformed block, or a revisited block.
    """
    if want in impure or got in impure:
        if got in impure:
            return None, got
        return None, want
    chain = [got]
    seen = {got}
    while chain[-1] != want:
        current = chain[-1]
        if len(preds[current]) != 1:
            return None, current
        only = next(iter(preds[current]))
        if only in impure or only in seen:
            return None, current
        if len(succs[only]) != 1:
            return None, current
        if current == 0 or names[current - 1] not in succs[only]:
            return None, current
        chain.append(only)
        seen.add(only)
    chain.reverse()
    if len(chain) > 1:
        return chain[1:-1], None
    return [], None


# The shared key cell is the 4-byte slot at r10-4. A store
# through a directly-exempt slot base still clobbers the key
# when its byte range reaches the cell, so the exemption below
# is width-aware.
_KEY_CELL_BASE = 4

_INT_TYPE_RE = re.compile(r"^i(\d+)$")
_ARRAY_TYPE_RE = re.compile(r"^\[\s*(\d+)\s+x\s+(.+)\s*\]$")


def _type_width_bytes(text):
    """Byte footprint of a stored type, or None when unsized.

    Scalar integers round up to whole bytes and pointers are 8
    bytes; one-dimensional vectors and arrays of sized elements
    multiply out exactly (no inter-element padding). Struct
    types return None: their padding is datalayout-dependent, so
    the text route cannot size them and the freshness proof
    treats them as possibly overlapping. Anything else is
    likewise unsized, never silently narrow.
    """
    text = text.strip()
    if text == "ptr":
        return 8
    matched = _INT_TYPE_RE.match(text)
    if matched:
        return (int(matched.group(1)) + 7) // 8
    matched = VECTOR_TYPE_RE.fullmatch(text)
    if matched:
        if matched.group(1):
            return None
        element = _type_width_bytes(matched.group(3))
        if element is None:
            return None
        return int(matched.group(2)) * element
    matched = _ARRAY_TYPE_RE.match(text)
    if matched:
        element = _type_width_bytes(matched.group(2))
        if element is None:
            return None
        return int(matched.group(1)) * element
    return None


def _benign_slot_bases(program):
    """SSA name -> stack-base magnitude for directly-exempt slots.

    The value slot sits at r10-16, the event base at r10-64, and
    each event field view at its audited r10-relative offset; a
    store through one of these results is benign only when its
    width provably avoids the key cell (see _check_key_freshness).
    """
    bases = {}
    for _, shape, match in program.calls:
        if shape == "valslot":
            bases[match.group(1)] = 16
        elif shape == "eventslot":
            bases[match.group(1)] = 64
        elif shape == "eventslotN":
            bases[match.group(1)] = int(match.group(2))
    return bases


def _store_overlaps_key(base_magnitude, width):
    """Whether a width-byte store at r10-<base> reaches r10-4."""
    return width > base_magnitude - _KEY_CELL_BASE


def _check_key_freshness(program):
    """Every key-consuming call proves its key buffer's value.

    All key-slot shapes share the single r10-4 stack cell, so only
    the most recently executed preparation is live at any helper
    call: the SSA name on the key operand proves nothing by
    itself. For each lookup, update, and delete, the consumed
    preparation must reach the call along a pure execution chain
    (see _freshness_chain) with no other key-cell write between
    them in execution order: any second key-slot preparation
    overwrites the shared cell whatever literal it stores, and so
    does any store through the cell, addressed directly or
    through a derived or ambiguously-aliased pointer (stores are
    the only other memory write the audited subset admits: atomic
    read-modify-write operations and memory intrinsics are
    refused at scan time). A store addressed directly through
    one of the other audited slots stays benign only when its
    width provably avoids the key cell: a wide store through the
    value slot (r10-16) still overwrites r10-4, and an
    unsized-typed or unparsable store in the live region cannot
    prove disjointness, so both fail closed. A preparation in
    one arm consumed in another is refused even when no second
    preparation is visible. Runs after operand provenance, so
    every key operand is known to come from a key slot holding a
    recorded literal, and in every mode: the liveness exemptions
    never exempt key freshness.
    """
    succs, preds, impure, block_of, bounds, names = _flow_graph(
        program
    )
    threats = _key_threats(program)
    benign_bases = _benign_slot_bases(program)
    prep_of = {}
    for lineno, shape, match in program.calls:
        if shape in KEYSLOT_SHAPES:
            prep_of[lineno] = program.key_of[match.group(1)]
    for lineno, shape, match in program.calls:
        if shape not in ("lookup", "update", "delete"):
            continue
        key = match.group(3)
        defined = program.defs.get(key)
        if defined is None or defined >= lineno:
            raise AuditError(
                CODE_KEYFRESH,
                "%s key operand %%%s is consumed at %s before its "
                "preparation at %s: the shared key slot holds no "
                "proven value there"
                % (shape, key, _at(lineno), _at(defined or 0)),
                location=_at(lineno),
                remedy=(
                    "prepare each key immediately before the helper "
                    "call that consumes it"
                ),
            )
        want = block_of[defined]
        got = block_of[lineno]
        middles, failed = _freshness_chain(
            preds, succs, impure, names, want, got
        )
        if failed is not None:
            if failed:
                edge = "block label at %s" % _at(bounds[failed - 1])
            else:
                edge = "function entry"
            raise AuditError(
                CODE_KEYFRESH,
                "%s key operand %%%s was prepared at %s but consumed "
                "at %s across a control-flow edge (%s): "
                "the shared key slot may have been re-prepared on "
                "another path, so the call cannot prove it reads key "
                "%d" % (
                    shape, key, _at(defined), _at(lineno), edge,
                    program.key_of[key],
                ),
                location=_at(lineno),
                remedy=(
                    "prepare each key in the same block as the helper "
                    "call that consumes it"
                ),
            )
        if want == got:
            regions = [(want, defined, lineno)]
        else:
            regions = [(want, defined, 10 ** 18)]
            for block in middles:
                regions.append((block, 0, 10 ** 18))
            regions.append((got, 0, lineno))
        ordered = []
        for rank, (block, low, high) in enumerate(regions):
            for number, line, _raw in program.body:
                if block_of[number] == block and low < number < high:
                    ordered.append((rank, number, line))
        for _, number, line in sorted(ordered):
            if number in prep_of:
                literal = prep_of[number]
                consumed = program.key_of[key]
                if literal == consumed:
                    explanation = (
                        "%s key operand %%%s holds key %d prepared at "
                        "%s, but the key-slot preparation at %s "
                        "re-prepared the shared key slot before the "
                        "call at %s: the call cannot prove it still "
                        "reads key %d"
                        % (
                            shape, key, consumed, _at(defined),
                            _at(number), _at(lineno), consumed,
                        )
                    )
                else:
                    explanation = (
                        "%s key operand %%%s holds key %d prepared at "
                        "%s, but the key-slot preparation at %s "
                        "overwrote the shared key slot before the call "
                        "at %s: the call would read key %d, not key %d"
                        % (
                            shape, key, consumed, _at(defined),
                            _at(number), _at(lineno), literal,
                            consumed,
                        )
                    )
                raise AuditError(
                    CODE_KEYFRESH,
                    explanation,
                    location=_at(lineno),
                    remedy=(
                        "prepare each key immediately before the helper "
                        "call that consumes it, with no other key "
                        "preparation between them"
                    ),
                )
            if line.startswith("store "):
                parsed = _store_operands(line)
                if parsed is None:
                    raise AuditError(
                        CODE_KEYFRESH,
                        "%s key operand %%%s holds key %d prepared at "
                        "%s, but the store at %s before the call at "
                        "%s cannot be proven disjoint from the shared "
                        "key slot: the call cannot prove it still "
                        "reads key %d"
                        % (
                            shape, key, program.key_of[key],
                            _at(defined), _at(number),
                            _at(lineno), program.key_of[key],
                        ),
                        location=_at(lineno),
                        remedy=(
                            "prepare each key immediately before the "
                            "helper call that consumes it, with no "
                            "other key preparation or store to the key "
                            "slot between them"
                        ),
                    )
                stored_type, _stored_value, dest = parsed
                if dest in threats:
                    raise AuditError(
                        CODE_KEYFRESH,
                        "%s key operand %%%s holds key %d prepared at "
                        "%s, but the store at %s through %%%s may write "
                        "the shared key slot before the call at %s: the "
                        "call cannot prove it still reads key %d"
                        % (
                            shape, key, program.key_of[key],
                            _at(defined), _at(number), dest,
                            _at(lineno), program.key_of[key],
                        ),
                        location=_at(lineno),
                        remedy=(
                            "prepare each key immediately before the "
                            "helper call that consumes it, with no "
                            "other key preparation or store to the key "
                            "slot between them"
                        ),
                    )
                if dest in benign_bases:
                    width = _type_width_bytes(stored_type)
                    if width is None:
                        raise AuditError(
                            CODE_KEYFRESH,
                            "%s key operand %%%s holds key %d prepared "
                            "at %s, but the store at %s through %%%s "
                            "has type %s with unknown size that may "
                            "overlap the shared key slot before the "
                            "call at %s: the call cannot prove it "
                            "still reads key %d"
                            % (
                                shape, key, program.key_of[key],
                                _at(defined), _at(number), dest,
                                stored_type, _at(lineno),
                                program.key_of[key],
                            ),
                            location=_at(lineno),
                            remedy=(
                                "prepare each key immediately before "
                                "the helper call that consumes it, with "
                                "no other key preparation or store to "
                                "the key slot between them"
                            ),
                        )
                    if _store_overlaps_key(benign_bases[dest], width):
                        raise AuditError(
                            CODE_KEYFRESH,
                            "%s key operand %%%s holds key %d prepared "
                            "at %s, but the store at %s through %%%s "
                            "writes %d bytes overlapping the shared key "
                            "slot before the call at %s: the call "
                            "cannot prove it still reads key %d"
                            % (
                                shape, key, program.key_of[key],
                                _at(defined), _at(number), dest,
                                width, _at(lineno),
                                program.key_of[key],
                            ),
                            location=_at(lineno),
                            remedy=(
                                "prepare each key immediately before "
                                "the helper call that consumes it, with "
                                "no other key preparation or store to "
                                "the key slot between them"
                            ),
                        )


def _check_roots(program):
    """Every used SSA value must have a definition.

    A use without a definition would otherwise surface only as a
    backend parse error, so the audit rejects it with its own code.
    Block names defined by label lines are excluded: ``phi``
    successor operands name blocks without the ``label`` keyword
    and therefore read as SSA uses.
    """
    for name in sorted(
        program.uses, key=lambda n: (min(program.uses[n]), n)
    ):
        if name in program.defs or name in program.labels:
            continue
        used = min(program.uses[name])
        raise AuditError(
            CODE_UNDEFINED,
            "SSA value %%%s is used at %s but never defined"
            % (name, _at(used)),
            location=_at(used),
            remedy="define every used value exactly once",
        )


# Opcodes whose results carry no lookup taint: loads read stored
# data (breaking the chain from the lookup result, which is what
# lets the reviewed round trip store load-derived sums), while
# comparisons yield one-bit predicates rather than addresses.
_UNTAINTED_OPCODES = frozenset(["load", "icmp", "fcmp"])

_STORE_DEST_RE = re.compile(r"^ptr\s+%([A-Za-z0-9_.$-]+)")


_STORE_TYPE_CLOSERS = {"<": ">", "{": "}", "[": "]"}


def _split_store_type(rest):
    """Split stored-type from the remainder of a store line.

    Vector (``<...>``), struct (``{...}``) and array (``[...]``)
    stored types scan to the balanced closer so an aggregate
    store never splits mid-type; anything else splits on the
    first whitespace run.
    """
    rest = rest.strip()
    if rest[:1] in _STORE_TYPE_CLOSERS:
        opener = rest[0]
        closer = _STORE_TYPE_CLOSERS[opener]
        depth = 0
        for index, char in enumerate(rest):
            if char == opener:
                depth += 1
            elif char == closer:
                depth -= 1
                if depth == 0:
                    return rest[: index + 1], rest[index + 1 :].strip()
        return None, None
    parts = rest.split(None, 1)
    if len(parts) != 2:
        return None, None
    return parts[0], parts[1]


def _split_top_level_comma(text):
    """Split text at its first comma outside any brackets.

    Aggregate (`{...}`), array (`[...]`), vector (`<...>`), and
    constant-expression (`(...)`) spellings nest commas that a
    plain split would mistake for the operand separator, so the
    scan tracks all four depths and splits only at depth zero.
    Returns (before, after) stripped, or (None, None) when no
    top-level comma exists.
    """
    depths = {"{": 0, "[": 0, "<": 0, "(": 0}
    closers = {"}": "{", "]": "[", ">": "<", ")": "("}
    for index, char in enumerate(text):
        if char in depths:
            depths[char] += 1
        elif char in closers:
            depths[closers[char]] -= 1
        elif char == "," and not any(depths.values()):
            return text[:index].strip(), text[index + 1 :].strip()
    return None, None


def _store_operands(line):
    """Split a store line into (stored type, stored value, dest name).

    The stored value splits from the destination at the first
    top-level comma, so an aggregate value (``store {i16, i16}
    {i16 1, i16 0}, ptr %2, ...``) parses instead of vanishing:
    a clobbering aggregate write is analyzed, never skipped.
    Returns None for anything that does not parse as a
    ``ptr %name``-addressed store; callers decide how an
    unprovable destination fails (the freshness proof fails
    closed, since it cannot show disjointness from the key cell).
    """
    rest = line[len("store ") :]
    while True:
        keyword = rest.split(None, 1)
        if keyword and keyword[0] in ("atomic", "volatile"):
            rest = keyword[1] if len(keyword) == 2 else ""
            continue
        break
    stored_type, rest = _split_store_type(rest)
    if stored_type is None:
        return None
    stored_value, after = _split_top_level_comma(rest)
    if stored_value is None:
        return None
    match = _STORE_DEST_RE.match(after.strip())
    if not stored_value or match is None:
        return None
    return stored_type, stored_value, match.group(1)


def _is_load_line(line):
    """Whether a normalized body line is an SSA load definition.

    Opcode-based: any defining line whose right-hand side starts
    with the ``load`` opcode reads memory, whatever the pointer
    operand spelling (``ptr %x``, ``ptr null``, constant
    expressions). The subprogram purity gate uses this so no
    operand spelling can bypass it; ``_load_source`` keeps
    serving checks that need the source SSA name.
    """
    defined, sep, rhs = line.partition("=")
    if not sep or not defined.strip().startswith("%"):
        return False
    opcode = rhs.strip().split(None, 1)
    return bool(opcode) and opcode[0] == "load"


def _load_source(line):
    """Return the pointer SSA name a load line reads through.

    The loaded type splits from the address at the first
    top-level comma, so an aggregate load (``load {i16, i16},
    ptr %p, ...``) resolves instead of vanishing. Returns None
    for anything that does not parse as a ``ptr %name``-addressed
    load; the audit never invents a violation from an
    unparsable line here.
    """
    defined, sep, rhs = line.partition("=")
    if not sep or not defined.strip().startswith("%"):
        return None
    rest = rhs.strip()
    if not rest.startswith("load "):
        return None
    rest = rest[len("load ") :]
    while True:
        keyword = rest.split(None, 1)
        if keyword and keyword[0] in ("atomic", "volatile"):
            rest = keyword[1] if len(keyword) == 2 else ""
            continue
        break
    _loaded_type, after = _split_top_level_comma(rest)
    if _loaded_type is None:
        return None
    match = _STORE_DEST_RE.match(after.strip())
    if match is None:
        return None
    return match.group(1)


def _definition_tainted(line, tainted):
    """Whether one defining line propagates lookup taint to its result."""
    if CALL_DETECT_RE.search(line):
        # Only admitted call shapes reach this check. Slot and map
        # loads produce fresh addresses, the update call a fresh
        # status; only the reinterpretation of a tainted integer
        # stays tainted as a pointer.
        if match_shape(line) != "empty":
            return False
        return any(name in tainted for name in ssa_operands(line))
    parts = line.split("=", 1)
    rhs = parts[1].strip() if len(parts) == 2 else ""
    opcode = rhs.split(None, 1)
    if not opcode or opcode[0] in _UNTAINTED_OPCODES:
        return False
    return any(name in tainted for name in ssa_operands(line))


def _lookup_taint(program):
    """SSA values derived from a lookup or reservation result.

    The lookup result is a nullable kernel address carried as an
    integer, as is the reservation result; taint follows both
    through dataflow to a fixpoint so laundering either through
    arithmetic, casts, or the reinterpretation call cannot hide
    a store. The terminus results are likewise tainted: the
    kernel returns nothing there, so any value they carry is
    meaningless and must never be stored. Loads break the chain
    (stored data is data), comparisons yield untainted
    predicates, and other non-reinterpretation call results are
    fresh.
    """
    tainted = set()
    for _, shape, match in program.calls:
        if shape in ("lookup", "reserve", "submit", "discard"):
            tainted.add(match.group(1))
    defs = {}
    for _, line, _raw in program.body:
        defined = SSA_DEF_RE.match(line)
        if defined:
            defs.setdefault(defined.group(1), line)
    changed = True
    while changed:
        changed = False
        for name, line in defs.items():
            if name in tainted:
                continue
            if _definition_tainted(line, tainted):
                tainted.add(name)
                changed = True
    return tainted


def _store_sink(program, tainted, dest):
    """Plain-language name for a store destination."""
    if dest in tainted:
        return "map memory"
    if _def_shape(program, dest) == "valslot":
        return "the update value buffer"
    return "a map slot"


def _check_pointer_stores(program):
    """Reject lookup-derived or pointer-typed values reaching stores.

    A stored lookup result (directly, or laundered through
    arithmetic, casts, or the value slot feeding the update call)
    would persist a kernel address into map state where it can be
    read back; a stored pointer-typed value can only be an address
    as well. Runs last, so every earlier check has already passed.
    """
    tainted = _lookup_taint(program)
    for lineno, line, raw in program.body:
        if not line.startswith("store "):
            continue
        parsed = _store_operands(line)
        if parsed is None:
            continue
        stored_type, stored_value, dest = parsed
        sink = _store_sink(program, tainted, dest)
        if stored_type == "ptr":
            raise AuditError(
                CODE_PTRSTORE,
                "pointer-typed value stored into %s; only scalars "
                "may be written there: %r" % (sink, raw.strip()),
                location=_at(lineno),
                remedy=_remedy_for(CODE_PTRSTORE),
            )
        if stored_value.startswith("%") and stored_value[1:] in tainted:
            raise AuditError(
                CODE_PTRSTORE,
                "lookup-derived value %s stored into %s would persist "
                "a kernel address: %r"
                % (stored_value, sink, raw.strip()),
                location=_at(lineno),
                remedy=_remedy_for(CODE_PTRSTORE),
            )


def validate(text):
    """Audit raw frontend IR; return the program mode.

    Returns ``"classifier"``, ``"classifier-loop"``, ``"map"``,
    ``"combined"``, ``"tracepoint"``, ``"event"``,
    ``"reserve"``, ``"subprog"``, ``"core"``, ``"uprobe"``, or
    ``"skb"`` for admitted input and raises AuditError naming
    the first violated check otherwise.
    """
    return scan(text).mode


LOWERED_LOOKUP_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+inttoptr\s+\(i64 1 to ptr\)"
    r"\(i64\s+%(\S+),\s+ptr\s+%(\S+)\)$"
)
LOWERED_UPDATE_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+inttoptr\s+\(i64 2 to ptr\)"
    r"\(i64\s+%(\S+),\s+ptr\s+%(\S+),\s+ptr\s+%(\S+),\s+i64 0\)$"
)
LOWERED_DELETE_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+inttoptr\s+\(i64 3 to ptr\)"
    r"\(i64\s+%(\S+),\s+ptr\s+%(\S+)\)$"
)
LOWERED_PID_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+inttoptr\s+\(i64 14 to ptr\)\(\)$"
)
LOWERED_KTIME_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+inttoptr\s+\(i64 5 to ptr\)\(\)$"
)
LOWERED_CPU_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+inttoptr\s+\(i64 8 to ptr\)\(\)$"
)
LOWERED_OUTPUT_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+inttoptr\s+\(i64 130 to ptr\)"
    r"\(i64\s+%(\S+),\s+ptr\s+%(\S+),\s+i64 32,\s+i64 0\)$"
)
LOWERED_RESERVE_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+inttoptr\s+\(i64 131 to ptr\)"
    r"\(i64\s+%(\S+),\s+i64 32,\s+i64 0\)$"
)
LOWERED_SUBMIT_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+inttoptr\s+\(i64 132 to ptr\)"
    r"\(ptr\s+%(\S+),\s+i64 0\)$"
)
LOWERED_DISCARD_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+inttoptr\s+\(i64 133 to ptr\)"
    r"\(ptr\s+%(\S+),\s+i64 0\)$"
)
LOWERED_SKBLOAD_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+inttoptr\s+\(i64 26 to ptr\)"
    r"\(ptr\s+%(\S+),\s+i32\s+(?:%\S+|\d+),\s+ptr\s+%(\S+),"
    r"\s+i32\s+(?:%\S+|\d+)\)$"
)
LOWERED_SKBSTORE_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i64\s+inttoptr\s+\(i64 9 to ptr\)"
    r"\(ptr\s+%(\S+),\s+i32\s+(?:%\S+|\d+),\s+ptr\s+%(\S+),"
    r"\s+i32\s+(?:%\S+|\d+),\s+i64 0\)$"
)
# Lowered relocation-expansion lines (core mode only). The field
# read is a relocation-global load, a passthrough with default 0,
# a zero extension, an address computation off the checked map
# value, and the relocated u32 load; the existence check is a
# relocation-global load plus a passthrough with default 1. Group
# 1 of every pattern is the defined SSA name; later groups bind
# the threaded operands, which the post check ties together.
CORE_POST_READ_LOAD_RE = re.compile(
    r"^%(\S+)\s*=\s*load\s+i32,\s*ptr\s+"
    r"@\"llvm\.task_struct:0:32\$0:1\",\s*align 4$"
)
CORE_POST_READ_PASS_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i32\s+"
    r"@llvm\.bpf\.passthrough\.i32\.i32\(i32 0,\s*i32 %(\S+)\)$"
)
CORE_POST_READ_ZEXT_RE = re.compile(
    r"^%(\S+)\s*=\s*zext\s+i32 %(\S+) to i64$"
)
CORE_POST_READ_GEP_RE = re.compile(
    r"^%(\S+)\s*=\s*getelementptr\s+i8,\s*ptr %(\S+),\s*i64 %(\S+)$"
)
CORE_POST_READ_VLOAD_RE = re.compile(
    r"^%(\S+)\s*=\s*load\s+i32,\s*ptr %(\S+),\s*align 4$"
)
CORE_POST_EX_LOAD_RE = re.compile(
    r"^%(\S+)\s*=\s*load\s+i32,\s*ptr\s+"
    r"@\"llvm\.task_struct:2:1\$0:4\",\s*align 4$"
)
CORE_POST_EX_PASS_RE = re.compile(
    r"^%(\S+)\s*=\s*call\s+i32\s+"
    r"@llvm\.bpf\.passthrough\.i32\.i32\(i32 1,\s*i32 %(\S+)\)$"
)


def body_lines(text):
    """Comment-stripped body lines between define and close."""
    lines = []
    in_body = False
    for raw in text.splitlines():
        line = strip_comment(raw).strip()
        if line.startswith("define "):
            in_body = True
            continue
        if line == "}":
            in_body = False
            continue
        if in_body and line and not line.startswith("!"):
            lines.append(line)
    return lines


def _check_core_expansion_post(adapted):
    """Require the exact lowered relocation expansions (core mode).

    Each expansion line must match its audit-owned pattern exactly
    once, the threaded SSA names must chain (passthrough takes the
    relocation load, the extension takes the passthrough, the
    address computation takes the extension and the checked map
    value, the value load takes the address), the address base
    must be a name the preserved reinterpretation defines, and
    both final values must be used downstream. The module scope
    must carry exactly the two relocation globals, the
    passthrough declaration, and the synthesis markers (compile
    unit, task and map composites, entry subprogram). Anything
    else is an adapter bug, never admitted silently.
    """
    body = body_lines(adapted)
    found = {
        "read_load": [],
        "read_pass": [],
        "read_zext": [],
        "read_gep": [],
        "read_vload": [],
        "ex_load": [],
        "ex_pass": [],
    }
    for lineno, line in enumerate(body, 1):
        for key, pattern in (
            ("read_load", CORE_POST_READ_LOAD_RE),
            ("read_pass", CORE_POST_READ_PASS_RE),
            ("read_zext", CORE_POST_READ_ZEXT_RE),
            ("read_gep", CORE_POST_READ_GEP_RE),
            ("read_vload", CORE_POST_READ_VLOAD_RE),
            ("ex_load", CORE_POST_EX_LOAD_RE),
            ("ex_pass", CORE_POST_EX_PASS_RE),
        ):
            matched = pattern.match(line)
            if matched:
                found[key].append((lineno, matched))
    for key in found:
        if len(found[key]) != 1:
            raise AuditError(
                CODE_CALL_FORM,
                "lowered core IR carries %d relocation %s lines, "
                "expected exactly 1" % (len(found[key]), key),
                location=None,
                remedy="report this adapter failure as a bug",
            )
    groups = {key: found[key][0][1] for key in found}
    threads = (
        ("read_pass", 2, "read_load", 1),
        ("read_zext", 2, "read_pass", 1),
        ("read_gep", 3, "read_zext", 1),
        ("read_vload", 2, "read_gep", 1),
        ("ex_pass", 2, "ex_load", 1),
    )
    for user_key, user_group, def_key, def_group in threads:
        user = groups[user_key].group(user_group)
        defined = groups[def_key].group(def_group)
        if user != defined:
            raise AuditError(
                CODE_CALL_FORM,
                "lowered relocation SSA is unthreaded: %s takes "
                "%%%s but %s defines %%%s"
                % (user_key, user, def_key, defined),
                location=None,
                remedy="report this adapter failure as a bug",
            )
    reinterps = set()
    for line in body:
        matched = ASM_CALL_RE.match(line)
        if matched:
            reinterps.add(matched.group(1))
    base = groups["read_gep"].group(2)
    if base not in reinterps:
        raise AuditError(
            CODE_CALL_FORM,
            "lowered relocation address base %%%s is not the "
            "preserved reinterpretation" % (base,),
            location=None,
            remedy="report this adapter failure as a bug",
        )
    uses: dict[str, int] = {}
    for line in body:
        for name in ssa_operands(line):
            uses[name] = uses.get(name, 0) + 1
    for key in ("read_vload", "ex_pass"):
        final = groups[key].group(1)
        if uses.get(final, 0) < 1:
            raise AuditError(
                CODE_CALL_FORM,
                "lowered relocation result %%%s is never used" % (final,),
                location=None,
                remedy="report this adapter failure as a bug",
            )
    read_global = (
        '@"llvm.task_struct:0:32$0:1" = external global i32, '
        "!llvm.preserve.access.index"
    )
    ex_global = (
        '@"llvm.task_struct:2:1$0:4" = external global i32, '
        "!llvm.preserve.access.index"
    )
    passthrough_decl = (
        "declare i32 @llvm.bpf.passthrough.i32.i32(i32, i32)"
    )
    for marker, want in (
        (read_global, 1),
        (ex_global, 1),
        (passthrough_decl, 1),
        ("!llvm.dbg.cu =", 1),
        ('name: "task_struct"', 1),
        ('name: "pid"', 1),
        ('name: "scx"', 1),
        ('name: "mojobpf_map0"', 1),
        ('!DISubprogram(name: "xdp_entry"', 1),
        ("!DISubrange(count: 4096)", 1),
    ):
        if adapted.count(marker) != want:
            raise AuditError(
                CODE_CALL_FORM,
                "lowered core IR carries %d occurrences of %r, "
                "expected %d" % (adapted.count(marker), marker, want),
                location=None,
                remedy="report this adapter failure as a bug",
            )


def audit_post(adapted, mode):
    """Audit adapted IR after the lowering transform.

    Requires exactly the lowered helper callees for the mode and no
    remaining reserved references or helper assembly. The core mode
    additionally requires the exact relocation expansions. The
    caller additionally runs :func:`check_graph_preserved` over the
    raw and adapted bodies.
    """
    for lineno, raw in enumerate(adapted.splitlines(), 1):
        line = strip_comment(raw).strip()
        for reserved in RESERVED_NAMES:
            if reserved in line:
                raise AuditError(
                    CODE_EXTERNAL,
                    "lowered IR still references %s: %r"
                    % (reserved, raw.strip()),
                    location=_at(lineno),
                    remedy="report this adapter failure as a bug",
                )
        if HELPER_ASM_RE.search(line):
            raise AuditError(
                CODE_CALL_FORM,
                "lowered IR still invokes a helper through inline "
                "assembly: %r" % (raw.strip(),),
                location=_at(lineno),
                remedy="report this adapter failure as a bug",
            )
    lowered = {
        "lookup": 0,
        "update": 0,
        "delete": 0,
        "pid": 0,
        "ktime": 0,
        "cpu": 0,
        "output": 0,
        "reserve": 0,
        "submit": 0,
        "discard": 0,
        "skbload": 0,
        "skbstore": 0,
    }
    for lineno, raw in enumerate(adapted.splitlines(), 1):
        line = strip_comment(raw).strip()
        if "inttoptr" in line:
            if LOWERED_LOOKUP_RE.match(line):
                lowered["lookup"] += 1
            elif LOWERED_UPDATE_RE.match(line):
                lowered["update"] += 1
            elif LOWERED_DELETE_RE.match(line):
                lowered["delete"] += 1
            elif LOWERED_PID_RE.match(line):
                lowered["pid"] += 1
            elif LOWERED_KTIME_RE.match(line):
                lowered["ktime"] += 1
            elif LOWERED_CPU_RE.match(line):
                lowered["cpu"] += 1
            elif LOWERED_OUTPUT_RE.match(line):
                lowered["output"] += 1
            elif LOWERED_RESERVE_RE.match(line):
                lowered["reserve"] += 1
            elif LOWERED_SUBMIT_RE.match(line):
                lowered["submit"] += 1
            elif LOWERED_DISCARD_RE.match(line):
                lowered["discard"] += 1
            elif LOWERED_SKBLOAD_RE.match(line):
                lowered["skbload"] += 1
            elif LOWERED_SKBSTORE_RE.match(line):
                lowered["skbstore"] += 1
            else:
                raise AuditError(
                    CODE_CALL_FORM,
                    "lowered helper callee deviates from the exact "
                    "inttoptr(ID) form with ID 1, 2, 3, 5, 8, 9, "
                    "14, 26, 130, 131, 132, or 133: %r"
                    % (raw.strip(),),
                    location=_at(lineno),
                    remedy="report this adapter failure as a bug",
                )
    if mode == "core":
        want_core = {
            "lookup": 1, "update": 0, "delete": 0, "pid": 0,
            "ktime": 0, "cpu": 0, "output": 0, "reserve": 0,
            "submit": 0, "discard": 0, "skbload": 0,
            "skbstore": 0,
        }
        if lowered != want_core:
            raise AuditError(
                CODE_EXTERNAL,
                "lowered IR has helper-call counts %r, expected %r"
                % (lowered, want_core),
                location=None,
                remedy="report this adapter failure as a bug",
            )
        _check_core_expansion_post(adapted)
        return
    if mode == "map":
        pairs = lowered["lookup"] == lowered["update"] >= 1
        bare = (
            lowered["delete"] == 0
            and lowered["pid"] == 0
            and lowered["ktime"] == 0
            and lowered["cpu"] == 0
            and lowered["output"] == 0
            and lowered["reserve"] == 0
            and lowered["submit"] == 0
            and lowered["discard"] == 0
            and lowered["skbload"] == 0
            and lowered["skbstore"] == 0
        )
        deletes = (
            lowered["delete"] >= 1
            and lowered["lookup"] == 0
            and lowered["update"] == 0
            and lowered["pid"] == 0
            and lowered["ktime"] == 0
            and lowered["cpu"] == 0
            and lowered["output"] == 0
            and lowered["reserve"] == 0
            and lowered["submit"] == 0
            and lowered["discard"] == 0
            and lowered["skbload"] == 0
            and lowered["skbstore"] == 0
        )
        if (pairs and bare) or deletes:
            return
        raise AuditError(
            CODE_EXTERNAL,
            "lowered IR has helper-call counts %r, expected one "
            "map family (N pairs or N deletions)" % (lowered,),
            location=None,
            remedy="report this adapter failure as a bug",
        )
    if mode == "reserve":
        base = (
            lowered["lookup"] == 4
            and lowered["update"] == 3
            and lowered["delete"] == 0
            and lowered["pid"] == 2
            and lowered["ktime"] == 1
            and lowered["cpu"] == 1
            and lowered["output"] == 0
            and lowered["reserve"] == 1
            and lowered["skbload"] == 0
            and lowered["skbstore"] == 0
        )
        terminus = (
            (lowered["submit"], lowered["discard"]) in ((1, 0), (0, 1))
        )
        if base and terminus:
            return
        raise AuditError(
            CODE_EXTERNAL,
            "lowered IR has helper-call counts %r, expected the "
            "reservation shape (4 lookups, 3 updates, 2 pid, 1 "
            "ktime, 1 cpu, 1 reserve, and one terminus)"
            % (lowered,),
            location=None,
            remedy="report this adapter failure as a bug",
        )
    if mode == "skb":
        rest_zero = (
            lowered["lookup"] == 0
            and lowered["delete"] == 0
            and lowered["pid"] == 0
            and lowered["ktime"] == 0
            and lowered["cpu"] == 0
            and lowered["output"] == 0
            and lowered["reserve"] == 0
            and lowered["submit"] == 0
            and lowered["discard"] == 0
        )
        mapless = (
            lowered["update"] == 0
            and (lowered["skbload"], lowered["skbstore"])
            in ((1, 0), (0, 1))
        )
        loadmap = (
            lowered["update"] == 1
            and lowered["skbload"] == 1
            and lowered["skbstore"] == 0
        )
        if rest_zero and (mapless or loadmap):
            return
        raise AuditError(
            CODE_EXTERNAL,
            "lowered IR has helper-call counts %r, expected one "
            "skb load, one skb store, or one skb load plus one "
            "map update" % (lowered,),
            location=None,
            remedy="report this adapter failure as a bug",
        )
    if mode == "combined":
        want = {
            "lookup": 2, "update": 2, "delete": 0, "pid": 0,
            "ktime": 0, "cpu": 0, "output": 0, "reserve": 0,
            "submit": 0, "discard": 0, "skbload": 0,
            "skbstore": 0,
        }
    elif mode == "tracepoint":
        want = {
            "lookup": 2, "update": 1, "delete": 0, "pid": 1,
            "ktime": 0, "cpu": 0, "output": 0, "reserve": 0,
            "submit": 0, "discard": 0, "skbload": 0,
            "skbstore": 0,
        }
    elif mode == "uprobe":
        want = {
            "lookup": 2, "update": 1, "delete": 0, "pid": 0,
            "ktime": 0, "cpu": 0, "output": 0, "reserve": 0,
            "submit": 0, "discard": 0, "skbload": 0,
            "skbstore": 0,
        }
    elif mode == "event":
        want = {
            "lookup": 4, "update": 3, "delete": 0, "pid": 2,
            "ktime": 1, "cpu": 1, "output": 1, "reserve": 0,
            "submit": 0, "discard": 0, "skbload": 0,
            "skbstore": 0,
        }
    elif mode == "subprog":
        want = {
            "lookup": 0, "update": 0, "delete": 0, "pid": 0,
            "ktime": 0, "cpu": 0, "output": 0, "reserve": 0,
            "submit": 0, "discard": 0, "skbload": 0,
            "skbstore": 0,
        }
    else:
        want = {
            "lookup": 0, "update": 0, "delete": 0, "pid": 0,
            "ktime": 0, "cpu": 0, "output": 0, "reserve": 0,
            "submit": 0, "discard": 0, "skbload": 0,
            "skbstore": 0,
        }
    if lowered != want:
        raise AuditError(
            CODE_EXTERNAL,
            "lowered IR has helper-call counts %r, expected %r"
            % (lowered, want),
            location=None,
            remedy="report this adapter failure as a bug",
        )


def check_graph_preserved(raw_body, adapted_body, lowered,
                          expanded=None):
    """Require byte-identical bodies outside the admitted edits.

    ``lowered`` maps raw lowered-call lines to their expected
    adapted form; ``expanded`` (core mode only) maps raw
    relocation-call lines to their expected adapted line tuples.
    Every other adapted body line must equal its raw counterpart
    in order.
    """
    expanded = expanded or {}
    if not expanded and len(raw_body) != len(adapted_body):
        raise AuditError(
            CODE_FALLBACK,
            "lowering changed the body length (%d raw lines, %d "
            "adapted lines)"
            % (len(raw_body), len(adapted_body)),
            location=None,
            remedy="report this adapter failure as a bug",
        )
    if not expanded:
        pairs = [
            (raw_line, lowered.get(raw_line, raw_line))
            for raw_line in raw_body
        ]
        for index, (raw_line, want) in enumerate(pairs):
            if adapted_body[index] != want:
                raise AuditError(
                    CODE_FALLBACK,
                    "lowering altered body line %d beyond the "
                    "admitted callee edit: %r -> %r"
                    % (index + 1, raw_line, adapted_body[index]),
                    location=None,
                    remedy="report this adapter failure as a bug",
                )
        return
    want_lines: list[str] = []
    for raw_line in raw_body:
        if raw_line in expanded:
            want_lines.extend(expanded[raw_line])
        else:
            want_lines.append(lowered.get(raw_line, raw_line))
    if adapted_body != want_lines:
        for index, (want, got) in enumerate(
            zip(want_lines, adapted_body)
        ):
            if want != got:
                raise AuditError(
                    CODE_FALLBACK,
                    "lowering altered body line %d beyond the "
                    "admitted edits: %r -> %r"
                    % (index + 1, want, got),
                    location=None,
                    remedy="report this adapter failure as a bug",
                )
        raise AuditError(
            CODE_FALLBACK,
            "lowering changed the body length (%d raw lines, %d "
            "adapted lines, %d expected)"
            % (len(raw_body), len(adapted_body), len(want_lines)),
            location=None,
            remedy="report this adapter failure as a bug",
        )
