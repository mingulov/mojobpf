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
  ``@xdp_entry(ptr...)`` or ``@trace_entry(ptr...)``;
* module scope limited to ``source_filename``, the target lines,
  attribute group ``#0``, and at most the four reserved helper
  declarations below (no globals, no other declarations, no
  module-level assembly);
* body calls limited to seven exact inline-assembly shapes (register
  reinterpretation, map-address load, key-slot preparation for key 0,
  key-slot preparation for key 1, key-slot preparation for keys 2
  and above, the per-CPU kind tag, and value-slot preparation)
  plus direct calls to the four reserved helper declarations;
* exactly one of the classifier, the map round trip, the combined
  packet workload, or the tracepoint counter count vector (all
  frozen), or one map count family over dense keys 0..N-1: N
  read-modify-write pairs (one lookup plus one update per key) or
  N deletions (one per key). The tracepoint vector is one filter
  read (key 0), one current-PID/TID call, and one count pair
  (key 1), and its entry parameter stays unused: tracepoint
  programs read no context payload fields;
* helper-call operands: the map address comes from a map load, the
  key/value pointers come from the prepared slots, update flags are
  the literal ``0``, and the PID/TID call takes no operands; in
  multi-pair shapes the i-th lookup and the i-th update reference
  the same key, while the tracepoint shape reads key 0 then pairs
  key 1;
* no value defined before a helper call is used after it
  (cross-call liveness), except in the combined vector, whose
  action selector and frame length necessarily cross helper calls,
  and in the tracepoint vector, whose filter value and PID/TID
  result necessarily meet at the comparison after their producing
  calls (kernel-address stores stay rejected by the pointer-store
  dataflow check in every mode);
* every used SSA value is defined on the define line or an
  earlier body line, except bare block references (undefined
  roots);
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
helper callee is exactly ``inttoptr (i64 ID to ptr)`` with ``ID`` 1
to 3 or 14 and the registered signature, that no reserved
pseudo-call reference remains, and that the instruction graph is
otherwise byte-identical to the validated input. The kernel offers
no from-program map-iteration helper, so no iteration callee
exists.

Standard library only.
"""

import re

STAGE_AUDIT = "adapter.audit"

# Diagnostic codes. MBPF301 is the coarse fallback for adapter-side
# failures without a narrower code (kept for wire compatibility);
# MBPF302-MBPF317 name the violated check.
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
# kernel-faithful long name below. The PID/TID spelling is selected
# the same way by the tracepoint counter until shared tracing
# vocabulary is versioned into the SDK.)
LOOKUP_NAME = "__mojobpf_lookup_v1"
UPDATE_NAME = "__mojobpf_update_v1"
DELETE_NAME = "__mojobpf_delete_elem_v1"
PID_NAME = "__mojobpf_get_pid_tgid_v1"
RESERVED_NAMES = (LOOKUP_NAME, UPDATE_NAME, DELETE_NAME, PID_NAME)
LOOKUP_DECL_LINE = "declare i64 @__mojobpf_lookup_v1(i64, ptr) #0"
UPDATE_DECL_LINE = "declare i64 @__mojobpf_update_v1(i64, ptr, ptr, i64) #0"
DELETE_DECL_LINE = "declare i64 @__mojobpf_delete_elem_v1(i64, ptr) #0"
PID_DECL_LINE = "declare i64 @__mojobpf_get_pid_tgid_v1() #0"
DECL_LINES = {
    "lookup": LOOKUP_DECL_LINE,
    "update": UPDATE_DECL_LINE,
    "delete": DELETE_DECL_LINE,
    "pid": PID_DECL_LINE,
}
# Ordinary BPF helper-call callees the adapter substitutes (helper
# IDs 1 to 3 and 14 with the registered signatures).
LOWERED_CALLEE = {
    "lookup": "inttoptr (i64 1 to ptr)",
    "update": "inttoptr (i64 2 to ptr)",
    "delete": "inttoptr (i64 3 to ptr)",
    "pid": "inttoptr (i64 14 to ptr)",
}

# Admitted body-call shapes. The seven assembly shapes are exact
# single lines (see the adapter contract); the four helper shapes are
# direct calls to the reserved declarations with exactly the
# signatures above, no attributes, and no operand bundles.
# Group 1 of every shape below is the result SSA name; the helper
# shapes add one group per operand in order (the PID/TID call takes
# none), and the keyslotN shape adds the key literal as group 2.
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
ASM_SHAPES = (
    ("empty", ASM_CALL_RE),
    ("mapaddr", MAPADDR_CALL_RE),
    ("keyslot", KEYSLOT_CALL_RE),
    ("keyslot1", KEYSLOT1_CALL_RE),
    ("keyslotN", KEYSLOTN_CALL_RE),
    ("kindtag", KINDTAG_CALL_RE),
    ("valslot", VALSLOT_CALL_RE),
    ("lookup", LOOKUP_CALL_RE),
    ("update", UPDATE_CALL_RE),
    ("delete", DELETE_CALL_RE),
    ("pid", PID_CALL_RE),
)
# Key-slot shapes whose result carries a key literal (keyslot holds
# 0, keyslot1 holds 1, keyslotN holds its group-2 literal).
KEYSLOT_SHAPES = ("keyslot", "keyslot1", "keyslotN")
# The four frozen admitted shape count vectors, keyed by shape
# name. The combined vector is the packet workload in one program:
# one packet reinterpretation plus two map read-modify-write pairs
# (entries 0 and 1), sharing the single lookup/update declaration
# pair. The tracepoint vector is the TID-filtered counter: one
# filter read through key 0, one current-PID/TID call, and one
# read-modify-write pair through key 1. Wider map shapes validate
# through the count families in _check_counts, never by editing
# these vectors.
CLASSIFIER_COUNTS = {
    "empty": 1,
    "mapaddr": 0,
    "keyslot": 0,
    "keyslot1": 0,
    "keyslotN": 0,
    "kindtag": 0,
    "valslot": 0,
    "lookup": 0,
    "update": 0,
    "delete": 0,
    "pid": 0,
}
MAP_COUNTS = {
    "empty": 1,
    "mapaddr": 2,
    "keyslot": 2,
    "keyslot1": 0,
    "keyslotN": 0,
    "kindtag": 0,
    "valslot": 1,
    "lookup": 1,
    "update": 1,
    "delete": 0,
    "pid": 0,
}
COMBINED_COUNTS = {
    "empty": 3,
    "mapaddr": 4,
    "keyslot": 2,
    "keyslot1": 2,
    "keyslotN": 0,
    "kindtag": 0,
    "valslot": 2,
    "lookup": 2,
    "update": 2,
    "delete": 0,
    "pid": 0,
}
TRACEPOINT_COUNTS = {
    "empty": 2,
    "mapaddr": 3,
    "keyslot": 1,
    "keyslot1": 2,
    "keyslotN": 0,
    "kindtag": 0,
    "valslot": 1,
    "lookup": 2,
    "update": 1,
    "delete": 0,
    "pid": 1,
}

# Admitted entrypoint symbols. The XDP programs export xdp_entry;
# the tracepoint counter exports trace_entry with the same C ABI
# (one context pointer, i32 result) and leaves the context unused.
ENTRY_SYMBOLS = ("xdp_entry", "trace_entry")
DEFINE_RE = re.compile(
    r"^define\s+\S+\s+i32\s+@(xdp_entry|trace_entry)"
    r"\(ptr\s+[^,)]+\)\s+#0\s*\{$"
)
GLOBAL_RE = re.compile(r"^@(?:\"[^\"]*\"|[A-Za-z0-9_.$]+)\s*=")
SOURCE_FILENAME_RE = re.compile(r"^source_filename\s*=\s*\"[^\"]*\"$")
TARGET_DATALAYOUT_RE = re.compile(r"^target datalayout\s*=\s*\"[^\"]*\"$")
TARGET_TRIPLE_RE = re.compile(r"^target triple\s*=\s*\"[^\"]*\"$")
ATTRS_ZERO_RE = re.compile(r"^attributes #0\s*=\s*\{.*\}$")
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
QUOTED_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
VECTOR_TYPE_RE = re.compile(
    r"<(vscale\s+x\s+)?(\d+)\s+x\s+([A-Za-z0-9]+)>"
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
        # Entrypoint symbol from the define line ("xdp_entry" or
        # "trace_entry"; empty until the define line is scanned).
        self.entry = ""
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
        }
        self.counts = {name: 0 for name, _ in ASM_SHAPES}
        # Key-slot SSA name -> key literal (keyslot 0, keyslot1 1,
        # keyslotN its group-2 literal).
        self.key_of = {}
        self.mode = "classifier"
        # Count family: "classifier", "map" (one or more
        # read-modify-write pairs), "combined", "delete", or
        # "tracepoint" (filter read plus one count pair). Map
        # families share mode "map"; the tracepoint family owns
        # mode "tracepoint".
        self.family = "classifier"
        # Map entry count the validated shape covers (dense keys
        # 0..entries-1); 0 for the classifier.
        self.entries = 0
        # Whether kind tags mark this program per-CPU.
        self.percpu = False


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
    elif kind == "pid":
        if parts != [""]:
            raise AuditError(
                CODE_OPERANDS,
                "pid helper call takes no operands, got %d "
                "operand(s): %r" % (len(parts), raw.strip()),
                location=_at(lineno),
                remedy="call the current-PID/TID helper without operands",
            )
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
    if (
        SOURCE_FILENAME_RE.match(line)
        or TARGET_DATALAYOUT_RE.match(line)
        or TARGET_TRIPLE_RE.match(line)
        or ATTRS_ZERO_RE.match(line)
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
    line order for structure and per-line behavior, then whole-body
    counts, the entry/family and tracepoint context rules, helper
    operands, cross-call liveness, undefined roots, and
    pointer-store dataflow.
    """
    program = Program()
    defines = 0
    in_body = False
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
            if not matched:
                raise AuditError(
                    CODE_ENTRY,
                    "unexpected definition (only one complete i32 "
                    "@xdp_entry(ptr...) or @trace_entry(ptr...) #0 "
                    "header, nothing after '{', allowed): %r"
                    % (raw.strip(),),
                    location=_at(lineno),
                    remedy=(
                        "expose exactly one C-ABI entrypoint taking "
                        "the context pointer"
                    ),
                )
            program.define_lineno = lineno
            program.entry = matched.group(1)
            for param in SSA_USE_RE.findall(
                line.split("(", 1)[1].rsplit(")", 1)[0]
            ):
                program.params.append(param)
                _record_def(program, param, lineno, raw)
            in_body = True
            continue
        if line == "}":
            if not in_body:
                raise AuditError(
                    CODE_ENTRY,
                    "stray closing brace: %r" % (raw.strip(),),
                    location=_at(lineno),
                    remedy="emit exactly one entrypoint definition",
                )
            in_body = False
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
            shape, match = classify_call(line, lineno, raw)
            program.counts[shape] += 1
            program.calls.append((lineno, shape, match))
            if shape == "keyslot":
                program.key_of[match.group(1)] = 0
            elif shape == "keyslot1":
                program.key_of[match.group(1)] = 1
            elif shape == "keyslotN":
                program.key_of[match.group(1)] = int(match.group(2))
            program.body.append((lineno, line, raw))
            defined = SSA_DEF_RE.match(line)
            if defined:
                _record_def(program, defined.group(1), lineno, raw)
            _record_uses(program, ssa_operands(line), lineno)
            continue
        if LABEL_DEF_RE.match(line):
            program.labels.add(line[:-1])
            continue
        check_body_line(line, lineno, raw)
        program.body.append((lineno, line, raw))
        defined = SSA_DEF_RE.match(line)
        if defined:
            _record_def(program, defined.group(1), lineno, raw)
        _record_uses(program, ssa_operands(line), lineno)
    if in_body:
        raise AuditError(
            CODE_ENTRY,
            "the @%s body was never closed with '}'" % (
                program.entry or "xdp_entry",
            ),
            location=None,
            remedy="emit exactly one entrypoint definition",
        )
    if defines != 1:
        raise AuditError(
            CODE_ENTRY,
            "expected exactly one @xdp_entry or @trace_entry "
            "definition, found %d" % defines,
            location=None,
            remedy="emit exactly one entrypoint definition",
        )
    _check_counts(program)
    _check_entry_family(program)
    _check_tracepoint_context(program)
    _check_helper_operands(program)
    _check_liveness(program)
    _check_roots(program)
    _check_pointer_stores(program)
    for name in program.uses:
        program.uses[name].sort()
    return program


def _check_decls(
    program, want_lookup, want_update, shared, want_delete=0,
    want_pid=0,
):
    """Require the declarations a matched count shape needs.

    Classifier programs declare nothing; single-pair map programs
    declare each helper once for their single call; wider shapes
    share one declaration per used helper across their calls. The
    tracepoint vector additionally declares its PID/TID call once.
    """
    if program.decl_counts["delete"] != want_delete:
        raise AuditError(
            CODE_PSEUDO,
            "each used helper needs exactly one shared declaration "
            "(delete calls %d declaration %d)"
            % (
                program.counts["delete"],
                program.decl_counts["delete"],
            ),
            location=None,
            remedy="use the SDK helper wrappers unchanged",
        )
    if program.decl_counts["pid"] != want_pid:
        raise AuditError(
            CODE_PSEUDO,
            "each used helper needs exactly one shared declaration "
            "(pid calls %d declaration %d)"
            % (
                program.counts["pid"],
                program.decl_counts["pid"],
            ),
            location=None,
            remedy="use the SDK helper wrappers unchanged",
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
    per-CPU flag set when the counts fit; returns False without
    setting anything otherwise. The frozen single-pair vector is
    matched before this rule, so N == 1 here means per-CPU.
    """
    pairs = program.counts["lookup"]
    if pairs < 1 or program.counts["update"] != pairs:
        return False
    if program.counts["delete"]:
        return False
    if program.counts["pid"]:
        return False
    if program.counts["empty"] != pairs:
        return False
    if program.counts["mapaddr"] != 2 * pairs:
        return False
    if program.counts["valslot"] != pairs:
        return False
    if program.counts["kindtag"] not in (0, 2 * pairs):
        return False
    if not _dense_keys(program, pairs, 2):
        return False
    _check_decls(program, 1, 1, pairs > 1)
    program.mode = "map"
    program.family = "map"
    program.entries = pairs
    program.percpu = program.counts["kindtag"] > 0
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
    if program.counts["empty"]:
        return False
    if program.counts["mapaddr"] != deletes:
        return False
    if program.counts["valslot"]:
        return False
    if program.counts["kindtag"] not in (0, deletes):
        return False
    if not _dense_keys(program, deletes, 1):
        return False
    _check_decls(program, 0, 0, deletes > 1, want_delete=1)
    program.mode = "map"
    program.family = "delete"
    program.entries = deletes
    program.percpu = program.counts["kindtag"] > 0
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


def _check_counts(program):
    """Require one frozen vector or one map count family."""
    if program.counts == CLASSIFIER_COUNTS:
        _check_decls(program, 0, 0, False)
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
        return
    if _match_pairs(program):
        return
    if _match_combined_percpu(program):
        return
    if _match_deletes(program):
        return
    for shape in ("lookup", "update", "delete", "pid"):
        want = 1 if program.counts[shape] else 0
        if program.decl_counts[shape] != want:
            raise AuditError(
                CODE_PSEUDO,
                "each used helper needs exactly one shared "
                "declaration (lookup calls %d declaration %d, "
                "update calls %d declaration %d, delete calls %d "
                "declaration %d, pid calls %d declaration %d)"
                % (
                    program.counts["lookup"],
                    program.decl_counts["lookup"],
                    program.counts["update"],
                    program.decl_counts["update"],
                    program.counts["delete"],
                    program.decl_counts["delete"],
                    program.counts["pid"],
                    program.decl_counts["pid"],
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
        + program.counts["valslot"]
        + program.counts["lookup"]
        + program.counts["update"]
        + program.counts["delete"]
        + program.counts["pid"]
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

    The tracepoint counter exports ``trace_entry``; every other
    shape exports ``xdp_entry``. A ``trace_entry`` program with any
    other body would misread the tracepoint context as packet
    metadata, and an ``xdp_entry`` program with the tracepoint
    vector would publish a miscounted shape, so both mismatches
    fail closed here. Runs after the count rule, so the family is
    known.
    """
    tracepoint_body = program.family == "tracepoint"
    tracepoint_entry = program.entry == "trace_entry"
    if tracepoint_body == tracepoint_entry:
        return
    if tracepoint_entry:
        detail = (
            "trace_entry exports the tracepoint counter, but the "
            "body matches the %s shape" % program.family
        )
    else:
        detail = (
            "the tracepoint counter body must export trace_entry, "
            "not @%s" % program.entry
        )
    raise AuditError(
        CODE_ENTRY,
        "%s: %r" % (detail, program.counts),
        location=None,
        remedy=(
            "export trace_entry for the tracepoint counter and "
            "xdp_entry for every other shape"
        ),
    )


def _check_tracepoint_context(program):
    """Require tracepoint programs to leave the context unused.

    Only the tracepoint family is checked: its filter comes from
    the current-PID/TID helper and map state, never from
    tracepoint context payload fields, whose layout is a separate
    unimplemented capability. Other families return early. Runs
    after the entry/family rule, so a checked program exports
    ``trace_entry``.
    """
    if program.family != "tracepoint":
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
    pairs key 1. Each kind tag ties one map-address load to its
    result.
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
        for role, group, origins in expect:
            name = match.group(group)
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


def _check_liveness(program):
    """No SSA value may be live across a helper call.

    For every helper-call line, every SSA value defined before it
    must have no use after it. Operands of the call itself and the
    call result are not crossings: only a use strictly after the
    call of a value defined strictly before it violates the rule.

    Combined programs are exempt: the packet workload's action
    selector and frame length necessarily cross helper calls, and
    SSA liveness alone cannot contain packet data anyway (values
    also cross through memory, which this check never saw). The
    tracepoint counter is exempt for the same structural reason:
    the filter value and the PID/TID result must both be live at
    their comparison, so one necessarily crosses the other's
    producing call. The pointer-store dataflow check still rejects
    kernel addresses reaching stores in every mode.
    """
    if program.mode in ("combined", "tracepoint"):
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


def _split_store_type(rest):
    """Split stored-type from the remainder of a store line."""
    rest = rest.strip()
    if rest.startswith("<"):
        depth = 0
        for index, char in enumerate(rest):
            if char == "<":
                depth += 1
            elif char == ">":
                depth -= 1
                if depth == 0:
                    return rest[: index + 1], rest[index + 1 :].strip()
        return None, None
    parts = rest.split(None, 1)
    if len(parts) != 2:
        return None, None
    return parts[0], parts[1]


def _store_operands(line):
    """Split a store line into (stored type, stored value, dest name).

    Returns None for anything that does not parse as a store; the
    audit never invents a violation from an unparsable line.
    """
    rest = line[len("store ") :]
    while True:
        keyword = rest.split(None, 1)
        if keyword and keyword[0] in ("atomic", "volatile"):
            rest = keyword[1] if len(keyword) == 2 else ""
            continue
        break
    stored_type, rest = _split_store_type(rest)
    if stored_type is None or "," not in rest:
        return None
    stored_value, after = rest.split(",", 1)
    stored_value = stored_value.strip()
    match = _STORE_DEST_RE.match(after.strip())
    if not stored_value or match is None:
        return None
    return stored_type, stored_value, match.group(1)


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
    """SSA values derived from a lookup result.

    The lookup result is a nullable kernel address carried as an
    integer; taint follows it through dataflow to a fixpoint so
    laundering it through arithmetic, casts, or the
    reinterpretation call cannot hide a store. Loads break the
    chain (stored data is data), comparisons yield untainted
    predicates, and non-reinterpretation call results are fresh.
    """
    tainted = set()
    for _, shape, match in program.calls:
        if shape == "lookup":
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

    Returns ``"classifier"``, ``"map"``, ``"combined"``, or
    ``"tracepoint"`` for admitted input and raises AuditError
    naming the first violated check otherwise.
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


def audit_post(adapted, mode):
    """Audit adapted IR after the lowering transform.

    Requires exactly the lowered helper callees for the mode and no
    remaining reserved references or helper assembly. The caller
    additionally runs :func:`check_graph_preserved` over the raw and
    adapted bodies.
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
    lowered = {"lookup": 0, "update": 0, "delete": 0, "pid": 0}
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
            else:
                raise AuditError(
                    CODE_CALL_FORM,
                    "lowered helper callee deviates from the exact "
                    "inttoptr(ID) form with ID 1 to 3 or 14: %r"
                    % (raw.strip(),),
                    location=_at(lineno),
                    remedy="report this adapter failure as a bug",
                )
    if mode == "map":
        pairs = lowered["lookup"] == lowered["update"] >= 1
        bare = lowered["delete"] == 0 and lowered["pid"] == 0
        deletes = (
            lowered["delete"] >= 1
            and lowered["lookup"] == 0
            and lowered["update"] == 0
            and lowered["pid"] == 0
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
    if mode == "combined":
        want = {"lookup": 2, "update": 2, "delete": 0, "pid": 0}
    elif mode == "tracepoint":
        want = {"lookup": 2, "update": 1, "delete": 0, "pid": 1}
    else:
        want = {"lookup": 0, "update": 0, "delete": 0, "pid": 0}
    if lowered != want:
        raise AuditError(
            CODE_EXTERNAL,
            "lowered IR has helper-call counts %r, expected %r"
            % (lowered, want),
            location=None,
            remedy="report this adapter failure as a bug",
        )


def check_graph_preserved(raw_body, adapted_body, lowered):
    """Require byte-identical bodies outside the callee edits.

    ``lowered`` maps raw lowered-call lines to their expected
    adapted form; every other adapted body line must equal its raw
    counterpart in order.
    """
    if len(raw_body) != len(adapted_body):
        raise AuditError(
            CODE_FALLBACK,
            "lowering changed the body length (%d raw lines, %d "
            "adapted lines)"
            % (len(raw_body), len(adapted_body)),
            location=None,
            remedy="report this adapter failure as a bug",
        )
    for index, (raw_line, adapted_line) in enumerate(
        zip(raw_body, adapted_body)
    ):
        want = lowered.get(raw_line, raw_line)
        if adapted_line != want:
            raise AuditError(
                CODE_FALLBACK,
                "lowering altered body line %d beyond the admitted "
                "callee edit: %r -> %r"
                % (index + 1, raw_line, adapted_line),
                location=None,
                remedy="report this adapter failure as a bug",
            )
