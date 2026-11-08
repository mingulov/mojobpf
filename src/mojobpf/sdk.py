# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Versioned surface of the ``mojobpf`` Mojo package.

This module is the tool-side export list for the Mojo SDK shipped
under ``resources/sdk/mojobpf/``: the SDK version, the exact set of
public modules and top-level names, the pinned declaration
signatures, and a static import checker. The Mojo sources stay the
behavioral truth; this module pins their importable shape so any
drift fails loudly in the surface and compatibility suites instead
of silently changing what consumer programs may use.

Versioning: ``SDK_VERSION`` is ``"<major>.<minor>"``. Within one
major version only additive changes are allowed (new modules or new
names with new signatures); removing or renaming a module or name,
or changing a pinned signature, requires a major-version bump. The
build stamps ``SDK_VERSION`` into provenance and evidence, and the
cache key covers it, so objects built under different SDK versions
never share a cache entry.

Internal namespace: leading-underscore modules and names are
reserved as internals and are never exported. The surface test
pins that the tree defines none, and the compatibility suite
proves the Mojo frontend rejects such imports at the source
layer. The static checker below enforces the same rules without
needing a compiler: it judges import statements only (module and
name membership, alias-tolerant); uses of module attributes past
the import (``packet._nope``) are the frontend's jurisdiction.

Standard library only.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .safeio import MOJO_LIMIT, read_capped

SDK_SCHEMA_VERSION = 1
# Minor 1 adds the events module (fixed-record ring-buffer
# vocabulary). No 1.0 name or signature changed: the frozen 1.0
# surface is a strict subset of this one, and the compatibility
# suite checks that against its frozen 1.0 baseline.
# Minor 2 adds the core module (the two pinned CO-RE field
# operations). No 1.0 or 1.1 name or signature changed.
# Minor 3 adds the hash map handle (`HashHandle`) and its kind
# constant (`MAP_TYPE_HASH`) to the maps module. No 1.0, 1.1, or
# 1.2 name or signature changed.
# Minor 4 adds the explicit ring-reservation vocabulary
# (`ReserveResult`, `bpf_ringbuf_reserve`, `bpf_ringbuf_submit`,
# `bpf_ringbuf_discard`, and the three helper-ID constants) to
# the events module. No 1.0, 1.1, 1.2, or 1.3 name or signature
# changed.
# Minor 5 adds the uprobe module (the pinned x86-64
# first-argument register read `uprobe_first_arg` plus its word
# and byte constants). No 1.0, 1.1, 1.2, 1.3, or 1.4 name or
# signature changed.
# Minor 6 adds the LRU hash map handle (`LruHandle`) and its kind
# constant (`MAP_TYPE_LRU_HASH`) to the maps module. No 1.0, 1.1,
# 1.2, 1.3, 1.4, or 1.5 name or signature changed.
# Minor 7 adds the skb helpers (`bpf_skb_load_bytes`,
# `bpf_skb_store_bytes`, and the two helper-ID constants) to the
# helpers module. No 1.0, 1.1, 1.2, 1.3, 1.4, 1.5, or 1.6 name or
# signature changed.
# Minor 8 adds the per-CPU hash map handle (`PercpuHashHandle`)
# and its kind constant (`MAP_TYPE_PERCPU_HASH`) to the maps
# module. No 1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, or 1.7 name or
# signature changed.
SDK_SURFACE_MINOR = 8
SDK_VERSION = "%d.%d" % (SDK_SCHEMA_VERSION, SDK_SURFACE_MINOR)

# Exact public modules of the mojobpf Mojo package, sorted. A new,
# removed, or renamed module file fails the surface pin until the
# export list (and the version, per the policy above) is reviewed.
SDK_MODULES = (
    "checksum",
    "core",
    "events",
    "helpers",
    "maps",
    "packet",
    "parse",
    "uprobe",
)

# Exact public top-level names per module, sorted: functions,
# structs, and comptime constants. Struct methods are pinned under
# SDK_SIGNATURES as "Struct.method" entries instead.
SDK_EXPORTS = {
    "checksum": (
        "cksum_add",
        "cksum_finalize",
        "cksum_fold",
    ),
    "core": (
        "core_exists_task_scx",
        "core_read_task_pid",
    ),
    "events": (
        "BPF_FUNC_get_current_pid_tgid",
        "BPF_FUNC_get_smp_processor_id",
        "BPF_FUNC_ktime_get_ns",
        "BPF_FUNC_ringbuf_discard",
        "BPF_FUNC_ringbuf_output",
        "BPF_FUNC_ringbuf_reserve",
        "BPF_FUNC_ringbuf_submit",
        "EVENT_OFF_CPU",
        "EVENT_OFF_MONOTONIC_NS",
        "EVENT_OFF_RECORD_SIZE",
        "EVENT_OFF_SEQUENCE",
        "EVENT_OFF_TGID",
        "EVENT_OFF_TID",
        "EVENT_OFF_VERSION",
        "EVENT_RECORD_SIZE",
        "EVENT_RECORD_VERSION",
        "EventRecord",
        "RINGBUF_SIZE_LARGE",
        "RINGBUF_SIZE_SMALL",
        "ReserveResult",
        "RingbufHandle",
        "bpf_get_current_pid_tgid",
        "bpf_get_smp_processor_id",
        "bpf_ktime_get_ns",
        "bpf_ringbuf_discard",
        "bpf_ringbuf_output",
        "bpf_ringbuf_reserve",
        "bpf_ringbuf_submit",
        "event_cpu_slot",
        "event_seq_slot",
        "event_size_slot",
        "event_slot",
        "event_tgid_slot",
        "event_tid_slot",
        "event_time_slot",
        "event_version_slot",
    ),
    "helpers": (
        "BPF_FUNC_map_delete_elem",
        "BPF_FUNC_map_lookup_elem",
        "BPF_FUNC_map_update_elem",
        "BPF_FUNC_skb_load_bytes",
        "BPF_FUNC_skb_store_bytes",
        "LookupResult",
        "bpf_map_delete",
        "bpf_map_lookup",
        "bpf_map_update",
        "bpf_skb_load_bytes",
        "bpf_skb_store_bytes",
    ),
    "maps": (
        "BPF_ANY",
        "BPF_EXIST",
        "BPF_NOEXIST",
        "HashHandle",
        "LruHandle",
        "MAP_KEY_SIZE",
        "MAP_MAX_ENTRIES",
        "MAP_MAX_ENTRIES_COMBINED",
        "MAP_MAX_ENTRIES_N3",
        "MAP_MAX_ENTRIES_N4",
        "MAP_TYPE_ARRAY",
        "MAP_TYPE_HASH",
        "MAP_TYPE_LRU_HASH",
        "MAP_TYPE_PERCPU_ARRAY",
        "MAP_TYPE_PERCPU_HASH",
        "MAP_VALUE_SIZE",
        "MapHandle",
        "PercpuHandle",
        "PercpuHashHandle",
        "key_slot",
        "key_slot1",
        "key_slot2",
        "key_slot3",
        "value_slot",
    ),
    "packet": (
        "Cursor",
        "GUARD_ACTION",
        "XDP_DROP",
        "XDP_PASS",
        "XdpCtx",
        "addr_short",
        "load_u16_le",
        "load_u32_le",
        "load_u8",
        "packet_addr",
        "packet_base",
        "packet_len",
        "packet_short",
    ),
    "parse": (
        "inner_ethertype",
        "is_vlan_tag",
        "load_u16_be",
        "outer_ethertype",
        "vlan_id",
        "vlan_tci",
    ),
    "uprobe": (
        "UPROBE_CTX_RDI_BYTE",
        "UPROBE_CTX_RDI_WORD",
        "uprobe_first_arg",
    ),
}

# Pinned normalized declarations per module: top-level names plus
# "Struct.method" entries. Each value is the declaration with every
# whitespace run collapsed to one space, prefixed by its attached
# decorators in source order (blank lines are not significant).
# Generated by parse_sdk_surface() and frozen here; any drift
# fails the surface suite until it is reviewed and re-pinned.
SDK_SIGNATURES = {
    "checksum": {
        "cksum_add": (
            "@inline(.always) "
            "def cksum_add(sum: UInt32, word: UInt16) -> UInt32:"
        ),
        "cksum_finalize": (
            "@inline(.always) "
            "def cksum_finalize(sum: UInt32) -> UInt16:"
        ),
        "cksum_fold": (
            "@inline(.always) "
            "def cksum_fold(sum: UInt32) -> UInt16:"
        ),
    },
    "core": {
        "core_exists_task_scx": (
            "@inline(.always) "
            "def core_exists_task_scx() -> Int32:"
        ),
        "core_read_task_pid": (
            "@inline(.always) "
            "def core_read_task_pid( "
            "value: MutPointer[UInt64, MutAnyOrigin], ) -> UInt32:"
        ),
    },
    "events": {
        "BPF_FUNC_get_current_pid_tgid": (
            "BPF_FUNC_get_current_pid_tgid = 14"
        ),
        "BPF_FUNC_get_smp_processor_id": (
            "BPF_FUNC_get_smp_processor_id = 8"
        ),
        "BPF_FUNC_ktime_get_ns": "BPF_FUNC_ktime_get_ns = 5",
        "BPF_FUNC_ringbuf_discard": "BPF_FUNC_ringbuf_discard = 133",
        "BPF_FUNC_ringbuf_output": "BPF_FUNC_ringbuf_output = 130",
        "BPF_FUNC_ringbuf_reserve": "BPF_FUNC_ringbuf_reserve = 131",
        "BPF_FUNC_ringbuf_submit": "BPF_FUNC_ringbuf_submit = 132",
        "EVENT_OFF_CPU": "EVENT_OFF_CPU = 12",
        "EVENT_OFF_MONOTONIC_NS": "EVENT_OFF_MONOTONIC_NS = 24",
        "EVENT_OFF_RECORD_SIZE": "EVENT_OFF_RECORD_SIZE = 2",
        "EVENT_OFF_SEQUENCE": "EVENT_OFF_SEQUENCE = 16",
        "EVENT_OFF_TGID": "EVENT_OFF_TGID = 4",
        "EVENT_OFF_TID": "EVENT_OFF_TID = 8",
        "EVENT_OFF_VERSION": "EVENT_OFF_VERSION = 0",
        "EVENT_RECORD_SIZE": "EVENT_RECORD_SIZE = 32",
        "EVENT_RECORD_VERSION": "EVENT_RECORD_VERSION = 1",
        "EventRecord": (
            "@fieldwise_init struct EventRecord(ImplicitlyCopyable):"
        ),
        "RINGBUF_SIZE_LARGE": "RINGBUF_SIZE_LARGE = 131072",
        "RINGBUF_SIZE_SMALL": "RINGBUF_SIZE_SMALL = 4096",
        "ReserveResult": (
            "@fieldwise_init struct ReserveResult(ImplicitlyCopyable):"
        ),
        "ReserveResult.is_null": (
            "@inline(.always) def is_null(self) -> Bool:"
        ),
        "ReserveResult.unsafe_reserve_ptr": (
            "@inline(.always) "
            "def unsafe_reserve_ptr(self) "
            "-> MutPointer[UInt8, MutAnyOrigin]:"
        ),
        "RingbufHandle": (
            "@fieldwise_init struct RingbufHandle(ImplicitlyCopyable):"
        ),
        "RingbufHandle.load": (
            "@staticmethod @inline(.always) "
            "def load(size: Int64) -> Self:"
        ),
        "bpf_get_current_pid_tgid": (
            "@inline(.always) "
            "def bpf_get_current_pid_tgid() -> Int64:"
        ),
        "bpf_get_smp_processor_id": (
            "@inline(.always) "
            "def bpf_get_smp_processor_id() -> Int64:"
        ),
        "bpf_ktime_get_ns": (
            "@inline(.always) def bpf_ktime_get_ns() -> Int64:"
        ),
        "bpf_ringbuf_discard": (
            "@inline(.always) "
            "def bpf_ringbuf_discard( "
            "data: MutPointer[UInt8, MutAnyOrigin], "
            "flags: Int64, ) -> None:"
        ),
        "bpf_ringbuf_output": (
            "@inline(.always) "
            "def bpf_ringbuf_output( "
            "map_addr: Int64, "
            "data: MutPointer[UInt8, MutAnyOrigin], "
            "size: Int64, "
            "flags: Int64, ) -> Int64:"
        ),
        "bpf_ringbuf_reserve": (
            "@inline(.always) "
            "def bpf_ringbuf_reserve( "
            "map_addr: Int64, "
            "size: Int64, "
            "flags: Int64, ) -> ReserveResult:"
        ),
        "bpf_ringbuf_submit": (
            "@inline(.always) "
            "def bpf_ringbuf_submit( "
            "data: MutPointer[UInt8, MutAnyOrigin], "
            "flags: Int64, ) -> None:"
        ),
        "event_cpu_slot": (
            "@inline(.always) "
            "def event_cpu_slot() -> MutPointer[UInt32, MutAnyOrigin]:"
        ),
        "event_seq_slot": (
            "@inline(.always) "
            "def event_seq_slot() -> MutPointer[UInt64, MutAnyOrigin]:"
        ),
        "event_size_slot": (
            "@inline(.always) "
            "def event_size_slot() -> MutPointer[UInt16, MutAnyOrigin]:"
        ),
        "event_slot": (
            "@inline(.always) "
            "def event_slot() -> MutPointer[UInt8, MutAnyOrigin]:"
        ),
        "event_tgid_slot": (
            "@inline(.always) "
            "def event_tgid_slot() -> MutPointer[UInt32, MutAnyOrigin]:"
        ),
        "event_tid_slot": (
            "@inline(.always) "
            "def event_tid_slot() -> MutPointer[UInt32, MutAnyOrigin]:"
        ),
        "event_time_slot": (
            "@inline(.always) "
            "def event_time_slot() -> MutPointer[UInt64, MutAnyOrigin]:"
        ),
        "event_version_slot": (
            "@inline(.always) "
            "def event_version_slot() "
            "-> MutPointer[UInt16, MutAnyOrigin]:"
        ),
    },
    "helpers": {
        "BPF_FUNC_map_delete_elem": "BPF_FUNC_map_delete_elem = 3",
        "BPF_FUNC_map_lookup_elem": "BPF_FUNC_map_lookup_elem = 1",
        "BPF_FUNC_map_update_elem": "BPF_FUNC_map_update_elem = 2",
        "BPF_FUNC_skb_load_bytes": "BPF_FUNC_skb_load_bytes = 26",
        "BPF_FUNC_skb_store_bytes": "BPF_FUNC_skb_store_bytes = 9",
        "LookupResult": (
            "@fieldwise_init struct LookupResult(ImplicitlyCopyable):"
        ),
        "LookupResult.is_null": (
            "@inline(.always) def is_null(self) -> Bool:"
        ),
        "LookupResult.unsafe_value_ptr": (
            "@inline(.always) "
            "def unsafe_value_ptr(self) "
            "-> MutPointer[UInt64, MutAnyOrigin]:"
        ),
        "bpf_map_delete": (
            "@inline(.always) "
            "def bpf_map_delete( "
            "map_addr: Int64, "
            "key: MutPointer[UInt32, MutAnyOrigin] ) -> Int64:"
        ),
        "bpf_map_lookup": (
            "@inline(.always) "
            "def bpf_map_lookup( "
            "map_addr: Int64, "
            "key: MutPointer[UInt32, MutAnyOrigin] ) -> LookupResult:"
        ),
        "bpf_map_update": (
            "@inline(.always) "
            "def bpf_map_update( "
            "map_addr: Int64, "
            "key: MutPointer[UInt32, MutAnyOrigin], "
            "value: MutPointer[UInt64, MutAnyOrigin], "
            "flags: Int64, ) -> Int64:"
        ),
        "bpf_skb_load_bytes": (
            "@inline(.always) "
            "def bpf_skb_load_bytes( "
            "ctx: MutPointer[UInt8, MutAnyOrigin], "
            "offset: Int32, "
            "to: MutPointer[UInt32, MutAnyOrigin], "
            "length: Int32, ) -> Int64:"
        ),
        "bpf_skb_store_bytes": (
            "@inline(.always) "
            "def bpf_skb_store_bytes( "
            "ctx: MutPointer[UInt8, MutAnyOrigin], "
            "offset: Int32, "
            "src: MutPointer[UInt32, MutAnyOrigin], "
            "length: Int32, "
            "flags: Int64, ) -> Int64:"
        ),
    },
    "maps": {
        "BPF_ANY": "BPF_ANY = 0",
        "BPF_EXIST": "BPF_EXIST = 2",
        "BPF_NOEXIST": "BPF_NOEXIST = 1",
        "MAP_KEY_SIZE": "MAP_KEY_SIZE = 4",
        "MAP_MAX_ENTRIES": "MAP_MAX_ENTRIES = 1",
        "MAP_MAX_ENTRIES_COMBINED": "MAP_MAX_ENTRIES_COMBINED = 2",
        "MAP_MAX_ENTRIES_N3": "MAP_MAX_ENTRIES_N3 = 3",
        "MAP_MAX_ENTRIES_N4": "MAP_MAX_ENTRIES_N4 = 4",
        "MAP_TYPE_ARRAY": "MAP_TYPE_ARRAY = 2",
        "MAP_TYPE_HASH": "MAP_TYPE_HASH = 1",
        "MAP_TYPE_LRU_HASH": "MAP_TYPE_LRU_HASH = 9",
        "MAP_TYPE_PERCPU_ARRAY": "MAP_TYPE_PERCPU_ARRAY = 6",
        "MAP_TYPE_PERCPU_HASH": "MAP_TYPE_PERCPU_HASH = 5",
        "MAP_VALUE_SIZE": "MAP_VALUE_SIZE = 8",
        "HashHandle": (
            "@fieldwise_init struct HashHandle(ImplicitlyCopyable):"
        ),
        "HashHandle.load": (
            "@staticmethod @inline(.always) def load() -> Self:"
        ),
        "LruHandle": (
            "@fieldwise_init struct LruHandle(ImplicitlyCopyable):"
        ),
        "LruHandle.load": (
            "@staticmethod @inline(.always) def load() -> Self:"
        ),
        "MapHandle": (
            "@fieldwise_init struct MapHandle(ImplicitlyCopyable):"
        ),
        "MapHandle.load": (
            "@staticmethod @inline(.always) def load() -> Self:"
        ),
        "PercpuHandle": (
            "@fieldwise_init struct PercpuHandle(ImplicitlyCopyable):"
        ),
        "PercpuHandle.load": (
            "@staticmethod @inline(.always) def load() -> Self:"
        ),
        "PercpuHashHandle": (
            "@fieldwise_init struct PercpuHashHandle(ImplicitlyCopyable):"
        ),
        "PercpuHashHandle.load": (
            "@staticmethod @inline(.always) def load() -> Self:"
        ),
        "key_slot": (
            "@inline(.always) "
            "def key_slot() -> MutPointer[UInt32, MutAnyOrigin]:"
        ),
        "key_slot1": (
            "@inline(.always) "
            "def key_slot1() -> MutPointer[UInt32, MutAnyOrigin]:"
        ),
        "key_slot2": (
            "@inline(.always) "
            "def key_slot2() -> MutPointer[UInt32, MutAnyOrigin]:"
        ),
        "key_slot3": (
            "@inline(.always) "
            "def key_slot3() -> MutPointer[UInt32, MutAnyOrigin]:"
        ),
        "value_slot": (
            "@inline(.always) "
            "def value_slot() -> MutPointer[UInt64, MutAnyOrigin]:"
        ),
    },
    "packet": {
        "GUARD_ACTION": "GUARD_ACTION = XDP_DROP",
        "XDP_DROP": "XDP_DROP = 1",
        "XDP_PASS": "XDP_PASS = 2",
        "Cursor": (
            "@fieldwise_init "
            "struct Cursor[O: MutOrigin, //](ImplicitlyCopyable):"
        ),
        "Cursor.advance": (
            "@inline(.always) def advance(self, step: Int) -> Self:"
        ),
        "Cursor.u8": "@inline(.always) def u8(self) -> UInt8:",
        "Cursor.u8_at": (
            "@inline(.always) def u8_at(self, k: Int) -> UInt8:"
        ),
        "XdpCtx": (
            "@fieldwise_init struct XdpCtx(ImplicitlyCopyable):"
        ),
        "XdpCtx.from_ctx": (
            "@staticmethod @inline(.always) "
            "def from_ctx(ctx: MutPointer[UInt8, MutAnyOrigin]) "
            "-> Self:"
        ),
        "addr_short": (
            "@inline(.always) "
            "def addr_short(addr: UInt64, ctx: XdpCtx, size: UInt64) "
            "-> Bool:"
        ),
        "load_u16_le": (
            "@inline(.always) "
            "def load_u16_le(base: MutPointer[UInt8, MutAnyOrigin], "
            "off: Int) -> UInt16:"
        ),
        "load_u32_le": (
            "@inline(.always) "
            "def load_u32_le(base: MutPointer[UInt8, MutAnyOrigin], "
            "off: Int) -> UInt32:"
        ),
        "load_u8": (
            "@inline(.always) "
            "def load_u8(base: MutPointer[UInt8, MutAnyOrigin], "
            "off: Int) -> UInt8:"
        ),
        "packet_addr": (
            "@inline(.always) "
            "def packet_addr(ctx: XdpCtx, off: UInt64) -> UInt64:"
        ),
        "packet_base": (
            "@inline(.always) "
            "def packet_base(addr: UInt64) "
            "-> MutPointer[UInt8, MutAnyOrigin]:"
        ),
        "packet_len": (
            "@inline(.always) "
            "def packet_len(ctx: XdpCtx) -> UInt64:"
        ),
        "packet_short": (
            "@inline(.always) "
            "def packet_short(ctx: XdpCtx, need: UInt64) -> Bool:"
        ),
    },
    "parse": {
        "inner_ethertype": (
            "@inline(.always) "
            "def inner_ethertype(base: MutPointer[UInt8, MutAnyOrigin]) "
            "-> UInt16:"
        ),
        "is_vlan_tag": (
            "@inline(.always) "
            "def is_vlan_tag(field12: UInt16) -> Bool:"
        ),
        "load_u16_be": (
            "@inline(.always) "
            "def load_u16_be(base: MutPointer[UInt8, MutAnyOrigin], "
            "off: Int) -> UInt16:"
        ),
        "outer_ethertype": (
            "@inline(.always) "
            "def outer_ethertype(base: MutPointer[UInt8, MutAnyOrigin]) "
            "-> UInt16:"
        ),
        "vlan_id": (
            "@inline(.always) def vlan_id(tci: UInt16) -> UInt16:"
        ),
        "vlan_tci": (
            "@inline(.always) "
            "def vlan_tci(base: MutPointer[UInt8, MutAnyOrigin]) "
            "-> UInt16:"
        ),
    },
    "uprobe": {
        "UPROBE_CTX_RDI_BYTE": "UPROBE_CTX_RDI_BYTE = 112",
        "UPROBE_CTX_RDI_WORD": "UPROBE_CTX_RDI_WORD = 14",
        "uprobe_first_arg": (
            "@inline(.always) "
            "def uprobe_first_arg(ctx: MutPointer[UInt8, "
            "MutAnyOrigin]) -> Int64:"
        ),
    },
}

_NAME_RE = re.compile(r"^(?:def|struct)\s+([A-Za-z_][A-Za-z0-9_]*)")
_COMPTIME_RE = re.compile(r"^comptime\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$")
_WS_RE = re.compile(r"\s+")
_STRING_MASK_RE = re.compile(r'"(?:[^"\\]|\\.)*("|$)')
_IMPORT_RE = re.compile(
    r"^(?:from\s+([A-Za-z_][A-Za-z0-9_.]*)|import\s+([A-Za-z_]"
    r"[A-Za-z0-9_.]*))"
)


def sdk_dir() -> str:
    """Return the packaged SDK import directory for ``-I`` use.

    This resolves through this package's own location, never the
    caller's working directory, so installed and checkout uses
    agree.
    """
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "resources", "sdk"
    )


def _normalize(text: str) -> str:
    return _WS_RE.sub(" ", text).strip()


@dataclass(frozen=True)
class ParsedModule:
    """One parsed SDK module: top-level names plus signatures."""

    name: str
    names: tuple[str, ...]
    signatures: dict[str, str]


def parse_sdk_module(path: str) -> ParsedModule:
    """Parse one SDK ``.mojo`` file into names and signatures.

    Only declaration shapes are read: top-level ``def``/``struct``
    headers (with their attached ``@`` decorators), indented
    ``def`` methods attributed to their enclosing struct as
    ``"Struct.method"``, and top-level ``comptime NAME = VALUE``
    bindings. Comment, import, blank, and body lines are skipped.
    Multi-line headers are joined through their closing ``:`` and
    normalized by collapsing every whitespace run to one space, so
    the result is deterministic for one declaration spelling.
    """
    lines = read_capped(
        path, limit=MOJO_LIMIT, kind="Mojo source"
    ).decode("utf-8").splitlines()
    names: list[str] = []
    signatures: dict[str, str] = {}
    pending: list[str] = []
    struct_name: str | None = None
    index = 0
    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip(" "))
        index += 1
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("@"):
            pending.append(_normalize(stripped))
            continue
        if stripped.startswith(("from ", "import ")):
            pending.clear()
            continue
        if indent == 0:
            struct_name = None
        if stripped.startswith("comptime ") and indent == 0:
            match = _COMPTIME_RE.match(stripped)
            if match is None:
                pinned = _normalize(stripped[len("comptime "):])
                name = pinned.split(" ", 1)[0]
            else:
                name = match.group(1)
                pinned = "%s = %s" % (
                    name, _normalize(match.group(2)),
                )
            pending.clear()
            names.append(name)
            signatures[name] = pinned
            continue
        is_def = stripped.startswith("def ")
        is_struct = stripped.startswith("struct ")
        if not (is_def or is_struct):
            pending.clear()
            continue
        if is_struct and indent != 0:
            # Nested struct shapes are not part of this SDK; treat
            # any as a body line so the pin cannot silently adopt
            # a shape the checker does not model.
            pending.clear()
            continue
        match = _NAME_RE.match(stripped)
        if match is None:
            pending.clear()
            continue
        name = match.group(1)
        joined = stripped
        while not joined.rstrip().endswith(":") and index < len(lines):
            joined += " " + lines[index].strip()
            index += 1
        normalized = _normalize(joined)
        if pending:
            normalized = " ".join(pending) + " " + normalized
        pending.clear()
        if is_struct:
            struct_name = name
            names.append(name)
            signatures[name] = normalized
        elif indent == 0 or struct_name is None:
            struct_name = None
            names.append(name)
            signatures[name] = normalized
        else:
            signatures["%s.%s" % (struct_name, name)] = normalized
    module = os.path.basename(path)
    if module.endswith(".mojo"):
        module = module[: -len(".mojo")]
    return ParsedModule(
        name=module, names=tuple(sorted(names)), signatures=signatures
    )


def parse_sdk_surface(root: str | None = None) -> dict[str, ParsedModule]:
    """Parse every SDK module under ``root`` (default: packaged)."""
    directory = os.path.join(sdk_dir() if root is None else root, "mojobpf")
    parsed: dict[str, ParsedModule] = {}
    for entry in sorted(os.listdir(directory)):
        if not entry.endswith(".mojo"):
            raise ValueError(
                "unexpected non-module file in the SDK package: %r"
                % entry
            )
        module = parse_sdk_module(os.path.join(directory, entry))
        parsed[module.name] = module
    return parsed


@dataclass(frozen=True)
class ImportViolation:
    """One import statement outside the pinned export list."""

    line: int
    statement: str
    explanation: str


def _split_import_names(body: str) -> list[str]:
    cleaned = body.strip()
    if cleaned.startswith("(") and cleaned.endswith(")"):
        cleaned = cleaned[1:-1]
    found: list[str] = []
    for chunk in cleaned.split(","):
        token = chunk.strip().strip("() ")
        if not token:
            continue
        found.append(token.split()[0])
    return found


def _join_logical_lines(text: str) -> list[tuple[int, str]]:
    """Join parenthesized import statements to logical lines.

    The depth count masks double-quoted string spans first: a
    paren inside a string literal never opens or closes a
    logical line, so a forbidden import can never hide behind
    one. Only the count is masked; the buffered statement text
    is unchanged.
    """
    logical: list[tuple[int, str]] = []
    buffer = ""
    start = 0
    depth = 0
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0]
        if not buffer:
            start = lineno
        buffer += " " + line.strip()
        masked = _STRING_MASK_RE.sub('""', line)
        depth += masked.count("(") - masked.count(")")
        if depth <= 0:
            depth = 0
            if buffer.strip():
                logical.append((start, _normalize(buffer)))
            buffer = ""
    if buffer.strip():
        logical.append((start, _normalize(buffer)))
    return logical


def check_mojo_imports(text: str) -> tuple[ImportViolation, ...]:
    """Check ``mojobpf`` imports in Mojo source against the pin.

    Every ``from``/``import`` statement naming the ``mojobpf``
    package is judged: the module must be exported, every imported
    name must be exported by its module (``as`` aliases are
    transparent), and paths deeper than ``mojobpf.<module>`` are
    rejected. Imports of other packages (``std.*`` included) are
    out of scope and ignored. Returns every violation in line
    order; an empty tuple means every ``mojobpf`` import is
    within the pinned surface.
    """
    violations: list[ImportViolation] = []
    for lineno, statement in _join_logical_lines(text):
        match = _IMPORT_RE.match(statement)
        if match is None:
            continue
        dotted = match.group(1) or match.group(2)
        if dotted != "mojobpf" and not dotted.startswith("mojobpf."):
            continue
        rest = statement[match.end():].strip()
        if match.group(1) is not None:
            parts = dotted.split(".")
            if len(parts) == 1:
                names = _split_import_names(rest[len("import "):])
                if not names:
                    violations.append(
                        ImportViolation(
                            line=lineno,
                            statement=statement,
                            explanation=(
                                "empty module list in %r" % statement
                            ),
                        )
                    )
                    continue
                for name in names:
                    if name not in SDK_EXPORTS:
                        violations.append(
                            ImportViolation(
                                line=lineno,
                                statement=statement,
                                explanation=(
                                    "module %r is not exported "
                                    "(exported: %s)"
                                    % (
                                        name,
                                        ", ".join(SDK_MODULES),
                                    )
                                ),
                            )
                        )
                continue
            if len(parts) > 2:
                violations.append(
                    ImportViolation(
                        line=lineno,
                        statement=statement,
                        explanation=(
                            "module path %r is deeper than "
                            "mojobpf.<module>" % dotted
                        ),
                    )
                )
                continue
            module = parts[1]
            if module not in SDK_EXPORTS:
                violations.append(
                    ImportViolation(
                        line=lineno,
                        statement=statement,
                        explanation=(
                            "module %r is not exported (exported: %s)"
                            % (module, ", ".join(SDK_MODULES))
                        ),
                    )
                )
                continue
            if not rest.startswith("import "):
                violations.append(
                    ImportViolation(
                        line=lineno,
                        statement=statement,
                        explanation=(
                            "malformed import statement %r" % statement
                        ),
                    )
                )
                continue
            names = _split_import_names(rest[len("import "):])
            if not names:
                violations.append(
                    ImportViolation(
                        line=lineno,
                        statement=statement,
                        explanation=(
                            "empty name list in %r" % statement
                        ),
                    )
                )
                continue
            for name in names:
                if name not in SDK_EXPORTS[module]:
                    violations.append(
                        ImportViolation(
                            line=lineno,
                            statement=statement,
                            explanation=(
                                "name %r is not exported by module "
                                "%r" % (name, module)
                            ),
                        )
                    )
        else:
            parts = rest.split()
            if parts[:1] == ["as"]:
                parts = parts[2:]
            path = dotted
            if len(path.split(".")) > 2:
                violations.append(
                    ImportViolation(
                        line=lineno,
                        statement=statement,
                        explanation=(
                            "module path %r is deeper than "
                            "mojobpf.<module>" % path
                        ),
                    )
                )
                continue
            if path != "mojobpf":
                module = path.split(".")[1]
                if module not in SDK_EXPORTS:
                    violations.append(
                        ImportViolation(
                            line=lineno,
                            statement=statement,
                            explanation=(
                                "module %r is not exported "
                                "(exported: %s)"
                                % (module, ", ".join(SDK_MODULES))
                            ),
                        )
                    )
    return tuple(violations)


def check_mojo_file(path: str) -> tuple[ImportViolation, ...]:
    """Check one Mojo file's ``mojobpf`` imports against the pin."""
    return check_mojo_imports(
        read_capped(
            path, limit=MOJO_LIMIT, kind="Mojo source"
        ).decode("utf-8")
    )
