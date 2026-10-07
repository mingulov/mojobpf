# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Array map definitions.
#
# The supported maps are arrays with u32 keys and u64 values,
# declared in the standard loader-compatible form with map BTF:
# a one-entry array for the map round trip, and a two-entry array
# (entries 0 and 1) for the combined packet workload. The map
# address is loaded from the map metadata section by
# `MapHandle.load`. Key and value scratch slots live in fixed stack
# slots prepared by `key_slot`, `key_slot1`, and `value_slot`; the
# key slots are initialized to keys 0 and 1 respectively and the
# value slot is left for the program to store through. Every item is
# force-inlined, so kernel programs built on this module contain only
# the intended map reference and slot shapes.
#
# Mutation semantics (array, one or two entries):
#
# * Lookup takes a key slot holding a valid key and returns a
#   nullable result: branch on `is_null` before converting with
#   `unsafe_value_ptr`. The kernel rejects any use that skips the
#   check, even though an in-range array lookup never misses.
# * Update takes key and value slots plus flags. Only `BPF_ANY` (0,
#   unconditional replace) lowers; `BPF_NOEXIST` and `BPF_EXIST` are
#   named here so call sites spell their intent, and the compile
#   pipeline refuses them until their behavior is qualified.
# * `key_slot` always holds key 0 (the one-entry array's only key:
#   both the first and the last) and `key_slot1` always holds key 1
#   (the two-entry array's second entry). Any other key is refused
#   before the kernel sees it.
# * There is no delete or iteration step in this slice: array
#   elements are preallocated, so deletion is meaningless, and
#   iteration helpers are unqualified. Out-of-range access from
#   userspace fails in the kernel instead of misdecoding.
#
# Vocabulary outside this module (other map types, key/value widths,
# other entry counts, helpers) is refused by the build driver and
# the IR audit with named diagnostics; nothing silently falls back.

from std.sys import inlined_assembly

comptime MAP_TYPE_ARRAY = 2
comptime MAP_KEY_SIZE = 4
comptime MAP_VALUE_SIZE = 8
comptime MAP_MAX_ENTRIES = 1
comptime MAP_MAX_ENTRIES_COMBINED = 2

# Update flags. Only BPF_ANY (unconditional replace) lowers to the
# kernel helper; the other two name refused spellings (the pipeline
# rejects any nonzero flags value rather than changing it).
comptime BPF_ANY = 0
comptime BPF_NOEXIST = 1
comptime BPF_EXIST = 2


@fieldwise_init
struct MapHandle(ImplicitlyCopyable):
    """Address of the single map, loaded from its metadata section."""

    var addr: Int64

    @staticmethod
    @inline(.always)
    def load() -> Self:
        var addr = inlined_assembly[
            "r0 = mojobpf_map0 ll",
            Int64,
            constraints="={r0}",
            has_side_effect=True,
        ]()
        return Self(addr)


@inline(.always)
def key_slot() -> MutPointer[UInt32, MutAnyOrigin]:
    """Prepare the key scratch slot holding key 0."""
    return inlined_assembly[
        "r0 = r10\nr0 += -4\n*(u32 *)(r0 + 0) = r1",
        MutPointer[UInt32, MutAnyOrigin],
        constraints="={r0},{r1},~{memory}",
        has_side_effect=True,
    ](UInt32(0))


@inline(.always)
def key_slot1() -> MutPointer[UInt32, MutAnyOrigin]:
    """Prepare the key scratch slot holding key 1.

    The identical audited stack template as `key_slot`, holding the
    two-entry array's second entry. Admitted only as part of the
    combined packet workload's count vector.
    """
    return inlined_assembly[
        "r0 = r10\nr0 += -4\n*(u32 *)(r0 + 0) = r1",
        MutPointer[UInt32, MutAnyOrigin],
        constraints="={r0},{r1},~{memory}",
        has_side_effect=True,
    ](UInt32(1))


@inline(.always)
def value_slot() -> MutPointer[UInt64, MutAnyOrigin]:
    """Reserve the value scratch slot (program stores through it)."""
    return inlined_assembly[
        "r0 = r10\nr0 += -16",
        MutPointer[UInt64, MutAnyOrigin],
        constraints="={r0}",
        has_side_effect=True,
    ]()
