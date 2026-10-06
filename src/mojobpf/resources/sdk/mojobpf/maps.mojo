# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Minimal single-map definitions.
#
# The supported map is a one-entry array with u32 keys and u64 values,
# declared in the standard loader-compatible form with map BTF. Its
# address is loaded from the map metadata section by `MapHandle.load`.
# Key and value scratch slots live in fixed stack slots prepared by
# `key_slot` and `value_slot`; the key slot is initialized to key 0 and
# the value slot is left for the program to store through. Every item is
# force-inlined, so kernel programs built on this module contain only
# the intended map reference and slot shapes.

from std.sys import inlined_assembly

comptime MAP_TYPE_ARRAY = 2
comptime MAP_KEY_SIZE = 4
comptime MAP_VALUE_SIZE = 8
comptime MAP_MAX_ENTRIES = 1


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
def value_slot() -> MutPointer[UInt64, MutAnyOrigin]:
    """Reserve the value scratch slot (program stores through it)."""
    return inlined_assembly[
        "r0 = r10\nr0 += -16",
        MutPointer[UInt64, MutAnyOrigin],
        constraints="={r0}",
        has_side_effect=True,
    ]()
