# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative fixture: five read-modify-write pairs over dense keys
# 0 through 4. No manifest can declare a five-entry map (entry
# counts are 1 through 4), so no five-entry object may publish.
# The IR audit accepts the program under its generic N-pair map
# rule and the adapter emits a five-entry map unboundedly; the
# first expected rejecting layer is the build driver's spill
# gate, with MBPF107 (no qualified add-immediate multiset for
# the ("map", 5) shape). The Mojo frontend accepts it.

from std.sys import inlined_assembly

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import (
    BPF_ANY,
    MapHandle,
    key_slot,
    key_slot1,
    key_slot2,
    key_slot3,
    value_slot,
)


@inline(.always)
def key_slot_four() -> MutPointer[UInt32, MutAnyOrigin]:
    """Prepare a key scratch slot holding key 4 (undeclarable)."""
    return inlined_assembly[
        "r0 = r10\nr0 += -4\n*(u32 *)(r0 + 0) = r1",
        MutPointer[UInt32, MutAnyOrigin],
        constraints="={r0},{r1},~{memory}",
        has_side_effect=True,
    ](UInt32(4))


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key0 = key_slot()
    var found0 = bpf_map_lookup(MapHandle.load().addr, key0)
    if found0.is_null():
        return Int32(2)
    var slot0 = value_slot()
    var old0 = found0.unsafe_value_ptr()[unsafe_offset=0]
    slot0[unsafe_offset=0] = old0 + 1
    var key0b = key_slot()
    _ = bpf_map_update(MapHandle.load().addr, key0b, slot0, Int64(BPF_ANY))
    var key1 = key_slot1()
    var found1 = bpf_map_lookup(MapHandle.load().addr, key1)
    if found1.is_null():
        return Int32(2)
    var slot1 = value_slot()
    var old1 = found1.unsafe_value_ptr()[unsafe_offset=0]
    slot1[unsafe_offset=0] = old1 + 1
    var key1b = key_slot1()
    _ = bpf_map_update(MapHandle.load().addr, key1b, slot1, Int64(BPF_ANY))
    var key2 = key_slot2()
    var found2 = bpf_map_lookup(MapHandle.load().addr, key2)
    if found2.is_null():
        return Int32(2)
    var slot2 = value_slot()
    var old2 = found2.unsafe_value_ptr()[unsafe_offset=0]
    slot2[unsafe_offset=0] = old2 + 1
    var key2b = key_slot2()
    _ = bpf_map_update(MapHandle.load().addr, key2b, slot2, Int64(BPF_ANY))
    var key3 = key_slot3()
    var found3 = bpf_map_lookup(MapHandle.load().addr, key3)
    if found3.is_null():
        return Int32(2)
    var slot3 = value_slot()
    var old3 = found3.unsafe_value_ptr()[unsafe_offset=0]
    slot3[unsafe_offset=0] = old3 + 1
    var key3b = key_slot3()
    _ = bpf_map_update(MapHandle.load().addr, key3b, slot3, Int64(BPF_ANY))
    var key4 = key_slot_four()
    var found4 = bpf_map_lookup(MapHandle.load().addr, key4)
    if found4.is_null():
        return Int32(2)
    var slot4 = value_slot()
    var old4 = found4.unsafe_value_ptr()[unsafe_offset=0]
    slot4[unsafe_offset=0] = old4 + 1
    var key4b = key_slot_four()
    _ = bpf_map_update(MapHandle.load().addr, key4b, slot4, Int64(BPF_ANY))
    return Int32(2)
