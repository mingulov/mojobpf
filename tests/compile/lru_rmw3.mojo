# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Map-only three-pair round trip written in Mojo.
#
# Behavior: read-modify-write entries 0, 1, and 2 of the
# three-entry LRU map in sequence (look up the key; on a hit
# read the value, add one, write the sum back; on a miss return
# without touching that entry), and report XDP_PASS (2). With
# entry K initialized to 41 by userspace, one execution observes
# 42 there. No value crosses a helper call: each pair recomputes
# its inputs after the previous pair's calls.
#
# Pointer discipline: each lookup result is null-checked before
# its only dereference, and each helper call takes freshly loaded
# inputs, exactly as in the single-pair round trip.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import (
    BPF_ANY,
    LruHandle,
    key_slot,
    key_slot1,
    key_slot2,
    value_slot,
)


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key0 = key_slot()
    var found0 = bpf_map_lookup(LruHandle.load().addr, key0)
    if found0.is_null():
        return Int32(2)
    var slot0 = value_slot()
    var old0 = found0.unsafe_value_ptr()[unsafe_offset=0]
    slot0[unsafe_offset=0] = old0 + 1
    var key0b = key_slot()
    _ = bpf_map_update(LruHandle.load().addr, key0b, slot0, Int64(BPF_ANY))
    var key1 = key_slot1()
    var found1 = bpf_map_lookup(LruHandle.load().addr, key1)
    if found1.is_null():
        return Int32(2)
    var slot1 = value_slot()
    var old1 = found1.unsafe_value_ptr()[unsafe_offset=0]
    slot1[unsafe_offset=0] = old1 + 1
    var key1b = key_slot1()
    _ = bpf_map_update(LruHandle.load().addr, key1b, slot1, Int64(BPF_ANY))
    var key2 = key_slot2()
    var found2 = bpf_map_lookup(LruHandle.load().addr, key2)
    if found2.is_null():
        return Int32(2)
    var slot2 = value_slot()
    var old2 = found2.unsafe_value_ptr()[unsafe_offset=0]
    slot2[unsafe_offset=0] = old2 + 1
    var key2b = key_slot2()
    _ = bpf_map_update(LruHandle.load().addr, key2b, slot2, Int64(BPF_ANY))
    return Int32(2)
