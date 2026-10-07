# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative fixture: a lone key-1 slot outside the combined shape.
# Key 1 is a qualified spelling (the two-entry array's second entry,
# spelled `key_slot1` in the SDK), so the slot preparation below
# passes shape matching. The program is refused at the count vector
# instead: a lone key-1 lookup without an update matches neither the
# map vector (key 0 only) nor the combined vector (two full
# read-modify-write pairs), and key 1 belongs to the combined
# vector only. The Mojo frontend accepts it.
#
# First expected rejecting layer: the IR audit at adapter time, with
# MBPF307 naming the combined count vector.

from std.sys import inlined_assembly

from mojobpf.helpers import bpf_map_lookup
from mojobpf.maps import MapHandle


@inline(.always)
def key_slot_one() -> MutPointer[UInt32, MutAnyOrigin]:
    """Prepare a key scratch slot holding the unqualified key 1."""
    return inlined_assembly[
        "r0 = r10\nr0 += -4\n*(u32 *)(r0 + 0) = r1",
        MutPointer[UInt32, MutAnyOrigin],
        constraints="={r0},{r1},~{memory}",
        has_side_effect=True,
    ](UInt32(1))


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key = key_slot_one()
    var found = bpf_map_lookup(MapHandle.load().addr, key)
    if found.is_null():
        return Int32(2)
    return Int32(2)
