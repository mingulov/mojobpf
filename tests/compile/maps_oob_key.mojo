# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative fixture: out-of-range key literal. The key slot below
# holds key 9, which no supported map declares (entry counts are 1
# through 4 and every program covers exactly keys 0 through N-1),
# so the program matches no map count family. The Mojo frontend
# accepts it.
#
# First expected rejecting layer: the IR audit at adapter time, with
# MBPF307 naming the dense key coverage the program breaks.

from std.sys import inlined_assembly

from mojobpf.helpers import bpf_map_lookup
from mojobpf.maps import MapHandle


@inline(.always)
def key_slot_nine() -> MutPointer[UInt32, MutAnyOrigin]:
    """Prepare a key scratch slot holding key 9 (undeclared)."""
    return inlined_assembly[
        "r0 = r10\nr0 += -4\n*(u32 *)(r0 + 0) = r1",
        MutPointer[UInt32, MutAnyOrigin],
        constraints="={r0},{r1},~{memory}",
        has_side_effect=True,
    ](UInt32(9))


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key = key_slot_nine()
    var found = bpf_map_lookup(MapHandle.load().addr, key)
    if found.is_null():
        return Int32(2)
    return Int32(2)
