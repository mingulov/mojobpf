# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative fixture: key slot holding key 1. The one-entry array admits
# only key 0, so the slot preparation below stores 1 instead of the
# qualified 0. The Mojo frontend accepts it; the SDK offers no way to
# spell this key.
#
# First expected rejecting layer: the IR audit at adapter time, which
# admits only the qualified key-slot shape.

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
