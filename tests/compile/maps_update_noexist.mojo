# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative fixture: map update with BPF_NOEXIST flags. Only the literal
# flags value 0 (BPF_ANY) is qualified; the shape is otherwise identical
# to the round trip, so the Mojo frontend accepts it.
#
# First expected rejecting layer: the IR audit at adapter time, which
# admits only the qualified flags spelling.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_NOEXIST, MapHandle, key_slot, value_slot


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key = key_slot()
    var found = bpf_map_lookup(MapHandle.load().addr, key)
    if found.is_null():
        return Int32(2)
    var slot = value_slot()
    var old = found.unsafe_value_ptr()[unsafe_offset=0]
    slot[unsafe_offset=0] = old + 1
    var key2 = key_slot()
    _ = bpf_map_update(MapHandle.load().addr, key2, slot, Int64(BPF_NOEXIST))
    return Int32(2)
