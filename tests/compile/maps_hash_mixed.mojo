# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative fixture: mixed map handles. The lookup below loads its
# map address through the array handle while the update loads its
# through the hash handle, so the program carries one hash tag
# for two map-address loads. One program defines one map of one
# kind, so the tag count matches neither array (zero tags) nor
# hash (one tag per load). The Mojo frontend accepts it.
#
# First expected rejecting layer: the IR audit at adapter time, with
# MBPF307 naming the map count family the program breaks.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import HashHandle, MapHandle, key_slot, value_slot


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
    _ = bpf_map_update(HashHandle.load().addr, key2, slot, Int64(0))
    return Int32(2)
