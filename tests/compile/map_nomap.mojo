# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative fixture: helper calls with no map reference. Both call sites
# pass a plain zero address instead of loading the map from its metadata
# section, so the program never references the map.
#
# First expected rejecting layer: the MojoBPF IR adapter at compile time,
# which admits helper calls only alongside their map reference shapes.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import key_slot, value_slot


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key = key_slot()
    var found = bpf_map_lookup(Int64(0), key)
    if found.is_null():
        return Int32(2)
    var slot = value_slot()
    var old = found.unsafe_value_ptr()[unsafe_offset=0]
    slot[unsafe_offset=0] = old + 1
    var key2 = key_slot()
    _ = bpf_map_update(Int64(0), key2, slot, Int64(0))
    return Int32(2)
