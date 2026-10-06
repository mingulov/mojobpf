# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Mutation of the map round trip: writes back the observed value plus two
# instead of plus one. Rebuilding from this source must change the
# independently observed map value from 42 to 43, proving the value flows
# from the Mojo kernel code rather than from the test harness.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import MapHandle, key_slot, value_slot


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key = key_slot()
    var found = bpf_map_lookup(MapHandle.load().addr, key)
    if found.is_null():
        return Int32(2)
    var slot = value_slot()
    var old = found.unsafe_value_ptr()[unsafe_offset=0]
    slot[unsafe_offset=0] = old + 2
    var key2 = key_slot()
    _ = bpf_map_update(MapHandle.load().addr, key2, slot, Int64(0))
    return Int32(2)
