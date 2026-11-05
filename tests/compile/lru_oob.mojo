# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative fixture: out-of-bounds map value access. The map value is 8
# bytes, but this program reads 8 bytes at byte offset 8, past the end of
# the value. The IR shape is otherwise identical to the round trip, so the
# compile pipeline accepts it.
#
# First expected rejecting layer: the kernel verifier at load time, which
# is the first layer that knows the map value size.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import LruHandle, key_slot, value_slot


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key = key_slot()
    var found = bpf_map_lookup(LruHandle.load().addr, key)
    if found.is_null():
        return Int32(2)
    var slot = value_slot()
    var oob = found.unsafe_value_ptr().unsafe_offset(1)[unsafe_offset=0]
    slot[unsafe_offset=0] = oob + 1
    var key2 = key_slot()
    _ = bpf_map_update(LruHandle.load().addr, key2, slot, Int64(0))
    return Int32(2)
