# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative fixture: lookup result dereferenced without a null check. The
# IR shape is otherwise identical to the round trip, so the compile
# pipeline accepts it.
#
# First expected rejecting layer: the kernel verifier at load time, which
# rejects the use of a possibly-null lookup result.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import HashHandle, key_slot, value_slot


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key = key_slot()
    var found = bpf_map_lookup(HashHandle.load().addr, key)
    var slot = value_slot()
    var old = found.unsafe_value_ptr()[unsafe_offset=0]
    slot[unsafe_offset=0] = old + 1
    var key2 = key_slot()
    _ = bpf_map_update(HashHandle.load().addr, key2, slot, Int64(0))
    return Int32(2)
