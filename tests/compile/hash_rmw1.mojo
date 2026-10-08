# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Map round trip written in Mojo.
#
# Behavior: look up key 0 in the single-entry hash map. On a lookup hit,
# read the stored value, add one, write the sum back through the update
# helper, and report XDP_PASS (2). On a lookup miss, report XDP_PASS (2)
# without touching the map. With the value initialized to 41 by userspace,
# one execution observes 42. The context pointer is accepted (the kernel
# passes it) but unused by this round trip.
#
# Pointer discipline: the lookup result is an unchecked integer (0 means
# null). The null check below dominates the only dereference; removing it
# is rejected by the kernel verifier (see the unchecked negative fixture).
# Each helper call takes freshly loaded inputs: no value is kept live
# across a helper call, because a call clobbers the argument registers.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import HashHandle, key_slot, value_slot


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key = key_slot()
    var found = bpf_map_lookup(HashHandle.load().addr, key)
    if found.is_null():
        return Int32(2)
    var slot = value_slot()
    var old = found.unsafe_value_ptr()[unsafe_offset=0]
    slot[unsafe_offset=0] = old + 1
    var key2 = key_slot()
    _ = bpf_map_update(HashHandle.load().addr, key2, slot, Int64(0))
    return Int32(2)
