# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Map round trip through the named update-flags spelling.
#
# Behavior: identical to the canonical round trip (look up key 0 in the
# single-entry array map; on a hit read the value, add one, write the
# sum back, and report XDP_PASS (2); on a miss report XDP_PASS (2)
# untouched). The only difference is the update call spells its flags
# with the `BPF_ANY` name instead of a bare zero. With the value
# initialized to 41 by userspace, one execution observes 42.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, value_slot


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
    _ = bpf_map_update(MapHandle.load().addr, key2, slot, Int64(BPF_ANY))
    return Int32(2)
