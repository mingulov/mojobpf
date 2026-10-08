# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Third-party hash tally written in Mojo by the consumer.
#
# Conduct: bump the two tally cells held under keys 0 and 1 of the
# two-entry hash map on every execution, then return XDP_PASS (2).
# A missing key is skipped without touching the map, so a fresh
# map runs quiet until userspace seeds it. Seeded with 41 in both
# cells, the first execution reports 42 in both and the second 43
# in both. The context argument rides along unused: the kernel
# hands it over and this tally never looks at it.
#
# Safety habits: each lookup outcome is an unchecked address (0 is
# empty). The emptiness test guards the single read that follows;
# dropping the test fails kernel verification. Helper arguments
# are reloaded for every call because calls trash the registers.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import HashHandle, key_slot, key_slot1, value_slot


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var first_key = key_slot()
    var first_hit = bpf_map_lookup(HashHandle.load().addr, first_key)
    if not first_hit.is_null():
        var first_cell = value_slot()
        var first_seen = first_hit.unsafe_value_ptr()[unsafe_offset=0]
        first_cell[unsafe_offset=0] = first_seen + 1
        var first_store = key_slot()
        _ = bpf_map_update(
            HashHandle.load().addr, first_store, first_cell, Int64(0)
        )
    var second_key = key_slot1()
    var second_hit = bpf_map_lookup(HashHandle.load().addr, second_key)
    if not second_hit.is_null():
        var second_cell = value_slot()
        var second_seen = second_hit.unsafe_value_ptr()[unsafe_offset=0]
        second_cell[unsafe_offset=0] = second_seen + 1
        var second_store = key_slot1()
        _ = bpf_map_update(
            HashHandle.load().addr, second_store, second_cell, Int64(0)
        )
    return Int32(2)
