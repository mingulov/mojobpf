# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Mismatch-counting uprobe mutant (shape-clean, behaviorally distinct).
#
# Same admitted shape as counter.mojo (one expected-argument read
# through key 0, one pinned register read, one read-modify-write
# pair through key 1), but the comparison is inverted: this
# program counts probed calls whose first argument DIFFERS from
# the expected value instead of the calls that match it. The
# kernel suite uses the mutant to prove it reads live kernel
# state (the mutant observes the mismatch phase the base object
# ignores, and the reloaded base object still observes exactly
# its own expectation).

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, key_slot1, value_slot
from mojobpf.uprobe import uprobe_first_arg


@export
def uprobe_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var arg = uprobe_first_arg(ctx)
    var fkey = key_slot()
    var ffound = bpf_map_lookup(MapHandle.load().addr, fkey)
    if ffound.is_null():
        return Int32(0)
    var filter_val = ffound.unsafe_value_ptr()[unsafe_offset=0]
    if Int64(filter_val) == arg:
        return Int32(0)
    var ckey = key_slot1()
    var cfound = bpf_map_lookup(MapHandle.load().addr, ckey)
    if cfound.is_null():
        return Int32(0)
    var slot = value_slot()
    var old = cfound.unsafe_value_ptr()[unsafe_offset=0]
    slot[unsafe_offset=0] = old + 1
    var ckey2 = key_slot1()
    _ = bpf_map_update(MapHandle.load().addr, ckey2, slot, Int64(BPF_ANY))
    return Int32(0)
