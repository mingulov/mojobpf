# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Third-party argument gate: a uprobe program written by the
# subscriber against the public SDK surface only.
#
# Watch rule: whenever the attached uprobe fires, fetch the
# probed call's first argument through the SDK's pinned x86-64
# register read, compare it with the watched value kept in map
# entry 0, and bump the tally in entry 1 on equality. Misses and
# mismatches return without touching the tally. The program reads
# no other context and names no attach target: the section is the
# bare uprobe name, and the subscriber's own loader attaches the
# built object to the subscriber's own executable at run time.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, key_slot1, value_slot
from mojobpf.uprobe import uprobe_first_arg


@export
def uprobe_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var seen = uprobe_first_arg(ctx)
    var wkey = key_slot()
    var wfound = bpf_map_lookup(MapHandle.load().addr, wkey)
    if wfound.is_null():
        return Int32(0)
    var watched = wfound.unsafe_value_ptr()[unsafe_offset=0]
    if Int64(watched) != seen:
        return Int32(0)
    var tkey = key_slot1()
    var tfound = bpf_map_lookup(MapHandle.load().addr, tkey)
    if tfound.is_null():
        return Int32(0)
    var tally = value_slot()
    var prior = tfound.unsafe_value_ptr()[unsafe_offset=0]
    tally[unsafe_offset=0] = prior + 1
    var tkey2 = key_slot1()
    _ = bpf_map_update(MapHandle.load().addr, tkey2, tally, Int64(BPF_ANY))
    return Int32(0)
