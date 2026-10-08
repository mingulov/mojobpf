# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative attempt: subprogram call alongside map helpers. The
# entrypoint runs a map read-modify-write pair and calls a
# subprogram, so the audit must refuse the program with MBPF313
# at stage adapter.audit: the second attribute set renumbers the
# helper declarations off their exact admitted spelling, and map
# helpers alongside a callee are outside the admitted call shape
# (the call shape rides the classifier shape only).

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, value_slot


@export
@no_inline
def bump(old: UInt64) abi("C") -> UInt64:
    return old + 1


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key = key_slot()
    var found = bpf_map_lookup(MapHandle.load().addr, key)
    if found.is_null():
        return Int32(2)
    var slot = value_slot()
    var old = found.unsafe_value_ptr()[unsafe_offset=0]
    slot[unsafe_offset=0] = bump(old)
    var key2 = key_slot()
    _ = bpf_map_update(MapHandle.load().addr, key2, slot, Int64(BPF_ANY))
    return Int32(2)
