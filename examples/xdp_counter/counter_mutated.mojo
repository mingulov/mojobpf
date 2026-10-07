# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Mutated XDP counter: returns XDP_DROP (1) instead of XDP_PASS (2).
#
# This file is identical to counter.mojo except that both action
# returns spell 1 instead of 2. The map update is unchanged, so the
# mutant still counts exactly; only the reported action differs. It
# exists so behavior tests can prove that the suites detect an
# action mutation: the pass expectations fail against the rebuilt
# mutant and pass again once the mutation is reverted.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, value_slot


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key = key_slot()
    var found = bpf_map_lookup(MapHandle.load().addr, key)
    if found.is_null():
        return Int32(1)
    var slot = value_slot()
    var old = found.unsafe_value_ptr()[unsafe_offset=0]
    slot[unsafe_offset=0] = old + 1
    var key2 = key_slot()
    _ = bpf_map_update(MapHandle.load().addr, key2, slot, Int64(BPF_ANY))
    return Int32(1)
