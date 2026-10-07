# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Mutated XDP counter: adds two per invocation instead of one.
#
# This file is identical to counter.mojo except that the map slot
# value spells `old + 2` instead of `old + 1`. The reported action
# is unchanged, so the mutant still passes every frame; only the
# accumulated count differs. It exists so behavior tests can prove
# that the suites detect a map-slot mutation: the exact-count
# expectations fail against the rebuilt mutant and pass again once
# the mutation is reverted.

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
    slot[unsafe_offset=0] = old + 2
    var key2 = key_slot()
    _ = bpf_map_update(MapHandle.load().addr, key2, slot, Int64(BPF_ANY))
    return Int32(2)
