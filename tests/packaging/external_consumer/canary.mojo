# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# External-consumer canary: a from-scratch XDP invocation counter.
#
# This program is owned by an external consumer, not by the MojoBPF
# project: it was written against the documented SDK surface only
# (``mojobpf.helpers`` plus ``mojobpf.maps``) with no access to
# compiler, adapter, or SDK internals. Behavior: on every invocation,
# add one to entry 0 of the single-entry array map and return
# XDP_PASS (2). A null lookup result returns XDP_PASS without
# touching the map, which keeps the kernel verifier satisfied.
#
# With the value initialized to N by userspace, K sequential runs
# observe exactly N + K. The canary test initializes 41, runs twice,
# and requires exactly 42 then 43 alongside the PASS action.
#
# The entry symbol (``xdp_entry``), the map name (``mojobpf_map0``),
# and the array u32/u64 shape are the project's public contract
# (see the manifest); everything else here -- structure, comments,
# and local names -- is the consumer's own.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, value_slot


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var lookup_key = key_slot()
    var entry_ptr = bpf_map_lookup(MapHandle.load().addr, lookup_key)
    if entry_ptr.is_null():
        return Int32(2)
    var writeback = value_slot()
    var previous = entry_ptr.unsafe_value_ptr()[unsafe_offset=0]
    writeback[unsafe_offset=0] = previous + 1
    var update_key = key_slot()
    _ = bpf_map_update(
        MapHandle.load().addr, update_key, writeback, Int64(BPF_ANY)
    )
    return Int32(2)
