# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# XDP invocation counter written in Mojo.
#
# Behavior: add one to entry 0 of the single-entry array map on every
# invocation and return XDP_PASS (2). On a lookup miss, return
# XDP_PASS without touching the map (an in-range array lookup never
# misses; the check satisfies the kernel verifier). With the value
# initialized to N by userspace, K sequential invocations observe
# exactly N + K: the counter half of the packet workload, proven at
# corpus scale with per-invocation map reads.
#
# This program counts invocations unconditionally: its action is a
# constant PASS and it never inspects packet bytes. It stays as
# subset documentation for the single-entry map shape (one
# reinterpretation, one read-modify-write pair, no cross-call
# packet values). The packet workload whole — content action plus
# both counters in one program — is the packet_counter example,
# admitted under the combined count vector; partial combined forms
# that match neither vector stay refused with named diagnostics
# under tests/compile/counter_*_attempt.mojo. The context pointer
# is accepted (the kernel passes it) but unused by this counter.
#
# Pointer discipline mirrors the canonical round trip: the lookup
# result is an unchecked integer (0 means null). The null check
# below dominates the only dereference. Each helper call takes
# freshly loaded inputs: no value is kept live across a helper call,
# because a call clobbers the argument registers.

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
