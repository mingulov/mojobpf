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
# constant PASS and it never inspects packet bytes. Combining the
# classifier rule with map counting in one program is refused by the
# IR audit (the map shape allows a single address reinterpretation,
# already spent on the map-value dereference, and no packet-derived
# value may stay live across a helper call). The closest combined
# forms are committed as refused reproducers under
# tests/compile/counter_*_attempt.mojo with their exact diagnostic
# codes; packet-content actions are demonstrated by the
# packet_classifier example instead. The context pointer is accepted
# (the kernel passes it) but unused by this counter.
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
