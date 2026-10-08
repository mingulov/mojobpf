# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# XDP hash-map counter written in Mojo.
#
# Behavior: add one to the value stored under key 0 of the
# single-entry hash map on every invocation and return XDP_PASS
# (2). On a lookup miss (key 0 absent), return XDP_PASS without
# touching the map: hash entries exist only after an update
# creates them, so a fresh map stays empty until userspace
# initializes key 0. With the value initialized to N by
# userspace, K sequential invocations observe exactly N + K.
#
# This program counts invocations unconditionally: its action is a
# constant PASS and it never inspects packet bytes. It stays as
# subset documentation for the single-entry hash shape (one
# address reinterpretation, one read-modify-write pair, one hash
# tag per map load, no cross-call packet values). The context
# pointer is accepted (the kernel passes it) but unused by this
# counter.
#
# Pointer discipline mirrors the canonical round trip: the lookup
# result is an unchecked integer (0 means null). The null check
# below dominates the only dereference. Each helper call takes
# freshly loaded inputs: no value is kept live across a helper call,
# because a call clobbers the argument registers.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, HashHandle, key_slot, value_slot


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key = key_slot()
    var found = bpf_map_lookup(HashHandle.load().addr, key)
    if found.is_null():
        return Int32(2)
    var slot = value_slot()
    var old = found.unsafe_value_ptr()[unsafe_offset=0]
    slot[unsafe_offset=0] = old + 1
    var key2 = key_slot()
    _ = bpf_map_update(HashHandle.load().addr, key2, slot, Int64(BPF_ANY))
    return Int32(2)
