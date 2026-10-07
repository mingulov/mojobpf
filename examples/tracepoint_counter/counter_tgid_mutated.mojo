# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# TID/TGID confusion mutant of the tracepoint counter.
#
# Identical to counter.mojo except the filter compares the
# thread-group ID (the high 32 bits of the helper-14 word) instead
# of the thread ID (the low 32 bits). The shape is unchanged — the
# audit admits it under the same tracepoint count vector and the
# object carries the same add-immediate multiset — but the behavior
# differs: a worker thread's TGID never equals its filter TID, so
# the counter stays at zero where the base program counts exactly.
# Exists for behavior-change proofs: a suite that cannot tell this
# object from the base one is not observing the kernel.
#
# The context pointer is accepted but unused, as in the base
# program. See counter.mojo for the TID discipline this mutant
# deliberately violates.

from std.ffi import external_call

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, key_slot1, value_slot

comptime BPF_FUNC_get_current_pid_tgid = 14


@inline(.always)
def bpf_get_current_pid_tgid() -> Int64:
    """Current TGID (high 32) and TID (low 32) in one word."""
    return external_call["__mojobpf_get_pid_tgid_v1", Int64]()


@export
def trace_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var fkey = key_slot()
    var ffound = bpf_map_lookup(MapHandle.load().addr, fkey)
    if ffound.is_null():
        return Int32(0)
    var filter_val = ffound.unsafe_value_ptr()[unsafe_offset=0]
    var pid_tgid = bpf_get_current_pid_tgid()
    var tid = pid_tgid >> 32
    if Int64(filter_val) != tid:
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
