# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Refused attempt: tracepoint counter reading context payload.
#
# The tracepoint count vector matches exactly, but the filter
# condition also probes a context byte. Tracepoint context payload
# layouts are a separate unimplemented capability, so the audit
# refuses the program with MBPF317 before any lowering happens.
# Exists so the build suite pins the intended rejecting layer.

from std.ffi import external_call

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, key_slot1, value_slot

comptime BPF_FUNC_get_current_pid_tgid = 14


@inline(.always)
def bpf_get_current_pid_tgid() -> Int64:
    return external_call["__mojobpf_get_pid_tgid_v1", Int64]()


@export
def trace_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var fkey = key_slot()
    var ffound = bpf_map_lookup(MapHandle.load().addr, fkey)
    if ffound.is_null():
        return Int32(0)
    var filter_val = ffound.unsafe_value_ptr()[unsafe_offset=0]
    var probe = ctx[unsafe_offset=0]
    var pid_tgid = bpf_get_current_pid_tgid()
    var tid = pid_tgid & Int64(0xFFFFFFFF)
    if Int64(filter_val) != tid or probe == UInt8(0):
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
