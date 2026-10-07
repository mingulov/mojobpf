# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Refused attempt: tracepoint counter adding two per match.
#
# The program is audit-clean under the tracepoint count vector,
# but its object carries [-16, -4, -4, -4, 2] instead of the
# qualified [-16, -4, -4, -4, 1], so the spill gate refuses to
# publish it with MBPF107 after a successful backend step. Exists
# so the build suite pins the gate on the tracepoint shape.

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
    var pid_tgid = bpf_get_current_pid_tgid()
    var tid = pid_tgid & Int64(0xFFFFFFFF)
    if Int64(filter_val) != tid:
        return Int32(0)
    var ckey = key_slot1()
    var cfound = bpf_map_lookup(MapHandle.load().addr, ckey)
    if cfound.is_null():
        return Int32(0)
    var slot = value_slot()
    var old = cfound.unsafe_value_ptr()[unsafe_offset=0]
    slot[unsafe_offset=0] = old + 2
    var ckey2 = key_slot1()
    _ = bpf_map_update(MapHandle.load().addr, ckey2, slot, Int64(BPF_ANY))
    return Int32(0)
