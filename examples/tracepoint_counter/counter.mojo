# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# TID-filtered tracepoint counter written in Mojo.
#
# Behavior: on every syscalls:sys_enter_getpid event, read the
# current thread's PID/TGID word with helper 14, compare its low 32
# bits (the TID) against the filter in entry 0 of the two-entry
# array map, and add one to the counter in entry 1 only on a match.
# On a lookup miss or a filter mismatch, return 0 without touching
# the counter (an in-range array lookup never misses; the checks
# satisfy the kernel verifier). With entry 0 holding a monitored
# TID and entry 1 starting at 0, exactly the monitored thread's
# getpid calls are counted.
#
# TID discipline: helper 14 returns TGID in the high 32 bits and
# TID in the low 32 bits. Only the low 32 bits select here; the
# high bits are never compared, so a thread is never confused
# with its thread group. The filter holds the monitored TID as a
# zero-extended u64, matching the masked helper result exactly.
# Both sides observe the initial PID namespace, where the helper
# result and gettid() agree.
#
# The context pointer is accepted (the kernel passes it) but
# unused: this program reads no tracepoint context payload fields,
# whose layout is a separate unimplemented capability. The audit
# refuses any use of the entry parameter.
#
# This program is admitted under the tracepoint count vector (one
# filter read through key 0, one PID/TID call, one read-modify-write
# pair through key 1). The filter value and the PID/TID result
# necessarily meet at their comparison after their producing
# calls; every other value is recomputed after the call that
# clobbers it.

from std.ffi import external_call

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, key_slot1, value_slot

comptime BPF_FUNC_get_current_pid_tgid = 14


@inline(.always)
def bpf_get_current_pid_tgid() -> Int64:
    """Current TGID (high 32) and TID (low 32) in one word.

    Issues the call as an ordinary typed call to a reserved
    compiler-recognized declaration with no implementation of its
    own; the adapter replaces only the callee operand with the
    standard helper-14 encoding. The wrapper is force-inlined, so
    kernel programs built on it contain only the intended helper
    invocation. The spelling lives here until shared tracing
    vocabulary is versioned into the SDK.
    """
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
    slot[unsafe_offset=0] = old + 1
    var ckey2 = key_slot1()
    _ = bpf_map_update(MapHandle.load().addr, ckey2, slot, Int64(BPF_ANY))
    return Int32(0)
