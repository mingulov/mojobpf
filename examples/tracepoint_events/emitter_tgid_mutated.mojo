# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# TID/TGID confusion mutant of the ring-buffer event emitter.
#
# Identical to emitter.mojo except the filter compares the
# thread-group ID (the high 32 bits of the helper-14 word) instead
# of the thread ID (the low 32 bits). The shape is unchanged — the
# audit admits it under the same event count vector and the object
# carries the same helper calls and add-immediate multiset — but
# the behavior differs: a worker thread's TGID never equals its
# filter TID, so nothing is emitted where the base program emits
# exactly. Exists for behavior-change proofs: a suite that cannot
# tell this object from the base one is not observing the kernel.
#
# Behavior: on every syscalls:sys_enter_getpid event, read the
# current thread's PID/TID word with helper 14 and compare its
# high 32 bits (the TGID) against the filter in entry 0 of the
# four-entry array map, returning 0 on a lookup miss or a filter
# mismatch without emitting anything. On a match, take the next
# per-run sequence number from entry 1 (incremented once per
# attempted output, including failed ones, so gaps mean failed
# outputs), read the CPU number (helper 8) and the monotonic
# clock (helper 5), read the PID/TID word a second time for the
# record's identity fields, stamp the 32-byte record (version,
# size, TGID, TID, CPU, sequence, monotonic time) with one word
# store per field, and emit it through the ring-buffer map with
# the copy-output helper 130. A zero status increments the
# successful-output count in entry 2; any nonzero status
# increments the failed-output count in entry 3. With entry 0
# holding a monitored TID and entries 1-3 starting at 0, the
# producer side reconciles attempted = successful + failed, and
# the drained records reconcile received = successful.
#
# TID discipline: helper 14 returns TGID in the high 32 bits and
# TID in the low 32 bits. Only the low 32 bits select here; the
# record carries both halves in their own fields. Both sides
# observe the initial PID namespace, where the helper result and
# gettid() agree.
#
# The PID/TID word is read twice on purpose: the filter read dies
# at the comparison, and the record read happens after every
# other helper call, so the record's identity fields span no
# helper call and keep no derived bytes live across one. Word
# stores plus this ordering keep the program frameless: at most
# three words (sequence, CPU, clock) are live across any call.
# A byte-at-a-time encoder spills, and any backend spill can
# collide with the fixed key/value slots, so the spill gate
# refuses spilling objects.
#
# The context pointer is accepted (the kernel passes it) but
# unused: this program reads no tracepoint context payload fields,
# whose layout is a separate unimplemented capability. The audit
# refuses any use of the entry parameter.
#
# Ring size: this emitter uses the large (healthy) ring
# (RINGBUF_SIZE_LARGE); emitter_small.mojo is the same program
# against the small (saturation) ring. The size rides the
# ring-buffer size tag so the adapter emits it without reading
# the manifest; the manifest must declare the same size.
#
# This program is admitted under the event count vector (one
# filter read through key 0, one filter PID/TID call, one
# sequence pair through key 1, one CPU call, one clock call, one
# record PID/TID call, one output call, one success pair through
# key 2 on the zero-status branch, one failure pair through
# key 3 on the nonzero branch). The filter value and the filter
# result meet at the comparison; the sequence, CPU, and clock
# necessarily meet after their producing calls.

from mojobpf.events import (
    EVENT_RECORD_SIZE,
    EVENT_RECORD_VERSION,
    RINGBUF_SIZE_LARGE,
    RingbufHandle,
    bpf_get_current_pid_tgid,
    bpf_get_smp_processor_id,
    bpf_ktime_get_ns,
    bpf_ringbuf_output,
    event_cpu_slot,
    event_seq_slot,
    event_size_slot,
    event_slot,
    event_tgid_slot,
    event_tid_slot,
    event_time_slot,
    event_version_slot,
)
from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import (
    BPF_ANY,
    MapHandle,
    key_slot,
    key_slot1,
    key_slot2,
    key_slot3,
    value_slot,
)


@export
def trace_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var fkey = key_slot()
    var ffound = bpf_map_lookup(MapHandle.load().addr, fkey)
    if ffound.is_null():
        return Int32(0)
    var filter_val = ffound.unsafe_value_ptr()[unsafe_offset=0]
    var filter_tid = bpf_get_current_pid_tgid() >> 32
    if Int64(filter_val) != filter_tid:
        return Int32(0)
    var skey = key_slot1()
    var sfound = bpf_map_lookup(MapHandle.load().addr, skey)
    if sfound.is_null():
        return Int32(0)
    var seq = sfound.unsafe_value_ptr()[unsafe_offset=0]
    var sslot = value_slot()
    sslot[unsafe_offset=0] = seq + 1
    var skey2 = key_slot1()
    _ = bpf_map_update(MapHandle.load().addr, skey2, sslot, Int64(BPF_ANY))
    var cpu = UInt32(bpf_get_smp_processor_id() & Int64(0xFFFFFFFF))
    var now = UInt64(bpf_ktime_get_ns())
    var pid_tgid = bpf_get_current_pid_tgid()
    var tgid = UInt32((pid_tgid >> 32) & Int64(0xFFFFFFFF))
    var tid = UInt32(pid_tgid & Int64(0xFFFFFFFF))
    event_version_slot()[unsafe_offset=0] = UInt16(EVENT_RECORD_VERSION)
    event_size_slot()[unsafe_offset=0] = UInt16(EVENT_RECORD_SIZE)
    event_tgid_slot()[unsafe_offset=0] = tgid
    event_tid_slot()[unsafe_offset=0] = tid
    event_cpu_slot()[unsafe_offset=0] = cpu
    event_seq_slot()[unsafe_offset=0] = seq
    event_time_slot()[unsafe_offset=0] = now
    var buf = event_slot()
    var rc = bpf_ringbuf_output(
        RingbufHandle.load(Int64(RINGBUF_SIZE_LARGE)).addr,
        buf,
        Int64(EVENT_RECORD_SIZE),
        Int64(0),
    )
    if rc == 0:
        var okey = key_slot2()
        var ofound = bpf_map_lookup(MapHandle.load().addr, okey)
        if ofound.is_null():
            return Int32(0)
        var oslot = value_slot()
        oslot[unsafe_offset=0] = ofound.unsafe_value_ptr()[unsafe_offset=0] + 1
        var okey2 = key_slot2()
        _ = bpf_map_update(
            MapHandle.load().addr, okey2, oslot, Int64(BPF_ANY)
        )
    else:
        var ekey = key_slot3()
        var efound = bpf_map_lookup(MapHandle.load().addr, ekey)
        if efound.is_null():
            return Int32(0)
        var eslot = value_slot()
        eslot[unsafe_offset=0] = efound.unsafe_value_ptr()[unsafe_offset=0] + 1
        var ekey2 = key_slot3()
        _ = bpf_map_update(
            MapHandle.load().addr, ekey2, eslot, Int64(BPF_ANY)
        )
    return Int32(0)
