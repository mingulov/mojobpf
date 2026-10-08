# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Explicit ring reservation emitter (submit path), written in Mojo.
#
# Behavior: on every syscalls:sys_enter_getpid event, read the
# current thread's PID/TID word with helper 14 and compare its
# low 32 bits (the TID) against the filter in entry 0 of the
# four-entry array map, returning 0 on a lookup miss or a filter
# mismatch without reserving anything. On a match, take the next
# per-run sequence number from entry 1 (incremented once per
# attempted reservation, including failed ones, so gaps mean
# failed reservations), read the CPU number (helper 8) and the
# monotonic clock (helper 5), read the PID/TID word a second
# time for the record's identity fields, then reserve a 32-byte
# record with the ring-buffer reserve helper (131). A null
# reservation increments the failed-reservation count in entry 3
# and publishes nothing. Otherwise the program stamps the
# 32-byte record (version, size, TGID, TID, CPU, sequence,
# monotonic time) with one word store per field directly into
# the reservation and publishes it with the ring-buffer submit
# helper (132), which publishes exactly one record; a submitted
# reservation increments the successful-output count in entry 2.
# With entry 0 holding a monitored TID and entries 1-3 starting
# at 0, the producer side reconciles attempted = successful +
# failed, and the drained records reconcile received =
# successful with exactly one record per submit.
#
# TID discipline: helper 14 returns TGID in the high 32 bits and
# TID in the low 32 bits. Only the low 32 bits select here; the
# record carries both halves in their own fields. Both sides
# observe the initial PID namespace, where the helper result and
# gettid() agree.
#
# The reservation pointer is checked for null before any store;
# the kernel verifier rejects any use that skips the check. The
# reservation is submitted exactly once on the non-null path and
# never touched again afterwards: double submit and
# use-after-submit are refused shapes. The discard path lives in
# reserve_discard.mojo; this program contains no discard call.
#
# The context pointer is accepted (the kernel passes it) but
# unused: this program reads no tracepoint context payload
# fields. The audit refuses any use of the entry parameter.
#
# Ring size: this emitter uses the large (healthy) ring
# (RINGBUF_SIZE_LARGE); reserve_submit_small.mojo is the same
# program against the small (saturation) ring. The size rides
# the ring-buffer size tag so the adapter emits it without
# reading the manifest; the manifest must declare the same
# size.

from mojobpf.events import (
    EVENT_RECORD_SIZE,
    EVENT_RECORD_VERSION,
    RINGBUF_SIZE_LARGE,
    RingbufHandle,
    bpf_get_current_pid_tgid,
    bpf_get_smp_processor_id,
    bpf_ktime_get_ns,
    bpf_ringbuf_discard,
    bpf_ringbuf_reserve,
    bpf_ringbuf_submit,
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
    var filter_tid = bpf_get_current_pid_tgid() & Int64(0xFFFFFFFF)
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
    var found = bpf_ringbuf_reserve(
        RingbufHandle.load(Int64(RINGBUF_SIZE_LARGE)).addr,
        Int64(EVENT_RECORD_SIZE),
        Int64(0),
    )
    if not found.is_null():
        var base = found.unsafe_reserve_ptr()
        base.unsafe_bitcast[UInt16]().unsafe_write(
            UInt16(EVENT_RECORD_VERSION)
        )
        base.unsafe_offset(2).unsafe_bitcast[UInt16]().unsafe_write(
            UInt16(EVENT_RECORD_SIZE)
        )
        base.unsafe_offset(4).unsafe_bitcast[UInt32]().unsafe_write(tgid)
        base.unsafe_offset(8).unsafe_bitcast[UInt32]().unsafe_write(tid)
        base.unsafe_offset(12).unsafe_bitcast[UInt32]().unsafe_write(cpu)
        base.unsafe_offset(16).unsafe_bitcast[UInt64]().unsafe_write(seq)
        base.unsafe_offset(24).unsafe_bitcast[UInt64]().unsafe_write(now)
        bpf_ringbuf_submit(base, Int64(0))
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
