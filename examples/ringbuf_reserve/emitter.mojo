# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Ring-reservation event emitter example, written in Mojo.
#
# Publishes one 32-byte tracepoint event record per monitored
# `getpid` system call through an explicit ring-buffer
# reservation: on every syscalls:sys_enter_getpid event the
# program compares the current thread's TID against the filter
# in entry 0 of the four-entry array map, takes the next
# per-run sequence number from entry 1, reads the CPU number
# and the monotonic clock plus the PID/TID identity word,
# reserves a 32-byte record with the ring-buffer reserve helper
# (131), stamps the record (version, size, TGID, TID, CPU,
# sequence, monotonic time) directly into the reservation with
# one word store per field, and publishes exactly that record
# with the ring-buffer submit helper (132). A null reservation
# (ring full) advances the failed count in entry 3 and
# publishes nothing; a submitted reservation advances the
# successful count in entry 2. Userspace initializes the four
# entries before attaching (filter TID, then zeros) and drains
# the ring afterwards; received == successful with contiguous
# sequences reconciles the run.
#
# Each reservation program commits to exactly one terminus;
# the terminus is fixed per program, never chosen per event,
# and a program containing both termini is refused (MBPF307).
# Prefer this explicit submit path over copy-output when the
# fill logic needs the record address; prefer copy-output when
# every event publishes unconditionally from a fixed scratch
# buffer. The discard terminus (helper 133) releases a
# reservation unpublished and is proven by the kernel suite's
# discard emitter; this example submits every reservation it
# takes. (On the discard path received is 0 while entry 2
# counts the released reservations.)
#
# The reservation is checked for null before any store, stamped
# fully, submitted exactly once, and never touched again
# afterwards. The compiler refuses two reserves, two termini,
# a mixed terminus, and any use after the terminus before the
# kernel sees the program; the kernel verifier independently
# rejects the same shapes.

from mojobpf.events import (
    EVENT_RECORD_SIZE,
    EVENT_RECORD_VERSION,
    RINGBUF_SIZE_LARGE,
    RingbufHandle,
    bpf_get_current_pid_tgid,
    bpf_get_smp_processor_id,
    bpf_ktime_get_ns,
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
