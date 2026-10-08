# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Third-party reservation emitter written in Mojo by the consumer.
#
# Conduct: on every syscalls:sys_enter_getpid event, keep only the
# monitored thread (entry 0 holds its TID; anything else returns 0
# without reserving), number the attempt from entry 1, snapshot the
# CPU, the clock, and the PID/TID word, then reserve one 32-byte
# record, stamp it field by field, and submit it. A null
# reservation (ring full) bumps entry 3 and publishes nothing; a
# submitted reservation bumps entry 2. Seeded with the monitored
# TID in entry 0 and zeros elsewhere, N monitored calls drain N
# records numbered 0 through N-1.
#
# Safety habits: the reservation outcome is an unchecked address
# (0 is empty). The emptiness test guards everything that
# follows; dropping the test fails kernel verification. The seven
# field stores land before the single submit, and the reservation
# is never touched again afterwards: a second terminus or any use
# after it is refused before the kernel sees the program.

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
    var wanted_key = key_slot()
    var wanted_hit = bpf_map_lookup(MapHandle.load().addr, wanted_key)
    if wanted_hit.is_null():
        return Int32(0)
    var wanted = wanted_hit.unsafe_value_ptr()[unsafe_offset=0]
    var here = bpf_get_current_pid_tgid() & Int64(0xFFFFFFFF)
    if Int64(wanted) != here:
        return Int32(0)
    var ticket_key = key_slot1()
    var ticket_hit = bpf_map_lookup(MapHandle.load().addr, ticket_key)
    if ticket_hit.is_null():
        return Int32(0)
    var ticket = ticket_hit.unsafe_value_ptr()[unsafe_offset=0]
    var ticket_cell = value_slot()
    ticket_cell[unsafe_offset=0] = ticket + 1
    var ticket_store = key_slot1()
    _ = bpf_map_update(
        MapHandle.load().addr, ticket_store, ticket_cell, Int64(BPF_ANY)
    )
    var core = UInt32(bpf_get_smp_processor_id() & Int64(0xFFFFFFFF))
    var stamp = UInt64(bpf_ktime_get_ns())
    var identity = bpf_get_current_pid_tgid()
    var group = UInt32((identity >> 32) & Int64(0xFFFFFFFF))
    var thread = UInt32(identity & Int64(0xFFFFFFFF))
    var booking = bpf_ringbuf_reserve(
        RingbufHandle.load(Int64(RINGBUF_SIZE_LARGE)).addr,
        Int64(EVENT_RECORD_SIZE),
        Int64(0),
    )
    if not booking.is_null():
        var page = booking.unsafe_reserve_ptr()
        page.unsafe_bitcast[UInt16]().unsafe_write(
            UInt16(EVENT_RECORD_VERSION)
        )
        page.unsafe_offset(2).unsafe_bitcast[UInt16]().unsafe_write(
            UInt16(EVENT_RECORD_SIZE)
        )
        page.unsafe_offset(4).unsafe_bitcast[UInt32]().unsafe_write(group)
        page.unsafe_offset(8).unsafe_bitcast[UInt32]().unsafe_write(thread)
        page.unsafe_offset(12).unsafe_bitcast[UInt32]().unsafe_write(core)
        page.unsafe_offset(16).unsafe_bitcast[UInt64]().unsafe_write(ticket)
        page.unsafe_offset(24).unsafe_bitcast[UInt64]().unsafe_write(stamp)
        bpf_ringbuf_submit(page, Int64(0))
        var kept_key = key_slot2()
        var kept_hit = bpf_map_lookup(MapHandle.load().addr, kept_key)
        if kept_hit.is_null():
            return Int32(0)
        var kept_cell = value_slot()
        kept_cell[unsafe_offset=0] = (
            kept_hit.unsafe_value_ptr()[unsafe_offset=0] + 1
        )
        var kept_store = key_slot2()
        _ = bpf_map_update(
            MapHandle.load().addr, kept_store, kept_cell, Int64(BPF_ANY)
        )
    else:
        var lost_key = key_slot3()
        var lost_hit = bpf_map_lookup(MapHandle.load().addr, lost_key)
        if lost_hit.is_null():
            return Int32(0)
        var lost_cell = value_slot()
        lost_cell[unsafe_offset=0] = (
            lost_hit.unsafe_value_ptr()[unsafe_offset=0] + 1
        )
        var lost_store = key_slot3()
        _ = bpf_map_update(
            MapHandle.load().addr, lost_store, lost_cell, Int64(BPF_ANY)
        )
    return Int32(0)
