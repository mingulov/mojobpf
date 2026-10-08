# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Explicit ring reservation emitter (discard path), written in Mojo.
#
# Behavior: identical to reserve_submit.mojo up to the
# reservation (TID filter in entry 0, per-attempt sequence in
# entry 1, CPU/clock/identity reads, then a 32-byte reserve with
# helper 131). A null reservation increments the dropped count
# in entry 3 and publishes nothing. Otherwise the program
# stamps the 32-byte record directly into the reservation with
# one word store per field and releases it with the ring-buffer
# discard helper (133), which publishes nothing; a discarded
# reservation increments the released count in entry 2. A null
# reservation increments the failed count in entry 3. This
# program contains no submit call, so a full run drains zero
# records while the counters prove every attempt reserved and
# released-or-failed exactly once (attempted = released +
# failed, received = 0).
#
# The reservation pointer is checked for null before any store;
# the reservation is discarded exactly once on the non-null
# path and never touched again afterwards: discard followed by
# any use is a refused shape. See reserve_submit.mojo for the
# TID discipline, the unused-context rule, and the ring-size
# note. This emitter uses the large (healthy) ring
# (RINGBUF_SIZE_LARGE).

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
        bpf_ringbuf_discard(base, Int64(0))
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
        var nkey = key_slot3()
        var nfound = bpf_map_lookup(MapHandle.load().addr, nkey)
        if nfound.is_null():
            return Int32(0)
        var nslot = value_slot()
        nslot[unsafe_offset=0] = nfound.unsafe_value_ptr()[unsafe_offset=0] + 1
        var nkey2 = key_slot3()
        _ = bpf_map_update(
            MapHandle.load().addr, nkey2, nslot, Int64(BPF_ANY)
        )
    return Int32(0)
