# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Refused reproducer: classifier rule plus map counting in one program.
#
# This source passes the Mojo frontend but the IR audit refuses it
# with MBPF307: the program needs two address reinterpretations (one
# for the guarded packet byte, one for the map-value dereference)
# while the map shape allows exactly one. No packet-content action
# can share a program with map counting until the audit admits that
# second reinterpretation. The committed demos keep the two halves
# separate (packet_classifier classifies without a map, xdp_counter
# counts without inspecting bytes).

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, value_slot
from mojobpf.packet import (
    XDP_DROP,
    XDP_PASS,
    XdpCtx,
    load_u8,
    packet_addr,
    packet_base,
    packet_short,
)


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    var is_drop = False
    if packet_short(pkt, 15):
        is_drop = False
    else:
        var base = packet_base(packet_addr(pkt, 0))
        var eth_last = load_u8(base, 14)
        is_drop = (eth_last & 1) == 1
    if is_drop:
        return Int32(XDP_DROP)
    var key = key_slot()
    var found = bpf_map_lookup(MapHandle.load().addr, key)
    if found.is_null():
        return Int32(XDP_PASS)
    var slot = value_slot()
    var old = found.unsafe_value_ptr()[unsafe_offset=0]
    slot[unsafe_offset=0] = old + 1
    var key2 = key_slot()
    _ = bpf_map_update(MapHandle.load().addr, key2, slot, Int64(BPF_ANY))
    return Int32(XDP_PASS)
