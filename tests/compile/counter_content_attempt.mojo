# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Refused reproducer: classifier rule plus single-entry counting.
#
# This source passes the Mojo frontend but the IR audit refuses it
# with MBPF307: the program carries two address reinterpretations
# (one for the guarded packet byte, one for the map-value
# dereference) with a single read-modify-write pair, matching
# neither the map vector (one reinterpretation) nor the combined
# vector (three reinterpretations plus two pairs over entries 0 and
# 1). It is also not the packet workload on its own terms: the drop
# path returns before the map pair, so drops are never counted. The
# qualified combined form is the packet_counter example, which
# counts both entries on every path and returns the content action.

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
