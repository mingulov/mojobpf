# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# case: escape-value
# Negative: packet pointer passed as a map-update value.
from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, value_slot
from mojobpf.packet import XdpCtx, packet_addr, packet_base


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    var base = packet_base(packet_addr(pkt, 0))
    var key = key_slot()
    var found = bpf_map_lookup(MapHandle.load().addr, key)
    if found.is_null():
        return Int32(2)
    var slot = value_slot()
    var leaked = base.unsafe_bitcast[UInt64]()
    _ = bpf_map_update(MapHandle.load().addr, key_slot(), leaked, Int64(BPF_ANY))
    return Int32(2)
