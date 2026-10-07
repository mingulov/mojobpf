# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Refused reproducer: per-packet byte accumulation into the map.
#
# This source passes the Mojo frontend but the IR audit refuses it
# with MBPF308: the frame length is derived from the context words
# before the lookup call and added to the map value after it, so a
# packet-derived value stays live across a helper call. The shape
# counts are satisfied (no packet byte is loaded), which is what
# distinguishes this pin from counter_content_attempt.mojo: even
# with the reinterpretation budget intact, packet-derived update
# values cannot reach the map. The committed counter therefore
# adds the constant one per invocation.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, value_slot
from mojobpf.packet import XdpCtx, packet_len


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    var length = packet_len(pkt)
    var key = key_slot()
    var found = bpf_map_lookup(MapHandle.load().addr, key)
    if found.is_null():
        return Int32(2)
    var slot = value_slot()
    var old = found.unsafe_value_ptr()[unsafe_offset=0]
    slot[unsafe_offset=0] = old + length
    var key2 = key_slot()
    _ = bpf_map_update(MapHandle.load().addr, key2, slot, Int64(BPF_ANY))
    return Int32(2)
