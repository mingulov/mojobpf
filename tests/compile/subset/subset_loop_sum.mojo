# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# case: loop-sum
# Bounded for-loop summing packet bytes (constant trip count).
from mojobpf.packet import (
    GUARD_ACTION,
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
    if packet_short(pkt, 18):
        return Int32(GUARD_ACTION)
    var base = packet_base(packet_addr(pkt, 0))
    var total: UInt32 = 0
    for i in range(4):
        total += UInt32(load_u8(base, 14 + i))
    if total > 100:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
