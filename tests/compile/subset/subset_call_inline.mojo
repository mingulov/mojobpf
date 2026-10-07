# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# case: call-inline
# Small plain helper inlined by the frontend (no inline attribute).

from mojobpf.packet import GUARD_ACTION, XDP_DROP, XDP_PASS, XdpCtx, packet_addr, packet_base, packet_short


def combine(lo: UInt8, hi: UInt8) -> UInt16:
    return UInt16(lo) | (UInt16(hi) << UInt16(8))


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 22):
        return Int32(GUARD_ACTION)
    var base = packet_base(packet_addr(pkt, 0))
    var word = combine(base[unsafe_offset=20], base[unsafe_offset=21])
    if word == 0xAA55:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
