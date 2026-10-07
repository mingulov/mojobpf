# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# case: casts
# Explicit integer narrowing/widening round trip over a packet word.

from mojobpf.packet import GUARD_ACTION, XDP_DROP, XDP_PASS, XdpCtx, load_u32_le, packet_addr, packet_base, packet_short


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 18):
        return Int32(GUARD_ACTION)
    var base = packet_base(packet_addr(pkt, 0))
    var w32 = load_u32_le(base, 14)
    var b0 = UInt8(w32 & UInt32(0xFF))
    var b1 = UInt8((w32 >> UInt32(8)) & UInt32(0xFF))
    var b2 = UInt8((w32 >> UInt32(16)) & UInt32(0xFF))
    var b3 = UInt8((w32 >> UInt32(24)) & UInt32(0xFF))
    var wide = UInt64(b0) | (UInt64(b1) << UInt64(8)) | (UInt64(b2) << UInt64(16)) | (UInt64(b3) << UInt64(24))
    if wide == UInt64(0x12345678):
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
