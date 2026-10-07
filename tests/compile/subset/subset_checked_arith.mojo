# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# case: checked-arith
# Checked arithmetic: narrow-multiply wrap detection plus u32 headroom.

from mojobpf.packet import GUARD_ACTION, XDP_DROP, XDP_PASS, XdpCtx, load_u8, load_u32_le, packet_addr, packet_base, packet_short


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 18):
        return Int32(GUARD_ACTION)
    var base = packet_base(packet_addr(pkt, 0))
    var b = load_u8(base, 14)
    var doubled_wide = UInt16(b) * UInt16(2)
    var doubled_narrow = UInt16(b * UInt8(2))
    if doubled_narrow != doubled_wide:
        return Int32(XDP_DROP)
    var w = load_u32_le(base, 14)
    if w > UInt32(0xFFFFFFFF) - UInt32(200):
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
