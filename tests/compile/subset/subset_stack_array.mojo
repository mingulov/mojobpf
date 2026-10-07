# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# case: stack-array
# Initialized fixed stack array promoted to SSA (no alloca).
from mojobpf.packet import GUARD_ACTION, XDP_DROP, XDP_PASS, XdpCtx, load_u8, packet_addr, packet_base, packet_short


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 18):
        return Int32(GUARD_ACTION)
    var base = packet_base(packet_addr(pkt, 0))
    var buf = Array[UInt8, 4](uninitialized=True)
    buf[0] = load_u8(base, 14)
    buf[1] = load_u8(base, 15)
    buf[2] = load_u8(base, 16)
    buf[3] = load_u8(base, 17)
    var total = UInt32(buf[0]) + UInt32(buf[1]) + UInt32(buf[2]) + UInt32(buf[3])
    if total > 200:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
