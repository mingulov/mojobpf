# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Cursor advance across a header-sized step, through the packet SDK.
#
# Behavior: drop the packet (return 1, XDP_DROP) when the frame holds
# at least 16 bytes, bit 0 of the byte under the advanced cursor
# (byte 14) is set, and the following byte (byte 15) is 0x34; pass
# it (return 2, XDP_PASS) otherwise. Frames shorter than 16 bytes
# take the guard path, which fails closed to XDP_DROP.
#
# The program uses no main function, printing, heap allocation, Python
# interop, exceptions, or runtime init. It exposes exactly one C-ABI
# entry point returning a 32-bit action code for a context pointer.

from mojobpf.packet import (
    GUARD_ACTION,
    XDP_DROP,
    XDP_PASS,
    Cursor,
    XdpCtx,
    packet_addr,
    packet_base,
    packet_short,
)


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 16):
        return Int32(GUARD_ACTION)
    var cursor = Cursor(packet_base(packet_addr(pkt, 0)), 0).advance(14)
    var eth_last = cursor.u8()
    var next_first = cursor.u8_at(1)
    if (eth_last & 1) == 1 and next_first == 0x34:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
