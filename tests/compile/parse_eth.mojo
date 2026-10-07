# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Ethernet parse with EtherType dispatch through the parse SDK.
#
# Behavior: drop the packet (return 1, XDP_DROP) when the frame holds
# at least 14 bytes and the bytes-12-13 field reads IPv4 (0x0800 in
# network order); pass it (return 2, XDP_PASS) otherwise. Frames
# shorter than 14 bytes take the guard path, which fails closed to
# XDP_DROP.
#
# The 2-byte field is read with the parsing slice (a little-endian
# load plus a byte swap) on a cursor advanced by the 12-byte address
# run, so the loaded offset stays a folded constant. The program uses
# no main function, printing, heap allocation, Python interop,
# exceptions, or runtime init. It exposes exactly one C-ABI entry
# point returning a 32-bit action code for a context pointer.

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
from mojobpf.parse import load_u16_be


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 14):
        return Int32(GUARD_ACTION)
    var cursor = Cursor(packet_base(packet_addr(pkt, 0)), 0).advance(12)
    var ethertype = load_u16_be(cursor.base, cursor.off)
    if ethertype == 0x0800:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
