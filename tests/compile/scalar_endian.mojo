# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Boundary integer words in both byte orders, through the SDK.
#
# Behavior: drop the packet (return 1, XDP_DROP) when the frame holds
# at least 28 bytes and every asserted word matches its boundary
# constant: the network-order words at bytes 14, 16, 18, and 20 read
# 0x0000, 0xFFFF, 0x00FF, and 0x8001; the little-endian half at byte
# 22 reads 0xFF00; and the little-endian word at byte 24 reads
# 0x80000001. Pass it (return 2, XDP_PASS) when any word differs.
# Frames shorter than 28 bytes take the guard path, which fails
# closed to XDP_DROP.
#
# The constants pin zero, all-ones, asymmetric halves, and
# sign-plus-low-bit edges per width and byte order, so a swapped,
# truncated, or half-dropped conversion fails the conjunction. All
# offsets stay constant, keeping the single-reinterpretation shape.
#
# The program uses no main function, printing, heap allocation, Python
# interop, exceptions, or runtime init. It exposes exactly one C-ABI
# entry point returning a 32-bit action code for a context pointer.

from mojobpf.packet import (
    GUARD_ACTION,
    XDP_DROP,
    XDP_PASS,
    XdpCtx,
    load_u16_le,
    load_u32_le,
    packet_addr,
    packet_base,
    packet_short,
)
from mojobpf.parse import load_u16_be


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 28):
        return Int32(GUARD_ACTION)
    var base = packet_base(packet_addr(pkt, 0))
    var be0 = load_u16_be(base, 14)
    var be1 = load_u16_be(base, 16)
    var be2 = load_u16_be(base, 18)
    var be3 = load_u16_be(base, 20)
    var le16 = load_u16_le(base, 22)
    var le32 = load_u32_le(base, 24)
    if (
        be0 == 0x0000
        and be1 == 0xFFFF
        and be2 == 0x00FF
        and be3 == 0x8001
        and le16 == 0xFF00
        and le32 == 0x80000001
    ):
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
