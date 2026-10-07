# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Four-byte alignment-safe load through the packet SDK.
#
# Behavior: drop the packet (return 1, XDP_DROP) when the frame holds
# at least 18 bytes and bytes 14-17 read 0x78563412 little-endian;
# pass it (return 2, XDP_PASS) otherwise. Frames shorter than 18
# bytes take the guard path, which fails closed to XDP_DROP.
#
# The program uses no main function, printing, heap allocation, Python
# interop, exceptions, or runtime init. It exposes exactly one C-ABI
# entry point returning a 32-bit action code for a context pointer.

from mojobpf.packet import (
    GUARD_ACTION,
    XDP_DROP,
    XDP_PASS,
    XdpCtx,
    load_u32_le,
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
    var word = load_u32_le(base, 14)
    if word == 0x78563412:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
