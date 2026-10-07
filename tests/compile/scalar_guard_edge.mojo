# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Length-guard exact edge, through the packet SDK.
#
# Behavior: drop the packet (return 1, XDP_DROP) when the frame holds
# at least 14 bytes and the last guarded byte (byte 13) is 0xA5;
# pass it (return 2, XDP_PASS) when the frame holds at least 14
# bytes with any other byte 13. Frames shorter than 14 bytes take
# the guard path, which fails closed to XDP_DROP.
#
# A frame of exactly 14 bytes proceeds past the guard (the need
# equals the length, so the short check is false) while a 13-byte
# frame trips it, pinning the guard's off-by-one boundary. The
# smallest frames (one byte, empty) exercise the same path.
#
# The program uses no main function, printing, heap allocation, Python
# interop, exceptions, or runtime init. It exposes exactly one C-ABI
# entry point returning a 32-bit action code for a context pointer.

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
    if packet_short(pkt, 14):
        return Int32(GUARD_ACTION)
    var base = packet_base(packet_addr(pkt, 0))
    var last = load_u8(base, 13)
    if last == 0xA5:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
