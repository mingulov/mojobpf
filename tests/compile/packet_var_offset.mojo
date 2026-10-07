# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Variable-offset load with a runtime bound check, through the SDK.
#
# Behavior: let off be the packet length masked to six bits. Drop the
# packet (return 1, XDP_DROP) when the frame holds byte `off` and bit
# 0 of that byte is set; pass it (return 2, XDP_PASS) when the byte
# exists with bit 0 clear. Frames too short to hold byte `off` take
# the guard path, which fails closed to XDP_DROP.
#
# The offset derives from the packet length (a context-word value),
# never from a packet pre-load: the guarded address and the loaded
# address are one shared computation, which is the shape the kernel
# verifier tracks. A content-derived offset would need a second
# address reinterpretation and is outside the supported subset.
#
# The program uses no main function, printing, heap allocation, Python
# interop, exceptions, or runtime init. It exposes exactly one C-ABI
# entry point returning a 32-bit action code for a context pointer.

from mojobpf.packet import (
    GUARD_ACTION,
    XDP_DROP,
    XDP_PASS,
    XdpCtx,
    addr_short,
    load_u8,
    packet_addr,
    packet_base,
    packet_len,
)


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    var off = packet_len(pkt) & 63
    var addr = packet_addr(pkt, off)
    if addr_short(addr, pkt, 1):
        return Int32(GUARD_ACTION)
    var slot = packet_base(addr)
    var mark = load_u8(slot, 0)
    if (mark & 1) == 1:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
