# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Short-packet guard path through the packet SDK.
#
# Behavior: frames shorter than 64 bytes take the guard path, which
# fails closed to XDP_DROP (return 1). Frames of at least 64 bytes
# pass (return 2, XDP_PASS) when byte 63 is 0x5A and drop otherwise.
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
    if packet_short(pkt, 64):
        return Int32(GUARD_ACTION)
    var base = packet_base(packet_addr(pkt, 0))
    var last = load_u8(base, 63)
    if last == 0x5A:
        return Int32(XDP_PASS)
    return Int32(XDP_DROP)
