# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# XDP packet classifier written in Mojo.
#
# Behavior: drop the packet (return 1, XDP_DROP) when the frame holds
# at least 15 bytes and bit 0 of byte 14 is set; pass it (return 2,
# XDP_PASS) otherwise. Frames shorter than 15 bytes take the pass
# path through the explicit bounds check: the short-input action is
# part of the specified rule, not the SDK's fail-closed guard idiom
# (short frames are ordinary traffic here, not errors).
#
# The program reads the kernel XDP context (packet data/data_end
# offsets) through the packet SDK's context handle, guards the load
# with an explicit 15-byte length check, reinterprets the guarded
# address once, and loads a single packet byte. It uses no main
# function, printing, heap allocation, Python interop, exceptions,
# maps, helpers, or runtime init. It exposes exactly one C-ABI entry
# point returning a 32-bit action code for a context pointer.

from mojobpf.packet import (
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
    if packet_short(pkt, 15):
        return Int32(XDP_PASS)
    var base = packet_base(packet_addr(pkt, 0))
    var eth_last = load_u8(base, 14)
    if (eth_last & 1) == 1:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
