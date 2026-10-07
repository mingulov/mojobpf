# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative fixture: unguarded packet dereference.
#
# This program loads byte 14 with no length guard. It compiles
# through the genuine pipeline (the audit admits its shape) and must
# then be rejected by the kernel verifier at load: it proves that a
# missing guard fails loudly in the kernel rather than silently
# passing, and that the structural guard checks discriminate (this
# fixture's IR carries no guard pattern).
#
# It is a rejection control only and never runs.

from mojobpf.packet import (
    XDP_DROP,
    XDP_PASS,
    XdpCtx,
    load_u8,
    packet_addr,
    packet_base,
)


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    var base = packet_base(packet_addr(pkt, 0))
    var eth_last = load_u8(base, 14)
    if (eth_last & 1) == 1:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
