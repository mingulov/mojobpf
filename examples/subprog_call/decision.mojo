# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# XDP packet decision through one static subprogram call, in Mojo.
#
# Behavior: drop the packet (return 1, XDP_DROP) when the frame holds
# at least 15 bytes and bit 0 of byte 14 is set; pass it (return 2,
# XDP_PASS) otherwise. Frames shorter than 15 bytes take the pass
# path through the explicit bounds check: the short-input action is
# part of the specified rule. The bit test itself lives in the
# `decide` subprogram below, so every full-size frame's action is an
# input-dependent result computed through the call, not in the
# entrypoint body.
#
# The call discipline (the only admitted BPF-to-BPF call shape):
# exactly one callee per program, spelled `@export` + `@no_inline`
# with a C ABI and the fixed one-argument scalar signature
# `(UInt64) -> UInt64` (one 64-bit integer in, one out). The
# entrypoint calls it with `tail call` IR the frontend emits; the
# callee body is pure scalar arithmetic with no calls of its own
# (no recursion, no helper calls, no calls back into the
# entrypoint). Any second callee, any other arity or argument type,
# any call inside the callee, and any call outside an XDP
# classifier program is refused before the backend runs.
#
# It uses no main function, printing, heap allocation, Python
# interop, exceptions, maps, helpers, or runtime init. It exposes
# exactly one C-ABI entry point returning a 32-bit action code for
# a context pointer, plus the one C-ABI subprogram above it.

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
@no_inline
def decide(byte_val: UInt64) abi("C") -> UInt64:
    if (byte_val & 1) == 1:
        return UInt64(XDP_DROP)
    return UInt64(XDP_PASS)


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 15):
        return Int32(XDP_PASS)
    var base = packet_base(packet_addr(pkt, 0))
    var eth_last = load_u8(base, 14)
    var action = decide(UInt64(eth_last))
    return Int32(action)
