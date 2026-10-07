# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Bounded-window checksum through the checksum SDK.
#
# Behavior: drop the packet (return 1, XDP_DROP) when the frame holds
# at least 24 bytes and the ones-complement checksum of the four
# network-order words at bytes 14-15, 16-17, 18-19, and 20-21 equals
# the expected network-order word at bytes 22-23; pass it (return 2,
# XDP_PASS) otherwise. Frames shorter than 24 bytes take the guard
# path, which fails closed to XDP_DROP.
#
# The accumulation is fully unrolled (four explicit adds, then fold
# and complement) with constant offsets: no loops, no content-derived
# addressing. The program uses no main function, printing, heap
# allocation, Python interop, exceptions, or runtime init. It exposes
# exactly one C-ABI entry point returning a 32-bit action code for a
# context pointer.

from mojobpf.checksum import cksum_add, cksum_finalize
from mojobpf.packet import (
    GUARD_ACTION,
    XDP_DROP,
    XDP_PASS,
    XdpCtx,
    packet_addr,
    packet_base,
    packet_short,
)
from mojobpf.parse import load_u16_be


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 24):
        return Int32(GUARD_ACTION)
    var base = packet_base(packet_addr(pkt, 0))
    var acc = UInt32(0)
    acc = cksum_add(acc, load_u16_be(base, 14))
    acc = cksum_add(acc, load_u16_be(base, 16))
    acc = cksum_add(acc, load_u16_be(base, 18))
    acc = cksum_add(acc, load_u16_be(base, 20))
    var digest = cksum_finalize(acc)
    var expect = load_u16_be(base, 22)
    if digest == expect:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
