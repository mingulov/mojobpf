# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Mutant of the Amendment A2 exhibit: the join-gate constant
# changes 100 -> 300 (single constant). NOT EXECUTED in Q;
# carried for the cost triple's mojo leg and the exhibit pair
# shape. Would-DROP on 60 zero bytes (w = 302).
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
    if packet_short(pkt, 16):
        return Int32(XDP_PASS)
    var base = packet_base(packet_addr(pkt, 0))
    var a = UInt64(load_u8(base, 14))
    var b = UInt64(load_u8(base, 15))
    var v: UInt64
    if a > b:
        v = classify(a)
    else:
        v = classify(b)
    var w = v + 300
    if w > 200:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)


@export
@no_inline
def classify(byte_val: UInt64) abi("C") -> UInt64:
    if (byte_val & 1) == 1:
        return UInt64(XDP_DROP)
    return UInt64(XDP_PASS)
