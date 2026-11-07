# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Closest admitted Mojo diamond (F-ISA/jmp/uncond Amendment A2
# exhibit): the same callee invoked in BOTH diamond arms, with
# a join gate. The adapter admits it (two call sites to the one
# callee preserved), but the backend merges the two calls into
# one shared call, so the emitted object carries 0 JA. This is
# the documented negative finding's exhibit: no admitted Mojo
# source emits JA. NOT EXECUTED in Q (the C control and the
# hand-IR oracle carry the executed JA cells). A host regression
# pins the 0-JA shape; if a future backend emits JA for this
# program, the regression fails and the amendment is revisited.
#
# Behavior (not executed): bounds check + read bytes 14/15;
# v = classify(a) or classify(b); w = v + 100; XDP_DROP (1)
# when w > 200, else XDP_PASS (2). On 60 zero bytes the else
# arm runs (v = 2), w = 102, PASS.
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
    var a = UInt64(load_u8(base, 14))
    var b = UInt64(load_u8(base, 15))
    var v: UInt64
    if a > b:
        v = classify(a)
    else:
        v = classify(b)
    var w = v + 100
    if w > 200:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)


@export
@no_inline
def classify(byte_val: UInt64) abi("C") -> UInt64:
    if (byte_val & 1) == 1:
        return UInt64(XDP_DROP)
    return UInt64(XDP_PASS)
