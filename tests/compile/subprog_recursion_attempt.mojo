# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative attempt: recursive subprogram. The callee calls itself,
# so the audit must refuse the self-call with MBPF312 at stage
# adapter.audit (recursion is outside the admitted call shape,
# which admits exactly one non-recursive callee).

from mojobpf.packet import (
    XDP_PASS,
    XdpCtx,
    load_u8,
    packet_addr,
    packet_base,
    packet_short,
)


@export
@no_inline
def countdown(n: UInt64) abi("C") -> UInt64:
    if n == 0:
        return UInt64(0)
    return countdown(n - 1) + 1


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 15):
        return Int32(XDP_PASS)
    var base = packet_base(packet_addr(pkt, 0))
    var eth_last = load_u8(base, 14)
    var action = countdown(UInt64(eth_last))
    if action == 1:
        return Int32(1)
    return Int32(XDP_PASS)
