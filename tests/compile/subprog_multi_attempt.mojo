# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative attempt: two subprogram callees. The entrypoint calls
# two distinct callees, so the audit must refuse the second
# callee definition with MBPF302 at stage adapter.audit (the
# admitted call shape admits exactly one callee per program).

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
def first(byte_val: UInt64) abi("C") -> UInt64:
    return byte_val + 1


@export
@no_inline
def second(byte_val: UInt64) abi("C") -> UInt64:
    return byte_val + 2


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 15):
        return Int32(XDP_PASS)
    var base = packet_base(packet_addr(pkt, 0))
    var eth_last = load_u8(base, 14)
    var action = first(UInt64(eth_last)) + second(UInt64(eth_last))
    if action == 3:
        return Int32(1)
    return Int32(XDP_PASS)
