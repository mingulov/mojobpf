# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative attempt: subprogram call under a tracepoint entrypoint.
# The call shape itself is exact, but the entrypoint is
# trace_entry, so the audit must refuse the entry/family mismatch
# with MBPF302 at stage adapter.audit (the admitted call shape is
# XDP-only).

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
def trace_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 15):
        return Int32(XDP_PASS)
    var base = packet_base(packet_addr(pkt, 0))
    var eth_last = load_u8(base, 14)
    var action = decide(UInt64(eth_last))
    return Int32(action)
