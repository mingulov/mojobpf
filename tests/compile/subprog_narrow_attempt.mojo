# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative attempt: 32-bit subprogram signature. The callee takes
# and returns a 32-bit integer, so the audit must refuse its
# definition with MBPF302 at stage adapter.audit (the admitted
# call shape fixes the signature at exactly (i64)->i64).

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
def narrow(byte_val: UInt32) abi("C") -> UInt32:
    return byte_val + 1


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 15):
        return Int32(XDP_PASS)
    var base = packet_base(packet_addr(pkt, 0))
    var eth_last = load_u8(base, 14)
    var action = narrow(UInt32(eth_last))
    if action == 2:
        return Int32(1)
    return Int32(XDP_PASS)
