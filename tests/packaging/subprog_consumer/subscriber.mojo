# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Third-party XDP subscriber: drops frames whose byte 14 has bit 1
# set, passes everything else. The bit test lives in the
# `select_action` subprogram, reached through the single supported
# BPF-to-BPF call shape (one `@export` + `@no_inline` C-ABI
# callee with the fixed one-argument 64-bit signature, called
# from an XDP classifier entrypoint).
#
# Frames shorter than 15 bytes take the pass path through the
# explicit bounds check. No maps, no helpers, no runtime init.

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
def select_action(byte_val: UInt64) abi("C") -> UInt64:
    if (byte_val & 2) == 2:
        return UInt64(XDP_DROP)
    return UInt64(XDP_PASS)


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 15):
        return Int32(XDP_PASS)
    var base = packet_base(packet_addr(pkt, 0))
    var verdict = select_action(UInt64(load_u8(base, 14)))
    return Int32(verdict)
