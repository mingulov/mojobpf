# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Subprogram shape with the entrypoint defined first: the same
# drop-on-bit-0 rule as the public decision example, but the
# callee (`classify`) is defined after the entrypoint in source
# order, so the frontend numbers the attribute sets the other way
# around (entry `#0`, callee `#1`). The audit admits both orders
# as the one call shape; the kernel suite executes this object
# too, so both orders are proven in the guest, not just in IR.

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
    var eth_last = load_u8(base, 14)
    var action = classify(UInt64(eth_last))
    return Int32(action)


@export
@no_inline
def classify(byte_val: UInt64) abi("C") -> UInt64:
    if (byte_val & 1) == 1:
        return UInt64(XDP_DROP)
    return UInt64(XDP_PASS)
