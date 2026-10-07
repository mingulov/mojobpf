# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Mutated XDP classifier: drops when bit 0 of byte 14 is CLEAR.
#
# This file is identical to classifier.mojo except for the bit-test
# comparison below (`== 1` became `== 0`). It exists so behavior
# tests can prove that a source change alters rebuilt behavior and
# that the suites detect the change: with this mutation, the drop
# and pass fixtures swap their expected actions, so the unmutated
# expectations fail against the rebuilt mutant and pass again once
# the mutation is reverted.

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
    if (eth_last & 1) == 0:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
