# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Mutated XDP decision: drops when bit 0 of byte 14 is CLEAR, and the
# subprogram call is gone (the inverted test is inline in the
# entrypoint, so this mutant is a plain call-free classifier).
#
# This file exists so behavior tests can prove two things at once:
# that the suites detect a source change (the drop and pass fixtures
# swap their expected actions, so the unmutated expectations fail
# against the rebuilt mutant and pass again once the mutation is
# reverted), and that the base program's board genuinely depends on
# the call shape (removing the call changes the observed behavior).
# It builds under the base profile: no subprogram, no capability
# beyond the classifier subset.

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
