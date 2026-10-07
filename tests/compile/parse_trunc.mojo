# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Truncated-header guard path: two-tier parse through the parse SDK.
#
# Behavior: frames shorter than 14 bytes take the first guard path,
# which fails closed to XDP_DROP (return 1). Longer frames load the
# bytes-12-13 field. Untagged frames dispatch on it directly: drop
# when it reads IPv4 (0x0800), pass (return 2, XDP_PASS) otherwise.
# Tagged frames (0x8100) must additionally clear the second guard of
# 18 bytes; tagged frames truncated below 18 bytes take that guard
# path to XDP_DROP, while tagged frames of at least 18 bytes dispatch
# on the inner EtherType at bytes 16-17 (drop on IPv4, pass
# otherwise).
#
# Both guards are start-based with constant needs and every packet
# offset is constant; the second guard is conditional on the loaded
# tag value, which is value dispatch, not content-derived addressing.
# The program uses no main function, printing, heap allocation, Python
# interop, exceptions, or runtime init. It exposes exactly one C-ABI
# entry point returning a 32-bit action code for a context pointer.

from mojobpf.packet import (
    GUARD_ACTION,
    XDP_DROP,
    XDP_PASS,
    XdpCtx,
    packet_addr,
    packet_base,
    packet_short,
)
from mojobpf.parse import inner_ethertype, is_vlan_tag, outer_ethertype


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 14):
        return Int32(GUARD_ACTION)
    var base = packet_base(packet_addr(pkt, 0))
    var outer = outer_ethertype(base)
    if is_vlan_tag(outer):
        if packet_short(pkt, 18):
            return Int32(GUARD_ACTION)
        var inner = inner_ethertype(base)
        if inner == 0x0800:
            return Int32(XDP_DROP)
        return Int32(XDP_PASS)
    if outer == 0x0800:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
