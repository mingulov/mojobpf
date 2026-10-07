# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Ethernet plus single VLAN tag parse through the parse SDK.
#
# Behavior: drop the packet (return 1, XDP_DROP) when the frame holds
# at least 18 bytes, the bytes-12-13 field is the 802.1Q tag protocol
# (0x8100), the inner EtherType at bytes 16-17 is IPv4 (0x0800), and
# the tag-control VLAN identifier is 7; pass it (return 2, XDP_PASS)
# otherwise. Frames shorter than 18 bytes take the guard path, which
# fails closed to XDP_DROP.
#
# The tag is handled by value dispatch over fixed loads, never by
# content-derived addressing: every packet offset is constant. The
# program uses no main function, printing, heap allocation, Python
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
from mojobpf.parse import (
    inner_ethertype,
    is_vlan_tag,
    outer_ethertype,
    vlan_id,
    vlan_tci,
)


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 18):
        return Int32(GUARD_ACTION)
    var base = packet_base(packet_addr(pkt, 0))
    var tpid = outer_ethertype(base)
    var tci = vlan_tci(base)
    var inner = inner_ethertype(base)
    if is_vlan_tag(tpid) and inner == 0x0800 and vlan_id(tci) == 7:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
