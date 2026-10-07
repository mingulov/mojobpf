# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Rejected negative: last-byte load through the address-form guard.
#
# Intended behavior (NOT exhibited: the kernel refuses this object
# at load): let off be the packet length minus one, then drop when
# the last byte exists with bit 0 set, else pass, with guards
# failing closed. Two guards cooperate: a start-based guard first
# requires at least one byte so the minus-one offset cannot wrap
# on an empty frame, then the address-based guard checks one byte
# at the computed address.
#
# The object compiles through the genuine pipeline and passes the
# IR audit as the classifier shape, but the kernel verifier
# rejects it at load with `R2 pointer arithmetic on pkt_end
# prohibited`: the backend rewrites the data-plus-(length-minus-one)
# address into data-end-minus-one, which is prohibited arithmetic.
# The unmasked last-byte edge is therefore unrepresentable through
# this pipeline; the kernel suite asserts this exact rejection, and
# the wrap-free offset arithmetic itself is covered by the
# differential scalar suite over synthetic length contexts.
#
# The program uses no main function, printing, heap allocation, Python
# interop, exceptions, or runtime init. It exposes exactly one C-ABI
# entry point returning a 32-bit action code for a context pointer.

from mojobpf.packet import (
    GUARD_ACTION,
    XDP_DROP,
    XDP_PASS,
    XdpCtx,
    addr_short,
    load_u8,
    packet_addr,
    packet_base,
    packet_len,
    packet_short,
)


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 1):
        return Int32(GUARD_ACTION)
    var off = packet_len(pkt) - 1
    var addr = packet_addr(pkt, off)
    if addr_short(addr, pkt, 1):
        return Int32(GUARD_ACTION)
    var slot = packet_base(addr)
    var last = load_u8(slot, 0)
    if (last & 1) == 1:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
