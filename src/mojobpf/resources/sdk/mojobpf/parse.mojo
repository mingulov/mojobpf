# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Ethernet header field accessors (plus one optional VLAN tag).
#
# This module is the parsing slice of the MojoBPF SDK: plain-integer
# field extraction over the Ethernet header with an optional single
# 802.1Q tag. Every accessor returns a plain integer or boolean and
# keeps no reference past the caller's guard.
#
# Layout: destination address at bytes 0-5, source address at bytes
# 6-11, then the bytes-12-13 field, which is the EtherType on an
# untagged frame and the tag protocol (TPID) on a tagged frame. A
# tagged frame adds the tag-control field (TCI) at bytes 14-15 and
# the inner EtherType at bytes 16-17, so untagged callers guard 14
# bytes and tagged callers guard 18. Each accessor below names the
# need its caller must establish with the packet guard idiom
# (`packet_short` failing closed to `GUARD_ACTION`) before loading.
#
# Byte order: header fields travel big-endian (network order), while
# the packet loads assemble little-endian, so every accessor here
# swaps to network order before returning. Callers compare against
# ordinary protocol numbers (for example IPv4 reads 0x0800 and the
# tag protocol reads 0x8100).
#
# The optional tag is handled by value dispatch, never by
# content-derived addressing: callers load the fixed fields, test
# `is_vlan_tag`, and select the outer or inner EtherType as integers.
# All packet offsets stay constant, which keeps the verifier's
# packet-range tracking and the single-reinterpretation shape: callers
# still call `packet_base` exactly once, on the guarded address, and
# read 2-byte fields with `load_u16_le` (this module's loads are that
# function plus a swap) on the base plus a constant offset.
#
# The module uses no main function, printing, heap allocation, Python
# interop, exceptions, or runtime init.

from mojobpf.packet import load_u16_le


@inline(.always)
def load_u16_be(base: MutPointer[UInt8, MutAnyOrigin], off: Int) -> UInt16:
    """Load two bytes in network (big-endian) order.

    Caller must have guarded `off + 2` bytes. The swap is plain
    integer arithmetic after an alignment-safe little-endian load.
    """
    var raw = load_u16_le(base, off)
    return (raw << 8) | (raw >> 8)


@inline(.always)
def outer_ethertype(base: MutPointer[UInt8, MutAnyOrigin]) -> UInt16:
    """Bytes-12-13 field: EtherType, or TPID on a tagged frame.

    Caller must have guarded 14 bytes.
    """
    return load_u16_be(base, 12)


@inline(.always)
def vlan_tci(base: MutPointer[UInt8, MutAnyOrigin]) -> UInt16:
    """Tag-control field at bytes 14-15 (caller must guard 16)."""
    return load_u16_be(base, 14)


@inline(.always)
def inner_ethertype(base: MutPointer[UInt8, MutAnyOrigin]) -> UInt16:
    """Inner EtherType at bytes 16-17 (caller must guard 18)."""
    return load_u16_be(base, 16)


@inline(.always)
def vlan_id(tci: UInt16) -> UInt16:
    """Low 12 bits of a tag-control field (the VLAN identifier)."""
    return tci & 0x0FFF


@inline(.always)
def is_vlan_tag(field12: UInt16) -> Bool:
    """True when the bytes-12-13 field is the 802.1Q tag protocol."""
    return field12 == 0x8100
