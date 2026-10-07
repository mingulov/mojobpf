# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# XDP packet classifier with invocation and byte accounting, in Mojo.
#
# Behavior: return XDP_DROP (1) when the frame holds at least 15
# bytes and bit 0 of byte 14 is set, else XDP_PASS (2); add one to
# entry 0 and the frame length to entry 1 of the two-entry array map
# on every invocation. Frames shorter than 15 bytes take the pass
# path through the explicit bounds check: the short-input action is
# part of the specified rule, not the SDK's fail-closed guard idiom
# (short frames are ordinary traffic here, not errors).
#
# Both read-modify-write pairs run on every path that reaches them,
# including the drop path: counting is unconditional. On a lookup
# miss the program returns the content action without counting that
# entry (an in-range array lookup never misses; the checks satisfy
# the kernel verifier). The pairs run sequentially, so a miss in the
# second pair after a hit in the first would advance entry 0 only;
# that path is unreachable in range and both orders agree there.
#
# The action selector and the frame length are computed before the
# first helper call and used after later ones; the IR audit admits
# these cross-call packet values only in the combined count vector
# (one packet reinterpretation plus two map pairs), while the
# pointer-store rule still rejects any kernel address reaching a
# store. The program uses no main function, printing, heap
# allocation, Python interop, exceptions, or runtime init. It
# exposes exactly one C-ABI entry point returning a 32-bit action
# code for a context pointer.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, key_slot1, value_slot
from mojobpf.packet import (
    XDP_DROP,
    XDP_PASS,
    XdpCtx,
    load_u8,
    packet_addr,
    packet_base,
    packet_len,
    packet_short,
)


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    var length = packet_len(pkt)
    var is_drop = False
    if packet_short(pkt, 15):
        is_drop = False
    else:
        var base = packet_base(packet_addr(pkt, 0))
        var eth_last = load_u8(base, 14)
        is_drop = (eth_last & 1) == 1
    var action = Int32(XDP_PASS)
    if is_drop:
        action = Int32(XDP_DROP)
    var key0 = key_slot()
    var found0 = bpf_map_lookup(MapHandle.load().addr, key0)
    if found0.is_null():
        return action
    var slot0 = value_slot()
    var old0 = found0.unsafe_value_ptr()[unsafe_offset=0]
    slot0[unsafe_offset=0] = old0 + 1
    var key0b = key_slot()
    _ = bpf_map_update(MapHandle.load().addr, key0b, slot0, Int64(BPF_ANY))
    var key1 = key_slot1()
    var found1 = bpf_map_lookup(MapHandle.load().addr, key1)
    if found1.is_null():
        return action
    var slot1 = value_slot()
    var old1 = found1.unsafe_value_ptr()[unsafe_offset=0]
    slot1[unsafe_offset=0] = old1 + length
    var key1b = key_slot1()
    _ = bpf_map_update(MapHandle.load().addr, key1b, slot1, Int64(BPF_ANY))
    return action
