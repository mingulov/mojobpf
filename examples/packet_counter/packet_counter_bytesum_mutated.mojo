# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Mutation of the packet counter: entry 1 accumulates one per
# invocation instead of the frame length (same action, different
# byte sum). Exists for behavior-change proofs: any frame longer
# than one byte observes the wrong sum. The unused length folds
# away, so the object carries one more constant increment than the
# qualified shape and the build driver refuses to publish it; the
# raw pipeline still builds it for the in-guest proof.

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
    slot1[unsafe_offset=0] = old1 + 1
    var key1b = key_slot1()
    _ = bpf_map_update(MapHandle.load().addr, key1b, slot1, Int64(BPF_ANY))
    return action
