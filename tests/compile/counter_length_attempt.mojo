# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Refused reproducer: length-gated action plus map counting.
#
# This source passes the Mojo frontend but the IR audit refuses it
# with MBPF308. The two constant returns (drop on the short path,
# pass after the map update on the long path) are merged by the
# frontend into one return of a selected value, and that value is
# defined before the lookup call but used after it, which the
# cross-call liveness rule forbids. The merge is optimizer behavior
# rather than source structure, so this pin is narrower than the
# shape-count refusal of counter_content_attempt.mojo; both pins
# together map the wall around packet-dependent counting.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, value_slot
from mojobpf.packet import XDP_DROP, XDP_PASS, XdpCtx, packet_len

comptime MIN_FRAME = 64


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_len(pkt) < MIN_FRAME:
        return Int32(XDP_DROP)
    var key = key_slot()
    var found = bpf_map_lookup(MapHandle.load().addr, key)
    if found.is_null():
        return Int32(XDP_PASS)
    var slot = value_slot()
    var old = found.unsafe_value_ptr()[unsafe_offset=0]
    slot[unsafe_offset=0] = old + 1
    var key2 = key_slot()
    _ = bpf_map_update(MapHandle.load().addr, key2, slot, Int64(BPF_ANY))
    return Int32(XDP_PASS)
