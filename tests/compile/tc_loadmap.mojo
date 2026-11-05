# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# TC classifier packet-byte load into a map, written in Mojo.
#
# Behavior: load one byte at packet offset 14 into the key-0
# slot, store it to map key 1, and return TC_ACT_OK (0).
# Frames shorter than 15 bytes fail the load closed and return
# TC_ACT_SHOT (2) without touching the map. Userspace reads
# map key 1 back after each run, which proves the helper
# loaded the packet byte the direct-read rule observes.
#
# The map is a two-entry array (keys 0 and 1); key 1 carries
# the loaded byte. It uses no main function, printing, heap
# allocation, Python interop, or exceptions. It exposes exactly
# one C-ABI entry point returning a 32-bit verdict for a
# context pointer.

from mojobpf.helpers import bpf_map_update, bpf_skb_load_bytes
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, key_slot1, value_slot


comptime TC_OK = 0
comptime TC_SHOT = 2


@export
def tc_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var to = key_slot()
    var rc = bpf_skb_load_bytes(ctx, 14, to, 1)
    if rc != Int64(0):
        return Int32(TC_SHOT)
    var word = to[unsafe_offset=0]
    var val = value_slot()
    val[unsafe_offset=0] = UInt64(word)
    var key = key_slot1()
    var urc = bpf_map_update(
        MapHandle.load().addr, key, val, Int64(BPF_ANY)
    )
    if urc != Int64(0):
        return Int32(TC_SHOT)
    return Int32(TC_OK)
