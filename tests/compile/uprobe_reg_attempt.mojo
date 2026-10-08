# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Refused attempt: uprobe counter reading a non-pinned register word.
#
# The uprobe call-shape counts match exactly, but the context-word
# address computes word 13 instead of the pinned word 14 (rdi).
# Register extraction outside the pinned x86-64 first-argument
# word is a different register, so the audit refuses the program
# with MBPF317 before any lowering happens. Exists so the build
# suite pins the intended rejecting layer.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, key_slot1, value_slot


@export
def uprobe_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var words = ctx.unsafe_bitcast[UInt64]()
    var arg = Int64(words[unsafe_offset=13])
    var fkey = key_slot()
    var ffound = bpf_map_lookup(MapHandle.load().addr, fkey)
    if ffound.is_null():
        return Int32(0)
    var filter_val = ffound.unsafe_value_ptr()[unsafe_offset=0]
    if Int64(filter_val) != arg:
        return Int32(0)
    var ckey = key_slot1()
    var cfound = bpf_map_lookup(MapHandle.load().addr, ckey)
    if cfound.is_null():
        return Int32(0)
    var slot = value_slot()
    var old = cfound.unsafe_value_ptr()[unsafe_offset=0]
    slot[unsafe_offset=0] = old + 1
    var ckey2 = key_slot1()
    _ = bpf_map_update(MapHandle.load().addr, ckey2, slot, Int64(BPF_ANY))
    return Int32(0)
