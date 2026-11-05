# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# TC classifier packet-byte store written in Mojo.
#
# Behavior: store one byte (value 2) at packet offset 13 and
# return TC_ACT_OK (0) when the store succeeds; return
# TC_ACT_SHOT (2) when the frame is too short for the store.
# The written byte is read back from the packet-out buffer,
# which proves the store reached the frame.
#
# The store source is the key-2 slot (an initialized u32
# holding 2); only its low byte is written. It uses no main
# function, printing, heap allocation, Python interop,
# exceptions, maps, or runtime init. It exposes exactly one
# C-ABI entry point returning a 32-bit verdict for a context
# pointer.

from mojobpf.helpers import bpf_skb_store_bytes
from mojobpf.maps import key_slot2


comptime TC_OK = 0
comptime TC_SHOT = 2


@export
def tc_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var slot = key_slot2()
    var rc = bpf_skb_store_bytes(ctx, 13, slot, 1, 0)
    if rc != Int64(0):
        return Int32(TC_SHOT)
    return Int32(TC_OK)
