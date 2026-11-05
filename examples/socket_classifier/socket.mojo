# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Socket-filter packet classifier written in Mojo.
#
# Behavior: drop the packet (return 0) when the frame holds at
# least 15 bytes and bit 0 of byte 14 is set; pass it (return 64)
# otherwise. Frames shorter than 15 bytes take the pass path
# through the helper status: `skb_load_bytes` fails closed on
# overrun, and the program returns 64 on any nonzero status, so
# the short-input action is part of the specified rule, not the
# SDK's fail-closed guard idiom (short frames are ordinary traffic
# here, not errors).
#
# Classic socket filters cannot read the `__sk_buff`
# data/data_end words directly (the verifier rejects those
# context offsets for this program type), so the program reads
# the packet through the `skb_load_bytes` helper into an
# initialized key slot and tests the low bit of the returned
# word. It uses no main function, printing, heap allocation,
# Python interop, exceptions, maps, or runtime init. It exposes
# exactly one C-ABI entry point returning a 32-bit verdict for a
# context pointer.

from mojobpf.helpers import bpf_skb_load_bytes
from mojobpf.maps import key_slot


comptime SOCKET_DROP = 0
comptime SOCKET_PASS = 64


@export
def socket_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var slot = key_slot()
    var rc = bpf_skb_load_bytes(ctx, 14, slot, 1)
    if rc != Int64(0):
        return Int32(SOCKET_PASS)
    var word = slot[unsafe_offset=0]
    if (word & 1) == 1:
        return Int32(SOCKET_DROP)
    return Int32(SOCKET_PASS)
