# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Socket-filter packet classifier written in Mojo.
#
# Behavior: drop the packet (return 0) when the frame holds at
# least 15 bytes and bit 0 of byte 14 is set; pass it (return 64)
# otherwise. Frames shorter than 15 bytes take the pass path
# through the explicit bounds check: the short-input action is
# part of the specified rule, not the SDK's fail-closed guard idiom
# (short frames are ordinary traffic here, not errors).
#
# The program reads the kernel socket-filter context (`struct
# __sk_buff` data/data_end words at u32 offsets 19 and 20), guards
# the load with an explicit 15-byte length check, reinterprets the
# guarded address once, and loads a single packet byte. It uses no
# main function, printing, heap allocation, Python interop, exceptions,
# maps, helpers, or runtime init. It exposes exactly one C-ABI entry
# point returning a 32-bit verdict for a context pointer.
#
# The guard arithmetic mirrors the packet SDK's addition form
# (`(base + need) > end`): needs are compiled-in small constants
# and packet addresses derive from u32 context words, so the
# addition never wraps in practice, and the kernel verifier
# independently bounds packet access.

from mojobpf.packet import load_u8, packet_base


comptime SOCKET_DROP = 0
comptime SOCKET_PASS = 64


@export
def socket_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var words = ctx.unsafe_bitcast[UInt32]()
    var data = words[unsafe_offset=19]
    var data_end = words[unsafe_offset=20]
    if UInt64(data) + 15 > UInt64(data_end):
        return Int32(SOCKET_PASS)
    var base = packet_base(UInt64(data))
    var eth_last = load_u8(base, 14)
    if (eth_last & 1) == 1:
        return Int32(SOCKET_DROP)
    return Int32(SOCKET_PASS)
