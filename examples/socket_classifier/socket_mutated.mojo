# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Mutated socket classifier: drops when bit 0 of byte 14 is CLEAR.
#
# This file is identical to socket.mojo except for the bit-test
# comparison below (`== 1` became `== 0`). It exists so behavior
# tests can prove that a source change alters rebuilt behavior and
# that the suites detect the change: with this mutation, the drop
# and pass fixtures swap their expected verdicts, so the unmutated
# expectations fail against the rebuilt mutant and pass again once
# the mutation is reverted.

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
    if (eth_last & 1) == 0:
        return Int32(SOCKET_DROP)
    return Int32(SOCKET_PASS)
