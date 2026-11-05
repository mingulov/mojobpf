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
    if (word & 1) == 0:
        return Int32(SOCKET_DROP)
    return Int32(SOCKET_PASS)
