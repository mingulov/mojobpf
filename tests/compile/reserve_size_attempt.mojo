# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Genuine-frontend negative: a reservation call with a wrong size.
#
# Only the literal size 32 with flags 0 lowers; any other pair is
# refused before the kernel sees it. The frontend emits the direct
# call below, and the audit must refuse the size operand with
# MBPF314, proving an over- or under-sized reservation cannot
# reach the backend through genuine Mojo.

from std.ffi import external_call


@export
def trace_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var map_addr = external_call["__mojobpf_get_pid_tgid_v1", Int64]()
    var slot = external_call["__mojobpf_ringbuf_reserve_v1", Int64](
        map_addr, Int64(64), Int64(0)
    )
    if slot == 0:
        return Int32(0)
    return Int32(1)
