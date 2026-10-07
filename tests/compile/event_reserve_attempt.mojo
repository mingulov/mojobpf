# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Genuine-frontend negative: a ring-buffer reserve pseudo-call.
#
# Copy-output is the only qualified ring-buffer path; reservation
# spellings are not reserved names. The frontend emits the direct
# call below, and the audit must refuse the unknown external with
# MBPF303, proving no reserve/submit/discard spelling can reach
# the backend through genuine Mojo.

from std.ffi import external_call


@export
def trace_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var slot = external_call["__mojobpf_ringbuf_reserve_v1", Int64](
        Int64(0), Int64(32)
    )
    if slot == 0:
        return Int32(0)
    return Int32(1)
