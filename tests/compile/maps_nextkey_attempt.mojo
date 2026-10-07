# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative fixture: map iteration-step attempt. No key-iteration
# helper is qualified (the kernel offers no from-program
# map-iteration helper at all), so the call below uses a reserved
# name the pipeline does not recognize. The Mojo frontend accepts
# it; nothing in the SDK offers this operation.
#
# First expected rejecting layer: the IR audit at adapter time, which
# admits only the three qualified helper pseudo-calls.

from std.ffi import external_call

from mojobpf.maps import MapHandle, key_slot


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key = key_slot()
    var rc = external_call["__mojobpf_nextkey_v1", Int64](
        MapHandle.load().addr, key
    )
    if rc == 0:
        return Int32(2)
    return Int32(2)
