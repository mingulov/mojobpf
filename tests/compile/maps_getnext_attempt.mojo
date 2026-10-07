# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative fixture: from-program key-iteration attempt spelled with
# the long reserved-style name. The kernel offers no from-program
# map-iteration helper (helper 4 is `probe_read`; key iteration is
# a userspace `bpf()` command only), so this name is not reserved
# and the pipeline must refuse it. The Mojo frontend accepts it;
# nothing in the SDK offers this operation.
#
# First expected rejecting layer: the IR audit at adapter time, with
# MBPF303 for the unreserved declaration.

from std.ffi import external_call

from mojobpf.maps import MapHandle, key_slot


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key = key_slot()
    var out = key_slot()
    var rc = external_call["__mojobpf_get_next_key_v1", Int64](
        MapHandle.load().addr, key, out
    )
    if rc == 0:
        return Int32(2)
    return Int32(2)
