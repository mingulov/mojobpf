# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Map delete probe written in Mojo.
#
# Behavior: delete key 0 of the one-entry array map and report
# XDP_PASS (2) exactly when the kernel refuses with -EINVAL (22):
# array elements are preallocated, so deletion always fails and
# the entry survives. Any other status reports XDP_DROP (1). The
# single deletion covers the map's only key.

from mojobpf.helpers import bpf_map_delete
from mojobpf.maps import MapHandle, key_slot


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key0 = key_slot()
    var rc0 = bpf_map_delete(MapHandle.load().addr, key0)
    if rc0 != Int64(-22):
        return Int32(1)
    return Int32(2)
