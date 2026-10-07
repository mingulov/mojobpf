# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Map delete probe written in Mojo.
#
# Behavior: delete keys 0 and 1 of the two-entry array map in
# sequence and report XDP_PASS (2) exactly when the kernel refuses
# both with -EINVAL (22): array elements are preallocated, so
# deletion always fails and the entries survive. Any other status
# reports XDP_DROP (1). Each deletion is checked immediately, so
# no value crosses a helper call.

from mojobpf.helpers import bpf_map_delete
from mojobpf.maps import MapHandle, key_slot, key_slot1


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key0 = key_slot()
    var rc0 = bpf_map_delete(MapHandle.load().addr, key0)
    if rc0 != Int64(-22):
        return Int32(1)
    var key1 = key_slot1()
    var rc1 = bpf_map_delete(MapHandle.load().addr, key1)
    if rc1 != Int64(-22):
        return Int32(1)
    return Int32(2)
