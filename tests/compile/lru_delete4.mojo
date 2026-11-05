# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Map delete probe written in Mojo.
#
# Behavior: delete keys 0 through 3 of the four-entry LRU map
# in sequence and report XDP_PASS (2) exactly when the kernel
# succeeds with 0 on each: LRU entries are created on update
# and removed on delete, so every entry is gone afterwards.
# Any other status reports XDP_DROP (1). Each deletion is
# checked immediately, so no value crosses a helper call.

from mojobpf.helpers import bpf_map_delete
from mojobpf.maps import (
    LruHandle,
    key_slot,
    key_slot1,
    key_slot2,
    key_slot3,
)


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key0 = key_slot()
    var rc0 = bpf_map_delete(LruHandle.load().addr, key0)
    if rc0 != Int64(0):
        return Int32(1)
    var key1 = key_slot1()
    var rc1 = bpf_map_delete(LruHandle.load().addr, key1)
    if rc1 != Int64(0):
        return Int32(1)
    var key2 = key_slot2()
    var rc2 = bpf_map_delete(LruHandle.load().addr, key2)
    if rc2 != Int64(0):
        return Int32(1)
    var key3 = key_slot3()
    var rc3 = bpf_map_delete(LruHandle.load().addr, key3)
    if rc3 != Int64(0):
        return Int32(1)
    return Int32(2)
