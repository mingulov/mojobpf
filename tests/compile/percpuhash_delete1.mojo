# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Map delete probe written in Mojo.
#
# Behavior: delete key 0 of the one-entry per-CPU hash map and report
# XDP_PASS (2) exactly when the kernel succeeds with 0: hash
# entries are created on update and removed on delete, so the
# entry is gone afterwards. Any other status reports XDP_DROP
# (1). The single deletion covers the map's only key.

from mojobpf.helpers import bpf_map_delete
from mojobpf.maps import PercpuHashHandle, key_slot


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key0 = key_slot()
    var rc0 = bpf_map_delete(PercpuHashHandle.load().addr, key0)
    if rc0 != Int64(0):
        return Int32(1)
    return Int32(2)
