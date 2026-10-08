# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Minimal CO-RE vertical slice: relocated field read plus existence check.

This XDP program is the Phase 5 Task 1 proof: one lookup through
key 0 into the single-entry 4096-byte core map, one relocated u32
read at ``value + CO-RE(task_struct.pid)``, one
``field_exists(task_struct.scx)`` check, and a packed test-run
observation word ``(v & 0xffff) | (ex << 16)``. Identical object
bytes load on both supported lanes; the loader resolves the
relocations against each lane's kernel BTF, so the observed word
carries the lane's marker (proving the lane-correct offset) and
the lane's existence bit.

The return word is a test-run observation, never a forwarding
decision: this program loads and runs under ``bpftool prog run``
only. The map value is prefilled from userspace with distinct
per-offset markers; the oracle (an independent C control plus the
recorded per-lane layouts) compares the observed words.
"""

from mojobpf.core import core_exists_task_scx, core_read_task_pid
from mojobpf.helpers import bpf_map_lookup
from mojobpf.maps import MapHandle, key_slot


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key = key_slot()
    var found = bpf_map_lookup(MapHandle.load().addr, key)
    if found.is_null():
        return Int32(0)
    var v = core_read_task_pid(found.unsafe_value_ptr())
    var ex = core_exists_task_scx()
    return Int32((v & 0xFFFF) | (UInt32(ex) << 16))
