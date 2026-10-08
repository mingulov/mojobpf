# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Argument-filtered uprobe counter written in Mojo.
#
# Behavior: on every hit of the uprobe this object is attached
# to, read the probed call's first argument from the pinned
# x86-64 register word, compare it against the expected value in
# entry 0 of the two-entry array map, and add one to the counter
# in entry 1 only on a match. On a lookup miss or an argument
# mismatch, return 0 without touching the counter (an in-range
# array lookup never misses; the checks satisfy the kernel
# verifier). With entry 0 holding an expected argument value and
# entry 1 starting at 0, exactly the calls carrying that value
# are counted.
#
# Register discipline: the context is the kernel's
# `struct pt_regs` at function entry, and the program reads
# exactly word 14 (`rdi` at byte 112), the first
# function-argument register under the System V ABI on x86-64.
# The uprobe fires before the first instruction of the probed
# function executes, so the register still holds the caller's
# first argument. Any other context access is refused before the
# kernel sees it; AArch64 register extraction is not claimed.
#
# Attach discipline: the object carries no attach target (the
# section is the bare `uprobe` name). The loader attaches it at
# load time to one symbol of a suite-owned test executable built
# alongside this example, never to a system binary. One build
# holds one uprobe program; multi-probe graphs are refused.
#
# This program is admitted under the uprobe count vector (one
# expected-argument read through key 0, one pinned register
# read, one read-modify-write pair through key 1). The expected
# value and the extracted register value necessarily meet at
# their comparison after their producing calls; every other
# value is recomputed after the call that clobbers it.

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, key_slot1, value_slot
from mojobpf.uprobe import uprobe_first_arg


@export
def uprobe_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var arg = uprobe_first_arg(ctx)
    var fkey = key_slot()
    var ffound = bpf_map_lookup(MapHandle.load().addr, fkey)
    if ffound.is_null():
        return Int32(0)
    var filter_val = ffound.unsafe_value_ptr()[unsafe_offset=0]
    if Int64(filter_val) != arg:
        return Int32(0)
    var ckey = key_slot1()
    var cfound = bpf_map_lookup(MapHandle.load().addr, ckey)
    if cfound.is_null():
        return Int32(0)
    var slot = value_slot()
    var old = cfound.unsafe_value_ptr()[unsafe_offset=0]
    slot[unsafe_offset=0] = old + 1
    var ckey2 = key_slot1()
    _ = bpf_map_update(MapHandle.load().addr, ckey2, slot, Int64(BPF_ANY))
    return Int32(0)
