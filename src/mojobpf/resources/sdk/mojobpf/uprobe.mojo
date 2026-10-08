# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Controlled-uprobe register vocabulary (x86-64 ONLY).
#
# This module is the uprobe slice of the MojoBPF SDK: the one
# pinned register extraction a uprobe program may perform. A
# uprobe fires at function entry, so the first-argument register
# still holds the caller's first argument when the program runs.
#
# Architecture discipline (explicit, never portable): on x86-64
# the kernel passes `struct pt_regs *` as the context, and word
# 14 of that record is `rdi` (byte 112), the first
# function-argument register under the System V ABI.
# `uprobe_first_arg` reads exactly that word. Any other word,
# width, or architecture is a different register: the compile
# pipeline refuses any context access outside this one pinned
# shape, and AArch64 uprobes are not claimed (no proven
# extraction exists there; a tracepoint is never presented as a
# portable uprobe).
#
# The helper is force-inlined, so kernel programs built on this
# module contain only the intended address computation and load.
# The module uses no main function, printing, heap allocation,
# Python interop, exceptions, or runtime init.

comptime UPROBE_CTX_RDI_WORD = 14
comptime UPROBE_CTX_RDI_BYTE = 112


@inline(.always)
def uprobe_first_arg(ctx: MutPointer[UInt8, MutAnyOrigin]) -> Int64:
    """Read the probed call's first argument (x86-64 word 14).

    The context is the kernel's `struct pt_regs` at function
    entry; word 14 is `rdi`, the first argument register. The
    frontend folds this spelling into one address computation
    plus one `i64` load, which is the only context access the
    uprobe program shape admits.
    """
    var words = ctx.unsafe_bitcast[UInt64]()
    return Int64(words[unsafe_offset=UPROBE_CTX_RDI_WORD])
