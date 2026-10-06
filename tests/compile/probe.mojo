# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Minimal Mojo probe for frontend-output inspection.
#
# This module is inspection-only: it exposes two integer-operating exported
# functions so the emitted LLVM IR and its ABI can be examined. It is not a
# kernel entrypoint (no packet context type, no ELF section or license
# metadata, no helper calls). It deliberately uses no main function,
# printing, heap allocation, Python interop, exceptions, or runtime init.


@export
def probe_add(a: Int32, b: Int32) abi("C") -> Int32:
    return a + b


@export
def probe_ctx(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var first = ctx[]
    if first == 0:
        return Int32(1)
    return Int32(2)
