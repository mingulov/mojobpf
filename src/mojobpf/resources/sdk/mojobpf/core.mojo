# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Minimal CO-RE field vocabulary.
#
# This module is the versioned home of the two pinned CO-RE
# operations: one relocated field read and one optional-field
# existence check. It is additive SDK surface (minor version 1.2):
# every name below is new, and no earlier signature changed.
#
# The wrappers select reserved compiler-recognized declarations
# with no implementation of their own. Unlike the helper wrappers,
# these declarations do NOT lower to kernel helper calls: the
# adapter expands each call site into the backend's
# preserve-access-index pattern (a load from a relocation global
# plus the passthrough intrinsic) and synthesizes the matching
# debuginfo, so `llc` emits genuine `.BTF` type records and
# `.BTF.ext` relocation records that unmodified libbpf resolves
# against the load target's BTF at load time.
#
# Pinned identity (the only admitted relocation shapes):
#
# * `core_read_task_pid` reads a little-endian u32 at
#   `value + CO-RE(task_struct.pid)`, where the offset is the
#   load target's `task_struct.pid` byte offset (one
#   FIELD_BYTE_OFFSET relocation). `value` must point into a map
#   value large enough to hold the relocated read on every
#   supported target (the committed program uses the 4096-byte
#   core map value); anything else is rejected before the kernel
#   sees it, and the kernel verifier re-checks the relocated
#   bounds at load.
# * `core_exists_task_scx` reports whether the load target's
#   `task_struct` carries the `scx` member (one FIELD_EXISTS
#   relocation, 1 when present, 0 when absent). It reads no
#   memory. Callers must branch on the result: there is no
#   spelling for reading the optional field itself.
#
# Every other (type, field, kind) combination is refused with a
# named diagnostic: the audit admits exactly these two
# declarations, these two call shapes, and one call of each per
# program. New fields need their own reviewed capability, never a
# wider spelling here.
#
# Every item is force-inlined, so kernel programs built on this
# module contain only the intended relocation call sites.

from std.ffi import external_call


@inline(.always)
def core_read_task_pid(
    value: MutPointer[UInt64, MutAnyOrigin],
) -> UInt32:
    """Read `task_struct.pid` through `value` at its relocated offset.

    Returns the little-endian u32 at `value + CO-RE(task_struct.pid)`.
    The caller passes a checked-non-null map value pointer (the
    lookup result after the null check); the audit requires that
    provenance and the adapter expands the call into the
    relocation pattern, so the backend emits the relocation
    record and the loader resolves the offset per target.
    """
    return external_call["__mojobpf_core_read_task_pid_v1", UInt32](value)


@inline(.always)
def core_exists_task_scx() -> Int32:
    """Report whether the load target's `task_struct` has `scx`.

    Returns 1 when the member exists, 0 when it does not. This is
    the optional-field check: branch on it, since no spelling
    reads the optional field itself.
    """
    return external_call["__mojobpf_core_exists_task_scx_v1", Int32]()
