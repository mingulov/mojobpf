# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Minimal BPF helper wrappers.
#
# Each wrapper issues one kernel helper call through documented inline
# assembly with explicit register constraints: arguments arrive in r1 and
# up, the result returns in r0, and the remaining caller-saved registers
# are listed as clobbered. The helper number is part of the fixed
# assembly template, so only the reviewed helpers below can be reached.
# Every wrapper is force-inlined: kernel programs built on this module
# contain no helper-'call' functions of their own, only the intended
# helper invocations.
#
# The lookup result is a nullable address as a plain integer (0 means
# null). Callers must branch on `is_null` before converting the result
# with `unsafe_value_ptr`; the verifier rejects any use that skips the
# check. Callers must also pass freshly loaded inputs to every helper
# call and keep nothing live across one, because a call clobbers the
# argument registers.

from std.sys import inlined_assembly

comptime BPF_FUNC_map_lookup_elem = 1
comptime BPF_FUNC_map_update_elem = 2


@fieldwise_init
struct LookupResult(ImplicitlyCopyable):
    """Nullable outcome of a map lookup (0 encodes null)."""

    var raw: Int64

    @inline(.always)
    def is_null(self) -> Bool:
        return self.raw == 0

    @inline(.always)
    def unsafe_value_ptr(self) -> MutPointer[UInt64, MutAnyOrigin]:
        """Reinterpret a checked-non-null result as a value pointer."""
        return inlined_assembly[
            "",
            MutPointer[UInt64, MutAnyOrigin],
            constraints="=r,r",
            has_side_effect=False,
        ](self.raw)


@inline(.always)
def bpf_map_lookup(
    map_addr: Int64, key: MutPointer[UInt32, MutAnyOrigin]
) -> LookupResult:
    """Look up `key` in the map at `map_addr` (helper 1)."""
    var raw = inlined_assembly[
        "call 1",
        Int64,
        constraints="={r0},{r1},{r2},~{r3},~{r4},~{r5}",
        has_side_effect=True,
    ](map_addr, key)
    return LookupResult(raw)


@inline(.always)
def bpf_map_update(
    map_addr: Int64,
    key: MutPointer[UInt32, MutAnyOrigin],
    value: MutPointer[UInt64, MutAnyOrigin],
    flags: Int64,
) -> Int64:
    """Store `value` at `key` in the map at `map_addr` (helper 2)."""
    return inlined_assembly[
        "call 2",
        Int64,
        constraints="={r0},{r1},{r2},{r3},{r4},~{r5}",
        has_side_effect=True,
    ](map_addr, key, value, flags)
