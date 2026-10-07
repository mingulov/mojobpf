# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Minimal BPF helper wrappers.
#
# Each wrapper issues one kernel helper call as an ordinary typed call
# to a reserved compiler-recognized declaration with no implementation
# of its own: `__mojobpf_lookup_v1` lowers to helper 1 (map lookup)
# and `__mojobpf_update_v1` lowers to helper 2 (map update). The
# adapter replaces only the callee operand with the standard BPF
# helper-call encoding, so argument registers, the result register,
# and the caller-saved clobbers all come from ordinary call lowering
# in the backend. The helper number is fixed per wrapper, so only the
# reviewed helpers below can be reached. Every wrapper is
# force-inlined: kernel programs built on this module contain no
# helper-'call' functions of their own, only the intended helper
# invocations.
#
# The lookup result is a nullable address as a plain integer (0 means
# null). Callers must branch on `is_null` before converting the result
# with `unsafe_value_ptr`; the verifier rejects any use that skips the
# check. Callers must also pass freshly prepared inputs to every
# helper call. Single-pair programs must keep nothing live across a
# call (the IR audit rejects any value defined before a helper call
# and used after it there); the combined workload's action selector
# and frame length necessarily cross calls and are admitted only in
# the combined count vector.

from std.ffi import external_call
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
            constraints="=r,0",
            has_side_effect=False,
        ](self.raw)


@inline(.always)
def bpf_map_lookup(
    map_addr: Int64, key: MutPointer[UInt32, MutAnyOrigin]
) -> LookupResult:
    """Look up `key` in the map at `map_addr` (helper 1)."""
    var raw = external_call["__mojobpf_lookup_v1", Int64](map_addr, key)
    return LookupResult(raw)


@inline(.always)
def bpf_map_update(
    map_addr: Int64,
    key: MutPointer[UInt32, MutAnyOrigin],
    value: MutPointer[UInt64, MutAnyOrigin],
    flags: Int64,
) -> Int64:
    """Store `value` at `key` in the map at `map_addr` (helper 2)."""
    return external_call["__mojobpf_update_v1", Int64](
        map_addr, key, value, flags
    )
