# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Fixed-record ring-buffer event vocabulary.
#
# This module is the versioned home of the event shape: the 32-byte
# record ABI, the ring-buffer map handle, the event scratch slot,
# and the copy-output wrappers. It is additive SDK surface (minor
# version 1.1): every name below is new, and no 1.0 signature
# changed. The record layout is explicit in the offset constants;
# the encoder stores every byte through those offsets, and the
# layout proof (C reference struct, Mojo probe, IR store scan, and
# live decoder) checks all five legs against each other, so a
# drifted offset fails loudly instead of misencoding.
#
# Record ABI (little-endian, all 32 bytes initialized by the
# encoder, no padding):
#
#   version:      u16 @ 0   = 1
#   record_size:  u16 @ 2   = 32
#   tgid:         u32 @ 4   (thread-group ID, high 32 of helper 14)
#   tid:          u32 @ 8   (thread ID, low 32 of helper 14)
#   cpu:          u32 @ 12  (helper 8)
#   sequence:     u64 @ 16  (per-TID-per-run attempt number)
#   monotonic_ns: u64 @ 24  (helper 5)
#
# The encoder stores each field as one whole word through its
# per-field view (seven stores covering bytes 0 through 31 with
# no gaps and no overlap); byte-at-a-time stores would keep
# sixteen derived bytes live across helper calls and spill, and
# any backend spill can collide with the fixed key/value slots,
# so the spill gate refuses spilling objects. For the same
# reason the emitter reads the PID/TID word twice (once for the
# filter, once late for the record): the record's identity
# fields then span no helper call at all.
#
# The sequence counts attempted outputs, including failed ones, so
# gaps in received sequences have an explicit meaning (failed
# outputs) and the producer side reconciles attempted against
# successful plus failed outputs. The first attempt of a run
# carries sequence 0.
#
# Ring sizes are deployment parameters with exactly two qualified
# values: 4096 (one page, the saturation shape) and 131072 (the
# healthy shape). The example passes its size to
# `RingbufHandle.load`; the frontend folds the comptime constant
# into the size-tag line, the audit pins the literal, the adapter
# emits it into the ring-buffer BTF, and the build reconciles it
# against the manifest. A program is otherwise size-agnostic: the
# output call takes the map address, the record pointer, the
# record size (32), and flags (0).
#
# Helpers: `bpf_ringbuf_output` lowers to helper 130 (copy-output:
# the kernel copies the record; there is deliberately no
# reserve/submit/discard spelling here — the reservation lifetime
# is a separate unreviewed capability and any such spelling is
# refused). `bpf_ktime_get_ns` lowers to helper 5 and
# `bpf_get_smp_processor_id` to helper 8; each exists only because
# its record field needs it. `bpf_get_current_pid_tgid` lowers to
# helper 14 and is the shared tracing spelling (new programs use
# this; the frozen counter example keeps its local spelling so
# its qualified bytes stay untouched).
#
# Every item is force-inlined, so kernel programs built on this
# module contain only the intended map reference, slot, and helper
# shapes.

from std.ffi import external_call
from std.sys import inlined_assembly

# Record ABI: version, total size, and per-field byte offsets.
comptime EVENT_RECORD_VERSION = 1
comptime EVENT_RECORD_SIZE = 32
comptime EVENT_OFF_VERSION = 0
comptime EVENT_OFF_RECORD_SIZE = 2
comptime EVENT_OFF_TGID = 4
comptime EVENT_OFF_TID = 8
comptime EVENT_OFF_CPU = 12
comptime EVENT_OFF_SEQUENCE = 16
comptime EVENT_OFF_MONOTONIC_NS = 24

# Qualified ring-buffer sizes in bytes: one page (saturation) and
# 128 KiB (healthy). The audit admits exactly these two literals.
comptime RINGBUF_SIZE_SMALL = 4096
comptime RINGBUF_SIZE_LARGE = 131072

# Helper IDs this module lowers to. They are pinned conveniences;
# the emitted IDs are what the lowering proofs check.
comptime BPF_FUNC_ktime_get_ns = 5
comptime BPF_FUNC_get_smp_processor_id = 8
comptime BPF_FUNC_get_current_pid_tgid = 14
comptime BPF_FUNC_ringbuf_output = 130


@fieldwise_init
struct EventRecord(ImplicitlyCopyable):
    """The 32-byte event record as a Mojo value.

    Field order and widths mirror the record ABI exactly; the
    layout probe dumps a known value byte by byte so hidden
    padding or a reordered field fails the layout suite. Kernel
    encoders do not place this struct (no addressable stack
    struct exists in the audited subset); they store each field
    as one word through its per-field view, and the IR scan
    proves the seven stores cover exactly bytes 0 through 31.
    """

    var version: UInt16
    var record_size: UInt16
    var tgid: UInt32
    var tid: UInt32
    var cpu: UInt32
    var sequence: UInt64
    var monotonic_ns: UInt64


@fieldwise_init
struct RingbufHandle(ImplicitlyCopyable):
    """Address of the ring-buffer map, tagged with its size.

    The address loads from the second map metadata entry
    (`mojobpf_map1`); the size tag ties the loaded address to its
    result through an empty template, so the backend emits nothing
    for the tag itself. The tag's value is always the map address,
    and it is the value the output call takes as its map operand.
    The size literal rides the tag line so the adapter emits it
    into the ring-buffer BTF without reading the manifest; the
    build reconciles it against the declared one.
    """

    var addr: Int64

    @staticmethod
    @inline(.always)
    def load(size: Int64) -> Self:
        var addr = inlined_assembly[
            "r0 = mojobpf_map1 ll",
            Int64,
            constraints="={r0},~{memory}",
            has_side_effect=True,
        ]()
        var sized = inlined_assembly[
            "",
            Int64,
            constraints="=r,0,r",
            has_side_effect=False,
        ](addr, size)
        return Self(sized)


@inline(.always)
def event_slot() -> MutPointer[UInt8, MutAnyOrigin]:
    """Address the 32-byte event scratch buffer at its base.

    The buffer spans r10-64..r10-33, clear of the key slot
    (r10-4) and the value slot (r10-16). This view feeds the
    output call's data operand; the per-field views below feed
    the stores. The encoder initializes all 32 bytes before the
    output call; the kernel verifier rejects any read of an
    uninitialized stack byte, so a short encoder fails at load.
    """
    return inlined_assembly[
        "r0 = r10\nr0 += -64",
        MutPointer[UInt8, MutAnyOrigin],
        constraints="={r0},~{memory}",
        has_side_effect=True,
    ]()


@inline(.always)
def event_version_slot() -> MutPointer[UInt16, MutAnyOrigin]:
    """Address the record's `version` field (u16 at buffer + 0)."""
    return inlined_assembly[
        "r0 = r10\nr0 += -64",
        MutPointer[UInt16, MutAnyOrigin],
        constraints="={r0},~{memory}",
        has_side_effect=True,
    ]()


@inline(.always)
def event_size_slot() -> MutPointer[UInt16, MutAnyOrigin]:
    """Address the record's `record_size` field (u16 at buffer + 2)."""
    return inlined_assembly[
        "r0 = r10\nr0 += -62",
        MutPointer[UInt16, MutAnyOrigin],
        constraints="={r0},~{memory}",
        has_side_effect=True,
    ]()


@inline(.always)
def event_tgid_slot() -> MutPointer[UInt32, MutAnyOrigin]:
    """Address the record's `tgid` field (u32 at buffer + 4)."""
    return inlined_assembly[
        "r0 = r10\nr0 += -60",
        MutPointer[UInt32, MutAnyOrigin],
        constraints="={r0},~{memory}",
        has_side_effect=True,
    ]()


@inline(.always)
def event_tid_slot() -> MutPointer[UInt32, MutAnyOrigin]:
    """Address the record's `tid` field (u32 at buffer + 8)."""
    return inlined_assembly[
        "r0 = r10\nr0 += -56",
        MutPointer[UInt32, MutAnyOrigin],
        constraints="={r0},~{memory}",
        has_side_effect=True,
    ]()


@inline(.always)
def event_cpu_slot() -> MutPointer[UInt32, MutAnyOrigin]:
    """Address the record's `cpu` field (u32 at buffer + 12)."""
    return inlined_assembly[
        "r0 = r10\nr0 += -52",
        MutPointer[UInt32, MutAnyOrigin],
        constraints="={r0},~{memory}",
        has_side_effect=True,
    ]()


@inline(.always)
def event_seq_slot() -> MutPointer[UInt64, MutAnyOrigin]:
    """Address the record's `sequence` field (u64 at buffer + 16)."""
    return inlined_assembly[
        "r0 = r10\nr0 += -48",
        MutPointer[UInt64, MutAnyOrigin],
        constraints="={r0},~{memory}",
        has_side_effect=True,
    ]()


@inline(.always)
def event_time_slot() -> MutPointer[UInt64, MutAnyOrigin]:
    """Address the record's `monotonic_ns` field (u64 at buffer + 24)."""
    return inlined_assembly[
        "r0 = r10\nr0 += -40",
        MutPointer[UInt64, MutAnyOrigin],
        constraints="={r0},~{memory}",
        has_side_effect=True,
    ]()


@inline(.always)
def bpf_ringbuf_output(
    map_addr: Int64,
    data: MutPointer[UInt8, MutAnyOrigin],
    size: Int64,
    flags: Int64,
) -> Int64:
    """Emit `size` bytes at `data` through the ring buffer (helper 130).

    Copy-output: the kernel copies the record on success and
    leaves the ring untouched on failure. Returns 0 on success, a
    negative errno otherwise; callers must branch on the status so
    failed outputs reconcile instead of vanishing. Only size 32
    with flags 0 lowers; any other pair is refused before the
    kernel sees it.
    """
    return external_call["__mojobpf_ringbuf_output_v1", Int64](
        map_addr, data, size, flags
    )


@inline(.always)
def bpf_ktime_get_ns() -> Int64:
    """Monotonic clock in nanoseconds (helper 5).

    Feeds the record's `monotonic_ns` field. Values are
    non-decreasing per producer; the clock granularity is
    environmental (coarse under emulation), so only ordering and
    range are asserted, never exact steps.
    """
    return external_call["__mojobpf_ktime_get_ns_v1", Int64]()


@inline(.always)
def bpf_get_smp_processor_id() -> Int64:
    """Current CPU number in the low 32 bits (helper 8).

    Feeds the record's `cpu` field. Values stay below the guest's
    CPU count; pinned runs assert exact CPUs.
    """
    return external_call["__mojobpf_get_smp_processor_id_v1", Int64]()


@inline(.always)
def bpf_get_current_pid_tgid() -> Int64:
    """Current TGID (high 32) and TID (low 32) in one word (helper 14).

    Shared tracing spelling: new programs import this instead of
    declaring their own wrapper. Feeds the record's `tgid`/`tid`
    fields and the TID filter, which compares the low 32 bits
    only, so a thread is never confused with its thread group.
    """
    return external_call["__mojobpf_get_pid_tgid_v1", Int64]()
