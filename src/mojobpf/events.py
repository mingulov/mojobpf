# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Fixed-record ring-buffer event decoding and run accounting.

This module decodes the 32-byte event records the Mojo emitter
writes (see the SDK ``events`` module for the ABI statement) and
reconciles one attachment run's producer/consumer accounting. It
is deliberately independent of the encoder: it pins its own ABI
constants (cross-checked against the SDK source, the C reference
struct, the Mojo layout probe, and the adapted IR by the event
structure suite) and shares no code with the kernel program.

Record ABI (little-endian, 32 bytes, no padding)::

    version:      u16 @ 0   = 1
    record_size:  u16 @ 2   = 32
    tgid:         u32 @ 4
    tid:          u32 @ 8
    cpu:          u32 @ 12
    sequence:     u64 @ 16
    monotonic_ns: u64 @ 24

Drain files hold one frame per record: a little-endian u32
kernel frame length followed by that many record bytes. The
decoder rejects a frame whose length is not 32 (the
kernel-framing cross-check) and a record whose version is not 1
or whose embedded size is not 32. Every other field value is
structurally legal; semantic checks (identity, CPU range,
ordering) live in :func:`check_event_run`, and producer-side
reconciliation in :func:`check_accounting`.

All entry points are total over hostile bytes: malformed input
raises :class:`EventDecodeError` or :class:`EventCheckError`
naming the defect, never an indexing, unpacking, or allocation
error. Lengths from the input are validated before use and never
trusted for allocation.

Standard library only.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

EVENT_RECORD_VERSION = 1
EVENT_RECORD_SIZE = 32
EVENT_OFF_VERSION = 0
EVENT_OFF_RECORD_SIZE = 2
EVENT_OFF_TGID = 4
EVENT_OFF_TID = 8
EVENT_OFF_CPU = 12
EVENT_OFF_SEQUENCE = 16
EVENT_OFF_MONOTONIC_NS = 24

_FRAME_HEADER = struct.Struct("<I")
_RECORD_BODY = struct.Struct("<HHIIIQQ")


@dataclass(frozen=True)
class EventRecord:
    """One decoded event record."""

    version: int
    record_size: int
    tgid: int
    tid: int
    cpu: int
    sequence: int
    monotonic_ns: int


class EventDecodeError(ValueError):
    """A drain file or record fails structural decoding."""


class EventCheckError(AssertionError):
    """Decoded records fail a semantic or accounting check."""


def decode_event_record(data: bytes, offset: int = 0) -> EventRecord:
    """Decode the 32-byte record at ``offset`` in ``data``.

    Raises :class:`EventDecodeError` when fewer than 32 bytes
    remain (``truncated-record``), when the version is not 1
    (``unsupported-version``), or when the embedded size is not
    32 (``bad-record-size``).
    """
    if offset < 0:
        raise EventDecodeError(
            "truncated-record: negative offset %d" % (offset,)
        )
    end = offset + EVENT_RECORD_SIZE
    if end > len(data):
        raise EventDecodeError(
            "truncated-record: need %d bytes at offset %d, have %d"
            % (EVENT_RECORD_SIZE, offset, len(data) - offset)
        )
    version, size, tgid, tid, cpu, sequence, now = _RECORD_BODY.unpack_from(
        data, offset
    )
    if version != EVENT_RECORD_VERSION:
        raise EventDecodeError(
            "unsupported-version: got %d at offset %d, want %d"
            % (version, offset, EVENT_RECORD_VERSION)
        )
    if size != EVENT_RECORD_SIZE:
        raise EventDecodeError(
            "bad-record-size: got %d at offset %d, want %d"
            % (size, offset, EVENT_RECORD_SIZE)
        )
    return EventRecord(
        version=version,
        record_size=size,
        tgid=tgid,
        tid=tid,
        cpu=cpu,
        sequence=sequence,
        monotonic_ns=now,
    )


def decode_event_stream(data: bytes) -> tuple[EventRecord, ...]:
    """Decode a drain file's frames into records.

    Each frame is a little-endian u32 kernel frame length plus
    that many record bytes. Raises :class:`EventDecodeError`
    when a frame header is truncated (``truncated-frame``), when
    a frame length is not 32 (``bad-frame-length``), when a frame
    body is truncated (``truncated-record``), or when a record
    fails :func:`decode_event_record`. An empty file decodes to
    no records.
    """
    records: list[EventRecord] = []
    offset = 0
    total = len(data)
    while offset < total:
        if total - offset < _FRAME_HEADER.size:
            raise EventDecodeError(
                "truncated-frame: need %d header bytes at offset "
                "%d, have %d"
                % (_FRAME_HEADER.size, offset, total - offset)
            )
        (length,) = _FRAME_HEADER.unpack_from(data, offset)
        if length != EVENT_RECORD_SIZE:
            raise EventDecodeError(
                "bad-frame-length: got %d at offset %d, want %d"
                % (length, offset, EVENT_RECORD_SIZE)
            )
        offset += _FRAME_HEADER.size
        records.append(decode_event_record(data, offset))
        offset += EVENT_RECORD_SIZE
    return tuple(records)


@dataclass(frozen=True)
class EventRunReport:
    """Semantic summary of one run's decoded records."""

    received: int
    first_sequence: int | None
    last_sequence: int | None
    gap_total: int


def check_event_run(
    records: tuple[EventRecord, ...],
    *,
    expect_tgid: int,
    expect_tid: int,
    max_cpu: int,
) -> EventRunReport:
    """Check one run's records against its expected identity.

    Every record must carry ``expect_tgid``/``expect_tid``, a CPU
    below ``max_cpu``, and a non-decreasing monotonic timestamp;
    sequences must start at 0 and strictly increase. Returns the
    run report (received count, first/last sequence, total gap).
    Raises :class:`EventCheckError` naming the first violation.
    """
    previous_seq: int | None = None
    previous_now: int | None = None
    gap_total = 0
    first: int | None = None
    for index, record in enumerate(records):
        if record.tgid != expect_tgid:
            raise EventCheckError(
                "record %d carries tgid %d, want %d"
                % (index, record.tgid, expect_tgid)
            )
        if record.tid != expect_tid:
            raise EventCheckError(
                "record %d carries tid %d, want %d"
                % (index, record.tid, expect_tid)
            )
        if record.cpu >= max_cpu:
            raise EventCheckError(
                "record %d carries cpu %d, want below %d"
                % (index, record.cpu, max_cpu)
            )
        if previous_now is not None and record.monotonic_ns < previous_now:
            raise EventCheckError(
                "record %d timestamp %d precedes record %d "
                "timestamp %d"
                % (
                    index, record.monotonic_ns,
                    index - 1, previous_now,
                )
            )
        previous_now = record.monotonic_ns
        if previous_seq is None:
            if record.sequence != 0:
                raise EventCheckError(
                    "first record carries sequence %d, want 0"
                    % (record.sequence,)
                )
            first = record.sequence
        else:
            if record.sequence <= previous_seq:
                raise EventCheckError(
                    "record %d sequence %d does not advance past "
                    "%d" % (index, record.sequence, previous_seq)
                )
            gap_total += record.sequence - previous_seq - 1
        previous_seq = record.sequence
    return EventRunReport(
        received=len(records),
        first_sequence=first,
        last_sequence=previous_seq,
        gap_total=gap_total,
    )


def check_accounting(
    *,
    attempted: int,
    successful: int,
    failed: int,
    received: int,
    gap_total: int,
) -> None:
    """Reconcile one run's producer/consumer accounting.

    Requires ``attempted == successful + failed`` (every attempt
    lands in exactly one producer category),
    ``received == successful`` (every success reaches the drain),
    and ``gap_total == failed`` (every failure shows as exactly
    one missing sequence). Raises :class:`EventCheckError`
    naming the first broken identity.
    """
    if attempted != successful + failed:
        raise EventCheckError(
            "attempted %d != successful %d + failed %d"
            % (attempted, successful, failed)
        )
    if received != successful:
        raise EventCheckError(
            "received %d != successful %d" % (received, successful)
        )
    if gap_total != failed:
        raise EventCheckError(
            "sequence gap total %d != failed %d"
            % (gap_total, failed)
        )
