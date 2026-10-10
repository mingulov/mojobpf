# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the fixed-record event decoder and run accounting.

The decoder is the independent observer of kernel-produced event
bytes: these tests prove it accepts exactly the version-1
32-byte records, rejects unsupported versions and malformed
lengths with named defects (never an indexing, unpacking, or
allocation error), and reconciles one run's attempted /
successful / failed / received accounting plus sequence gaps.
Adversarial coverage (seeded fuzz over hostile bytes) sits
alongside the golden vectors; the kernel suite proves the same
decoder against live bytes.

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3 tests/unit/test_event_decoder.py``).
"""

import os
import random
import struct
import sys

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

from mojobpf.events import (  # noqa: E402
    EVENT_OFF_CPU,
    EVENT_OFF_MONOTONIC_NS,
    EVENT_OFF_RECORD_SIZE,
    EVENT_OFF_SEQUENCE,
    EVENT_OFF_TGID,
    EVENT_OFF_TID,
    EVENT_OFF_VERSION,
    EVENT_RECORD_SIZE,
    EVENT_RECORD_VERSION,
    EventCheckError,
    EventDecodeError,
    check_accounting,
    check_event_run,
    decode_event_record,
    decode_event_stream,
)


def make_record(version=1, size=32, tgid=100, tid=7, cpu=3, seq=0,
                now=999):
    return struct.pack(
        "<HHIIIQQ", version, size, tgid, tid, cpu, seq, now
    )


def frame(payload):
    return struct.pack("<I", len(payload)) + payload


def test_abi_constants_match_layout():
    assert EVENT_RECORD_VERSION == 1
    assert EVENT_RECORD_SIZE == 32
    assert (
        EVENT_OFF_VERSION, EVENT_OFF_RECORD_SIZE, EVENT_OFF_TGID,
        EVENT_OFF_TID, EVENT_OFF_CPU, EVENT_OFF_SEQUENCE,
        EVENT_OFF_MONOTONIC_NS,
    ) == (0, 2, 4, 8, 12, 16, 24)


def test_golden_record_decodes():
    record = decode_event_record(
        make_record(tgid=1111, tid=2222, cpu=5, seq=42, now=777)
    )
    assert record.version == 1
    assert record.record_size == 32
    assert (record.tgid, record.tid, record.cpu) == (1111, 2222, 5)
    assert (record.sequence, record.monotonic_ns) == (42, 777)


def test_boundary_values_decode():
    record = decode_event_record(
        make_record(tgid=0, tid=0, cpu=0, seq=0, now=0)
    )
    assert (record.tgid, record.tid, record.cpu) == (0, 0, 0)
    record = decode_event_record(
        make_record(
            tgid=0xFFFFFFFF, tid=0xFFFFFFFF, cpu=0xFFFFFFFF,
            seq=0xFFFFFFFFFFFFFFFF, now=0xFFFFFFFFFFFFFFFF,
        )
    )
    assert record.tgid == 0xFFFFFFFF
    assert record.sequence == 0xFFFFFFFFFFFFFFFF


def test_record_with_offset():
    blob = b"\xaa\xbb" + make_record(seq=9) + b"\xcc"
    record = decode_event_record(blob, offset=2)
    assert record.sequence == 9


def test_unsupported_versions_rejected():
    for version in (0, 2, 3, 255, 256, 65535):
        try:
            decode_event_record(make_record(version=version))
        except EventDecodeError as exc:
            assert "unsupported-version" in str(exc), version
            assert str(version) in str(exc), version
        else:
            raise AssertionError(
                "version %d decoded, want rejection" % version
            )


def test_bad_record_sizes_rejected():
    for size in (0, 1, 31, 33, 64, 4096, 65535):
        try:
            decode_event_record(make_record(size=size))
        except EventDecodeError as exc:
            assert "bad-record-size" in str(exc), size
        else:
            raise AssertionError(
                "size %d decoded, want rejection" % size
            )


def test_truncated_records_rejected():
    good = make_record()
    for length in (0, 1, 31):
        try:
            decode_event_record(good[:length])
        except EventDecodeError as exc:
            assert "truncated-record" in str(exc), length
        else:
            raise AssertionError(
                "length %d decoded, want rejection" % length
            )
    try:
        decode_event_record(good, offset=1)
    except EventDecodeError as exc:
        assert "truncated-record" in str(exc)
    else:
        raise AssertionError("offset 1 decoded, want rejection")
    try:
        decode_event_record(good, offset=-1)
    except EventDecodeError as exc:
        assert "truncated-record" in str(exc)
    else:
        raise AssertionError("negative offset decoded")


def test_truncated_message_never_reports_negative_have():
    # An offset past the end of the data still names the defect,
    # but reports zero remaining bytes, never a negative count.
    good = make_record()
    try:
        decode_event_record(good, offset=len(good) + 8)
    except EventDecodeError as exc:
        assert "truncated-record" in str(exc)
        assert "have 0" in str(exc), str(exc)
    else:
        raise AssertionError("past-end offset decoded")


def test_empty_stream_decodes_empty():
    assert decode_event_stream(b"") == ()


def test_stream_frames_decode():
    blob = frame(make_record(seq=0)) + frame(make_record(seq=1))
    records = decode_event_stream(blob)
    assert [record.sequence for record in records] == [0, 1]


def test_bad_frame_lengths_rejected():
    for length in (0, 1, 31, 33, 64, 0xFFFFFFFF):
        blob = struct.pack("<I", length) + make_record()
        try:
            decode_event_stream(blob)
        except EventDecodeError as exc:
            assert "bad-frame-length" in str(exc), length
        else:
            raise AssertionError(
                "frame length %d decoded, want rejection" % length
            )


def test_truncated_frame_headers_rejected():
    blob = frame(make_record(seq=0)) + b"\x20\x00"
    try:
        decode_event_stream(blob)
    except EventDecodeError as exc:
        assert "truncated-frame" in str(exc)
    else:
        raise AssertionError("short header decoded, want rejection")


def test_truncated_frame_bodies_rejected():
    blob = frame(make_record(seq=0))
    blob += struct.pack("<I", 32) + make_record(seq=1)[:17]
    try:
        decode_event_stream(blob)
    except EventDecodeError as exc:
        assert "truncated-record" in str(exc)
    else:
        raise AssertionError("short body decoded, want rejection")


def test_huge_frame_length_never_allocates():
    # A hostile 4 GiB length with a short file must fail on the
    # length check, not on allocation or indexing.
    blob = struct.pack("<I", 0xFFFFFFFF) + b"\x00" * 64
    try:
        decode_event_stream(blob)
    except EventDecodeError as exc:
        assert "bad-frame-length" in str(exc)
    else:
        raise AssertionError("huge length decoded, want rejection")


def test_trailing_garbage_rejected():
    blob = frame(make_record(seq=0)) + b"\x99"
    try:
        decode_event_stream(blob)
    except EventDecodeError as exc:
        assert "truncated-frame" in str(exc)
    else:
        raise AssertionError("trailing byte decoded, want rejection")


def test_stream_rejects_bad_record_inside():
    blob = frame(make_record(seq=0)) + frame(make_record(version=2))
    try:
        decode_event_stream(blob)
    except EventDecodeError as exc:
        assert "unsupported-version" in str(exc)
    else:
        raise AssertionError("bad inner record decoded")


def test_run_check_accepts_dense_run():
    records = tuple(
        decode_event_record(make_record(tgid=50, tid=51, cpu=i % 2,
                                        seq=i, now=100 + i))
        for i in range(10)
    )
    report = check_event_run(
        records, expect_tgid=50, expect_tid=51, max_cpu=2
    )
    assert report.received == 10
    assert (report.first_sequence, report.last_sequence) == (0, 9)
    assert report.gap_total == 0


def test_run_check_accepts_gaps_and_counts_them():
    records = tuple(
        decode_event_record(
            make_record(tgid=50, tid=51, cpu=0, seq=seq,
                        now=100 + seq)
        )
        for seq in (0, 1, 4, 5, 9)
    )
    report = check_event_run(
        records, expect_tgid=50, expect_tid=51, max_cpu=1
    )
    assert report.received == 5
    assert (report.first_sequence, report.last_sequence) == (0, 9)
    assert report.gap_total == 5


def test_run_check_rejects_identity_mismatch():
    records = (
        decode_event_record(make_record(tgid=50, tid=51, seq=0)),
        decode_event_record(make_record(tgid=50, tid=52, seq=1)),
    )
    try:
        check_event_run(records, expect_tgid=50, expect_tid=51,
                        max_cpu=8)
    except EventCheckError as exc:
        assert "tid 52" in str(exc)
    else:
        raise AssertionError("wrong tid accepted")
    records = (
        decode_event_record(make_record(tgid=50, tid=51, seq=0)),
        decode_event_record(make_record(tgid=60, tid=51, seq=1)),
    )
    try:
        check_event_run(records, expect_tgid=50, expect_tid=51,
                        max_cpu=8)
    except EventCheckError as exc:
        assert "tgid 60" in str(exc)
    else:
        raise AssertionError("wrong tgid accepted")


def test_run_check_rejects_bad_cpu():
    records = (
        decode_event_record(
            make_record(tgid=50, tid=51, cpu=7, seq=0, now=5)
        ),
    )
    try:
        check_event_run(records, expect_tgid=50, expect_tid=51,
                        max_cpu=8)
    except EventCheckError:
        raise AssertionError("cpu 7 below 8 rejected")
    try:
        check_event_run(records, expect_tgid=50, expect_tid=51,
                        max_cpu=7)
    except EventCheckError as exc:
        assert "cpu 7" in str(exc)
    else:
        raise AssertionError("cpu 7 with max 7 accepted")


def test_run_check_rejects_unordered_sequences():
    base = dict(tgid=50, tid=51, cpu=0, now=10)
    for seqs in ((1,), (0, 0), (0, 2, 1), (5, 6)):
        records = tuple(
            decode_event_record(make_record(seq=seq, **base))
            for seq in seqs
        )
        try:
            check_event_run(records, expect_tgid=50, expect_tid=51,
                            max_cpu=1)
        except EventCheckError:
            continue
        raise AssertionError("sequences %r accepted" % (seqs,))


def test_run_check_rejects_time_reversal():
    records = (
        decode_event_record(
            make_record(tgid=50, tid=51, cpu=0, seq=0, now=100)
        ),
        decode_event_record(
            make_record(tgid=50, tid=51, cpu=0, seq=1, now=99)
        ),
    )
    try:
        check_event_run(records, expect_tgid=50, expect_tid=51,
                        max_cpu=1)
    except EventCheckError as exc:
        assert "timestamp" in str(exc)
    else:
        raise AssertionError("time reversal accepted")
    # Equal timestamps are legal (coarse clocks repeat).
    records = (
        decode_event_record(
            make_record(tgid=50, tid=51, cpu=0, seq=0, now=100)
        ),
        decode_event_record(
            make_record(tgid=50, tid=51, cpu=0, seq=1, now=100)
        ),
    )
    report = check_event_run(records, expect_tgid=50, expect_tid=51,
                             max_cpu=1)
    assert report.received == 2


def test_run_check_empty_run():
    report = check_event_run((), expect_tgid=1, expect_tid=2,
                             max_cpu=1)
    assert report.received == 0
    assert report.first_sequence is None
    assert report.last_sequence is None
    assert report.gap_total == 0


def test_accounting_identities():
    check_accounting(
        attempted=10, successful=7, failed=3, received=7,
        gap_total=3,
    )
    check_accounting(
        attempted=0, successful=0, failed=0, received=0,
        gap_total=0,
    )
    for kwargs in (
        dict(attempted=9, successful=7, failed=3, received=7,
             gap_total=3),
        dict(attempted=10, successful=7, failed=3, received=6,
             gap_total=3),
        dict(attempted=10, successful=7, failed=3, received=7,
             gap_total=2),
    ):
        try:
            check_accounting(**kwargs)
        except EventCheckError:
            continue
        raise AssertionError("broken accounting accepted: %r" % kwargs)


def test_fuzz_never_crashes_and_classifies():
    # Seeded hostile bytes: every input either decodes to valid
    # records or fails with EventDecodeError. Anything else
    # (struct.error, IndexError, MemoryError) is a decoder bug.
    rng = random.Random(20261007)
    decoded = 0
    rejected = 0
    allowed = (EventDecodeError,)
    for _ in range(3000):
        length = rng.randrange(0, 100)
        blob = bytes(rng.randrange(256) for _ in range(length))
        try:
            records = decode_event_stream(blob)
        except allowed:
            rejected += 1
            continue
        decoded += 1
        for record in records:
            assert record.version == 1
            assert record.record_size == 32
    assert decoded + rejected == 3000
    assert rejected > 2900, rejected


def test_fuzz_mutated_golden_record():
    # Single-bit flips of a golden record: flips inside the
    # version/size fields must reject; flips elsewhere must
    # decode (fields carry arbitrary values) or reject — never
    # crash.
    good = bytearray(make_record(tgid=50, tid=51, seq=3, now=77))
    validated = 0
    for bit in range(32 * 8):
        mutated = bytearray(good)
        mutated[bit // 8] ^= 1 << (bit % 8)
        try:
            record = decode_event_record(bytes(mutated))
        except EventDecodeError as exc:
            text = str(exc)
            assert (
                "unsupported-version" in text
                or "bad-record-size" in text
            ), (bit, text)
            continue
        validated += 1
        if bit // 8 < 4:
            raise AssertionError(
                "bit %d inside version/size decoded" % bit
            )
        assert record.version == 1
        assert record.record_size == 32
    # Exactly the 32 version/size bits must reject; the other 224
    # decode to (possibly changed) field values.
    assert validated == 224, validated


def _direct_run():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    names = sorted(
        name
        for name in globals()
        if name.startswith("test_") and callable(globals()[name])
    )
    for name in names:
        try:
            globals()[name]()
        except Exception:
            failures += 1
            print("FAIL %s" % name)
            import traceback

            traceback.print_exc()
        else:
            print("ok %s" % name)
    print("%d tests, %d failures" % (len(names), failures))
    return 1 if failures else 0


def test_check_error_is_a_value_error_not_an_assertion():
    # F-018: a semantic failure is wrong record values, not a
    # test bug, so the taxonomy must keep it out of except
    # AssertionError's reach.
    assert issubclass(EventCheckError, ValueError)
    assert not issubclass(EventCheckError, AssertionError)


def test_assertion_handler_cannot_swallow_a_semantic_failure():
    records = (
        decode_event_record(make_record(tgid=50, tid=51, seq=0)),
        decode_event_record(make_record(tgid=50, tid=52, seq=1)),
    )
    try:
        try:
            check_event_run(
                records, expect_tgid=50, expect_tid=51, max_cpu=8
            )
        except AssertionError:
            raise AssertionError("semantic failure was swallowed")
    except EventCheckError as exc:
        assert "tid 52" in str(exc)
    else:
        raise AssertionError("wrong tid accepted")


def test_accounting_failure_is_explicitly_catchable():
    try:
        check_accounting(
            attempted=2, successful=2, failed=0, received=1,
            gap_total=0,
        )
    except EventCheckError as exc:
        assert "received 1" in str(exc), str(exc)
    else:
        raise AssertionError("dropped record accepted")


if __name__ == "__main__":
    sys.exit(_direct_run())
