# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Differential proof for the SDK scalar functions.

Builds ``tests/differential/scalars_probe.mojo`` with the pinned
Mojo compiler (plain ``mojo build``, native host target) and runs
the resulting binary, which executes the genuine SDK integer,
endian, checksum, and guard helpers over exhaustive and
boundary inputs. Every output line is predicted here by an
independent integer oracle that is mechanically distinct from the
Mojo under test: multi-byte fields decode with ``int.from_bytes``
(never the assemble-and-shift the SDK performs), the checksum fold
runs as a carry loop (never the two-stage fold), the final
complement is a subtraction (never a bitwise not), the VLAN mask
is a modulo (never a bit mask), and every narrowing or wrapping
operation is an explicit Python big-integer mask (never native
fixed-width arithmetic). A shared endianness, folding, or
wrapping misunderstanding therefore cannot hide: the two sides
share only the input bytes.

Coverage: all 256 single bytes; all 65,536 byte pairs through
both endian loads; boundary 32-bit words; boundary tag-control
fields and tag-protocol neighbors; boundary checksum sums, words,
and whole windows; and synthetic length/address contexts through
the guard, length, and address arithmetic, including 64-bit wrap
edges (empty and degenerate ranges, maximum needs and sizes)
that no packet run can reach. The probe also exercises the
context-word loader over fixed patterns.

The probe runs on the build host and uses host heap scratch
buffers; it is test glue, not kernel code. Kernel behavior of
the same helpers is proven in-guest by the kernel suites, which
also cover the guard paths on short frames.

Requires the pinned Mojo compiler on PATH (``MODULAR_HOME`` set
as for the other suites). A missing toolchain fails loudly as an
environment failure; a build failure or any oracle mismatch is a
proof failure. Neither ever passes.

Runnable directly (``python3 tests/differential/test_scalars.py``)
or under any ``test_``-style runner. Standard library only.
"""

import os
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
PROBE_SOURCE = os.path.join(REPO_ROOT, "tests", "differential",
                            "scalars_probe.mojo")
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")

MASK16 = 0xFFFF
MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

LE32_VALUES = (
    0x00000000, 0x00000001, 0x000000FF, 0x00000100,
    0x0000FF00, 0x00FF0000, 0x00FF00FF, 0x12345678,
    0x78563412, 0x7FFFFFFF, 0x80000000, 0x80000001,
    0xFFFFFFFE, 0xFFFFFFFF,
)
VLAN_TCIS = (
    0x0000, 0x0001, 0x0FFF, 0x1000, 0x1FFF,
    0x8100, 0x8107, 0x8FFF, 0xFFFF,
)
TAG_FIELDS = (0x0000, 0x0800, 0x80FF, 0x8100, 0x8101, 0xFFFF)
ADD_SUMS = (
    0x00000000, 0x00000001, 0x0000FFFE, 0x0000FFFF,
    0x00010000, 0x0001FFFE, 0xFFFFFFFE, 0xFFFFFFFF,
)
ADD_WORDS = (0x0000, 0x0001, 0xFFFF)
FOLD_SUMS = (
    0x00000000, 0x00000001, 0x000000FF, 0x0000FFFF,
    0x00010000, 0x00010001, 0x0001FFFE, 0x0001FFFF,
    0x00020000, 0xFFFEFFFF, 0xFFFFFFFE, 0xFFFFFFFF,
)
WINDOWS = (
    (0x0000, 0x0000, 0x0000, 0x0000),
    (0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF),
    (0x8000, 0x8000, 0x0000, 0x0000),
    (0x1234, 0x5678, 0x9ABC, 0xDEF0),
)
U64_MAX = MASK64
GUARD_CASES = (
    (0, 0, 0), (0, 0, 1), (0, 1, 0), (0, 1, 1), (0, 1, 2),
    (100, 160, 60), (100, 160, 61), (5, 5, 0), (5, 6, 1), (5, 6, 2),
    (0xFFFFFFFF, 0xFFFFFFFF, 0), (0xFFFFFFFF, 0xFFFFFFFF, 1),
    (0xFFFFFFFF, 0, 1), (0, 0, U64_MAX),
    (0xFFFFFFFF, 0xFFFFFFFF, U64_MAX),
    (0, 0xFFFFFFFF, 0xFFFFFFFF), (0, 0xFFFFFFFF, 0x100000000),
    (0, 1, U64_MAX), (12345, 13345, 1000), (12345, 13345, 1001),
    (10, 5, 0),
)
ADDR_CASES = (
    (0, 0, 0), (0, 0, 1), (10, 10, 0), (10, 11, 1), (10, 11, 2),
    (100, 160, 60), (100, 160, 61),
    (0xFFFFFFFF, 0xFFFFFFFF, 1), (U64_MAX, 0xFFFFFFFF, 1),
    (0, 0xFFFFFFFF, 0xFFFFFFFF), (0, 0xFFFFFFFF, 0x100000000),
    (U64_MAX - 1, 0xFFFFFFFF, 1),
)
LENGTH_CASES = (
    (0, 0), (0, 1), (100, 160), (160, 100), (10, 5),
    (0xFFFFFFFF, 0xFFFFFFFF), (0xFFFFFFFF, 0), (0, 0xFFFFFFFF),
    (5, 5), (12345, 13345),
)
OFFSET_CASES = (
    (0, 0), (100, 60), (100, 0), (0xFFFFFFFF, 0),
    (0xFFFFFFFF, 1), (0xFFFFFFFF, U64_MAX), (0, U64_MAX),
    (12345, U64_MAX - 12345),
)
CONTEXT_PATTERNS = (
    bytes(range(12)),
    bytes((1, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF)),
)


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def run_step(argv, timeout=600):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def fold_oracle(total):
    """Carry-loop fold (distinct from the two-stage fold)."""
    total &= MASK32
    while total >> 16:
        total = (total & MASK16) + (total >> 16)
    return total


def finalize_oracle(total):
    """Subtract-complement (distinct from the bitwise not)."""
    return MASK16 - fold_oracle(total)


def parse_bool(token, where):
    if token == "True":
        return True
    if token == "False":
        return False
    raise AssertionError("%s: not a boolean: %r" % (where, token))


def build_and_run():
    """Build the probe with the pinned compiler; return its lines."""
    if shutil.which("mojo") is None:
        raise EnvironmentFailure("mojo not found on PATH")
    if not os.path.isfile(PROBE_SOURCE):
        raise EnvironmentFailure("missing probe: %s" % PROBE_SOURCE)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK dir: %s" % SDK_INCLUDE)
    workdir = tempfile.mkdtemp(prefix="mojo-scalars-")
    binary = os.path.join(workdir, "scalars_probe")
    proc = run_step(
        ["mojo", "build", "-I", SDK_INCLUDE, "-o", binary, PROBE_SOURCE]
    )
    if proc.returncode != 0 or not os.path.isfile(binary):
        raise AssertionError(
            "probe build failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    if "error:" in proc.stderr.lower() or "warning:" in proc.stderr.lower():
        raise AssertionError(
            "probe build reported diagnostics:\n%s" % proc.stderr
        )
    proc = run_step([binary], timeout=300)
    if proc.returncode != 0:
        raise AssertionError(
            "probe run failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    if proc.stderr:
        raise AssertionError(
            "probe run wrote to stderr:\n%s" % proc.stderr
        )
    lines = proc.stdout.splitlines()
    if not lines:
        raise AssertionError("probe printed no output")
    return lines


_CACHED = {}


def probe_lines():
    if "lines" not in _CACHED:
        _CACHED["lines"] = build_and_run()
    return _CACHED["lines"]


def section(lines, tag, start, count, fields):
    """Slice one tagged section; assert tags, arity, and order."""
    window = lines[start : start + count]
    assert len(window) == count, (
        "%s: want %d lines at offset %d, stream has %d lines total"
        % (tag, count, start, len(lines))
    )
    rows = []
    for index, line in enumerate(window):
        parts = line.split(" ")
        assert parts[0] == tag, (
            "%s line %d: want tag %r, got %r"
            % (tag, index, tag, parts[0])
        )
        assert len(parts) == fields, (
            "%s line %d: want %d fields, got %d: %r"
            % (tag, index, fields, len(parts), line)
        )
        rows.append(parts[1:])
    return rows


def test_byte_load_identity():
    rows = section(probe_lines(), "U8", 0, 256, 2)
    for index, (value,) in enumerate(rows):
        assert int(value) == index, (
            "U8 %d: oracle %d, Mojo %s" % (index, index, value)
        )


def test_exhaustive_endian_pairs():
    lines = probe_lines()
    base = 256
    assert len(lines) >= base + 2 * 65536, (
        "stream too short for the endian loops: %d lines" % len(lines)
    )
    checked = 0
    for lo in range(256):
        for hi in range(256):
            pair = bytes((lo, hi))
            want_le = int.from_bytes(pair, "little")
            want_be = int.from_bytes(pair, "big")
            le_line = lines[base + 2 * checked]
            be_line = lines[base + 2 * checked + 1]
            le_parts = le_line.split(" ")
            be_parts = be_line.split(" ")
            assert le_parts == ["LE16", str(want_le)], (
                "pair %02x%02x: LE oracle %d, Mojo line %r"
                % (lo, hi, want_le, le_line)
            )
            assert be_parts == ["BE16", str(want_be)], (
                "pair %02x%02x: BE oracle %d, Mojo line %r"
                % (lo, hi, want_be, be_line)
            )
            checked += 1
    assert checked == 65536, "checked %d pairs" % checked


def test_boundary_words():
    base = 256 + 2 * 65536
    rows = section(probe_lines(), "LE32", base, len(LE32_VALUES), 6)
    for index, parts in enumerate(rows):
        want = LE32_VALUES[index]
        echoed = bytes(int(token) for token in parts[:4])
        assert echoed == want.to_bytes(4, "little"), (
            "LE32 case %d: probe setup bytes %r are not %08x"
            % (index, echoed, want)
        )
        assert int(parts[4]) == int.from_bytes(echoed, "little"), (
            "LE32 %08x: oracle %d, Mojo %s"
            % (want, int.from_bytes(echoed, "little"), parts[4])
        )


def test_vlan_fields():
    base = 256 + 2 * 65536 + len(LE32_VALUES)
    rows = section(probe_lines(), "VLID", base, len(VLAN_TCIS), 3)
    for index, (echoed, value) in enumerate(rows):
        tci = VLAN_TCIS[index]
        assert int(echoed) == tci, (
            "VLID case %d: probe input %s is not %04x" % (index, echoed, tci)
        )
        assert int(value) == tci % 0x1000, (
            "VLID %04x: oracle %d, Mojo %s" % (tci, tci % 0x1000, value)
        )
    rows = section(
        probe_lines(), "ISVL", base + len(VLAN_TCIS), len(TAG_FIELDS), 3
    )
    for index, (echoed, value) in enumerate(rows):
        field = TAG_FIELDS[index]
        assert int(echoed) == field, (
            "ISVL case %d: probe input %s is not %04x"
            % (index, echoed, field)
        )
        want = field.to_bytes(2, "big") == b"\x81\x00"
        assert parse_bool(value, "ISVL %04x" % field) == want, (
            "ISVL %04x: oracle %r, Mojo %s" % (field, want, value)
        )


def test_checksum_accumulate():
    base = 256 + 2 * 65536 + len(LE32_VALUES) + len(VLAN_TCIS) + len(TAG_FIELDS)
    rows = section(
        probe_lines(), "ADD", base, len(ADD_SUMS) * len(ADD_WORDS), 4
    )
    expect = [
        (total, word) for total in ADD_SUMS for word in ADD_WORDS
    ]
    for index, (echo_s, echo_w, value) in enumerate(rows):
        total, word = expect[index]
        assert (int(echo_s), int(echo_w)) == (total, word), (
            "ADD case %d: probe inputs (%s, %s) are not (%d, %d)"
            % (index, echo_s, echo_w, total, word)
        )
        assert int(value) == (total + word) & MASK32, (
            "ADD %08x+%04x: oracle %d, Mojo %s"
            % (total, word, (total + word) & MASK32, value)
        )


def test_checksum_fold_and_finalize():
    base = (
        256 + 2 * 65536 + len(LE32_VALUES) + len(VLAN_TCIS)
        + len(TAG_FIELDS) + len(ADD_SUMS) * len(ADD_WORDS)
    )
    rows = section(probe_lines(), "FOLD", base, len(FOLD_SUMS), 3)
    for index, (echoed, value) in enumerate(rows):
        total = FOLD_SUMS[index]
        assert int(echoed) == total, (
            "FOLD case %d: probe input %s is not %08x"
            % (index, echoed, total)
        )
        assert int(value) == fold_oracle(total), (
            "FOLD %08x: oracle %d, Mojo %s"
            % (total, fold_oracle(total), value)
        )
    rows = section(
        probe_lines(), "FIN", base + len(FOLD_SUMS), len(FOLD_SUMS), 3
    )
    for index, (echoed, value) in enumerate(rows):
        total = FOLD_SUMS[index]
        assert int(echoed) == total, (
            "FIN case %d: probe input %s is not %08x"
            % (index, echoed, total)
        )
        assert int(value) == finalize_oracle(total), (
            "FIN %08x: oracle %d, Mojo %s"
            % (total, finalize_oracle(total), value)
        )
    rows = section(
        probe_lines(), "WIN", base + 2 * len(FOLD_SUMS), len(WINDOWS), 6
    )
    for index, parts in enumerate(rows):
        words = WINDOWS[index]
        assert tuple(int(token) for token in parts[:4]) == words, (
            "WIN case %d: probe inputs %r are not %r"
            % (index, parts[:4], words)
        )
        want = finalize_oracle(sum(words))
        assert int(parts[4]) == want, (
            "WIN %r: oracle %d, Mojo %s" % (words, want, parts[4])
        )


def guard_base():
    return (
        256 + 2 * 65536 + len(LE32_VALUES) + len(VLAN_TCIS)
        + len(TAG_FIELDS) + len(ADD_SUMS) * len(ADD_WORDS)
        + 2 * len(FOLD_SUMS) + len(WINDOWS)
    )


def test_length_guard_arithmetic():
    rows = section(probe_lines(), "GSH", guard_base(), len(GUARD_CASES), 5)
    for index, (echo_d, echo_e, echo_n, value) in enumerate(rows):
        data, end, need = GUARD_CASES[index]
        assert (int(echo_d), int(echo_e), int(echo_n)) == (data, end, need), (
            "GSH case %d: probe inputs are not (%d, %d, %d)"
            % (index, data, end, need)
        )
        want = ((data + need) & MASK64) > end
        assert parse_bool(value, "GSH %r" % (GUARD_CASES[index],)) == want, (
            "GSH (%d, %d, %d): oracle %r, Mojo %s"
            % (data, end, need, want, value)
        )


def test_address_guard_arithmetic():
    base = guard_base() + len(GUARD_CASES)
    rows = section(probe_lines(), "ASH", base, len(ADDR_CASES), 5)
    for index, (echo_a, echo_e, echo_s, value) in enumerate(rows):
        addr, end, size = ADDR_CASES[index]
        assert (int(echo_a), int(echo_e), int(echo_s)) == (addr, end, size), (
            "ASH case %d: probe inputs are not (%d, %d, %d)"
            % (index, addr, end, size)
        )
        want = ((addr + size) & MASK64) > end
        assert parse_bool(value, "ASH %r" % (ADDR_CASES[index],)) == want, (
            "ASH (%d, %d, %d): oracle %r, Mojo %s"
            % (addr, end, size, want, value)
        )


def test_length_and_address_values():
    base = guard_base() + len(GUARD_CASES) + len(ADDR_CASES)
    rows = section(probe_lines(), "PLEN", base, len(LENGTH_CASES), 4)
    for index, (echo_d, echo_e, value) in enumerate(rows):
        data, end = LENGTH_CASES[index]
        assert (int(echo_d), int(echo_e)) == (data, end), (
            "PLEN case %d: probe inputs are not (%d, %d)"
            % (index, data, end)
        )
        assert int(value) == (end - data) & MASK64, (
            "PLEN (%d, %d): oracle %d, Mojo %s"
            % (data, end, (end - data) & MASK64, value)
        )
    rows = section(
        probe_lines(), "PADDR", base + len(LENGTH_CASES), len(OFFSET_CASES), 4
    )
    for index, (echo_d, echo_o, value) in enumerate(rows):
        data, off = OFFSET_CASES[index]
        assert (int(echo_d), int(echo_o)) == (data, off), (
            "PADDR case %d: probe inputs are not (%d, %d)"
            % (index, data, off)
        )
        assert int(value) == (data + off) & MASK64, (
            "PADDR (%d, %d): oracle %d, Mojo %s"
            % (data, off, (data + off) & MASK64, value)
        )


def test_context_loader():
    base = (
        guard_base() + len(GUARD_CASES) + len(ADDR_CASES)
        + len(LENGTH_CASES) + len(OFFSET_CASES)
    )
    rows = section(
        probe_lines(), "FCTX", base, len(CONTEXT_PATTERNS), 4
    )
    for index, parts in enumerate(rows):
        pattern = CONTEXT_PATTERNS[index]
        want = tuple(
            int.from_bytes(pattern[off : off + 4], "little")
            for off in (0, 4, 8)
        )
        assert tuple(int(token) for token in parts) == want, (
            "FCTX case %d: oracle %r, Mojo %r" % (index, want, parts)
        )


def test_stream_fully_consumed():
    total = (
        256 + 2 * 65536 + len(LE32_VALUES) + len(VLAN_TCIS)
        + len(TAG_FIELDS) + len(ADD_SUMS) * len(ADD_WORDS)
        + 2 * len(FOLD_SUMS) + len(WINDOWS) + len(GUARD_CASES)
        + len(ADDR_CASES) + len(LENGTH_CASES) + len(OFFSET_CASES)
        + len(CONTEXT_PATTERNS)
    )
    assert len(probe_lines()) == total, (
        "stream holds %d lines, suite consumes %d"
        % (len(probe_lines()), total)
    )


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    for name, func in sorted(
        [(k, v) for k, v in globals().items() if k.startswith("test_")]
    ):
        try:
            func()
        except EnvironmentFailure as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            return 2
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
        else:
            print("PASS %s" % name)
    if failures:
        return 1
    print("differential scalars: Mojo probe vs independent oracle agree")
    print("  stream lines: %d" % len(probe_lines()))
    return 0


if __name__ == "__main__":
    sys.exit(main())