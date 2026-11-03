#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Dual-shape bpftool lookup parser bounds (D2-R5).

The guest-side ``map_u64`` shell parser (``bpftool map lookup`` piped
into a ``python3 -c`` one-liner) must decode all THREE ``bpftool map
lookup`` plain-text shapes that D2 typed maps emit:

* one-line spaced hex (map WITHOUT value-type BTF):
  ``key: 00 00 00 00  value: 2a 00 00 00 00 00 00 00``;
* two-line contiguous hex (older bpftool, same untyped case):
  ``key: 00 00 00 00`` newline ``value: 2a00000000000000``;
* JSON object (map WITH value-type BTF): ``{"key": 0, "value": 42}``
  compact, or the pretty multi-line writer form below.

("Dual-shape" is the historical bound name; the bound now covers
all three shapes. The file name is kept: lane runners and the
matrix runner reference it.)

The pre-R5 one-liner died on the second shape with ``ValueError:
bytes must be in range(0, 256)`` (the whole 16-hex-digit value
became one ``int(tok, 16)`` instead of 8 byte tokens), printed
nothing, and the caller recorded ``FILTER-READBACK-MISMATCH`` --
the with-R1 ringbuf batch failure on D1+D2 bytes.

Shapes 1 and 2 are verbatim lane bytes (no invented shapes).
Shape 1 is quoted from the 20261017 v6.12 TCG lane; shape 2 is
quoted from the 20261015T075351Z v6.12 RV04 green transcripts
(the only readable lane evidence of a ``btf_id``-carrying map
lookup; the 20261017 bundles carry shape 1 only; the F1 gap left
those maps without ``btf_id``).

Shape 3 is source-derived, not lane bytes: no lane has yet
produced a value-BTF-typed lookup readback (lane maps lack
value-type BTF per the F1 gap). Pinned bpftool v7.6.0
``print_key_value`` (src/map.c) routes a PLAIN ``map lookup``
through ``do_dump_btf`` on a pretty JSON writer whenever
``get_map_kv_btf`` succeeds -- i.e. the map carries
``btf_value_type_id`` or ``btf_vmlinux_value_type_id`` -- even
without ``-j``. The compact form (``{"key": 0, "value": 42}``)
is quoted from review finding P3; the pretty form is derived
byte-for-byte from src/json_writer.c with ``jsonw_pretty(true)``:
``{`` newline, four-space ``"key": N,`` newline, four-space
``"value": M`` newline, ``}`` newline (plus the writer-destroy
newline). A bare ``btf_id`` WITHOUT value-type IDs still takes
the hex path (``print_entry_plain``), so "BTF linkage" alone
does not select shape 3; the value-type ID does. When D2
restores typed linkage, live lookups flip to shape 3, and the
pre-P3 parser -- which demands literal ``value:``/``key:`` hex
sections -- would die on every readback. The JSON branch is
preventive: dormant on current lanes, load-bearing on typed
maps.

Dispatch design (single-line constraint): the program rides on
one shell line inside double quotes, so it carries no double
quotes, backslashes, or braces (embedding guard), and a
statement-level ``if:`` would swallow the hex path that shares
the line. Dispatch is therefore one leading assert expression:
inputs whose stripped first byte is ``chr(123)`` (``{`` spelled
without a brace literal) must parse as JSON with exactly the
``key``/``value`` members, an int key equal to the requested
key, and an int value in u64 range -- anything else dies inside
the assert and never reaches the hex path. Non-``{`` inputs
skip the assert's right side untouched and take the unchanged
hex path. ``type(x) is int`` (not ``isinstance``) keeps JSON
``true``/``false``/``42.0`` out; member order is free but the
member SET is exact, so per-CPU ``values`` arrays and ``-j``
``formatted`` siblings are rejected. Duplicate members are
rejected during decoding (``object_pairs_hook`` collapses to
``None`` when pair count disagrees with dict size): plain
``json.loads`` keeps the LAST duplicate, which would admit
``{"key": 1, "key": 0, ...}`` for requested key 0.

Parser under test (``map_u64`` in all bound files below,
byte-identical; the helper asserts that bound instead of re-stating
the one-liner, so these tests fail on the parser gap and only on
the parser gap). The contract is strict (global audit Q4-F3):
exactly one ``key:`` echo matching the requested key, exactly one
``value:`` section, exactly 8 value bytes; anything else fails
closed with a nonzero exit. Every bound copy invokes the
reviewed ``"$BPFTOOL"`` launcher (admission prologue); the
Python program is byte-identical across all bound copies.

WP-1 complete scope: all eight copies bound below
(six kernel + two packaging), every one invoking the
reviewed ``"$BPFTOOL"`` launcher:

* tests/kernel/test_tracing_lifecycle.py
* tests/kernel/test_arch_portability.py
* tests/kernel/test_ringbuf_reserve.py
* tests/kernel/test_tracepoint_counter.py
* tests/kernel/test_tracepoint_events.py
* tests/kernel/test_uprobe_register.py
* tests/packaging/test_reserve_consumer.py
* tests/packaging/test_uprobe_consumer.py

Shape tests feed every shape for one value and assert the
correct u64 parse. Strictness tests feed malformed readbacks
(truncated, overlong, empty, duplicate, conflicting, wrong-key,
malformed-hex, missing-key, preamble/inter-line junk, plus the
JSON member/type/range violations below) and assert rejection.

Host-only, standard library only. Runnable directly
(``python3 tests/kernel/test_btf_dualshape_bounds.py``) or under any
``test_``-style runner. ``MOJOBPF_REPO_ROOT`` overrides the product
root (default: the checkout this file is integrated into).
"""

import os
import re
import stat
import subprocess
import sys
import tempfile

REPO_ROOT = os.environ.get("MOJOBPF_REPO_ROOT") or os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

PARSER_FILES = (
    "tests/kernel/test_tracing_lifecycle.py",
    "tests/kernel/test_arch_portability.py",
    "tests/kernel/test_ringbuf_reserve.py",
    "tests/kernel/test_tracepoint_counter.py",
    "tests/kernel/test_tracepoint_events.py",
    "tests/kernel/test_uprobe_register.py",
    "tests/packaging/test_reserve_consumer.py",
    "tests/packaging/test_uprobe_consumer.py",
)

# Every bound copy uses the reviewed "$BPFTOOL" launcher
# (never bare bpftool). The Python program bound below is
# launcher-blind, so the launcher each copy uses is
# asserted explicitly per file.
LAUNCHER_FILES = (
    "tests/kernel/test_tracing_lifecycle.py",
    "tests/kernel/test_arch_portability.py",
    "tests/kernel/test_ringbuf_reserve.py",
    "tests/kernel/test_tracepoint_counter.py",
    "tests/kernel/test_tracepoint_events.py",
    "tests/kernel/test_uprobe_register.py",
    "tests/packaging/test_reserve_consumer.py",
    "tests/packaging/test_uprobe_consumer.py",
)

# Shape 1: one-line spaced hex, map WITHOUT BTF linkage.
# Quoted from
# artifacts/validation/20261017-fedora-guest/logs/test_map_roundtrip-prebuilt.log
# (v6.12 TCG lane, ``bpftool map lookup id <id> key 0 0 0 0``):
#   :16  base  after: key: 00 00 00 00  value: 2a 00 00 00 00 00 00 00
#   :67  mut   after: key: 00 00 00 00  value: 2b 00 00 00 00 00 00 00
#   :169 zero1 after: key: 00 00 00 00  value: 01 00 00 00 00 00 00 00
# (The :220 all-zero case is degenerate -- 0 parses by accident on
# either shape -- so it cannot be a RED bound and is excluded.)
SHAPE1_TEMPLATE = "key: 00 00 00 00  value: %s\n"

# Shape 2: two-line contiguous hex, map WITH BTF linkage
# (``"btf_id": 2`` in the same transcript's ``--- <tag> maps ---``
# ``bpftool -j map show`` record). Quoted from
# artifacts/validation/20261015T075351Z-full-plan-resume/rv04-transcripts-pure/
# projections-green-expanded/7f9ff8817dc79619/raw-output.log
# (guest-kernel 6.12.0-061200-generic, same ``map lookup`` command):
#   :46-47 base    before: key: 00 00 00 00 / value: 2900000000000000
#   :51-52 base    after:  key: 00 00 00 00 / value: 2a00000000000000
#   :72    mut     after:  value: 2b00000000000000
#   :112   zero1   after:  value: 0100000000000000
SHAPE2_TEMPLATE = "key: 00 00 00 00\nvalue: %s\n"

# (shape-1 spaced bytes, shape-2 contiguous hex, expected u64)
DUAL_CASES = (
    ("2a 00 00 00 00 00 00 00", "2a00000000000000", 42),
    ("2b 00 00 00 00 00 00 00", "2b00000000000000", 43),
    ("01 00 00 00 00 00 00 00", "0100000000000000", 1),
)

# Shape 3: JSON object, map WITH value-type BTF. Compact form
# quoted from review finding P3; pretty form derived from
# bpftool v7.6.0 src/json_writer.c (see the module docstring).
# Source-derived, not lane bytes (no lane has yet produced a
# value-BTF-typed lookup readback).
SHAPE3_COMPACT_TEMPLATE = '{"key": %d, "value": %d}\n'
SHAPE3_PRETTY_TEMPLATE = '{\n    "key": %d,\n    "value": %d\n}\n'

# (requested key, expected u64); each case feeds BOTH layouts.
JSON_CASES = (
    (0, 42),
    (0, 43),
    (0, 1),
    (5, 42),
    (0, 18446744073709551615),
)


def _extract_parser_program():
    """Return the one ``map_u64`` program shared by all bound files."""
    programs = {}
    for relpath in PARSER_FILES:
        path = os.path.join(REPO_ROOT, relpath)
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        matches = [
            line for line in lines if "python3 -c" in line
            and "split('value" in line
        ]
        assert len(matches) == 1, (
            "%s holds %d map_u64 lookup lines, want 1"
            % (relpath, len(matches))
        )
        line = matches[0]
        assert relpath in LAUNCHER_FILES, (
            "%s is bound but has no launcher-class entry" % relpath
        )
        assert '"$BPFTOOL" map lookup' in line, (
            "%s lookup line lost the reviewed launcher" % relpath
        )
        assert " bpftool map lookup" not in line.replace(
            '"$BPFTOOL" map lookup', ""), (
            "%s lookup line mixes in bare bpftool" % relpath
        )
        prefix = 'python3 -c "'
        # The program carries no double quotes, so it spans the
        # first to the second quote; the expected key rides as
        # argv ("$2") after the closing quote. The lookup runs
        # under pipefail and the decoded value publishes only on
        # lookup success, so a nonzero bpftool exit prints
        # nothing and fails.
        assert '"$2") && echo "$_mu_out"' in line, (
            "%s lookup line does not publish-on-success" % relpath
        )
        assert "_mu_out=$(set -o pipefail;" in line, (
            "%s lookup line does not preserve lookup failure" % relpath
        )
        rest = line.split(prefix, 1)[1]
        programs[relpath] = rest.split('"', 1)[0]
    distinct = set(programs.values())
    assert len(distinct) == 1, (
        "map_u64 copies disagree across %d files" % len(programs)
    )
    return programs[PARSER_FILES[0]]


def _run_parser(program, payload, key="0"):
    """Feed one transcript payload to the parser; return completed proc."""
    return subprocess.run(
        [sys.executable, "-c", program, key],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=60,
    )


def _check_dual_shape(spaced, contiguous, want):
    program = _extract_parser_program()
    first = _run_parser(program, SHAPE1_TEMPLATE % spaced)
    assert first.returncode == 0, (
        "one-line shape unexpectedly refused: rc=%d stderr=%r"
        % (first.returncode, first.stderr)
    )
    assert first.stdout.strip() == str(want), (
        "one-line shape parsed %r, want %d"
        % (first.stdout.strip(), want)
    )
    second = _run_parser(program, SHAPE2_TEMPLATE % contiguous)
    assert second.returncode == 0, (
        "two-line BTF-linked shape refused: rc=%d stderr=%r"
        % (second.returncode, second.stderr)
    )
    assert second.stdout.strip() == str(want), (
        "two-line BTF-linked shape parsed %r, want %d"
        % (second.stdout.strip(), want)
    )


def test_lookup_u64_dualshape_value_42():
    _check_dual_shape(*DUAL_CASES[0])


def test_lookup_u64_dualshape_value_43():
    _check_dual_shape(*DUAL_CASES[1])


def test_lookup_u64_dualshape_value_1():
    _check_dual_shape(*DUAL_CASES[2])


def _check_json_shape(key, want):
    program = _extract_parser_program()
    compact = _run_parser(
        program, SHAPE3_COMPACT_TEMPLATE % (key, want), str(key))
    assert compact.returncode == 0, (
        "compact JSON shape refused: rc=%d stderr=%r"
        % (compact.returncode, compact.stderr)
    )
    assert compact.stdout.strip() == str(want), (
        "compact JSON shape parsed %r, want %d"
        % (compact.stdout.strip(), want)
    )
    pretty = _run_parser(
        program, SHAPE3_PRETTY_TEMPLATE % (key, want), str(key))
    assert pretty.returncode == 0, (
        "pretty JSON shape refused: rc=%d stderr=%r"
        % (pretty.returncode, pretty.stderr)
    )
    assert pretty.stdout.strip() == str(want), (
        "pretty JSON shape parsed %r, want %d"
        % (pretty.stdout.strip(), want)
    )


def test_lookup_u64_json_value_42():
    _check_json_shape(*JSON_CASES[0])


def test_lookup_u64_json_value_43():
    _check_json_shape(*JSON_CASES[1])


def test_lookup_u64_json_value_1():
    _check_json_shape(*JSON_CASES[2])


def test_lookup_u64_json_nonzero_key():
    _check_json_shape(*JSON_CASES[3])


def test_lookup_u64_json_u64_max():
    _check_json_shape(*JSON_CASES[4])


def test_lookup_u64_json_reversed_members():
    # Member order is free (JSON objects are unordered); the
    # member SET is what the parser pins.
    program = _extract_parser_program()
    proc = _run_parser(program, '{"value": 42, "key": 0}\n', "0")
    assert proc.returncode == 0, (
        "reversed-member JSON refused: rc=%d stderr=%r"
        % (proc.returncode, proc.stderr)
    )
    assert proc.stdout.strip() == "42", (
        "reversed-member JSON parsed %r, want 42"
        % proc.stdout.strip()
    )


# Strictness bounds (global audit Q4-F3): the parser must fail
# closed (nonzero exit, no valid-looking stdout) on malformed
# readbacks. Each payload below must be REJECTED.
STRICT_CASES = (
    ("truncated", "key: 00 00 00 00\nvalue: 2a\n", "0"),
    ("overlong", "key: 00 00 00 00\nvalue: 2a0000000000000000\n", "0"),
    ("empty", "key: 00 00 00 00\nvalue:\n", "0"),
    ("duplicate", "key: 00 00 00 00\nvalue: 2a00000000000000\n"
     "value: 2a00000000000000\n", "0"),
    ("conflicting", "key: 00 00 00 00\nvalue: 2a00000000000000\n"
     "value: 2b00000000000000\n", "0"),
    ("wrong_key", "key: 01 00 00 00\nvalue: 2a00000000000000\n", "0"),
    ("malformed_hex", "key: 00 00 00 00\nvalue: zz\n", "0"),
    ("missing_key", "value: 2a00000000000000\n", "0"),
)


def _check_strict(name, payload, key):
    program = _extract_parser_program()
    proc = _run_parser(program, payload, key)
    assert proc.returncode != 0, (
        "%s readback unexpectedly accepted: stdout=%r" % (name, proc.stdout)
    )
    assert proc.stdout == "", (
        "%s rejection printed valid-looking stdout=%r" % (name, proc.stdout)
    )


def _extract_map_u64():
    """Return the one ``map_u64`` shell body shared by bound files.

    Normalized for comparison: ``.format`` copies (arch) use
    doubled braces, and raw copies carry comment lines. Braces
    are un-doubled and comment-only lines dropped; both are
    inert. Every bound copy uses the reviewed ``"$BPFTOOL"``
    launcher (asserted per file in the program extractor);
    the launcher is normalized to bare ``bpftool`` here so
    the residual bodies must agree exactly and the shared
    body stays executable against a PATH-shadowed stub. The
    Python program itself stays byte-identical (asserted
    separately). Returns the normalized body, executable
    as bash.
    """
    bodies = {}
    for relpath in PARSER_FILES:
        path = os.path.join(REPO_ROOT, relpath)
        with open(path, "r", encoding="utf-8") as handle:
            src = handle.read()
        found = re.findall(r"map_u64\(\) \{{1,2}\n(.*?)\n\}{1,2}\n",
                           src, re.DOTALL)
        assert len(found) == 1, (
            "%s holds %d map_u64 bodies, want 1" % (relpath, len(found))
        )
        body = found[0].replace("{{", "{").replace("}}", "}")
        assert relpath in LAUNCHER_FILES, (
            "%s is bound but has no launcher-class entry" % relpath
        )
        assert '"$BPFTOOL" map lookup' in body, (
            "%s body lost the reviewed launcher" % relpath
        )
        body = body.replace('"$BPFTOOL"', "bpftool")
        code = [line for line in body.splitlines()
                if not line.strip().startswith("#")]
        bodies[relpath] = "\n".join(code)
    distinct = set(bodies.values())
    assert len(distinct) == 1, (
        "map_u64 bodies disagree across %d files" % len(bodies)
    )
    return bodies[PARSER_FILES[0]]


def test_lookup_u64_rejects_truncated():
    name, payload, key = STRICT_CASES[0]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_overlong():
    name, payload, key = STRICT_CASES[1]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_empty():
    name, payload, key = STRICT_CASES[2]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_duplicate():
    name, payload, key = STRICT_CASES[3]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_conflicting():
    name, payload, key = STRICT_CASES[4]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_wrong_key():
    name, payload, key = STRICT_CASES[5]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_malformed_hex():
    name, payload, key = STRICT_CASES[6]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_missing_key():
    name, payload, key = STRICT_CASES[7]
    _check_strict(name, payload, key)


# Round-2 strictness (D2-R5 follow-up): complete-input validation.
# Trailing bytes/lines after the value and extra key echoes
# anywhere in the input must fail closed.
SUFFIX_CASES = (
    ("trailing_bytes",
     "key: 00 00 00 00\nvalue: 2a00000000000000\n00\n", "0"),
    ("trailing_malformed_hex",
     "key: 00 00 00 00\nvalue: 2a00000000000000\nzz\n", "0"),
    ("key_echo_after_value",
     "key: 00 00 00 00\nvalue: 2a00000000000000\n"
     "key: 01 00 00 00\n", "0"),
    ("key_echo_same_line",
     "key: 00 00 00 00 key: 01 00 00 00\n"
     "value: 2a00000000000000\n", "0"),
)


def test_lookup_u64_rejects_trailing_bytes():
    name, payload, key = SUFFIX_CASES[0]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_trailing_malformed_hex():
    name, payload, key = SUFFIX_CASES[1]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_key_echo_after_value():
    name, payload, key = SUFFIX_CASES[2]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_key_echo_same_line():
    name, payload, key = SUFFIX_CASES[3]
    _check_strict(name, payload, key)


# Preamble strictness (P5): the hex path once filtered the
# pre-value input for key lines and ignored everything else, so
# an arbitrary preamble or inter-line junk decoded to a value.
# The head before ``value:`` must now fullmatch ``key:`` plus
# the four key bytes plus the bpftool separator -- a spaces run
# (shape 1 splits mid-line) or one newline (shape 2 ends the
# key line). Token-counting alone erases leading-LF and CR
# separators, so the match is byte-exact: no leading bytes, no
# carriage returns, no zero separator. Each payload below must
# be REJECTED.
PREAMBLE_CASES = (
    ("preamble_before_key",
     "unexpected data\nkey: 00 00 00 00\n"
     "value: 2a00000000000000\n", "0"),
    ("line_between_key_and_value",
     "key: 00 00 00 00\nunexpected data\n"
     "value: 2a00000000000000\n", "0"),
    ("blank_line_between_key_and_value",
     "key: 00 00 00 00\n\nvalue: 2a00000000000000\n", "0"),
    ("preamble_before_shape1",
     "junk\nkey: 00 00 00 00  value: 2a 00 00 00 00 00 00 00\n",
     "0"),
    ("leading_blank_line",
     "\nkey: 00 00 00 00\nvalue: 2a00000000000000\n", "0"),
    ("junk_before_value_same_line",
     "key: 00 00 00 00\njunk value: 2a00000000000000\n", "0"),
    ("prefix_before_key_same_line",
     "junk key: 00 00 00 00  value: 2a 00 00 00 00 00 00 00\n",
     "0"),
    ("trailing_junk_same_line",
     "key: 00 00 00 00 junk value: 2a 00 00 00 00 00 00 00\n",
     "0"),
    ("leading_lf_before_shape1",
     "\nkey: 00 00 00 00  value: 2a 00 00 00 00 00 00 00\n",
     "0"),
    ("cr_before_key",
     "\rkey: 00 00 00 00\nvalue: 2a00000000000000\n", "0"),
    ("crlf_between_key_and_value",
     "key: 00 00 00 00\r\nvalue: 2a00000000000000\n", "0"),
    ("crlf_blank_lines_around_key",
     "\r\nkey: 00 00 00 00\r\nvalue: 2a00000000000000\n", "0"),
    ("zero_separator_before_value",
     "key: 00 00 00 00value: 2a00000000000000\n", "0"),
)


def test_lookup_u64_rejects_preamble_before_key():
    name, payload, key = PREAMBLE_CASES[0]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_line_between_key_and_value():
    name, payload, key = PREAMBLE_CASES[1]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_blank_line_between_key_and_value():
    name, payload, key = PREAMBLE_CASES[2]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_preamble_before_shape1():
    name, payload, key = PREAMBLE_CASES[3]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_leading_blank_line():
    name, payload, key = PREAMBLE_CASES[4]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_junk_before_value_same_line():
    name, payload, key = PREAMBLE_CASES[5]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_prefix_before_key_same_line():
    name, payload, key = PREAMBLE_CASES[6]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_trailing_junk_same_line():
    name, payload, key = PREAMBLE_CASES[7]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_leading_lf_before_shape1():
    name, payload, key = PREAMBLE_CASES[8]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_cr_before_key():
    name, payload, key = PREAMBLE_CASES[9]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_crlf_between_key_and_value():
    name, payload, key = PREAMBLE_CASES[10]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_crlf_blank_lines_around_key():
    name, payload, key = PREAMBLE_CASES[11]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_zero_separator_before_value():
    name, payload, key = PREAMBLE_CASES[12]
    _check_strict(name, payload, key)


# JSON strictness (P3): every member/type/range violation of
# shape 3 must fail closed -- nonzero exit, empty stdout. Each
# payload below must be REJECTED.
JSON_STRICT_CASES = (
    ("json_wrong_key", '{"key": 1, "value": 42}\n', "0"),
    ("json_missing_key", '{"value": 42}\n', "0"),
    ("json_missing_value", '{"key": 0}\n', "0"),
    ("json_extra_member",
     '{"key": 0, "value": 42, "id": 7}\n', "0"),
    ("json_percpu_values",
     '{"key": 0, "values": [{"cpu": 0, "value": 42}]}\n', "0"),
    ("json_string_value", '{"key": 0, "value": "42"}\n', "0"),
    ("json_float_value", '{"key": 0, "value": 42.0}\n', "0"),
    ("json_bool_value", '{"key": 0, "value": true}\n', "0"),
    ("json_bool_key", '{"key": false, "value": 42}\n', "0"),
    ("json_negative_value", '{"key": 0, "value": -1}\n', "0"),
    ("json_u64_overflow",
     '{"key": 0, "value": 18446744073709551616}\n', "0"),
    ("json_truncated", '{"key": 0,\n', "0"),
    ("json_empty_object", '{}\n', "0"),
    ("json_array", '[1, 2]\n', "0"),
    ("json_trailing_garbage",
     '{"key": 0, "value": 42} extra\n', "0"),
    ("json_then_hex",
     '{"key": 0, "value": 42}\nkey: 00 00 00 00\n'
     "value: 2a00000000000000\n", "0"),
    ("json_duplicate_key",
     '{"key": 0, "key": 1, "value": 42}\n', "0"),
    ("json_duplicate_key_first_wrong",
     '{"key": 1, "key": 0, "value": 42}\n', "0"),
    ("json_duplicate_value",
     '{"key": 0, "value": 41, "value": 42}\n', "0"),
)


def test_lookup_u64_rejects_json_wrong_key():
    name, payload, key = JSON_STRICT_CASES[0]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_missing_key():
    name, payload, key = JSON_STRICT_CASES[1]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_missing_value():
    name, payload, key = JSON_STRICT_CASES[2]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_extra_member():
    name, payload, key = JSON_STRICT_CASES[3]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_percpu_values():
    name, payload, key = JSON_STRICT_CASES[4]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_string_value():
    name, payload, key = JSON_STRICT_CASES[5]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_float_value():
    name, payload, key = JSON_STRICT_CASES[6]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_bool_value():
    name, payload, key = JSON_STRICT_CASES[7]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_bool_key():
    name, payload, key = JSON_STRICT_CASES[8]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_negative_value():
    name, payload, key = JSON_STRICT_CASES[9]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_u64_overflow():
    name, payload, key = JSON_STRICT_CASES[10]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_truncated():
    name, payload, key = JSON_STRICT_CASES[11]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_empty_object():
    name, payload, key = JSON_STRICT_CASES[12]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_array():
    name, payload, key = JSON_STRICT_CASES[13]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_trailing_garbage():
    name, payload, key = JSON_STRICT_CASES[14]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_then_hex():
    name, payload, key = JSON_STRICT_CASES[15]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_duplicate_key():
    name, payload, key = JSON_STRICT_CASES[16]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_duplicate_key_first_wrong():
    name, payload, key = JSON_STRICT_CASES[17]
    _check_strict(name, payload, key)


def test_lookup_u64_rejects_json_duplicate_value():
    name, payload, key = JSON_STRICT_CASES[18]
    _check_strict(name, payload, key)


def test_lookup_u64_program_embedding_guard():
    # The program rides inside shell double quotes in every
    # bound file (raw + .format): it must carry no double
    # quotes, backslashes, or braces, or the embeds diverge.
    program = _extract_parser_program()
    for char in ('"', "\\", "{", "}"):
        assert char not in program, (
            "embedding hazard %r in shared parser program" % char
        )


def _run_map_u64(stub_exit, stub_stdout):
    """Run the real ``map_u64`` shell function against a stub bpftool."""
    body = _extract_map_u64()
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "out"), "w",
                  encoding="utf-8") as handle:
            handle.write(stub_stdout)
        stub = os.path.join(tmp, "bpftool")
        with open(stub, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\ncat %s/out\nexit %d\n"
                         % (tmp, stub_exit))
        os.chmod(stub, os.stat(stub).st_mode | stat.S_IXUSR)
        script = ("map_u64() {\n%s\n}\n"
                  "map_u64 pin 0\n" % body)
        env = dict(os.environ)
        env["PATH"] = tmp + os.pathsep + env["PATH"]
        return subprocess.run(
            ["bash", "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=60,
            env=env,
        )


def test_map_u64_preserves_lookup_failure():
    # A lookup emitting valid-looking stdout but exiting nonzero
    # must fail closed: nonzero exit, empty stdout.
    proc = _run_map_u64(
        1, "key: 00 00 00 00\nvalue: 2a00000000000000\n")
    assert proc.returncode != 0, (
        "lookup failure masked: stdout=%r" % proc.stdout
    )
    assert proc.stdout == "", (
        "lookup failure printed stdout=%r" % proc.stdout
    )


def test_map_u64_control_decodes():
    # Control: the same shell path decodes a successful lookup.
    proc = _run_map_u64(
        0, "key: 00 00 00 00\nvalue: 2a00000000000000\n")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "42"


def _load_packaging_module(relpath):
    """Import one packaging suite module under a private name.

    The suites are standard library only and side-effect free
    at import (search-path inserts plus constant tables); the
    private name keeps clear of any runner-owned module
    registry entry for the same file.
    """
    import importlib.util

    name = "wp1_packaging_%s" % os.path.basename(relpath)[:-3]
    path = os.path.join(REPO_ROOT, relpath)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _rendered_packaging_map_u64(relpath):
    """Return the ``map_u64`` body from the ACTUAL rendered script.

    Goes through the suite's own ``_render_guest_script``
    (including the uprobe ``.format`` template path) with dummy
    pins, so the exercised bytes are the bytes the guest would
    run -- not a re-typed copy. The rendered body must match
    the shared bound up to the reviewed launcher.
    """
    module = _load_packaging_module(relpath)
    pins = {"path": "/usr/sbin/bpftool", "sha256": "0" * 64}
    if "uprobe" in os.path.basename(relpath):
        rendered = module._render_guest_script(
            "/tmp/wp1-stage",
            {"watched_call": "0x1234", "never_watched": "0x5678"},
            pins,
        )
    else:
        rendered = module._render_guest_script(
            "/tmp/wp1-stage", "0" * 64, pins)
    found = re.findall(r"map_u64\(\) \{{1,2}\n(.*?)\n\}{1,2}\n",
                       rendered, re.DOTALL)
    assert len(found) == 1, (
        "%s rendered script holds %d map_u64 bodies, want 1"
        % (relpath, len(found))
    )
    assert '"$BPFTOOL" map lookup' in found[0], (
        "%s rendered body lost the reviewed launcher" % relpath
    )
    assert found[0].replace('"$BPFTOOL"', "bpftool") == _extract_map_u64(), (
        "%s rendered body diverges from the shared bound" % relpath
    )
    return found[0]


def _run_rendered_map_u64(body, stub_exit, stub_stdout):
    """Run one rendered packaging ``map_u64`` with BPFTOOL stubbed."""
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "out"), "w",
                  encoding="utf-8") as handle:
            handle.write(stub_stdout)
        stub = os.path.join(tmp, "bpftool")
        with open(stub, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\ncat %s/out\nexit %d\n"
                         % (tmp, stub_exit))
        os.chmod(stub, os.stat(stub).st_mode | stat.S_IXUSR)
        script = ("map_u64() {\n%s\n}\n"
                  "map_u64 pin 0\n" % body)
        env = dict(os.environ)
        env["BPFTOOL"] = stub
        return subprocess.run(
            ["bash", "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=60,
            env=env,
        )


def _check_rendered_packaging_decodes(relpath):
    body = _rendered_packaging_map_u64(relpath)
    proc = _run_rendered_map_u64(
        body, 0, "key: 00 00 00 00\nvalue: 2a00000000000000\n")
    assert proc.returncode == 0, (
        "%s rendered map_u64 refused shape 2: %r" % (relpath, proc.stderr)
    )
    assert proc.stdout.strip() == "42", (
        "%s rendered map_u64 parsed %r, want 42"
        % (relpath, proc.stdout.strip())
    )


def _check_rendered_packaging_lookup_failure(relpath):
    body = _rendered_packaging_map_u64(relpath)
    proc = _run_rendered_map_u64(
        body, 1, "key: 00 00 00 00\nvalue: 2a00000000000000\n")
    assert proc.returncode != 0, (
        "%s rendered map_u64 masked lookup failure: stdout=%r"
        % (relpath, proc.stdout)
    )
    assert proc.stdout == "", (
        "%s rendered map_u64 lookup failure printed stdout=%r"
        % (relpath, proc.stdout)
    )


def _check_rendered_packaging_json_decodes(relpath):
    body = _rendered_packaging_map_u64(relpath)
    proc = _run_rendered_map_u64(
        body, 0, '{"key": 0, "value": 42}\n')
    assert proc.returncode == 0, (
        "%s rendered map_u64 refused shape 3: %r" % (relpath, proc.stderr)
    )
    assert proc.stdout.strip() == "42", (
        "%s rendered map_u64 parsed %r, want 42"
        % (relpath, proc.stdout.strip())
    )


def test_rendered_reserve_consumer_map_u64_decodes():
    _check_rendered_packaging_decodes(
        "tests/packaging/test_reserve_consumer.py")


def test_rendered_reserve_consumer_map_u64_json_decodes():
    _check_rendered_packaging_json_decodes(
        "tests/packaging/test_reserve_consumer.py")


def test_rendered_reserve_consumer_map_u64_preserves_lookup_failure():
    _check_rendered_packaging_lookup_failure(
        "tests/packaging/test_reserve_consumer.py")


def test_rendered_uprobe_consumer_map_u64_decodes():
    _check_rendered_packaging_decodes(
        "tests/packaging/test_uprobe_consumer.py")


def test_rendered_uprobe_consumer_map_u64_json_decodes():
    _check_rendered_packaging_json_decodes(
        "tests/packaging/test_uprobe_consumer.py")


def test_rendered_uprobe_consumer_map_u64_preserves_lookup_failure():
    _check_rendered_packaging_lookup_failure(
        "tests/packaging/test_uprobe_consumer.py")


_TESTS = (
    test_lookup_u64_dualshape_value_42,
    test_lookup_u64_dualshape_value_43,
    test_lookup_u64_dualshape_value_1,
    test_lookup_u64_json_value_42,
    test_lookup_u64_json_value_43,
    test_lookup_u64_json_value_1,
    test_lookup_u64_json_nonzero_key,
    test_lookup_u64_json_u64_max,
    test_lookup_u64_json_reversed_members,
    test_lookup_u64_rejects_truncated,
    test_lookup_u64_rejects_overlong,
    test_lookup_u64_rejects_empty,
    test_lookup_u64_rejects_duplicate,
    test_lookup_u64_rejects_conflicting,
    test_lookup_u64_rejects_wrong_key,
    test_lookup_u64_rejects_malformed_hex,
    test_lookup_u64_rejects_missing_key,
    test_lookup_u64_rejects_trailing_bytes,
    test_lookup_u64_rejects_trailing_malformed_hex,
    test_lookup_u64_rejects_key_echo_after_value,
    test_lookup_u64_rejects_key_echo_same_line,
    test_lookup_u64_rejects_preamble_before_key,
    test_lookup_u64_rejects_line_between_key_and_value,
    test_lookup_u64_rejects_blank_line_between_key_and_value,
    test_lookup_u64_rejects_preamble_before_shape1,
    test_lookup_u64_rejects_leading_blank_line,
    test_lookup_u64_rejects_junk_before_value_same_line,
    test_lookup_u64_rejects_prefix_before_key_same_line,
    test_lookup_u64_rejects_trailing_junk_same_line,
    test_lookup_u64_rejects_leading_lf_before_shape1,
    test_lookup_u64_rejects_cr_before_key,
    test_lookup_u64_rejects_crlf_between_key_and_value,
    test_lookup_u64_rejects_crlf_blank_lines_around_key,
    test_lookup_u64_rejects_zero_separator_before_value,
    test_lookup_u64_rejects_json_wrong_key,
    test_lookup_u64_rejects_json_missing_key,
    test_lookup_u64_rejects_json_missing_value,
    test_lookup_u64_rejects_json_extra_member,
    test_lookup_u64_rejects_json_percpu_values,
    test_lookup_u64_rejects_json_string_value,
    test_lookup_u64_rejects_json_float_value,
    test_lookup_u64_rejects_json_bool_value,
    test_lookup_u64_rejects_json_bool_key,
    test_lookup_u64_rejects_json_negative_value,
    test_lookup_u64_rejects_json_u64_overflow,
    test_lookup_u64_rejects_json_truncated,
    test_lookup_u64_rejects_json_empty_object,
    test_lookup_u64_rejects_json_array,
    test_lookup_u64_rejects_json_trailing_garbage,
    test_lookup_u64_rejects_json_then_hex,
    test_lookup_u64_rejects_json_duplicate_key,
    test_lookup_u64_rejects_json_duplicate_key_first_wrong,
    test_lookup_u64_rejects_json_duplicate_value,
    test_lookup_u64_program_embedding_guard,
    test_map_u64_preserves_lookup_failure,
    test_map_u64_control_decodes,
    test_rendered_reserve_consumer_map_u64_decodes,
    test_rendered_reserve_consumer_map_u64_json_decodes,
    test_rendered_reserve_consumer_map_u64_preserves_lookup_failure,
    test_rendered_uprobe_consumer_map_u64_decodes,
    test_rendered_uprobe_consumer_map_u64_json_decodes,
    test_rendered_uprobe_consumer_map_u64_preserves_lookup_failure,
)


def main():
    failures = 0
    for test in _TESTS:
        try:
            test()
        except Exception as exc:
            failures += 1
            print("FAIL %s: %s" % (test.__name__, exc))
        else:
            print("PASS %s" % test.__name__)
    if failures:
        print("%d/%d dual-shape bounds failed" % (failures, len(_TESTS)))
        return 1
    print("all %d dual-shape bounds passed" % len(_TESTS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
