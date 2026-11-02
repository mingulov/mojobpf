#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Dual-shape bpftool lookup parser bounds (D2-R5).

The guest-side ``map_u64`` shell parser (``bpftool map lookup`` piped
into a ``python3 -c`` one-liner) must decode BOTH ``bpftool map
lookup`` plain-text shapes that D2 typed maps emit:

* one-line spaced hex (map WITHOUT BTF linkage, ``btf_id`` absent):
  ``key: 00 00 00 00  value: 2a 00 00 00 00 00 00 00``;
* two-line contiguous hex (map WITH BTF linkage, ``"btf_id": 2``):
  ``key: 00 00 00 00`` newline ``value: 2a00000000000000``.

The pre-R5 one-liner died on the second shape with ``ValueError:
bytes must be in range(0, 256)`` (the whole 16-hex-digit value
became one ``int(tok, 16)`` instead of 8 byte tokens), printed
nothing, and the caller recorded ``FILTER-READBACK-MISMATCH`` --
the with-R1 ringbuf batch failure on D1+D2 bytes.

Both shapes are verbatim lane bytes (no invented shapes). Shape 1 is
quoted from the 20261017 v6.12 TCG lane; shape 2 is quoted from the
20261015T075351Z v6.12 RV04 green transcripts, the only readable lane
evidence of a BTF-linked ``map lookup`` (the 20261017 bundles carry
shape 1 only; the F1 gap left those maps without ``btf_id``). D2
restores the linkage, hence the shape-2 bytes, for the same command.

Parser under test (``map_u64`` in all bound files below,
byte-identical; the helper asserts that bound instead of re-stating
the one-liner, so these tests fail on the parser gap and only on
the parser gap). The contract is strict (global audit Q4-F3):
exactly one ``key:`` echo matching the requested key, exactly one
``value:`` section, exactly 8 value bytes; anything else fails
closed with a nonzero exit. Every bound copy invokes the
reviewed ``"$BPFTOOL"`` launcher (admission prologue); the
Python program is byte-identical across all bound copies.

WP-1 staged scope: bound to the two migrated kernel
copies plus the two ported packaging copies below; the
four remaining kernel copies join with their suite
migrations:

* tests/kernel/test_tracing_lifecycle.py
* tests/kernel/test_arch_portability.py
* tests/packaging/test_reserve_consumer.py
* tests/packaging/test_uprobe_consumer.py

Dual-shape tests feed BOTH shapes for one value and assert the
correct u64 parse. Strictness tests feed malformed readbacks
(truncated, overlong, empty, duplicate, conflicting, wrong-key,
malformed-hex, missing-key) and assert rejection.

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
    "tests/packaging/test_reserve_consumer.py",
    "tests/packaging/test_uprobe_consumer.py",
)

# Every bound copy uses the reviewed "$BPFTOOL" launcher
# (never bare bpftool). The per-file table grows with the
# staged scope: later WP-1 ports append their files here
# (launcher class) and to PARSER_FILES above. The Python
# program bound below is launcher-blind, so the launcher
# each copy uses is asserted explicitly per file.
LAUNCHER_FILES = (
    "tests/kernel/test_tracing_lifecycle.py",
    "tests/kernel/test_arch_portability.py",
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


def test_rendered_reserve_consumer_map_u64_decodes():
    _check_rendered_packaging_decodes(
        "tests/packaging/test_reserve_consumer.py")


def test_rendered_reserve_consumer_map_u64_preserves_lookup_failure():
    _check_rendered_packaging_lookup_failure(
        "tests/packaging/test_reserve_consumer.py")


def test_rendered_uprobe_consumer_map_u64_decodes():
    _check_rendered_packaging_decodes(
        "tests/packaging/test_uprobe_consumer.py")


def test_rendered_uprobe_consumer_map_u64_preserves_lookup_failure():
    _check_rendered_packaging_lookup_failure(
        "tests/packaging/test_uprobe_consumer.py")


_TESTS = (
    test_lookup_u64_dualshape_value_42,
    test_lookup_u64_dualshape_value_43,
    test_lookup_u64_dualshape_value_1,
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
    test_lookup_u64_program_embedding_guard,
    test_map_u64_preserves_lookup_failure,
    test_map_u64_control_decodes,
    test_rendered_reserve_consumer_map_u64_decodes,
    test_rendered_reserve_consumer_map_u64_preserves_lookup_failure,
    test_rendered_uprobe_consumer_map_u64_decodes,
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
