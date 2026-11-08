# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-ISA/flags/load-opts: BPF_PROG_LOAD prog_flags are never set.

Six UAPI bits (STRICT_ALIGNMENT, ANY_ALIGNMENT,
TEST_RND_HI32, TEST_STATE_FREQ, SLEEPABLE,
TEST_REG_INVARIANTS) ride ``prog_flags`` on BPF_PROG_LOAD.
No product load path sets any of them: every load goes
through ``bpftool prog load``, whose syntax exposes no
flags option, and our staged commands, CLI, and harness
pass none. This suite pins the UAPI bits against the
installed header and proves the unset surface over the
product tree. Kernel-side semantics of set flags are out
of scope (we never set them). See the leaf packet for
the per-flag disposition.
"""
import ast
import os
import re
import sys

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

from mojobpf import cli as cli_module  # noqa: E402
from mojobpf import verify as verify_module  # noqa: E402

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
HARNESS_PATH = os.path.join(
    REPO_ROOT, "tests", "harness", "bpf_test_run.py"
)
UAPI_HEADER = "/usr/include/linux/bpf.h"

# Owned prog_flags bits (BPF_PROG_LOAD), pinned here and
# verified against the installed header below.
PROG_FLAGS = {
    "BPF_F_STRICT_ALIGNMENT": 0,
    "BPF_F_ANY_ALIGNMENT": 1,
    "BPF_F_TEST_RND_HI32": 2,
    "BPF_F_TEST_STATE_FREQ": 3,
    "BPF_F_SLEEPABLE": 4,
    "BPF_F_TEST_REG_INVARIANTS": 7,
}

# Neighbor bits owned by other leaves (NOT owned here).
NEIGHBOR_FLAGS = {
    "BPF_F_XDP_HAS_FRAGS": 5,
    "BPF_F_XDP_DEV_BOUND_ONLY": 6,
}

# Identifiers that would set or forward prog_flags.
SETTER_NAMES = (
    "set_flags",
    "prog_flags",
    "bpf_prog_load",
    "BPF_PROG_LOAD",
)


def _header_bits():
    with open(UAPI_HEADER, encoding="utf-8") as handle:
        text = handle.read()
    found = {}
    for name in list(PROG_FLAGS) + list(NEIGHBOR_FLAGS):
        match = re.search(
            r"#define\s+%s\s+\(1U?\s*<<\s*(\d+)\)" % name, text)
        assert match, "UAPI macro missing: %s" % name
        found[name] = int(match.group(1))
    return found


def test_prog_flags_uapi_bits():
    bits = _header_bits()
    for name, bit in sorted(PROG_FLAGS.items()):
        assert bits[name] == bit, (name, bits[name])
    for name, bit in sorted(NEIGHBOR_FLAGS.items()):
        assert bits[name] == bit, (name, bits[name])
    assert set(bits) == set(PROG_FLAGS) | set(NEIGHBOR_FLAGS)


def test_verify_staged_load_carries_no_flags():
    lines = [
        line.strip()
        for line in verify_module.GUEST_SCRIPT_TEMPLATE.splitlines()
        if "prog load" in line and not line.strip().startswith("echo")
    ]
    assert len(lines) == 1, lines
    command = lines[0].split(">")[0].strip()
    assert command.split() == [
        "$LOAD_RUN", "prog", "load", '"$OBJ"', '"$PIN"',
    ], command


def _load_argv_lists(tree):
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.List):
            continue
        values = []
        for element in node.elts:
            if isinstance(element, ast.Constant):
                values.append(element.value)
            else:
                values.append(None)
        if "load" in values:
            found.append(values)
    return found


def test_harness_load_argv_carries_no_flags():
    with open(HARNESS_PATH, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    found = _load_argv_lists(tree)
    assert len(found) == 1, found
    assert found[0][1:3] == ["prog", "load"], found
    assert len(found[0]) == 5, found


def _parser_options(parser):
    options = set()
    for action in parser._actions:
        options.update(action.option_strings)
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict):
            for sub in choices.values():
                options |= _parser_options(sub)
    return options


def test_cli_and_harness_expose_no_prog_flag_option():
    sys.path.insert(0, os.path.join(REPO_ROOT, "tests", "harness"))
    import bpf_test_run  # noqa: E402
    options = _parser_options(
        cli_module.build_parser()) | _parser_options(
            bpf_test_run.build_parser())
    assert options, "option walk must stay populated"
    hits = sorted(
        option for option in options
        if "sleepable" in option or "align" in option
        or "prog-flag" in option or "rnd-hi32" in option
        or "state-freq" in option or "reg-invariants" in option)
    assert hits == [], hits


def test_no_prog_flags_setter_in_tree():
    roots = ["src", "compiler", "tests", "ci"]
    allowed = {
        os.path.join("tests", "unit", "test_prog_flags.py"),
        os.path.join("tests", "negative", "isa", "flags",
                     "unset_flags.txt"),
    }
    names = list(PROG_FLAGS) + list(SETTER_NAMES)
    hits = []
    for root in roots:
        for current, _dirs, files in os.walk(
                os.path.join(REPO_ROOT, root)):
            for name in sorted(files):
                if not name.endswith(".py") and not name.endswith(
                        ".txt"):
                    continue
                rel = os.path.relpath(
                    os.path.join(current, name), REPO_ROOT)
                with open(os.path.join(current, name),
                          encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
                for needle in names:
                    if needle in text and rel not in allowed:
                        hits.append((rel, needle))
    assert hits == [], hits
