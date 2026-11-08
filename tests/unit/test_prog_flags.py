# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-ISA/flags/load-opts: BPF_PROG_LOAD prog_flags are never set.

Six UAPI bits (STRICT_ALIGNMENT, ANY_ALIGNMENT,
TEST_RND_HI32, TEST_STATE_FREQ, SLEEPABLE,
TEST_REG_INVARIANTS) ride ``prog_flags`` on BPF_PROG_LOAD.
Claim (emitted profile): on every object our toolchain
emits, no product load path sets any of the six bits —
every load goes through ``bpftool prog load`` (no flags
option exists) or the joint native ``bpf_object__load``
wrapper (which sets none), our staged commands, CLI, and
harness pass none, and our emitted sections trigger none
of libbpf's automatic prog_flags insertions. This suite
pins the UAPI bits against the installed header and
proves the unset surface over the product tree.
Kernel-side semantics of set flags, and flags on
arbitrary third-party objects handed to the generic
``verify --object`` loader, are out of scope (libbpf
auto-sets SLEEPABLE only for ``.s``-suffixed sections,
which our emitter never produces). See the leaf packet
for the per-flag disposition.
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

from mojobpf import build as build_module  # noqa: E402
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

# Identifiers that would set or forward prog_flags. The full
# libbpf API name is pinned separately: \bset_flags\b cannot
# match inside bpf_program__set_flags (no word boundary
# between _ and s), which a scratch mutant proved.
SETTER_NAMES = (
    "set_flags",
    "bpf_program__set_flags",
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


WALK_ROOTS = ["src", "compiler", "tests", "ci"]
WALK_EXTENSIONS = (".py", ".txt", ".mojo", ".cpp", ".h", ".c")
WALK_ALLOWED = {
    os.path.join("tests", "unit", "test_prog_flags.py"),
    os.path.join("tests", "negative", "isa", "flags",
                 "unset_flags.txt"),
}


def _walk_files():
    for root in WALK_ROOTS:
        for current, _dirs, files in os.walk(
                os.path.join(REPO_ROOT, root)):
            for name in sorted(files):
                if not name.endswith(WALK_EXTENSIONS):
                    continue
                path = os.path.join(current, name)
                rel = os.path.relpath(path, REPO_ROOT)
                if rel in WALK_ALLOWED:
                    continue
                with open(path, encoding="utf-8",
                          errors="replace") as handle:
                    yield rel, handle.read()


def _setter_patterns():
    return [
        re.compile(r"\b%s\b" % re.escape(needle))
        for needle in list(PROG_FLAGS) + list(SETTER_NAMES)
    ]


def test_no_prog_flags_setter_in_tree():
    # Repo-local roots only. The external joint wrapper
    # (read-only libbpf-mojo checkout, outside this tree)
    # is covered by the recorded audit in the leaf packet
    # (Amendment A2): no setter at the pinned commit.
    needles = list(PROG_FLAGS) + list(SETTER_NAMES)
    hits = []
    for rel, text in _walk_files():
        for needle, pattern in zip(needles, _setter_patterns()):
            if pattern.search(text):
                hits.append((rel, needle))
    assert hits == [], hits


def test_setter_matcher_catches_libbpf_api_call():
    # Retained mutation: the full API call must match even
    # though \bset_flags\b alone cannot match inside it.
    call = "bpf_program__set_flags(prog, 1u << 4);"
    needles = list(PROG_FLAGS) + list(SETTER_NAMES)
    matched = [
        needle for needle, pattern in zip(needles,
                                          _setter_patterns())
        if pattern.search(call)
    ]
    assert matched == ["bpf_program__set_flags"], matched


# Tokens that would smuggle prog_flags through a shell load.
LOAD_FLAG_TOKENS = (
    "flag",
    "sleepable",
    "SLEEPABLE",
    "align",
    "ALIGN",
    "rnd-hi32",
    "RND_HI32",
    "state-freq",
    "STATE_FREQ",
    "reg-invariants",
    "REG_INVARIANTS",
)


def test_shell_load_sites_carry_no_flags():
    sites, hits = 0, []
    for rel, text in _walk_files():
        for number, line in enumerate(text.splitlines(), 1):
            if "prog load" not in line and not (
                    '"prog"' in line and '"load"' in line):
                continue
            sites += 1
            lowered = line.lower()
            for token in LOAD_FLAG_TOKENS:
                if token.lower() in lowered:
                    hits.append((rel, number, token, line.strip()))
    # 111 at the R2 exit + 8 per-CPU-hash legs (audited: plain
    # `prog load <obj> <pin> type xdp`, no flag tokens; the 8
    # case functions in tests/kernel/test_percpu_hash_maps.py).
    assert sites == 119, (
        "load-site inventory drifted (%d); audit the new "
        "sites for flag tokens, then re-pin" % sites)
    assert hits == [], hits


# Sections our pipeline emits (entry -> (prog type, section)).
EMITTED_SECTIONS = {
    "xdp_entry": ("xdp", "xdp"),
    "trace_entry": ("tracepoint",
                    "tracepoint/syscalls/sys_enter_getpid"),
    "uprobe_entry": ("uprobe", "uprobe"),
    "socket_entry": ("socket", "socket"),
    "tc_entry": ("tc", "classifier"),
}


def _triggers_libbpf_auto_flags(section):
    # libbpf_prepare_prog_load (libbpf 1.6/1.7 src/libbpf.c)
    # sets BPF_F_SLEEPABLE only for SEC_SLEEPABLE section
    # defs (`.s`-suffixed sections, `syscall`, `struct_ops`)
    # and BPF_F_XDP_HAS_FRAGS only for `xdp.frags*`.
    base = section.split("/")[0]
    return (
        base.endswith(".s")
        or section.startswith("xdp.frags")
        or section in ("syscall", "struct_ops")
    )


def test_emitted_sections_trigger_no_libbpf_auto_flags():
    assert build_module.ENTRY_PROGRAM_SECTIONS == EMITTED_SECTIONS
    for entry, (_prog_type, section) in sorted(
            EMITTED_SECTIONS.items()):
        assert not _triggers_libbpf_auto_flags(section), entry
