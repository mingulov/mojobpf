# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the guest stray-check map filter.

The kernel suites compare a ``bpftool map show`` baseline captured
before the run against the post-run state to prove no stray maps
remain. bpftool 7.6 breaks raw exact-equality two ways: it observes
its own ephemeral iterator maps (``pid_iter.*``) with per-run IDs
and PIDs, and it leaks its skeleton maps (``libbpf_global``,
``libbpf_det_bind``) with no owning process. Both were observed
live in a v6.12 virtme-ng guest: two consecutive ``map show``
runs differ, and leaked-map IDs grow monotonically.

Each affected guest script therefore captures through
``map_show_filtered`` (an awk program embedded in the suite's
``GUEST_SCRIPT``), which drops exactly the tool-owned entries
and the ephemeral ``pids`` lines. Suite maps (``mojobpf_map*``)
and any unknown entry always pass through, so a real stray
still fails the baseline comparison.

These tests execute the actual embedded awk program (extracted
from each suite module, never a copy) against fixture output
recorded from the guest observations above.
"""

import importlib.util
import os
import re
import shutil
import subprocess
import sys

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

FILTER_SUITES = (
    ("kernel", "test_arch_portability"),
    ("kernel", "test_ringbuf_reserve"),
    ("kernel", "test_tracepoint_counter"),
    ("kernel", "test_tracepoint_events"),
    ("kernel", "test_tracing_lifecycle"),
    ("kernel", "test_uprobe_register"),
    ("verifier", "test_helper_licenses"),
)

# Fixture recorded from live v6.12-guest bpftool 7.6 output: two
# leaked skeleton maps (no pids line: no owning process), one
# ephemeral iterator map owned by the observing bpftool itself,
# one suite map, and one unknown third-party map.
FIXTURE_SHOW = (
    "10: array  name libbpf_global  flags 0x0\n"
    "\tkey 4B  value 32B  max_entries 1  memlock 296B\n"
    "11: array  name pid_iter.rodata  flags 0x480\n"
    "\tkey 4B  value 4B  max_entries 1  memlock 8192B\n"
    "\tbtf_id 71  frozen\n"
    "\tpids bpftool(218)\n"
    "12: array  name pid_iter.bss  flags 0x480\n"
    "\tkey 4B  value 4B  max_entries 1  memlock 8192B\n"
    "\tbtf_id 72  frozen\n"
    "\tpids bpftool(218)\n"
    "13: array  name libbpf_det_bind  flags 0x0\n"
    "\tkey 4B  value 32B  max_entries 1  memlock 296B\n"
    "30: array  name mojobpf_map0  flags 0x0\n"
    "\tkey 4B  value 8B  max_entries 2  memlock 4096B\n"
    "\tpids tracepoint_attach(385)\n"
    "31: array  name xdp_stats  flags 0x0\n"
    "\tkey 4B  value 8B  max_entries 1  memlock 256B\n"
)

AWK_RE = re.compile(
    r"bpftool map show \| awk '\n(.*?)'\n  return", re.S
)


def _load_suite(location):
    subdir, stem = location
    path = os.path.join(REPO_ROOT, "tests", subdir, stem + ".py")
    spec = importlib.util.spec_from_file_location(stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _guest_text(module, stem):
    """Return the guest script text the suite actually stages.

    The arch suite renders its template through str.format, so
    only the rendered text carries the shipped filter (escaping
    bugs in the raw template would otherwise go untested).
    """
    if stem == "test_arch_portability":
        return module.GUEST_SCRIPT.format(
            stage="/tmp/stage", staged_names="a b",
            provision="provision", map_name="map",
            init_bytes="41", reader="reader", init="1",
            commands="true",
        )
    return module.GUEST_SCRIPT


def _extract_program(script):
    match = AWK_RE.search(script)
    if match is None:
        raise AssertionError("map_show_filtered awk not found")
    return match.group(1)


def _run_filter(program, text):
    proc = subprocess.run(
        ["awk", program],
        input=text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        raise AssertionError(
            "awk filter failed (exit %d): %s"
            % (proc.returncode, proc.stderr[-500:])
        )
    return proc.stdout


def test_filter_drops_tool_owned_entries():
    """Leaked skeleton and ephemeral iterator maps vanish."""
    if shutil.which("awk") is None:
        raise AssertionError("awk is required for this test")
    first = None
    for location in FILTER_SUITES:
        _subdir, stem = location
        module = _load_suite(location)
        program = _extract_program(_guest_text(module, stem))
        if first is None:
            first = program
        if program != first:
            raise AssertionError(
                "%s carries a divergent filter program" % stem
            )
        filtered = _run_filter(program, FIXTURE_SHOW)
        for name in ("libbpf_global", "pid_iter", "det_bind"):
            if name in filtered:
                raise AssertionError(
                    "%s leaks tool-owned entry %r:\n%s"
                    % (stem, name, filtered)
                )
        if "pids" in filtered:
            raise AssertionError(
                "%s leaks ephemeral pids lines:\n%s"
                % (stem, filtered)
            )


def test_filter_keeps_suite_and_unknown_entries():
    """Suite maps and unknown entries pass through intact."""
    if shutil.which("awk") is None:
        raise AssertionError("awk is required for this test")
    for location in FILTER_SUITES:
        _subdir, stem = location
        module = _load_suite(location)
        program = _extract_program(_guest_text(module, stem))
        filtered = _run_filter(program, FIXTURE_SHOW)
        for name in ("mojobpf_map0", "xdp_stats"):
            if name not in filtered:
                raise AssertionError(
                    "%s drops non-tool entry %r:\n%s"
                    % (stem, name, filtered)
                )


def test_baseline_captures_use_the_filter():
    """Every full map-show capture routes through the filter."""
    for location in FILTER_SUITES:
        subdir, stem = location
        path = os.path.join(
            REPO_ROOT, "tests", subdir, stem + ".py"
        )
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
        for lineno, line in enumerate(source.splitlines(), 1):
            if "bpftool map show)" in line and "pinned" not in line:
                raise AssertionError(
                    "%s:%d captures raw map show: %s"
                    % (stem, lineno, line.strip())
                )
