# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Cleanup guest script filters bpftool 7.6 self-observation.

``bpftool map list`` observes its own ephemeral iterator maps
with per-run IDs/PIDs and leaks skeleton maps, so the repeat
script's resource snapshots and quiesce comparisons must drop
exactly the tool-owned entries (same rule as the verify CLI
template and the lifecycle suite). Unfiltered, the exact
before/after comparison can never pass and quiesce never
stabilizes.
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

_FIXTURE_SHOW = (
    "10: array  name libbpf_global  flags 0x0\n"
    "\tkey 4B  value 32B  max_entries 1  memlock 296B\n"
    "11: array  name pid_iter.rodata  flags 0x480\n"
    "\tkey 4B  value 4B  max_entries 1  memlock 8192B\n"
    "\tbtf_id 71  frozen\n"
    "\tpids bpftool(218)\n"
    "30: array  name mojobpf_map0  flags 0x0\n"
    "\tkey 4B  value 8B  max_entries 2  memlock 4096B\n"
    "\tpids bpftool(219)\n"
)


def _repeat_script():
    path = os.path.join(
        REPO_ROOT, "tests", "kernel", "test_cleanup.py"
    )
    spec = importlib.util.spec_from_file_location(
        "cleanup_guest_module", path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.REPEAT_GUEST_SCRIPT.format(
        stage="/tmp/stage",
        cycles=1,
        bpftool_prologue=":",
        harness_flags="",
    )


def _filter_program(script):
    match = re.search(
        r"list_filtered\(\) \{\n(.*?)map list 2>&1 \| awk '\n(.*?)'\n\}",
        script,
        re.S,
    )
    if match is None:
        raise AssertionError("repeat map filter not found")
    return match.group(2)


def test_repeat_snapshot_uses_filtered_map_list():
    script = _repeat_script()
    assert '"$BPFTOOL" map list 2>&1\n' not in script, (
        "snapshot captures raw map list"
    )
    assert "list_filtered" in script, script[-500:]


def test_repeat_quiesce_uses_filtered_map_list():
    script = _repeat_script()
    assert '"$BPFTOOL" map list 2>&1;' not in script, (
        "quiesce CUR captures raw map list"
    )


def test_repeat_filter_drops_tool_owned_maps():
    if shutil.which("awk") is None:
        raise AssertionError("awk is required for this test")
    program = _filter_program(_repeat_script())
    proc = subprocess.run(
        ["awk", program],
        input=_FIXTURE_SHOW,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr[-500:]
    filtered = proc.stdout
    for name in ("libbpf_global", "pid_iter"):
        assert name not in filtered, filtered
    assert "pids" not in filtered, filtered
    assert "mojobpf_map0" in filtered, filtered


if __name__ == "__main__":
    test_repeat_snapshot_uses_filtered_map_list()
    test_repeat_quiesce_uses_filtered_map_list()
    test_repeat_filter_drops_tool_owned_maps()
    print("cleanup-guest-filter OK")
