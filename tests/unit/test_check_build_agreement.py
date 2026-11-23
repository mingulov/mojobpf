# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""check/build toolchain agreement (O-8 back-to-back regression).

F-21: ``check`` and ``build`` disagreed on one lockfile plus
environment (``check`` refused the python pin while ``build``
passed). The contract now: mojo/llc/bpftool are hash-pinned
identically in both verbs (same exit, same per-code refusal
lines), and python is the ambient running interpreter --
observed and reported, never a hash gate. Every agreement test
below runs ``check`` and ``build`` back-to-back in ONE fixture
environment and asserts identical toolchain verdicts, plus the
O-8 CLI surface (``doctor --strict``, ``--version``, no
``present (None)``). Deliberately out of scope: diagnostic
ordering across fault classes (no consumer pins it; per-code
lines are byte-identical), and pre-admission failure report
shape -- an unloadable lockfile or a failed distribution
binding (probe reports discovery state, admission fails fast,
each pinned by its own layer contract; both exit 3 with the
blocking diagnostic present).

Standard library only. Sibling fixture helpers are imported from
the CLI test module (unique names resolve through sys.path).
"""

import json
import os
import platform
import sys
import tempfile

from test_build_commands import (  # noqa: E402
    ADAPTER_OK_FIXTURE,
    run_cli,
    write_executable,
    write_lockfile,
    write_project,
    write_tool_bindir,
)

from mojobpf import __version__ as TOOL_VERSION  # noqa: E402
from mojobpf import build as build_module  # noqa: E402
from mojobpf import cli as cli_module  # noqa: E402
from mojobpf.sdk import SDK_VERSION  # noqa: E402
from mojobpf.toolchain import (  # noqa: E402
    GATED_TOOLS,
    REQUIRED_TOOLS,
    ToolchainConfig,
    probe_toolchain,
)

_DECOY_PYTHON_VERSION = "Python 0.0-decoy"


def _write_adapter(parent):
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    return adapter


def _mbpf_lines(err, code):
    return [
        line for line in err.splitlines() if line.startswith(code + " ")
    ]


def test_gated_sets_match():
    assert set(GATED_TOOLS) == {"mojo", "llc", "bpftool"}
    assert (
        set(build_module.REQUIRED_BUILD_TOOLS) == set(GATED_TOOLS)
    )
    assert "python" in REQUIRED_TOOLS
    assert "python" not in GATED_TOOLS


def test_python_is_ambient_observed_never_probed():
    parent = tempfile.mkdtemp(prefix="agree-pyobs-")
    bindir = write_tool_bindir(
        parent, extra=(("python3", _DECOY_PYTHON_VERSION),)
    )
    lockfile = write_lockfile(parent, bindir)
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=lockfile, search_paths=(bindir,))
    )
    python = next(
        tool for tool in report.tools if tool.name == "python"
    )
    # The PATH decoy is never resolved, probed, or reported: the
    # observation is the running interpreter itself.
    assert python.status == "present", python
    assert python.version == platform.python_version(), python
    assert python.version != _DECOY_PYTHON_VERSION, python
    assert python.path == os.path.realpath(sys.executable), python
    assert python.execution is None, python
    assert python.dialect is None, python
    assert report.supported is True
    assert report.lockfile_status == "matched"


def test_back_to_back_all_matched_passes():
    parent = tempfile.mkdtemp(prefix="agree-match-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(
        parent, extra=(("python3", _DECOY_PYTHON_VERSION),)
    )
    adapter = _write_adapter(parent)
    lockfile = write_lockfile(parent, bindir)
    check_code, check_out, check_err = run_cli(
        [
            "check", "--manifest", manifest_path,
            "--lockfile", lockfile, "--adapter", adapter,
        ],
        path=bindir,
    )
    build_code, build_out, build_err = run_cli(
        [
            "build", "--manifest", manifest_path,
            "--out-dir", out_dir, "--adapter", adapter,
            "--lockfile", lockfile,
        ],
        path=bindir,
    )
    assert (check_code, build_code) == (
        cli_module.EXIT_OK, cli_module.EXIT_OK,
    ), (check_out, check_err, build_out, build_err)
    assert "compile OK" in check_out, check_out
    assert "built " in build_out, build_out
    assert "(None)" not in check_out, check_out
    assert "(None)" not in build_out, build_out


def test_back_to_back_mojo_mismatch_refuses_identically():
    parent = tempfile.mkdtemp(prefix="agree-mismatch-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = _write_adapter(parent)
    lockfile = write_lockfile(
        parent,
        bindir,
        pins={"mojo": ("Mojo 0.0.0 (wrong)", "0" * 64)},
    )
    check_code, check_out, check_err = run_cli(
        [
            "check", "--manifest", manifest_path,
            "--lockfile", lockfile, "--adapter", adapter,
        ],
        path=bindir,
    )
    build_code, _, build_err = run_cli(
        [
            "build", "--manifest", manifest_path,
            "--out-dir", out_dir, "--adapter", adapter,
            "--lockfile", lockfile,
        ],
        path=bindir,
    )
    assert (check_code, build_code) == (
        cli_module.EXIT_ENVIRONMENT, cli_module.EXIT_ENVIRONMENT,
    ), (check_err, build_err)
    check_lines = _mbpf_lines(check_err, "MBPF102")
    build_lines = _mbpf_lines(build_err, "MBPF102")
    assert len(check_lines) == 1, check_err
    assert check_lines == build_lines, (check_err, build_err)
    assert "version unknown: not probed" in check_out, check_out
    assert "(None)" not in check_out, check_out


def test_back_to_back_bpftool_missing_refuses_identically():
    parent = tempfile.mkdtemp(prefix="agree-bpfmiss-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = _write_adapter(parent)
    lockfile = write_lockfile(parent, bindir)
    os.remove(os.path.join(bindir, "bpftool"))
    check_code, _, check_err = run_cli(
        [
            "check", "--manifest", manifest_path,
            "--lockfile", lockfile, "--adapter", adapter,
        ],
        path=bindir,
    )
    build_code, _, build_err = run_cli(
        [
            "build", "--manifest", manifest_path,
            "--out-dir", out_dir, "--adapter", adapter,
            "--lockfile", lockfile,
        ],
        path=bindir,
    )
    assert (check_code, build_code) == (
        cli_module.EXIT_ENVIRONMENT, cli_module.EXIT_ENVIRONMENT,
    ), (check_err, build_err)
    check_lines = _mbpf_lines(check_err, "MBPF103")
    build_lines = _mbpf_lines(build_err, "MBPF103")
    assert len(check_lines) == 1, check_err
    assert check_lines == build_lines, (check_err, build_err)


def test_back_to_back_bpftool_mismatch_refuses_identically():
    parent = tempfile.mkdtemp(prefix="agree-bpfmatch-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = _write_adapter(parent)
    lockfile = write_lockfile(
        parent,
        bindir,
        pins={"bpftool": ("bpftool wrong", "0" * 64)},
    )
    check_code, _, check_err = run_cli(
        [
            "check", "--manifest", manifest_path,
            "--lockfile", lockfile, "--adapter", adapter,
        ],
        path=bindir,
    )
    build_code, _, build_err = run_cli(
        [
            "build", "--manifest", manifest_path,
            "--out-dir", out_dir, "--adapter", adapter,
            "--lockfile", lockfile,
        ],
        path=bindir,
    )
    assert (check_code, build_code) == (
        cli_module.EXIT_ENVIRONMENT, cli_module.EXIT_ENVIRONMENT,
    ), (check_err, build_err)
    check_lines = _mbpf_lines(check_err, "MBPF102")
    build_lines = _mbpf_lines(build_err, "MBPF102")
    assert len(check_lines) == 1, check_err
    assert check_lines == build_lines, (check_err, build_err)


def test_back_to_back_relative_lockfile_matches():
    parent = tempfile.mkdtemp(prefix="agree-rellock-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = _write_adapter(parent)
    lockfile = write_lockfile(
        parent,
        bindir,
        pins={"bpftool": ("bpftool wrong", "0" * 64)},
    )
    # A relative spelling must not change refusal lines: check
    # probes the same absolute path build admits.
    relative = os.path.relpath(lockfile)
    check_code, _, check_err = run_cli(
        [
            "check", "--manifest", manifest_path,
            "--lockfile", relative, "--adapter", adapter,
        ],
        path=bindir,
    )
    build_code, _, build_err = run_cli(
        [
            "build", "--manifest", manifest_path,
            "--out-dir", out_dir, "--adapter", adapter,
            "--lockfile", relative,
        ],
        path=bindir,
    )
    assert (check_code, build_code) == (
        cli_module.EXIT_ENVIRONMENT, cli_module.EXIT_ENVIRONMENT,
    ), (check_err, build_err)
    check_lines = _mbpf_lines(check_err, "MBPF102")
    build_lines = _mbpf_lines(build_err, "MBPF102")
    assert len(check_lines) == 1, check_err
    assert check_lines == build_lines, (check_err, build_err)


def test_back_to_back_combined_faults_report_identically():
    parent = tempfile.mkdtemp(prefix="agree-combined-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = _write_adapter(parent)
    lockfile = write_lockfile(
        parent,
        bindir,
        pins={"bpftool": ("bpftool wrong", "0" * 64)},
    )
    os.remove(os.path.join(bindir, "mojo"))
    check_code, _, check_err = run_cli(
        [
            "check", "--manifest", manifest_path,
            "--lockfile", lockfile, "--adapter", adapter,
        ],
        path=bindir,
    )
    build_code, _, build_err = run_cli(
        [
            "build", "--manifest", manifest_path,
            "--out-dir", out_dir, "--adapter", adapter,
            "--lockfile", lockfile,
        ],
        path=bindir,
    )
    assert (check_code, build_code) == (
        cli_module.EXIT_ENVIRONMENT, cli_module.EXIT_ENVIRONMENT,
    ), (check_err, build_err)
    # One fault class must not hide the other in either verb:
    # both refuse with the same two diagnostics.
    for code in ("MBPF102", "MBPF103"):
        check_lines = _mbpf_lines(check_err, code)
        build_lines = _mbpf_lines(build_err, code)
        assert len(check_lines) == 1, (code, check_err)
        assert check_lines == build_lines, (
            code, check_err, build_err,
        )


def test_back_to_back_unloadable_lockfile_refuses_together():
    parent = tempfile.mkdtemp(prefix="agree-badlock-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = _write_adapter(parent)
    lockfile = os.path.join(parent, "toolchains.lock.json")
    with open(lockfile, "w", encoding="utf-8") as handle:
        handle.write("{not json\n")
    check_code, _, check_err = run_cli(
        [
            "check", "--manifest", manifest_path,
            "--lockfile", lockfile, "--adapter", adapter,
        ],
        path=bindir,
    )
    build_code, _, build_err = run_cli(
        [
            "build", "--manifest", manifest_path,
            "--out-dir", out_dir, "--adapter", adapter,
            "--lockfile", lockfile,
        ],
        path=bindir,
    )
    # An unloadable lockfile has no pins to agree on; both
    # verbs refuse with MBPF104 present (check additionally
    # reports discovery state, build fails fast -- each per
    # its deliberate layer contract).
    assert (check_code, build_code) == (
        cli_module.EXIT_ENVIRONMENT, cli_module.EXIT_ENVIRONMENT,
    ), (check_err, build_err)
    assert "MBPF104" in check_err, check_err
    assert "MBPF104" in build_err, build_err


def test_back_to_back_failed_distribution_refuses_together():
    parent = tempfile.mkdtemp(prefix="agree-dist-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = _write_adapter(parent)
    lockfile = write_lockfile(parent, bindir)
    with open(lockfile, encoding="utf-8") as handle:
        document = json.load(handle)
    document["distribution"] = {
        "file": "dist.txt", "sha256": "0" * 64,
    }
    with open(lockfile, "w", encoding="utf-8") as handle:
        json.dump(document, handle)
    empty = tempfile.mkdtemp(prefix="empty-path-", dir=parent)
    check_code, _, check_err = run_cli(
        [
            "check", "--manifest", manifest_path,
            "--lockfile", lockfile, "--adapter", adapter,
        ],
        path=empty,
    )
    build_code, _, build_err = run_cli(
        [
            "build", "--manifest", manifest_path,
            "--out-dir", out_dir, "--adapter", adapter,
            "--lockfile", lockfile,
        ],
        path=empty,
    )
    # The failed distribution binding blocks admission in both
    # verbs (exit 3, MBPF102 naming it); check additionally
    # reports the missing tools, build fails fast.
    assert (check_code, build_code) == (
        cli_module.EXIT_ENVIRONMENT, cli_module.EXIT_ENVIRONMENT,
    ), (check_err, build_err)
    for err in (check_err, build_err):
        lines = _mbpf_lines(err, "MBPF102")
        assert len(lines) == 1, err
        assert "distribution" in lines[0], err


def test_back_to_back_python_drift_ignored():
    parent = tempfile.mkdtemp(prefix="agree-pydrift-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(
        parent, extra=(("python3", _DECOY_PYTHON_VERSION),)
    )
    adapter = _write_adapter(parent)
    # A present-but-wrong python pin plus a decoy binary: both
    # verbs must ignore every python input and pass.
    lockfile = write_lockfile(
        parent,
        bindir,
        pins={"python": ("Python 0.0-wrong", "0" * 64)},
        tools_pinned=("mojo", "llc", "bpftool", "python"),
    )
    check_code, _, check_err = run_cli(
        [
            "check", "--manifest", manifest_path,
            "--lockfile", lockfile, "--adapter", adapter,
        ],
        path=bindir,
    )
    build_code, _, build_err = run_cli(
        [
            "build", "--manifest", manifest_path,
            "--out-dir", out_dir, "--adapter", adapter,
            "--lockfile", lockfile,
        ],
        path=bindir,
    )
    assert (check_code, build_code) == (
        cli_module.EXIT_OK, cli_module.EXIT_OK,
    ), (check_err, build_err)


def test_doctor_strict_gates_presence_by_default():
    parent = tempfile.mkdtemp(prefix="agree-strict-")
    bindir = write_tool_bindir(parent)
    code, out, _ = run_cli(["doctor", "--strict"], path=bindir)
    assert code == cli_module.EXIT_OK, out
    assert "strict: gating on required-tool presence only" in out
    os.remove(os.path.join(bindir, "bpftool"))
    code, out, err = run_cli(["doctor", "--strict"], path=bindir)
    assert code == cli_module.EXIT_ENVIRONMENT, (out, err)
    assert "MBPF103" in err, err
    # The default contract is unchanged: exit 0 plus the
    # explicit not-ready line.
    code, out, _ = run_cli(["doctor"], path=bindir)
    assert code == cli_module.EXIT_OK, out
    assert "exit 0 does not mean ready" in out, out


def test_doctor_strict_qualifies_pins_with_lockfile():
    parent = tempfile.mkdtemp(prefix="agree-strictlock-")
    bindir = write_tool_bindir(parent)
    lockfile = write_lockfile(parent, bindir)
    code, out, _ = run_cli(
        ["doctor", "--strict", "--lockfile", lockfile], path=bindir
    )
    assert code == cli_module.EXIT_OK, out
    assert "strict: gating on required tools" in out, out
    assert "gating this verdict" in out, out
    assert "never here" not in out, out
    bad_lock = write_lockfile(
        parent,
        bindir,
        name="bad.lock.json",
        pins={"llc": ("llc wrong", "0" * 64)},
    )
    code, _, err = run_cli(
        ["doctor", "--strict", "--lockfile", bad_lock], path=bindir
    )
    assert code == cli_module.EXIT_ENVIRONMENT, err
    assert "MBPF102" in err, err
    code, out, _ = run_cli(
        ["doctor", "--lockfile", bad_lock], path=bindir
    )
    assert code == cli_module.EXIT_OK, out
    assert "version unknown: not probed" in out, out
    assert "(None)" not in out, out
    code, out, _ = run_cli(
        ["doctor", "--strict", "--lockfile", bad_lock, "--json"],
        path=bindir,
    )
    assert code == cli_module.EXIT_ENVIRONMENT, out
    document = json.loads(out)
    assert document["toolchain"]["lockfile_status"] == "mismatched"
    assert document["discovery_only"] is False, document
    os.remove(os.path.join(bindir, "mojo"))
    code, _, err = run_cli(
        ["doctor", "--strict", "--lockfile", bad_lock], path=bindir
    )
    assert code == cli_module.EXIT_ENVIRONMENT, err
    assert "MBPF103" in err and "MBPF102" in err, err


def test_version_flag_prints_tool_and_sdk():
    code, out, err = run_cli(["--version"])
    assert code == cli_module.EXIT_OK, err
    assert out.strip() == "mojobpf %s (sdk %s)" % (
        TOOL_VERSION, SDK_VERSION,
    ), out


def test_check_json_carries_ambient_python():
    parent = tempfile.mkdtemp(prefix="agree-jsonpy-")
    manifest_path, _ = write_project(parent)
    bindir = write_tool_bindir(
        parent, extra=(("python3", _DECOY_PYTHON_VERSION),)
    )
    code, out, err = run_cli(
        ["check", "--manifest", manifest_path, "--json"], path=bindir
    )
    assert code == cli_module.EXIT_ENVIRONMENT, out + err
    document = json.loads(out)
    tools = {
        item["name"]: item
        for item in document["toolchain"]["tools"]
    }
    assert tools["python"]["status"] == "present", tools["python"]
    assert tools["python"]["version"] == platform.python_version()
    assert tools["python"]["path"] == os.path.realpath(
        sys.executable
    )
