# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for toolchain discovery and lockfile matching.

Discovery uses fixture tools planted on a shadow ``PATH`` so results
are deterministic on any host; the real ``PATH`` is only used by the
test that checks the repository lockfile stays readable. Every failure
asserts its exact diagnostic code. Uses only the standard library.

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3 tests/unit/test_toolchain.py``).
"""

import contextlib
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

from mojobpf import build as build_module  # noqa: E402
from mojobpf import execution as execution_module  # noqa: E402
from mojobpf import toolchain as toolchain_module  # noqa: E402
from mojobpf.build import (  # noqa: E402
    admit_adapter,
    default_adapter_path,
)
from mojobpf.execution import (  # noqa: E402
    AdmissionError,
    run_admitted,
)
from mojobpf.toolchain import (  # noqa: E402
    REQUIRED_TOOLS,
    ToolchainConfig,
    admit_tools,
    probe_toolchain,
)

REPO_LOCKFILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "..",
    "toolchains.lock.json",
)

# Fixture tool binaries shadowed ahead of the real PATH, with version
# strings that cannot be confused with real tool output.
FIXTURE_TOOLS = {
    "mojo": "Mojo 9.9.9 (fixture)",
    "llc": "Fixture LLVM version 1.2.3",
    "bpftool": "bpftool v0.0-fixture",
    "python3": "Python 9.9.9-fixture",
}

TOOL_BINARY = {
    "mojo": "mojo",
    "llc": "llc",
    "bpftool": "bpftool",
    "python": "python3",
}


def write_tool_bindir(overrides=None, broken=(), missing=()):
    """Create a bindir of fixture tools; return (bindir, versions).

    ``broken`` and ``missing`` hold tool keys from REQUIRED_TOOLS;
    ``overrides`` maps tool keys to version strings.
    """
    overrides = overrides or {}
    tmpdir = tempfile.mkdtemp(prefix="toolchain-test-")
    bindir = os.path.join(tmpdir, "bin")
    os.makedirs(bindir)
    versions = {}
    for key in REQUIRED_TOOLS:
        if key in missing:
            continue
        binary = TOOL_BINARY[key]
        if key in broken:
            script = "#!/bin/sh\necho broken >&2\nexit 1\n"
        else:
            text = overrides.get(key, FIXTURE_TOOLS[binary])
            script = "#!/bin/sh\necho '%s'\n" % text
            versions[key] = text
        path = os.path.join(bindir, binary)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(script)
        os.chmod(path, 0o755)
    return bindir, versions


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_lockfile(bindir, versions, mutate=None):
    """Write a lockfile pinning the fixture tools; return its path."""
    tools = {}
    for name in REQUIRED_TOOLS:
        binary = TOOL_BINARY[name]
        tools[name] = {
            "path": os.path.join(bindir, binary),
            "status": "present",
            "version": versions[name],
            "sha256": sha256_of(os.path.join(bindir, binary)),
        }
    data = {
        "generated_by": "fixture",
        "schema_version": 1,
        "status": "draft",
        "tools": tools,
    }
    if mutate is not None:
        mutate(data)
    path = os.path.join(
        tempfile.mkdtemp(prefix="lockfile-test-"), "toolchains.lock.json"
    )
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    return path


@contextlib.contextmanager
def isolated_path(value):
    old = os.environ.get("PATH")
    os.environ["PATH"] = value
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = old


def codes(report):
    return [item.code for item in report.diagnostics]


def test_candidate_lock2_requires_strict_native_record(tmp_path):
    from mojobpf.toolchain import load_toolchain_lock, load_toolchain_document

    record = {
        "adapter_path": "/consumer/native_adapter.py",
        "service_sha256": "1" * 64,
        "execution_sibling_sha256": "2" * 64,
        "bundle_descriptor_path": "/consumer/native-bundle.json",
        "bundle_descriptor_sha256": "3" * 64,
        "runtime_closure_path": "/consumer/runtime-closure.json",
        "runtime_closure_sha256": "4" * 64,
        "route_id": "parsed-xdp-array-candidate-v1", "qualified": False,
    }
    path = tmp_path / "candidate.json"
    document = {"schema_version": 2, "tools": {}, "native_adapter": record}
    path.write_text(json.dumps(document))
    table, status, diagnostics = load_toolchain_lock(str(path))
    assert table == {}, (status, diagnostics)
    assert load_toolchain_document(str(path)) == document
    for name in record:
        broken = dict(document, native_adapter=dict(record))
        broken["native_adapter"].pop(name)
        path.write_text(json.dumps(broken))
        table, _status, diagnostics = load_toolchain_lock(str(path))
        assert table is None, name
        assert diagnostics[0].code == "MBPF104"


def test_discovery_records_versions_and_hashes():
    bindir, versions = write_tool_bindir()
    report = probe_toolchain(ToolchainConfig(search_paths=(bindir,)))
    assert [tool.name for tool in report.tools] == list(REQUIRED_TOOLS)
    for tool in report.tools:
        assert tool.status == "present", tool
        assert tool.version == versions[tool.name], tool
        assert tool.sha256 == sha256_of(tool.path), tool
    assert report.lockfile_status == "not_checked"
    assert report.supported is False
    assert codes(report) == ["MBPF105"]
    assert report.diagnostics[0].severity == "note"


def test_matching_lockfile_validates():
    bindir, versions = write_tool_bindir()
    lockfile = write_lockfile(bindir, versions)
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=lockfile, search_paths=(bindir,))
    )
    assert report.lockfile_status == "matched"
    assert report.supported is True
    assert report.diagnostics == ()


def test_matching_lockfile_with_supported_profile_validates():
    bindir, versions = write_tool_bindir()
    lockfile = write_lockfile(bindir, versions)
    report = probe_toolchain(
        ToolchainConfig(
            lockfile_path=lockfile,
            profile_id="linux-bpfel-v3",
            search_paths=(bindir,),
        )
    )
    assert report.profile_supported is True
    assert report.supported is True
    assert report.diagnostics == ()


def test_wrong_tool_version_fails():
    bindir, versions = write_tool_bindir()

    def mutate(data):
        data["tools"]["llc"]["version"] = "Wrong LLVM version 0.0.0"

    lockfile = write_lockfile(bindir, versions, mutate=mutate)
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=lockfile, search_paths=(bindir,))
    )
    assert report.lockfile_status == "mismatched"
    assert report.supported is False
    assert codes(report) == ["MBPF102"]
    assert "llc" in report.diagnostics[0].explanation


def test_wrong_tool_hash_fails():
    bindir, versions = write_tool_bindir()

    def mutate(data):
        data["tools"]["mojo"]["sha256"] = "0" * 64

    lockfile = write_lockfile(bindir, versions, mutate=mutate)
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=lockfile, search_paths=(bindir,))
    )
    assert report.lockfile_status == "mismatched"
    assert report.supported is False
    assert codes(report) == ["MBPF102"]


def test_missing_tool_fails_without_fallback():
    bindir, _versions = write_tool_bindir(missing=("bpftool",))
    empty = tempfile.mkdtemp(prefix="empty-path-")
    with isolated_path(empty):
        report = probe_toolchain(
            ToolchainConfig(search_paths=(bindir,))
        )
    by_name = {tool.name: tool for tool in report.tools}
    assert by_name["bpftool"].status == "missing"
    assert by_name["mojo"].status == "present"
    assert "MBPF103" in codes(report)
    assert report.supported is False
    # No substitute tool is ever invented: exactly the required names.
    assert [tool.name for tool in report.tools] == list(REQUIRED_TOOLS)


def test_fully_empty_path_reports_all_missing():
    empty = tempfile.mkdtemp(prefix="empty-path-")
    with isolated_path(empty):
        report = probe_toolchain(ToolchainConfig())
    assert [tool.status for tool in report.tools] == ["missing"] * 4
    assert codes(report).count("MBPF103") == 4
    assert report.supported is False


def test_broken_tool_fails():
    bindir, versions = write_tool_bindir(broken=("llc",))
    versions = dict(versions, llc=FIXTURE_TOOLS["llc"])
    lockfile = write_lockfile(bindir, versions)
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=lockfile, search_paths=(bindir,))
    )
    by_name = {tool.name: tool for tool in report.tools}
    assert by_name["llc"].status == "broken"
    assert "MBPF103" in codes(report)
    assert report.lockfile_status == "mismatched"
    assert report.supported is False


def test_missing_lockfile_file_fails_loudly():
    bindir, _versions = write_tool_bindir()
    report = probe_toolchain(
        ToolchainConfig(
            lockfile_path=os.path.join(bindir, "no-such-lock.json"),
            search_paths=(bindir,),
        )
    )
    assert report.lockfile_status == "unreadable"
    assert codes(report) == ["MBPF104"]
    assert report.supported is False


def test_invalid_lockfile_json_fails_loudly():
    path = os.path.join(
        tempfile.mkdtemp(prefix="lockfile-test-"), "toolchains.lock.json"
    )
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("{not json\n")
    bindir, _versions = write_tool_bindir()
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=path, search_paths=(bindir,))
    )
    assert report.lockfile_status == "unreadable"
    assert codes(report) == ["MBPF104"]


def test_unsupported_lockfile_version_fails_loudly():
    bindir, versions = write_tool_bindir()

    def mutate(data):
        data["schema_version"] = 99

    lockfile = write_lockfile(bindir, versions, mutate=mutate)
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=lockfile, search_paths=(bindir,))
    )
    assert report.lockfile_status == "unsupported_version"
    assert codes(report) == ["MBPF104"]
    assert report.supported is False


def test_bool_or_float_lockfile_version_fails_loudly():
    # True == 1 and 1.0 == 1, so a bare != check would accept these
    # as schema version 1; only a strict int passes.
    for bad in (True, 1.0):
        bindir, versions = write_tool_bindir()

        def mutate(data, bad=bad):
            data["schema_version"] = bad

        lockfile = write_lockfile(bindir, versions, mutate=mutate)
        report = probe_toolchain(
            ToolchainConfig(lockfile_path=lockfile, search_paths=(bindir,))
        )
        assert report.lockfile_status == "unsupported_version", bad
        assert codes(report) == ["MBPF104"], bad
        assert report.supported is False


@contextlib.contextmanager
def refuse_spawns():
    """Fail any subprocess spawn; fail-closed paths must not probe.

    Yields the (empty on success) argv list. Manual patching
    keeps the direct-run entry point working (no pytest
    fixtures); the real spawners are always restored.
    """
    real_run = subprocess.run
    real_popen = subprocess.Popen
    calls = []

    def _refused(*args, **kwargs):
        calls.append(args[0] if args else None)
        raise AssertionError(
            "spawn refused: %r" % (args[0] if args else None,)
        )

    subprocess.run = _refused
    subprocess.Popen = _refused
    try:
        yield calls
    finally:
        subprocess.run = real_run
        subprocess.Popen = real_popen


def test_invalid_lockfile_never_probes():
    # A supplied lockfile that cannot be loaded -- missing file,
    # invalid JSON or unsupported schema -- fails closed with
    # MBPF104: every tool is still resolved and hashed
    # statically, but no version probe runs (versions stay
    # None, zero spawns), so invalid input never falls back to
    # unpinned discovery.
    bindir, versions = write_tool_bindir()
    bad_json = os.path.join(
        tempfile.mkdtemp(prefix="lockfile-test-"), "toolchains.lock.json"
    )
    with open(bad_json, "w", encoding="utf-8") as handle:
        handle.write("{not json\n")

    def mutate(data):
        data["schema_version"] = 99

    cases = [
        (
            os.path.join(bindir, "no-such-lock.json"),
            "unreadable",
        ),
        (bad_json, "unreadable"),
        (
            write_lockfile(bindir, versions, mutate=mutate),
            "unsupported_version",
        ),
    ]
    for lockfile, expected_status in cases:
        with refuse_spawns() as calls:
            report = probe_toolchain(
                ToolchainConfig(
                    lockfile_path=lockfile, search_paths=(bindir,)
                )
            )
        assert calls == [], (lockfile, calls)
        assert report.lockfile_status == expected_status, lockfile
        assert codes(report) == ["MBPF104"], (
            lockfile,
            codes(report),
        )
        assert report.supported is False
        for tool in report.tools:
            assert tool.status == "present", (lockfile, tool)
            assert tool.version is None, (lockfile, tool)
            assert tool.sha256 == sha256_of(tool.path), (
                lockfile,
                tool,
            )


def test_admit_tools_with_invalid_lock_never_probes():
    bindir, _versions = write_tool_bindir()
    with refuse_spawns() as calls:
        admitted, diagnostics = admit_tools(
            lockfile_path=os.path.join(bindir, "no-such-lock.json"),
            search_paths=(bindir,),
        )
    assert calls == []
    assert admitted == {}
    assert [item.code for item in diagnostics] == ["MBPF104"]


def test_unpinned_tool_fails():
    bindir, versions = write_tool_bindir()

    def mutate(data):
        del data["tools"]["bpftool"]

    lockfile = write_lockfile(bindir, versions, mutate=mutate)
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=lockfile, search_paths=(bindir,))
    )
    assert report.lockfile_status == "mismatched"
    assert codes(report) == ["MBPF102"]
    assert report.supported is False


def test_malformed_lockfile_pin_fails_loudly():
    bindir, versions = write_tool_bindir()

    def mutate(data):
        del data["tools"]["llc"]["sha256"]

    lockfile = write_lockfile(bindir, versions, mutate=mutate)
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=lockfile, search_paths=(bindir,))
    )
    assert report.lockfile_status == "mismatched"
    assert codes(report) == ["MBPF104"]
    assert report.supported is False


def test_unsupported_profile_fails():
    bindir, versions = write_tool_bindir()
    lockfile = write_lockfile(bindir, versions)
    report = probe_toolchain(
        ToolchainConfig(
            lockfile_path=lockfile,
            profile_id="linux-bpfeb-v9",
            search_paths=(bindir,),
        )
    )
    assert report.profile_supported is False
    assert report.supported is False
    assert codes(report) == ["MBPF101"]


def test_config_schema_version_is_rejected():
    try:
        ToolchainConfig(schema_version=99)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for schema_version 99")
    try:
        probe_toolchain("not-a-config")  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for bad config")


def test_config_bool_schema_version_is_rejected():
    for bad in (True, 1.0):
        try:
            ToolchainConfig(schema_version=bad)
        except ValueError:
            pass
        else:
            raise AssertionError(
                "expected ValueError for schema_version %r" % (bad,)
            )


def test_undecodable_tool_output_is_broken():
    bindir, _versions = write_tool_bindir()
    path = os.path.join(bindir, "mojo")
    with open(path, "wb") as handle:
        handle.write(
            b"#!/usr/bin/python3\n"
            b"import sys\n"
            b"sys.stdout.buffer.write(b'\\xff\\xfenot-utf8\\n')\n"
        )
    os.chmod(path, 0o755)
    report = probe_toolchain(ToolchainConfig(search_paths=(bindir,)))
    mojo = [tool for tool in report.tools if tool.name == "mojo"][0]
    assert mojo.status == "broken"
    assert mojo.path == path
    assert "MBPF103" in codes(report)
    assert report.supported is False


def test_admit_tools_admits_pinned_build_tools():
    bindir, versions = write_tool_bindir()
    lockfile = write_lockfile(bindir, versions)
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,)
    )
    assert sorted(admitted) == ["llc", "mojo"]
    assert diagnostics == ()
    for name in ("mojo", "llc"):
        info = admitted[name]
        assert info.status == "present"
        assert info.version == versions[name]
        assert info.sha256 == sha256_of(
            os.path.realpath(info.path)
        )
        assert info.path == os.path.join(bindir, TOOL_BINARY[name])


def test_admit_tools_requires_lockfile():
    bindir, _versions = write_tool_bindir()
    admitted, diagnostics = admit_tools(
        lockfile_path=None, search_paths=(bindir,)
    )
    assert admitted == {}
    assert [item.code for item in diagnostics] == ["MBPF104"]
    assert diagnostics[0].stage == "toolchain.match"


def test_admit_tools_rejects_pin_mismatch():
    bindir, versions = write_tool_bindir()
    lockfile = write_lockfile(bindir, versions)
    with open(lockfile, encoding="utf-8") as handle:
        data = json.load(handle)
    data["tools"]["llc"]["version"] = "wrong"
    with open(lockfile, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,)
    )
    assert admitted == {}
    assert [item.code for item in diagnostics] == ["MBPF102"]


def test_admit_tools_ignores_unpinned_extra_tools():
    bindir, versions = write_tool_bindir()
    lockfile = write_lockfile(bindir, versions)
    with open(lockfile, encoding="utf-8") as handle:
        data = json.load(handle)
    del data["tools"]["bpftool"]
    del data["tools"]["python"]
    with open(lockfile, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,)
    )
    assert sorted(admitted) == ["llc", "mojo"]
    assert diagnostics == ()


def test_admit_tools_rejects_unknown_names():
    try:
        admit_tools(lockfile_path=None, names=("mojo", "nope"))
    except ValueError:
        pass
    else:
        raise AssertionError("unknown tool name admitted")


def test_repository_lockfile_stays_readable():
    assert os.path.isfile(REPO_LOCKFILE), "repo lockfile missing"
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=REPO_LOCKFILE)
    )
    # The verdict depends on the host, but the draft format must never
    # be unreadable or silently misread by this driver.
    assert report.lockfile_status in ("matched", "mismatched")
    assert "MBPF104" not in codes(report)
    assert "MBPF105" not in codes(report)
    for diagnostic in report.diagnostics:
        assert diagnostic.code.startswith("MBPF1")


def write_launcher_bindir(kind):
    """Bindir where mojo is a launcher script; return (bindir, real).

    ``kind`` is ``"exec"`` (one ``exec`` line at a real script) or
    ``"ambiguous"`` (two ``exec`` lines; the first still runs, so the
    version probe passes but static resolution must fail closed).
    """
    tmpdir = tempfile.mkdtemp(prefix="toolchain-launcher-")
    bindir = os.path.join(tmpdir, "bin")
    realdir = os.path.join(tmpdir, "real")
    os.makedirs(bindir)
    os.makedirs(realdir)
    real = os.path.join(realdir, "mojo")
    with open(real, "w", encoding="utf-8") as handle:
        handle.write("#!/bin/sh\necho '%s'\n" % FIXTURE_TOOLS["mojo"])
    os.chmod(real, 0o755)
    script = "#!/bin/sh\nTC=%s\nexec \"$TC/mojo\" \"$@\"\n" % realdir
    if kind == "ambiguous":
        script += "exec \"$TC/other\" \"$@\"\n"
    elif kind != "exec":
        raise AssertionError(kind)
    launcher = os.path.join(bindir, "mojo")
    with open(launcher, "w", encoding="utf-8") as handle:
        handle.write(script)
    os.chmod(launcher, 0o755)
    for key in REQUIRED_TOOLS:
        if key == "mojo":
            continue
        binary = TOOL_BINARY[key]
        path = os.path.join(bindir, binary)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\necho '%s'\n" % FIXTURE_TOOLS[binary])
        os.chmod(path, 0o755)
    return bindir, real


def _tool_by_name(report, name):
    for tool in report.tools:
        if tool.name == name:
            return tool
    raise AssertionError(name)


def test_launcher_exec_target_recorded():
    bindir, real = write_launcher_bindir("exec")
    report = probe_toolchain(ToolchainConfig(search_paths=(bindir,)))
    mojo = _tool_by_name(report, "mojo")
    assert mojo.status == "present", mojo
    assert mojo.exec_path == os.path.realpath(real), mojo
    assert mojo.exec_sha256 == sha256_of(real), mojo
    assert mojo.sha256 == sha256_of(os.path.join(bindir, "mojo")), mojo
    assert mojo.exec_sha256 != mojo.sha256, mojo


def test_launcher_without_unique_exec_resolves_none():
    bindir, _real = write_launcher_bindir("ambiguous")
    report = probe_toolchain(ToolchainConfig(search_paths=(bindir,)))
    mojo = _tool_by_name(report, "mojo")
    assert mojo.status == "present", mojo
    assert mojo.exec_path is None, mojo
    assert mojo.exec_sha256 is None, mojo


def test_plain_scripts_have_no_exec_target():
    bindir, _versions = write_tool_bindir()
    report = probe_toolchain(ToolchainConfig(search_paths=(bindir,)))
    for tool in report.tools:
        assert tool.status == "present", tool
        assert tool.exec_path is None, tool
        assert tool.exec_sha256 is None, tool


def _fixture_versions():
    return {
        key: FIXTURE_TOOLS[TOOL_BINARY[key]] for key in REQUIRED_TOOLS
    }


def _patch_lockfile(lockfile, mutate):
    with open(lockfile, encoding="utf-8") as handle:
        data = json.load(handle)
    mutate(data)
    with open(lockfile, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    return lockfile


def _write_executable(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o755)


def test_admitted_probe_uses_absolute_argv0():
    # The version probe executes the captured absolute path, never
    # a re-resolved bare name: the fixture records its own argv[0].
    bindir, _versions = write_tool_bindir()
    mojo = os.path.join(bindir, "mojo")
    _write_executable(mojo, "#!/bin/sh\necho \"$0\"\n")
    report = probe_toolchain(ToolchainConfig(search_paths=(bindir,)))
    observed = _tool_by_name(report, "mojo")
    assert observed.status == "present", observed
    assert observed.version == mojo, observed
    assert observed.version != "mojo", observed


def test_exec_target_rewrite_rejected_before_probe():
    # F-002 scratch reproducer, preserved: an in-place exec-target
    # rewrite (launcher bytes unchanged) is rejected with MBPF102
    # and the substituted target never executes (no marker).
    parent = tempfile.mkdtemp(prefix="toolchain-exec-rewrite-")
    bindir, real = write_launcher_bindir("exec")
    marker = os.path.join(parent, "EXECUTED.marker")
    lockfile = write_lockfile(bindir, _fixture_versions())
    real_sha = sha256_of(real)

    def _pin_exec(data):
        data["tools"]["mojo"]["exec_sha256"] = real_sha

    _patch_lockfile(lockfile, _pin_exec)
    # Control: the intact launcher admits.
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,), names=("mojo",)
    )
    assert sorted(admitted) == ["mojo"], diagnostics
    assert admitted["mojo"].execution is not None
    # Rewrite the exec target behind the unchanged launcher entry.
    _write_executable(
        real,
        "#!/bin/sh\ntouch '%s'\necho '%s'\n"
        % (marker, FIXTURE_TOOLS["mojo"]),
    )
    assert sha256_of(os.path.join(bindir, "mojo")) == (
        admitted["mojo"].sha256
    )
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,), names=("mojo",)
    )
    assert admitted == {}
    assert [item.code for item in diagnostics] == ["MBPF102"]
    assert not os.path.exists(marker), "substituted target executed"


def test_same_version_replacement_rejected_without_execution():
    # Same bytes-shape, same version string, different bytes: the
    # replacement is rejected before any probe, leaving no marker.
    parent = tempfile.mkdtemp(prefix="toolchain-replace-")
    bindir, versions = write_tool_bindir()
    marker = os.path.join(parent, "EXECUTED.marker")
    lockfile = write_lockfile(bindir, versions)
    _write_executable(
        os.path.join(bindir, "mojo"),
        "#!/bin/sh\ntouch '%s'\necho '%s'\n"
        % (marker, FIXTURE_TOOLS["mojo"]),
    )
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,), names=("mojo",)
    )
    assert admitted == {}
    assert [item.code for item in diagnostics] == ["MBPF102"]
    assert not os.path.exists(marker), "substituted tool executed"


def test_symlink_repoint_refused_at_spawn():
    # F-003 scratch reproducer, preserved: admission hashes the
    # resolved target, but repointing the entry symlink before the
    # spawn is refused (stat identity drift) without executing.
    parent = tempfile.mkdtemp(prefix="toolchain-repoint-")
    bindir = os.path.join(parent, "bin")
    os.makedirs(bindir)
    marker = os.path.join(parent, "EXECUTED.marker")
    real1 = os.path.join(parent, "real1")
    real2 = os.path.join(parent, "real2")
    _write_executable(
        real1, "#!/bin/sh\necho '%s'\n" % FIXTURE_TOOLS["mojo"]
    )
    _write_executable(
        real2,
        "#!/bin/sh\ntouch '%s'\necho '%s'\n"
        % (marker, FIXTURE_TOOLS["mojo"]),
    )
    os.symlink(real1, os.path.join(bindir, "mojo"))
    versions = {"mojo": FIXTURE_TOOLS["mojo"]}
    lock_path = os.path.join(parent, "toolchains.lock.json")
    with open(lock_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "schema_version": 1,
                "tools": {
                    "mojo": {
                        "version": versions["mojo"],
                        "sha256": sha256_of(real1),
                    },
                },
            },
            handle,
        )
    admitted, diagnostics = admit_tools(
        lockfile_path=lock_path, search_paths=(bindir,), names=("mojo",)
    )
    assert sorted(admitted) == ["mojo"], diagnostics
    execution = admitted["mojo"].execution
    assert execution is not None
    os.remove(os.path.join(bindir, "mojo"))
    os.symlink(real2, os.path.join(bindir, "mojo"))
    record = run_admitted(execution, ("--version",))
    assert record.status == "spawn_failed", record
    assert "spawn refused" in record.log_excerpt, record
    assert not os.path.exists(marker), "repointed target executed"


def test_unknown_launcher_rejected_without_guess():
    # PATH-resolved interpreters are never guessed: admission
    # rejects the entry before probing, leaving no marker.
    # (Lock-free discovery stays observational and still reports
    # what the entry does; only admission enforces.)
    parent = tempfile.mkdtemp(prefix="toolchain-unknown-")
    bindir, versions = write_tool_bindir()
    marker = os.path.join(parent, "EXECUTED.marker")
    _write_executable(
        os.path.join(bindir, "mojo"),
        "#!/usr/bin/env sh\ntouch '%s'\necho '%s'\n"
        % (marker, FIXTURE_TOOLS["mojo"]),
    )
    versions = dict(versions, mojo=FIXTURE_TOOLS["mojo"])
    lockfile = write_lockfile(bindir, versions)
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,), names=("mojo",)
    )
    assert admitted == {}
    assert [item.code for item in diagnostics] == ["MBPF102"]
    assert "form" in diagnostics[0].explanation, diagnostics[0]
    assert not os.path.exists(marker), "unknown launcher executed"


def test_launcher_requires_exec_pin():
    # A launcher tool under a lockfile without an exec pin is
    # rejected: the chain cannot be bound, so it never runs.
    bindir, _real = write_launcher_bindir("exec")
    lockfile = write_lockfile(bindir, _fixture_versions())
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,), names=("mojo",)
    )
    assert admitted == {}
    assert [item.code for item in diagnostics] == ["MBPF102"]
    assert "exec pin" in diagnostics[0].explanation, diagnostics[0]


def test_admit_tools_attaches_executions():
    bindir, versions = write_tool_bindir()
    lockfile = write_lockfile(bindir, versions)
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,)
    )
    assert sorted(admitted) == ["llc", "mojo"]
    assert diagnostics == ()
    for name in ("mojo", "llc"):
        execution = admitted[name].execution
        assert execution is not None, name
        assert execution.contract == "execution-contract-v1", name
        assert execution.digest, name
        assert execution.argv_prefix[0] == admitted[name].path, name


def test_adapter_default_pin_enforced():
    # The packaged default adapter matches the repository lock's
    # adapter pins and admits as default-qualified.
    diagnostics = []
    execution, trust = admit_adapter(
        default_adapter_path(), REPO_LOCKFILE, diagnostics,
        trust_root="lock:%s" % REPO_LOCKFILE,
    )
    assert trust == "default", trust
    assert execution is not None, diagnostics
    assert diagnostics == []
    assert execution.argv_prefix[1] == default_adapter_path()


def test_adapter_modified_default_refused():
    # F-004 scratch reproducer, preserved: a packaged default
    # service whose BYTES no longer match the pin is refused with
    # MBPF102 before anything executes (no marker). The bytes are
    # substituted in a staged copy standing in for the packaged
    # tree; the pin is untouched. The marker line is prepended at
    # module top -- code appended after ``sys.exit(main())`` never
    # runs, so it would make the oracle ineffective -- and a
    # positive control first proves that executing the
    # substituted bytes with ``--help`` does emit the marker.
    parent = tempfile.mkdtemp(prefix="adapter-bytes-")
    marker = os.path.join(parent, "EXECUTED.marker")
    staged = os.path.join(parent, "adapter")
    os.makedirs(staged)
    service_dir = os.path.dirname(default_adapter_path())
    for name in (
        "adapter_service.py",
        "mojo_ir_adapter.py",
        "audit.py",
    ):
        with open(os.path.join(service_dir, name), "rb") as handle:
            content = handle.read()
        with open(os.path.join(staged, name), "wb") as handle:
            handle.write(content)
    staged_service = os.path.join(staged, "adapter_service.py")
    with open(staged_service, encoding="utf-8") as handle:
        staged_lines = handle.read().splitlines(keepends=True)
    # Module top, but after any shebang or __future__ import so
    # the substituted bytes still parse and execute.
    insert_at = 0
    if staged_lines and staged_lines[0].startswith("#!"):
        insert_at = 1
    for index, line in enumerate(staged_lines):
        if line.startswith("from __future__ import "):
            insert_at = index + 1
    staged_lines.insert(
        insert_at, "open(%r, 'w').write('evil')\n" % marker
    )
    with open(staged_service, "w", encoding="utf-8") as handle:
        handle.write("".join(staged_lines))
    control = subprocess.run(
        [sys.executable, staged_service, "--help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    assert control.returncode == 0, control
    assert os.path.exists(marker), "oracle control never emitted"
    os.remove(marker)
    real_default = build_module.default_adapter_path
    build_module.default_adapter_path = lambda: staged_service
    try:
        diagnostics = []
        execution, _trust = admit_adapter(
            staged_service,
            REPO_LOCKFILE,
            diagnostics,
            trust_root="lock:%s" % REPO_LOCKFILE,
        )
    finally:
        build_module.default_adapter_path = real_default
    assert execution is None
    assert [item.code for item in diagnostics] == ["MBPF102"]
    assert not os.path.exists(marker), "modified adapter executed"


def test_adapter_modified_sibling_refused():
    lock_path = os.path.join(
        tempfile.mkdtemp(prefix="adapter-sibling-"),
        "toolchains.lock.json",
    )
    with open(REPO_LOCKFILE, encoding="utf-8") as handle:
        data = json.load(handle)
    data["adapter"]["siblings"]["audit.py"] = "0" * 64
    with open(lock_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    diagnostics = []
    execution, _trust = admit_adapter(
        default_adapter_path(), lock_path, diagnostics
    )
    assert execution is None
    assert [item.code for item in diagnostics] == ["MBPF102"]


def test_adapter_explicit_is_extension():
    # An explicit non-default service is a documented opt-in
    # extension: it admits, but never as default-qualified --
    # even when its bytes match the default pin.
    parent = tempfile.mkdtemp(prefix="adapter-extension-")
    custom = os.path.join(parent, "custom-adapter.py")
    with open(default_adapter_path(), "rb") as handle:
        content = handle.read()
    with open(custom, "wb") as handle:
        handle.write(content)
    diagnostics = []
    execution, trust = admit_adapter(
        custom, REPO_LOCKFILE, diagnostics
    )
    assert trust == "extension", trust
    assert execution is not None, diagnostics
    assert diagnostics == []


def test_adapter_default_without_pins_is_unpinned():
    # The packaged default under a pin-less (test/legacy) lock
    # still runs, but records default-unpinned status.
    bindir, versions = write_tool_bindir()
    lockfile = write_lockfile(bindir, versions)
    diagnostics = []
    execution, trust = admit_adapter(
        default_adapter_path(), lockfile, diagnostics
    )
    assert trust == "default-unpinned", trust
    assert execution is not None, diagnostics
    assert diagnostics == []


def test_adapter_missing_is_setup_failure():
    diagnostics = []
    execution, _trust = admit_adapter(
        os.path.join(
            tempfile.mkdtemp(prefix="adapter-missing-"), "nope.py"
        ),
        REPO_LOCKFILE,
        diagnostics,
    )
    assert execution is None
    assert [item.code for item in diagnostics] == ["MBPF106"]


def test_spawn_refusal_raises_typed_error():
    # The low-level spawn path raises AdmissionError (typed) on
    # drift; run_admitted converts it to a spawn_failed record.
    parent = tempfile.mkdtemp(prefix="toolchain-drift-")
    bindir = os.path.join(parent, "bin")
    os.makedirs(bindir)
    target = os.path.join(parent, "tool")
    _write_executable(
        target, "#!/bin/sh\necho '%s'\n" % FIXTURE_TOOLS["mojo"]
    )
    os.symlink(target, os.path.join(bindir, "mojo"))
    lock_path = os.path.join(parent, "toolchains.lock.json")
    with open(lock_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "schema_version": 1,
                "tools": {
                    "mojo": {
                        "version": FIXTURE_TOOLS["mojo"],
                        "sha256": sha256_of(target),
                    },
                },
            },
            handle,
        )
    admitted, _diagnostics = admit_tools(
        lockfile_path=lock_path, search_paths=(bindir,), names=("mojo",)
    )
    execution = admitted["mojo"].execution
    os.remove(target)
    try:
        run_admitted(execution, ("--version",))
    except AdmissionError:
        raise AssertionError("run_admitted must not raise for outcomes")
    from mojobpf.execution import popen_admitted

    try:
        popen_admitted(execution, ("--version",))
    except AdmissionError as exc:
        assert exc.reason == "spawn-refused", exc
    else:
        raise AssertionError("drifted spawn must raise AdmissionError")


def test_version_probe_reverifies_before_spawn():
    # The version probe spawns through the same verify-then-spawn
    # path as run_admitted: drift between the static checks and
    # the probe is refused (spawn-refused) instead of executed,
    # leaving no marker. The repoint hook below only runs when
    # admission re-verifies before the probe.
    parent = tempfile.mkdtemp(prefix="toolchain-probe-drift-")
    bindir = os.path.join(parent, "bin")
    os.makedirs(bindir)
    marker = os.path.join(parent, "EXECUTED.marker")
    good = os.path.join(parent, "good")
    evil = os.path.join(parent, "evil")
    _write_executable(
        good, "#!/bin/sh\necho '%s'\n" % FIXTURE_TOOLS["mojo"]
    )
    _write_executable(
        evil,
        "#!/bin/sh\ntouch '%s'\necho '%s'\n"
        % (marker, FIXTURE_TOOLS["mojo"]),
    )
    link = os.path.join(bindir, "mojo")
    os.symlink(good, link)
    real_verify = execution_module.verify_spawn

    def _repoint_then_verify(execution):
        os.remove(link)
        os.symlink(evil, link)
        return real_verify(execution)

    execution_module.verify_spawn = _repoint_then_verify
    try:
        try:
            execution_module.admit_execution(
                execution_module.ExecutionRequest(
                    name="mojo",
                    argv0=link,
                    allow_path_lookup=False,
                    version_argv=("--version",),
                    probe_version=True,
                ),
                execution_module.ExecutionPins(
                    version=FIXTURE_TOOLS["mojo"],
                    entry_sha256=sha256_of(good),
                ),
            )
        except AdmissionError as exc:
            assert exc.reason == "spawn-refused", exc
        else:
            raise AssertionError("drifted version probe admitted")
    finally:
        execution_module.verify_spawn = real_verify
    assert not os.path.exists(marker), "drifted probe executed"


def test_conditional_wrapper_rejected_without_execution():
    # A launcher whose image selection runs through a conditional
    # is rejected as an unknown launcher, never resolved by
    # guessing which branch executes. Static reading names the
    # good image; the shell would execute the evil one (no marker).
    parent = tempfile.mkdtemp(prefix="toolchain-conditional-")
    marker = os.path.join(parent, "EXECUTED.marker")
    good = os.path.join(parent, "good.sh")
    evil = os.path.join(parent, "evil.sh")
    _write_executable(
        good, "#!/bin/sh\necho '%s'\n" % FIXTURE_TOOLS["mojo"]
    )
    _write_executable(
        evil,
        "#!/bin/sh\ntouch '%s'\necho '%s'\n"
        % (marker, FIXTURE_TOOLS["mojo"]),
    )
    bindir, versions = write_tool_bindir()
    _write_executable(
        os.path.join(bindir, "mojo"),
        "#!/bin/sh\nTARGET=%s\nif true; then TARGET=%s; fi\n"
        "exec \"$TARGET\" \"$@\"\n" % (good, evil),
    )
    lockfile = write_lockfile(bindir, versions)

    def _pin_exec(data):
        data["tools"]["mojo"]["exec_sha256"] = sha256_of(good)

    _patch_lockfile(lockfile, _pin_exec)
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,), names=("mojo",)
    )
    assert admitted == {}
    assert [item.code for item in diagnostics] == ["MBPF102"]
    assert "form" in diagnostics[0].explanation, diagnostics[0]
    assert not os.path.exists(marker), "conditional wrapper executed"


def test_distribution_binding_enforced():
    # The lockfile's distribution closure binding is verified,
    # never trusted descriptively: a valid binding admits, while
    # a placeholder digest, a nonexistent file or changed bytes
    # fail the match (MBPF102) and a malformed record is a
    # lockfile problem (MBPF104).
    bindir, versions = write_tool_bindir()
    lockfile = write_lockfile(bindir, versions)
    lockdir = os.path.dirname(lockfile)
    dist_file = os.path.join(lockdir, "dist.txt")
    with open(dist_file, "w", encoding="utf-8") as handle:
        handle.write("distribution-bytes")
    digest = sha256_of(dist_file)

    def _admit_mojo():
        return admit_tools(
            lockfile_path=lockfile,
            search_paths=(bindir,),
            names=("mojo",),
        )

    _patch_lockfile(
        lockfile,
        lambda data: data.update(
            distribution={"file": "dist.txt", "sha256": digest}
        ),
    )
    admitted, diagnostics = _admit_mojo()
    assert sorted(admitted) == ["mojo"], diagnostics

    _patch_lockfile(
        lockfile,
        lambda data: data.update(
            distribution={"file": "dist.txt", "sha256": "0" * 64}
        ),
    )
    admitted, diagnostics = _admit_mojo()
    assert admitted == {}
    assert [item.code for item in diagnostics] == ["MBPF102"]

    _patch_lockfile(
        lockfile,
        lambda data: data.update(
            distribution={"file": "no-such-dist.txt", "sha256": digest}
        ),
    )
    admitted, diagnostics = _admit_mojo()
    assert admitted == {}
    assert [item.code for item in diagnostics] == ["MBPF102"]

    with open(dist_file, "w", encoding="utf-8") as handle:
        handle.write("other-bytes")
    _patch_lockfile(
        lockfile,
        lambda data: data.update(
            distribution={"file": "dist.txt", "sha256": digest}
        ),
    )
    admitted, diagnostics = _admit_mojo()
    assert admitted == {}
    assert [item.code for item in diagnostics] == ["MBPF102"]

    _patch_lockfile(
        lockfile,
        lambda data: data.update(
            distribution={"file": "dist.txt", "sha256": 7}
        ),
    )
    admitted, diagnostics = _admit_mojo()
    assert admitted == {}
    assert [item.code for item in diagnostics] == ["MBPF104"]


def test_failed_distribution_allows_zero_probes():
    # A failed distribution binding is enforced before ANY
    # discovery probe: with an all-zero digest, no fixture tool
    # spawns, every tool carries version=None, and the match
    # fails with the distribution diagnostic.
    bindir, versions = write_tool_bindir()
    lockfile = write_lockfile(bindir, versions)
    _patch_lockfile(
        lockfile,
        lambda data: data.update(
            distribution={"file": "dist.txt", "sha256": "0" * 64}
        ),
    )
    spawns = []
    real_popen = subprocess.Popen

    def _spy(*args, **kwargs):
        argv = args[0] if args else kwargs.get("args", [])
        spawns.append(list(argv))
        return real_popen(*args, **kwargs)

    subprocess.Popen = _spy
    try:
        report = probe_toolchain(
            ToolchainConfig(
                lockfile_path=lockfile, search_paths=(bindir,)
            )
        )
    finally:
        subprocess.Popen = real_popen
    assert report.supported is False, report
    assert report.lockfile_status == "mismatched", report
    assert [tool.version for tool in report.tools] == (
        [None] * len(report.tools)
    ), report.tools
    tool_probes = [
        argv
        for argv in spawns
        if argv and argv[0].startswith(bindir + os.path.sep)
    ]
    assert tool_probes == [], tool_probes
    assert any(
        item.code == "MBPF102" and "distribution" in item.explanation
        for item in report.diagnostics
    ), report.diagnostics


def test_pinned_adapter_sibling_missing_refused():
    # A pinned adapter sibling that is missing beside the service
    # fails closed (module-not-found), never silent default trust.
    parent = tempfile.mkdtemp(prefix="adapter-missing-sibling-")
    staged = os.path.join(parent, "adapter")
    os.makedirs(staged)
    service_dir = os.path.dirname(default_adapter_path())
    with open(REPO_LOCKFILE, encoding="utf-8") as handle:
        pins = json.load(handle)["adapter"]
    for name in ("adapter_service.py", "mojo_ir_adapter.py"):
        with open(os.path.join(service_dir, name), "rb") as handle:
            content = handle.read()
        with open(os.path.join(staged, name), "wb") as handle:
            handle.write(content)

    def _admit_staged():
        return execution_module.admit_script_data(
            name="adapter",
            interpreter_path=sys.executable,
            script_path=os.path.join(staged, "adapter_service.py"),
            script_sha256=pins["service_sha256"],
            sibling_shas=dict(pins["siblings"]),
            sibling_names=("mojo_ir_adapter.py", "audit.py"),
        )

    try:
        _admit_staged()
    except AdmissionError as exc:
        assert exc.reason == "module-not-found", exc
    else:
        raise AssertionError("missing pinned sibling admitted")
    # Control: the complete staged tree admits.
    with open(os.path.join(service_dir, "audit.py"), "rb") as handle:
        audit = handle.read()
    with open(os.path.join(staged, "audit.py"), "wb") as handle:
        handle.write(audit)
    admitted = _admit_staged()
    assert admitted is not None
    assert sorted(item.name for item in admitted.modules) == [
        "audit.py",
        "mojo_ir_adapter.py",
    ]


def test_spawn_env_omits_injection_variables():
    # The spawn environment carries none of the ambient
    # import-path, loader-injection or shell-startup variables.
    bindir, versions = write_tool_bindir()
    lockfile = write_lockfile(bindir, versions)
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,), names=("mojo",)
    )
    assert sorted(admitted) == ["mojo"], diagnostics
    execution = admitted["mojo"].execution
    assert execution is not None
    saved = dict(os.environ)
    os.environ.update(
        {
            "PYTHONPATH": "/tmp/ambient",
            "PYTHONHOME": "/tmp/ambient",
            "PYTHONSTARTUP": "/tmp/ambient",
            "LD_PRELOAD": "/tmp/ambient.so",
            "LD_LIBRARY_PATH": "/tmp/ambient",
            "LD_AUDIT": "/tmp/ambient.so",
            "BASH_ENV": "/tmp/ambient",
            "ENV": "/tmp/ambient",
            "API_KEY": "s3cr3t",
            "EVIL_SNEAKY": "1",
        }
    )
    try:
        env = execution_module.spawn_env(execution)
    finally:
        os.environ.clear()
        os.environ.update(saved)
    for name in (
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "BASH_ENV",
        "ENV",
        "API_KEY",
        "EVIL_SNEAKY",
    ):
        assert name not in env, name


def test_spawn_env_allows_only_allowlisted_ambient():
    # The spawn environment keeps allowlisted ambient names and
    # drops everything else, before the overlay applies.
    bindir, versions = write_tool_bindir()
    lockfile = write_lockfile(bindir, versions)
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,), names=("mojo",)
    )
    assert sorted(admitted) == ["mojo"], diagnostics
    execution = admitted["mojo"].execution
    assert execution is not None
    saved = dict(os.environ)
    os.environ.update(
        {
            "HOME": "/home/fixture",
            "PATH": "/fixture/bin",
            "MOJO_X": "1",
            "MOJOBPF_TARGET_LEASE": "lease",
            "EVIL_SNEAKY": "1",
        }
    )
    try:
        env = execution_module.spawn_env(execution)
    finally:
        os.environ.clear()
        os.environ.update(saved)
    assert env["HOME"] == "/home/fixture", env
    assert env["PATH"] == "/fixture/bin", env
    assert env["MOJO_X"] == "1", env
    assert env["MOJOBPF_TARGET_LEASE"] == "lease", env
    assert "EVIL_SNEAKY" not in env, env


def test_version_probe_succeeds_under_minimal_env():
    # A live version probe under an allowlisted-only ambient
    # still reports the version: the allowlist must not starve
    # real tools.
    bindir, versions = write_tool_bindir()
    entry = os.path.join(bindir, "mojo")
    saved = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(
            {
                "PATH": "/usr/bin:/bin",
                "HOME": "/home/fixture",
                "LANG": "C",
                "MOJOBPF_TARGET_LEASE": "lease",
            }
        )
        version, failure = toolchain_module._observational_probe(
            "mojo", entry, (bindir,)
        )
    finally:
        os.environ.clear()
        os.environ.update(saved)
    assert failure is None, failure
    assert version == versions["mojo"], version


def test_popen_admitted_rejects_dangerous_kwargs():
    # shell/executable/preexec_fn/pass_fds raise TypeError naming
    # the kwarg before any spawn (zero spawns observed).
    bindir, versions = write_tool_bindir()
    lockfile = write_lockfile(bindir, versions)
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,), names=("mojo",)
    )
    assert sorted(admitted) == ["mojo"], diagnostics
    execution = admitted["mojo"].execution
    assert execution is not None
    dangerous = (
        ("shell", True),
        ("executable", "/bin/sh"),
        ("preexec_fn", lambda: None),
        ("pass_fds", ()),
    )
    with refuse_spawns() as calls:
        for name, value in dangerous:
            try:
                execution_module.popen_admitted(
                    execution,
                    ("--version",),
                    **{name: value},
                )
            except TypeError as exc:
                assert name in str(exc), (name, exc)
            else:
                raise AssertionError(
                    "kwarg %r was not rejected" % (name,)
                )
    assert calls == [], calls


def test_popen_admitted_accepts_current_caller_kwargs():
    # Every allowlisted kwarg passes through to a real spawn.
    bindir, versions = write_tool_bindir()
    lockfile = write_lockfile(bindir, versions)
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,), names=("mojo",)
    )
    assert sorted(admitted) == ["mojo"], diagnostics
    execution = admitted["mojo"].execution
    assert execution is not None
    proc = execution_module.popen_admitted(
        execution,
        ("--version",),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
        errors="replace",
        start_new_session=True,
        close_fds=True,
    )
    out, _err = proc.communicate(timeout=30)
    assert proc.returncode == 0, proc.returncode
    assert versions["mojo"] in out, out


def test_run_step_spawn_kwargs_within_allowlist():
    # The build step's fixed spawn kwargs stay within the
    # popen allowlist (plus cwd, a named popen_admitted param).
    names = {
        name for name, _value in build_module._RUN_STEP_SPAWN_KWARGS
    }
    assert names - {"cwd"} <= execution_module.POPN_KWARGS_ALLOW


def test_swapped_binary_between_verify_and_exec_never_runs_new_bytes():
    # File A is admitted, the path is swapped to file B (marker
    # + exit 7), verification is mocked to pass (simulating a
    # swap inside the verify→exec window): the spawn binds its
    # open descriptor to the admission and refuses the drifted
    # bytes instead of running them.
    bindir, versions = write_tool_bindir()
    lockfile = write_lockfile(bindir, versions)
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,), names=("mojo",)
    )
    assert sorted(admitted) == ["mojo"], diagnostics
    execution = admitted["mojo"].execution
    assert execution is not None
    marker = os.path.join(bindir, "SWAPPED.marker")
    swapped = os.path.join(bindir, "mojo.swapped")
    with open(swapped, "w", encoding="utf-8") as handle:
        handle.write(
            "#!/bin/sh\ntouch '%s'\nexit 7\n" % marker
        )
    os.chmod(swapped, 0o755)
    os.replace(swapped, os.path.join(bindir, "mojo"))
    real_verify = execution_module.verify_spawn
    execution_module.verify_spawn = lambda _execution: None
    try:
        record = execution_module.run_admitted(
            execution, ("--version",)
        )
        try:
            proc = execution_module.popen_admitted(
                execution,
                ("--version",),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except execution_module.AdmissionError as exc:
            assert exc.reason == (
                execution_module.REASON_SPAWN_REFUSED
            ), exc
        else:
            proc.communicate(timeout=30)
            raise AssertionError("spawned swapped bytes")
    finally:
        execution_module.verify_spawn = real_verify
    assert record.status == "spawn_failed", record
    assert record.exit_code != 7, record
    assert "drifted" in record.log_excerpt, record
    assert not os.path.exists(marker), "swapped bytes executed"


def test_admit_spawn_cycle_leaks_no_fds():
    # One admit+spawn cycle holds no file descriptors after its
    # admission is released; ResourceWarnings fail loudly.
    import gc
    import warnings

    def live_fds():
        return len(os.listdir("/proc/self/fd"))

    def cycle():
        bindir, versions = write_tool_bindir()
        lockfile = write_lockfile(bindir, versions)
        admitted, _diagnostics = admit_tools(
            lockfile_path=lockfile,
            search_paths=(bindir,),
            names=("mojo",),
        )
        record = execution_module.run_admitted(
            admitted["mojo"].execution, ("--version",)
        )
        assert record.status == "ok", record
        assert record.exit_code == 0, record

    with warnings.catch_warnings():
        warnings.simplefilter("error", ResourceWarning)
        cycle()
        gc.collect()
        before = live_fds()
        cycle()
        gc.collect()
        assert live_fds() == before


def test_no_src_caller_uses_direct_spawn_seam():
    # The unadmitted _run_step seam is test-only: no source
    # module may opt into it.
    root = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "..",
        "src",
        "mojobpf",
    )
    offenders = []
    for name in sorted(os.listdir(root)):
        if not name.endswith(".py"):
            continue
        path = os.path.join(root, name)
        with open(path, encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, 1):
                if "_direct=True" in line:
                    offenders.append(
                        "%s:%d" % (name, lineno)
                    )
    assert offenders == [], offenders


def test_spawned_environment_strips_injection_variables():
    # A child that dumps its own environment observes none of the
    # ambient injection variables, and a BASH_ENV startup file
    # pointing at a marker leaves no marker.
    parent = tempfile.mkdtemp(prefix="toolchain-spawn-env-")
    marker = os.path.join(parent, "EXECUTED.marker")
    startup = os.path.join(parent, "startup.sh")
    with open(startup, "w", encoding="utf-8") as handle:
        handle.write("touch '%s'\n" % marker)
    bindir, versions = write_tool_bindir()
    versions = dict(versions, mojo="ENVFIXTURE 1.0")
    _write_executable(
        os.path.join(bindir, "mojo"),
        "#!/bin/bash\nif [ \"x$1\" = \"x--version\" ]; then\n"
        "echo 'ENVFIXTURE 1.0'\nelse\nenv\nfi\n",
    )
    lockfile = write_lockfile(bindir, versions)
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,), names=("mojo",)
    )
    assert sorted(admitted) == ["mojo"], diagnostics
    execution = admitted["mojo"].execution
    assert execution is not None
    saved = dict(os.environ)
    os.environ.update(
        {
            "PYTHONPATH": "/tmp/ambient",
            "LD_PRELOAD": "/tmp/ambient.so",
            "LD_LIBRARY_PATH": "/tmp/ambient",
            "LD_AUDIT": "/tmp/ambient.so",
            "BASH_ENV": startup,
            "ENV": startup,
        }
    )
    try:
        from mojobpf.execution import popen_admitted
        import subprocess

        proc = popen_admitted(
            execution,
            ("dump",),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        out, _err = proc.communicate(timeout=30)
        assert proc.returncode == 0, proc.returncode
    finally:
        os.environ.clear()
        os.environ.update(saved)
    dumped = dict(
        line.split("=", 1)
        for line in out.splitlines()
        if "=" in line
    )
    for name in (
        "PYTHONPATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "BASH_ENV",
        "ENV",
    ):
        assert name not in dumped, name
    assert dumped.get("PYTHONNOUSERSITE") == "1", dumped
    assert not os.path.exists(marker), "shell startup file executed"


def _host_contract_lines():
    root = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(root))
    path = os.path.join(root, "compiler", "mojo_ir_adapter.py")
    spec = importlib.util.spec_from_file_location(
        "mojo_ir_adapter_contract", path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return (
        module.HOST_DATALAYOUT,
        module.HOST_TRIPLE,
        module.HOST_ATTRS,
    )


def write_ir_mojo(bindir, body):
    """Replace bindir mojo with a stub emitting fixed IR to -o."""
    script = (
        "#!" + sys.executable + "\n"
        "import sys\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print('Mojo 9.9.9 (fixture)')\n"
        "    sys.exit(0)\n"
        "out = sys.argv[sys.argv.index('-o') + 1]\n"
        "with open(out, 'w', encoding='utf-8') as handle:\n"
        "    handle.write(" + repr(body) + ")\n"
    )
    _write_executable(os.path.join(bindir, "mojo"), script)


def _canary_body(datalayout=None, triple=None, attrs=None):
    host_datalayout, host_triple, host_attrs = _host_contract_lines()
    lines = [
        datalayout if datalayout is not None else host_datalayout,
        triple if triple is not None else host_triple,
        "define dso_local i32 @xdp_entry(ptr noundef %0) #0 {",
        "  ret i32 2",
        "}",
        attrs if attrs is not None else host_attrs,
    ]
    return "\n".join(lines) + "\n"


def test_canary_mismatch_fails_probe_with_mbpf102():
    bindir, _versions = write_tool_bindir()
    write_ir_mojo(
        bindir, _canary_body(datalayout='target datalayout = "e-m:e"')
    )
    lockfile = write_lockfile(bindir, _fixture_versions())
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=lockfile, search_paths=(bindir,))
    )
    assert "MBPF102" in codes(report), codes(report)
    assert report.supported is False
    mojo = _tool_by_name(report, "mojo")
    assert mojo.dialect == "mismatch", mojo
    diagnostic = [
        item for item in report.diagnostics if item.code == "MBPF102"
    ][0]
    assert diagnostic.stage == "toolchain.match", diagnostic
    assert "9.9.9" in diagnostic.explanation, diagnostic
    assert "1.2.3" in diagnostic.explanation, diagnostic
    assert 'e-m:e"' in diagnostic.explanation, diagnostic


def test_canary_match_passes_silently():
    bindir, _versions = write_tool_bindir()
    write_ir_mojo(bindir, _canary_body())
    lockfile = write_lockfile(bindir, _fixture_versions())
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=lockfile, search_paths=(bindir,))
    )
    assert codes(report) == [], codes(report)
    assert report.supported is True
    mojo = _tool_by_name(report, "mojo")
    assert mojo.dialect == "match", mojo


def test_canary_skips_fixture_shaped_output():
    bindir, _versions = write_tool_bindir()
    lockfile = write_lockfile(bindir, _fixture_versions())
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=lockfile, search_paths=(bindir,))
    )
    assert codes(report) == [], codes(report)
    assert report.supported is True
    mojo = _tool_by_name(report, "mojo")
    assert mojo.dialect == "skip", mojo


def test_canary_skips_failing_emit():
    bindir, _versions = write_tool_bindir()
    _write_executable(
        os.path.join(bindir, "mojo"),
        "#!/bin/sh\necho 'Mojo 9.9.9 (fixture)'\n"
        "if [ \"$1\" != \"--version\" ]; then exit 3; fi\n",
    )
    lockfile = write_lockfile(bindir, _fixture_versions())
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=lockfile, search_paths=(bindir,))
    )
    assert codes(report) == [], codes(report)
    mojo = _tool_by_name(report, "mojo")
    assert mojo.dialect == "skip", mojo


def test_canary_never_runs_without_lockfile():
    bindir, _versions = write_tool_bindir()
    report = probe_toolchain(ToolchainConfig(search_paths=(bindir,)))
    assert codes(report) == ["MBPF105"], codes(report)
    mojo = _tool_by_name(report, "mojo")
    assert mojo.dialect is None, mojo


def test_canary_mismatch_fails_admission():
    bindir, _versions = write_tool_bindir()
    write_ir_mojo(
        bindir, _canary_body(datalayout='target datalayout = "e-m:e"')
    )
    lockfile = write_lockfile(bindir, _fixture_versions())
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,)
    )
    assert admitted == {}, admitted
    assert [item.code for item in diagnostics] == ["MBPF102"]
    assert "9.9.9" in diagnostics[0].explanation
    assert "1.2.3" in diagnostics[0].explanation


def test_canary_skips_subset_admission():
    bindir, _versions = write_tool_bindir()
    write_ir_mojo(
        bindir, _canary_body(datalayout='target datalayout = "e-m:e"')
    )
    lockfile = write_lockfile(bindir, _fixture_versions())
    admitted, diagnostics = admit_tools(
        lockfile_path=lockfile, search_paths=(bindir,), names=("mojo",)
    )
    assert sorted(admitted) == ["mojo"], diagnostics
    assert diagnostics == (), diagnostics
    assert admitted["mojo"].dialect is None


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


if __name__ == "__main__":
    sys.exit(_direct_run())
