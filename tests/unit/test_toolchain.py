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
import json
import os
import sys
import tempfile

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

from mojobpf.toolchain import (  # noqa: E402
    REQUIRED_TOOLS,
    ToolchainConfig,
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


def _direct_run():
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
