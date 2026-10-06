# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Pipeline tests: the reusable build interface reproduces the pins.

Builds the two canonical programs (the packet classifier and the map
round trip) through ``build_project`` and through the ``mojobpf build``
CLI, and asserts every intermediate hash matches the pinned genuine
pipeline outputs: raw frontend IR, adapted IR (via the versioned
adapter service), and the final object. A final test feeds invalid
source through the same interface and asserts the frontend failure is
reported with its stage and exit, leaving no object behind.

Requires the working Mojo compiler and LLVM ``llc`` on PATH (for
example the project pixi environment plus system LLVM). A missing tool
is reported as an environment failure; a hash mismatch or a build
failure is a proof failure. Neither ever passes.

Runnable directly (``python3 tests/compile/test_build_pipeline.py``)
or under any ``test_``-style runner. Standard library only.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)
sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..",
        "compiler",
    ),
)

import audit  # noqa: E402
from mojobpf.build import (  # noqa: E402
    BuildRequest,
    LOWERED_CALLEE_MARKERS,
    QUALIFIED_MAP_ADD_IMMS,
    build_project,
)

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
CLASSIFIER_SOURCE = os.path.join(
    REPO_ROOT, "examples", "xdp_pass", "xdp_pass.mojo"
)
MAP_SOURCE = os.path.join(REPO_ROOT, "tests", "compile",
                          "map_roundtrip.mojo")
MUTATED_SOURCE = os.path.join(REPO_ROOT, "tests", "compile",
                             "map_roundtrip_mutated.mojo")
BAD_SOURCE = os.path.join(REPO_ROOT, "tests", "compile", "probe_bad.mojo")
SERVICE = os.path.join(REPO_ROOT, "compiler", "adapter_service.py")
SRC_DIR = os.path.join(REPO_ROOT, "src")
LOCKFILE = os.path.join(REPO_ROOT, "toolchains.lock.json")

# Pinned SHA-256 of the genuine pipeline outputs (see
# tests/probes/run_feasibility.py): the reusable interface must
# reproduce them byte-identically.
EXPECTED_PINS = {
    "classifier": {
        "raw_ir":
            "aea81a0f56b2ecbaecd3b84c04cc3c3c373c7759ccacdcb30380ab2d2b32a39a",
        "adapted_ir":
            "42cc47109656b8649ce89fe84fb9586df1e5830e3b56e7db255b5c8eabdf2413",
        "object":
            "17570ee79a16b64ccc4f723d00d26ae316a286cffdd3382ba3a6e6b4be95097c",
    },
    "map": {
        "raw_ir":
            "699d4a9797fc4f318064adb7f93e33df5c11e52c316d20c59c005b436241ab49",
        "adapted_ir":
            "b111c0d3b4fba1c32391fd3d01747ccac1381d8ffe77a5c57ece46913f50045a",
        "object":
            "18f7490634c6462360aafcb1ece85406b2374b4b74a2ca4501f90b5781e8a540",
    },
}

MANIFEST_TEMPLATE = """\
schema_version = 1

[project]
name = "{project}"

[target]
profile = "linux-bpfel-v3"
core = false

[artifact]
name = "{artifact}"
source_license = "Apache-2.0 WITH LLVM-exception"
kernel_license = "Apache-2.0 WITH LLVM-exception"

[[programs]]
source = "{source}"
entry = "{entry}"
program_type = "xdp"
section = "xdp"
{maps}
"""

MAPS_BLOCK = """\
[[maps]]
name = "mojobpf_map0"
map_type = "array"
key_type = "u32"
value_type = "u64"
max_entries = 1
"""


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def check_tools():
    for tool in ("mojo", "llc"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (
        CLASSIFIER_SOURCE, MAP_SOURCE, BAD_SOURCE, SERVICE, LOCKFILE
    ):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_project(source, entry, artifact, with_maps, dirname="proj"):
    """Copy a canonical source into a fresh project; return paths."""
    parent = tempfile.mkdtemp(prefix="build-pipeline-")
    root = os.path.join(parent, dirname)
    os.makedirs(root)
    filename = os.path.basename(source)
    staged = os.path.join(root, filename)
    shutil.copyfile(source, staged)
    manifest_path = os.path.join(root, "mojobpf.toml")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(
            MANIFEST_TEMPLATE.format(
                project="%s-proj" % entry,
                artifact=artifact,
                source=filename,
                entry=entry,
                maps=MAPS_BLOCK if with_maps else "",
            )
        )
    return manifest_path, os.path.join(root, "out")


def build(manifest_path, out_dir, save_temps=False):
    return build_project(
        BuildRequest(
            manifest_path=manifest_path,
            out_dir=out_dir,
            adapter_path=SERVICE,
            save_temps=save_temps,
            lockfile_path=LOCKFILE,
        )
    )


def assert_failure(result, out_dir):
    assert result.success is False, "failing build reported success"
    assert result.artifacts == (), "failing build reported artifacts"
    assert result.diagnostics, "failing build carried no diagnostics"
    assert not os.path.exists(out_dir) or (
        [name for name in os.listdir(out_dir) if name.endswith(".bpf.o")]
        == []
    ), "failing build left an object behind"


def test_classifier_matches_pins():
    check_tools()
    manifest_path, out_dir = write_project(
        CLASSIFIER_SOURCE, "xdp_entry", "classifier_obj", False
    )
    result = build(manifest_path, out_dir, save_temps=True)
    try:
        assert result.success is True, result.diagnostics
        assert [item.role for item in result.artifacts] == [
            "object", "evidence",
        ]
        pins = EXPECTED_PINS["classifier"]
        observed = result.artifacts[0].sha256
        assert observed == pins["object"], (
            "object mismatch: observed %s expected %s"
            % (observed, pins["object"])
        )
        workdir = result.work_dir
        assert workdir is not None
        for key, relpath in (
            ("raw_ir", "xdp_entry.raw.ll"),
            ("adapted_ir", os.path.join("xdp_entry.adapter",
                                        "adapted.ll")),
        ):
            observed = sha256_file(os.path.join(workdir, relpath))
            assert observed == pins[key], (
                "%s mismatch: observed %s expected %s"
                % (key, observed, pins[key])
            )
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_map_roundtrip_matches_pins():
    check_tools()
    manifest_path, out_dir = write_project(
        MAP_SOURCE, "xdp_entry", "roundtrip_obj", True
    )
    result = build(manifest_path, out_dir, save_temps=True)
    try:
        assert result.success is True, result.diagnostics
        assert [item.role for item in result.artifacts] == [
            "object", "evidence",
        ]
        pins = EXPECTED_PINS["map"]
        observed = result.artifacts[0].sha256
        assert observed == pins["object"], (
            "object mismatch: observed %s expected %s"
            % (observed, pins["object"])
        )
        workdir = result.work_dir
        assert workdir is not None
        for key, relpath in (
            ("raw_ir", "xdp_entry.raw.ll"),
            ("adapted_ir", os.path.join("xdp_entry.adapter",
                                        "adapted.ll")),
        ):
            observed = sha256_file(os.path.join(workdir, relpath))
            assert observed == pins[key], (
                "%s mismatch: observed %s expected %s"
                % (key, observed, pins[key])
            )
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_cli_build_matches_pin():
    check_tools()
    manifest_path, out_dir = write_project(
        CLASSIFIER_SOURCE, "xdp_entry", "cli_obj", False
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC_DIR + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [
            sys.executable, "-m", "mojobpf.cli", "build",
            "--manifest", manifest_path,
            "--out-dir", out_dir,
            "--adapter", SERVICE,
            "--lockfile", LOCKFILE,
        ],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=900,
    )
    assert proc.returncode == 0, (
        "cli build exited %d:\n%s\n%s"
        % (proc.returncode, proc.stdout, proc.stderr)
    )
    assert "built " in proc.stdout
    object_path = os.path.join(out_dir, "cli_obj.bpf.o")
    assert os.path.isfile(object_path)
    observed = sha256_file(object_path)
    expected = EXPECTED_PINS["classifier"]["object"]
    assert observed == expected, (
        "cli object mismatch: observed %s expected %s"
        % (observed, expected)
    )


def test_spaces_path_matches_pin():
    check_tools()
    manifest_path, out_dir = write_project(
        CLASSIFIER_SOURCE, "xdp_entry", "spaced_obj", False,
        dirname="pr ojéct dir",
    )
    result = build(manifest_path, out_dir)
    assert result.success is True, result.diagnostics
    observed = result.artifacts[0].sha256
    expected = EXPECTED_PINS["classifier"]["object"]
    assert observed == expected, (
        "spaced-path object mismatch: observed %s expected %s"
        % (observed, expected)
    )


def test_map_object_beyond_qualified_shape_rejected():
    # The plus-two mutation is audit-clean map IR whose object
    # carries [-16, -4, -4, 2]: the spill gate must refuse to
    # publish it with MBPF107 after a successful backend step.
    check_tools()
    if not os.path.isfile(MUTATED_SOURCE):
        raise EnvironmentFailure("missing repo file: %s" % MUTATED_SOURCE)
    manifest_path, out_dir = write_project(
        MUTATED_SOURCE, "xdp_entry", "mutated_obj", True
    )
    result = build(manifest_path, out_dir, save_temps=True)
    try:
        assert_failure(result, out_dir)
        diagnostic = result.diagnostics[0]
        assert diagnostic.code == "MBPF107", diagnostic
        assert diagnostic.stage == "build.backend", diagnostic
        assert "[-16, -4, -4, 2]" in diagnostic.explanation, diagnostic
        assert "[-16, -4, -4, 1]" in diagnostic.explanation, diagnostic
        backend = [
            record for record in result.commands
            if record.stage == "build.backend"
        ]
        assert len(backend) == 2
        assert all(record.status == "ok" for record in backend), backend
        assert result.work_dir is not None
        with open(
            os.path.join(result.work_dir, "xdp_entry.raw.ll"),
            "r", encoding="utf-8",
        ) as handle:
            assert audit.validate(handle.read()) == "map"
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_spill_gate_contract_matches_audit():
    # The gate detects map mode with the audit's own lowered
    # callee spellings and enforces the lowering suite's pinned
    # add-immediate multiset; either side drifting breaks this.
    assert tuple(LOWERED_CALLEE_MARKERS) == (
        audit.LOWERED_CALLEE["lookup"],
        audit.LOWERED_CALLEE["update"],
    )
    assert list(QUALIFIED_MAP_ADD_IMMS) == [-16, -4, -4, 1]


def test_invalid_source_fails_with_frontend_diagnostic():
    check_tools()
    manifest_path, out_dir = write_project(
        BAD_SOURCE, "xdp_entry", "bad_obj", False
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF106", diagnostic
    assert diagnostic.stage == "build.frontend", diagnostic
    frontend = [
        record for record in result.commands
        if record.stage == "build.frontend"
    ]
    assert len(frontend) == 1
    assert frontend[0].exit_code != 0


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
    print("build pipeline: both pinned objects reproduced")
    return 0


if __name__ == "__main__":
    sys.exit(main())
