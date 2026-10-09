# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Wheel contract: the installable package ships exactly the tool.

Builds the ``mojobpf`` wheel offline (``pip wheel --no-deps
--no-build-isolation``, so no network fetch can smuggle in
content) and pins its contract:

* the payload is exactly the Python tool modules, the validation
  package modules, the seven Mojo SDK sources, and the three
  adapter scripts (byte-identical to the tree), with the five
  contract schemas shipped as versioned wheel data files;
* the console script, license texts, and metadata (name, version,
  Python floor, SPDX grant) are present and agree with the tree;
* no stowaways: no caches, no tests, no examples, no compiler
  binaries, no development-environment paths.

Requires ``pip`` with ``setuptools``/``wheel`` for the running
interpreter. A missing builder is an environment failure, never a
pass. The installed end-to-end proof (doctor/build/inspect from a
clean virtual environment) lives in
``tests/packaging/test_installed_build.py``.

Runnable directly (``python3
tests/packaging/test_wheel_contents.py``) or under any ``test_``-style
runner. Standard library only.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(
    0, os.path.join(REPO_ROOT, "tests", "harness")
)
import mirror_sync  # noqa: E402

# Exact mojobpf/ payload of the wheel, sorted. A new, removed, or
# renamed shipped file fails here until the pin is reviewed.
PINNED_PAYLOAD = (
    "mojobpf/__init__.py",
    "mojobpf/build.py",
    "mojobpf/cli.py",
    "mojobpf/diagnostics.py",
    "mojobpf/events.py",
    "mojobpf/evidence.py",
    "mojobpf/execution.py",
    "mojobpf/helpers.py",
    "mojobpf/inputs.py",
    "mojobpf/inspect.py",
    "mojobpf/manifest.py",
    "mojobpf/resources/adapter/adapter_service.py",
    "mojobpf/resources/adapter/audit.py",
    "mojobpf/resources/adapter/mojo_ir_adapter.py",
    "mojobpf/resources/sdk/mojobpf/checksum.mojo",
    "mojobpf/resources/sdk/mojobpf/core.mojo",
    "mojobpf/resources/sdk/mojobpf/events.mojo",
    "mojobpf/resources/sdk/mojobpf/helpers.mojo",
    "mojobpf/resources/sdk/mojobpf/maps.mojo",
    "mojobpf/resources/sdk/mojobpf/packet.mojo",
    "mojobpf/resources/sdk/mojobpf/parse.mojo",
    "mojobpf/resources/sdk/mojobpf/uprobe.mojo",
    "mojobpf/sdk.py",
    "mojobpf/toolchain.py",
    "mojobpf/validation/__init__.py",
    "mojobpf/validation/aggregate.py",
    "mojobpf/validation/models.py",
    "mojobpf/verify.py",
)

# Contract schemas shipped as wheel data files under
# share/mojobpf/schemas (wheel path carries the versioned
# "<dist>.data/data/" prefix), pinned by basename. A new,
# removed, or renamed shipped schema fails here until reviewed.
PINNED_SCHEMA_DATA = (
    "cost.schema.json",
    "fixture.schema.json",
    "result.schema.json",
    "run-plan.schema.json",
    "target.schema.json",
)

# Wheel path -> tree path for byte-identity checks. The table
# lives in tests/harness/mirror_sync.py so the fast mirror check
# and this wheel contract pin the same pairs.
SYNCED_FILES = mirror_sync.SYNCED_FILES

# Substrings that must never appear in any wheel entry name.
BANNED_NAME_PARTS = (
    "__pycache__",
    ".pyc",
    ".pyo",
    ".so",
    ".o:",
    "tests/",
    "examples/",
    "compiler/",
    ".pixi",
    ".git",
)

# Basenames that would indicate a bundled compiler toolchain.
BANNED_TOOL_NAMES = (
    "mojo",
    "llc",
    "clang",
    "bpftool",
    "llc.exe",
    "mojo.exe",
)

_WHEEL_CACHE = {}


class EnvironmentFailure(Exception):
    """The wheel builder needed by this test is missing or broken."""


def build_wheel(parent):
    """Build the wheel offline into ``parent``; return its path."""
    scratch = (
        os.path.join(REPO_ROOT, "build"),
        os.path.join(REPO_ROOT, "src", "mojobpf.egg-info"),
    )
    preexisting = {path for path in scratch if os.path.exists(path)}
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                ".",
                "--no-deps",
                "--no-build-isolation",
                "-w",
                parent,
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,
        )
    except OSError as exc:
        raise EnvironmentFailure(
            "cannot run pip: %s" % exc
        ) from None
    for path in scratch:
        if path not in preexisting and os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "pip wheel failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    wheels = sorted(
        entry
        for entry in os.listdir(parent)
        if entry.endswith(".whl")
    )
    if len(wheels) != 1:
        raise EnvironmentFailure(
            "expected exactly one wheel, found: %s" % wheels
        )
    return os.path.join(parent, wheels[0])


def wheel_path():
    """Return the cached offline-built wheel path for this process."""
    if "path" not in _WHEEL_CACHE:
        parent = tempfile.mkdtemp(prefix="mojobpf-wheel-")
        _WHEEL_CACHE["dir"] = parent
        _WHEEL_CACHE["path"] = build_wheel(parent)
    return _WHEEL_CACHE["path"]


def wheel_names():
    """Return the sorted entry names of the cached wheel."""
    with zipfile.ZipFile(wheel_path()) as archive:
        return sorted(archive.namelist())


def wheel_bytes(name):
    """Return the raw bytes of one wheel entry."""
    with zipfile.ZipFile(wheel_path()) as archive:
        return archive.read(name)


def tree_version():
    """Return the tool version from the tree's package init."""
    path = os.path.join(REPO_ROOT, "src", "mojobpf", "__init__.py")
    with open(path, encoding="utf-8") as handle:
        for line in handle.read().splitlines():
            if line.startswith("__version__"):
                return line.split("=", 1)[1].strip().strip("'\"")
    raise AssertionError("no __version__ in %s" % path)


def test_wheel_builds_offline():
    path = wheel_path()
    assert os.path.isfile(path)
    expected = "mojobpf-%s-py3-none-any.whl" % tree_version()
    assert os.path.basename(path) == expected, os.path.basename(path)


def test_payload_pinned_exact():
    payload = tuple(
        name for name in wheel_names() if name.startswith("mojobpf/")
    )
    assert payload == PINNED_PAYLOAD, (
        sorted(set(payload) ^ set(PINNED_PAYLOAD))
    )


def test_no_stowaways():
    for name in wheel_names():
        lowered = name.lower()
        for part in BANNED_NAME_PARTS:
            assert part not in lowered, name
        assert os.path.isabs(name) is False, name
        assert ".." not in name.split("/"), name


def test_no_bundled_compiler():
    for name in wheel_names():
        base = os.path.basename(name).lower()
        assert base not in BANNED_TOOL_NAMES, name
    metadata = wheel_bytes(
        "mojobpf-%s.dist-info/METADATA" % tree_version()
    ).decode("utf-8")
    assert "Requires-Dist:" not in metadata, metadata


def test_entry_point():
    text = wheel_bytes(
        "mojobpf-%s.dist-info/entry_points.txt" % tree_version()
    ).decode("utf-8")
    assert "[console_scripts]" in text
    assert "mojobpf = mojobpf.cli:main" in text


def test_metadata_matches_tree():
    metadata = wheel_bytes(
        "mojobpf-%s.dist-info/METADATA" % tree_version()
    ).decode("utf-8")
    fields = {}
    for line in metadata.splitlines():
        if ": " in line:
            key, _, value = line.partition(": ")
            fields.setdefault(key, value)
    assert fields.get("Name") == "mojobpf", metadata
    assert fields.get("Version") == tree_version(), metadata
    assert fields.get("Requires-Python") == ">=3.11", metadata
    assert (
        fields.get("License") == "Apache-2.0 WITH LLVM-exception"
    ), metadata


def test_licenses_shipped_byte_identical():
    dist_info = "mojobpf-%s.dist-info" % tree_version()
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
        shipped = wheel_bytes(
            "%s/licenses/%s" % (dist_info, name)
        )
        with open(
            os.path.join(REPO_ROOT, name), "rb"
        ) as handle:
            assert shipped == handle.read(), name


def test_adapter_sync():
    dist_files = {
        name: wheel_bytes(name)
        for name in wheel_names()
        if name.startswith("mojobpf/resources/adapter/")
    }
    assert sorted(dist_files) == [
        "mojobpf/resources/adapter/adapter_service.py",
        "mojobpf/resources/adapter/audit.py",
        "mojobpf/resources/adapter/mojo_ir_adapter.py",
    ]
    for shipped, source in SYNCED_FILES:
        with open(
            os.path.join(REPO_ROOT, source), "rb"
        ) as handle:
            assert wheel_bytes(shipped) == handle.read(), shipped
    # The tree's packaged copy is the same bytes too: one source
    # of truth (compiler/), one distributed copy, pinned in sync
    # by the shared helper (also enforced wheel-free by the fast
    # mirror check).
    try:
        mirror_sync.check_tree_mirrors(REPO_ROOT)
    except mirror_sync.MirrorDriftError as exc:
        raise AssertionError(str(exc))


def test_sdk_sources_sync():
    for name in PINNED_PAYLOAD:
        if "/resources/sdk/" not in name:
            continue
        shipped = wheel_bytes(name)
        with open(
            os.path.join(
                REPO_ROOT, "src", "mojobpf",
                name[len("mojobpf/"):],
            ),
            "rb",
        ) as handle:
            assert shipped == handle.read(), name


def test_validation_sources_sync():
    for name in (
        "mojobpf/validation/__init__.py",
        "mojobpf/validation/aggregate.py",
        "mojobpf/validation/models.py",
    ):
        assert name in PINNED_PAYLOAD, name
        with open(
            os.path.join(REPO_ROOT, "src", name),
            "rb",
        ) as handle:
            assert wheel_bytes(name) == handle.read(), name


def test_schemas_shipped_byte_identical():
    prefix = "mojobpf-%s.data/data/share/mojobpf/schemas/" % (
        tree_version()
    )
    shipped = sorted(
        name for name in wheel_names() if name.startswith(prefix)
    )
    assert shipped == [prefix + name for name in PINNED_SCHEMA_DATA], (
        shipped
    )
    for name in shipped:
        with open(
            os.path.join(
                REPO_ROOT, "schemas", os.path.basename(name)
            ),
            "rb",
        ) as handle:
            assert wheel_bytes(name) == handle.read(), name


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    names = sorted(k for k in globals() if k.startswith("test_"))
    try:
        for name in names:
            try:
                globals()[name]()
            except EnvironmentFailure as exc:
                print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
                return 2
            except AssertionError as exc:
                print("FAIL %s: %s" % (name, exc))
                failures += 1
            else:
                print("PASS %s" % name)
    finally:
        parent = _WHEEL_CACHE.pop("dir", None)
        _WHEEL_CACHE.pop("path", None)
        if parent is not None:
            shutil.rmtree(parent, ignore_errors=True)
    if failures:
        return 1
    print("wheel contents: installable package contract passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
