# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Third-party usability proof for the hash map SDK slice.

An external consumer (``tests/packaging/hash_consumer/``) builds its
own two-cell hash tally through the INSTALLED ``mojobpf`` package
only: a fresh wheel built from this tree is installed into a fresh
virtualenv, the consumer project is copied to an unrelated work
directory, and the product tree is scrubbed from every search path.
``mojo``/``llc``/``vng`` resolve PATH-only from an independently
installed Mojo (never the checkout's toolchain), with versions and
hashes recorded. The installed build must emit the object plus a
schema-v4 evidence sidecar sealing the consumer's own sources; the
consumer source must import only the SDK surface and must differ
from every in-tree Mojo source; the build must fail without the
installed package.

The consumer-built object then boots one disposable Linux guest and
must produce exact kernel results: seed keys 0 and 1 with 41, run
once, both read 42; run again, both read 43; the standard runner
passes on the consumer bytes; no owned pin survives.

Requires an independently installed Mojo 1.1.0 plus ``llc`` and
``vng`` on PATH (default release v6.12; MOJOBPF_VNG_RELEASE selects
the matrix lane). Missing tools fail loudly as environment failures,
never as passes.

Runnable directly (``python3 tests/packaging/test_hash_consumer.py``)
or under any ``test_``-style runner. Standard library only. The
guest boot takes a few minutes under software emulation. The guest
command runs as a session leader and a timeout kills the whole owned
guest tree (the runner group plus any detached emulator groups it
booted), never just the direct child.

Consumer toolchain admission: when MOJOBPF_CONSUMER_TOOLCHAIN_BIN
(a compiler prefix directory) and MOJOBPF_CONSUMER_TOOLCHAIN_LOCK
(independently recorded mojo/llc pins) are both set, the suite
admits the prefix tools against those pins before executing them;
a same-version replacement or an unpinned exec chain fails loudly
without running. Without both variables the suite keeps the
historical PATH discovery, but the written lockfile is labeled
bootstrap: a self-pin is never an independent trust root.

Under pytest the toolchain/venv/guest tests skip unless
MOJOBPF_CONSUMER_FULL=1 is set; direct runs always execute
everything, and the host-only admission tests always run.
"""

import atexit
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(
    0, os.path.join(REPO_ROOT, "tests", "harness")
)
import exec_chain  # noqa: E402
import lane_lock  # noqa: E402
import guest_proc  # noqa: E402
CONSUMER_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "hash_consumer"
)
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")

CONSUMER_FILES = ("README.md", "mojobpf.toml", "tally.mojo")
CONSUMER_LOCKFILE = "toolchains.lock.json"
CONSUMER_OBJECT = "hash_tally.bpf.o"
CONSUMER_SIDECAR = "hash_tally.evidence.json"

# Tokens that must never appear in the consumer's own files: adapter
# and compiler internals, tree-relative escapes, SDK source paths,
# and developer-environment markers.
FORBIDDEN_TOKENS = (
    "mojo_ir_adapter",
    "adapter_service",
    "compiler/",
    "../mojobpf",
    "resources/sdk",
    "src/mojobpf",
    ".pixi",
    "MODULAR_HOME",
)

XDP_PASS = 2
# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = 900
MAP_NAME = "mojobpf_map0"
INIT_VALUE = 41
AFTER_FIRST = 42
AFTER_SECOND = 43

_FIXTURE = {}
_GUEST = {}


class EnvironmentFailure(Exception):
    """The toolchain, builder, or VM needed by this test is missing."""


CONSUMER_FULL_ENV = "MOJOBPF_CONSUMER_FULL"
CONSUMER_PREFIX_ENV = "MOJOBPF_CONSUMER_TOOLCHAIN_BIN"
CONSUMER_PINS_ENV = "MOJOBPF_CONSUMER_TOOLCHAIN_LOCK"


class ConsumerAdmissionError(Exception):
    """A substituted consumer toolchain was refused before execution."""


def _require_full_run(caller):
    """Skip tool/venv/guest work unless a full run is requested.

    Direct runs (``python3 tests/packaging/test_*_consumer.py``, the
    form the VM matrix uses) always run everything: ``main()`` opts
    in. Under pytest the toolchain/venv/guest tests skip unless
    ``MOJOBPF_CONSUMER_FULL=1`` is set; the host-only admission
    tests always run.
    """
    if os.environ.get(CONSUMER_FULL_ENV) == "1":
        return
    try:
        import pytest as _pytest
    except ImportError:
        raise EnvironmentFailure(
            "%s needs %s=1 (toolchain, fresh installs and a guest)"
            % (caller, CONSUMER_FULL_ENV)
        )
    _pytest.skip(
        "%s needs %s=1 (toolchain, fresh installs and a guest)"
        % (caller, CONSUMER_FULL_ENV)
    )


def _run(argv, cwd, env, timeout):
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except OSError as exc:
        raise EnvironmentFailure(
            "cannot run %s: %s" % (argv[:2], exc)
        ) from None


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _under_repo(path):
    try:
        return os.path.commonpath(
            [os.path.realpath(path), os.path.realpath(REPO_ROOT)]
        ) == os.path.realpath(REPO_ROOT)
    except (OSError, ValueError):
        return True


def _build_wheel(parent):
    proc = _run(
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
        REPO_ROOT,
        dict(os.environ),
        600,
    )
    for path in (
        os.path.join(REPO_ROOT, "build"),
        os.path.join(REPO_ROOT, "src", "mojobpf.egg-info"),
    ):
        if os.path.exists(path):
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


def _scrubbed_env(venv_bin):
    """Consumer environment: ambient PATH minus the checkout tree."""
    kept = []
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry or _under_repo(entry):
            continue
        kept.append(entry)
    for entry in [venv_bin] + kept:
        assert not _under_repo(entry), entry
    env = {
        "PATH": os.pathsep.join([venv_bin] + kept),
        "HOME": os.environ.get("HOME", "/tmp"),
    }
    assert "PYTHONPATH" not in env
    assert "MODULAR_HOME" not in env
    return env


def _probe_tool(name, env):
    """Resolve one toolchain binary PATH-only; record its identity."""
    path = shutil.which(name, path=env["PATH"])
    if path is None:
        raise EnvironmentFailure(
            "required tool %r is not on the consumer PATH" % name
        )
    if _under_repo(path) or _under_repo(os.path.realpath(path)):
        raise EnvironmentFailure(
            "tool %r resolves into the checkout tree: %s" % (name, path)
        )
    argv = [path, "--version"]
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EnvironmentFailure(
            "tool version probe failed for %s: %s" % (name, exc)
        )
    if completed.returncode != 0:
        raise EnvironmentFailure(
            "tool version probe exited %d for %s"
            % (completed.returncode, name)
        )
    version = None
    text = (
        completed.stdout
        if completed.stdout.strip()
        else completed.stderr
    )
    for line in text.splitlines():
        if line.strip():
            version = line.strip()
            break
    if version is None:
        raise EnvironmentFailure(
            "tool version probe printed nothing for %s" % name
        )
    realpath = os.path.realpath(path)
    exec_path = exec_chain.follow_exec_target(realpath)
    exec_sha256 = None
    if exec_path is not None:
        exec_sha256 = _sha256_file(exec_path)
    return {
        "name": name,
        "path": path,
        "realpath": realpath,
        "version": version,
        "sha256": _sha256_file(realpath),
        "exec_path": exec_path,
        "exec_sha256": exec_sha256,
    }


def _resolve_prefix_tool(name, prefix):
    """Resolve one tool strictly under the admitted prefix directory."""
    if not prefix or not os.path.isdir(prefix):
        raise ConsumerAdmissionError(
            "consumer toolchain prefix is not a directory: %r"
            % (prefix,)
        )
    candidate = os.path.join(prefix, name)
    if not os.path.isfile(candidate):
        raise ConsumerAdmissionError(
            "required tool %r is missing from the admitted prefix %s"
            % (name, prefix)
        )
    if _under_repo(candidate) or _under_repo(os.path.realpath(candidate)):
        raise ConsumerAdmissionError(
            "tool %r resolves into the checkout tree: %s"
            % (name, candidate)
        )
    return candidate


def _admit_tool(name, path, expected, env, timeout=120):
    """Admit one prefix-resolved tool against independent pins.

    Static checks (entry hash, exec-chain binding) run before the
    version probe; any mismatch raises ConsumerAdmissionError
    without executing the tool. ``expected`` carries version/sha256
    plus exec_sha256 (None requires the entry to be its own image).
    Returns the same record shape as :func:`_probe_tool`.
    """
    for key in ("version", "sha256"):
        if not isinstance(expected.get(key), str) or not expected[key]:
            raise ConsumerAdmissionError(
                "independent pins for %r lack %r" % (name, key)
            )
    realpath = os.path.realpath(path)
    entry_sha256 = _sha256_file(realpath)
    if entry_sha256 != expected["sha256"]:
        raise ConsumerAdmissionError(
            "tool %r entry hash %s does not match the independent pin"
            % (name, entry_sha256)
        )
    exec_path = exec_chain.follow_exec_target(realpath)
    exec_sha256 = None
    if exec_path is not None:
        exec_sha256 = _sha256_file(exec_path)
    expected_exec = expected.get("exec_sha256")
    if exec_path is not None and expected_exec is None:
        raise ConsumerAdmissionError(
            "tool %r launcher chain is not pinned" % name
        )
    if exec_path is None and expected_exec is not None:
        raise ConsumerAdmissionError(
            "tool %r pins an exec chain but the entry is its own "
            "image" % name
        )
    if exec_sha256 != expected_exec:
        raise ConsumerAdmissionError(
            "tool %r exec image hash %s does not match the "
            "independent pin" % (name, exec_sha256)
        )
    argv = [path, "--version"]
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ConsumerAdmissionError(
            "admitted tool version probe failed for %s: %s" % (name, exc)
        )
    if completed.returncode != 0:
        raise ConsumerAdmissionError(
            "admitted tool version probe exited %d for %s"
            % (completed.returncode, name)
        )
    version = None
    text = (
        completed.stdout
        if completed.stdout.strip()
        else completed.stderr
    )
    for line in text.splitlines():
        if line.strip():
            version = line.strip()
            break
    if version is None:
        raise ConsumerAdmissionError(
            "admitted tool version probe printed nothing for %s" % name
        )
    if version != expected["version"]:
        raise ConsumerAdmissionError(
            "tool %r version %r does not match the independent pin "
            "%r" % (name, version, expected["version"])
        )
    return {
        "name": name,
        "path": path,
        "realpath": realpath,
        "version": version,
        "sha256": entry_sha256,
        "exec_path": exec_path,
        "exec_sha256": exec_sha256,
    }


def _load_independent_pins():
    """Load independently recorded compiler pins, or None for bootstrap.

    Both MOJOBPF_CONSUMER_TOOLCHAIN_BIN (a compiler prefix
    directory) and MOJOBPF_CONSUMER_TOOLCHAIN_LOCK (a pins JSON
    document recorded out of band) must be set; anything else is
    bootstrap mode. A configured-but-unusable pins document fails
    loudly: silent fallback would hide a broken independent
    channel. A consumer-generated self-pin is never accepted as
    the independent record.
    """
    prefix = os.environ.get(CONSUMER_PREFIX_ENV, "")
    pins_path = os.environ.get(CONSUMER_PINS_ENV, "")
    if not prefix or not pins_path:
        return None
    try:
        with open(pins_path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ConsumerAdmissionError(
            "cannot load independent pins %s: %s" % (pins_path, exc)
        )
    if not isinstance(document, dict):
        raise ConsumerAdmissionError(
            "independent pins %s is not an object" % pins_path
        )
    if str(document.get("status", "")).lower() == "bootstrap":
        raise ConsumerAdmissionError(
            "independent pins %s carry bootstrap status: a "
            "test-generated self-pin is not an independent trust "
            "root" % pins_path
        )
    if "consumer" in str(document.get("generated_by", "")).lower():
        raise ConsumerAdmissionError(
            "independent pins %s were generated by a consumer "
            "suite: a self-pin is not an independent trust root"
            % pins_path
        )
    if document.get("schema_version") != 1:
        raise ConsumerAdmissionError(
            "independent pins %s have unsupported schema_version"
            % pins_path
        )
    tools = document.get("tools")
    if not isinstance(tools, dict):
        raise ConsumerAdmissionError(
            "independent pins %s have no tools table" % pins_path
        )
    expected = {}
    for name in ("mojo", "llc"):
        entry = tools.get(name)
        if not isinstance(entry, dict):
            raise ConsumerAdmissionError(
                "independent pins %s lack %r" % (pins_path, name)
            )
        for key in ("version", "sha256"):
            if not isinstance(entry.get(key), str) or not entry[key]:
                raise ConsumerAdmissionError(
                    "independent pins %s entry %r lacks %r"
                    % (pins_path, name, key)
                )
        expected[name] = {
            "exec_sha256": entry.get("exec_sha256"),
            "sha256": entry["sha256"],
            "version": entry["version"],
        }
    return {
        "llc": expected["llc"],
        "mojo": expected["mojo"],
        "path": pins_path,
        "prefix": prefix,
        "source_sha256": _sha256_file(pins_path),
    }


def _write_consumer_lockfile(project, mojo, llc, trust):
    """Pin the consumer's toolchain plus its trust origin.

    ``trust`` is ``{"status": "admitted"|"bootstrap", ...}``:
    admitted pins were checked against the independently recorded
    compiler pins before execution; bootstrap pins are PATH
    self-pins and never qualify as independently trusted.
    """
    admitted = trust.get("status") == "admitted"
    document = {
        "generated_by": (
            "hash consumer (independently admitted pins)"
            if admitted
            else "hash consumer (PATH-resolved pins)"
        ),
        "license": "Apache-2.0 WITH LLVM-exception",
        "schema_version": 1,
        "status": trust["status"],
        "trust": dict(trust),
        "tools": {
            "llc": {
                "exec_sha256": llc["exec_sha256"],
                "sha256": llc["sha256"],
                "version": llc["version"],
            },
            "mojo": {
                "exec_sha256": mojo["exec_sha256"],
                "sha256": mojo["sha256"],
                "version": mojo["version"],
            },
        },
    }
    lockfile_path = os.path.join(project, CONSUMER_LOCKFILE)
    with open(lockfile_path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return lockfile_path


def _make_venv(root, name):
    venv = os.path.join(root, name)
    proc = _run(
        [sys.executable, "-m", "venv", venv],
        REPO_ROOT,
        dict(os.environ),
        300,
    )
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "venv creation failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    venv_bin = os.path.join(venv, "bin")
    if not os.path.isfile(os.path.join(venv_bin, "pip")):
        raise EnvironmentFailure("venv has no pip")
    return venv, venv_bin


def fixture():
    """Install the wheel fresh, then run the isolated consumer build."""
    _require_full_run("fixture")
    if "root" in _FIXTURE:
        return _FIXTURE
    for tool in ("mojo", "llc", "vng"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure(
                "%s not found on PATH" % tool
            )
    for name in CONSUMER_FILES:
        if not os.path.isfile(os.path.join(CONSUMER_DIR, name)):
            raise EnvironmentFailure("missing consumer file: %s" % name)
    if not os.path.isfile(HARNESS):
        raise EnvironmentFailure("missing harness: %s" % HARNESS)
    root = tempfile.mkdtemp(prefix="mojobpf-hash-consumer-")
    _FIXTURE["root"] = root
    atexit.register(_cleanup)
    venv, venv_bin = _make_venv(root, "venv")
    venv_python = os.path.join(venv_bin, "python")
    venv_mojobpf = os.path.join(venv_bin, "mojobpf")
    wheel = _build_wheel(os.path.join(root, "dist"))
    proc = _run(
        [os.path.join(venv_bin, "pip"), "install",
         "--no-index", "--no-deps", wheel],
        root,
        dict(os.environ),
        300,
    )
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "pip install failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    if not os.path.isfile(venv_mojobpf):
        raise EnvironmentFailure("installed console script missing")
    work = os.path.join(root, "work")
    project = os.path.join(work, "consumer")
    os.makedirs(project)
    for name in CONSUMER_FILES:
        with open(os.path.join(CONSUMER_DIR, name), "rb") as handle:
            data = handle.read()
        with open(os.path.join(project, name), "wb") as handle:
            handle.write(data)
    env = _scrubbed_env(venv_bin)
    independent = _load_independent_pins()
    if independent is not None:
        prefix = independent["prefix"]
        mojo = _admit_tool(
            "mojo",
            _resolve_prefix_tool("mojo", prefix),
            independent["mojo"],
            env,
        )
        llc = _admit_tool(
            "llc",
            _resolve_prefix_tool("llc", prefix),
            independent["llc"],
            env,
        )
        trust = {
            "origin": (
                "independently admitted compiler prefix %s "
                "(pins %s sha256 %s)"
                % (
                    prefix,
                    independent["path"],
                    independent["source_sha256"],
                )
            ),
            "pins": independent["path"],
            "pins_sha256": independent["source_sha256"],
            "prefix": prefix,
            "status": "admitted",
        }
    else:
        mojo = _probe_tool("mojo", env)
        llc = _probe_tool("llc", env)
        trust = {
            "origin": (
                "self-pin from PATH discovery; not an independent "
                "trust root (set %s and %s for admitted pins)"
                % (CONSUMER_PREFIX_ENV, CONSUMER_PINS_ENV)
            ),
            "status": "bootstrap",
        }
    vng = _probe_tool("vng", env)
    lockfile_path = _write_consumer_lockfile(project, mojo, llc, trust)
    manifest_path = os.path.join(project, "mojobpf.toml")
    out_dir = os.path.join(work, "out")
    for path in (manifest_path, out_dir, lockfile_path, work):
        assert os.path.isabs(path), path
        assert not _under_repo(path), path
    proc = _run(
        [
            venv_mojobpf,
            "build",
            "--manifest", manifest_path,
            "--out-dir", out_dir,
            "--lockfile", lockfile_path,
        ],
        project,
        env,
        600,
    )
    object_path = os.path.join(out_dir, CONSUMER_OBJECT)
    object_sha = (
        _sha256_file(object_path) if proc.returncode == 0 else None
    )
    if object_sha is not None:
        print("consumer hash object sha256: %s" % object_sha)
    _FIXTURE.update(
        {
            "venv": venv,
            "venv_bin": venv_bin,
            "venv_python": venv_python,
            "venv_mojobpf": venv_mojobpf,
            "work": work,
            "project": project,
            "manifest_path": manifest_path,
            "lockfile_path": lockfile_path,
            "out_dir": out_dir,
            "env": env,
            "mojo": mojo,
            "llc": llc,
            "vng": vng,
            "trust": trust,
            "independent_pins": (
                independent["path"] if independent is not None else None
            ),
            "build": proc,
            "object_sha": object_sha,
        }
    )
    return _FIXTURE


def _cleanup():
    root = _FIXTURE.pop("root", None)
    if root is not None:
        shutil.rmtree(root, ignore_errors=True)


def _evidence_document(fix):
    sidecar = os.path.join(fix["out_dir"], CONSUMER_SIDECAR)
    assert os.path.isfile(sidecar), "evidence sidecar missing"
    with open(sidecar, "rb") as handle:
        raw = handle.read()
    assert REPO_ROOT.encode() not in raw, "sidecar leaks checkout bytes"
    assert os.path.dirname(REPO_ROOT).encode() not in raw
    return json.loads(raw.decode("ascii")), raw


def test_consumer_builds_with_installed_tool():
    fix = fixture()
    proc = fix["build"]
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
    objects = sorted(
        entry
        for entry in os.listdir(fix["out_dir"])
        if entry.endswith(".bpf.o")
    )
    assert objects == [CONSUMER_OBJECT], objects
    doc, _raw = _evidence_document(fix)
    assert doc["schema_version"] == 4, doc
    assert doc["success"] is True
    assert doc["tool_version"] == "0.2.0", doc
    assert doc["sdk_version"] == "1.5", doc
    assert doc["artifact"] == "hash_tally", doc
    assert doc["profile_id"] == "linux-bpfel-v3-hash", doc


def test_consumer_toolchain_resolved_path_only():
    fix = fixture()
    mojo = fix["mojo"]
    assert mojo["version"].startswith("Mojo 1.1.0"), mojo
    assert not _under_repo(mojo["path"]), mojo
    assert not _under_repo(mojo["realpath"]), mojo
    assert "MODULAR_HOME" not in fix["env"], "consumer env leaks home"
    assert "PYTHONPATH" not in fix["env"]
    for entry in fix["env"]["PATH"].split(os.pathsep):
        assert not _under_repo(entry), entry
    proc = _run(
        [fix["venv_python"], "-c",
         "import sys; print(sys.path)"],
        fix["project"],
        fix["env"],
        60,
    )
    assert proc.returncode == 0, proc.stderr
    assert REPO_ROOT not in proc.stdout, proc.stdout
    proc = _run(
        [fix["venv_mojobpf"], "doctor", "--json"],
        fix["project"],
        fix["env"],
        120,
    )
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    package = os.path.realpath(doc["package_path"])
    assert package.startswith(
        os.path.realpath(fix["venv"]) + os.sep
    ), package
    tools = {
        item["name"]: item
        for item in doc["toolchain"]["tools"]
    }
    assert tools["mojo"]["status"] == "present", tools
    assert tools["mojo"]["version"] == mojo["version"], tools
    assert tools["mojo"]["sha256"] == mojo["sha256"], tools
    assert not _under_repo(tools["mojo"]["path"]), tools
    assert tools["mojo"]["exec_path"] == mojo["exec_path"], tools
    assert tools["mojo"]["exec_sha256"] == mojo["exec_sha256"], tools
    assert mojo["exec_sha256"] is not None, mojo
    assert mojo["exec_sha256"] != mojo["sha256"], mojo
    assert not _under_repo(mojo["exec_path"]), mojo
    assert os.path.isfile(mojo["exec_path"]), mojo


def test_consumer_imports_only_the_sdk_surface():
    fix = fixture()
    source = os.path.join(fix["project"], "tally.mojo")
    proc = _run(
        [
            fix["venv_python"], "-c",
            "import json, sys; "
            "from mojobpf.sdk import check_mojo_file; "
            "sys.stdout.write(json.dumps("
            "[(v.line, v.statement, v.explanation) "
            "for v in check_mojo_file(sys.argv[1])]))",
            source,
        ],
        fix["project"],
        fix["env"],
        120,
    )
    assert proc.returncode == 0, proc.stderr
    violations = json.loads(proc.stdout)
    assert violations == [], violations


def test_consumer_has_no_copy_no_path_back():
    fix = fixture()
    project_files = sorted(os.listdir(fix["project"]))
    assert project_files == sorted(
        list(CONSUMER_FILES) + [CONSUMER_LOCKFILE]
    ), project_files
    for name in CONSUMER_FILES:
        with open(
            os.path.join(fix["project"], name), "rb"
        ) as handle:
            data = handle.read()
        for token in FORBIDDEN_TOKENS:
            assert token.encode() not in data, (name, token)
        assert REPO_ROOT.encode() not in data, name
    assert not [
        name for name in project_files
        if name.endswith((".bpf.o", ".ll", ".json"))
        and name != CONSUMER_LOCKFILE
    ], "consumer must compile; no prebuilt object may ride along"
    tally_sha = _sha256_file(os.path.join(fix["project"], "tally.mojo"))
    own_source = os.path.join(CONSUMER_DIR, "tally.mojo")
    compared = 0
    for current, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [
            entry for entry in dirs
            if entry not in ("__pycache__", ".git", ".pixi", "build")
        ]
        for name in files:
            if not name.endswith(".mojo"):
                continue
            other = os.path.join(current, name)
            if os.path.realpath(other) == os.path.realpath(own_source):
                continue
            compared += 1
            assert _sha256_file(other) != tally_sha, (
                "consumer source copies %s" % other
            )
    assert compared > 0, "no in-tree Mojo sources compared"
    print("PASS no-copy corpus: tally differs from %d sources" % compared)


def test_consumer_object_compiled_from_own_source():
    fix = fixture()
    assert fix["build"].returncode == 0
    doc, _raw = _evidence_document(fix)
    by_stage = {}
    for item in doc["commands"]:
        by_stage.setdefault(item["stage"], []).append(item)
    for stage in ("build.frontend", "build.adapter", "build.backend"):
        assert stage in by_stage, sorted(by_stage)
        for item in by_stage[stage]:
            assert item["status"] == "ok", item
            assert item["exit_code"] == 0, item
    frontend_argv = " ".join(by_stage["build.frontend"][0]["argv"])
    assert "mojo" in frontend_argv, frontend_argv
    assert "--emit" in frontend_argv, frontend_argv
    backend_argv = " ".join(by_stage["build.backend"][0]["argv"])
    assert "llc" in backend_argv, backend_argv
    assert "bpfel" in backend_argv, backend_argv
    sources = {
        item["path"]: item["sha256"]
        for item in doc["inputs"]["source"]
    }
    assert sources == {
        "tally.mojo": _sha256_file(
            os.path.join(fix["project"], "tally.mojo")
        )
    }, sources
    compiler_blob = " ".join(doc["inputs"]["compiler"])
    assert fix["mojo"]["version"] in compiler_blob, compiler_blob
    assert fix["mojo"]["sha256"] in compiler_blob, compiler_blob
    assert fix["llc"]["version"] in compiler_blob, compiler_blob
    assert fix["llc"]["sha256"] in compiler_blob, compiler_blob
    obj = os.path.join(fix["out_dir"], CONSUMER_OBJECT)
    proc = _run(
        [
            fix["venv_mojobpf"],
            "inspect",
            "--object", obj,
            "--source-license", "Apache-2.0 WITH LLVM-exception",
            "--kernel-license", "Apache-2.0 WITH LLVM-exception",
        ],
        fix["project"],
        fix["env"],
        120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ok" in proc.stdout


def test_build_fails_without_installed_package():
    fix = fixture()
    bare_venv, bare_bin = _make_venv(fix["root"], "bare-venv")
    bare_python = os.path.join(bare_bin, "python")
    assert not os.path.exists(os.path.join(bare_bin, "mojobpf"))
    env = _scrubbed_env(bare_bin)
    proc = _run(
        [bare_python, "-c", "import mojobpf"],
        fix["project"],
        env,
        60,
    )
    assert proc.returncode != 0, "mojobpf resolves without install"
    proc = _run(
        [
            bare_python, "-m", "mojobpf", "build",
            "--manifest", fix["manifest_path"],
            "--out-dir", os.path.join(fix["work"], "bare-out"),
            "--lockfile", fix["lockfile_path"],
        ],
        fix["project"],
        env,
        120,
    )
    assert proc.returncode != 0, "build works without the package"
    assert "No module named mojobpf" in proc.stderr, proc.stderr
    assert not os.path.exists(os.path.join(fix["work"], "bare-out"))


def hexle(value):
    """Lowercase hex of a u64 value without spaces (bpftool order)."""
    return "".join(
        "%02x" % byte for byte in value.to_bytes(8, byteorder="little")
    )


GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin guest_tally ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
bpftool version | head -2
echo "=== staged hashes ==="
sha256sum bpf_test_run.py tally.bpf.o data.bin
map_case() {{
  tag="$1"; obj="$2"
  pin="/sys/fs/bpf/mojobpf_tally_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  bpftool prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  python3 - "$out" >/tmp/xdp-$tag.mapinfo 2>&1 <<'PYEOF'
import json
import subprocess
import sys
fields = sys.argv[1]
info = {{"map_found": "0"}}
try:
    raw = subprocess.run(
        ["bpftool", "-j", "map", "show"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    for entry in json.loads(raw.stdout or "[]"):
        if entry.get("name") == "{map_name}":
            info = {{
                "map_found": "1",
                "map_id": str(entry.get("id")),
                "map_type": str(entry.get("type")),
                "map_key": str(entry.get("bytes_key")),
                "map_value": str(entry.get("bytes_value")),
                "map_entries": str(entry.get("max_entries")),
            }}
except Exception as exc:
    info = {{"map_found": "0", "map_error": str(exc)}}
with open(fields, "a") as handle:
    for key in sorted(info):
        handle.write("%s=%s\\n" % (key, info[key]))
PYEOF
  echo "mapinfo_exit=$?" >> "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  for key in 0 1; do
    bpftool map update id "$map_id" key $key 0 0 0 value {init} 0 0 0 0 0 0 0 >/tmp/xdp-$tag.update$key 2>&1
    echo "init${{key}}_exit=$?" >> "$out"
  done
  for key in 0 1; do
    bpftool map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.before$key 2>&1
    echo "before${{key}}_exit=$?" >> "$out"
  done
  bpftool prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run1 2>&1
  echo "run1_exit=$?" >> "$out"
  for key in 0 1; do
    bpftool map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.after1$key 2>&1
    echo "after1_${{key}}_exit=$?" >> "$out"
  done
  bpftool prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run2 2>&1
  echo "run2_exit=$?" >> "$out"
  for key in 0 1; do
    bpftool map lookup id "$map_id" key $key 0 0 0 > /tmp/xdp-$tag.after2$key 2>&1
    echo "after2_${{key}}_exit=$?" >> "$out"
  done
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
  echo "=== BEGIN $tag ==="
  cat "$out"
  for key in 0 1; do
    echo "--- $tag before$key ---"
    cat /tmp/xdp-$tag.before$key
  done
  echo "--- $tag run1 ---"
  cat /tmp/xdp-$tag.run1
  for key in 0 1; do
    echo "--- $tag after1_$key ---"
    cat /tmp/xdp-$tag.after1$key
  done
  echo "--- $tag run2 ---"
  cat /tmp/xdp-$tag.run2
  for key in 0 1; do
    echo "--- $tag after2_$key ---"
    cat /tmp/xdp-$tag.after2$key
  done
  echo "=== END $tag ==="
}}
harness_case() {{
  tag="$1"; obj="$2"
  out="/tmp/xdp-$tag.json"
  python3 bpf_test_run.py --object "$obj" --expect-action {action} \\
    --data-in data.bin --output "$out" >/tmp/xdp-$tag.stdout 2>/tmp/xdp-$tag.stderr
  code=$?
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
stray=0
for pin in /sys/fs/bpf/mojobpf_tally_* /sys/fs/bpf/mojobpf_control; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; stray=1; fi
done
if [ "$stray" -eq 0 ]; then echo "pin absent (unloaded)"; fi
echo "=== end guest_tally ==="
"""

CASES = (
    ("tally", "tally.bpf.o", "map"),
    ("tally-harness", "tally.bpf.o", "harness"),
)


def _run_guest(argv, stage, timeout):
    """Run the guest command; return (exit code, output text).

    Thin mapping over the shared owned runner
    (tests/harness/guest_proc.py): a timeout surfaces as
    EnvironmentFailure carrying the partial output.
    """
    try:
        return guest_proc.run_owned(argv, stage, timeout)
    except guest_proc.GuestTimeout as exc:
        raise EnvironmentFailure(
            "guest run timed out after %ds (stage kept at %s):\n%s"
            % (timeout, stage, exc.output[-4000:])
        )


def guest_run():
    """Stage the consumer object, boot one guest, return case results."""
    _require_full_run("guest_run")
    if "run" in _GUEST:
        return _GUEST["run"]
    fix = fixture()
    assert fix["build"].returncode == 0, "consumer build must pass first"
    # The guest boots with the same scrubbed-PATH vng binary the
    # fixture probed and recorded, never an ambient re-resolution.
    vng_path = fix["vng"]["path"]
    stage = tempfile.mkdtemp(prefix="consumer-tally-", dir="/tmp")
    staged = {
        "bpf_test_run.py": HARNESS,
        "tally.bpf.o": os.path.join(fix["out_dir"], CONSUMER_OBJECT),
    }
    with open(os.path.join(stage, "data.bin"), "wb") as handle:
        handle.write(bytes(60))
    for name, src in staged.items():
        with open(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    host_shas = {
        name: _sha256_file(os.path.join(stage, name))
        for name in list(staged) + ["data.bin"]
    }
    commands = []
    for tag, obj, kind in CASES:
        if kind == "map":
            commands.append("map_case %s %s" % (tag, obj))
        else:
            commands.append("harness_case %s %s" % (tag, obj))
    script = GUEST_SCRIPT.format(
        stage=stage,
        commands="\n".join(commands),
        map_name=MAP_NAME,
        init=INIT_VALUE,
        action=XDP_PASS,
    )
    script_path = os.path.join(stage, "guest_tally.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["data.bin", "guest_tally.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    code, output = _run_guest(
        [vng_path, "--run", VNG_RELEASE, "--disable-kvm",
         "--exec", "bash %s" % script_path],
        stage,
        VNG_TIMEOUT,
    )
    if code != 0:
        raise EnvironmentFailure(
            "vng guest run failed (exit %d, stage kept at %s):\n%s"
            % (code, stage, output[-4000:])
        )
    results = {}
    for match in re.finditer(
        r"=== BEGIN (\S+)(?: exit=(\d+))? ===\n(.*?)\n=== END \1 ===",
        output,
        re.DOTALL,
    ):
        tag, exit_code, body = match.groups()
        results[tag] = {
            "exit": int(exit_code) if exit_code is not None else None,
            "body": body,
        }
    missing = [tag for tag, _, _ in CASES if tag not in results]
    if missing:
        raise EnvironmentFailure(
            "guest output lacks cases %s (stage kept at %s):\n%s"
            % (", ".join(missing), stage, output[-4000:])
        )
    _GUEST["run"] = {
        "stage": stage,
        "output": output,
        "results": results,
        "host_shas": host_shas,
    }
    return _GUEST["run"]


def parse_fields(body):
    fields = {}
    for line in body.splitlines():
        if "=" in line and not line.startswith(("key:", "---", "Return")):
            key, _, value = line.partition("=")
            key = key.strip()
            if key and " " not in key:
                fields[key] = value.strip()
    return fields


def parse_lookup_hex(body, marker):
    """Extract the looked-up value bytes as compact lowercase hex."""
    section = body.split(marker, 1)[1]
    match = re.search(r"value:\s*([0-9a-fA-F ]+)", section)
    assert match, "no bpftool value line after %r" % marker
    return match.group(1).replace(" ", "").lower()


def parse_run_action(body, marker):
    section = body.split(marker, 1)[1]
    match = re.search(r"Return value:\s*(\d+)", section)
    assert match, "no bpftool return-value line after %r" % marker
    return int(match.group(1))


def test_consumer_exact_kernel_result():
    run = guest_run()
    body = run["results"]["tally"]["body"]
    fields = parse_fields(body)
    for key in (
        "load_exit",
        "mapinfo_exit",
        "init0_exit",
        "init1_exit",
        "before0_exit",
        "before1_exit",
        "run1_exit",
        "after1_0_exit",
        "after1_1_exit",
        "run2_exit",
        "after2_0_exit",
        "after2_1_exit",
    ):
        assert fields.get(key) == "0", "%s=%r" % (key, fields.get(key))
    assert fields.get("map_found") == "1", "map not found"
    assert fields.get("map_type") == "hash", "not a hash map"
    assert fields.get("map_key") == "4", "key size is not u32"
    assert fields.get("map_value") == "8", "value size is not u64"
    assert fields.get("map_entries") == "2", "not two entries"
    assert fields.get("unload_ok") == "1", "pin was not removed"
    for key in (0, 1):
        before = parse_lookup_hex(body, "before%d ---" % key)
        assert before == hexle(INIT_VALUE), (
            "key %d: userspace init must read back %d first, got %s"
            % (key, INIT_VALUE, before)
        )
    assert parse_run_action(body, "run1 ---") == XDP_PASS
    for key in (0, 1):
        after_first = parse_lookup_hex(body, "after1_%d ---" % key)
        assert after_first == hexle(AFTER_FIRST), (
            "key %d: first run must observe %d, got %s"
            % (key, AFTER_FIRST, after_first)
        )
    assert parse_run_action(body, "run2 ---") == XDP_PASS
    for key in (0, 1):
        after_second = parse_lookup_hex(body, "after2_%d ---" % key)
        assert after_second == hexle(AFTER_SECOND), (
            "key %d: second run must observe %d, got %s"
            % (key, AFTER_SECOND, after_second)
        )


def test_consumer_standard_runner_passes():
    run = guest_run()
    record = run["results"]["tally-harness"]
    assert record["exit"] == 0, (
        "standard runner must exit 0, got %r" % (record["exit"],)
    )
    try:
        doc = json.loads(record["body"])
    except ValueError:
        raise AssertionError(
            "harness did not emit JSON:\n%s" % record["body"][-500:]
        )
    assert doc.get("contract_version") == 2, doc
    assert doc.get("status") == "pass", doc
    assert doc.get("stage") == "run", doc
    assert doc.get("classification") is None, doc
    assert doc.get("expected_action") == XDP_PASS, doc
    assert doc.get("actual_action") == XDP_PASS, doc
    assert doc.get("cleanup_ok") is True, doc
    assert doc.get("object", {}).get("sha256") == run["host_shas"][
        "tally.bpf.o"
    ], doc


def test_consumer_guest_provenance():
    run = guest_run()
    try:
        observed_kernel = lane_lock.booted_kernel_from_output(run["output"])
        lane_lock.check_booted_kernel(
            observed_kernel, REPO_ROOT, VNG_RELEASE
        )
    except lane_lock.LaneLockError as exc:
        raise AssertionError("guest kernel must be locked: %s" % exc)
    assert "pin absent (unloaded)" in run["output"], "pins must go"
    assert "PIN STILL PRESENT" not in run["output"], "pins must go"
    for name, sha in sorted(run["host_shas"].items()):
        assert "%s  %s" % (sha, name) in run["output"], (
            "guest must re-verify staged bytes for %s" % name
        )


def _write_host_script(path, body):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
    os.chmod(path, 0o755)


def _make_host_prefix(workdir):
    """Fixture compiler prefix: launcher mojo plus script llc."""
    bindir = os.path.join(workdir, "prefix", "bin")
    realdir = os.path.join(workdir, "prefix", "real")
    os.makedirs(bindir)
    os.makedirs(realdir)
    mojo_marker = os.path.join(workdir, "mojo-marker.log")
    llc_marker = os.path.join(workdir, "llc-marker.log")
    mojo_version = "Mojo 1.1.0 (host-fixture)"
    llc_version = "Host LLVM version 1.0"
    real = os.path.join(realdir, "mojo")
    _write_host_script(
        real,
        "#!/bin/sh\necho probe >> %s\necho '%s'\n"
        % (mojo_marker, mojo_version),
    )
    entry = os.path.join(bindir, "mojo")
    _write_host_script(
        entry,
        "#!/bin/sh\nTC=%s\nexec \"$TC/mojo\" \"$@\"\n" % realdir,
    )
    llc = os.path.join(bindir, "llc")
    _write_host_script(
        llc,
        "#!/bin/sh\necho probe >> %s\necho '%s'\n"
        % (llc_marker, llc_version),
    )
    return {
        "bin": bindir,
        "mojo": entry,
        "mojo_marker": mojo_marker,
        "mojo_version": mojo_version,
        "llc": llc,
        "llc_marker": llc_marker,
        "llc_version": llc_version,
    }


def _make_host_pins(workdir, prefix, mutate=None):
    document = {
        "generated_by": "host fixture (independent toolchain record)",
        "schema_version": 1,
        "tools": {
            "llc": {
                "sha256": _sha256_file(prefix["llc"]),
                "version": prefix["llc_version"],
            },
            "mojo": {
                "exec_sha256": _sha256_file(
                    os.path.join(
                        os.path.dirname(prefix["bin"]), "real", "mojo"
                    )
                ),
                "sha256": _sha256_file(prefix["mojo"]),
                "version": prefix["mojo_version"],
            },
        },
    }
    if mutate is not None:
        mutate(document)
    pins_path = os.path.join(workdir, "independent-pins.json")
    with open(pins_path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return pins_path


def _host_env(prefix):
    return {"PATH": prefix["bin"] + os.pathsep + "/usr/bin:/bin"}


def _save_consumer_env():
    saved = {}
    for key in (CONSUMER_FULL_ENV, CONSUMER_PREFIX_ENV, CONSUMER_PINS_ENV):
        saved[key] = os.environ.pop(key, None)
    return saved


def _restore_consumer_env(saved):
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def _bootstrap_trust():
    return {
        "origin": (
            "self-pin from PATH discovery; not an independent "
            "trust root"
        ),
        "status": "bootstrap",
    }


def test_consumer_lock_declares_trust():
    fix = fixture()
    with open(fix["lockfile_path"], encoding="utf-8") as handle:
        document = json.load(handle)
    assert document["status"] == fix["trust"]["status"]
    if fix["independent_pins"] is None:
        assert document["status"] == "bootstrap"
        assert "not an independent" in document["trust"]["origin"]
    else:
        assert document["status"] == "admitted"
        assert fix["independent_pins"] in document["trust"]["origin"]


def test_consumer_admission_rejects_replacement():
    workdir = tempfile.mkdtemp(prefix="consumer-admission-")
    saved = _save_consumer_env()
    try:
        prefix = _make_host_prefix(workdir)
        pins_path = _make_host_pins(workdir, prefix)
        os.environ[CONSUMER_PREFIX_ENV] = prefix["bin"]
        os.environ[CONSUMER_PINS_ENV] = pins_path
        independent = _load_independent_pins()
        assert independent["prefix"] == prefix["bin"]
        env = _host_env(prefix)
        record = _admit_tool(
            "mojo", prefix["mojo"], independent["mojo"], env
        )
        assert record["version"] == prefix["mojo_version"]
        assert os.path.isfile(prefix["mojo_marker"])
        os.unlink(prefix["mojo_marker"])
        with open(prefix["mojo"], "a", encoding="utf-8") as handle:
            handle.write("# same-version replacement\n")
        try:
            _admit_tool(
                "mojo", prefix["mojo"], independent["mojo"], env
            )
        except ConsumerAdmissionError as exc:
            assert "hash" in str(exc), exc
        else:
            raise AssertionError("replacement compiler admitted")
        assert not os.path.exists(prefix["mojo_marker"]), (
            "replaced compiler must never execute"
        )
        probed = _probe_tool(
            "mojo", {"PATH": prefix["bin"], "HOME": workdir}
        )
        assert probed["version"] == prefix["mojo_version"]
        assert os.path.isfile(prefix["mojo_marker"]), (
            "control: PATH-only probing executes whatever it finds"
        )
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_consumer_admission_rejects_unapproved_chain():
    workdir = tempfile.mkdtemp(prefix="consumer-chain-")
    saved = _save_consumer_env()
    try:
        prefix = _make_host_prefix(workdir)
        env = _host_env(prefix)

        def _drop_exec(document):
            del document["tools"]["mojo"]["exec_sha256"]

        pins_path = _make_host_pins(workdir, prefix, mutate=_drop_exec)
        os.environ[CONSUMER_PREFIX_ENV] = prefix["bin"]
        os.environ[CONSUMER_PINS_ENV] = pins_path
        independent = _load_independent_pins()
        try:
            _admit_tool(
                "mojo", prefix["mojo"], independent["mojo"], env
            )
        except ConsumerAdmissionError as exc:
            assert "pinned" in str(exc), exc
        else:
            raise AssertionError("unpinned launcher chain admitted")
        assert not os.path.exists(prefix["mojo_marker"])

        def _wrong_exec(document):
            document["tools"]["mojo"]["exec_sha256"] = "5" * 64

        pins_path = _make_host_pins(workdir, prefix, mutate=_wrong_exec)
        os.environ[CONSUMER_PINS_ENV] = pins_path
        independent = _load_independent_pins()
        try:
            _admit_tool(
                "mojo", prefix["mojo"], independent["mojo"], env
            )
        except ConsumerAdmissionError as exc:
            assert "exec" in str(exc), exc
        else:
            raise AssertionError("mismatched exec image admitted")
        assert not os.path.exists(prefix["mojo_marker"])
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_consumer_admits_independent_prefix():
    workdir = tempfile.mkdtemp(prefix="consumer-admitted-")
    saved = _save_consumer_env()
    try:
        prefix = _make_host_prefix(workdir)
        pins_path = _make_host_pins(workdir, prefix)
        os.environ[CONSUMER_PREFIX_ENV] = prefix["bin"]
        os.environ[CONSUMER_PINS_ENV] = pins_path
        independent = _load_independent_pins()
        env = _host_env(prefix)
        mojo = _admit_tool(
            "mojo",
            _resolve_prefix_tool("mojo", independent["prefix"]),
            independent["mojo"],
            env,
        )
        llc = _admit_tool(
            "llc",
            _resolve_prefix_tool("llc", independent["prefix"]),
            independent["llc"],
            env,
        )
        assert mojo["version"] == prefix["mojo_version"]
        assert llc["version"] == prefix["llc_version"]
        assert os.path.isfile(prefix["mojo_marker"])
        assert os.path.isfile(prefix["llc_marker"])
        project = os.path.join(workdir, "project")
        os.makedirs(project)
        trust = {
            "origin": (
                "independently admitted compiler prefix %s "
                "(pins %s sha256 %s)"
                % (
                    independent["prefix"],
                    independent["path"],
                    independent["source_sha256"],
                )
            ),
            "pins": independent["path"],
            "pins_sha256": independent["source_sha256"],
            "prefix": independent["prefix"],
            "status": "admitted",
        }
        lockfile_path = _write_consumer_lockfile(
            project, mojo, llc, trust
        )
        with open(lockfile_path, encoding="utf-8") as handle:
            document = json.load(handle)
        assert document["status"] == "admitted"
        assert pins_path in document["trust"]["origin"]
        assert document["tools"]["mojo"]["exec_sha256"] == (
            independent["mojo"]["exec_sha256"]
        )
        assert "(independently admitted pins)" in document[
            "generated_by"
        ]
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_consumer_bootstrap_without_independent_pins():
    workdir = tempfile.mkdtemp(prefix="consumer-bootstrap-")
    saved = _save_consumer_env()
    try:
        assert _load_independent_pins() is None
        os.environ[CONSUMER_PREFIX_ENV] = os.path.join(workdir, "bin")
        assert _load_independent_pins() is None
        prefix = _make_host_prefix(workdir)
        project = os.path.join(workdir, "project")
        os.makedirs(project)
        mojo = {
            "exec_sha256": "5" * 64,
            "sha256": _sha256_file(prefix["mojo"]),
            "version": prefix["mojo_version"],
        }
        llc = {
            "exec_sha256": None,
            "sha256": _sha256_file(prefix["llc"]),
            "version": prefix["llc_version"],
        }
        lockfile_path = _write_consumer_lockfile(
            project, mojo, llc, _bootstrap_trust()
        )
        with open(lockfile_path, encoding="utf-8") as handle:
            document = json.load(handle)
        assert document["status"] == "bootstrap"
        assert "not an independent" in document["trust"]["origin"]
        assert "(PATH-resolved pins)" in document["generated_by"]
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_consumer_self_pin_is_not_a_trust_root():
    workdir = tempfile.mkdtemp(prefix="consumer-selfpin-")
    saved = _save_consumer_env()
    try:
        prefix = _make_host_prefix(workdir)
        project = os.path.join(workdir, "project")
        os.makedirs(project)
        mojo = {
            "exec_sha256": "5" * 64,
            "sha256": _sha256_file(prefix["mojo"]),
            "version": prefix["mojo_version"],
        }
        llc = {
            "exec_sha256": None,
            "sha256": _sha256_file(prefix["llc"]),
            "version": prefix["llc_version"],
        }
        self_pin = _write_consumer_lockfile(
            project, mojo, llc, _bootstrap_trust()
        )
        os.environ[CONSUMER_PREFIX_ENV] = prefix["bin"]
        os.environ[CONSUMER_PINS_ENV] = self_pin
        try:
            _load_independent_pins()
        except ConsumerAdmissionError as exc:
            assert "not an independent trust root" in str(exc), exc
        else:
            raise AssertionError("self-pin accepted as independent")
        broken = os.path.join(workdir, "broken.json")
        with open(broken, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        os.environ[CONSUMER_PINS_ENV] = broken
        try:
            _load_independent_pins()
        except ConsumerAdmissionError:
            pass
        else:
            raise AssertionError("malformed pins silently accepted")
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_consumer_lockfile_schema_for_build():
    workdir = tempfile.mkdtemp(prefix="consumer-schema-")
    saved = _save_consumer_env()
    try:
        prefix = _make_host_prefix(workdir)
        project = os.path.join(workdir, "project")
        os.makedirs(project)
        mojo = {
            "exec_sha256": "5" * 64,
            "sha256": _sha256_file(prefix["mojo"]),
            "version": prefix["mojo_version"],
        }
        llc = {
            "exec_sha256": None,
            "sha256": _sha256_file(prefix["llc"]),
            "version": prefix["llc_version"],
        }
        lockfile_path = _write_consumer_lockfile(
            project, mojo, llc, _bootstrap_trust()
        )
        with open(lockfile_path, "rb") as handle:
            raw = handle.read()
        assert REPO_ROOT.encode() not in raw
        document = json.loads(raw.decode("utf-8"))
        assert document["schema_version"] == 1
        assert set(document["tools"]) == {"llc", "mojo"}
        for name in ("llc", "mojo"):
            entry = document["tools"][name]
            assert isinstance(entry["version"], str), entry
            assert isinstance(entry["sha256"], str), entry
            assert "exec_sha256" in entry, entry
        assert document["tools"]["llc"]["exec_sha256"] is None
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    # Direct runs always execute everything, including the
    # toolchain/venv/guest tests that skip under pytest by default.
    os.environ[CONSUMER_FULL_ENV] = "1"
    failures = 0
    names = sorted(k for k in globals() if k.startswith("test_"))
    for name in names:
        try:
            globals()[name]()
        except EnvironmentFailure as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            return 2
        except ConsumerAdmissionError as exc:
            print("ADMISSION FAILURE in %s: %s" % (name, exc))
            return 1
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
        else:
            print("PASS %s" % name)
    if failures:
        return 1
    fix = fixture()
    run = guest_run()
    print("consumer: %s" % fix["mojo"]["path"])
    print(
        "consumer mojo: %s sha256 %s"
        % (fix["mojo"]["version"], fix["mojo"]["sha256"])
    )
    print(
        "consumer object: %s sha256 %s"
        % (CONSUMER_OBJECT, run["host_shas"]["tally.bpf.o"])
    )
    print(
        "consumer kernel: action %d, map %d -> %d -> %d"
        % (XDP_PASS, INIT_VALUE, AFTER_FIRST, AFTER_SECOND)
    )
    print("hash consumer: isolated build plus exact kernel result")
    return 0


if __name__ == "__main__":
    sys.exit(main())
