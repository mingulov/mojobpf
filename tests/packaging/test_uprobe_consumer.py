# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Third-party usability proof for the controlled uprobe shape.

Installs the release-candidate wheel into a fresh virtual
environment, copies ``tests/packaging/uprobe_consumer/`` (the
subscriber's own manifest plus its own ``subscriber.mojo``
uprobe source, which differs from every in-tree Mojo source, and
its own ``consumer_target.c`` probe-target executable, which
carries the subscriber's own probe sites) to an unrelated
working directory with the MojoBPF tree scrubbed from every
search path, resolves ``mojo`` from PATH only (an independently
installed Mojo 1.1.0, never the checkout's developer
environment), builds through the installed ``mojobpf`` command,
and requires the exact kernel result through the standard
loader/attach flow.

The subscriber counts probed calls carrying a watched argument:
entry 0 holds the watched value, entry 1 the tally. The guest
suite loads the consumer-built object, attaches it to the
subscriber's own executable, and requires 200/200 with every
oracle word equal to the watched value 97, 0/100 with every
oracle word equal to the other value 98, 0 on the never-watched
symbol, plus pin absence and residue checks.

The consumer pins its own toolchain: the suite writes a
``toolchains.lock.json`` beside the copied manifest from the
PATH-resolved tools, the way a real user pins theirs.

Requires an independent Mojo 1.1.0 plus ``llc`` and ``vng`` on
PATH outside the checkout, and ``cc`` plus ``readelf`` for
suite-side staging of the subscriber's own C sources. The guest
release comes from ``MOJOBPF_VNG_RELEASE`` (``v6.12`` by
default). Only the vng guest performs BPF loads and uprobe
attaches; the host never attaches to anything. The guest boots
as a session leader, so a timeout kills the whole owned guest
tree, never just the direct child.

Runnable directly
(``python3 tests/packaging/test_uprobe_consumer.py``) or under
any ``test_``-style runner. Standard library only.
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
    os.path.dirname(os.path.abspath(__file__)), "uprobe_consumer"
)
HOLDER_SOURCE = os.path.join(REPO_ROOT, "tests", "harness", "uprobe_attach.c")

CONSUMER_FILES = (
    "README.md", "mojobpf.toml", "subscriber.mojo",
    "consumer_target.c",
)
CONSUMER_LOCKFILE = "toolchains.lock.json"
CONSUMER_OBJECT = "subscriber_probe.bpf.o"
CONSUMER_SIDECAR = "subscriber_probe.evidence.json"
CONSUMER_SOURCE = "subscriber.mojo"
CONSUMER_TARGET_SOURCE = "consumer_target.c"
CONSUMER_PROFILE = "linux-bpfel-v3-uprobe"
BASE_PROFILE = "linux-bpfel-v3"

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

CONSUMER_N = 200
CONSUMER_M = 100
CONSUMER_WATCHED = 97
CONSUMER_OTHER = 98
# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = 900

_FIXTURE = {}
_GUEST = {}


class EnvironmentFailure(Exception):
    """The toolchain, builder, or VM needed by this test is missing."""


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


def _write_consumer_lockfile(project, mojo, llc):
    """Pin the consumer's own toolchain, as a real user would."""
    document = {
        "generated_by": "uprobe consumer (PATH-resolved pins)",
        "license": "Apache-2.0 WITH LLVM-exception",
        "schema_version": 1,
        "tools": {
            "llc": {
                "sha256": llc["sha256"],
                "version": llc["version"],
            },
            "mojo": {
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


def _compile(path, argv):
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EnvironmentFailure("cannot run cc: %s" % exc)
    if proc.returncode != 0 or proc.stderr != "":
        raise EnvironmentFailure(
            "suite-side C build failed for %s: exit=%d stderr=%r"
            % (path, proc.returncode, proc.stderr[-2000:])
        )


def _resolve_offsets(target_path):
    """Resolve probe file offsets from the consumer binary bytes.

    Suite-side staging (ambient readelf): both subscriber symbols
    must be global functions in .text of a non-PIE executable.
    """
    try:
        header = subprocess.run(
            ["readelf", "-h", "-W", target_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=120,
        )
        sections = subprocess.run(
            ["readelf", "-S", "-W", target_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=120,
        )
        symbols = subprocess.run(
            ["readelf", "-s", "-W", target_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EnvironmentFailure("cannot run readelf: %s" % exc)
    if header.returncode != 0 or "EXEC" not in header.stdout:
        raise EnvironmentFailure(
            "consumer target must be non-PIE (ET_EXEC)"
        )
    section_map = {}
    for line in sections.stdout.splitlines():
        match = re.match(
            r"\s*\[(\d+)\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)",
            line,
        )
        if match:
            section_map[int(match.group(1))] = (
                match.group(2),
                int(match.group(3), 16),
                int(match.group(4), 16),
            )
    offsets = {}
    for line in symbols.stdout.splitlines():
        match = re.match(
            r"\s*\d+:\s+([0-9a-f]+)\s+\d+\s+(\S+)\s+(\S+)\s+\S+\s+"
            r"(\d+)\s+(\S+)",
            line,
        )
        if not match:
            continue
        value, sym_type, bind, ndx, name = (
            int(match.group(1), 16),
            match.group(2),
            match.group(3),
            int(match.group(4)),
            match.group(5),
        )
        if name not in ("watched_call", "never_watched"):
            continue
        if sym_type != "FUNC" or bind != "GLOBAL":
            raise EnvironmentFailure(
                "consumer symbol %s must be a global function" % name
            )
        section_name, vma, file_off = section_map[ndx]
        if section_name != ".text":
            raise EnvironmentFailure(
                "consumer symbol %s must live in .text" % name
            )
        offsets[name] = "0x%x" % (value - vma + file_off)
    if set(offsets) != {"watched_call", "never_watched"}:
        raise EnvironmentFailure(
            "consumer probe symbols missing: %r" % (offsets,)
        )
    if offsets["watched_call"] == offsets["never_watched"]:
        raise EnvironmentFailure("consumer probe symbols must be distinct")
    return offsets


def fixture():
    """Install the wheel fresh, then run the isolated consumer build."""
    if "root" in _FIXTURE:
        return _FIXTURE
    for tool in ("mojo", "llc", "vng"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure(
                "%s not found on PATH" % tool
            )
    for tool in ("cc", "readelf"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure(
                "%s not found on PATH (suite-side staging)" % tool
            )
    for name in CONSUMER_FILES:
        if not os.path.isfile(os.path.join(CONSUMER_DIR, name)):
            raise EnvironmentFailure("missing consumer file: %s" % name)
    if not os.path.isfile(HOLDER_SOURCE):
        raise EnvironmentFailure("missing harness: %s" % HOLDER_SOURCE)
    root = tempfile.mkdtemp(prefix="mojobpf-consumer-")
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
    mojo = _probe_tool("mojo", env)
    llc = _probe_tool("llc", env)
    vng = _probe_tool("vng", env)
    lockfile_path = _write_consumer_lockfile(project, mojo, llc)
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
    # Suite-side staging of the subscriber's own C sources (ambient
    # cc/readelf): the consumer's binary carries the probe sites.
    staging = os.path.join(root, "staging")
    os.makedirs(staging)
    consumer_target = os.path.join(staging, "consumer_target")
    _compile(
        CONSUMER_TARGET_SOURCE,
        [
            "cc", "-no-pie", "-fno-pie", "-O2", "-Wall", "-Wextra",
            "-o", consumer_target,
            os.path.join(project, CONSUMER_TARGET_SOURCE),
        ],
    )
    holder = os.path.join(staging, "uprobe_attach")
    _compile(
        HOLDER_SOURCE,
        ["cc", "-O2", "-Wall", "-Wextra", "-o", holder, HOLDER_SOURCE],
    )
    offsets = _resolve_offsets(consumer_target)
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
            "build": proc,
            "consumer_target": consumer_target,
            "holder": holder,
            "offsets": offsets,
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
    assert doc["artifact"] == "subscriber_probe", doc


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
    source = os.path.join(fix["project"], CONSUMER_SOURCE)
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
    subscriber_sha = _sha256_file(
        os.path.join(fix["project"], CONSUMER_SOURCE)
    )
    own_source = os.path.join(CONSUMER_DIR, CONSUMER_SOURCE)
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
            assert _sha256_file(other) != subscriber_sha, (
                "consumer source copies %s" % other
            )
    assert compared > 0, "no in-tree Mojo sources compared"
    print(
        "PASS no-copy corpus: subscriber differs from %d sources" % compared
    )


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
        CONSUMER_SOURCE: _sha256_file(
            os.path.join(fix["project"], CONSUMER_SOURCE)
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
            "--profile", CONSUMER_PROFILE,
            "--source-license", "Apache-2.0 WITH LLVM-exception",
            "--kernel-license", "Apache-2.0 WITH LLVM-exception",
        ],
        fix["project"],
        fix["env"],
        120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ok" in proc.stdout
    proc = _run(
        [
            fix["venv_mojobpf"],
            "inspect",
            "--object", obj,
            "--profile", BASE_PROFILE,
            "--source-license", "Apache-2.0 WITH LLVM-exception",
            "--kernel-license", "Apache-2.0 WITH LLVM-exception",
        ],
        fix["project"],
        fix["env"],
        120,
    )
    assert proc.returncode != 0, proc.stdout
    assert "MBPF406" in proc.stdout, proc.stdout


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


GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
WATCHED_OFFSET="{watched_offset}"
NEVER_OFFSET="{never_offset}"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin guest_subscriber ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
bpftool version | head -2
echo "=== staged hashes ==="
sha256sum subscriber.bpf.o consumer_target uprobe_attach
map_u64() {{
  bpftool map lookup pinned "$1" key "$2" 0 0 0 | python3 -c "import sys; print(int.from_bytes(bytes(int(tok, 16) for tok in sys.stdin.read().split('value:')[1].splitlines()[0].split()), 'little'))"
}}
u64_bytes() {{
  python3 -c "print(' '.join('%d' % b for b in ($1).to_bytes(8, 'little')))"
}}
map_set_u64() {{
  bpftool map update pinned "$1" key "$2" 0 0 0 value $(u64_bytes "$3")
}}
bpftool feature probe kernel >feature.txt 2>&1
grep -q "eBPF program_type kprobe is available" feature.txt || {{ echo "KPROBE-MISSING"; exit 3; }}
[ -w /sys/kernel/tracing/uprobe_events ] || {{ echo "UPROBE-IFACE-MISSING"; exit 3; }}
PINS_BEFORE=$(ls /sys/fs/bpf/)
LINKS_BEFORE=$(bpftool link show)
PROGS_BEFORE=$(bpftool prog show)
MAPS_BEFORE=$(bpftool map show)
EVENTS_BEFORE=$(cat /sys/kernel/tracing/uprobe_events)
run_phase() {{
  LABEL="$1"; OFFSET="$2"; FILTER="$3"; CALLS="$4"; VALUE="$5"
  PIN="/sys/fs/bpf/mojobpf_sub_$LABEL"
  MAP_DIR="$PIN-maps"
  mkdir -p "$MAP_DIR" || {{ echo "$LABEL-MAPDIR-FAILED"; exit 1; }}
  bpftool prog load subscriber.bpf.o "$PIN" type kprobe pinmaps "$MAP_DIR/" >"/tmp/csub-$LABEL.load" 2>&1
  [ $? = 0 ] || {{ echo "$LABEL-LOAD-FAILED"; cat "/tmp/csub-$LABEL.load"; exit 1; }}
  MAP_PIN="$MAP_DIR/mojobpf_map0"
  [ -e "$MAP_PIN" ] || {{ echo "$LABEL-MAP-PIN-MISSING"; exit 1; }}
  rm -f "$LABEL-rel" "$LABEL-ora"
  mkfifo "$LABEL-rel" "$LABEL-ora"
  ./uprobe_attach "$PIN" "{stage}" "{stage}/consumer_target" "$OFFSET" "csub_$LABEL" <"$LABEL-rel" >"/tmp/csub-$LABEL.holder.log" 2>&1 &
  HOLDER_PID=$!
  exec 8<>"$LABEL-rel"
  for _ in $(seq 1 600); do
    grep -q "^ATTACHED " "/tmp/csub-$LABEL.holder.log" 2>/dev/null && break
    kill -0 "$HOLDER_PID" 2>/dev/null || break
    sleep 0.1
  done
  grep -q "^ATTACHED " "/tmp/csub-$LABEL.holder.log" || {{ echo "$LABEL-ATTACH-TIMEOUT"; cat "/tmp/csub-$LABEL.holder.log"; exit 1; }}
  map_set_u64 "$MAP_PIN" 0 "$FILTER" || {{ echo "$LABEL-FILTER-INIT-FAILED"; exit 1; }}
  map_set_u64 "$MAP_PIN" 1 0 || {{ echo "$LABEL-COUNT-INIT-FAILED"; exit 1; }}
  FILTER_READ=$(map_u64 "$MAP_PIN" 0)
  echo "=== BEGIN $LABEL ==="
  echo "filter: want=$FILTER readback=$FILTER_READ"
  timeout 300 python3 - "$LABEL" "$CALLS" "$VALUE" <<'PYEOF' || {{ echo "$LABEL-ORACLE-FAILED"; exit 1; }}
import struct, subprocess, sys
label, calls, value = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
proc = subprocess.Popen(['./consumer_target', str(calls), str(value), label + '-ora'],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
with open(label + '-ora', 'rb') as reader:
    data = reader.read()
out, err = proc.communicate()
print('%s-target-exit: %d' % (label, proc.returncode))
print('%s-target-out: %s %s' % (label, out.strip(), err.strip()))
if proc.returncode != 0:
    sys.exit(1)
words = struct.unpack('<%dQ' % (len(data) // 8), data) if data else ()
print('%s-oracle: n=%d distinct=%s' % (label, len(words), sorted(set(words))))
PYEOF
  echo "$LABEL-counter: $(map_u64 "$MAP_PIN" 1)"
  exec 8>&-
  wait "$HOLDER_PID"
  echo "$LABEL-detach-exit: $?"
  rm -f "$PIN" "$MAP_PIN"
  rmdir "$MAP_DIR" || {{ echo "$LABEL-MAPDIR-NOT-EMPTY"; exit 1; }}
  rm -f "$LABEL-rel" "$LABEL-ora"
  echo "=== END $LABEL ==="
}}
run_phase match "$WATCHED_OFFSET" {watched} {calls_n} {watched}
run_phase mismatch "$WATCHED_OFFSET" {watched} {calls_m} {other}
run_phase never "$NEVER_OFFSET" {watched} {calls_n} {watched}
echo "=== BEGIN residue ==="
echo "--- prog ---"
bpftool prog show
echo "--- map ---"
bpftool map show
echo "--- link ---"
bpftool link show
echo "--- events ---"
cat /sys/kernel/tracing/uprobe_events
echo "=== END residue ==="
echo "=== pin check ==="
stray=0
for pin in /sys/fs/bpf/mojobpf_sub_*; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; stray=1; fi
done
if [ "$stray" -eq 0 ]; then echo "pin absent (unloaded)"; fi
echo "=== end guest_subscriber ==="
"""

CASES = ("match", "mismatch", "never", "residue")


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
    if "run" in _GUEST:
        return _GUEST["run"]
    fix = fixture()
    assert fix["build"].returncode == 0, "consumer build must pass first"
    vng_path = fix["vng"]["path"]
    stage = tempfile.mkdtemp(prefix="consumer-subscriber-", dir="/tmp")
    staged = {
        "subscriber.bpf.o": os.path.join(fix["out_dir"], CONSUMER_OBJECT),
        "consumer_target": fix["consumer_target"],
        "uprobe_attach": fix["holder"],
    }
    for name, src in staged.items():
        with open(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    host_shas = {
        name: _sha256_file(os.path.join(stage, name))
        for name in staged
    }
    script = GUEST_SCRIPT.format(
        stage=stage,
        watched_offset=fix["offsets"]["watched_call"],
        never_offset=fix["offsets"]["never_watched"],
        watched=CONSUMER_WATCHED,
        other=CONSUMER_OTHER,
        calls_n=CONSUMER_N,
        calls_m=CONSUMER_M,
    )
    script_path = os.path.join(stage, "guest_subscriber.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["guest_subscriber.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(os.path.join(stage, "consumer_target"), 0o755)
    os.chmod(os.path.join(stage, "uprobe_attach"), 0o755)
    os.chmod(stage, 0o755)
    exit_code, output = _run_guest(
        [vng_path, "--run", VNG_RELEASE, "--disable-kvm",
         "--exec", "bash %s" % script_path],
        stage,
        VNG_TIMEOUT,
    )
    if "KPROBE-MISSING" in output or "UPROBE-IFACE-MISSING" in output:
        raise EnvironmentFailure(
            "guest lacks the kprobe program type or the tracefs "
            "uprobe interface (stage kept at %s)" % stage
        )
    if exit_code != 0:
        raise EnvironmentFailure(
            "vng guest run failed (exit %d, stage kept at %s):\n%s"
            % (exit_code, stage, output[-4000:])
        )
    transcript_path = os.path.join(stage, "guest_transcript.log")
    with open(transcript_path, "w", encoding="utf-8") as handle:
        handle.write(output)
    print("guest transcript: %s" % transcript_path)
    results = {}
    for match in re.finditer(
        r"=== BEGIN (\S+)(?: exit=(\d+))? ===\n(.*?)\n=== END \1 ===",
        output,
        re.DOTALL,
    ):
        tag, exit_text, body = match.groups()
        results[tag] = {
            "exit": int(exit_text) if exit_text is not None else None,
            "body": body,
        }
    missing = [tag for tag in CASES if tag not in results]
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


def parse_board(body, label):
    """Parse one phase board into its fields."""
    fields = {}
    for line in body.splitlines():
        if line.startswith(label + "-") or line.startswith("filter:"):
            key, _, value = line.partition(": ")
            fields[key.strip()] = value.strip()
    for key in (
        "%s-target-exit" % label,
        "%s-target-out" % label,
        "%s-oracle" % label,
        "%s-counter" % label,
        "%s-detach-exit" % label,
        "filter",
    ):
        assert key in fields, "%s board lacks %s:\n%s" % (label, key, body)
    return fields


def check_board(label, calls, value, want_counter):
    run = guest_run()
    fields = parse_board(run["results"][label]["body"], label)
    assert fields["%s-target-exit" % label] == "0", fields
    assert fields["%s-target-out" % label].startswith(
        "done calls=%d value=%d" % (calls, value)
    ), fields
    assert fields["%s-oracle" % label] == "n=%d distinct=[%d]" % (
        calls, value,
    ), fields
    assert fields["filter"] == "want=%d readback=%d" % (
        CONSUMER_WATCHED, CONSUMER_WATCHED,
    ), fields
    assert fields["%s-counter" % label] == str(want_counter), fields
    assert fields["%s-detach-exit" % label] == "0", fields


def test_consumer_exact_kernel_result():
    check_board("match", CONSUMER_N, CONSUMER_WATCHED, CONSUMER_N)
    check_board("mismatch", CONSUMER_M, CONSUMER_OTHER, 0)
    check_board("never", CONSUMER_N, CONSUMER_WATCHED, 0)
    print(
        "consumer kernel: match/mismatch/never = %d/0/0 "
        "with oracle agreement" % CONSUMER_N
    )


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
    residue = run["results"]["residue"]["body"]
    for name in ("uprobe_entry", "mojobpf", "mojobpf_sub_", "csub_"):
        assert name not in residue, (
            "residue still names %r:\n%s" % (name, residue)
        )


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    names = sorted(k for k in globals() if k.startswith("test_"))
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
    if failures:
        return 1
    fix = fixture()
    obj = os.path.join(fix["out_dir"], CONSUMER_OBJECT)
    print("consumer: %s" % fix["mojo"]["path"])
    print(
        "consumer mojo: %s sha256 %s"
        % (fix["mojo"]["version"], fix["mojo"]["sha256"])
    )
    print(
        "consumer object: %s sha256 %s" % (CONSUMER_OBJECT, _sha256_file(obj))
    )
    print(
        "consumer kernel: match/mismatch/never = %d/0/0"
        % CONSUMER_N
    )
    print("uprobe consumer: isolated build plus exact kernel result")
    return 0


if __name__ == "__main__":
    sys.exit(main())
