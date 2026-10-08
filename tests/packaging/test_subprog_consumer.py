# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Third-party usability proof for the subprogram call shape.

Installs the release-candidate wheel into a fresh virtual
environment, copies ``tests/packaging/subprog_consumer/`` (the
subscriber's own manifest plus its own ``subscriber.mojo`` XDP
decision source, which differs from every in-tree Mojo source)
to an unrelated working directory with the MojoBPF tree scrubbed
from every search path, resolves ``mojo`` from PATH only (an
independently installed Mojo 1.1.0, never the checkout's
developer environment), builds through the installed ``mojobpf``
command, and requires the exact kernel result through the
standard loader/test runner.

The subscriber classifies frames through one static subprogram
call: the ``select_action`` callee drops (returns 1) when bit 1
of byte 14 is set and passes (returns 2) otherwise, with short
frames taking the pass path. The guest suite loads the
consumer-built object and requires 1/2/2/2 on the
drop/pass/zero/short frames through the frozen
``bpf_test_run`` harness, plus an exact direct-loader board,
pin absence, and residue checks.

The consumer pins its own toolchain: the suite writes a
``toolchains.lock.json`` beside the copied manifest from the
PATH-resolved tools, the way a real user pins theirs.

Requires an independent Mojo 1.1.0 plus ``llc`` and ``vng`` on
PATH outside the checkout. The guest release comes from
``MOJOBPF_VNG_RELEASE`` (``v6.12`` by default). Only the vng
guest performs BPF loads. The guest boots as a session leader,
so a timeout kills the whole owned guest tree, never just the
direct child.

Runnable directly
(``python3 tests/packaging/test_subprog_consumer.py``) or under
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
    os.path.dirname(os.path.abspath(__file__)), "subprog_consumer"
)
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")

CONSUMER_FILES = ("README.md", "mojobpf.toml", "subscriber.mojo")
CONSUMER_LOCKFILE = "toolchains.lock.json"
CONSUMER_OBJECT = "subscriber_decision.bpf.o"
CONSUMER_SIDECAR = "subscriber_decision.evidence.json"
CONSUMER_SOURCE = "subscriber.mojo"
CONSUMER_PROFILE = "linux-bpfel-v3-subprog"
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

XDP_DROP = 1
XDP_PASS = 2
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
        "generated_by": "subprogram consumer (PATH-resolved pins)",
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


def fixture():
    """Install the wheel fresh, then run the isolated consumer build."""
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
    assert doc["artifact"] == "subscriber_decision", doc


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
    assert "MBPF407" in proc.stdout, proc.stdout


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
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin guest_subscriber ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
bpftool version | head -2
echo "=== staged hashes ==="
sha256sum bpf_test_run.py subscriber.bpf.o frame_drop.bin frame_pass.bin frame_zero.bin frame_short.bin
harness_case() {{
  tag="$1"; obj="$2"; expect="$3"; data="$4"
  out="/tmp/sub-$tag.json"
  python3 bpf_test_run.py --object "$obj" --expect-action "$expect" \\
    --data-in "$data" --output "$out" >/tmp/sub-$tag.stdout 2>/tmp/sub-$tag.stderr
  code=$?
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
direct_case() {{
  tag="$1"; obj="$2"
  pin="/sys/fs/bpf/mojobpf_sub_$tag"
  out="/tmp/sub-$tag.fields"
  : > "$out"
  bpftool prog load "$obj" "$pin" type xdp >/tmp/sub-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  for frame in drop pass zero short; do
    bpftool prog run pinned "$pin" data_in frame_$frame.bin repeat 1 > /tmp/sub-$tag.run-$frame 2>&1
    echo "run_${{frame}}_exit=$?" >> "$out"
  done
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
  echo "=== BEGIN $tag ==="
  cat "$out"
  for frame in drop pass zero short; do
    echo "--- $tag run-$frame ---"
    cat /tmp/sub-$tag.run-$frame
  done
  echo "=== END $tag ==="
}}
residue_case() {{
  bpftool prog show >/tmp/sub-residue.prog 2>&1
  bpftool map show >/tmp/sub-residue.map 2>&1
  echo "=== BEGIN residue ==="
  echo "--- prog ---"
  cat /tmp/sub-residue.prog
  echo "--- map ---"
  cat /tmp/sub-residue.map
  echo "=== END residue ==="
}}
{commands}
echo "=== pin check ==="
stray=0
for pin in /sys/fs/bpf/mojobpf_sub_* /sys/fs/bpf/mojobpf_control; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; stray=1; fi
done
if [ "$stray" -eq 0 ]; then echo "pin absent (unloaded)"; fi
echo "=== end guest_subscriber ==="
"""

CASES = (
    ("sub-drop", "subscriber.bpf.o", "harness", "frame_drop.bin", 1),
    ("sub-pass", "subscriber.bpf.o", "harness", "frame_pass.bin", 2),
    ("sub-zero", "subscriber.bpf.o", "harness", "frame_zero.bin", 2),
    ("sub-short", "subscriber.bpf.o", "harness", "frame_short.bin", 2),
    ("sub-direct", "subscriber.bpf.o", "direct", "", 0),
    ("residue", "", "residue", "", 0),
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


def _frame(byte14, size=60):
    frame = bytearray(bytes(size))
    if size > 14:
        frame[14] = byte14
    return bytes(frame)


def guest_run():
    """Stage the consumer object, boot one guest, return case results."""
    if "run" in _GUEST:
        return _GUEST["run"]
    fix = fixture()
    assert fix["build"].returncode == 0, "consumer build must pass first"
    # The guest boots with the same scrubbed-PATH vng binary the
    # fixture probed and recorded, never an ambient re-resolution.
    vng_path = fix["vng"]["path"]
    stage = tempfile.mkdtemp(prefix="consumer-subscriber-", dir="/tmp")
    frames = {
        "frame_drop.bin": _frame(0x02),
        "frame_pass.bin": _frame(0x01),
        "frame_zero.bin": _frame(0x00),
        "frame_short.bin": bytes(10),
    }
    for name, data in frames.items():
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    staged = {
        "bpf_test_run.py": HARNESS,
        "subscriber.bpf.o": os.path.join(fix["out_dir"], CONSUMER_OBJECT),
    }
    for name, src in staged.items():
        with open(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    host_shas = {
        name: _sha256_file(os.path.join(stage, name))
        for name in list(staged) + sorted(frames)
    }
    commands = []
    for tag, obj, kind, data, expect in CASES:
        if kind == "harness":
            commands.append(
                "harness_case %s %s %d %s" % (tag, obj, expect, data)
            )
        elif kind == "direct":
            commands.append("direct_case %s %s" % (tag, obj))
        else:
            commands.append("residue_case")
    script = GUEST_SCRIPT.format(
        stage=stage,
        commands="\n".join(commands),
    )
    script_path = os.path.join(stage, "guest_subscriber.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + sorted(frames) + ["guest_subscriber.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    exit_code, output = _run_guest(
        [vng_path, "--run", VNG_RELEASE, "--disable-kvm",
         "--exec", "bash %s" % script_path],
        stage,
        VNG_TIMEOUT,
    )
    if exit_code != 0:
        raise EnvironmentFailure(
            "vng guest run failed (exit %d, stage kept at %s):\n%s"
            % (exit_code, stage, output[-4000:])
        )
    # Retain the raw guest transcript alongside the staged inputs
    # so observed results stay auditable after the run; the stage
    # directory is never cleaned by the suite itself.
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
        tag, exit_code, body = match.groups()
        results[tag] = {
            "exit": int(exit_code) if exit_code is not None else None,
            "body": body,
        }
    missing = [tag for tag, _, _, _, _ in CASES if tag not in results]
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


def parse_run_action(body, marker):
    section = body.split(marker, 1)[1]
    match = re.search(r"Return value:\s*(\d+)", section)
    assert match, "no bpftool return-value line after %r" % marker
    return int(match.group(1))


def test_consumer_exact_kernel_result():
    run = guest_run()
    body = run["results"]["sub-direct"]["body"]
    fields = parse_fields(body)
    for key in (
        "load_exit",
        "run_drop_exit",
        "run_pass_exit",
        "run_zero_exit",
        "run_short_exit",
    ):
        assert fields.get(key) == "0", "%s=%r" % (key, fields.get(key))
    assert fields.get("unload_ok") == "1", "pin was not removed"
    assert parse_run_action(body, "run-drop ---") == XDP_DROP
    assert parse_run_action(body, "run-pass ---") == XDP_PASS
    assert parse_run_action(body, "run-zero ---") == XDP_PASS
    assert parse_run_action(body, "run-short ---") == XDP_PASS


def test_consumer_standard_runner_passes():
    run = guest_run()
    for tag, expect in (
        ("sub-drop", XDP_DROP),
        ("sub-pass", XDP_PASS),
        ("sub-zero", XDP_PASS),
        ("sub-short", XDP_PASS),
    ):
        record = run["results"][tag]
        assert record["exit"] == 0, (
            "%s: standard runner must exit 0, got %r" % (tag, record["exit"])
        )
        try:
            doc = json.loads(record["body"])
        except ValueError:
            raise AssertionError(
                "%s: harness did not emit JSON:\n%s"
                % (tag, record["body"][-500:])
            )
        assert doc.get("contract_version") == 2, (tag, doc)
        assert doc.get("status") == "pass", (tag, doc)
        assert doc.get("stage") == "run", (tag, doc)
        assert doc.get("classification") is None, (tag, doc)
        assert doc.get("expected_action") == expect, (tag, doc)
        assert doc.get("actual_action") == expect, (tag, doc)
        assert doc.get("cleanup_ok") is True, (tag, doc)
        assert doc.get("object", {}).get("sha256") == run["host_shas"][
            "subscriber.bpf.o"
        ], (tag, doc)


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
    for name in ("select_action", "xdp_entry", "mojobpf"):
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
    run = guest_run()
    print("consumer: %s" % fix["mojo"]["path"])
    print(
        "consumer mojo: %s sha256 %s"
        % (fix["mojo"]["version"], fix["mojo"]["sha256"])
    )
    print(
        "consumer object: %s sha256 %s"
        % (CONSUMER_OBJECT, run["host_shas"]["subscriber.bpf.o"])
    )
    print("consumer kernel: actions drop/pass/zero/short = 1/2/2/2")
    print("subprogram consumer: isolated build plus exact kernel result")
    return 0


if __name__ == "__main__":
    sys.exit(main())
