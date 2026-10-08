# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Third-party usability proof for the ring-reservation SDK slice.

An external consumer (``tests/packaging/reserve_consumer/``) builds its
own tracepoint reservation emitter through the INSTALLED ``mojobpf``
package only: a fresh wheel built from this tree is installed into a
fresh virtualenv, the consumer project is copied to an unrelated work
directory, and the product tree is scrubbed from every search path.
``mojo``/``llc``/``vng`` resolve PATH-only from an independently
installed Mojo (never the checkout's toolchain), with versions and
hashes recorded. The installed build must emit the object plus a
schema-v4 evidence sidecar sealing the consumer's own sources; the
consumer source must import only the SDK surface and must differ
from every in-tree Mojo source; the build must fail without the
installed package.

The consumer-built object then boots one disposable Linux guest and
must produce exact kernel results: with the filter holding the
monitored TID, N=500 monitored getpids yield attempted=successful=500,
failed=0, and 500 drained records with contiguous sequences 0..499
carrying the monitored identity; no owned pin, link, program, or map
survives.

Requires an independently installed Mojo 1.1.0 plus ``cc``, ``llc``
and ``vng`` on PATH (default release v6.12; MOJOBPF_VNG_RELEASE selects
the matrix lane). Missing tools fail loudly as environment failures,
never as passes.

Runnable directly (``python3 tests/packaging/test_reserve_consumer.py``)
or under any ``test_``-style runner. Standard library only. The
guest boot takes a few minutes under software emulation. The guest
command runs as a session leader and a timeout kills the whole owned
guest tree (the runner group plus any detached emulator groups it
booted), never just the direct child.
"""

import atexit
import hashlib
import json
import os
import re
import shutil
import struct
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
    os.path.dirname(os.path.abspath(__file__)), "reserve_consumer"
)
WORKLOAD_SOURCE = os.path.join(
    REPO_ROOT, "tests", "harness", "syscall_workload.c"
)
HOLDER_SOURCE = os.path.join(
    REPO_ROOT, "tests", "harness", "tracepoint_attach.c"
)
DRAIN_SOURCE = os.path.join(
    REPO_ROOT, "tests", "harness", "ringbuf_drain.c"
)

CONSUMER_FILES = ("README.md", "mojobpf.toml", "emitter.mojo")
CONSUMER_LOCKFILE = "toolchains.lock.json"
CONSUMER_OBJECT = "reserve_emitter.bpf.o"
CONSUMER_SIDECAR = "reserve_emitter.evidence.json"

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

# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = 900
CONSUMER_N = 500
CONSUMER_M = 500

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
        "generated_by": "reserve consumer (PATH-resolved pins)",
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


def _build_harness_tool(source, output):
    proc = _run(
        ["cc", "-O2", source, "-o", output]
        + (["-pthread"] if "workload" in source else []),
        REPO_ROOT,
        dict(os.environ),
        300,
    )
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "harness build failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    return output


def fixture():
    """Install the wheel fresh, then run the isolated consumer build."""
    if "root" in _FIXTURE:
        return _FIXTURE
    for tool in ("mojo", "llc", "vng", "cc"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure(
                "%s not found on PATH" % tool
            )
    for name in CONSUMER_FILES:
        if not os.path.isfile(os.path.join(CONSUMER_DIR, name)):
            raise EnvironmentFailure("missing consumer file: %s" % name)
    for path in (WORKLOAD_SOURCE, HOLDER_SOURCE, DRAIN_SOURCE):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing harness: %s" % path)
    root = tempfile.mkdtemp(prefix="mojobpf-reserve-consumer-")
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
    object_path = os.path.join(out_dir, CONSUMER_OBJECT)
    object_sha = (
        _sha256_file(object_path) if proc.returncode == 0 else None
    )
    if object_sha is not None:
        print("consumer reserve object sha256: %s" % object_sha)
    tools_dir = os.path.join(work, "tools")
    os.makedirs(tools_dir)
    workload = _build_harness_tool(
        WORKLOAD_SOURCE, os.path.join(tools_dir, "syscall_workload")
    )
    holder = _build_harness_tool(
        HOLDER_SOURCE, os.path.join(tools_dir, "tracepoint_attach")
    )
    drain = _build_harness_tool(
        DRAIN_SOURCE, os.path.join(tools_dir, "ringbuf_drain")
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
            "object_sha": object_sha,
            "workload": workload,
            "holder": holder,
            "drain": drain,
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
    assert doc["artifact"] == "reserve_emitter", doc
    assert doc["profile_id"] == "linux-bpfel-v3-reserve", doc


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
    source = os.path.join(fix["project"], "emitter.mojo")
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
    emitter_sha = _sha256_file(
        os.path.join(fix["project"], "emitter.mojo")
    )
    own_source = os.path.join(CONSUMER_DIR, "emitter.mojo")
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
            assert _sha256_file(other) != emitter_sha, (
                "consumer source copies %s" % other
            )
    assert compared > 0, "no in-tree Mojo sources compared"
    print("PASS no-copy corpus: emitter differs from %d sources" % compared)


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
        "emitter.mojo": _sha256_file(
            os.path.join(fix["project"], "emitter.mojo")
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
            "--profile", "linux-bpfel-v3-reserve",
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


GUEST_SCRIPT = r"""#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
STAGE="__STAGE__"
cd "$STAGE"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin reserve-consumer ==="
echo "guest-kernel: $(uname -r)"
echo "ncpu: $(nproc)"
echo "--- staged hashes ---"
sha256sum consumer.bpf.o syscall_workload tracepoint_attach ringbuf_drain
echo "__OBJECT_HASH__  consumer.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH consumer"; exit 1; }
echo "staged bytes: qualified"
echo "--- pins before ---"
PINS_BEFORE=$(ls /sys/fs/bpf/)
LINKS_BEFORE=$(bpftool link show)
PROGS_BEFORE=$(bpftool prog show)
MAPS_BEFORE=$(bpftool map show)
echo "$PINS_BEFORE"
echo "$LINKS_BEFORE"
echo "--- namespace self-check ---"
SELF_NS=$(readlink /proc/self/ns/pid)
INIT_NS=$(readlink /proc/1/ns/pid)
echo "self-ns: $SELF_NS"
echo "init-ns: $INIT_NS"
[ "$SELF_NS" = "$INIT_NS" ] || { echo "NAMESPACE-MISMATCH"; exit 1; }
echo "namespace: initial"

map_u64() {
  bpftool map lookup pinned "$1" key "$2" 0 0 0 | python3 -c "import sys; print(int.from_bytes(bytes(int(tok, 16) for tok in sys.stdin.read().split('value:')[1].splitlines()[0].split()), 'little'))"
}

u64_bytes() {
  python3 -c "print(' '.join('%d' % b for b in ($1).to_bytes(8, 'little')))"
}

map_set_u64() {
  bpftool map update pinned "$1" key "$2" 0 0 0 value $(u64_bytes "$3")
}

echo "--- consumer run ---"
MAP_DIR=/sys/fs/bpf/consumer-maps
mkdir -p "$MAP_DIR" || { echo "MAPDIR-FAILED"; exit 1; }
bpftool prog load consumer.bpf.o /sys/fs/bpf/consumer type tracepoint pinmaps "$MAP_DIR/" >/tmp/consumer.load 2>&1
[ $? = 0 ] || { echo "CONSUMER-LOAD-FAILED"; cat /tmp/consumer.load; exit 1; }
MAP_PIN="$MAP_DIR/mojobpf_map0"
RING_PIN="$MAP_DIR/mojobpf_map1"
[ -e "$MAP_PIN" ] || { echo "MAP-PIN-MISSING"; ls -la obj-maps; exit 1; }
[ -e "$RING_PIN" ] || { echo "RING-PIN-MISSING"; ls -la obj-maps; exit 1; }
rm -f run-rel run-go run-done run-tids
mkfifo run-rel run-go run-done
./tracepoint_attach /sys/fs/bpf/consumer syscalls sys_enter_getpid <run-rel >/tmp/consumer.holder.log 2>&1 &
HOLDER_PID=$!
exec 8<>run-rel
./syscall_workload --monitored __N__ --excluded __M__ --phase full --tid-file run-tids --go-fifo run-go --done-fifo run-done >/tmp/consumer.wl.log 2>&1 &
WL_PID=$!
for _ in $(seq 1 600); do
  grep -q "^ATTACHED " /tmp/consumer.holder.log 2>/dev/null && [ -f run-tids ] && [ "$(wc -l < run-tids)" = "4" ] && break
  kill -0 "$HOLDER_PID" 2>/dev/null || break
  kill -0 "$WL_PID" 2>/dev/null || break
  sleep 0.1
done
grep -q "^ATTACHED " /tmp/consumer.holder.log || { echo "ATTACH-TIMEOUT"; cat /tmp/consumer.holder.log; exit 1; }
[ -f run-tids ] && [ "$(wc -l < run-tids)" = "4" ] || { echo "TID-TIMEOUT"; cat run-tids 2>/dev/null; cat /tmp/consumer.wl.log; exit 1; }
MON_TID=$(awk '$1=="monitored"{print $2}' run-tids)
OBS_TID=$(awk '$1=="observer"{print $2}' run-tids)
echo "run-tids: $(tr '\n' ';' < run-tids)"
[ "$MON_TID" != "$OBS_TID" ] || { echo "OBSERVER-NOT-OUTSIDE"; exit 1; }
map_set_u64 "$MAP_PIN" 0 "$MON_TID" || { echo "FILTER-INIT-FAILED"; exit 1; }
map_set_u64 "$MAP_PIN" 1 0 || { echo "SEQ-INIT-FAILED"; exit 1; }
map_set_u64 "$MAP_PIN" 2 0 || { echo "SUCC-INIT-FAILED"; exit 1; }
map_set_u64 "$MAP_PIN" 3 0 || { echo "FAIL-INIT-FAILED"; exit 1; }
FILTER_READ=$(map_u64 "$MAP_PIN" 0)
echo "run-filter: want=$MON_TID readback=$FILTER_READ"
[ "$FILTER_READ" = "$MON_TID" ] || { echo "FILTER-READBACK-MISMATCH"; exit 1; }
timeout 60 bash -c "echo go > run-go" || { echo "GO-TIMEOUT"; exit 1; }
DONE_LINE=$(timeout 120 cat run-done) || { echo "DONE-TIMEOUT"; exit 1; }
echo "run-done: $DONE_LINE"
wait "$WL_PID"
[ $? = 0 ] || { echo "WORKLOAD-FAILED"; cat /tmp/consumer.wl.log; exit 1; }
ATTEMPTED=$(map_u64 "$MAP_PIN" 1)
SUCCESSFUL=$(map_u64 "$MAP_PIN" 2)
FAILED=$(map_u64 "$MAP_PIN" 3)
echo "run-counters: attempted=$ATTEMPTED successful=$SUCCESSFUL failed=$FAILED"
DRAIN_OUT=$(./ringbuf_drain --map "$RING_PIN" --out run.frames) || { echo "DRAIN-FAILED"; exit 1; }
DRAINED_N=$(echo "$DRAIN_OUT" | awk '/^DRAINED /{print $2}')
DISCARDED_N=$(echo "$DRAIN_OUT" | awk '/^DISCARDED /{print $2}')
RING_LINE=$(echo "$DRAIN_OUT" | awk '/^RING /{print $2" "$3" "$4}')
[ -n "$DRAINED_N" ] && [ -n "$DISCARDED_N" ] && [ -n "$RING_LINE" ] || { echo "DRAIN-PARSE-FAILED: $DRAIN_OUT"; exit 1; }
echo "run-drained: $DRAINED_N"
echo "run-discarded: $DISCARDED_N"
echo "run-ring: $RING_LINE"
python3 -c "
import hashlib
blob = open('run.frames', 'rb').read()
assert len(blob) % 36 == 0, len(blob)
for i in range(0, len(blob), 36):
    print('run-frame: %s' % blob[i:i + 36].hex())
print('run-sha256: %s' % hashlib.sha256(blob).hexdigest())
" || { echo "PUBLISH-FAILED"; exit 1; }
exec 8>&-
wait "$HOLDER_PID"
[ $? = 0 ] || { echo "DETACH-FAILED"; exit 1; }
grep -q "^DETACHED$" /tmp/consumer.holder.log || { echo "DETACH-MARKER-MISSING"; exit 1; }
rm -f /sys/fs/bpf/consumer "$MAP_PIN" "$RING_PIN"
rmdir "$MAP_DIR" || { echo "MAPDIR-NOT-EMPTY"; ls -la "$MAP_DIR"; exit 1; }
rm -f run-rel run-go run-done run-tids

echo "--- stray check ---"
for _ in $(seq 1 600); do
  PINS_AFTER=$(ls /sys/fs/bpf/)
  LINKS_AFTER=$(bpftool link show)
  PROGS_AFTER=$(bpftool prog show)
  MAPS_AFTER=$(bpftool map show)
  [ "$PINS_AFTER" = "$PINS_BEFORE" ] && [ "$LINKS_AFTER" = "$LINKS_BEFORE" ] && [ "$PROGS_AFTER" = "$PROGS_BEFORE" ] && [ "$MAPS_AFTER" = "$MAPS_BEFORE" ] && break
  sleep 0.1
done
echo "$PINS_AFTER"
echo "$LINKS_AFTER"
[ "$PINS_AFTER" = "$PINS_BEFORE" ] || { echo "STRAY-PINS"; exit 1; }
[ "$LINKS_AFTER" = "$LINKS_BEFORE" ] || { echo "STRAY-LINKS"; exit 1; }
[ "$PROGS_AFTER" = "$PROGS_BEFORE" ] || { echo "STRAY-PROGS"; exit 1; }
[ "$MAPS_AFTER" = "$MAPS_BEFORE" ] || { echo "STRAY-MAPS"; exit 1; }
echo "cleanup: proven"
echo "=== end reserve-consumer ==="
"""


def guest_run():
    """Stage the consumer object, boot one guest, return the transcript."""
    if "run" in _GUEST:
        return _GUEST["run"]
    fix = fixture()
    assert fix["build"].returncode == 0, "consumer build must pass first"
    # The guest boots with the same scrubbed-PATH vng binary the
    # fixture probed and recorded, never an ambient re-resolution.
    vng_path = fix["vng"]["path"]
    stage = tempfile.mkdtemp(prefix="consumer-reserve-", dir="/tmp")
    staged = {
        "consumer.bpf.o": os.path.join(fix["out_dir"], CONSUMER_OBJECT),
        "syscall_workload": fix["workload"],
        "tracepoint_attach": fix["holder"],
        "ringbuf_drain": fix["drain"],
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
    script = (
        GUEST_SCRIPT.replace("__STAGE__", stage)
        .replace("__OBJECT_HASH__", host_shas["consumer.bpf.o"])
        .replace("__N__", str(CONSUMER_N))
        .replace("__M__", str(CONSUMER_M))
    )
    script_path = os.path.join(stage, "guest_consumer.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    os.chmod(os.path.join(stage, "consumer.bpf.o"), 0o644)
    os.chmod(script_path, 0o644)
    for name in (
        "syscall_workload", "tracepoint_attach", "ringbuf_drain"
    ):
        os.chmod(os.path.join(stage, name), 0o755)
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
    if "=== end reserve-consumer ===" not in output:
        raise EnvironmentFailure(
            "guest transcript incomplete (stage kept at %s):\n%s"
            % (stage, output[-4000:])
        )
    _GUEST["run"] = {
        "stage": stage,
        "output": output,
        "host_shas": host_shas,
    }
    return _GUEST["run"]


def run_lines(output):
    """Parse the guest's run- lines into a dict of observations."""
    found = {}
    for line in output.splitlines():
        if not line.startswith("run-"):
            continue
        key, _, value = line[len("run-"):].partition(": ")
        found[key] = value.strip()
    return found


def run_frames(output):
    """Rebuild the drained bytes from the transcript frame lines.

    Every line is strictly validated and the rebuilt bytes must
    match the published digest, so transcript corruption fails
    loudly instead of decoding as kernel data.
    """
    chunks = []
    digest = None
    for line in output.splitlines():
        if line.startswith("run-frame: "):
            text = line[len("run-frame: "):].strip()
            if not re.fullmatch(r"[0-9a-f]{72}", text):
                raise AssertionError(
                    "frame line malformed: %r" % (line,)
                )
            chunks.append(bytes.fromhex(text))
        elif line.startswith("run-sha256: "):
            digest = line[len("run-sha256: "):].strip()
    if digest is None:
        raise AssertionError("run sha256 line missing")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise AssertionError("run sha256 malformed: %r" % (digest,))
    blob = b"".join(chunks)
    observed = hashlib.sha256(blob).hexdigest()
    if observed != digest:
        raise AssertionError(
            "transcript bytes %s do not match the published %s"
            % (observed, digest)
        )
    return blob


def decode_frames(blob):
    """Decode 36-byte frames without the product decoder.

    The consumer proof observes kernel bytes independently: each
    frame is a u32 frame length plus the 32-byte record (u16
    version, u16 size, u32 tgid, u32 tid, u32 cpu, u64 sequence,
    u64 monotonic_ns).
    """
    if len(blob) % 36 != 0:
        raise AssertionError("drained bytes are not whole frames")
    records = []
    for offset in range(0, len(blob), 36):
        frame = blob[offset:offset + 36]
        (frame_len,) = struct.unpack_from("<I", frame, 0)
        (version, size, tgid, tid, cpu, sequence, monotonic) = (
            struct.unpack_from("<HHIIIQQ", frame, 4)
        )
        records.append(
            {
                "frame_len": frame_len,
                "version": version,
                "size": size,
                "tgid": tgid,
                "tid": tid,
                "cpu": cpu,
                "sequence": sequence,
                "monotonic": monotonic,
            }
        )
    return records


def test_consumer_kernel_run_exact():
    run = guest_run()
    output = run["output"]
    phase = run_lines(output)
    for key in (
        "tids", "filter", "done", "counters", "drained",
        "discarded", "ring",
    ):
        assert key in phase, (key, phase)
    pairs = {}
    for chunk in phase["tids"].split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        role, _, tid = chunk.partition(" ")
        pairs[role.strip()] = tid.strip()
    assert set(pairs) == {
        "monitored", "excl1", "excl2", "observer",
    }, pairs
    assert len(set(pairs.values())) == 4, pairs
    match = re.fullmatch(
        r"attempted=(\d+) successful=(\d+) failed=(\d+)",
        phase["counters"].strip(),
    )
    assert match, phase["counters"]
    attempted, successful, failed = (
        int(group) for group in match.groups()
    )
    assert attempted == CONSUMER_N, (attempted, CONSUMER_N)
    assert successful == CONSUMER_N, (successful, CONSUMER_N)
    assert failed == 0, (failed,)
    assert phase["drained"] == str(CONSUMER_N), (phase["drained"],)
    assert phase["discarded"] == "0", (phase["discarded"],)
    assert phase["ring"] == "0 %d %d" % (
        CONSUMER_N * 40, CONSUMER_N * 40,
    ), (phase["ring"],)
    records = decode_frames(run_frames(output))
    assert len(records) == CONSUMER_N, len(records)
    assert [record["sequence"] for record in records] == list(
        range(CONSUMER_N)
    )
    ncpu = None
    for line in output.splitlines():
        if line.startswith("ncpu:"):
            ncpu = int(line.split("ncpu:")[1].strip())
    assert ncpu is not None and ncpu >= 1, output[-500:]
    previous = None
    for record in records:
        assert record["frame_len"] == 32, record
        assert record["version"] == 1, record
        assert record["size"] == 32, record
        assert record["tgid"] == int(pairs["observer"]), record
        assert record["tid"] == int(pairs["monitored"]), record
        assert 0 <= record["cpu"] < ncpu, record
        if previous is not None:
            assert record["monotonic"] >= previous, record
        previous = record["monotonic"]


def test_consumer_guest_provenance():
    run = guest_run()
    try:
        observed_kernel = lane_lock.booted_kernel_from_output(run["output"])
        lane_lock.check_booted_kernel(
            observed_kernel, REPO_ROOT, VNG_RELEASE
        )
    except lane_lock.LaneLockError as exc:
        raise AssertionError("guest kernel must be locked: %s" % exc)
    assert "cleanup: proven" in run["output"], "residue must go"
    assert "STRAY-" not in run["output"], "residue must go"
    assert "%s  consumer.bpf.o" % (
        run["host_shas"]["consumer.bpf.o"]
    ) in run["output"], "guest must re-verify the staged object"


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
        % (CONSUMER_OBJECT, run["host_shas"]["consumer.bpf.o"])
    )
    print(
        "consumer kernel: %d/%d/0 counters, %d contiguous records"
        % (CONSUMER_N, CONSUMER_N, CONSUMER_N)
    )
    print("reserve consumer: isolated build plus exact kernel result")
    return 0


if __name__ == "__main__":
    sys.exit(main())
