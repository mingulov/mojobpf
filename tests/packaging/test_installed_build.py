# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Installed-tool proof: doctor/build/inspect with no repository paths.

Installs the ``mojobpf`` wheel (built offline, as in
``tests/packaging/test_wheel_contents.py``) into a clean virtual
environment, then runs the installed ``mojobpf doctor``, ``mojobpf
build`` (genuinely compiling the packet-classifier example through
``mojo`` -> adapter -> ``llc``), and ``mojobpf inspect`` from a
directory unrelated to the checkout, with every CLI path absolute
and outside the checkout and ``PYTHONPATH`` scrubbed. The tool
must resolve its package, SDK, and adapter from the virtual
environment (asserted from ``doctor --json`` and from the
interpreter's own ``sys.path``); the evidence sidecar must carry
no repository path bytes.

Editable installs alone do not satisfy this suite: the wheel is a
real artifact installed with ``pip install --no-index`` (no
network), and the build deliberately omits ``--adapter`` so the
packaged default is what runs.

External toolchain exception, stated plainly: Mojo and LLVM are
documented external dependencies, not bundled files. This suite
lets them resolve from wherever the ambient environment provides
them (here, the checkout's pinned pixi environment for ``mojo``
plus system LLVM). Only the tool's own resolutions -- package,
SDK, adapter, and every CLI argument -- are held to the
zero-repository-paths rule.

The virtual environment is an ephemeral fixture under a temporary
directory, removed afterwards; it is not the project's
environment. Requires ``pip`` with ``setuptools``/``wheel`` for
the running interpreter, the ``venv`` module, and the genuine
``mojo``/``llc`` tools on PATH. Anything missing is an
environment failure, never a pass.

Runnable directly (``python3
tests/packaging/test_installed_build.py``) or under any
``test_``-style runner. Standard library only.
"""

import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
PIXI_BIN = os.path.join(
    REPO_ROOT, ".pixi", "envs", "default", "bin"
)
EXAMPLE_SOURCE = os.path.join(
    REPO_ROOT, "examples", "packet_classifier", "classifier.mojo"
)
LOCKFILE_SOURCE = os.path.join(REPO_ROOT, "toolchains.lock.json")

_FIXTURE = {}


class EnvironmentFailure(Exception):
    """The toolchain or builder needed by this test is missing."""


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
    """Environment with no repository paths except the toolchain."""
    kept = []
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        if os.path.realpath(entry) == os.path.realpath(PIXI_BIN):
            kept.append(entry)
            continue
        try:
            under_repo = os.path.commonpath(
                [os.path.realpath(entry), os.path.realpath(REPO_ROOT)]
            ) == os.path.realpath(REPO_ROOT)
        except (OSError, ValueError):
            continue
        if not under_repo:
            kept.append(entry)
    env = {
        "PATH": os.pathsep.join([venv_bin] + kept),
        "MODULAR_HOME": os.path.join(
            os.path.dirname(PIXI_BIN), "share", "max"
        ),
        "HOME": os.environ.get("HOME", "/tmp"),
    }
    return env


def fixture():
    """Build the venv, install the wheel, run the genuine build."""
    if "root" in _FIXTURE:
        return _FIXTURE
    if not os.path.isfile(
        os.path.join(PIXI_BIN, "mojo")
    ) or shutil.which("llc") is None:
        raise EnvironmentFailure(
            "genuine mojo/llc tools are required on PATH"
        )
    root = tempfile.mkdtemp(prefix="mojobpf-installed-")
    _FIXTURE["root"] = root
    atexit.register(_cleanup)
    venv = os.path.join(root, "venv")
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
    venv_python = os.path.join(venv_bin, "python")
    venv_pip = os.path.join(venv_bin, "pip")
    venv_mojobpf = os.path.join(venv_bin, "mojobpf")
    if not os.path.isfile(venv_pip):
        raise EnvironmentFailure("venv has no pip")
    wheel = _build_wheel(os.path.join(root, "dist"))
    proc = _run(
        [venv_pip, "install", "--no-index", "--no-deps", wheel],
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
    project = os.path.join(work, "proj")
    os.makedirs(project)
    with open(EXAMPLE_SOURCE, "rb") as handle:
        source_bytes = handle.read()
    with open(
        os.path.join(project, "classifier.mojo"), "wb"
    ) as handle:
        handle.write(source_bytes)
    manifest_text = (
        "schema_version = 1\n"
        "\n"
        "[project]\n"
        'name = "installed-proof"\n'
        "\n"
        "[target]\n"
        'profile = "linux-bpfel-v3"\n'
        "core = false\n"
        "\n"
        "[artifact]\n"
        'name = "classifier_obj"\n'
        'source_license = "Apache-2.0 WITH LLVM-exception"\n'
        'kernel_license = "Apache-2.0 WITH LLVM-exception"\n'
        "\n"
        "[[programs]]\n"
        'source = "classifier.mojo"\n'
        'entry = "xdp_entry"\n'
        'program_type = "xdp"\n'
        'section = "xdp"\n'
    )
    manifest_path = os.path.join(project, "mojobpf.toml")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(manifest_text)
    lockfile_path = os.path.join(project, "toolchains.lock.json")
    shutil.copyfile(LOCKFILE_SOURCE, lockfile_path)
    out_dir = os.path.join(work, "out")
    env = _scrubbed_env(venv_bin)
    assert "PYTHONPATH" not in env
    for path in (manifest_path, out_dir, lockfile_path, work):
        assert os.path.isabs(path), path
        assert not path.startswith(REPO_ROOT + os.sep), path
    proc = _run(
        [
            venv_mojobpf,
            "build",
            "--manifest", manifest_path,
            "--out-dir", out_dir,
            "--lockfile", lockfile_path,
        ],
        work,
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
            "build": proc,
        }
    )
    return _FIXTURE


def _cleanup():
    root = _FIXTURE.pop("root", None)
    if root is not None:
        shutil.rmtree(root, ignore_errors=True)


def test_installed_console_script_exists():
    fix = fixture()
    assert os.path.isfile(fix["venv_mojobpf"])
    proc = _run(
        [fix["venv_mojobpf"], "--help"], fix["work"], fix["env"], 60
    )
    assert proc.returncode == 0, proc.stderr
    assert "build" in proc.stdout and "inspect" in proc.stdout


def test_installed_doctor_reports_venv_paths():
    fix = fixture()
    proc = _run(
        [fix["venv_mojobpf"], "doctor", "--json"],
        fix["work"],
        fix["env"],
        120,
    )
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    assert doc["mojobpf_version"] == "0.1.0", doc
    assert doc["sdk_version"] == "1.0", doc
    package = os.path.realpath(doc["package_path"])
    assert package.startswith(
        os.path.realpath(fix["venv"]) + os.sep
    ), package
    assert REPO_ROOT not in doc["package_path"], package
    proc = _run(
        [
            fix["venv_python"],
            "-c",
            "import sys; print(sys.path)",
        ],
        fix["work"],
        fix["env"],
        60,
    )
    assert proc.returncode == 0, proc.stderr
    assert REPO_ROOT not in proc.stdout, proc.stdout


def test_installed_builds_example_without_repo_paths():
    fix = fixture()
    proc = fix["build"]
    assert proc.returncode == 0, (
        proc.stdout + "\n" + proc.stderr
    )
    objects = sorted(
        entry
        for entry in os.listdir(fix["out_dir"])
        if entry.endswith(".bpf.o")
    )
    assert objects == ["classifier_obj.bpf.o"], objects
    sidecar = os.path.join(
        fix["out_dir"], "classifier_obj.evidence.json"
    )
    assert os.path.isfile(sidecar)
    with open(sidecar, "rb") as handle:
        raw = handle.read()
    doc = json.loads(raw.decode("ascii"))
    assert doc["tool_version"] == "0.1.0", doc
    assert doc["sdk_version"] == "1.0", doc
    assert doc["success"] is True
    assert REPO_ROOT.encode() not in raw
    assert os.path.dirname(REPO_ROOT).encode() not in raw


def test_installed_inspect_verifies_object():
    fix = fixture()
    obj = os.path.join(fix["out_dir"], "classifier_obj.bpf.o")
    proc = _run(
        [fix["venv_mojobpf"], "inspect", "--object", obj],
        fix["work"],
        fix["env"],
        120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ok" in proc.stdout
    proc = _run(
        [
            fix["venv_mojobpf"],
            "inspect",
            "--object", obj,
            "--source-license", "Apache-2.0 WITH LLVM-exception",
            "--kernel-license", "Apache-2.0 WITH LLVM-exception",
        ],
        fix["work"],
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
            "--source-license", "MIT",
            "--kernel-license", "MIT",
        ],
        fix["work"],
        fix["env"],
        120,
    )
    assert proc.returncode == 4, proc.stdout + proc.stderr
    assert "MBPF704" in proc.stdout


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
    print("installed build: clean-venv proof passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
