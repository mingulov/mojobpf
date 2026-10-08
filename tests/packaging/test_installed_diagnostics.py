# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Installed-package diagnostic parity: the wheel surfaces the same
source-line diagnostics as the checkout driver.

Builds the wheel, installs it into a throwaway virtualenv with no
repository paths, and runs the installed ``mojobpf build`` on an
invalid source (frontend refusal) and an audit-invalid source
(MBPF306 with a mapped source line). The same staged projects are
then built through the checkout driver, and the rendered
diagnostics must match after temporary-path normalization. This
proves host-only diagnostic parity for the installed tool,
including the packaged adapter copy the installed CLI uses.

Requires network-isolated pip installs to work (``--no-index``),
the genuine Mojo/LLVM tools on PATH, and a writable temp area. A
missing prerequisite is reported as an environment failure; a
parity mismatch is a proof failure. Neither ever passes.

Runnable directly (``python3
tests/packaging/test_installed_diagnostics.py``). Standard library
only.
"""

import atexit
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
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

PIXI_BIN = os.path.join(REPO_ROOT, ".pixi", "envs", "default", "bin")
LOCKFILE_SOURCE = os.path.join(REPO_ROOT, "toolchains.lock.json")
BAD_SOURCE = os.path.join(REPO_ROOT, "tests", "compile", "probe_bad.mojo")
AUDIT_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "subset", "subset_bad_helper.mojo"
)

_FIXTURE = {}


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def _run(argv, cwd, env, timeout):
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def _build_wheel(parent):
    os.makedirs(parent, exist_ok=True)
    proc = _run(
        [
            sys.executable, "-m", "pip", "wheel", "--no-deps",
            "--no-build-isolation", "-w", parent, REPO_ROOT,
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
    # Temp-dir parity with the in-process checkout side: without it
    # the installed CLI builds under /tmp while the checkout side
    # honors a nested TMPDIR, and the rendering comparison trips on
    # the temp base. A real installed CLI inherits these.
    for name in ("TMPDIR", "TEMP", "TMP"):
        if name in os.environ:
            env[name] = os.environ[name]
    return env


MANIFEST_TEXT = """\
schema_version = 1

[project]
name = "installed-diag"

[target]
profile = "linux-bpfel-v3"
core = false

[artifact]
name = "{artifact}"
source_license = "Apache-2.0 WITH LLVM-exception"
kernel_license = "Apache-2.0 WITH LLVM-exception"

[[programs]]
source = "{source}"
entry = "xdp_entry"
program_type = "xdp"
section = "xdp"
"""


def fixture():
    """Build the venv, install the wheel, stage invalid projects."""
    if "root" in _FIXTURE:
        return _FIXTURE
    if not os.path.isfile(
        os.path.join(PIXI_BIN, "mojo")
    ) or shutil.which("llc") is None:
        raise EnvironmentFailure(
            "genuine mojo/llc tools are required on PATH"
        )
    for path in (BAD_SOURCE, AUDIT_SOURCE, LOCKFILE_SOURCE):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    root = tempfile.mkdtemp(prefix="mojobpf-installed-diag-")
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
    projects = {}
    for tag, source, artifact in (
        ("frontend", BAD_SOURCE, "bad_obj"),
        ("audit", AUDIT_SOURCE, "audit_obj"),
    ):
        project = os.path.join(work, tag)
        os.makedirs(project)
        filename = os.path.basename(source)
        shutil.copyfile(source, os.path.join(project, filename))
        manifest_path = os.path.join(project, "mojobpf.toml")
        with open(manifest_path, "w", encoding="utf-8") as handle:
            handle.write(
                MANIFEST_TEXT.format(
                    artifact=artifact, source=filename
                )
            )
        lockfile_path = os.path.join(project, "toolchains.lock.json")
        shutil.copyfile(LOCKFILE_SOURCE, lockfile_path)
        out_dir = os.path.join(work, "%s-out" % tag)
        for path in (manifest_path, out_dir, lockfile_path, work):
            assert os.path.isabs(path), path
            assert not path.startswith(REPO_ROOT + os.sep), path
        projects[tag] = {
            "project": project,
            "manifest_path": manifest_path,
            "lockfile_path": lockfile_path,
            "out_dir": out_dir,
            "source_name": filename,
        }
    env = _scrubbed_env(venv_bin)
    assert "PYTHONPATH" not in env
    # The checkout comparison runs the frontend in-process, so it
    # needs the same module-home the scrubbed env provides.
    os.environ.setdefault("MODULAR_HOME", env["MODULAR_HOME"])
    _FIXTURE.update(
        {
            "venv": venv,
            "venv_bin": venv_bin,
            "venv_mojobpf": venv_mojobpf,
            "work": work,
            "env": env,
            "projects": projects,
        }
    )
    return _FIXTURE


def _cleanup():
    root = _FIXTURE.pop("root", None)
    if root is not None:
        shutil.rmtree(root, ignore_errors=True)


def normalize_rendering(text, root):
    """Normalize temporary paths for cross-run comparison."""
    text = text.replace(root, "<tmp>")
    text = re.sub(
        r"mojobpf-build-[^/\'\"\s:]+", "<work>", text
    )
    for binary in ("mojo", "llc"):
        found = shutil.which(binary)
        if found:
            text = text.replace(found, "<%s>" % binary)
    return text.replace(REPO_ROOT, "<repo>")


def checkout_renderings(manifest_path, out_dir, lockfile_path):
    """Render the checkout driver's diagnostics for one project."""
    from mojobpf import cli as cli_module
    from mojobpf.build import (
        BuildRequest,
        build_project,
        default_adapter_path,
    )

    result = build_project(
        BuildRequest(
            manifest_path=manifest_path,
            out_dir=out_dir,
            adapter_path=default_adapter_path(),
            lockfile_path=lockfile_path,
        )
    )
    assert result.success is False, "expected the build to fail"
    return [
        cli_module._format_diagnostic(item)
        for item in result.diagnostics
    ]


def installed_build(fix, tag):
    """Run the installed CLI on one staged project."""
    paths = fix["projects"][tag]
    return _run(
        [
            fix["venv_mojobpf"],
            "build",
            "--manifest", paths["manifest_path"],
            "--out-dir", paths["out_dir"],
            "--lockfile", paths["lockfile_path"],
        ],
        fix["work"],
        fix["env"],
        600,
    )


def test_installed_frontend_failure_matches_checkout():
    fix = fixture()
    proc = installed_build(fix, "frontend")
    assert proc.returncode == 4, proc.stdout + "\n" + proc.stderr
    assert "MBPF106 (build.frontend/error)" in proc.stderr, proc.stderr
    assert (
        "probe_bad.mojo:7:12: error: expected argument name"
        in proc.stderr
    ), proc.stderr
    paths = fix["projects"]["frontend"]
    checkouts = checkout_renderings(
        paths["manifest_path"],
        paths["out_dir"] + "-checkout",
        paths["lockfile_path"],
    )
    assert len(checkouts) == 1, checkouts
    installed = normalize_rendering(proc.stderr.strip(), fix["root"])
    expected = normalize_rendering(checkouts[0], fix["root"])
    assert installed == expected, (
        "installed rendering differs:\n  installed: %r\n  checkout:  %r"
        % (installed, expected)
    )
    print("PASS installed frontend failure matches checkout")


def test_installed_audit_failure_matches_checkout():
    fix = fixture()
    proc = installed_build(fix, "audit")
    assert proc.returncode == 4, proc.stdout + "\n" + proc.stderr
    assert "MBPF306 (adapter.audit/error)" in proc.stderr, proc.stderr
    assert (
        "subset_bad_helper.mojo:18:     ]()" in proc.stderr
    ), proc.stderr
    paths = fix["projects"]["audit"]
    checkouts = checkout_renderings(
        paths["manifest_path"],
        paths["out_dir"] + "-checkout",
        paths["lockfile_path"],
    )
    assert len(checkouts) == 1, checkouts
    installed = normalize_rendering(proc.stderr.strip(), fix["root"])
    expected = normalize_rendering(checkouts[0], fix["root"])
    assert installed == expected, (
        "installed rendering differs:\n  installed: %r\n  checkout:  %r"
        % (installed, expected)
    )
    print("PASS installed audit failure matches checkout")


def test_installed_doctor_reports_venv_package():
    fix = fixture()
    proc = _run(
        [fix["venv_mojobpf"], "doctor", "--json"],
        fix["work"],
        fix["env"],
        120,
    )
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    package = os.path.realpath(doc["package_path"])
    assert package.startswith(
        os.path.realpath(fix["venv"]) + os.sep
    ), package
    assert REPO_ROOT not in doc["package_path"], package
    print("PASS installed CLI runs from the venv package")


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
    print("installed diagnostics: %d cases green" % len(names))
    return 0


if __name__ == "__main__":
    sys.exit(main())
