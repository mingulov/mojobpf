# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Clean-directory reproduction of the MojoBPF feasibility proofs.

Reproduces the packet-classifier and map round-trip proofs from a fresh
checkout: clones this repository at its current commit into a new temporary
directory, runs a fresh ``pixi install`` there, executes the four proof
suites (two structural suites plus two in-kernel suites) inside that
directory, then rebuilds both canonical objects through the genuine
pipeline (``mojo build --emit llvm`` -> ``compiler/mojo_ir_adapter.py`` ->
``llc -mtriple=bpfel -mcpu=v3``) and compares every intermediate hash
against the pinned values below.

The script fails loudly, never warn-and-passes: any suite failure, any
hash mismatch, any missing or malformed pin, or any leak of the source
checkout into the clean environment exits nonzero. The working tree must
be committed first (a clone cannot reproduce uncommitted work), so a
dirty tree is refused up front.

Each kernel suite boots its own disposable Linux guest, so a full run
takes a long time (tens of minutes under software emulation) and needs
``git``, ``pixi``, ``llc``, ``bpftool`` and ``vng`` on PATH. The host
itself only compiles; privileged execution happens inside the guests.

Exit codes: 0 means every suite passed and every hash matched; 1 means a
proof failed (suite failure, suite timeout, a frontend/adapter/backend
rebuild failure, hash mismatch, or malformed pin); 2 means the
environment or setup is unusable (missing tool, dirty tree, clone or
install failure, or a suite reporting exit 2). Rebuild failures are
proof failures with a named stage, never environment failures: with the
tools present, a broken build means a broken proof. ``--keep-dir``
keeps the clean directory on success; it is always kept (and its path
printed) on failure.

Pass contract: each suite prints one ``PASS <test>`` line per passing
test; a suite that exits 0 without any ``PASS`` line is treated as a
failure. Suites use ``assert`` oracles, so this probe scrubs
``PYTHONOPTIMIZE`` from the clean environment and every suite refuses
to run when ``__debug__`` is false.

Runnable directly (``python3 tests/probes/run_feasibility.py``). Standard
library only.
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

# Pinned SHA-256 of the genuine pipeline outputs for the two canonical
# programs. Any drift in the compiler, the adapter, or the backend shows
# up here first; update these only together with a reviewed change.
EXPECTED_PINS = {
    "classifier": {
        "source": "examples/xdp_pass/xdp_pass.mojo",
        "raw_ir": (
            "aea81a0f56b2ecbaecd3b84c04cc3c3c373c7759ccacdcb30380ab2d2b32a39a"
        ),
        "adapted_ir": (
            "42cc47109656b8649ce89fe84fb9586df1e5830e3b56e7db255b5c8eabdf2413"
        ),
        "object": (
            "17570ee79a16b64ccc4f723d00d26ae316a286cffdd3382ba3a6e6b4be95097c"
        ),
    },
    "map": {
        "source": "tests/compile/map_roundtrip.mojo",
        "raw_ir": (
            "6206cf76a8a123b6036618e52d9ffd7ac093e5939b3cb83bc2c2f44b6dc26681"
        ),
        "adapted_ir": (
            "4ce089bd7408958642a84a92e78c1bef2b0aadf4e64e3097f45e64b96977fb86"
        ),
        "object": (
            "18f7490634c6462360aafcb1ece85406b2374b4b74a2ca4501f90b5781e8a540"
        ),
    },
}

# (label, suite path relative to the clean checkout, timeout seconds).
SUITES = (
    ("elf-classifier", "tests/elf/test_minimal_object.py", 900),
    ("elf-map", "tests/elf/test_map_btf.py", 900),
    ("kernel-classifier", "tests/kernel/test_mojo_xdp.py", 1500),
    ("kernel-map", "tests/kernel/test_map_roundtrip.py", 1500),
)

REQUIRED_TOOLS = ("git", "pixi", "python3", "llc", "bpftool", "vng")
PIXI_TIMEOUT = 1800


class SetupFailure(Exception):
    """The environment or setup is unusable (exit 2)."""


class ProofFailure(Exception):
    """A proof step failed: suite, timeout, or hash mismatch (exit 1)."""


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_capture(argv, cwd=None, env=None, timeout=600, label=None):
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise SetupFailure(
            "%s timed out after %ds" % (label or " ".join(argv), timeout)
        )


def run_stream(argv, cwd, env, timeout, label):
    """Run argv, echoing merged output live; return (exit, output, secs)."""
    start = time.monotonic()
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        bufsize=1,
    )
    lines = []

    def pump():
        for line in proc.stdout:
            lines.append(line)
            sys.stdout.write("[%s] %s" % (label, line))
            sys.stdout.flush()

    worker = threading.Thread(target=pump, daemon=True)
    worker.start()
    try:
        exit_code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        exit_code = proc.wait()
        worker.join(timeout=30)
        return exit_code, "".join(lines), time.monotonic() - start, True
    worker.join(timeout=60)
    return exit_code, "".join(lines), time.monotonic() - start, False


def check_pins():
    for program, pins in EXPECTED_PINS.items():
        for key in ("raw_ir", "adapted_ir", "object"):
            value = pins.get(key, "")
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(c not in "0123456789abcdef" for c in value)
            ):
                raise ProofFailure(
                    "missing or malformed pin for %s/%s" % (program, key)
                )


def git_head():
    proc = run_capture(["git", "-C", REPO_ROOT, "rev-parse", "HEAD"])
    if proc.returncode != 0:
        raise SetupFailure("cannot read HEAD: %s" % proc.stderr.strip())
    return proc.stdout.strip()


def check_tree_clean():
    proc = run_capture(["git", "-C", REPO_ROOT, "status", "--porcelain"])
    if proc.returncode != 0:
        raise SetupFailure("cannot inspect tree: %s" % proc.stderr.strip())
    if proc.stdout.strip():
        raise SetupFailure(
            "working tree is dirty; commit first so the clone reproduces "
            "a recorded state:\n%s" % proc.stdout.strip()
        )


def fresh_clone(parent, commit):
    clone = os.path.join(parent, "clone")
    proc = run_capture(["git", "clone", "--quiet", REPO_ROOT, clone],
                       timeout=600, label="git clone")
    if proc.returncode != 0 or not os.path.isdir(clone):
        raise SetupFailure(
            "git clone failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    proc = run_capture(["git", "-C", clone, "checkout", "--quiet", commit],
                       timeout=300, label="git checkout %s" % commit[:12])
    if proc.returncode != 0:
        raise SetupFailure(
            "checkout of %s failed:\n%s\n%s"
            % (commit, proc.stdout, proc.stderr)
        )
    proc = run_capture(["git", "-C", clone, "rev-parse", "HEAD"])
    if proc.stdout.strip() != commit:
        raise SetupFailure(
            "clone HEAD %r is not the recorded commit %r"
            % (proc.stdout.strip(), commit)
        )
    proc = run_capture(["git", "-C", clone, "status", "--porcelain"])
    if proc.returncode != 0 or proc.stdout.strip():
        raise SetupFailure("clone tree is not clean: %s" % proc.stdout)
    if os.path.exists(os.path.join(clone, ".pixi")):
        raise SetupFailure("clone unexpectedly contains a .pixi directory")
    return clone


def _under(path, root):
    """True when the canonical path is root itself or lives under it."""
    try:
        real = os.path.realpath(path)
    except OSError:
        return False
    return real == root or real.startswith(root + os.sep)


def clean_env_for_clone(clone):
    """Environment whose toolchain paths all live under the clone."""
    pixi_bin = os.path.join(clone, ".pixi", "envs", "default", "bin")
    if not os.path.isfile(os.path.join(pixi_bin, "mojo")):
        raise SetupFailure(
            "pixi install did not produce %s" % os.path.join(pixi_bin, "mojo")
        )
    repo_real = os.path.realpath(REPO_ROOT)
    # Drop any entry under the source checkout so the clean directory can
    # never resolve its tools (or the Mojo standard library) from it.
    # Entries are compared by canonical real path, never substring.
    kept = [
        entry
        for entry in os.environ.get("PATH", "").split(os.pathsep)
        if entry and not _under(entry, repo_real)
    ]
    env = dict(os.environ)
    env["PATH"] = os.pathsep.join([pixi_bin] + kept)
    env["MODULAR_HOME"] = os.path.join(
        clone, ".pixi", "envs", "default", "share", "max"
    )
    python_path = [
        entry
        for entry in env.get("PYTHONPATH", "").split(os.pathsep)
        if entry and not _under(entry, repo_real)
    ]
    if python_path:
        env["PYTHONPATH"] = os.pathsep.join(python_path)
    else:
        env.pop("PYTHONPATH", None)
    # Optimization would strip the suites' assert-oracles; the clean
    # environment must run them unoptimized.
    env.pop("PYTHONOPTIMIZE", None)
    # No other search path may leak the source checkout (or a tainted
    # toolchain) into the clean build: drop every remaining *PATH
    # variable and every dynamic-loader variable.
    for name in list(env):
        if name in ("PATH", "PYTHONPATH"):
            continue
        if name.endswith("PATH") or name.startswith("LD_"):
            env.pop(name, None)
    for leaked in ("PIXI_PROJECT_MANIFEST", "PIXI_PROJECT_ROOT"):
        env.pop(leaked, None)
    for key in ("PATH", "MODULAR_HOME", "PYTHONPATH"):
        for entry in env.get(key, "").split(os.pathsep):
            if entry and _under(entry, repo_real):
                raise SetupFailure(
                    "source checkout leaks into clean %s" % key
                )
    resolved = shutil.which("mojo", path=env["PATH"])
    if resolved != os.path.join(pixi_bin, "mojo"):
        raise SetupFailure(
            "mojo resolves to %r instead of the clean environment"
            % resolved
        )
    return env


def run_suites(clone, env):
    failures = []
    for label, relpath, timeout in SUITES:
        suite = os.path.join(clone, relpath)
        if not os.path.isfile(suite):
            raise ProofFailure("suite missing from clone: %s" % relpath)
        print("=== suite %s (%s) ===" % (label, relpath))
        sys.stdout.flush()
        exit_code, output, secs, timed_out = run_stream(
            ["python3", suite], cwd=clone, env=env,
            timeout=timeout, label=label,
        )
        print(
            "=== suite %s finished: exit=%d timed_out=%s secs=%.1f ==="
            % (label, exit_code, timed_out, secs)
        )
        if timed_out:
            failures.append("%s timed out after %ds" % (label, timeout))
        elif exit_code == 2:
            raise SetupFailure(
                "%s reported an environment failure (exit 2)" % label
            )
        elif exit_code != 0:
            failures.append("%s exited %d" % (label, exit_code))
        elif "PASS " not in output:
            failures.append("%s produced no PASS lines" % label)
    if failures:
        raise ProofFailure("suite failures:\n- " + "\n- ".join(failures))


def rebuild_and_compare(parent, clone, env):
    workdir = os.path.join(parent, "hashcheck")
    os.mkdir(workdir)
    adapter = os.path.join(clone, "compiler", "mojo_ir_adapter.py")
    sdk_include = os.path.join(clone, "src", "mojobpf", "resources", "sdk")
    rows = []
    for program, pins in EXPECTED_PINS.items():
        source = os.path.join(clone, pins["source"])
        raw_path = os.path.join(workdir, program + ".ll")
        adapted_path = os.path.join(workdir, program + ".bpf.ll")
        object_path = os.path.join(workdir, program + ".bpf.o")
        build = ["mojo", "build", "--emit", "llvm"]
        if program == "map":
            build += ["-I", sdk_include]
        build += ["-o", raw_path, source]
        try:
            proc = run_capture(build, cwd=workdir, env=env, timeout=600,
                               label="mojo build %s" % pins["source"])
        except SetupFailure as exc:
            raise ProofFailure("frontend stage failed: %s" % exc)
        if proc.returncode != 0 or not os.path.isfile(raw_path):
            raise ProofFailure(
                "frontend stage failed for %s (exit %d):\n%s\n%s"
                % (pins["source"], proc.returncode, proc.stdout, proc.stderr)
            )
        if (
            "error:" in proc.stderr.lower()
            or "warning:" in proc.stderr.lower()
        ):
            raise ProofFailure(
                "frontend stage diagnostics for %s:\n%s"
                % (pins["source"], proc.stderr)
            )
        try:
            proc = run_capture(
                ["python3", adapter, "--input", raw_path,
                 "--output", adapted_path],
                cwd=workdir, env=env, timeout=300,
                label="adapter %s" % pins["source"],
            )
        except SetupFailure as exc:
            raise ProofFailure("adapter stage failed: %s" % exc)
        if proc.returncode != 0 or not os.path.isfile(adapted_path):
            raise ProofFailure(
                "adapter stage failed for %s (exit %d):\n%s\n%s"
                % (pins["source"], proc.returncode, proc.stdout, proc.stderr)
            )
        try:
            proc = run_capture(
                ["llc", "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
                 adapted_path, "-o", object_path],
                cwd=workdir, env=env, timeout=300,
                label="llc %s" % pins["source"],
            )
        except SetupFailure as exc:
            raise ProofFailure("backend stage failed: %s" % exc)
        if proc.returncode != 0 or not os.path.isfile(object_path):
            raise ProofFailure(
                "backend stage failed for %s (exit %d):\n%s\n%s"
                % (pins["source"], proc.returncode, proc.stdout, proc.stderr)
            )
        observed = {
            "raw_ir": sha256_file(raw_path),
            "adapted_ir": sha256_file(adapted_path),
            "object": sha256_file(object_path),
        }
        for key in ("raw_ir", "adapted_ir", "object"):
            rows.append((program, key, pins[key], observed[key]))
    print("=== hash comparison ===")
    mismatches = 0
    for program, key, expected, observed in rows:
        match = "MATCH" if expected == observed else "MISMATCH"
        if expected != observed:
            mismatches += 1
        print("%-10s %-10s expected %s" % (program, key, expected))
        print("%-10s %-10s observed %s %s" % (program, key, observed, match))
    if mismatches:
        raise ProofFailure("%d hash mismatch(es)" % mismatches)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Reproduce the feasibility proofs from a clean clone."
    )
    parser.add_argument(
        "--keep-dir", action="store_true",
        help="Keep the clean directory on success too.",
    )
    args = parser.parse_args(argv)
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    wall_start = time.monotonic()
    parent = None
    try:
        check_pins()
        for tool in REQUIRED_TOOLS:
            if shutil.which(tool) is None:
                raise SetupFailure("%s not found on PATH" % tool)
        check_tree_clean()
        commit = git_head()
        print("source checkout: %s" % REPO_ROOT)
        print("recorded commit: %s" % commit)
        parent = tempfile.mkdtemp(prefix="mojobpf-feasibility-")
        print("clean parent: %s" % parent)
        clone = fresh_clone(parent, commit)
        print("clean clone: %s at %s" % (clone, commit))
        print("=== pixi install (fresh, in the clone) ===")
        sys.stdout.flush()
        exit_code, _, secs, timed_out = run_stream(
            ["pixi", "install"], cwd=clone, env=dict(os.environ),
            timeout=PIXI_TIMEOUT, label="pixi",
        )
        print("=== pixi install finished: exit=%d secs=%.1f ==="
              % (exit_code, secs))
        if timed_out:
            raise SetupFailure(
                "pixi install timed out after %ds" % PIXI_TIMEOUT
            )
        if exit_code != 0:
            raise SetupFailure("pixi install exited %d" % exit_code)
        env = clean_env_for_clone(clone)
        print("clean mojo: %s" % shutil.which("mojo", path=env["PATH"]))
        run_suites(clone, env)
        rebuild_and_compare(parent, clone, env)
    except ProofFailure as exc:
        print("FAIL: %s" % exc)
        if parent is not None:
            print("clean directory kept at: %s" % parent)
        print("wall time: %.1fs" % (time.monotonic() - wall_start))
        return 1
    except SetupFailure as exc:
        print("ENVIRONMENT FAILURE: %s" % exc)
        if parent is not None:
            print("clean directory kept at: %s" % parent)
        print("wall time: %.1fs" % (time.monotonic() - wall_start))
        return 2
    wall = time.monotonic() - wall_start
    print("feasibility reproduction passed: 4 suites green, 6 hashes match")
    print("wall time: %.1fs" % wall)
    if parent is not None:
        if args.keep_dir:
            print("clean directory kept at: %s" % parent)
        else:
            shutil.rmtree(parent, ignore_errors=True)
            if os.path.exists(parent):
                print(
                    "WARNING: clean directory still present at: %s" % parent
                )
            else:
                print("clean directory removed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
