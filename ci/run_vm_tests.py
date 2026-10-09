# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Two-lane VM matrix runner for the kernel proof suites.

Runs every guest-backed suite (the kernel suites including the
tracepoint/event/lifecycle tracing proofs, the verifier kernel
and license suites, the external-consumer suite, and the
cleanup suite) in each lane pinned by ``ci/kernels.lock.json``
with the same committed source tree, and reports one board. The tree must be committed first:
a dirty tree is refused up front so both lanes provably test the
same bits. A lane whose cached kernel image is absent fails the run;
lanes are never silently skipped.

Each suite boots its own disposable guests through ``vng`` (software
emulation, as pinned); the host itself only compiles. Lane selection
reaches the suites through ``MOJOBPF_VNG_RELEASE``; every suite
defaults to the primary lane when the variable is unset, so
standalone runs are unchanged.

Usage::

    python3 ci/run_vm_tests.py [--lock ci/kernels.lock.json]
        [--lane v6.12-tcg] [--suite kernel-xdp] [--out-dir DIR]
        [--timeout SECS] [--consumer-path DIR]

The ``packaging-*`` consumer suites build with an independently
installed toolchain that must resolve outside the checkout;
``--consumer-path`` prepends directories to PATH for those suites
only (every other suite uses the ambient toolchain). Without it
each consumer suite fails on its own isolation gate -- never
skipped, never faked.

Exit codes: 0 when every selected suite passed in every selected
lane; 1 when any suite failed or reported an environment failure;
2 for setup problems (dirty tree, runner/QEMU mismatch, consumer
PATH shadowing the locked runner, missing lane cache, bad
lockfile). Skips never occur: an unrun lane or suite is a
failure, not a pass.

The runner, its launcher and its emulator are admitted through
``execution-contract-v1`` before any suite starts: the ``vng``
entry, its ``exec`` chain, the console-script interpreter, the
runner package modules, the ``virtme-run`` launcher ``vng``
invokes through a shell plus its ``virtme.*`` implementation,
and the QEMU image are all hash-checked against the lock, and
the lock's distribution bindings are enforced. Suites run with
a farm-first ``PATH`` plus stripped import-path, loader and
shell-startup variables so ambient shadows can never substitute
the admitted chain.

Standard library plus the first-party ``mojobpf`` package.
"""

import argparse
import atexit
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_LOCK = os.path.join(REPO_ROOT, "ci", "kernels.lock.json")

sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf import execution as execution_mod  # noqa: E402

# (suite id, path relative to the checkout, guest timeout seconds).
SUITES = (
    ("kernel-xdp", "tests/kernel/test_mojo_xdp.py", 1500),
    ("kernel-map", "tests/kernel/test_map_roundtrip.py", 1500),
    ("kernel-packet", "tests/kernel/test_packet_sdk.py", 1500),
    ("kernel-parse", "tests/kernel/test_parse_checksum_sdk.py", 1500),
    ("kernel-array", "tests/kernel/test_array_maps.py", 1500),
    ("kernel-percpu", "tests/kernel/test_percpu_maps.py", 1500),
    ("kernel-accounting", "tests/kernel/test_xdp_accounting.py", 1500),
    ("kernel-generalized", "tests/kernel/test_generalized_arrays.py", 1500),
    ("kernel-mojopercpu", "tests/kernel/test_mojo_percpu.py", 1500),
    ("kernel-tracepoint", "tests/kernel/test_tracepoint_counter.py", 1500),
    ("kernel-events", "tests/kernel/test_tracepoint_events.py", 1500),
    ("kernel-tracing-lifecycle", "tests/kernel/test_tracing_lifecycle.py", 1800),
    ("verifier-subset", "tests/verifier/test_subset_kernel.py", 1500),
    ("verifier-licenses", "tests/verifier/test_helper_licenses.py", 1500),
    ("packaging-consumer", "tests/packaging/test_external_consumer.py", 2400),
    ("packaging-hash-consumer", "tests/packaging/test_hash_consumer.py", 2400),
    ("packaging-reserve-consumer",
     "tests/packaging/test_reserve_consumer.py", 2400),
    ("packaging-subprog-consumer",
     "tests/packaging/test_subprog_consumer.py", 2400),
    ("packaging-uprobe-consumer",
     "tests/packaging/test_uprobe_consumer.py", 2400),
    ("kernel-core-layouts", "tests/kernel/test_core_layouts.py", 1800),
    ("kernel-hash", "tests/kernel/test_hash_maps.py", 1800),
    ("kernel-ringbuf", "tests/kernel/test_ringbuf_reserve.py", 1800),
    ("kernel-subprog", "tests/kernel/test_subprog_calls.py", 1800),
    ("kernel-uprobe", "tests/kernel/test_uprobe_register.py", 1800),
    ("kernel-cleanup", "tests/kernel/test_cleanup.py", 1800),
)

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_SETUP = 2


class SetupFailure(Exception):
    """The matrix cannot run honestly (exit 2)."""


def sha256_file(path):
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_head():
    try:
        completed = subprocess.run(
            ["git", "-C", REPO_ROOT, "rev-parse", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SetupFailure("cannot read git HEAD: %s" % exc)
    if completed.returncode != 0:
        raise SetupFailure("cannot read git HEAD: %s" % completed.stderr)
    return completed.stdout.strip()


def git_clean():
    try:
        completed = subprocess.run(
            ["git", "-C", REPO_ROOT, "status", "--short"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SetupFailure("cannot inspect the worktree: %s" % exc)
    if completed.returncode != 0:
        raise SetupFailure("cannot inspect the worktree: %s" % completed.stderr)
    return completed.stdout.strip()


def load_lock(path):
    if not os.path.isfile(path):
        raise SetupFailure("lockfile not found: %s" % path)
    try:
        with open(path, encoding="utf-8") as handle:
            lock = json.load(handle)
    except (OSError, ValueError) as exc:
        raise SetupFailure("lockfile %s is unreadable: %s" % (path, exc))
    if lock.get("schema_version") != 1:
        raise SetupFailure("lockfile schema_version must be 1")
    runner = lock.get("runner")
    if not isinstance(runner, dict) or runner.get("name") != "vng":
        raise SetupFailure("lockfile runner must name vng")
    for key in ("version", "sha256", "qemu"):
        if not runner.get(key):
            raise SetupFailure("lockfile runner lacks %s" % key)
    _validate_runner_pins(runner)
    _validate_distribution(lock.get("distribution"))
    lanes = lock.get("lanes")
    if not isinstance(lanes, list) or len(lanes) < 2:
        raise SetupFailure("lockfile must pin at least two lanes")
    seen_ids = set()
    for lane in lanes:
        for key in (
            "id",
            "release",
            "accelerator",
            "kernel_release",
            "kernel_debs",
            "vng_argv_prefix",
        ):
            if key not in lane:
                raise SetupFailure(
                    "lane %r lacks %s" % (lane.get("id"), key)
                )
        if lane["id"] in seen_ids:
            raise SetupFailure(
                "duplicate lane id %r" % lane["id"]
            )
        seen_ids.add(lane["id"])
        if not lane["kernel_debs"]:
            raise SetupFailure(
                "lane %r pins no kernel debs" % lane["id"]
            )
        for deb in lane["kernel_debs"]:
            if not isinstance(deb, dict) or (
                not deb.get("file") or not deb.get("sha256")
            ):
                raise SetupFailure(
                    "lane %r carries a deb without file+sha256"
                    % lane["id"]
                )
        if lane["vng_argv_prefix"][:3] != ["vng", "--run", lane["release"]]:
            raise SetupFailure(
                "lane %r argv prefix does not match its release"
                % lane.get("id")
            )
        tcg_flag = "--disable-kvm" in lane["vng_argv_prefix"]
        if tcg_flag != (lane["accelerator"] == "tcg"):
            raise SetupFailure(
                "lane %r accelerator %r disagrees with its argv "
                "prefix" % (lane["id"], lane["accelerator"])
            )
    return lock


def _validate_runner_pins(runner):
    """Validate the lock's optional execution pins when present.

    Locks pre-dating ``execution-contract-v1`` stay loadable (lane
    tools read them), but admission refuses to qualify guests from
    them until they are re-pinned.
    """
    for key in (
        "exec_sha256",
        "qemu_sha256",
        "qemu_exec_sha256",
        "virtme_run_exec_sha256",
    ):
        if key in runner and not (
            runner[key] is None or isinstance(runner[key], str)
        ):
            raise SetupFailure(
                "lockfile runner %s must be a hash string or null" % key
            )
    if "virtme_run_sha256" in runner and not isinstance(
        runner["virtme_run_sha256"], str
    ):
        raise SetupFailure(
            "lockfile runner virtme_run_sha256 must be a hash string"
        )
    if "qemu_binary" in runner and not isinstance(
        runner["qemu_binary"], str
    ):
        raise SetupFailure("lockfile runner qemu_binary must be a string")
    interpreter = runner.get("interpreter")
    if interpreter is not None:
        if not isinstance(interpreter, dict) or not isinstance(
            interpreter.get("sha256"), str
        ):
            raise SetupFailure(
                "lockfile runner interpreter must carry a sha256 string"
            )
    package = runner.get("package")
    if package is not None:
        if not isinstance(package, dict) or not isinstance(
            package.get("modules"), dict
        ):
            raise SetupFailure(
                "lockfile runner package must carry a modules table"
            )
        for dotted, digest in package["modules"].items():
            if not isinstance(dotted, str) or not isinstance(digest, str):
                raise SetupFailure(
                    "lockfile runner package modules must map names "
                    "to hash strings"
                )
    virtme_package = runner.get("virtme_package")
    if virtme_package is not None:
        if not isinstance(virtme_package, dict) or not isinstance(
            virtme_package.get("modules"), dict
        ):
            raise SetupFailure(
                "lockfile runner virtme_package must carry a modules table"
            )
        for dotted, digest in virtme_package["modules"].items():
            if not isinstance(dotted, str) or not isinstance(digest, str):
                raise SetupFailure(
                    "lockfile runner virtme_package modules must map "
                    "names to hash strings"
                )
    python_path = runner.get("python_path", [])
    if not isinstance(python_path, list) or not all(
        isinstance(entry, str) for entry in python_path
    ):
        raise SetupFailure(
            "lockfile runner python_path must be a list of strings"
        )


def _validate_distribution(distribution):
    """Validate the lock's distribution record shape when present.

    Digest/existence enforcement happens at admission; load time
    only rejects malformed shapes so lane tools keep reading
    legacy locks without the record.
    """
    if distribution is None:
        return
    if not isinstance(distribution, dict):
        raise SetupFailure("lockfile distribution must be a mapping")
    runner_dist = distribution.get("runner")
    if runner_dist is not None:
        if not isinstance(runner_dist, dict):
            raise SetupFailure(
                "lockfile distribution runner must be a mapping"
            )
        dependencies = runner_dist.get("dependencies", [])
        if not isinstance(dependencies, list):
            raise SetupFailure(
                "lockfile distribution dependencies must be a list"
            )
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                raise SetupFailure(
                    "lockfile distribution dependency must be a mapping"
                )
            for key in ("name", "version", "metadata_sha256"):
                if not isinstance(dependency.get(key), str):
                    raise SetupFailure(
                        "lockfile distribution dependency lacks a %s "
                        "string" % key
                    )
    emulator = distribution.get("emulator")
    if emulator is not None:
        if not isinstance(emulator, dict):
            raise SetupFailure(
                "lockfile distribution emulator must be a mapping"
            )
        if "qemu_version" in emulator and not isinstance(
            emulator["qemu_version"], str
        ):
            raise SetupFailure(
                "lockfile distribution emulator qemu_version must be "
                "a string"
            )


def qemu_binary_for_lock(lock):
    """Return the QEMU binary name driving this lock's lanes.

    An explicit ``runner.qemu_binary`` wins; otherwise the lanes'
    ``arch`` decides (``arm64``/``aarch64`` selects the AArch64
    system emulator, anything else the x86-64 one). A mixed-arch
    lock without an explicit binary fails closed.
    """
    explicit = lock["runner"].get("qemu_binary")
    if explicit:
        return explicit
    archs = set(
        lane.get("arch", "x86_64") for lane in lock["lanes"]
    )
    if len(archs) > 1:
        raise SetupFailure(
            "mixed-arch lock needs an explicit runner.qemu_binary"
        )
    if archs <= {"arm64", "aarch64"}:
        return "qemu-system-aarch64"
    return "qemu-system-x86_64"


def check_qemu(lock, lock_path="", timeout=60):
    """Admit the locked QEMU emulator; return its record.

    The lock pins the emulator next to the runner because both
    shape guest behavior. The image is hash-checked before its
    version probe runs, so a same-version unrelated binary is
    refused without executing; an unpinned or drifting QEMU fails
    the run up front instead of qualifying unknown emulation.
    """
    binary = qemu_binary_for_lock(lock)
    try:
        _binary, pins = execution_mod.qemu_pins(lock["runner"])
    except ValueError as exc:
        raise SetupFailure("lockfile %s" % (exc,))
    try:
        admitted = execution_mod.admit_execution(
            execution_mod.ExecutionRequest(
                name=binary,
                argv0=binary,
                version_argv=("--version",),
                probe_version=True,
                trust_root=("lock:%s" % lock_path) if lock_path else "",
            ),
            pins,
            probe_timeout=timeout,
        )
    except execution_mod.AdmissionError as exc:
        raise SetupFailure("emulator admission refused: %s" % (exc,))
    except UnicodeDecodeError as exc:
        raise SetupFailure(
            "%s version probe printed undecodable output: %s"
            % (binary, exc)
        )
    return {
        "binary": binary,
        "path": admitted.image.realpath,
        "version": admitted.version,
        "sha256": admitted.image.sha256,
        "execution": admitted,
    }


def check_virtme_run(lock, lock_path="", timeout=60):
    """Admit the locked virtme-run launcher; return its record.

    ``vng`` invokes this bare name through a shell, so the
    launcher and its ``virtme.*`` implementation are admitted
    exactly like the runner itself (entry, ``exec`` chain, shared
    interpreter, package modules) before the launcher probe runs.
    ``virtme-run`` has no ``--version``; the ``--help`` probe line
    is record-only (usage wrapping varies with output width), so
    identity rests on the entry/interpreter/module hashes.
    """
    try:
        name, pins = execution_mod.virtme_run_pins(lock["runner"])
    except ValueError as exc:
        raise SetupFailure("lockfile %s" % (exc,))
    try:
        admitted = execution_mod.admit_execution(
            execution_mod.ExecutionRequest(
                name=name,
                argv0=name,
                version_argv=("--help",),
                probe_version=True,
                trust_root=("lock:%s" % lock_path) if lock_path else "",
            ),
            pins,
            probe_timeout=timeout,
        )
    except execution_mod.AdmissionError as exc:
        raise SetupFailure("launcher admission refused: %s" % (exc,))
    except UnicodeDecodeError as exc:
        raise SetupFailure(
            "virtme-run probe printed undecodable output: %s" % (exc,)
        )
    return {
        "binary": name,
        "path": admitted.entry.realpath,
        "version": admitted.version,
        "sha256": admitted.entry.sha256,
        "execution": admitted,
    }


def check_runner(lock, lock_path="", farm_parent=None, timeout=60):
    """Admit the locked runner plus its launcher and emulator.

    The ``vng`` entry, its ``exec`` chain, the console-script
    interpreter and the runner package modules are hash-checked
    against the lock, then the lock's distribution bindings are
    enforced, and only then does any version probe run: the
    ``virtme-run`` launcher follows through
    :func:`check_virtme_run` and the emulator through
    :func:`check_qemu`. Returns the runner record with the
    ``execution``/``virtme_run_execution``/``qemu_execution``
    admissions and a ``farm`` directory forcing admitted
    ``vng``/``virtme-run``/QEMU resolution for every suite. The
    caller owns farm cleanup.
    """
    expected = lock["runner"]
    try:
        pins = execution_mod.runner_pins(expected)
    except ValueError as exc:
        raise SetupFailure("lockfile runner is malformed: %s" % (exc,))
    trust_root = ("lock:%s" % lock_path) if lock_path else ""
    try:
        static_admitted = execution_mod.admit_execution(
            execution_mod.ExecutionRequest(
                name="vng",
                argv0="vng",
                version_argv=("--version",),
                probe_version=False,
                trust_root=trust_root,
            ),
            pins,
            probe_timeout=timeout,
        )
    except execution_mod.AdmissionError as exc:
        raise SetupFailure("runner admission refused: %s" % (exc,))
    # Distribution bindings BEFORE any entry probe: the probes
    # execute distribution code (vng imports its dependencies at
    # startup), so unverified content must never reach them. The
    # emulator claim is checked against the lock's pinned version
    # here; the observed version is checked again after the
    # emulator probe below.
    try:
        execution_mod.verify_runner_dependencies(
            lock.get("distribution"), static_admitted
        )
        expected_qemu = expected.get("qemu")
        if expected_qemu is not None:
            execution_mod.verify_emulator_claim(
                lock.get("distribution"), expected_qemu
            )
    except ValueError as exc:
        raise SetupFailure(
            "lockfile distribution is malformed: %s" % (exc,)
        )
    except execution_mod.AdmissionError as exc:
        raise SetupFailure("runner distribution refused: %s" % (exc,))
    try:
        admitted = execution_mod.admit_execution(
            execution_mod.ExecutionRequest(
                name="vng",
                argv0="vng",
                version_argv=("--version",),
                probe_version=True,
                trust_root=trust_root,
            ),
            pins,
            probe_timeout=timeout,
        )
    except execution_mod.AdmissionError as exc:
        raise SetupFailure("runner admission refused: %s" % (exc,))
    except UnicodeDecodeError as exc:
        raise SetupFailure(
            "vng version probe printed undecodable output: %s" % (exc,)
        )
    qemu = check_qemu(lock, lock_path=lock_path, timeout=timeout)
    launcher = check_virtme_run(
        lock, lock_path=lock_path, timeout=timeout
    )
    # Post-probe half: the emulator claim against the OBSERVED
    # version (dependencies were already enforced pre-probe and
    # are re-checked here for a single final verdict).
    try:
        execution_mod.verify_runner_distribution(
            lock.get("distribution"), admitted, qemu["version"]
        )
    except ValueError as exc:
        raise SetupFailure(
            "lockfile distribution is malformed: %s" % (exc,)
        )
    except execution_mod.AdmissionError as exc:
        raise SetupFailure("runner distribution refused: %s" % (exc,))
    try:
        farm = execution_mod.build_path_farm(
            {
                "vng": admitted.entry.realpath,
                launcher["binary"]: launcher["execution"].entry.realpath,
                qemu["binary"]: qemu["execution"].image.realpath,
            },
            parent=farm_parent,
        )
    except (ValueError, OSError) as exc:
        raise SetupFailure(
            "cannot stage the admitted PATH farm: %s" % (exc,)
        )
    image = admitted.image
    return {
        "path": admitted.entry.path,
        "realpath": admitted.entry.realpath,
        "version": admitted.version,
        "sha256": admitted.entry.sha256,
        "exec_path": (
            image.realpath if image.realpath != admitted.entry.realpath
            else None
        ),
        "exec_sha256": (
            image.sha256 if image.realpath != admitted.entry.realpath
            else None
        ),
        "qemu_binary": qemu["binary"],
        "qemu_path": qemu["path"],
        "qemu_version": qemu["version"],
        "qemu_sha256": qemu["sha256"],
        "virtme_run_path": launcher["path"],
        "virtme_run_version": launcher["version"],
        "virtme_run_sha256": launcher["sha256"],
        "farm": farm,
        "digest": admitted.digest,
        "execution": admitted,
        "virtme_run_execution": launcher["execution"],
        "qemu_execution": qemu["execution"],
    }


def runner_report(runner):
    """Return the JSON-safe runner attestation for the report."""
    report = {
        key: value
        for key, value in runner.items()
        if key
        not in ("execution", "virtme_run_execution", "qemu_execution")
    }
    report["admission"] = execution_mod.summarize(runner["execution"])
    report["virtme_run_admission"] = execution_mod.summarize(
        runner["virtme_run_execution"]
    )
    report["qemu_admission"] = execution_mod.summarize(
        runner["qemu_execution"]
    )
    return report


def check_consumer_vng_shadow(consumer_path, runner_realpath):
    """Reject a consumer PATH that shadows the locked vng.

    Consumer suites resolve their guest runner PATH-only after
    the matrix prepends ``consumer_path``; a vng binary there
    would run guests under an unrecorded runner. The vng
    resolving under the augmented PATH must be the validated
    one (or absent, in which case the suite fails on its own
    isolation gate).
    """
    if not consumer_path:
        return
    augmented = os.pathsep.join(
        list(consumer_path) + [os.environ.get("PATH", "")]
    )
    shadow = shutil.which("vng", path=augmented)
    if shadow is not None and (
        os.path.realpath(shadow) != runner_realpath
    ):
        raise SetupFailure(
            "consumer path shadows the locked vng: %s "
            "resolves to %s, want %s"
            % (shadow, os.path.realpath(shadow), runner_realpath)
        )


def check_consumer_qemu_shadow(
    consumer_path, qemu_binary, qemu_realpath
):
    """Reject a consumer PATH that shadows the locked QEMU.

    vng resolves its emulator PATH-only (``shutil.which`` on
    the locked ``qemu-system-{arch}`` binary) after the matrix
    prepends ``consumer_path``; a QEMU binary there would run
    guests under an unrecorded emulator. The QEMU resolving
    under the augmented PATH must be the validated one (or
    absent, in which case the suite fails on its own
    isolation gate).
    """
    if not consumer_path:
        return
    augmented = os.pathsep.join(
        list(consumer_path) + [os.environ.get("PATH", "")]
    )
    shadow = shutil.which(qemu_binary, path=augmented)
    if shadow is not None and (
        os.path.realpath(shadow) != qemu_realpath
    ):
        raise SetupFailure(
            "consumer path shadows the locked %s: %s "
            "resolves to %s, want %s"
            % (
                qemu_binary, shadow,
                os.path.realpath(shadow), qemu_realpath,
            )
        )


def check_consumer_virtme_run_shadow(
    consumer_path, virtme_run_realpath
):
    """Reject a consumer PATH that shadows the locked virtme-run.

    ``vng`` invokes the bare ``virtme-run`` name through a shell
    under the augmented PATH; a launcher there would run guests
    under an unrecorded implementation. The ``virtme-run``
    resolving under the augmented PATH must be the validated one
    (or absent, in which case the suite fails on its own
    isolation gate).
    """
    if not consumer_path:
        return
    augmented = os.pathsep.join(
        list(consumer_path) + [os.environ.get("PATH", "")]
    )
    shadow = shutil.which("virtme-run", path=augmented)
    if shadow is not None and (
        os.path.realpath(shadow) != virtme_run_realpath
    ):
        raise SetupFailure(
            "consumer path shadows the locked virtme-run: %s "
            "resolves to %s, want %s"
            % (shadow, os.path.realpath(shadow), virtme_run_realpath)
        )


def check_lane_cache(lane):
    """Fail when the lane's kernel image is not cached and pinned."""
    cache = os.path.join(
        os.path.expanduser("~"), ".cache", "virtme-ng", lane["release"]
    )
    if not os.path.isdir(cache):
        raise SetupFailure(
            "lane %s cache is absent (%s); fetch it with "
            "`vng --run %s --disable-kvm --exec true` and re-run"
            % (lane["id"], cache, lane["release"])
        )
    found = []
    for root, _dirs, files in os.walk(cache):
        for name in files:
            if name.endswith(".deb"):
                found.append(os.path.join(root, name))
    problems = []
    for deb in lane["kernel_debs"]:
        matches = [
            path
            for path in found
            if os.path.basename(path) == deb["file"]
        ]
        if not matches:
            problems.append("missing %s" % deb["file"])
            continue
        if len(matches) > 1:
            problems.append(
                "ambiguous %s (%d copies; refusing to pick)"
                % (deb["file"], len(matches))
            )
            continue
        digest = sha256_file(matches[0])
        if digest != deb["sha256"]:
            problems.append(
                "%s hash mismatch (cache %s)" % (deb["file"], digest)
            )
    if problems:
        raise SetupFailure(
            "lane %s cache mismatch: %s" % (lane["id"], "; ".join(problems))
        )
    return {"cache": cache, "debs": sorted(os.path.basename(p) for p in found)}


def _scan_processes():
    """Snapshot the process table into ``{pid: (ppid, pgid, state)}``.

    Best-effort: processes that exit mid-scan are skipped, and a
    missing ``/proc`` yields an empty table.
    """
    table = {}
    try:
        entries = [entry for entry in os.listdir("/proc") if entry.isdigit()]
    except OSError:
        return table
    for entry in entries:
        try:
            pid = int(entry)
            with open("/proc/%s/stat" % entry, encoding="utf-8") as handle:
                fields = handle.read().rsplit(")", 1)
        except (OSError, ValueError):
            continue
        if len(fields) != 2:
            continue
        rest = fields[1].split()
        if len(rest) < 3:
            continue
        try:
            ppid = int(rest[1])
            pgid = int(rest[2])
        except ValueError:
            continue
        table[pid] = (ppid, pgid, rest[0])
    return table


def _owned_descendants(root, table):
    """Return the pids whose parent chain reaches ``root``.

    Only parent links from a ``_scan_processes`` snapshot are
    followed, so foreign processes are never collected -- but
    orphans already reparented past ``root`` are invisible too,
    which is why the tree kill snapshots before signalling and
    remembers every owned group it saw.
    """
    children = {}
    for pid, (ppid, _pgid, _state) in table.items():
        children.setdefault(ppid, []).append(pid)
    owned = []
    stack = list(children.get(root, []))
    while stack:
        pid = stack.pop()
        owned.append(pid)
        stack.extend(children.get(pid, []))
    return owned


def _signal_live_owned(pgid, table, seen_groups):
    """SIGKILL the living owned tree once; extend the seen groups.

    Only owned pids are signalled: living descendants of the
    suite child plus groups observed holding an owned member --
    never a bare pid used as a group id. Only groups that still
    show a living member are signalled, so dead groups are left
    alone once empty. Returns the living owned pids plus the
    groups that still hold a living member.
    """
    descendants = _owned_descendants(pgid, table)
    for pid in descendants:
        seen_groups.add(table[pid][1])
    live_owned = [
        pid for pid in descendants
        if table[pid][2] not in ("Z", "X")
    ]
    live_groups = set()
    for _ppid, member_pgid, state in table.values():
        if member_pgid in seen_groups and state not in ("Z", "X"):
            live_groups.add(member_pgid)
    for group in sorted(live_groups):
        try:
            os.killpg(group, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    for pid in live_owned:
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    return live_owned, live_groups


def _kill_suite_tree(pgid):
    """SIGKILL the suite tree; wait for every owned group to empty.

    Suites boot guests as session leaders (their own process
    group), so killing only the suite group would orphan them.
    The owned tree is snapshotted BEFORE signalling -- dead
    parents reparent their orphans and the chain is lost
    afterwards -- and every group that ever held an owned member
    stays a kill candidate while it shows a living member, which
    also reaps already-reparented stragglers that kept their
    group. Zombies count as gone and the wait is best-effort:
    whatever remains, the timeout verdict below stands. Without
    ``/proc`` the snapshot is empty and only the suite group is
    killed, as before.
    """
    seen_groups = {pgid}
    deadline = time.monotonic() + 30
    first = True
    while time.monotonic() < deadline:
        table = _scan_processes()
        if not table and first:
            # No snapshot (no /proc): fall back to the suite
            # group alone, as before.
            try:
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            return
        first = False
        live_owned, live_groups = _signal_live_owned(
            pgid, table, seen_groups
        )
        if not live_owned and not live_groups:
            return
        time.sleep(0.2)


def run_suite(suite_id, relpath, lane, out_dir, timeout, commit,
              consumer_path, farm=None):
    """Run one suite in one lane; return its result record.

    The suite runs as a session leader, so a timeout kills the
    whole owned suite tree (the suite group plus any detached
    guest groups the suite booted), never just the suite child.
    An interruption reaps the owned suite tree and propagates.

    When ``farm`` (an admitted ``vng``/``virtme-run``/QEMU
    ``PATH`` farm) is given, it heads the suite's ``PATH`` so
    guests the suite boots resolve exactly the admitted chain;
    ambient import-path, loader and shell-startup variables are
    always stripped (in-tree suites self-insert their import
    paths and never need them).
    """
    path = os.path.join(REPO_ROOT, relpath)
    record = {
        "suite": suite_id,
        "lane": lane["id"],
        "release": lane["release"],
        "commit": commit,
        "path": relpath,
        "exit_code": None,
        "outcome": "fail",
        "passes": 0,
        "failures": 0,
        "envfailures": 0,
        "timed_out": False,
        "elapsed_secs": None,
        "log": None,
    }
    if not os.path.isfile(path):
        record["note"] = "suite file missing: %s" % relpath
        return record
    env = dict(os.environ)
    env["MOJOBPF_VNG_RELEASE"] = lane["release"]
    env["LC_ALL"] = "C"
    env.pop("PYTHONOPTIMIZE", None)
    stripped = [
        name for name in execution_mod.SPAWN_ENV_UNSET if name in env
    ]
    for name in stripped:
        env.pop(name, None)
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONSAFEPATH"] = "1"
    path_parts = []
    if farm:
        path_parts.append(farm)
    if suite_id.startswith("packaging-") and consumer_path:
        path_parts.extend(consumer_path)
    path_parts.append(env.get("PATH", ""))
    env["PATH"] = os.pathsep.join(path_parts)
    log_path = os.path.join(
        out_dir, "%s.%s.log" % (lane["id"], suite_id)
    )
    record["log"] = log_path
    record["farm"] = farm
    record["env_stripped"] = stripped
    start = time.monotonic()
    proc = subprocess.Popen(
        [sys.executable, path],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_suite_tree(proc.pid)
            try:
                stdout, stderr = proc.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
            output = (
                "MATRIX TIMEOUT after %ds\n%s\n%s"
                % (timeout, stdout or "", stderr or "")
            )
            record["timed_out"] = True
            record["exit_code"] = None
        else:
            output = (stdout or "") + (stderr or "")
            record["exit_code"] = proc.returncode
    except KeyboardInterrupt:
        # An operator abort lands here from any communicate call
        # above: reap the owned suite tree (suites run as session
        # leaders in their own groups, so the terminal interrupt
        # never reaches them), then propagate.
        _kill_suite_tree(proc.pid)
        raise
    record["elapsed_secs"] = round(time.monotonic() - start, 1)
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(
            "matrix: suite=%s lane=%s release=%s commit=%s\n"
            % (suite_id, lane["id"], lane["release"], commit)
        )
        handle.write(
            "matrix: farm=%s env_stripped=%s\n"
            % (farm, ",".join(stripped) if stripped else "none")
        )
        handle.write(output)
        if not output.endswith("\n"):
            handle.write("\n")
    for line in output.splitlines():
        if line.startswith("PASS "):
            record["passes"] += 1
        elif line.startswith("FAIL "):
            record["failures"] += 1
        elif "ENVIRONMENT FAILURE" in line:
            record["envfailures"] += 1
    if record["timed_out"]:
        record["outcome"] = "timeout"
    elif (
        record["exit_code"] == 0
        and record["passes"] > 0
        and record["failures"] == 0
        and record["envfailures"] == 0
    ):
        record["outcome"] = "pass"
    elif record["envfailures"] > 0 or record["exit_code"] == 2:
        record["outcome"] = "envfail"
    else:
        record["outcome"] = "fail"
    return record


def build_parser():
    parser = argparse.ArgumentParser(
        description="Run the kernel proof suites in every pinned VM lane."
    )
    parser.add_argument("--lock", default=DEFAULT_LOCK)
    parser.add_argument(
        "--lane",
        action="append",
        default=[],
        help="lane id to run (default: every pinned lane)",
    )
    parser.add_argument(
        "--suite",
        action="append",
        default=[],
        help="suite id to run (default: every suite)",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="directory for per-suite logs and the report",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="per-suite timeout override in seconds",
    )
    parser.add_argument(
        "--consumer-path",
        action="append",
        default=[],
        help="directory prepended to PATH for the consumer suite only "
        "(independent toolchain outside the checkout)",
    )
    return parser


def _remove_farm(farm_dir):
    """Best-effort removal of an admitted PATH farm."""
    shutil.rmtree(farm_dir, ignore_errors=True)


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        lock = load_lock(args.lock)
        commit = git_head()
        dirt = git_clean()
        if dirt:
            raise SetupFailure(
                "worktree is dirty; commit first so every lane "
                "tests the same bits:\n%s" % dirt
            )
        runner = check_runner(lock, lock_path=args.lock)
        atexit.register(_remove_farm, runner["farm"])
        lanes = lock["lanes"]
        if args.lane:
            wanted = set(args.lane)
            lanes = [lane for lane in lanes if lane["id"] in wanted]
            missing = wanted - {lane["id"] for lane in lanes}
            if missing:
                raise SetupFailure(
                    "unknown lane(s): %s" % ", ".join(sorted(missing))
                )
        suites = SUITES
        if args.suite:
            wanted = set(args.suite)
            suites = [item for item in SUITES if item[0] in wanted]
            missing = wanted - {item[0] for item in suites}
            if missing:
                raise SetupFailure(
                    "unknown suite(s): %s" % ", ".join(sorted(missing))
                )
        caches = {}
        for lane in lanes:
            caches[lane["id"]] = check_lane_cache(lane)
        for entry in args.consumer_path:
            if not os.path.isdir(entry):
                raise SetupFailure(
                    "consumer path is not a directory: %s" % entry
                )
        check_consumer_vng_shadow(
            args.consumer_path, runner["realpath"]
        )
        check_consumer_qemu_shadow(
            args.consumer_path,
            runner["qemu_binary"],
            runner["qemu_path"],
        )
        check_consumer_virtme_run_shadow(
            args.consumer_path,
            runner["virtme_run_path"],
        )
    except SetupFailure as exc:
        sys.stderr.write("run_vm_tests: %s\n" % exc)
        return EXIT_SETUP

    if args.out_dir:
        out_dir = args.out_dir
        os.makedirs(out_dir, exist_ok=True)
    else:
        out_dir = tempfile.mkdtemp(prefix="mojobpf-matrix-")
    started = time.time()
    print("matrix: commit %s" % commit)
    print("matrix: runner %s (%s)" % (runner["version"], runner["realpath"]))
    print("matrix: runner digest %s" % runner["digest"])
    print("matrix: farm %s" % runner["farm"])
    print(
        "matrix: qemu %s (%s)"
        % (runner["qemu_version"], runner["qemu_path"])
    )
    print(
        "matrix: virtme-run %s (%s)"
        % (runner["virtme_run_version"], runner["virtme_run_path"])
    )
    print(
        "matrix: lanes %s"
        % ", ".join(
            "%s/%s" % (lane["id"], lane["kernel_release"]) for lane in lanes
        )
    )
    print("matrix: logs at %s" % out_dir)
    sys.stdout.flush()

    results = []
    for lane in lanes:
        for suite_id, relpath, suite_timeout in suites:
            timeout = args.timeout or suite_timeout
            print(
                "matrix: lane=%s suite=%s timeout=%ds ..."
                % (lane["id"], suite_id, timeout)
            )
            sys.stdout.flush()
            record = run_suite(
                suite_id,
                relpath,
                lane,
                out_dir,
                timeout,
                commit,
                args.consumer_path,
                runner["farm"],
            )
            mid_commit = git_head()
            mid_dirt = git_clean()
            if mid_commit != commit or mid_dirt:
                record["outcome"] = "fail"
                record["note"] = (
                    "tree changed mid-run (commit %s, dirt %r); "
                    "same-bits guarantee broken" % (mid_commit, mid_dirt)
                )
            results.append(record)
            print(
                "matrix: lane=%s suite=%s outcome=%s "
                "(exit=%s passes=%d failures=%d envfailures=%d %.1fs)"
                % (
                    lane["id"],
                    suite_id,
                    record["outcome"],
                    record["exit_code"],
                    record["passes"],
                    record["failures"],
                    record["envfailures"],
                    record["elapsed_secs"] or 0,
                )
            )
            sys.stdout.flush()

    report = {
        "tool": "run_vm_tests",
        "commit": commit,
        "python": {
            "executable": sys.executable,
            "version": sys.version.split()[0],
        },
        "consumer_path": list(args.consumer_path),
        "runner": runner_report(runner),
        "lanes": [
            {
                "id": lane["id"],
                "release": lane["release"],
                "accelerator": lane["accelerator"],
                "kernel_release": lane["kernel_release"],
                "cache": caches[lane["id"]],
            }
            for lane in lanes
        ],
        "results": results,
        "elapsed_secs": round(time.time() - started, 1),
    }
    report_path = os.path.join(out_dir, "matrix-report.json")
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")

    print("matrix board (commit %s):" % commit)
    for lane in lanes:
        row = []
        for suite_id, _relpath, _timeout in suites:
            match = [
                item
                for item in results
                if item["lane"] == lane["id"] and item["suite"] == suite_id
            ][0]
            row.append("%s=%s" % (suite_id, match["outcome"]))
        print("  %s: %s" % (lane["id"], " ".join(row)))
    print("matrix report: %s" % report_path)
    bad = [item for item in results if item["outcome"] != "pass"]
    if bad:
        print(
            "matrix: %d/%d lane-suites failed (%s)"
            % (
                len(bad),
                len(results),
                ", ".join(
                    "%s/%s=%s"
                    % (item["lane"], item["suite"], item["outcome"])
                    for item in bad
                ),
            )
        )
        return EXIT_FAILURE
    print("matrix: %d/%d lane-suites passed" % (len(results), len(results)))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
