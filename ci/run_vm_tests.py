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

The external-consumer suite builds with an independently installed
toolchain that must resolve outside the checkout; ``--consumer-path``
prepends directories to PATH for that suite only (every other suite
uses the ambient toolchain). Without it the consumer suite fails on
its own isolation gate -- never skipped, never faked.

Exit codes: 0 when every selected suite passed in every selected
lane; 1 when any suite failed or reported an environment failure;
2 for setup problems (dirty tree, runner mismatch, missing lane
cache, bad lockfile). Skips never occur: an unrun lane or suite is a
failure, not a pass.

Standard library only.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_LOCK = os.path.join(REPO_ROOT, "ci", "kernels.lock.json")

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
    for key in ("version", "sha256"):
        if not runner.get(key):
            raise SetupFailure("lockfile runner lacks %s" % key)
    lanes = lock.get("lanes")
    if not isinstance(lanes, list) or len(lanes) < 2:
        raise SetupFailure("lockfile must pin at least two lanes")
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
        if lane["vng_argv_prefix"][:3] != ["vng", "--run", lane["release"]]:
            raise SetupFailure(
                "lane %r argv prefix does not match its release"
                % lane.get("id")
            )
    return lock


def check_runner(lock):
    import shutil

    path = shutil.which("vng")
    if path is None:
        raise SetupFailure("vng not found on PATH")
    realpath = os.path.realpath(path)
    try:
        completed = subprocess.run(
            [path, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SetupFailure("vng version probe failed: %s" % exc)
    version = ((completed.stdout or "") + (completed.stderr or "")).strip()
    version = version.splitlines()[0] if version else ""
    digest = sha256_file(realpath)
    expected = lock["runner"]
    if version != expected["version"]:
        raise SetupFailure(
            "vng version %r does not match the lock (%r)"
            % (version, expected["version"])
        )
    if digest != expected["sha256"]:
        raise SetupFailure(
            "vng at %s (sha256 %s) does not match the lock"
            % (realpath, digest)
        )
    return {"path": path, "realpath": realpath, "version": version}


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
              consumer_path):
    """Run one suite in one lane; return its result record.

    The suite runs as a session leader, so a timeout kills the
    whole owned suite tree (the suite group plus any detached
    guest groups the suite booted), never just the suite child.
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
    if suite_id == "packaging-consumer" and consumer_path:
        env["PATH"] = os.pathsep.join(
            list(consumer_path) + [env.get("PATH", "")]
        )
    log_path = os.path.join(
        out_dir, "%s.%s.log" % (lane["id"], suite_id)
    )
    record["log"] = log_path
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
    record["elapsed_secs"] = round(time.monotonic() - start, 1)
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(
            "matrix: suite=%s lane=%s release=%s commit=%s\n"
            % (suite_id, lane["id"], lane["release"], commit)
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
    elif record["exit_code"] == 0 and record["passes"] > 0:
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
        runner = check_runner(lock)
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
        "runner": runner,
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
