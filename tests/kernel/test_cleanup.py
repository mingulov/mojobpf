# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Reproducibility, restricted-environment, and cleanup proofs.

This suite owns three behaviors of the load-and-unload workflow:

* Reproducible builds: the same pinned inputs built in two clean
  absolute paths produce byte-identical objects, both through the
  direct frontend/adapter/backend pipeline and through a manifest
  ``mojobpf build``. Stage paths must not leak into object bytes.
* Restricted environments: a load without privilege, a BTF-carrying
  object without kernel BTF, a program type the guest kernel lacks,
  and a guest command that exceeds its budget each produce their own
  accurate ``unavailable``/``timeout`` result -- never a pass, never
  a crash.
* Cleanup: repeated load/test/unload cycles leave the owned guest
  resources (programs, maps, links, pins) exactly as found, and
  interrupting the wrapper mid-run (SIGTERM) or killing its runner
  child (SIGKILL) reaps the whole runner group with no stray host
  emulator processes. Stray detection is neighbor-safe: only
  processes this test spawned count (owned stage path in cmdline
  or live descendant of a test-spawned pid); other host runners
  are reported, never asserted on, never signalled.

It also proves the wrapper's loader-versus-verifier classification
with real failing inputs: a truncated object and a non-ELF file
classify as ``loader``, while a Mojo-authored out-of-bounds store
(which the genuine pipeline builds but the kernel verifier rejects)
classifies as ``verifier`` with its predicted log line.

Every kernel interaction goes through the real ``mojobpf verify
--kernel`` command (checkout CLI) or the frozen test-run harness
(contract revision 2, used as-is) inside disposable guests. Nothing
here attaches a hook, runs a live workload, or loads on the host.

Requires working ``mojo``/``llc``, ``vng`` (virtme-ng) with a
cached guest image on PATH (default release v6.12;
MOJOBPF_VNG_RELEASE selects the matrix lane), and an unprivileged
``nobody`` account in the guest. Missing tools fail loudly as
environment failures, never as passes.

Runnable directly (``python3 tests/kernel/test_cleanup.py``) or
under any ``test_``-style runner. Standard library only.
"""

import difflib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(
    0, os.path.join(REPO_ROOT, "tests", "harness")
)
import guest_proc  # noqa: E402
import lane_lock  # noqa: E402
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402
EXAMPLE_DIR = os.path.join(REPO_ROOT, "examples", "xdp_pass")
CLASSIFIER_SOURCE = os.path.join(EXAMPLE_DIR, "xdp_pass.mojo")
MAP_SOURCE = os.path.join(REPO_ROOT, "tests", "compile", "map_roundtrip.mojo")
OOB_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "subset", "subset_oob_store.mojo"
)
CONSUMER_DIR = os.path.join(
    REPO_ROOT, "tests", "packaging", "external_consumer"
)
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")
SDK_INCLUDE = os.path.join(
    REPO_ROOT, "src", "mojobpf", "resources", "sdk"
)

# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = 900

XDP_DROP = 1
XDP_PASS = 2

# Pinned genuine-pipeline object hashes (the feasibility baseline):
# reproducibility must reproduce these exact bytes, not merely agree
# with itself.
EXPECTED_CLASSIFIER_OBJECT = (
    "17570ee79a16b64ccc4f723d00d26ae316a286cffdd3382ba3a6e6b4be95097c"
)
EXPECTED_MAP_OBJECT = (
    "18f7490634c6462360aafcb1ece85406b2374b4b74a2ca4501f90b5781e8a540"
)
EXPECTED_OOB_LOG_LINE = (
    "invalid access to map value, value_size=8 off=8 size=8"
)

# A real program type (probed by bpftool from its known list) that
# the pinned guest kernels do not support.
UNSUPPORTED_PROG_TYPE = "lirc_mode2"

REPEAT_CYCLES = 5


class EnvironmentFailure(Exception):
    """The toolchain or VM needed by this test is missing or broken."""


def sha256_file(path):
    import hashlib

    digest = hashlib.sha256()
    with guest_proc.open_consumed(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_step(argv, timeout=600, env=None, cwd=None):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        env=env,
        cwd=cwd,
    )


def check_tools():
    for tool in ("mojo", "llc", "vng"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (
        CLASSIFIER_SOURCE,
        MAP_SOURCE,
        OOB_SOURCE,
        ADAPTER,
        HARNESS,
        os.path.join(CONSUMER_DIR, "mojobpf.toml"),
        os.path.join(CONSUMER_DIR, "canary.mojo"),
    ):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK directory: %s" % SDK_INCLUDE)


@guest_proc.consumes_source
def build_object(source, workdir, name, include_sdk):
    """Build one object through the genuine pipeline."""
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    object_path = os.path.join(workdir, name + ".bpf.o")
    frontend = ["mojo", "build", "--emit", "llvm", *FRONTEND_TARGET_FLAGS]
    if include_sdk:
        frontend += ["-I", SDK_INCLUDE]
    frontend += ["-o", raw_path, source]
    proc = run_step(frontend)
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise AssertionError(
            "frontend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    if "error:" in proc.stderr.lower() or "warning:" in proc.stderr.lower():
        raise AssertionError(
            "frontend diagnostics for %s:\n%s" % (source, proc.stderr)
        )
    proc = run_step(
        [sys.executable, ADAPTER, "--input", raw_path, "--output", adapted_path]
    )
    if proc.returncode != 0 or not os.path.isfile(adapted_path):
        raise AssertionError(
            "adapter failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    proc = run_step(
        [
            "llc",
            "-mtriple=bpfel",
            "-mcpu=v3",
            "-filetype=obj",
            adapted_path,
            "-o",
            object_path,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "backend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    return {
        "raw": raw_path,
        "adapted": adapted_path,
        "object": object_path,
    }


_FIXTURE = {}


def fixture():
    """Build the shared objects once per process; return their paths."""
    if "stage" in _FIXTURE:
        return _FIXTURE
    check_tools()
    stage = guest_proc.owned_stage(prefix="mojo-cleanup-", dir="/tmp")
    _OWNED_STAGES.add(stage)
    built = {}
    built["classifier"] = build_object(
        CLASSIFIER_SOURCE, stage, "classifier", include_sdk=False
    )
    built["map"] = build_object(
        MAP_SOURCE, stage, "map", include_sdk=True
    )
    built["oob"] = build_object(
        OOB_SOURCE, stage, "oob", include_sdk=True
    )
    with guest_proc.open_consumed(built["classifier"]["object"], "rb") as handle:
        head = handle.read(300)
    trunc_path = os.path.join(stage, "truncated.bpf.o")
    with open(trunc_path, "wb") as handle:
        handle.write(head)
    text_path = os.path.join(stage, "not-an-object.txt")
    with open(text_path, "w", encoding="utf-8") as handle:
        handle.write("this file is not an ELF object\n")
    for fixture_name in ("pkt_drop.bin", "pkt_pass.bin"):
        with guest_proc.open_consumed(os.path.join(EXAMPLE_DIR, fixture_name), "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, fixture_name), "wb") as handle:
            handle.write(data)
    # The repeat case consumes this staged copy: it must exist
    # before any begin_case seals the inputs (a case body that
    # rewrites the identical bytes afterwards still verifies).
    with guest_proc.open_consumed(built["classifier"]["object"], "rb") as handle:
        repeat_data = handle.read()
    with open(os.path.join(stage, "repeat.bpf.o"), "wb") as handle:
        handle.write(repeat_data)
    for name in os.listdir(stage):
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    # Consumption seal: hash the staged inputs before any case
    # body executes against them (this fixture only stages;
    # guests boot per case in the bodies below).
    guest_proc.consume_declared_inputs(stage)
    _FIXTURE.update(
        {
            "stage": stage,
            "built": built,
            "truncated": trunc_path,
            "text": text_path,
        }
    )
    return _FIXTURE


def cli_env():
    """Environment that runs the checkout CLI without installing it."""
    env = dict(os.environ)
    src_dir = os.path.join(REPO_ROOT, "src")
    previous = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        src_dir if not previous else src_dir + os.pathsep + previous
    )
    return env


def verify_cli(extra_args, timeout=600):
    """Run the real ``mojobpf verify --kernel``; return (exit, record).

    ``record`` is the parsed JSON result (``--json`` is always
    passed); the raw outputs ride along as ``_stdout``/``_stderr``.
    The verify command boots a disposable guest, so it needs
    the target lease up front: without one this refuses before
    any process starts (the main loop reports the case
    required-unavailable), exactly like the guarded guest
    entrypoint. This changes only admission, never the
    verify --kernel no-live-attach contract.
    """
    guest_proc.require_target_lease("mojobpf verify --kernel")
    argv = [
        sys.executable,
        "-m",
        "mojobpf.cli",
        "verify",
        "--kernel",
        "--release",
        VNG_RELEASE,
        "--json",
    ] + list(extra_args)
    with guest_proc.consumed_arguments(
            argv, ("--object", "--data-in")) as consumed_argv:
        proc = run_step(consumed_argv, timeout=timeout,
                        env=cli_env(), cwd=REPO_ROOT)
    try:
        record = json.loads(proc.stdout)
    except ValueError:
        raise guest_proc.GuestMissing(
            "verify printed invalid JSON (exit %d):\nstdout:\n%s\nstderr:\n%s"
            % (proc.returncode, proc.stdout[-2000:], proc.stderr[-2000:])
        )
    record["_exit"] = proc.returncode
    record["_stderr"] = proc.stderr
    if record.get("stage_path"):
        _OWNED_STAGES.add(record["stage_path"])
    return proc.returncode, record


def guest_exec(script_text, name, timeout=VNG_TIMEOUT):
    """Boot one guest running ``script_text``; return the transcript.

    Thin mapping over the shared owned runner
    (tests/harness/guest_proc.py): a timeout surfaces as
    EnvironmentFailure carrying the partial output. Each call
    saves its own stage log (success and partial alike), since
    one fixture stage hosts several calls.
    """
    fix = fixture()
    script_path = os.path.join(fix["stage"], name)
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script_text)
    os.chmod(script_path, 0o644)
    try:
        returncode, output = guest_proc.run_owned(
            ["vng", "--run", VNG_RELEASE, "--disable-kvm",
             "--exec", "bash %s" % script_path],
            fix["stage"], timeout,
            log_name=name + ".log",
        )
    except guest_proc.GuestTimeout as exc:
        raise EnvironmentFailure(
            "vng guest run timed out after %ds (stage %s):\n%s"
            % (timeout, fix["stage"], exc.output[-4000:])
        )
    verdict = guest_proc.classify_guest_exit(
        returncode, output,
        records=(),
        progress_banner="=== begin guest_repeat ===",
    )
    if verdict == "proof":
        raise AssertionError(
            "vng guest run failed with proof evidence "
            "(exit %d, stage %s):\n%s"
            % (returncode, fix["stage"], output[-4000:])
        )
    if verdict == "env":
        raise EnvironmentFailure(
            "vng guest run failed (exit %d, stage %s):\n%s"
            % (returncode, fix["stage"], output[-4000:])
        )
    return output


def live_processes():
    """Snapshot live (non-zombie) host processes as {pid: cmdline}."""
    found = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % entry, encoding="utf-8") as handle:
                fields = handle.read().rsplit(")", 1)
            with open(
                "/proc/%s/cmdline" % entry, "rb"
            ) as handle:
                cmdline = handle.read().replace(b"\x00", b" ").decode(
                    "utf-8", "replace"
                )
        except OSError:
            continue
        if len(fields) != 2:
            continue
        state = fields[1].split()[0] if fields[1].split() else ""
        if state in ("Z", "X"):
            continue
        found[int(entry)] = cmdline
    return found


def runner_pids(snapshot):
    """Pids in a snapshot whose cmdline looks like a guest runner.

    Host-wide and neighbor-unsafe by design: informational census
    only, never asserted on and never signalled. Assertions use
    owned_runner_pids() below.
    """
    return {
        pid
        for pid, cmdline in snapshot.items()
        if "qemu-system-" in cmdline
        or "vng --run" in cmdline
        or "virtme-run" in cmdline
    }


# Owned-process tracking (neighbor-safe stray detection).
#
# The host may run other projects' guests whose vng/qemu/virtme-run
# cmdlines are indistinguishable by token alone, so stray/runner
# assertions must only consider processes THIS test process spawned.
# A pid counts as an owned runner iff its cmdline carries a runner
# token AND either (a) a stage path this test owns appears in its
# cmdline, (b) it is a live descendant of a test-spawned pid (ppid
# walk up to a recorded root), (c) its process group is a recorded
# owned runner group (orphaning keeps the group id), or (d) it was
# recorded as an owned runner while alive (starttime-pinned, so pid
# reuse cannot promote a foreigner). This test never signals a pid
# that fails this check.
_RUNNER_TOKENS = ("qemu-system-", "vng --run", "virtme-run")

_OWNED_STAGES = set()
_OWNED_ROOTS = {os.getpid()}
_OWNED_GROUPS = set()
_OWNED_PIDS = {}


def _proc_stat_part(pid, index):
    try:
        with open("/proc/%d/stat" % pid, encoding="utf-8") as handle:
            fields = handle.read().rsplit(")", 1)
    except OSError:
        return None
    if len(fields) != 2:
        return None
    parts = fields[1].split()
    if len(parts) <= index:
        return None
    return parts[index]


def _ppid_of(pid):
    try:
        return int(_proc_stat_part(pid, 1))
    except (TypeError, ValueError):
        return None


def _pgrp_of(pid):
    try:
        return int(_proc_stat_part(pid, 2))
    except (TypeError, ValueError):
        return None


def _starttime_of(pid):
    return _proc_stat_part(pid, 19)


def _cmdline_of(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as handle:
            data = handle.read()
    except OSError:
        return None
    return data.replace(b"\x00", b" ").decode("utf-8", "replace")


def _is_live_descendant(pid):
    seen = set()
    current = _ppid_of(pid)
    while current is not None and current not in seen:
        if current in _OWNED_ROOTS:
            return True
        if current <= 1:
            return False
        seen.add(current)
        current = _ppid_of(current)
    return False


def _is_owned_runner(pid, cmdline):
    if not any(token in cmdline for token in _RUNNER_TOKENS):
        return False
    for stage in _OWNED_STAGES:
        if stage in cmdline:
            return True
    if _is_live_descendant(pid):
        return True
    pgrp = _pgrp_of(pid)
    if pgrp is not None and pgrp in _OWNED_GROUPS:
        return True
    pinned = _OWNED_PIDS.get(pid)
    return pinned is not None and pinned == _starttime_of(pid)


def owned_runner_pids(snapshot):
    """Pids in a snapshot that are runners THIS test spawned."""
    return {
        pid
        for pid, cmdline in snapshot.items()
        if _is_owned_runner(pid, cmdline)
    }


def _record_owned_tree():
    """Pin every live owned runner pid, starttime, and group."""
    for pid in owned_runner_pids(live_processes()):
        starttime = _starttime_of(pid)
        if starttime is not None:
            _OWNED_PIDS[pid] = starttime
        pgrp = _pgrp_of(pid)
        if pgrp is not None:
            _OWNED_GROUPS.add(pgrp)


def _stray_census(before_owned, wide_before):
    """Owned survivors to assert on, plus an informational census."""
    snapshot = live_processes()
    owned_now = owned_runner_pids(snapshot)
    wide_now = runner_pids(snapshot)
    line = (
        "runner census: owned %d -> %d, host-wide foreign %d -> %d "
        "(foreigners informational only)"
        % (
            len(before_owned),
            len(owned_now),
            len(wide_before - before_owned),
            len(wide_now - owned_now),
        )
    )
    return owned_now - before_owned, line


def fd_count():
    return len(os.listdir("/proc/self/fd"))


def assert_guest_lane(record, where):
    kernel = (record.get("guest") or {}).get("kernel") or ""
    try:
        lane_lock.check_booted_kernel(kernel, REPO_ROOT, VNG_RELEASE)
    except lane_lock.LaneLockError as exc:
        raise AssertionError("%s: %s" % (where, exc))
    return kernel


def assert_no_never_tokens(commands, where):
    never = (
        "attach",
        "detach",
        "prog run",
        "link pin",
        "map pin",
        "net attach",
        "tc filter",
        "test-run",
    )
    for command in commands:
        for token in never:
            assert token not in command, (
                "%s: guest command carries forbidden %r: %r"
                % (where, token, command)
            )


def test_reproducible_two_paths():
    """Same pinned inputs in two clean paths: identical objects."""
    fix = fixture()
    dir_a = tempfile.mkdtemp(prefix="t016-a-")
    deep = tempfile.mkdtemp(prefix="t016-b-much-longer-prefix-")
    dir_b = os.path.join(deep, "nested", "deeper")
    os.makedirs(dir_b)
    assert len(os.path.abspath(dir_b)) > len(
        os.path.abspath(dir_a)
    ) + 20, "the two paths must differ in length too"
    try:
        for key, source, include_sdk, expected in (
            (
                "classifier",
                CLASSIFIER_SOURCE,
                False,
                EXPECTED_CLASSIFIER_OBJECT,
            ),
            ("map", MAP_SOURCE, True, EXPECTED_MAP_OBJECT),
        ):
            built_a = build_object(source, dir_a, key, include_sdk)
            built_b = build_object(source, dir_b, key, include_sdk)
            hash_a = sha256_file(built_a["object"])
            hash_b = sha256_file(built_b["object"])
            assert hash_a == hash_b, (
                "%s: %s (%s) != %s (%s)"
                % (key, hash_a, dir_a, hash_b, dir_b)
            )
            assert hash_a == expected, (
                "%s: reproduced %s, feasibility pin is %s"
                % (key, hash_a, expected)
            )
            # The shared fixture object must equal the same bytes:
            # one pipeline, one answer, however many directories.
            assert sha256_file(fix["built"][key]["object"]) == expected, (
                "%s: fixture object drifted from the pin" % key
            )
            with guest_proc.open_consumed(built_a["object"], "rb") as handle:
                image = handle.read()
            for path in (
                os.path.abspath(dir_a),
                os.path.abspath(dir_b),
            ):
                assert path.encode() not in image, (
                    "%s: stage path leaks into object bytes: %s" % (key, path)
                )
            print(
                "PASS two-path %s identical: %s (ir %s/%s)" % (
                    key,
                    hash_a[:16],
                    sha256_file(built_a["raw"])[:12],
                    sha256_file(built_a["adapted"])[:12],
                )
            )
    finally:
        shutil.rmtree(dir_a, ignore_errors=True)
        shutil.rmtree(deep, ignore_errors=True)


def test_reproducible_manifest_build():
    """A manifest build in two clean paths: identical objects."""
    check_tools()
    roots = []
    objects = []
    sidecars = []
    try:
        for index in range(2):
            root = tempfile.mkdtemp(
                prefix="t016-manifest-%d-with-a-longer-tail-" % index
            )
            roots.append(root)
            project = os.path.join(root, "project")
            out_dir = os.path.join(root, "out")
            os.makedirs(project)
            captured = {}
            for name in ("mojobpf.toml", "canary.mojo"):
                with guest_proc.open_consumed(
                    os.path.join(CONSUMER_DIR, name), "rb"
                ) as handle:
                    data = handle.read()
                captured[name] = data
                with open(os.path.join(project, name), "wb") as handle:
                    handle.write(data)
            proc = run_step(
                [
                    sys.executable,
                    "-m",
                    "mojobpf.cli",
                    "build",
                    "--manifest",
                    os.path.join(project, "mojobpf.toml"),
                    "--out-dir",
                    out_dir,
                    "--lockfile",
                    os.path.join(REPO_ROOT, "toolchains.lock.json"),
                ],
                timeout=900,
                env=cli_env(),
                cwd=REPO_ROOT,
            )
            assert proc.returncode == 0, (
                "manifest build %d failed (exit %d):\n%s\n%s"
                % (index, proc.returncode, proc.stdout, proc.stderr)
            )
            found = sorted(
                entry
                for entry in os.listdir(out_dir)
                if entry.endswith(".bpf.o")
            )
            assert len(found) == 1, (index, found)
            objects.append(os.path.join(out_dir, found[0]))
            sidecar = os.path.join(
                out_dir, found[0].replace(".bpf.o", ".evidence.json")
            )
            assert os.path.isfile(sidecar), (index, os.listdir(out_dir))
            with guest_proc.open_consumed(sidecar, "rb") as handle:
                guest_proc.verify_captured_project_inputs(
                    handle.read(), manifest=("mojobpf.toml", captured["mojobpf.toml"]),
                    sources=[("canary.mojo", captured["canary.mojo"])],
                )
            sidecars.append(sidecar)
        hash_0 = sha256_file(objects[0])
        hash_1 = sha256_file(objects[1])
        assert hash_0 == hash_1, (hash_0, hash_1)
        with guest_proc.open_consumed(objects[0], "rb") as handle:
            image = handle.read()
        for root in roots:
            assert os.path.abspath(root).encode() not in image, (
                "build root leaks into object bytes: %s" % root
            )
            assert os.path.abspath(root).encode() not in guest_proc.open_consumed(
                sidecars[0], "rb"
            ).read(), "build root leaks into sidecar bytes: %s" % root
        # The evidence sidecar carries no absolute build paths, so it
        # is identical too -- stronger than the object-only rule.
        sidecar_0 = sha256_file(sidecars[0])
        sidecar_1 = sha256_file(sidecars[1])
        assert sidecar_0 == sidecar_1, (sidecar_0, sidecar_1)
        print(
            "PASS manifest two-path identical: object %s sidecar %s"
            % (hash_0[:16], sidecar_0[:16])
        )
    finally:
        for root in roots:
            shutil.rmtree(root, ignore_errors=True)


def test_verify_load_unload_pass():
    """Positive control: the wrapper loads and unloads, then proves it."""
    fix = fixture()
    expected = sha256_file(fix["built"]["classifier"]["object"])
    exit_code, record = verify_cli(
        ["--object", fix["built"]["classifier"]["object"]]
    )
    guest_proc.check_harness_exit(
        "pass", exit=record["_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["status"] == "pass", record["status"]
    assert record["stage"] == "done", record["stage"]
    assert record["classification"] is None, record["classification"]
    assert record["object"]["sha256"] == expected, "hash must match inputs"
    kernel = assert_guest_lane(record, "pass control")
    assert record["guest"]["btf"] == "present", record["guest"]
    assert record["guest"]["prog_type_supported"] is True, record["guest"]
    assert record["load"]["attempted"] is True, record["load"]
    assert record["load"]["exit"] == 0, record["load"]
    assert record["unload"]["attempted"] is True, record["unload"]
    assert record["unload"]["pin_absent"] is True, record["unload"]
    assert record["unload"]["quiesced"] is True, record["unload"]
    print(
        "unload quiesced after %s polls"
        % (record["unload"]["quiesce_waits"],)
    )
    commands = record["guest_commands"]
    assert any("prog load" in item for item in commands), commands
    assert any(item.startswith("rm -f ") for item in commands), commands
    assert_no_never_tokens(commands, "pass control")
    res_before = record["resources"]["before"] or ""
    res_after = record["resources"]["after"] or ""
    assert "mojobpf" not in res_before, res_before
    assert "mojobpf" not in res_after, res_after
    if res_before != res_after:
        diff = "".join(
            difflib.unified_diff(
                res_before.splitlines(True),
                res_after.splitlines(True),
                "res-before",
                "res-after",
            )
        )
        raise AssertionError(
            "a lone load/unload must leave guest resources unchanged:\n%s"
            % diff
        )
    print("PASS load/unload on %s, %d guest commands" % (kernel, len(commands)))


def test_verify_loader_classification():
    """Real unloadable inputs classify as loader (exit 5), twice."""
    fix = fixture()
    hints = []
    for label, path in (
        ("truncated", fix["truncated"]),
        ("text", fix["text"]),
    ):
        exit_code, record = verify_cli(["--object", path])
        hints.append(guest_proc.check_harness_exit(
            "loader-%s" % label, exit=record["_exit"],
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=5))
        assert record["status"] == "load-failed", (label, record["status"])
        assert record["stage"] == "load", (label, record["stage"])
        assert record["classification"] == "loader", (
            label, record["classification"], record["load"],
        )
        assert record["load"]["attempted"] is True, (label, record["load"])
        assert record["load"]["exit"] != 0, (label, record["load"])
        assert record["unload"]["attempted"] is False, (label, record)
        assert_guest_lane(record, label)
        print(
            "PASS loader %s: exit=%s log=%r" % (
                label,
                record["load"]["exit"],
                (record["load"]["log_excerpt"] or "").splitlines()[:1],
            )
        )
    return guest_proc.combine_outcomes(*hints)


def test_verify_verifier_classification():
    """A Mojo oob store classifies as verifier (exit 4) with its line."""
    fix = fixture()
    exit_code, record = verify_cli(
        ["--object", fix["built"]["oob"]["object"]]
    )
    hint = guest_proc.check_harness_exit(
        "verifier", exit=record["_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=4)
    assert record["status"] == "load-failed", record["status"]
    assert record["stage"] == "load", record["stage"]
    assert record["classification"] == "verifier", (
        record["classification"], record["load"],
    )
    assert record["load"]["attempted"] is True, record["load"]
    assert record["unload"]["attempted"] is False, record
    assert_guest_lane(record, "verifier proof")
    log = record["load"]["log_excerpt"] or ""
    assert EXPECTED_OOB_LOG_LINE in log, (
        "kernel verifier log must carry the predicted line:\n%s" % log[-2000:]
    )
    print("PASS verifier rejection carries %r" % EXPECTED_OOB_LOG_LINE)
    return hint


def test_unprivileged_load_unavailable():
    """A load without privilege: environment, never a pass."""
    fix = fixture()
    exit_code, record = verify_cli(
        [
            "--object",
            fix["built"]["classifier"]["object"],
            "--as-user",
            "nobody",
        ]
    )
    guest_proc.check_harness_exit(
        "unprivileged", exit=record["_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect_environment=True)
    assert record["status"] == "load-failed", record["status"]
    assert record["stage"] == "load", record["stage"]
    assert record["classification"] == "environment", (
        record["classification"], record["load"],
    )
    assert record["load"]["attempted"] is True, record["load"]
    assert record["load"]["exit"] != 0, record["load"]
    assert record["unload"]["attempted"] is False, record
    assert_guest_lane(record, "unprivileged")
    # The guest itself runs privileged; only the load dropped to
    # nobody (the recorded guest command proves which side ran as
    # whom).
    assert record["guest"]["id"] == "0:0", record["guest"]
    assert any("setpriv" in item for item in record["guest_commands"]), (
        record["guest_commands"]
    )
    print("PASS unprivileged load denied as environment")


def test_missing_btf_unavailable():
    """A BTF object without kernel BTF: unavailable; policy proven."""
    fix = fixture()
    # The refusal: a .BTF-carrying object with no kernel BTF at the
    # checked path is unavailable, and no load is attempted.
    exit_code, record = verify_cli(
        [
            "--object",
            fix["built"]["map"]["object"],
            "--kernel-btf",
            "/nonexistent-btf-for-test",
        ]
    )
    guest_proc.check_harness_exit(
        "missing-btf", exit=record["_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect_environment=True)
    assert record["status"] == "unavailable", record["status"]
    assert record["stage"] == "preflight", record["stage"]
    assert record["classification"] == "environment", record["classification"]
    assert record["preflight"]["unavailable_reason"] == "missing-btf", (
        record["preflight"]
    )
    assert record["load"]["attempted"] is False, record["load"]
    assert record["guest"]["btf"] == "absent", record["guest"]
    assert_guest_lane(record, "missing-btf")
    # Auto mode only requires BTF for objects that carry BTF
    # sections: the classifier (no .BTF) proceeds on the same path.
    exit_code, record = verify_cli(
        [
            "--object",
            fix["built"]["classifier"]["object"],
            "--kernel-btf",
            "/nonexistent-btf-for-test",
        ]
    )
    guest_proc.check_harness_exit(
        "missing-btf-classifier", exit=record["_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["status"] == "pass", record["status"]
    assert (
        record["preflight"]["require_btf_effective"] is False
    ), record["preflight"]
    # The refusal is wrapper policy, not a kernel verdict: with the
    # requirement lifted the same BTF object loads (the kernel
    # accepts BTF-annotated loads without its own BTF -- observed).
    exit_code, record = verify_cli(
        [
            "--object",
            fix["built"]["map"]["object"],
            "--kernel-btf",
            "/nonexistent-btf-for-test",
            "--require-btf",
            "no",
        ]
    )
    guest_proc.check_harness_exit(
        "missing-btf-no-require", exit=record["_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect=0)
    assert record["status"] == "pass", record["status"]
    print("PASS missing-btf unavailable; auto/no semantics proven")


def test_unsupported_prog_type_unavailable():
    """A program type the kernel lacks: unavailable, no load."""
    fix = fixture()
    exit_code, record = verify_cli(
        [
            "--object",
            fix["built"]["classifier"]["object"],
            "--prog-type",
            UNSUPPORTED_PROG_TYPE,
        ]
    )
    guest_proc.check_harness_exit(
        "unsupported-prog-type", exit=record["_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect_environment=True)
    assert record["status"] == "unavailable", record["status"]
    assert record["stage"] == "preflight", record["stage"]
    assert record["classification"] == "environment", record["classification"]
    assert (
        record["preflight"]["unavailable_reason"] == "unsupported-prog-type"
    ), record["preflight"]
    assert record["load"]["attempted"] is False, record["load"]
    assert record["guest"]["prog_type_supported"] is False, record["guest"]
    # bpftool probed the type by name and reported it missing: this
    # is a real unsupported type, not a misspelled flag.
    probe = record["guest"]["probe_line"] or ""
    assert UNSUPPORTED_PROG_TYPE in probe, record["guest"]
    assert "NOT available" in probe, record["guest"]
    assert_guest_lane(record, "unsupported-prog-type")
    # Positive control on the same lane: xdp is supported.
    exit_code, control = verify_cli(
        [
            "--object",
            fix["built"]["classifier"]["object"],
            "--prog-type",
            "xdp",
        ]
    )
    guest_proc.check_harness_exit(
        "prog-type-xdp", exit=control["_exit"],
        classification=control.get("classification"),
        stage=control.get("stage"),
        contract_version=control.get("contract_version"),
        note=control.get("note"), expect=0)
    assert control["guest"]["prog_type_supported"] is True, control["guest"]
    print("PASS unsupported type refused; xdp control passes")


def test_harness_timeout():
    """A guest command past its budget: timeout, group reaped."""
    fix = fixture()
    snapshot = live_processes()
    before = owned_runner_pids(snapshot)
    wide_before = runner_pids(snapshot)
    exit_code, record = verify_cli(
        ["--object", fix["built"]["classifier"]["object"], "--timeout", "5"],
        timeout=300,
    )
    guest_proc.check_harness_exit(
        "timeout", exit=record["_exit"],
        classification=record.get("classification"),
        stage=record.get("stage"),
        contract_version=record.get("contract_version"),
        note=record.get("note"), expect_environment=True)
    assert record["status"] == "timeout", record["status"]
    assert record["stage"] == "run", record["stage"]
    assert record["classification"] == "environment", record["classification"]
    assert record["child"]["timed_out"] is True, record["child"]
    assert record["child"]["group_killed"] is True, record["child"]
    assert record["child"]["group_reaped"] is True, record["child"]
    members = record["child"]["group_members"] or []
    assert all(
        item["state"] in ("Z", "X") for item in members
    ), ("live group members after timeout kill", members)
    survivors, census = _stray_census(before, wide_before)
    print(census)
    assert not survivors, ("stray runner processes", survivors)
    print(
        "PASS timeout reaped the group (residual members: %s)" % (members,)
    )


REPEAT_GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin guest_repeat ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
sha256sum bpf_test_run.py repeat.bpf.o pkt_drop.bin pkt_pass.bin
snapshot() {{
  echo "--- progs ---"
  bpftool prog list 2>&1
  echo "--- maps ---"
  bpftool map list 2>&1
  echo "--- links ---"
  bpftool link list 2>&1
  echo "--- pins ---"
  ls /sys/fs/bpf/ 2>&1
}}
echo "=== BEGIN res-before ==="
snapshot
echo "=== END res-before ==="
FAILURES=0
for i in $(seq 1 {cycles}); do
  for case in drop:1:pkt_drop pass:2:pkt_pass; do
    tag="${{case%%:*}}"; rest="${{case#*:}}"; expect="${{rest%%:*}}"; data="${{rest#*:}}"
    out="/tmp/repeat-$tag-$i.json"
    python3 bpf_test_run.py --object repeat.bpf.o --expect-action "$expect" \\
      --data-in "$data.bin" --output "$out" >/tmp/repeat-$tag-$i.stdout 2>/tmp/repeat-$tag-$i.stderr
    code=$?
    echo "=== BEGIN cycle-$tag-$i exit=$code ==="
    cat "$out"
    echo "=== END cycle-$tag-$i ==="
    if [ "$code" -ne 0 ]; then FAILURES=$((FAILURES + 1)); fi
  done
  pin="/sys/fs/bpf/mojobpf_repeat_$i"
  bpftool prog load repeat.bpf.o "$pin" >/tmp/repeat-plain-$i.log 2>&1 || FAILURES=$((FAILURES + 1))
  rm -f "$pin"
  if [ -e "$pin" ]; then FAILURES=$((FAILURES + 1)); fi
done
echo "plain/harness failures: $FAILURES"
# Pin removal is synchronous, but the kernel may free programs
# asynchronously (observed: still listed for ~2s under emulation),
# so quiesce on stable listings before the after-snapshot.
QUIESCED=0
QUIESCE_WAITS=0
PREV="__unset__"
for i in $(seq 1 60); do
  QUIESCE_WAITS=$i
  if ls /sys/fs/bpf/mojobpf* >/dev/null 2>&1; then sleep 1; continue; fi
  CUR=$(bpftool prog list 2>&1; bpftool map list 2>&1; bpftool link list 2>&1)
  if [ "$PREV" != "__unset__" ] && [ "$CUR" = "$PREV" ]; then
    QUIESCED=1
    break
  fi
  PREV="$CUR"
  sleep 1
done
echo "quiesced=$QUIESCED"
echo "quiesce_waits=$QUIESCE_WAITS"
echo "=== BEGIN res-after ==="
snapshot
echo "=== END res-after ==="
echo "=== end guest_repeat ==="
"""


def test_repeated_load_unload_no_leak():
    """Repeated load/test/unload cycles: owned resources unchanged."""
    fix = fixture()
    snapshot = live_processes()
    before = owned_runner_pids(snapshot)
    wide_before = runner_pids(snapshot)
    stage = fix["stage"]
    for name, src in (
        ("bpf_test_run.py", HARNESS),
        ("repeat.bpf.o", fix["built"]["classifier"]["object"]),
    ):
        with guest_proc.open_consumed(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
        os.chmod(os.path.join(stage, name), 0o644)
    expected_obj = sha256_file(os.path.join(stage, "repeat.bpf.o"))
    expected_drop = sha256_file(os.path.join(stage, "pkt_drop.bin"))
    expected_pass = sha256_file(os.path.join(stage, "pkt_pass.bin"))
    output = guest_exec(
        REPEAT_GUEST_SCRIPT.format(stage=stage, cycles=REPEAT_CYCLES),
        "guest_repeat.sh",
    )
    try:
        observed_kernel = lane_lock.booted_kernel_from_output(output)
        lane_lock.check_booted_kernel(
            observed_kernel, REPO_ROOT, VNG_RELEASE
        )
    except lane_lock.LaneLockError as exc:
        raise AssertionError("guest kernel must be locked: %s" % exc)
    rec = guest_proc.active_recorder()
    if rec is not None:
        for name, digest in (
            ("repeat.bpf.o", expected_obj),
            ("pkt_drop.bin", expected_drop),
            ("pkt_pass.bin", expected_pass),
        ):
            assert rec.consumed_staged_digest(
                name, stage
            ) == digest, (
                "staged bytes changed between staging and "
                "seal: %s" % name
            )
        reported = guest_proc.parse_reported_hashes(output)
        for name, digest in (
            ("repeat.bpf.o", expected_obj),
            ("pkt_drop.bin", expected_drop),
            ("pkt_pass.bin", expected_pass),
        ):
            assert reported.get(name) == digest, (
                "guest must report the consumed bytes of %s" % name
            )
    else:
        for digest in (expected_obj, expected_drop, expected_pass):
            assert digest in output, (
                "guest must re-verify staged hash %s" % digest
            )
    cycles = {}
    for match in re.finditer(
        r"=== BEGIN (\S+) exit=(\d+) ===\n(.*?)\n=== END \1 ===",
        output,
        re.DOTALL,
    ):
        tag, exit_code, body = match.groups()
        try:
            record = json.loads(body)
        except ValueError:
            raise guest_proc.GuestMissing(
                "guest case %s produced invalid JSON (stage %s):\n%s"
                % (tag, stage, body[-1000:])
            )
        cycles[tag] = (int(exit_code), record)
    want = REPEAT_CYCLES * 2
    if len(cycles) != want:
        raise guest_proc.GuestMissing(
            "expected %d harness cycles, found %d" % (want, len(cycles))
        )
    for tag, (exit_code, record) in sorted(cycles.items()):
        guest_proc.check_harness_exit(
            tag, exit=exit_code,
            classification=record.get("classification"),
            stage=record.get("stage"),
            contract_version=record.get("contract_version"),
            note=record.get("note"), expect=0)
        assert record["status"] == "pass", (tag, record)
        assert record["cleanup_ok"] is True, (tag, record)
        assert record["contract_version"] == 2, (tag, record)
    assert "plain/harness failures: 0" in output, output[-2000:]
    assert "\nquiesced=1\n" in output, (
        "guest resources must quiesce after the cycles"
    )
    waits = re.search(r"^quiesce_waits=(\d+)$", output, re.MULTILINE)
    print("repeat quiesced after %s polls" % (waits.group(1) if waits else "?"))
    before_block = re.search(
        r"=== BEGIN res-before ===\n(.*?)\n=== END res-before ===",
        output,
        re.DOTALL,
    )
    after_block = re.search(
        r"=== BEGIN res-after ===\n(.*?)\n=== END res-after ===",
        output,
        re.DOTALL,
    )
    assert before_block and after_block, "guest must print both snapshots"
    res_before = before_block.group(1)
    res_after = after_block.group(1)
    assert "mojobpf" not in res_before, res_before
    assert "mojobpf" not in res_after, res_after
    if res_before != res_after:
        diff = "".join(
            difflib.unified_diff(
                res_before.splitlines(True),
                res_after.splitlines(True),
                "res-before",
                "res-after",
            )
        )
        raise AssertionError(
            "owned guest resources changed across %d cycles:\n%s"
            % (REPEAT_CYCLES, diff)
        )
    survivors, census = _stray_census(before, wide_before)
    print(census)
    assert not survivors, ("stray runner processes", survivors)
    print(
        "PASS %d harness + %d plain cycles, guest resources identical"
        % (want, REPEAT_CYCLES)
    )


def _spawn_wrapper(object_path, extra_args):
    # Same lease gate as verify_cli above: the wrapper boots a
    # disposable guest, so an unleased spawn refuses before any
    # process starts instead of reaching the execution
    # boundary with an empty environment.
    guest_proc.require_target_lease("mojobpf verify --kernel wrapper")
    argv = [
        sys.executable,
        "-m",
        "mojobpf.cli",
        "verify",
        "--kernel",
        "--release",
        VNG_RELEASE,
        "--timeout",
        "600",
        "--object",
        object_path,
    ] + list(extra_args)
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=cli_env(),
        cwd=REPO_ROOT,
        start_new_session=True,
    )
    _OWNED_ROOTS.add(proc.pid)
    return proc


def _wait_for_runner(baseline, timeout=180):
    """Wait for a new OWNED runner pid; return it.

    Only processes this test spawned are eligible, so a foreign
    runner can neither satisfy the wait nor be signalled by the
    caller.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        fresh = owned_runner_pids(live_processes()) - baseline
        if fresh:
            _record_owned_tree()
            return sorted(fresh)[0]
        time.sleep(1)
    raise EnvironmentFailure(
        "no guest runner appeared within %ds" % timeout
    )


def _wait_for_pids_gone(pids, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        live = {
            pid
            for pid in pids
            if os.path.isdir("/proc/%d" % pid)
            and _pid_state(pid) not in ("Z", "X")
        }
        if not live:
            return set()
        time.sleep(1)
    return live


def _pid_state(pid):
    try:
        with open("/proc/%d/stat" % pid, encoding="utf-8") as handle:
            fields = handle.read().rsplit(")", 1)
    except OSError:
        return None
    if len(fields) != 2 or not fields[1].split():
        return None
    return fields[1].split()[0]


def test_interrupt_sigterm_reaps():
    """SIGTERM mid-run: the wrapper exits 130 with no stray runners."""
    fix = fixture()
    snapshot = live_processes()
    baseline = owned_runner_pids(snapshot)
    wide_before = runner_pids(snapshot)
    fds_before = fd_count()
    proc = _spawn_wrapper(fix["built"]["classifier"]["object"], [])
    try:
        runner = _wait_for_runner(baseline)
        proc.send_signal(signal.SIGTERM)
        try:
            exit_code = proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            raise AssertionError(
                "wrapper ignored SIGTERM (runner was %d)" % runner
            )
        assert exit_code == 130, (
            "interrupted wrapper must exit 130, got %r" % (exit_code,)
        )
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    leftover = _wait_for_pids_gone({runner}, timeout=60)
    assert not leftover, ("runner survived the interrupt", leftover)
    survivors, census = _stray_census(baseline, wide_before)
    print(census)
    assert not survivors, ("stray runner processes", survivors)
    assert fd_count() == fds_before, "test leaked file descriptors"
    print("PASS SIGTERM reaped runner %d; exit 130, no strays" % runner)


def test_killed_child_no_hang():
    """A SIGKILLed runner child: the wrapper fails fast, no strays."""
    fix = fixture()
    snapshot = live_processes()
    baseline = owned_runner_pids(snapshot)
    wide_before = runner_pids(snapshot)
    proc = _spawn_wrapper(fix["built"]["classifier"]["object"], [])
    try:
        runner = _wait_for_runner(baseline)
        cmdline = _cmdline_of(runner)
        assert cmdline is not None and _is_owned_runner(
            runner, cmdline
        ), "refusing to signal a pid this test did not spawn: %d" % runner
        try:
            os.kill(runner, signal.SIGKILL)
        except ProcessLookupError:
            raise AssertionError("runner %d vanished before the kill" % runner)
        start = time.monotonic()
        try:
            exit_code = proc.wait(timeout=180)
        except subprocess.TimeoutExpired:
            raise AssertionError(
                "wrapper hung after its runner died (runner %d)" % runner
            )
        elapsed = time.monotonic() - start
        assert exit_code != 0, "wrapper must not pass a dead runner"
        assert exit_code in (2, 3), (
            "wrapper must fail as setup/environment, got %r" % (exit_code,)
        )
        assert elapsed < 120, (
            "wrapper must fail fast on a dead runner, took %.1fs" % elapsed
        )
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    leftover = _wait_for_pids_gone({runner}, timeout=60)
    assert not leftover, ("runner survived SIGKILL", leftover)
    survivors, census = _stray_census(baseline, wide_before)
    print(census)
    assert not survivors, ("stray runner processes", survivors)
    print(
        "PASS killed runner %d: wrapper exit %d, no strays, no hang"
        % (runner, exit_code)
    )


def test_owned_runner_classification():
    """Owned-runner rule, pinned without live guests.

    A runner cmdline carrying an owned stage path counts; the same
    tokens with a foreign path do not -- even for dead or unknown
    pids, so pid reuse can never promote a foreigner.
    """
    fix = fixture()
    owned_cmdline = (
        "vng --run %s --disable-kvm --exec bash %s/guest_verify.sh "
        % (VNG_RELEASE, fix["stage"])
    )
    assert _is_owned_runner(2**30 + 7, owned_cmdline), (
        "a runner cmdline with an owned stage must count"
    )
    foreign_cmdline = (
        "qemu-system-x86_64 -name virtme-ng -kernel "
        "/work/other-project/.virtme/guest/vmlinuz-6.12.0 "
    )
    assert not _is_owned_runner(2**30 + 9, foreign_cmdline), (
        "a foreign runner cmdline must never count"
    )
    print("PASS owned-runner classification pinned (stage/foreign)")


# The loader/verifier classification cases are denials: they
# expect the wire-derived FAIL at LOAD/VERIFY and pass only
# their own cell when the rejection is observed with evidence.
# They guard the load/unload positive control: the wrapper must
# accept the good object while observably refusing the bad ones,
# proving the classification is not vacuous.
CASE_DENIALS = {
    "test_verify_loader_classification": (
        "test_verify_load_unload_pass", "LOAD"
    ),
    "test_verify_verifier_classification": (
        "test_verify_load_unload_pass", "VERIFY"
    ),
}


# Durable inputs per case: repo sources plus the fixture-stage
# files each case consumes (resolved against the fixture stage
# at finish).
CASE_INPUTS = {
    "test_reproducible_two_paths": {
        "sources": [CLASSIFIER_SOURCE, MAP_SOURCE],
        "objects": [],
        "corpus": [],
    },
    "test_reproducible_manifest_build": {
        "sources": [
            os.path.join(CONSUMER_DIR, "mojobpf.toml"),
            os.path.join(CONSUMER_DIR, "canary.mojo"),
        ],
        "objects": [],
        "corpus": [],
    },
    "test_verify_load_unload_pass": {
        "sources": [CLASSIFIER_SOURCE],
        "objects": [("stage", "classifier.bpf.o")],
        "corpus": [],
    },
    "test_verify_loader_classification": {
        "sources": [
            CLASSIFIER_SOURCE,
            ("stage", "not-an-object.txt"),
        ],
        "objects": [("stage", "truncated.bpf.o")],
        "corpus": [],
    },
    "test_verify_verifier_classification": {
        "sources": [OOB_SOURCE],
        "objects": [("stage", "oob.bpf.o")],
        "corpus": [],
    },
    "test_unprivileged_load_unavailable": {
        "sources": [CLASSIFIER_SOURCE],
        "objects": [("stage", "classifier.bpf.o")],
        "corpus": [],
    },
    "test_missing_btf_unavailable": {
        "sources": [MAP_SOURCE, CLASSIFIER_SOURCE],
        "objects": [
            ("stage", "map.bpf.o"),
            ("stage", "classifier.bpf.o"),
        ],
        "corpus": [],
    },
    "test_unsupported_prog_type_unavailable": {
        "sources": [CLASSIFIER_SOURCE],
        "objects": [("stage", "classifier.bpf.o")],
        "corpus": [],
    },
    "test_harness_timeout": {
        "sources": [CLASSIFIER_SOURCE],
        "objects": [("stage", "classifier.bpf.o")],
        "corpus": [],
    },
    "test_repeated_load_unload_no_leak": {
        "sources": [CLASSIFIER_SOURCE, HARNESS],
        "objects": [("stage", "repeat.bpf.o")],
        "corpus": [
            ("stage", "pkt_drop.bin"),
            ("stage", "pkt_pass.bin"),
        ],
    },
    "test_interrupt_sigterm_reaps": {
        "sources": [CLASSIFIER_SOURCE],
        "objects": [("stage", "classifier.bpf.o")],
        "corpus": [],
    },
    "test_killed_child_no_hang": {
        "sources": [CLASSIFIER_SOURCE],
        "objects": [("stage", "classifier.bpf.o")],
        "corpus": [],
    },
    "test_owned_runner_classification": {
        "sources": [("impl", __file__)],
        "objects": [],
        "corpus": [],
    },
}


def _finish(rec, unavailable_seen=False):
    """Finish the typed suite against the cached fixture stage.

    This suite boots several guests (one transcript per
    guest_exec/verify_cli call), so there is no single transcript
    to attach; the fixture stage resolves the declared inputs.
    """
    code = rec.finish(
        stage_dir=_FIXTURE.get("stage"),
        unavailable_seen=unavailable_seen,
    )
    guest_proc.discard_owned_stages()
    return code


def main():
    names = sorted(k for k in globals() if k.startswith("test_"))
    rec = guest_proc.SuiteRecorder(
        suite_id="kernel-cleanup", suite_path=__file__,
        case_ids=names,
        denials=CASE_DENIALS, inputs=CASE_INPUTS,
        lane_release=VNG_RELEASE)
    # Attestation context: fixture consumption reads route
    # through this recorder from here (warmup included).
    guest_proc.set_active_recorder(rec)
    if not __debug__:
        return rec.finish_unrun(
            "must not run under python -O (asserts stripped)"
        )
    failures = 0
    unavailable_seen = False
    # Stage before any begin_case: the begin seals must observe
    # the staged input bytes (bytes first seen after begin can
    # never back a PASS), so warm the cached fixture here. A
    # warm failure is ignored: each case body retries and
    # records it per case below.
    try:
        fixture()
    except (
        EnvironmentFailure, guest_proc.HarnessEnvironment,
        AssertionError, subprocess.TimeoutExpired,
        guest_proc.TargetLeaseRequired,
    ):
        pass
    for name in names:
        func = globals()[name]
        rec.begin_case(name)
        try:
            hint = func()
        except guest_proc.HarnessEnvironment as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            rec.end_case_infra(name, exc.stage, exc.availability)
            return _finish(rec, unavailable_seen)
        except EnvironmentFailure as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            rec.end_case_infra(name, "INFRA", "UNKNOWN")
            return _finish(rec, unavailable_seen)
        except subprocess.TimeoutExpired as exc:
            print("ENVIRONMENT FAILURE in %s: timed out: %s" % (name, exc))
            rec.end_case_infra(name, "INFRA", "TOOLCHAIN_UNAVAILABLE")
            return _finish(rec, unavailable_seen)
        except guest_proc.TargetLeaseRequired as exc:
            print("REQUIRED-UNAVAILABLE %s: %s" % (name, exc))
            rec.end_case_not_run(name, "TARGET_RESOURCE_ABSENT")
            unavailable_seen = True
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            rec.end_case_fail(name)
            failures += 1
        else:
            print("PASS %s" % name)
            rec.end_case_hint(name, hint)
    if failures or unavailable_seen:
        return _finish(rec, unavailable_seen)
    print("cleanup: reproducibility, restriction, and interruption proofs")
    if "stage" in _FIXTURE:
        print("guest stage: %s (removed after the run)" % _FIXTURE["stage"])
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
