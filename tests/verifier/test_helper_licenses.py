# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Helper availability and GPL-only restriction proofs.

The helper capability registry records the seven profile helpers
as available and non-GPL plus one GPL-only witness (helper 35,
``bpf_get_current_task``) admitted by no profile. This suite
proves the restriction end to end:

* gate agreement (host): the independent C witness object fails
  the pre-publication gate with exactly the helper-license
  preflight diagnostic (``MBPF709``) plus the declaration-pair
  GPL refusal (``MBPF704``), while the qualified Mojo counter
  object passes the same gate cleanly;
* declaration discipline (host): the preflight quotes the
  declaration unchanged and its remedy restricts the program
  instead of suggesting a declaration change; the witness keeps
  the project's non-GPL license bytes, and no code path rewrites
  them to gain helper access;
* kernel rejection (disposable guest): the witness load fails,
  classifies as ``verifier`` (never loader or environment), and
  carries the kernel's GPL-restriction marker, with the full raw
  log preserved; the no-call control (same shape, no helper call)
  loads and unloads cleanly on the same lane, attributing the
  rejection to the helper call; no residue remains.

The GPL-declared positive (the same call admitted under a
GPL-compatible declaration) is deliberately out of scope:
ordinary event support never depends on it.

Requires ``mojo``, ``llc``, ``clang``, ``bpftool`` and ``vng`` on
PATH plus the pinned kernels. ``MOJOBPF_VNG_RELEASE`` selects the
guest lane (default ``v6.12``). A missing tool or lane is an
environment failure; a failing proof step is a proof failure.
Neither ever passes.

Runnable directly (``python3
tests/verifier/test_helper_licenses.py``) or under any
``test_``-style runner. Standard library only.
"""

import hashlib
import importlib.util
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
WITNESS_SOURCE = os.path.join(
    REPO_ROOT, "tests", "reference_c", "gpl_witness.bpf.c"
)
WITNESS_SOURCE_REL = os.path.join(
    "tests", "reference_c", "gpl_witness.bpf.c"
)
NOCALL_SOURCE = os.path.join(
    REPO_ROOT, "tests", "reference_c", "gpl_witness_nocall.bpf.c"
)
NOCALL_SOURCE_REL = os.path.join(
    "tests", "reference_c", "gpl_witness_nocall.bpf.c"
)
COUNTER_SOURCE = os.path.join(
    REPO_ROOT, "examples", "tracepoint_counter", "counter.mojo"
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
LOCKFILE = os.path.join(REPO_ROOT, "toolchains.lock.json")

sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf import helpers as helpers_module  # noqa: E402
from mojobpf import inspect as inspect_module  # noqa: E402
from mojobpf.verify import (  # noqa: E402
    classify_load_output,
    read_elf_sections,
)

# The guest must test exactly the qualified bytes.
WITNESS_OBJECT_HASH = (
    "014e419cd4af54aaa741b9bc36e84c0b5a2aba14047a58d4daad5b5750568153"
)
NOCALL_OBJECT_HASH = (
    "a440ad697ae5d229db441c94e247cb5bbd12d434d9458dacde72af4d3d2a3909"
)
COUNTER_OBJECT_HASH = (
    "b687af78c3056e2299929cd635044875f8369f9ca6e27f626c4f55c4def8b67a"
)

APACHE = "Apache-2.0 WITH LLVM-exception"
PROFILE = "linux-bpfel-v3"

# The kernel's GPL-restriction class marker (observed in the
# verifier log; the full raw log is preserved alongside).
GPL_MARKER = "GPL-restricted function"

GUEST_TIMEOUT = 900


class EnvironmentFailure(Exception):
    """The toolchain or lane needed by this test is missing."""


class ProofFailure(Exception):
    """A proof step failed inside the guest."""


def run_step(argv, timeout=600, cwd=None):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        cwd=cwd,
    )


def _owned_group_live(pgid):
    """Return True when the owned group holds a living member.

    Zombie members count as gone: ``communicate`` reaps the
    direct child, init reaps orphaned grandchildren, and only
    their reaper can collect them.
    """
    try:
        pids = [entry for entry in os.listdir("/proc") if entry.isdigit()]
    except OSError:
        return False
    for pid in pids:
        try:
            with open("/proc/%s/stat" % pid, encoding="utf-8") as handle:
                fields = handle.read().rsplit(")", 1)
        except OSError:
            continue
        if len(fields) != 2:
            continue
        rest = fields[1].split()
        if len(rest) < 3:
            continue
        try:
            member_pgid = int(rest[2])
        except ValueError:
            continue
        if member_pgid != pgid:
            continue
        if rest[0] not in ("Z", "X"):
            return True
    return False


def _kill_owned_group(pgid):
    """SIGKILL the owned suite process group; wait for it to empty.

    The group is always one this suite spawned (a session leader
    whose pgid equals its own pid); nothing else is signalled.
    The wait ignores zombies and is best-effort.
    """
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        return
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if not _owned_group_live(pgid):
            return
        time.sleep(0.2)


def run_guest(argv, timeout):
    """Run one owned child as a session leader with group cleanup.

    On timeout the whole owned process group (the booted guest
    included) is killed and reaped instead of orphaning a guest.
    Returns ``(returncode, output)``; raises :class:`ProofFailure`
    on timeout with the partial output attached.
    """
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_owned_group(proc.pid)
        try:
            stdout, stderr = proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
        partial = (stdout or "") + (stderr or "")
        raise ProofFailure(
            "guest run timed out after %ds; owned process group "
            "%d killed and reaped; partial output (last 2000 "
            "chars): %r" % (timeout, proc.pid, partial[-2000:])
        )
    return proc.returncode, (stdout or "") + (stderr or "")


def check_tools(*tools):
    for tool in tools:
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)


def vng_release():
    release = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
    if not re.fullmatch(r"v\d+\.\d+", release):
        raise EnvironmentFailure(
            "MOJOBPF_VNG_RELEASE must look like v6.12, got %r" % release
        )
    return release


def sha256_file(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def clang_version():
    proc = run_step(["clang", "--version"])
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "clang --version failed (exit %d)" % proc.returncode
        )
    first = (proc.stdout or "").splitlines()
    if not first:
        raise EnvironmentFailure("clang --version printed nothing")
    return first[0].strip()


def build_control(source_rel, workdir, tag, want_hash):
    """Build one C fixture; assert the qualified object bytes.

    The fixture objects carry DWARF, so the build maps the debug
    compilation directory to a fixed placeholder: identical sources
    produce byte-identical objects from any checkout directory. A
    clang version mismatch is an environment failure, never a proof
    failure.
    """
    with open(LOCKFILE, encoding="utf-8") as handle:
        lock = json.load(handle)
    want_version = lock["tools"]["clang"]["version"]
    observed_version = clang_version()
    if observed_version != want_version:
        raise EnvironmentFailure(
            "clang version %r does not match the pinned %r"
            % (observed_version, want_version)
        )
    build_root = os.path.realpath(REPO_ROOT)
    object_path = os.path.join(workdir, "%s.bpf.o" % tag)
    proc = run_step(
        [
            "clang", "--target=bpf", "-O2", "-g", "-c",
            "-fdebug-prefix-map=%s=." % build_root,
            source_rel, "-o", object_path,
        ],
        cwd=build_root,
    )
    if proc.returncode != 0 or proc.stderr != "":
        raise ProofFailure(
            "control build failed for %s: exit=%d stderr=%r"
            % (source_rel, proc.returncode, proc.stderr[-2000:])
        )
    observed = sha256_file(object_path)
    if observed != want_hash:
        raise ProofFailure(
            "staged %s bytes %s do not match the qualified %s"
            % (tag, observed, want_hash)
        )
    return object_path


def build_counter(workdir):
    """Build the Mojo counter; assert the qualified object bytes."""
    raw_path = os.path.join(workdir, "counter.ll")
    adapted_path = os.path.join(workdir, "counter.bpf.ll")
    object_path = os.path.join(workdir, "counter.bpf.o")
    proc = run_step(
        [
            "mojo", "build", "--emit", "llvm",
            "-I", SDK_INCLUDE, "-o", raw_path, COUNTER_SOURCE,
        ]
    )
    if proc.returncode != 0 or proc.stderr != "":
        raise ProofFailure(
            "frontend failed for %s: exit=%d stderr=%r"
            % (COUNTER_SOURCE, proc.returncode, proc.stderr[-1000:])
        )
    proc = run_step(
        [
            sys.executable, ADAPTER,
            "--input", raw_path, "--output", adapted_path,
        ]
    )
    if proc.returncode != 0:
        raise ProofFailure(
            "adapter failed for %s: %s%s"
            % (COUNTER_SOURCE, proc.stdout[-500:], proc.stderr[-500:])
        )
    proc = run_step(
        [
            "llc", "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
            adapted_path, "-o", object_path,
        ]
    )
    if proc.returncode != 0 or proc.stderr != "":
        raise ProofFailure(
            "backend failed for %s: exit=%d stderr=%r"
            % (COUNTER_SOURCE, proc.returncode, proc.stderr[-1000:])
        )
    observed = sha256_file(object_path)
    if observed != COUNTER_OBJECT_HASH:
        raise ProofFailure(
            "staged counter bytes %s do not match the qualified %s"
            % (observed, COUNTER_OBJECT_HASH)
        )
    return object_path


_FIXTURE = {}


def fixture():
    """Build the three objects once per process; return their paths."""
    if "witness" in _FIXTURE:
        return _FIXTURE
    check_tools("mojo", "llc", "clang", "bpftool", "vng")
    for path in (WITNESS_SOURCE, NOCALL_SOURCE, COUNTER_SOURCE):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    workdir = tempfile.mkdtemp(prefix="mojo-helper-licenses-")
    witness = build_control(
        WITNESS_SOURCE_REL, workdir, "witness", WITNESS_OBJECT_HASH
    )
    nocall = build_control(
        NOCALL_SOURCE_REL, workdir, "nocall", NOCALL_OBJECT_HASH
    )
    counter = build_counter(workdir)
    _FIXTURE.update(
        {"witness": witness, "nocall": nocall, "counter": counter}
    )
    return _FIXTURE


def license_bytes_of(object_path):
    _names, payload = read_elf_sections(object_path)
    if payload is None:
        raise ProofFailure(
            "object %s carries no license section" % object_path
        )
    return payload


GUEST_SCRIPT = r"""#!/bin/bash
# Helper-license guest proof. Loads the no-call control (expect
# success, then unload) and the GPL-only witness (expect a
# verifier rejection carrying the kernel's GPL-restriction
# marker), then proves no residue remains.
set -u
export PYTHONDONTWRITEBYTECODE=1
STAGE="__STAGE__"
cd "$STAGE"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin helper-licenses ==="
echo "guest-kernel: $(uname -r)"
bpftool version | head -1
echo "--- staged hashes ---"
sha256sum witness.bpf.o nocall.bpf.o
echo "__WITNESS_HASH__  witness.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH witness"; exit 1; }
echo "__NOCALL_HASH__  nocall.bpf.o" | sha256sum -c - || { echo "STAGE-HASH-MISMATCH nocall"; exit 1; }
echo "staged bytes: qualified"
echo "--- pins before ---"
PINS_BEFORE=$(ls /sys/fs/bpf/)
LINKS_BEFORE=$(bpftool link show)
PROGS_BEFORE=$(bpftool prog show)
MAPS_BEFORE=$(bpftool map show)
echo "$PINS_BEFORE"
echo "$LINKS_BEFORE"
echo "--- tracepoint probe ---"
bpftool feature probe kernel > feature.txt 2>&1
TP_LINE=$(grep "program_type tracepoint is" feature.txt | head -1 || true)
echo "tracepoint-probe: $TP_LINE"
echo "--- no-call control ---"
bpftool prog load nocall.bpf.o /sys/fs/bpf/lic_nocall type tracepoint >/tmp/lic-nocall.log 2>&1
NOCALL_EXIT=$?
echo "nocall-load-exit: $NOCALL_EXIT"
cat /tmp/lic-nocall.log
if [ "$NOCALL_EXIT" != "0" ]; then
  echo "CONTROL-LOAD-FAILED: this lane cannot load tracepoint programs"
  exit 3
fi
rm -f /sys/fs/bpf/lic_nocall
echo "control: loaded+unloaded"
echo "--- witness load ---"
bpftool prog load witness.bpf.o /sys/fs/bpf/lic_witness type tracepoint >/tmp/lic-witness.log 2>&1
WITNESS_EXIT=$?
echo "witness-load-exit: $WITNESS_EXIT"
echo "=== BEGIN witness-log ==="
cat /tmp/lic-witness.log
echo "=== END witness-log ==="
[ "$WITNESS_EXIT" != "0" ] || { echo "WITNESS-UNEXPECTEDLY-LOADED"; exit 1; }
grep -q "GPL-restricted function" /tmp/lic-witness.log || { echo "GPL-MARKER-MISSING"; exit 1; }
echo "witness: rejected with the GPL marker"
rm -f /sys/fs/bpf/lic_witness
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
echo "=== end helper-licenses ==="
"""

_RESULT = None


def executed():
    """Boot one guest and run the license proof; cache the transcript."""
    global _RESULT
    if _RESULT is not None:
        return _RESULT
    fix = fixture()
    release = vng_release()
    stage = tempfile.mkdtemp(prefix="mojo-helper-licenses-", dir="/tmp")
    staged_script = os.path.join(stage, "guest_helper_licenses.sh")
    script = (
        GUEST_SCRIPT.replace("__STAGE__", stage)
        .replace("__WITNESS_HASH__", WITNESS_OBJECT_HASH)
        .replace("__NOCALL_HASH__", NOCALL_OBJECT_HASH)
    )
    with open(staged_script, "w", encoding="utf-8") as handle:
        handle.write(script)
    for source, name in (
        (fix["witness"], "witness.bpf.o"),
        (fix["nocall"], "nocall.bpf.o"),
    ):
        shutil.copyfile(source, os.path.join(stage, name))
    os.chmod(stage, 0o755)
    os.chmod(staged_script, 0o644)
    os.chmod(os.path.join(stage, "witness.bpf.o"), 0o644)
    os.chmod(os.path.join(stage, "nocall.bpf.o"), 0o644)
    try:
        returncode, output = run_guest(
            ["vng", "--run", release, "--disable-kvm",
             "--exec", "bash %s" % staged_script],
            GUEST_TIMEOUT,
        )
    except ProofFailure as exc:
        raise ProofFailure(
            "guest %s: %s; stage kept at %s" % (release, exc, stage)
        )
    if "CONTROL-LOAD-FAILED:" in output:
        raise EnvironmentFailure(
            "guest %s cannot load tracepoint programs; "
            "stage kept at %s" % (release, stage)
        )
    if returncode != 0:
        raise ProofFailure(
            "guest %s failed (exit %d); stage kept at %s\n%s"
            % (release, returncode, stage, output[-6000:])
        )
    for marker in ("=== end helper-licenses ===", "cleanup: proven"):
        if marker not in output:
            raise ProofFailure(
                "guest %s transcript incomplete; stage kept at %s\n%s"
                % (release, stage, output[-6000:])
            )
    kernel = ""
    for line in output.splitlines():
        if line.startswith("guest-kernel:"):
            kernel = line.split("guest-kernel:")[1].strip()
    if not kernel.startswith(release[1:] + "."):
        raise ProofFailure(
            "guest kernel %r does not match lane %s" % (kernel, release)
        )
    _RESULT = output
    return _RESULT


def witness_log(output):
    """Extract the raw witness load log from the transcript."""
    match = re.search(
        r"=== BEGIN witness-log ===\n(.*?)\n=== END witness-log ===",
        output,
        re.DOTALL,
    )
    if match is None:
        raise ProofFailure("transcript has no witness-log block")
    return match.group(1)


def test_fixture_build_portable():
    """Control: the C fixtures build byte-identically anywhere.

    Host-only (no guest): rebuild both fixtures with the checkout
    root redirected to a temporary source copy and require the
    qualified hashes, so the pins can never depend on a private
    directory again.
    """
    global REPO_ROOT
    previous = REPO_ROOT
    replica = tempfile.mkdtemp(prefix="mojo-licenses-replica-")
    try:
        for rel in (WITNESS_SOURCE_REL, NOCALL_SOURCE_REL):
            dest = os.path.join(replica, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copyfile(os.path.join(previous, rel), dest)
        REPO_ROOT = replica
        workdir = tempfile.mkdtemp(prefix="mojo-licenses-portable-")
        witness = build_control(
            WITNESS_SOURCE_REL, workdir, "witness", WITNESS_OBJECT_HASH
        )
        nocall = build_control(
            NOCALL_SOURCE_REL, workdir, "nocall", NOCALL_OBJECT_HASH
        )
        assert sha256_file(witness) == WITNESS_OBJECT_HASH
        assert sha256_file(nocall) == NOCALL_OBJECT_HASH
        assert license_bytes_of(witness) == APACHE.encode("ascii") + b"\x00"
        assert license_bytes_of(nocall) == APACHE.encode("ascii") + b"\x00"
    finally:
        REPO_ROOT = previous
    print("PASS portability: fixtures rebuild byte-identically elsewhere")


_FAKE_SLEEPER = """\
import os
import subprocess
import sys
import time
child = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(300)"]
)
with open(os.environ["MOJOBPF_FAKE_PIDFILE"], "w") as handle:
    handle.write(str(child.pid))
print("MOJOBPF-PARTIAL-MARKER", flush=True)
time.sleep(300)
"""


def _pid_dead(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    try:
        with open("/proc/%d/stat" % pid, "r", encoding="utf-8") as handle:
            state = handle.read().rsplit(")", 1)[1].split()[0]
    except OSError:
        return True
    return state in ("Z", "X")


def test_runner_cancels_owned_group_on_timeout():
    """Control: the direct runner kills its group on timeout.

    Host-only (no guest): a fake sleeper with a grandchild is
    run through the same ``run_guest`` helper the guest boot
    uses; the timeout must kill the whole owned group (child
    and grandchild) instead of orphaning it.
    """
    scratch = tempfile.mkdtemp(prefix="mojo-licenses-cancel-")
    pidfile = os.path.join(scratch, "grandchild.pid")
    sleeper = os.path.join(scratch, "sleeper.py")
    with open(sleeper, "w", encoding="utf-8") as handle:
        handle.write(_FAKE_SLEEPER)
    saved = os.environ.get("MOJOBPF_FAKE_PIDFILE")
    os.environ["MOJOBPF_FAKE_PIDFILE"] = pidfile
    try:
        try:
            run_guest([sys.executable, sleeper], 5)
        except ProofFailure as exc:
            assert "timed out after 5s" in str(exc), exc
            assert "killed and reaped" in str(exc), exc
            assert "MOJOBPF-PARTIAL-MARKER" in str(exc), exc
        else:
            raise AssertionError("the sleeper must time out")
        with open(pidfile, "r", encoding="utf-8") as handle:
            grandchild = int(handle.read().strip())
        deadline = time.monotonic() + 15
        while not _pid_dead(grandchild):
            assert time.monotonic() < deadline, (
                "grandchild %d survived the runner timeout"
                % grandchild
            )
            time.sleep(0.2)
    finally:
        if saved is None:
            os.environ.pop("MOJOBPF_FAKE_PIDFILE", None)
        else:
            os.environ["MOJOBPF_FAKE_PIDFILE"] = saved
        shutil.rmtree(scratch, ignore_errors=True)
    print(
        "PASS cancellation: runner timeout kills the owned group"
    )


_FAKE_MATRIX_GRANDCHILD = """\
import time
time.sleep(300)
"""


_FAKE_MATRIX_SLEEPER = """\
import os
import subprocess
import sys
import time
child = subprocess.Popen(
    [sys.executable, os.environ["MOJOBPF_FAKE_GRANDCHILD"]]
)
with open(os.environ["MOJOBPF_FAKE_PIDFILE"], "w") as handle:
    handle.write("%d %d" % (os.getpid(), child.pid))
time.sleep(300)
"""


_FAKE_MATRIX_SUITE = """\
import importlib.util
import sys
spec = importlib.util.spec_from_file_location(
    "probe_target_suite", %(suite)r
)
target = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target)
target.run_guest([sys.executable, %(sleeper)r], 300)
"""


def _load_matrix_runner():
    spec = importlib.util.spec_from_file_location(
        "matrix_runner",
        os.path.join(REPO_ROOT, "ci", "run_vm_tests.py"),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _kill_owned_pid(pid, marker):
    """SIGKILL one probe-owned pid after a command-line recheck.

    The pid was recorded from a child this probe spawned; the
    recheck keeps a recycled pid from signalling a foreign
    process. Best-effort: missing processes are already gone.
    """
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as handle:
            cmdline = handle.read().decode("utf-8", "replace")
    except OSError:
        return
    if marker not in cmdline:
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        return
    deadline = time.monotonic() + 15
    while not _pid_dead(pid) and time.monotonic() < deadline:
        time.sleep(0.2)


def test_matrix_timeout_reaps_detached_guest():
    """Control: a matrix timeout reaps the suite's detached guest.

    Host-only (no guest): a fake suite boots a sleeper through
    this suite's real ``run_guest`` (new session, own group) and
    the real matrix ``run_suite`` times the suite out; the
    sleeper and its grandchild must not survive (a bare
    suite-group kill would orphan the detached guest).
    """
    matrix = _load_matrix_runner()
    scratch = tempfile.mkdtemp(prefix="mojo-licenses-matrix-")
    pidfile = os.path.join(scratch, "tree.pid")
    grandchild = os.path.join(scratch, "grandchild.py")
    sleeper = os.path.join(scratch, "sleeper.py")
    fakesuite = os.path.join(scratch, "fake_suite.py")
    with open(grandchild, "w", encoding="utf-8") as handle:
        handle.write(_FAKE_MATRIX_GRANDCHILD)
    with open(sleeper, "w", encoding="utf-8") as handle:
        handle.write(_FAKE_MATRIX_SLEEPER)
    with open(fakesuite, "w", encoding="utf-8") as handle:
        handle.write(
            _FAKE_MATRIX_SUITE
            % {"suite": os.path.abspath(__file__), "sleeper": sleeper}
        )
    saved_pidfile = os.environ.get("MOJOBPF_FAKE_PIDFILE")
    saved_grandchild = os.environ.get("MOJOBPF_FAKE_GRANDCHILD")
    os.environ["MOJOBPF_FAKE_PIDFILE"] = pidfile
    os.environ["MOJOBPF_FAKE_GRANDCHILD"] = grandchild
    try:
        record = matrix.run_suite(
            "probe-fake", fakesuite,
            {"id": "probe", "release": "v6.12"},
            scratch, 5, "probe", [],
        )
        assert record["timed_out"] is True, record
        assert record["outcome"] == "timeout", record
        with open(record["log"], "r", encoding="utf-8") as handle:
            assert "MATRIX TIMEOUT after 5s" in handle.read()
        with open(pidfile, "r", encoding="utf-8") as handle:
            owned = [int(pid) for pid in handle.read().split()]
        assert len(owned) == 2, owned
        deadline = time.monotonic() + 15
        for pid in owned:
            while not _pid_dead(pid):
                assert time.monotonic() < deadline, (
                    "owned process %d survived the matrix timeout"
                    % pid
                )
                time.sleep(0.2)
    finally:
        try:
            with open(pidfile, "r", encoding="utf-8") as handle:
                survivors = [
                    int(pid) for pid in handle.read().split()
                ]
        except (OSError, ValueError):
            survivors = []
        for pid in survivors:
            _kill_owned_pid(pid, scratch)
        if saved_pidfile is None:
            os.environ.pop("MOJOBPF_FAKE_PIDFILE", None)
        else:
            os.environ["MOJOBPF_FAKE_PIDFILE"] = saved_pidfile
        if saved_grandchild is None:
            os.environ.pop("MOJOBPF_FAKE_GRANDCHILD", None)
        else:
            os.environ["MOJOBPF_FAKE_GRANDCHILD"] = saved_grandchild
        shutil.rmtree(scratch, ignore_errors=True)
    print(
        "PASS matrix composition: suite timeout reaps the "
        "detached guest tree"
    )


def test_registry_names_witness_gpl_only():
    witness = helpers_module.lookup_helper(35)
    assert witness is not None
    assert witness.kernel_name == "bpf_get_current_task"
    assert witness.gpl_only is True
    assert witness.profiles == ()
    assert helpers_module.profile_helper_ids(PROFILE) == (1, 2, 3, 5, 8, 14, 130)
    print("PASS registry: witness 35 is GPL-only, admitted nowhere")


def test_witness_gate_verdict():
    fix = fixture()
    payload = license_bytes_of(fix["witness"])
    assert payload == APACHE.encode("ascii") + b"\x00", payload
    report = inspect_module.verify_object(
        fix["witness"], PROFILE, APACHE, APACHE
    )
    assert report.ok is False
    license_codes = [item.code for item in report.license]
    assert license_codes == ["MBPF709", "MBPF704"], license_codes
    preflight = report.license[0]
    assert "35" in preflight.explanation, preflight.explanation
    assert "bpf_get_current_task" in preflight.explanation
    assert repr(APACHE) in preflight.explanation
    assert (
        preflight.remedy == "restrict the program to non-GPL facilities"
    ), preflight.remedy
    unsupported_text = " ".join(
        item.explanation for item in report.unsupported
    )
    assert "helper ID 35" in unsupported_text, unsupported_text
    print("PASS gate: witness fails with MBPF709 + MBPF704")


def test_counter_gate_verdict():
    fix = fixture()
    payload = license_bytes_of(fix["counter"])
    assert payload == APACHE.encode("ascii") + b"\x00", payload
    report = inspect_module.verify_object(
        fix["counter"], PROFILE, APACHE, APACHE
    )
    assert report.ok is True, (
        [item.code for item in report.structural],
        [item.code for item in report.unsupported],
        [item.code for item in report.license],
    )
    assert report.structural == ()
    assert report.unsupported == ()
    assert report.license == ()
    print("PASS gate: qualified counter passes cleanly")


def test_declaration_never_rewritten():
    fix = fixture()
    validated = inspect_module.validate_declaration_pair(APACHE, APACHE)
    assert validated.kernel_license == APACHE
    assert validated.source_license == APACHE
    assert validated.expected_license_bytes == (
        APACHE.encode("ascii") + b"\x00"
    )
    assert license_bytes_of(fix["witness"]) == (
        validated.expected_license_bytes
    )
    assert license_bytes_of(fix["nocall"]) == (
        validated.expected_license_bytes
    )
    # The preflight remedy restricts the program; it never suggests
    # a declaration change, and neither layer rewrites the input.
    try:
        inspect_module.preflight_helper_licenses((35,), APACHE, PROFILE)
    except inspect_module.InspectionError as exc:
        assert exc.diagnostic.code == "MBPF709"
        assert "change" not in exc.diagnostic.remedy.lower()
        assert "GPL" not in exc.diagnostic.remedy.replace(
            "non-GPL", ""
        ), exc.diagnostic.remedy
    else:
        raise AssertionError("expected the preflight to refuse helper 35")
    print("PASS declarations: quoted unchanged, remedy restricts")


def test_kernel_rejects_gpl_only_helper():
    output = executed()
    assert "control: loaded+unloaded" in output
    assert "nocall-load-exit: 0" in output
    exit_line = None
    for line in output.splitlines():
        if line.startswith("witness-load-exit:"):
            exit_line = line.split("witness-load-exit:")[1].strip()
    assert exit_line is not None, "transcript has no witness exit line"
    assert exit_line != "0", "the witness must not load"
    log = witness_log(output)
    assert GPL_MARKER in log, log[-2000:]
    classification = classify_load_output(log, "", False)
    assert classification == "verifier", (classification, log[-2000:])
    assert "witness: rejected with the GPL marker" in output
    assert "cleanup: proven" in output
    print(
        "PASS kernel: witness rejected as %s (exit %s) with %r"
        % (classification, exit_line, GPL_MARKER)
    )


def guest_kernel(output):
    """Guest kernel release from the transcript (lane identity)."""
    for line in output.splitlines():
        if line.startswith("guest-kernel:"):
            return line.split("guest-kernel:")[1].strip()
    raise ProofFailure("guest transcript has no kernel line")


def print_board(output):
    """Print the license-proof board from the transcript."""
    release = vng_release()
    print("guest: %s kernel %s" % (release, guest_kernel(output)))
    print(
        "staged objects: witness=%s nocall=%s"
        % (WITNESS_OBJECT_HASH[:16], NOCALL_OBJECT_HASH[:16])
    )
    print(
        "staged sources: witness=%s nocall=%s"
        % (
            sha256_file(WITNESS_SOURCE)[:16],
            sha256_file(NOCALL_SOURCE)[:16],
        )
    )
    print(
        "registry: version=%d witness=%s"
        % (
            helpers_module.HELPER_REGISTRY_VERSION,
            helpers_module.lookup_helper(35),
        )
    )
    for line in output.splitlines():
        if line.startswith(
            (
                "tracepoint-probe:",
                "nocall-load-exit:",
                "witness-load-exit:",
                "control:",
                "witness:",
            )
        ):
            print("board %s" % line)
    print("board witness raw log:")
    for line in witness_log(output).splitlines():
        print("board | %s" % line)


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    names = (
        "test_fixture_build_portable",
        "test_runner_cancels_owned_group_on_timeout",
        "test_matrix_timeout_reaps_detached_guest",
        "test_registry_names_witness_gpl_only",
        "test_witness_gate_verdict",
        "test_counter_gate_verdict",
        "test_declaration_never_rewritten",
        "test_kernel_rejects_gpl_only_helper",
    )
    output = None
    for name in names:
        try:
            globals()[name]()
        except EnvironmentFailure as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            return 2
        except (AssertionError, ProofFailure) as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
        else:
            print("PASS %s" % name)
    if failures:
        return 1
    try:
        output = executed()
        print_board(output)
    except (EnvironmentFailure, ProofFailure) as exc:
        print("FAIL board: %s" % exc)
        return 1
    release = vng_release()
    print(
        "helper licenses: preflight MBPF709 agrees with the kernel "
        "GPL rejection in one %s guest" % release
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
