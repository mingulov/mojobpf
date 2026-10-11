# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Shared host-side guest-runner composition for the guest suites.

Every suite boots its guests through :func:`run_owned`: the guest
boots as a session leader, so a timeout kills the whole owned
guest tree (the runner group plus any detached qemu groups it
booted), never just the direct child. Both the success transcript
and the timed-out partial transcript are saved to the stage log;
a timeout raises :class:`GuestTimeout` carrying the partial
output, and an interruption reaps the owned tree, saves the
partial transcript, and propagates (never converted into a
timeout). Suites map :class:`GuestTimeout` to their own local
error type and keep no runner machinery of their own.

Every suite boots guests in text mode, but ``TimeoutExpired``
partials still arrive as bytes (``communicate`` decodes only on
success). The owned drain retries ``communicate`` after killing
the tree, and the retry carries the complete stream, so the
timed-out partials are never re-added (adding them would
duplicate every line); :func:`decode_timeout_partial` remains
for the legacy call sites that still report raw partials.

Standard library only. Imported host-side by the directly
runnable suites (``sys.path``-relative to this directory); never
staged into a guest.

The second half of this module is the shared typed-outcome
composition: every suite seals an immutable run plan, records one
``test-contracts-v1`` case result per case, and emits a terminal
``suite-result-v1`` record the matrix re-aggregates. Text logs
remain evidence, never the verdict authority. The record
construction itself runs through the first-party
``mojobpf.validation`` contract library (same checkout, lazily
imported); this module carries only the suite-side wiring
(harness-record mapping, guest-exit classification, owned-process
census, emission) so the matrix can re-verify every claim.
"""

import atexit
import copy
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time


class GuestTimeout(Exception):
    """A guest run exceeded its timeout; the owned tree is reaped.

    Carries the partial ``output``, the ``timeout`` seconds, the
    stage ``log_path`` holding the partial transcript, and the
    ``residue`` list of owned strays that survived the tree kill
    (empty when the tree reaped cleanly; each entry names a pid,
    its group and its state).
    """

    def __init__(self, output, timeout, log_path, residue=None):
        message = "guest run timed out after %ds (partial log at %s)" % (
            timeout, log_path
        )
        if residue:
            message += "; owned residue: %s" % (", ".join(residue),)
        super().__init__(message)
        self.output = output
        self.timeout = timeout
        self.log_path = log_path
        self.residue = list(residue) if residue else []


def decode_timeout_partial(value):
    """Decode timed-out child output, which arrives as bytes.

    ``None`` decodes to ``""``; ``bytes`` decode as UTF-8 with
    replacement; ``str`` passes through unchanged.
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def _scan_processes():
    """Snapshot the process table into ``{pid: (ppid, pgid, state)}``.

    Best-effort: processes that exit mid-scan are skipped, and a
    missing ``/proc`` yields an empty table. This is the matrix
    runner's owned-process-tracking composition
    (``ci/run_vm_tests.py``), shared so every suite reaps the
    same way.
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


def owned_pids(root):
    """Return the living pids whose parent chain reaches ``root``.

    Survivor-check helper for the stand-in controls: zombies
    count as gone (only their reaper can collect them).
    """
    table = _scan_processes()
    return [
        pid for pid in _owned_descendants(root, table)
        if table[pid][2] not in ("Z", "X")
    ]


def _signal_live_owned(pgid, table, seen_groups):
    """SIGKILL the living owned tree once; extend the seen groups.

    Only owned pids are signalled: living descendants of the
    guest child plus groups observed holding an owned member --
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


def _residue_entries(table, seen_groups):
    """Format living members of owned groups as residue entries."""
    entries = []
    for pid in sorted(table):
        _ppid, pgid, state = table[pid]
        if state in ("Z", "X"):
            continue
        if pgid in seen_groups:
            entries.append(
                "pid %d (pgid %d, state %s)" % (pid, pgid, state)
            )
    return entries


def kill_guest_tree(pgid):
    """SIGKILL the guest tree; wait for every owned group to empty.

    The guest runner boots as a session leader (its own process
    group), so killing only the direct child would orphan the
    qemu tree. The owned tree is snapshotted BEFORE signalling --
    dead parents reparent their orphans and the chain is lost
    afterwards -- and every group that ever held an owned member
    stays a kill candidate while it shows a living member, which
    also reaps already-reparented stragglers that kept their
    group. Zombies count as gone and the wait is best-effort:
    whatever remains, the timeout verdict below stands. Without
    ``/proc`` the snapshot is empty and only the guest group is
    killed.

    Returns the residue: a list of ``pid ... (pgid ..., state
    ...)`` entries for owned strays still living after the
    deadline, ``[]`` when the tree reaped cleanly. A SIGKILL-immune
    (D-state) straggler is reported, never silently dropped; the
    caller records the entries in the typed cleanup result.
    """
    seen_groups = {pgid}
    deadline = time.monotonic() + 30
    first = True
    while time.monotonic() < deadline:
        table = _scan_processes()
        if not table and first:
            # No snapshot (no /proc): fall back to the guest
            # group alone. The kill is unverifiable, so the
            # residue says so honestly instead of claiming clean.
            try:
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            return ["pgid %d kill unverified (no /proc)" % pgid]
        first = False
        live_owned, live_groups = _signal_live_owned(
            pgid, table, seen_groups
        )
        if not live_owned and not live_groups:
            return []
        time.sleep(0.2)
    return _residue_entries(_scan_processes(), seen_groups)


def _save_log(stage, log_name, first_line, output):
    log_path = os.path.join(stage, log_name)
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(first_line)
        handle.write(output)
    return log_path


def _drain_after_kill(proc):
    try:
        stdout, stderr = proc.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
    return (stdout or "") + (stderr or "")


TARGET_LEASE_ENV = "MOJOBPF_TARGET_LEASE"


class TargetLeaseRequired(AssertionError):
    """Target execution was requested without a target lease.

    An ``AssertionError`` subclass so any main loop that only
    knows the historical failure type still fails closed (FAIL,
    never PASS); suites that report lease refusal as
    required-unavailable catch this class explicitly before
    ``AssertionError``.
    """


def require_target_lease(caller):
    """Refuse target execution without an explicit target lease.

    Only the incoming environment grants the lease (an
    external disposable-target approval setting
    ``MOJOBPF_TARGET_LEASE=1``); the matrix propagates that
    environment but never synthesizes a lease of its own, so
    an absent or ``0`` lease stays unleased and refuses here.
    Without the lease, raise :class:`TargetLeaseRequired`
    naming it: a guest is never booted without one, never
    skipped silently, and never counted as a pass.
    """
    if os.environ.get(TARGET_LEASE_ENV) != "1":
        raise TargetLeaseRequired(
            "%s: guest required, no target lease (set %s=1 "
            "with a disposable target to boot)"
            % (caller, TARGET_LEASE_ENV)
        )


def run_owned(argv, stage, timeout, log_name="guest.log"):
    """Run ``argv`` as an owned session leader; return (code, output).

    On timeout the whole owned tree is killed and reaped, the
    partial transcript is saved to the stage log, and
    :class:`GuestTimeout` is raised carrying the partial output.
    On interruption the owned tree is reaped, the partial
    transcript is saved, and the interruption propagates. The
    success transcript is saved to the stage log as well.
    Booting a guest (a ``vng`` command) additionally requires
    the target lease; without it the boot is refused before any
    process starts.
    """
    if argv and os.path.basename(argv[0]) == "vng":
        require_target_lease("vng guest boot")
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    # The child is a session leader, so its pid is its group id:
    # register the owned group before it can fork so the census
    # below can still attribute strays that reparent away.
    note_owned_group(proc.pid)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        residue = kill_guest_tree(proc.pid)
        # Retrying communication after a timeout loses no output:
        # the retry carries the complete stream, so the timed-out
        # partials are not re-added (adding them would duplicate
        # every line).
        try:
            output = _drain_after_kill(proc)
        except KeyboardInterrupt:
            # An abort landing inside the post-timeout drain
            # cannot reach the sibling handler below (a handler
            # never catches what it raises itself), so the
            # partial transcript is saved here, under the
            # interrupted banner, before propagating. The tree
            # is already killed above.
            output = _drain_after_kill(proc)
            _save_log(
                stage, log_name,
                "guest interrupted (partial)\n", output,
            )
            raise
        log_path = _save_log(
            stage, log_name,
            "guest timeout after %ds (partial)\n" % timeout,
            output,
        )
        raise GuestTimeout(output, timeout, log_path, residue=residue)
    except KeyboardInterrupt:
        # An operator abort from the initial wait: reap the owned
        # tree, save whatever the pipes hold, then propagate the
        # interruption.
        kill_guest_tree(proc.pid)
        output = _drain_after_kill(proc)
        _save_log(
            stage, log_name, "guest interrupted (partial)\n", output
        )
        raise
    output = (stdout or "") + (stderr or "")
    _save_log(
        stage, log_name, "guest exit: %d\n" % proc.returncode, output
    )
    return proc.returncode, output


# Owned-process census: per-case leak attribution for the typed
# cleanup record. A case passes its census when no owned stray
# outlives it; a stray poisons the case (never silently) and the
# suite reaps it at finish as hygiene. Three owned identities
# are unioned: parent-chain descendants of the suite, living
# members of registered owned groups (guest groups reparent
# away when their runner dies but keep their group), and -- only
# when the suite is itself a session leader, as under the
# matrix -- other members of the suite session (catches
# setpgid escapees). A full setsid escape (new session and new
# group) would be invisible from userspace without cgroup
# delegation, which is unavailable to these unprivileged
# suites -- so a suite run marks itself a child subreaper for
# the run (see _ensure_subreaper): orphaned descendants then
# reparent to the suite instead of init and stay parent-chain
# visible. When the subreaper cannot be set, the run's
# censuses report unavailable (None, hence NOT_CHECKED),
# never CLEAN. Cgroup/process identities would be used where
# available; parent-chain plus group plus session snapshots
# under the subreaper are the available mechanism here. Pid
# reuse across a snapshot window stays the accepted residual:
# a reused pid reads as its earlier identity.

_OWNED_GROUPS = set()


def _prctl_subreaper(value):
    """Set (1) or clear (0) the child-subreaper flag; report success.

    Deliberately uncached: the flag is process-global kernel
    state shared by every importer of this module, so each
    call re-asserts the requested state instead of trusting a
    stale per-module answer.
    """
    try:
        import ctypes
        PR_SET_CHILD_SUBREAPER = 36
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [
            ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
            ctypes.c_ulong, ctypes.c_ulong,
        ]
        libc.prctl.restype = ctypes.c_int
        return (
            libc.prctl(PR_SET_CHILD_SUBREAPER, value, 0, 0, 0)
            == 0
        )
    except (OSError, AttributeError, TypeError, ValueError,
            ImportError):
        return False


def _ensure_subreaper():
    """Mark this process a child subreaper; report success.

    Orphaned descendants then reparent to us instead of init,
    so a setsid escapee stays parent-chain visible to the
    census instead of vanishing. Best-effort probe: False
    means the run cannot rule out a setsid escape and its
    censuses must not claim CLEAN.
    """
    return _prctl_subreaper(1)


def _release_subreaper():
    """Clear the child-subreaper flag (best-effort).

    Restores pre-run kernel state for long-lived hosts that
    run suite flows in-process (test sessions): orphans
    created afterwards reparent to init again, as before the
    run. Never called mid-run (a nested run would silently
    lose its guard); suite processes simply exit.
    """
    _prctl_subreaper(0)
    reap_zombie_children()


def note_owned_group(pgid):
    """Register an owned process group for the census.

    :func:`run_owned` registers every guest group it boots. Tests
    register stand-in groups the same way. The registry lives for
    the process (a suite run); stale groups simply show no living
    members.
    """
    if not isinstance(pgid, int) or pgid <= 0:
        raise ValueError("owned pgid must be a positive int")
    _OWNED_GROUPS.add(pgid)


def _scan_census():
    """Snapshot the process table into ``{pid: (ppid, pgid, session, state)}``.

    Best-effort like :func:`_scan_processes`: processes that exit
    mid-scan are skipped. Unlike the kill scan this one also
    reads the session id, and it never touches signalling.
    Returns None when the scan is untrustworthy: denied
    enumeration, or a table that cannot even see this very
    process (an empty snapshot reads as uncensused, never as
    clean), or any still-present entry whose stat read fails
    (a denied owned stat must never read as clean).
    """
    table = {}
    try:
        entries = [entry for entry in os.listdir("/proc") if entry.isdigit()]
    except OSError:
        return None
    for entry in entries:
        try:
            pid = int(entry)
            with open("/proc/%s/stat" % entry, encoding="utf-8") as handle:
                fields = handle.read().rsplit(")", 1)
        except (OSError, ValueError):
            # A pid that vanished mid-scan is skipped; a pid
            # that is still present but unreadable makes the
            # whole census untrustworthy (an owned child whose
            # stat read is denied would otherwise vanish from
            # the snapshot and read as clean), so the snapshot
            # is refused instead of silently dropping the entry.
            try:
                still_present = os.path.isdir("/proc/%s" % entry)
            except OSError:
                still_present = True
            if still_present:
                return None
            continue
        if len(fields) != 2:
            continue
        rest = fields[1].split()
        if len(rest) < 4:
            continue
        try:
            ppid = int(rest[1])
            pgid = int(rest[2])
            session = int(rest[3])
        except ValueError:
            continue
        table[pid] = (ppid, pgid, session, rest[0])
    if os.getpid() not in table:
        return None
    return table


def _living_owned_identities(table, me, session_leader, groups):
    """Return living owned pids: descendants, group members, session."""
    children = {}
    for pid, (ppid, _pgid, _session, _state) in table.items():
        children.setdefault(ppid, []).append(pid)
    owned = set()
    stack = [me]
    seen = {me}
    while stack:
        current = stack.pop()
        for child in children.get(current, []):
            if child in seen:
                continue
            seen.add(child)
            if table[child][3] not in ("Z", "X"):
                owned.add(child)
            stack.append(child)
    for pid, (_ppid, pgid, _session, state) in table.items():
        if state not in ("Z", "X") and pgid in groups:
            owned.add(pid)
    if session_leader:
        for pid, (_ppid, _pgid, session, state) in table.items():
            if state not in ("Z", "X") and pid != me and session == me:
                owned.add(pid)
    owned.discard(me)
    return owned


def _census_context():
    """Return (me, session_leader, groups) for this process."""
    me = os.getpid()
    try:
        leader = os.getsid(0) == me
    except OSError:
        leader = False
    return me, leader, set(_OWNED_GROUPS)


def census_snapshot():
    """Snapshot the current owned identities.

    Returns a frozenset of owned pids, or None when the census
    is impossible (no ``/proc`` or an untrustworthy scan).
    None must flow into a NOT_CHECKED cleanup record, never
    into a CLEAN claim: without a snapshot a leak cannot be
    detected. Suite runs additionally gate on the subreaper
    guard (see :class:`SuiteRecorder`); the bare mechanism
    here stays guard-agnostic for direct unit use.
    """
    if not os.path.isdir("/proc"):
        return None
    table = _scan_census()
    if table is None:
        return None
    me, leader, groups = _census_context()
    return frozenset(_living_owned_identities(table, me, leader, groups))


def _current_strays(before):
    """Return (sorted_new_pids, table) or None when uncensused."""
    if not os.path.isdir("/proc"):
        return None
    table = _scan_census()
    if table is None:
        return None
    me, leader, groups = _census_context()
    now = _living_owned_identities(table, me, leader, groups)
    return sorted(pid for pid in now if pid not in before), table


def census_leaks(before):
    """Return residue entries for owned strays absent from BEFORE.

    BEFORE is a :func:`census_snapshot` result. Returns a sorted
    list of ``pid ... (pgid ..., state ...)`` entries, ``[]``
    when nothing leaked, or None when the census itself is
    impossible (caller records NOT_CHECKED). Pid reuse across the
    snapshot window is the accepted residual: a reused pid reads
    as its earlier identity. Entries are attribution evidence;
    reaping is :func:`reap_owned_strays`.
    """
    current = _current_strays(before)
    if current is None:
        return None
    pids, table = current
    entries = []
    for pid in pids:
        info = table.get(pid)
        if info is None:
            entries.append("pid %d (vanished during census)" % pid)
        else:
            _ppid, pgid, _session, state = info
            entries.append(
                "pid %d (pgid %d, state %s)" % (pid, pgid, state)
            )
    return entries


def reap_owned_strays(before, timeout=10.0):
    """SIGKILL owned strays absent from BEFORE; return survivors.

    BEFORE is a :func:`census_snapshot` result. Every newly owned
    living pid is signalled (kill failures are ignored: a pid
    that cannot be signalled is either gone or foreign through
    reuse, and both read as survivors below or vanish), then the
    census is re-polled until the timeout. Killed strays that
    reparented to us are collected (never left as zombies).
    Returns the surviving residue entries (``[]`` when
    everything reaped) or None when the census itself is
    impossible. Only owned identities are ever signalled, never
    a bare group id.
    """
    current = _current_strays(before)
    if current is None:
        return None
    pids, _table = current
    for target in pids:
        try:
            os.kill(target, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    reap_zombie_children()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = _current_strays(before)
        if current is None:
            reap_zombie_children()
            return None
        pids, table = current
        if not pids:
            reap_zombie_children()
            return []
        time.sleep(0.2)
    current = _current_strays(before)
    if current is None:
        reap_zombie_children()
        return None
    pids, table = current
    survivors = []
    for pid in pids:
        info = table.get(pid)
        if info is None:
            survivors.append("pid %d (vanished during census)" % pid)
        else:
            _ppid, pgid, _session, state = info
            survivors.append(
                "pid %d (pgid %d, state %s)" % (pid, pgid, state)
            )
    reap_zombie_children()
    return survivors


def reap_zombie_children():
    """Reap direct-child zombies; return the count reaped.

    Best-effort hygiene for ``Popen`` handles the suite never
    waited on. Only direct children are reaped (``waitpid``
    semantics), never foreign processes.
    """
    reaped = 0
    while True:
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except (ChildProcessError, OSError):
            break
        if pid == 0:
            break
        reaped += 1
    return reaped


_OWNED_STAGES = set()
_OWNED_STAGES_ATEXIT = False


def owned_stage(prefix, dir=None):
    """Create a suite stage directory registered for discard.

    The stage works like :func:`tempfile.mkdtemp` but is
    remembered: :meth:`SuiteRecorder.finish` removes every
    registered stage after hashing the declared inputs but
    before emitting the terminal record, so a failed removal
    lands in the terminal (never a PASS with forgotten
    residue) while guest/build stages are still cleaned on
    success and on every early failure, including attempts
    that raised before their stage was cached. Post-finish
    :func:`discard_owned_stages` calls remain as retry hygiene,
    and an ``atexit`` backstop covers interrupted runs.
    """
    global _OWNED_STAGES_ATEXIT
    stage = tempfile.mkdtemp(prefix=prefix, dir=dir)
    _OWNED_STAGES.add(stage)
    if not _OWNED_STAGES_ATEXIT:
        _OWNED_STAGES_ATEXIT = True
        atexit.register(discard_owned_stages)
    return stage


def _discard_owned_stages_collected():
    """Remove every registered stage; return (discarded, errors).

    Each stage is attempted (no blanket ``ignore_errors``): a
    stage that is already gone counts as discarded, a stage
    whose removal fails stays registered (with its error
    recorded) so the failure is reported and a later retry can
    still remove it. Only registered stages are ever removed,
    never foreign directories. ``errors`` is a sorted list of
    ``(stage, message)`` pairs.
    """
    discarded = []
    errors = []
    for stage in sorted(_OWNED_STAGES):
        try:
            shutil.rmtree(stage)
        except FileNotFoundError:
            _OWNED_STAGES.discard(stage)
            discarded.append(stage)
        except OSError as exc:
            errors.append((stage, "%s" % exc))
        else:
            _OWNED_STAGES.discard(stage)
            discarded.append(stage)
    return discarded, errors


def discard_owned_stages():
    """Remove every registered stage (best-effort); return paths.

    Returns the sorted discarded paths. Stages whose removal
    fails stay registered for a later retry (see
    :func:`_discard_owned_stages_collected`); only registered
    stages are ever removed, never foreign directories.
    """
    discarded, _errors = _discard_owned_stages_collected()
    return discarded


# Typed harness-record mapping (F-040): branch the harness
# classification before the exit assertion, so a degraded guest
# (environment record) can never surface as a product FAIL. The
# table below maps the bpf_test_run contract revision 2
# exit/classification pairs to ``test-contracts-v1`` typed
# outcomes. Suites call :func:`check_harness_exit` for every
# record they consume; the matrix re-verifies the emitted typed
# records independently.

HARNESS_CONTRACT_VERSION = 2

# Harness stage to failure-stage for environment records: where
# the run stopped when the environment refused. Runtime records
# (behavior mismatches) always map to RUNTIME instead: the
# test-run step completed and the program's behavior differed.
_HARNESS_ENV_STAGE = {
    "setup": "INFRA",
    "load": "LOAD",
    "run": "TEST_RUN",
    "unload": "CLEANUP",
}

# Cause-note vocabulary for availability refinement. Only the
# availability refinement reads the note; the INFRA verdict
# itself comes from the classification, and an unrecognized note
# falls back to UNKNOWN (still infrastructure, still
# gate-failing). Vocabulary is the harness's own emitted notes
# (setup admission/pin notes, not-found notes, load/run cause
# notes) plus the harness permission patterns.
_POLICY_PATTERNS = (
    "operation not permitted",
    "permission denied",
    "permission substrings",
    "eacces",
    "eperm",
    "unprivileged",
    "cap_sys_admin",
    "cap_bpf",
    "capabilities",
    "admission refused",
    "ownership token",
    "outside the owned root",
    "outside the owned run",
    "another run's ownership",
    "not pinned",
    "does not match the pinned",
)

_TOOLCHAIN_PATTERNS = (
    "bpftool binary not found",
    "bpftool version failed",
    "cannot hash bpftool",
    "unresolvable launcher",
)

_RESOURCE_PATTERNS = (
    "object file not found",
    "data-in file not found",
)


class HarnessEnvironment(Exception):
    """A consumed harness record reports environment/setup trouble.

    Raised by :func:`check_harness_exit` when a record carries
    the ``environment`` or ``setup`` classification and the case
    did not declare it expected. Carries the derived typed
    outcome: ``stage`` (a failure stage), ``availability`` (a
    test-contracts-v1 availability), ``cause`` (the record note
    or record identity), and the harness ``exit_code``. Suites
    catch this alongside their own ``EnvironmentFailure`` and
    record an infrastructure case result, never a product FAIL.
    """

    def __init__(self, message, *, stage, availability, cause,
                 exit_code):
        super().__init__(message)
        self.stage = stage
        self.availability = availability
        self.cause = cause
        self.exit_code = exit_code


class GuestMissing(HarnessEnvironment):
    """The guest produced no (parseable) result for a case.

    Raised where suites parse guest transcripts: invalid JSON or
    missing case blocks mean the result is missing, an
    infrastructure outcome at TEST_RUN with unknown cause, never
    a product FAIL and never a pass.
    """

    def __init__(self, message):
        super().__init__(
            message,
            stage="TEST_RUN",
            availability="UNKNOWN",
            cause="missing or unparseable guest result",
            exit_code=None,
        )


def _availability_from_note(note):
    """Refine availability from a harness cause note.

    Unrecognized notes (including None) yield UNKNOWN: the
    record is still infrastructure trouble, only the refinement
    is unknown.
    """
    text = (note or "").lower()
    if any(pattern in text for pattern in _POLICY_PATTERNS):
        return "POLICY_DENIED"
    if any(pattern in text for pattern in _TOOLCHAIN_PATTERNS):
        return "TOOLCHAIN_UNAVAILABLE"
    if any(pattern in text for pattern in _RESOURCE_PATTERNS):
        return "TARGET_RESOURCE_ABSENT"
    return "UNKNOWN"


def check_harness_exit(tag, *, exit, classification, stage,
                       contract_version=None, note=None, expect=0,
                       expect_environment=False):
    """Check one consumed harness record; return its typed outcome.

    ``tag`` names the record, ``exit``/``classification``/
    ``stage`` are the harness wire values, ``contract_version``
    (when given) must be 2, and ``note`` is the record cause
    note. Classification branches before the exit assertion: an
    ``environment`` or ``setup`` record raises
    :class:`HarnessEnvironment` carrying the derived
    infrastructure outcome (fail-closed into the env bucket,
    never ``AssertionError``), unless the case declares
    ``expect_environment`` (an expected refusal, asserted
    strictly and consumed as evidence on the PASS track). A
    non-environment exit mismatch raises ``AssertionError`` in
    the historical message shape. A negative (signal) exit
    raises ``AssertionError`` preserving the signed code: a
    signal death is an unclassified casualty and fails closed to
    FAIL, never to env or unavailable.

    Returns the derived ``(outcome, stage)`` pair: ``("PASS",
    None)`` on the pass track (including consumed expected
    refusals) or ``("FAIL", stage)`` for a matched failure exit
    (denial cases return this hint to the main loop, which
    records the wire-derived stage instead of the default).
    """
    if contract_version is not None and (
            contract_version != HARNESS_CONTRACT_VERSION):
        raise AssertionError(
            "%s: harness contract must be revision %d, got %r"
            % (tag, HARNESS_CONTRACT_VERSION, contract_version)
        )
    if exit is None:
        raise AssertionError(
            "%s: harness record carries no exit code" % (tag,)
        )
    if not isinstance(exit, int) or isinstance(exit, bool):
        raise AssertionError(
            "%s: harness exit %r is not an integer" % (tag, exit)
        )
    if exit < 0:
        raise AssertionError(
            "%s: harness killed by signal %d (%s/%s)"
            % (tag, exit, stage, classification)
        )
    if exit == 2:
        raise AssertionError(
            "%s: harness CLI misuse (exit 2): the suite guest "
            "script passed bad arguments" % (tag,)
        )
    if classification in ("environment", "setup") or exit == 3:
        if expect_environment:
            if classification != "environment" or exit != 3:
                raise AssertionError(
                    "%s: expected an environment record, got "
                    "exit %d (%s/%s)"
                    % (tag, exit, stage, classification)
                )
            return ("PASS", None)
        if classification == "setup" or exit == 6:
            derived_stage = "INFRA"
        else:
            derived_stage = _HARNESS_ENV_STAGE.get(stage, "INFRA")
        availability = _availability_from_note(note)
        raise HarnessEnvironment(
            "%s: harness environment record (exit %d, %s/%s%s)"
            % (
                tag, exit, stage, classification,
                (": %s" % note) if note else "",
            ),
            stage=derived_stage,
            availability=availability,
            cause=note or ("%s/%s exit %d" % (stage, classification, exit)),
            exit_code=exit,
        )
    if exit == 0:
        if classification is not None:
            raise AssertionError(
                "%s: malformed harness record: exit 0 with "
                "classification %r" % (tag, classification)
            )
        if expect_environment:
            raise AssertionError(
                "%s: expected an environment record, got exit 0"
                % (tag,)
            )
        if expect != 0:
            raise AssertionError(
                "%s: harness exit 0 (%s/%s), want %d"
                % (tag, stage, classification, expect)
            )
        return ("PASS", None)
    derived = {
        1: ("runtime", "RUNTIME"),
        4: ("verifier", "VERIFY"),
        5: ("loader", "LOAD"),
    }.get(exit)
    if derived is None or classification != derived[0]:
        raise AssertionError(
            "%s: harness exit %d (%s/%s) is not a known "
            "contract outcome" % (tag, exit, stage, classification)
        )
    if expect_environment:
        raise AssertionError(
            "%s: expected an environment record, got exit %d "
            "(%s/%s)" % (tag, exit, stage, classification)
        )
    if expect != exit:
        raise AssertionError(
            "%s: harness exit %d (%s/%s), want %d"
            % (tag, exit, stage, classification, expect)
        )
    return ("FAIL", derived[1])


def combine_outcomes(*hints):
    """Combine per-record hints into one case hint.

    The first non-PASS hint wins (fail-fast, matching the
    assert-abort order of the suites); all-PASS (or no hints)
    yields ``("PASS", None)``. Each hint is a
    :func:`check_harness_exit` return or None (ignored).
    """
    for hint in hints:
        if hint is None:
            continue
        outcome, stage = hint
        if outcome != "PASS":
            return (outcome, stage)
    return ("PASS", None)


# Unified guest-exit rule (F-043). A nonzero guest exit maps by
# transcript evidence, identically in every suite: completed
# proof evidence (a harness record with a product-failure
# classification, or a suite-declared product marker) means the
# guest observed product behavior and the exit is a proof
# failure; a guest that never ran our script (progress banner
# absent) or died in the runner itself (runner traceback) is an
# environment failure; anything else nonzero fails closed to
# proof, so a bare product ``exit 1`` can never hide in the env
# bucket.

PROOF_CLASSIFICATIONS = frozenset({"runtime", "verifier", "loader"})

RUNNER_FAILURE_MARKERS = ("Traceback (most recent call last)",)


def classify_guest_exit(returncode, output, *, records=(),
                        progress_banner, product_markers=()):
    """Classify a guest exit as ``ok``, ``proof`` or ``env``.

    ``returncode`` is the guest exit code, ``output`` the guest
    transcript, ``records`` the suite-parsed case records
    (mappings with a ``classification`` entry), and
    ``product_markers`` suite-declared transcript markers that
    prove a product observation. ``progress_banner`` (required)
    is the transcript line proving the guest ran our script; a
    nonzero exit without it means the guest never ran. Proof
    evidence wins over runner evidence: a completed failing
    observation stands even when the runner later crashed in
    teardown.
    """
    if not progress_banner:
        raise ValueError("classify_guest_exit needs a progress banner")
    if returncode == 0:
        return "ok"
    for record in records:
        try:
            classification = record.get("classification")
        except AttributeError:
            continue
        if classification in PROOF_CLASSIFICATIONS:
            return "proof"
    for marker in product_markers:
        if marker and marker in output:
            return "proof"
    if any(marker in output for marker in RUNNER_FAILURE_MARKERS):
        return "env"
    if progress_banner not in output:
        return "env"
    return "proof"


# Suite-result emission (F-049): the structured result protocol
# between suites and the matrix runner. Each suite seals one
# immutable run plan (case IDs, target, revisions, input hashes,
# typed expectations), records one case result per case, runs the
# real ``mojobpf.validation`` aggregation over its own records,
# and prints the plan, the results and the terminal suite record
# as single-line ``MOJOBPF_*`` JSON documents. The matrix
# extracts these lines, re-parses and re-aggregates them against
# its own pins (expected case IDs, commit, suite bytes, lane
# target), and judges the suite by the recomputed verdict --
# never by scraping PASS/FAIL lines. A suite that prints PASS
# without emitting a verifying terminal record fails; a missing
# or truncated terminal record fails; the suite exit code
# derives from the suite's own aggregation verdict, and the
# matrix additionally requires exit and verdict to agree.
#
# Observed outcomes are derived, never chosen: harness-backed
# cases derive from :func:`check_harness_exit` hints, denial
# cases expect a wire-derived FAIL at a pinned stage, and every
# other case derives from its main-loop exception (none/PASS,
# AssertionError or ProofFailure/FAIL, environment/INFRA_ERROR,
# lease-gated/NOT_RUN). Cleanup is censused per case (see the
# census above): a leak poisons its case with RESIDUE, and a
# passing case that leaks becomes INFRA_ERROR at CLEANUP (a PASS
# with residue is no PASS).

PLAN_TOOL_MATRIX = "run_vm_tests"
PLAN_TOOL_STANDALONE = "standalone"

LINE_PLAN = "MOJOBPF_RUN_PLAN "
LINE_RESULT = "MOJOBPF_CASE_RESULT "
LINE_SUITE = "MOJOBPF_SUITE_RESULT "

ENV_TARGET_MANIFEST = "MOJOBPF_TARGET_MANIFEST"
ENV_PLAN_COMMIT = "MOJOBPF_PLAN_COMMIT"
ENV_PLAN_TOOL = "MOJOBPF_PLAN_TOOL"

ZERO_SHA256 = "0" * 64
ZERO_COMMIT = "0" * 40
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

_CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

_validation_mod = None


def _validation():
    """Import ``mojobpf.validation`` from this checkout (cached).

    The contracts library lives in the same checkout as the
    suites (same-bits guarantee); it is imported lazily so the
    guest-runner composition above stays importable without it.
    Refuses a ``mojobpf`` resolving outside this checkout: a
    version-skewed contract library must fail loudly, never
    silently emit records the matrix reads differently.
    """
    global _validation_mod
    if _validation_mod is None:
        here = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(os.path.dirname(here))
        src = os.path.join(repo_root, "src")
        if os.path.isdir(src) and src not in sys.path:
            sys.path.insert(0, src)
        import mojobpf.validation as validation
        anchor = os.path.join(
            src, "mojobpf", "validation", "__init__.py"
        )
        actual = os.path.abspath(
            getattr(validation, "__file__", "")
        )
        if actual != os.path.abspath(anchor):
            raise RuntimeError(
                "mojobpf.validation resolved outside this "
                "checkout: %s" % (getattr(validation, "__file__", None),)
            )
        _validation_mod = validation
    return _validation_mod


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _digest_file_bytes(path):
    """Return the file's SHA-256 hex digest, or None if unreadable.

    A seal-time read failure records as unobserved (the
    finish-time hash stays authoritative for attestation); only
    two observed digests that differ -- or observed bytes that
    vanish -- count as a byte mismatch.
    """
    try:
        return _sha256_file(path)
    except OSError:
        return None


def _standalone_commit(repo_root):
    """Return the worktree HEAD or the unknown-commit sentinel."""
    try:
        completed = subprocess.run(
            ["git", "-C", repo_root, "rev-parse", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return ZERO_COMMIT
    commit = completed.stdout.strip() if completed.returncode == 0 else ""
    if not _COMMIT_RE.match(commit):
        return ZERO_COMMIT
    return commit


def _standalone_target_manifest(repo_root, lane_release, arch=""):
    """Build the lane-declared target without matrix help.

    Standalone runs (no ``MOJOBPF_TARGET_MANIFEST``) resolve the
    lane through ``lane_lock`` and construct the manifest with
    the matrix runner's own constructor, so standalone plans
    follow the same documented rules. Matrix runs never reach
    here: the suite embeds the matrix manifest verbatim.
    """
    import lane_lock
    here = os.path.dirname(os.path.abspath(__file__))
    checkout = os.path.dirname(os.path.dirname(here))
    runner_path = os.path.join(checkout, "ci", "run_vm_tests.py")
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "guest_proc_matrix_runner", runner_path
    )
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    lane = lane_lock.lane_for_release(repo_root, lane_release, arch)
    manifest = runner.lane_target_manifest(lane)
    return json.loads(json.dumps(manifest))


class SuiteRecorder:
    """Seal a run plan, record typed cases, emit the terminal record.

    One recorder per suite run, driven by the suite main loop::

        rec = SuiteRecorder(
            suite_id="kernel-xdp", suite_path=__file__,
            case_ids=[...], denials={...}, inputs={...},
            lane_release=VNG_RELEASE)
        for name in case_ids:
            rec.begin_case(name)
            try:
                hint = func()
            except HarnessEnvironment as exc:
                rec.end_case_infra(name, exc.stage, exc.availability)
                return rec.finish(stage_dir=..., unavailable_seen=False)
            except EnvironmentFailure:
                rec.end_case_infra(name, "INFRA", "UNKNOWN")
                return rec.finish(...)
            except (AssertionError, ProofFailure):
                rec.end_case_fail(name)
            else:
                rec.end_case_hint(name, hint)
        return rec.finish(...)

    ``denials`` maps denial case IDs to ``(denies_case_id,
    failure_stage)`` pairs; ``inputs`` maps case IDs to
    ``{"sources": [...], "objects": [...], "corpus": [...]}``
    file lists where each entry is an absolute path or a
    ``("stage", basename)`` tuple resolved against the
    ``stage_dir`` passed to :meth:`finish`. A class with no
    declared files -- or whose files total zero bytes --
    digests to the empty-input hash; a class with any missing
    file digests to zeros (an incomplete input, which can
    never back a PASS). Cases the loop never ends are recorded
    NOT_RUN with unknown cause. The run marks itself a child
    subreaper at construction so orphaned descendants
    (including setsid escapees) stay visible to the census;
    when the guard cannot be set, every census reads
    uncensused and no CLEAN is claimed.

    Input bytes seal before attestation: absolute-path inputs
    hash at construction, staged inputs seal when their case
    ends (the fixture builds them mid-run, so case completion
    is the earliest observable point). :meth:`finish`
    re-hashes and fails any case whose observed bytes changed
    or vanished, so a post-completion swap is attested as
    FAIL at TEST_RUN, never as PASS.
    """

    def __init__(self, suite_id, suite_path, case_ids, denials=None,
                 inputs=None, lane_release="", arch="",
                 revisions=None, target_manifest=None):
        validation = _validation()
        if not isinstance(suite_id, str) or not _CASE_ID_RE.match(
                suite_id):
            raise ValueError("suite_id %r is not a plan ID" % (suite_id,))
        if not case_ids or len(set(case_ids)) != len(list(case_ids)):
            raise ValueError("case_ids must be a non-empty unique list")
        for case_id in case_ids:
            if not isinstance(case_id, str) or not _CASE_ID_RE.match(
                    case_id):
                raise ValueError(
                    "case_id %r is not a plan ID" % (case_id,)
                )
        denials = dict(denials or {})
        for case_id, spec in denials.items():
            if case_id not in case_ids:
                raise ValueError(
                    "denial %r is not a plan case" % (case_id,)
                )
            denies, stage = spec
            if denies not in case_ids or denies == case_id:
                raise ValueError(
                    "denial %r must deny another plan case"
                    % (case_id,)
                )
            if denies in denials:
                raise ValueError(
                    "denial %r must deny a positive case"
                    % (case_id,)
                )
            if stage not in ("RUNTIME", "VERIFY", "LOAD"):
                raise ValueError(
                    "denial %r must pin a wire stage "
                    "(RUNTIME/VERIFY/LOAD), got %r"
                    % (case_id, stage)
                )
        inputs = dict(inputs or {})
        for case_id, classes in inputs.items():
            if case_id not in case_ids:
                raise ValueError(
                    "inputs for unknown case %r" % (case_id,)
                )
            if set(classes) != {"sources", "objects", "corpus"}:
                raise ValueError(
                    "inputs for %r must name sources/objects/corpus"
                    % (case_id,)
                )
            for _class, entries in classes.items():
                for entry in entries:
                    if isinstance(entry, str):
                        if not entry or not os.path.isabs(entry):
                            raise ValueError(
                                "inputs for %r: %s entry %r "
                                "must be an absolute path"
                                % (case_id, _class, entry)
                            )
                        continue
                    if (
                        isinstance(entry, (tuple, list))
                        and len(entry) == 2
                        and entry[0] == "stage"
                        and isinstance(entry[1], str)
                        and entry[1]
                    ):
                        continue
                    raise ValueError(
                        "inputs for %r: bad %s entry %r"
                        % (case_id, _class, entry)
                    )
        self._val = validation
        self.suite_id = suite_id
        self.suite_path = os.path.abspath(suite_path)
        here = os.path.dirname(os.path.abspath(__file__))
        self.repo_root = os.path.dirname(os.path.dirname(here))
        self.case_ids = list(case_ids)
        self.denials = denials
        self.inputs = inputs
        self.lane_release = lane_release
        self.arch = arch
        # The plan seals BEFORE execution: these private copies
        # freeze the declared obligations at construction, and
        # only they feed the emitted plan. Post-hoc edits --
        # added denials, swapped inputs, mutated revisions --
        # can never weaken the obligations the run is judged
        # by; at worst they describe a run the sealed plan no
        # longer matches, which fails closed.
        self._sealed_case_ids = list(case_ids)
        self._sealed_denials = copy.deepcopy(denials)
        self._sealed_inputs = copy.deepcopy(inputs)
        self._explicit_revisions = (
            None if revisions is None
            else copy.deepcopy(revisions)
        )
        self._explicit_manifest = (
            None if target_manifest is None
            else copy.deepcopy(target_manifest)
        )
        self._cases = {}
        self._begun = {}
        self._transcripts = []
        # Flow-scoped setsid guard (see _ensure_subreaper): the
        # run claims CLEAN only while the guard holds; without
        # it every census reads uncensused (NOT_CHECKED).
        self._subreaper_ok = _ensure_subreaper()
        self._run_baseline = (
            census_snapshot() if self._subreaper_ok else None
        )
        self.run_id = "%s-%s-%d-%d" % (
            suite_id, lane_release or "lane",
            os.getpid(), int(time.time() * 1000),
        )
        # Input byte seals (see the class docstring): absolute
        # entries hash here, at plan construction; staged
        # entries seal per case in _end_case. Earliest
        # observation wins, so a mid-run change still
        # mismatches at finish.
        self._sealed_entry_digests = {}
        self._seal_absolute_inputs()

    def note_transcript(self, label, text):
        """Attach transcript bytes as case evidence (digest-bound)."""
        if not label or not isinstance(label, str):
            raise ValueError("transcript label must be a string")
        data = text.encode("utf-8", "replace") if isinstance(
            text, str
        ) else bytes(text)
        self._transcripts.append(
            {
                "path": "transcript:%s" % label,
                "sha256": _sha256_bytes(data),
                "bytes": len(data),
            }
        )

    def begin_case(self, case_id):
        """Open a case: snapshots the owned census for leak diffing."""
        if case_id not in self._sealed_case_ids:
            raise ValueError("begin_case: unknown case %r" % (case_id,))
        if case_id in self._begun:
            raise ValueError(
                "begin_case: case %r already begun" % (case_id,)
            )
        self._begun[case_id] = (
            census_snapshot() if self._subreaper_ok else None
        )

    def _end_case(self, case_id, outcome, stage, availability):
        if case_id not in self._sealed_case_ids:
            raise ValueError("end_case: unknown case %r" % (case_id,))
        if case_id in self._cases:
            raise ValueError(
                "end_case: case %r already recorded" % (case_id,)
            )
        if availability not in self._val.AVAILABILITY:
            raise ValueError(
                "end_case: unknown availability %r" % (availability,)
            )
        if case_id not in self._begun:
            raise ValueError(
                "end_case: case %r never begun" % (case_id,)
            )
        self._seal_case_inputs(case_id)
        before = self._begun[case_id]
        if before is None:
            cleanup = {"status": "NOT_CHECKED", "residue": []}
        else:
            leaks = census_leaks(before)
            if leaks is None:
                cleanup = {"status": "NOT_CHECKED", "residue": []}
            elif leaks:
                cleanup = {"status": "RESIDUE", "residue": leaks}
            else:
                cleanup = {"status": "CLEAN", "residue": []}
        if outcome == "PASS" and cleanup["status"] != "CLEAN":
            # A PASS with residue or an uncensused cleanup is no
            # PASS: the case becomes infrastructure-failed at
            # CLEANUP instead of emitting a record the contracts
            # would reject as malformed.
            outcome, stage = "INFRA_ERROR", "CLEANUP"
        self._cases[case_id] = {
            "outcome": outcome,
            "failure_stage": stage,
            "availability": availability,
            "cleanup": cleanup,
        }

    def end_case_pass(self, case_id):
        """Record a passed case (census decides CLEAN vs poisoned)."""
        if case_id in self._sealed_denials:
            raise ValueError(
                "end_case_pass: denial %r can only be satisfied "
                "by a returned failure hint" % (case_id,)
            )
        self._end_case(case_id, "PASS", None, "APPLICABLE")

    def end_case_fail(self, case_id, stage="RUNTIME"):
        """Record a product-failed case at ``stage`` (default RUNTIME).

        A denial that raises records FAIL at TEST_RUN instead:
        the proof broke before completing, so the observation
        must never equal the pinned wire stage (a denial
        satisfied by an assert-mismatch would prove nothing).
        """
        if stage not in self._val.FAILURE_STAGES:
            raise ValueError("end_case_fail: unknown stage %r" % (stage,))
        if case_id in self._sealed_denials:
            stage = "TEST_RUN"
        self._end_case(case_id, "FAIL", stage, "APPLICABLE")

    def end_case_hint(self, case_id, hint):
        """Record from a test return: None/PASS-hint or FAIL-hint.

        None (tests that return nothing) records a pass. A
        ``("FAIL", stage)`` hint from
        :func:`check_harness_exit` records the wire-derived
        stage. Anything else raises loudly: a malformed hint is
        a suite author error and must fail closed, never
        silently become a PASS. A denial case returning no
        failure hint raises too: the denial observed nothing
        failing, which can never satisfy its expectation.
        """
        if hint is None or (
            isinstance(hint, tuple)
            and len(hint) == 2
            and hint[0] == "PASS"
            and hint[1] is None
        ):
            if case_id in self._sealed_denials:
                raise ValueError(
                    "end_case_hint: denial %r returned no "
                    "failure hint" % (case_id,)
                )
            self._end_case(case_id, "PASS", None, "APPLICABLE")
            return
        if (
            isinstance(hint, tuple)
            and len(hint) == 2
            and hint[0] == "FAIL"
            and hint[1] in self._val.FAILURE_STAGES
        ):
            self._end_case(case_id, "FAIL", hint[1], "APPLICABLE")
            return
        raise ValueError(
            "end_case_hint: malformed hint %r for case %r"
            % (hint, case_id)
        )

    def end_case_infra(self, case_id, stage, availability):
        """Record an infrastructure-failed case (precise or coarse)."""
        if stage not in self._val.FAILURE_STAGES:
            raise ValueError(
                "end_case_infra: unknown stage %r" % (stage,)
            )
        self._end_case(case_id, "INFRA_ERROR", stage, availability)

    def end_case_not_run(self, case_id, availability):
        """Record a case that never ran (lease-gated or aborted)."""
        self._end_case(case_id, "NOT_RUN", "INFRA", availability)

    @staticmethod
    def _entry_key(_class, entry):
        return (_class, json.dumps(entry, sort_keys=True))

    def _seal_absolute_inputs(self):
        """Hash absolute-path inputs at plan construction."""
        for case_id in self._sealed_case_ids:
            classes = self._sealed_inputs.get(case_id, {})
            sealed = self._sealed_entry_digests.setdefault(case_id, {})
            for _class in ("sources", "objects", "corpus"):
                for entry in classes.get(_class, []):
                    if isinstance(entry, str) and os.path.isabs(entry):
                        key = self._entry_key(_class, entry)
                        sealed[key] = (
                            "absolute", _digest_file_bytes(entry)
                        )

    def _seal_case_inputs(self, case_id):
        """Seal a case's inputs at case completion (earliest wins).

        Absolute entries keep their construction seal when one
        exists; staged entries resolve each basename against
        the owned-stage registry and record every observed
        ``{stage: digest}`` pair (an empty map means the file
        was unobservable then, which stays lenient at finish).
        """
        classes = self._sealed_inputs.get(case_id, {})
        sealed = self._sealed_entry_digests.setdefault(case_id, {})
        for _class in ("sources", "objects", "corpus"):
            for entry in classes.get(_class, []):
                key = self._entry_key(_class, entry)
                if key in sealed:
                    continue
                if isinstance(entry, str):
                    if os.path.isabs(entry):
                        sealed[key] = (
                            "absolute", _digest_file_bytes(entry)
                        )
                    continue
                observed = {}
                for stage in sorted(_OWNED_STAGES):
                    digest = _digest_file_bytes(
                        os.path.join(stage, entry[1])
                    )
                    if digest is not None:
                        observed[os.path.abspath(stage)] = digest
                sealed[key] = ("staged", observed)

    def _verify_sealed_inputs(self, stage_dir):
        """Return ``{case_id: [mismatches]}`` for resealed inputs.

        Compares the finish-time bytes against the earliest
        seals. Only observed-then-changed (or
        observed-then-vanished) bytes mismatch; entries
        unobserved at seal time stay lenient (staged late, or
        finished from a directory the seal never resolved),
        with the finish-time hash authoritative.
        """
        if stage_dir is None:
            stage_key = None
        else:
            stage_key = os.path.abspath(stage_dir)
        mismatches = {}
        for case_id in self._sealed_case_ids:
            sealed = self._sealed_entry_digests.get(case_id, {})
            if not sealed:
                continue
            classes = self._sealed_inputs.get(case_id, {})
            bad = []
            for _class in ("sources", "objects", "corpus"):
                for entry in classes.get(_class, []):
                    record = sealed.get(self._entry_key(_class, entry))
                    if record is None:
                        continue
                    kind, first = record
                    if kind == "absolute":
                        if first is None:
                            continue
                        if _digest_file_bytes(entry) != first:
                            bad.append(
                                "%s entry %r changed after sealing"
                                % (_class, entry)
                            )
                    elif stage_key is not None and stage_key in first:
                        current = _digest_file_bytes(
                            os.path.join(stage_dir, entry[1])
                        )
                        if current != first[stage_key]:
                            bad.append(
                                "%s staged entry %r changed after "
                                "sealing" % (_class, entry[1])
                            )
            if bad:
                mismatches[case_id] = bad
        return mismatches

    def _resolve_revisions(self):
        """Resolve (commit, package, tool): explicit, matrix env, standalone."""
        if self._explicit_revisions is not None:
            revisions = dict(self._explicit_revisions)
            if not _COMMIT_RE.match(
                    revisions.get("repository_commit", "")):
                raise ValueError("explicit revisions carry a bad commit")
            for key in ("package", "tool"):
                if not revisions.get(key):
                    raise ValueError(
                        "explicit revisions lack %s" % key
                    )
            return revisions
        commit = os.environ.get(ENV_PLAN_COMMIT, "")
        tool = os.environ.get(ENV_PLAN_TOOL, "")
        if commit or tool:
            if not _COMMIT_RE.match(commit):
                raise ValueError(
                    "%s=%r is not a commit" % (ENV_PLAN_COMMIT, commit)
                )
            if not tool:
                raise ValueError("%s is empty" % ENV_PLAN_TOOL)
            return {
                "repository_commit": commit,
                "package": "mojobpf@" + commit,
                "tool": tool,
            }
        commit = _standalone_commit(self.repo_root)
        return {
            "repository_commit": commit,
            "package": "mojobpf@" + commit,
            "tool": PLAN_TOOL_STANDALONE,
        }

    def _resolve_target(self):
        """Resolve the lane target manifest: explicit, matrix, standalone."""
        if self._explicit_manifest is not None:
            manifest = json.loads(json.dumps(self._explicit_manifest))
        else:
            raw = os.environ.get(ENV_TARGET_MANIFEST, "")
            if raw:
                try:
                    manifest = json.loads(raw)
                except ValueError as exc:
                    raise ValueError(
                        "%s is not JSON: %s" % (ENV_TARGET_MANIFEST, exc)
                    )
            else:
                manifest = _standalone_target_manifest(
                    self.repo_root, self.lane_release, self.arch
                )
        # Validated here so a malformed manifest fails the suite
        # loudly instead of emitting records the matrix rejects.
        return self._val.TargetManifest.from_dict(manifest)

    def _hash_inputs(self, stage_dir):
        """Digest the declared per-case input classes.

        Returns ``{case_id: {"sources": ..., "objects": ...,
        "corpus": ...}}``. A class with no declared files digests
        to the empty-input hash, as does a class whose files
        total zero bytes (declared-but-empty backs no
        workload); a class with any missing file digests to
        zeros. ``("stage", basename)`` entries resolve against
        ``stage_dir`` (None means every staged entry is
        missing: nothing was built or staged).
        """
        digests = {}
        for case_id in self._sealed_case_ids:
            classes = self._sealed_inputs.get(case_id, {})
            hashed = {}
            for _class in ("sources", "objects", "corpus"):
                entries = classes.get(_class, [])
                if not entries:
                    hashed[_class] = EMPTY_SHA256
                    continue
                digest = hashlib.sha256()
                complete = True
                seen_bytes = 0
                for entry in sorted(
                        entries, key=lambda item: json.dumps(item)):
                    if isinstance(entry, str):
                        path = entry
                    else:
                        if stage_dir is None:
                            complete = False
                            break
                        path = os.path.join(stage_dir, entry[1])
                    try:
                        with open(path, "rb") as handle:
                            for chunk in iter(
                                    lambda: handle.read(65536), b""):
                                digest.update(chunk)
                                seen_bytes += len(chunk)
                    except OSError:
                        complete = False
                        break
                    digest.update(b"\x00")
                if not complete:
                    hashed[_class] = ZERO_SHA256
                elif seen_bytes == 0:
                    hashed[_class] = EMPTY_SHA256
                else:
                    hashed[_class] = digest.hexdigest()
            digests[case_id] = hashed
        return digests

    def _suite_evidence(self):
        """Return the auto-attached evidence: suite bytes + transcripts."""
        try:
            rel = os.path.relpath(self.suite_path, self.repo_root)
        except ValueError:
            rel = os.path.basename(self.suite_path)
        if rel.startswith(".."):
            rel = os.path.basename(self.suite_path)
        evidence = [
            {
                "path": "suite:%s" % rel,
                "sha256": _sha256_file(self.suite_path),
                "bytes": os.path.getsize(self.suite_path),
            }
        ]
        evidence.extend(self._transcripts)
        return evidence

    def _build_plan(self, revisions, target, digests):
        """Seal the immutable run plan for this run."""
        validation = self._val
        suite_sha = _sha256_file(self.suite_path)
        consumer = {
            "name": self.suite_id,
            "version": revisions["repository_commit"],
            "artifact_sha256": suite_sha,
        }
        cases = []
        for case_id in self._sealed_case_ids:
            entry = {
                "case_id": case_id,
                "fixture_id": "fx-%s-%s" % (self.suite_id, case_id),
                "targets": [target.fingerprint],
                "expectation": (
                    "denial" if case_id in self._sealed_denials else "positive"
                ),
                "required": True,
                "consumers": [dict(consumer)],
                "source_sha256": digests[case_id]["sources"],
                "object_sha256": digests[case_id]["objects"],
                "corpus_sha256": digests[case_id]["corpus"],
                "expected_attempts": 1,
            }
            if case_id in self._sealed_denials:
                denies, stage = self._sealed_denials[case_id]
                entry["denies"] = denies
                entry["expected"] = {
                    "outcome": "FAIL", "failure_stage": stage
                }
            cases.append(entry)
        return validation.plan(
            cases, [target.to_dict()], dict(revisions)
        )

    def _build_results(self, plan, digests, evidence):
        """Build one validated result per plan case, in plan order."""
        validation = self._val
        by_case = {case.case_id: case for case in plan.cases}
        results = []
        for case_id in self._sealed_case_ids:
            plan_case = by_case[case_id]
            stored = self._cases[case_id]
            outcome = stored["outcome"]
            stage = stored["failure_stage"]
            observed = {"outcome": outcome, "failure_stage": stage}
            record = {
                "schema_version": 1,
                "run_id": self.run_id,
                "case_id": case_id,
                "target_fingerprint": plan_case.targets[0],
                "attempt": 1,
                "plan_hash": plan.plan_hash,
                "identities": {
                    "repository_commit": plan.revisions[
                        "repository_commit"],
                    "package": plan.revisions["package"],
                    "tool": plan.revisions["tool"],
                    "consumer": {
                        "name": self.suite_id,
                        "version": plan.revisions[
                            "repository_commit"],
                        "artifact_sha256": _sha256_file(
                            self.suite_path),
                    },
                    "object_sha256": digests[case_id]["objects"],
                    "source_sha256": digests[case_id]["sources"],
                    "workload": {
                        "fixture_id": plan_case.fixture_id,
                        "corpus_sha256": digests[case_id]["corpus"],
                    },
                },
                "applicability": stored["availability"],
                "required": True,
                "expected": dict(plan_case.expected),
                "observed": observed,
                "outcome": outcome,
                "failure_stage": stage,
                "evidence": [dict(item) for item in evidence],
                "cleanup": {
                    "status": stored["cleanup"]["status"],
                    "residue": list(stored["cleanup"]["residue"]),
                },
            }
            results.append(validation.CaseResult.from_dict(record))
        return results

    def _reap_and_annotate(self):
        """Reap run strays as hygiene; annotate attributed leaks.

        Returns surviving residue entries unattributed to any
        case (only possible for strays appearing outside any
        case window); the caller attributes them to the last
        recorded case. Leaks attributed at :meth:`_end_case`
        time gain a ``(gone at finish)`` / ``(survives)``
        suffix so triage can tell transient leaks from
        survivors. None when no baseline exists or the
        setsid guard is down (an unguarded final sweep cannot
        rule out an escape).
        """
        reap_zombie_children()
        baseline = self._run_baseline
        if baseline is None or not self._subreaper_ok:
            return None
        survivors = reap_owned_strays(baseline, timeout=10.0)
        if survivors is None:
            return None
        living = set()
        for entry in survivors:
            match = re.match(r"pid (\d+) ", entry)
            if match:
                living.add(int(match.group(1)))
        attributed = set()
        for stored in self._cases.values():
            annotated = []
            for entry in stored["cleanup"]["residue"]:
                match = re.match(r"pid (\d+) ", entry)
                if match:
                    attributed.add(int(match.group(1)))
                    if int(match.group(1)) in living:
                        annotated.append(entry + " (survives)")
                    else:
                        annotated.append(entry + " (gone at finish)")
                else:
                    annotated.append(entry)
            stored["cleanup"]["residue"] = annotated
        return [
            entry for entry in survivors
            if not re.match(r"pid (\d+) ", entry)
            or int(re.match(r"pid (\d+) ", entry).group(1))
            not in attributed
        ]

    def _fill_unrecorded(self):
        """Record unrun cases NOT_RUN (loop aborted early)."""
        for case_id in self._sealed_case_ids:
            if case_id not in self._cases:
                self._cases[case_id] = {
                    "outcome": "NOT_RUN",
                    "failure_stage": "INFRA",
                    "availability": "UNKNOWN",
                    "cleanup": {"status": "NOT_CHECKED", "residue": []},
                }

    def finish(self, *, stage_dir=None, unavailable_seen=False):
        """Aggregate, emit plan/results/terminal, return the exit code.

        Gaps (cases the loop never ended) are recorded NOT_RUN.
        Run strays are reaped as hygiene and attributed leaks
        annotated. Declared inputs hash, then the byte seals
        are verified (a case whose observed bytes changed or
        vanished fails at TEST_RUN), then owned stages are
        discarded with any removal failure folded into the
        terminal (a PASS it can no longer prove clean becomes
        INFRA_ERROR at CLEANUP) -- teardown always precedes
        the terminal. The exit derives from the aggregation
        verdict: 0 for PASS, 1 for FAIL, 3 for INCOMPLETE with
        lease-gated cases, else 2. Every path through the
        suites funnels here (or :meth:`finish_unrun`), so the
        exit always agrees with the emitted terminal record.
        """
        self._fill_unrecorded()
        unattributed = self._reap_and_annotate()
        if unattributed is None:
            # Final hygiene is unverifiable: every CLEAN claim
            # made earlier is withdrawn (NOT_CHECKED), and a
            # PASS that can no longer prove clean cleanup
            # becomes INFRA_ERROR at CLEANUP -- unknown cleanup
            # is never reported CLEAN.
            for stored in self._cases.values():
                if stored["cleanup"]["status"] != "CLEAN":
                    continue
                stored["cleanup"] = {
                    "status": "NOT_CHECKED", "residue": [],
                }
                if stored["outcome"] == "PASS":
                    stored["outcome"] = "INFRA_ERROR"
                    stored["failure_stage"] = "CLEANUP"
        elif unattributed:
            last = self._sealed_case_ids[-1]
            stored = self._cases[last]
            stored["cleanup"]["residue"].extend(unattributed)
            stored["cleanup"]["status"] = "RESIDUE"
            if stored["outcome"] == "PASS":
                stored["outcome"] = "INFRA_ERROR"
                stored["failure_stage"] = "CLEANUP"
        revisions = self._resolve_revisions()
        target = self._resolve_target()
        digests = self._hash_inputs(stage_dir)
        for case_id, bad in self._verify_sealed_inputs(
                stage_dir).items():
            # The attestation is void: the bytes the case ran
            # against no longer match the sealed bytes, so the
            # case fails at TEST_RUN (never the pinned wire
            # stage, so no denial is satisfied) with the
            # resealed entries as residue.
            stored = self._cases[case_id]
            stored["cleanup"]["residue"].extend(
                "input bytes changed after seal: %s" % item
                for item in bad
            )
            stored["cleanup"]["status"] = "RESIDUE"
            stored["outcome"] = "FAIL"
            stored["failure_stage"] = "TEST_RUN"
        _discarded, teardown_errors = (
            _discard_owned_stages_collected()
        )
        if teardown_errors:
            # Teardown runs before the terminal is emitted, so
            # a failed removal lands in the terminal: the last
            # case carries the residue, and a PASS it can no
            # longer prove clean becomes INFRA_ERROR at
            # CLEANUP. Failed stages stay registered for the
            # post-finish retry.
            last = self._sealed_case_ids[-1]
            stored = self._cases[last]
            stored["cleanup"]["residue"].extend(
                "stage %s not removed: %s" % (stage, message)
                for stage, message in teardown_errors
            )
            stored["cleanup"]["status"] = "RESIDUE"
            if stored["outcome"] == "PASS":
                stored["outcome"] = "INFRA_ERROR"
                stored["failure_stage"] = "CLEANUP"
        plan = self._build_plan(revisions, target, digests)
        evidence = self._suite_evidence()
        results = self._build_results(plan, digests, evidence)
        decision = self._val.aggregate(plan, results)
        print("%s%s" % (LINE_PLAN, json.dumps(
            plan.to_dict(), sort_keys=True)))
        for result in results:
            print("%s%s" % (LINE_RESULT, json.dumps(
                result.to_dict(), sort_keys=True)))
        print("%s%s" % (LINE_SUITE, json.dumps(
            decision.to_suite_dict(), sort_keys=True)))
        sys.stdout.flush()
        if decision.verdict == "PASS":
            return 0
        if decision.verdict == "FAIL":
            return 1
        return 3 if unavailable_seen else 2

    def finish_unrun(self, reason):
        """Emit an all-NOT_RUN terminal record; return 2.

        The ``python -O`` refusal path: nothing ran (asserts
        would be stripped), so every case is NOT_RUN at
        TOOLCHAIN_UNAVAILABLE and the verdict is INCOMPLETE.
        Prints the refusal line first, then the records.
        """
        print("REFUSED: %s" % reason)
        for case_id in self._sealed_case_ids:
            self._cases[case_id] = {
                "outcome": "NOT_RUN",
                "failure_stage": "INFRA",
                "availability": "TOOLCHAIN_UNAVAILABLE",
                "cleanup": {"status": "NOT_CHECKED", "residue": []},
            }
        return self.finish(unavailable_seen=False)
