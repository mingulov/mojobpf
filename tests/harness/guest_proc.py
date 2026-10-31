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
import contextlib
import copy
import fcntl
import functools
import hashlib
import io
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

    Best-effort like :func:`_scan_census`: processes that exit
    mid-scan are skipped. Returns None when the scan is
    untrustworthy -- denied enumeration, or any entry whose
    stat cannot be read or parsed while the pid is still
    present (or whose presence cannot even be determined) --
    so a failed stat read on a potentially-owned pid never
    reads as an empty table. This is the matrix runner's
    owned-process-tracking composition
    (``ci/run_vm_tests.py``), shared so every suite reaps the
    same way.
    """
    table = {}
    try:
        entries = [entry for entry in os.listdir("/proc") if entry.isdigit()]
    except OSError:
        return None
    for entry in entries:
        try:
            pid = int(entry)
            # errors="replace": a foreign comm may hold
            # non-UTF-8 bytes; the numeric tail still parses,
            # so membership stays attributable instead of
            # crashing the scan.
            with open("/proc/%s/stat" % entry, encoding="utf-8",
                      errors="replace") as handle:
                text = handle.read()
            fields = text.rsplit(")", 1)
            if len(fields) != 2:
                raise ValueError("truncated stat for %s" % entry)
            rest = fields[1].split()
            if len(rest) < 3:
                raise ValueError("truncated stat for %s" % entry)
            ppid = int(rest[1])
            pgid = int(rest[2])
        except (OSError, ValueError):
            # A pid that vanished mid-scan is skipped; a pid
            # that is still present but unreadable -- or whose
            # presence check itself fails (denied directory
            # metadata) -- makes the whole snapshot
            # untrustworthy, so the scan is refused instead of
            # silently dropping the entry (see
            # :func:`_scan_census`).
            try:
                present = _pid_still_present(entry)
            except OSError:
                return None
            if present:
                return None
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
    Returns None when the process table itself is unreadable
    (an unknown survivor set, never an empty one).
    """
    table = _scan_processes()
    if table is None:
        return None
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
    (D-state) straggler is reported, never silently dropped, and
    an unreadable process table reports the kill unverified,
    never clean; the caller records the entries in the typed
    cleanup result.
    """
    seen_groups = {pgid}
    deadline = time.monotonic() + 30
    first = True
    while time.monotonic() < deadline:
        table = _scan_processes()
        if table is None:
            if first and not os.path.isdir("/proc"):
                # No snapshot (no /proc): fall back to the guest
                # group alone. The kill is unverifiable, so the
                # residue says so honestly instead of claiming clean.
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                return ["pgid %d kill unverified (no /proc)" % pgid]
            first = False
            # Unreadable table, owned tree possibly alive: keep
            # signalling every owned group seen so far and wait
            # for a trustworthy snapshot. Emptiness can never be
            # verified over read errors, so this path never
            # returns clean.
            for group in sorted(seen_groups):
                try:
                    os.killpg(group, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            time.sleep(0.2)
            continue
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
    final = _scan_processes()
    if final is None:
        return [
            "pgid %d kill unverified (process table unreadable)"
            % pgid
        ]
    return _residue_entries(final, seen_groups)


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


def _pid_still_present(entry):
    """Return True when ``/proc/<entry>`` still exists.

    True means the pid is alive; False is returned only when
    the stat proves it vanished (``FileNotFoundError``). Any
    other metadata failure propagates: a denied or unreadable
    directory is census uncertainty, never evidence of
    absence. (``os.path.isdir`` must not be used here: it
    swallows metadata errors into False, which would read a
    concealed live child as vanished.)
    """
    try:
        os.stat("/proc/%s" % entry)
    except FileNotFoundError:
        return False
    return True


def _scan_census():
    """Snapshot the process table into ``{pid: (ppid, pgid, session, state)}``.

    Best-effort like :func:`_scan_processes`: processes that exit
    mid-scan are skipped. Unlike the kill scan this one also
    reads the session id, and it never touches signalling.
    Returns None when the scan is untrustworthy: denied
    enumeration, or a table that cannot even see this very
    process (an empty snapshot reads as uncensused, never as
    clean), or any entry whose stat cannot be read or parsed
    while the pid is still present -- or whose presence cannot
    even be determined (denied directory metadata). A denied
    owned stat, a truncated stat, or a denied directory lookup
    must never read as clean.
    """
    table = {}
    try:
        entries = [entry for entry in os.listdir("/proc") if entry.isdigit()]
    except OSError:
        return None
    for entry in entries:
        try:
            pid = int(entry)
            # errors="replace": a foreign comm may hold
            # non-UTF-8 bytes; the numeric tail still parses,
            # so membership stays attributable instead of
            # crashing the census.
            with open("/proc/%s/stat" % entry, encoding="utf-8",
                      errors="replace") as handle:
                text = handle.read()
            fields = text.rsplit(")", 1)
            if len(fields) != 2:
                raise ValueError("truncated stat for %s" % entry)
            rest = fields[1].split()
            if len(rest) < 4:
                raise ValueError("truncated stat for %s" % entry)
            ppid = int(rest[1])
            pgid = int(rest[2])
            session = int(rest[3])
        except (OSError, ValueError):
            # A pid that vanished mid-scan is skipped; a pid
            # that is still present but unreadable -- or whose
            # presence check itself fails (denied directory
            # metadata) -- makes the whole census
            # untrustworthy, so the snapshot is refused instead
            # of silently dropping the entry.
            try:
                present = _pid_still_present(entry)
            except OSError:
                return None
            if present:
                return None
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
        # Drop the guest-handoff watch before removing the
        # directory: teardown is not an in-window mutation.
        disarm_staged_handoffs(stage)
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


# Consumption routing (executed-byte identity): the attested
# digest of every declared input must equal the bytes the run
# actually consumed. Fixtures consume through the suite's
# active recorder through the buffer handoffs below, which
# hash the exact buffer returned, so the same bytes
# are both hashed and executed -- never a separate hash-read
# versus exec-read. ``main()`` activates its recorder before
# the warmup; fixture helpers below no-op without one (pytest
# and standalone paths make no attestation claims).

_ACTIVE_RECORDER = None


def set_active_recorder(recorder):
    """Route fixture consumption reads through ``recorder``."""
    global _ACTIVE_RECORDER
    _ACTIVE_RECORDER = recorder
    return recorder


def active_recorder():
    """Return the active suite recorder, or None."""
    return _ACTIVE_RECORDER


def clear_active_recorder(recorder=None):
    """Drop the active recorder (``recorder`` or any when None)."""
    global _ACTIVE_RECORDER
    if recorder is None or _ACTIVE_RECORDER is recorder:
        _ACTIVE_RECORDER = None


def consume_declared_inputs(stage, extra=()):
    """Observe the active run's inputs for preflight comparisons.

    Returns the ``{"staged": ..., "absolute": ...}`` digest map
    (see :meth:`SuiteRecorder.consume_declared`); without an
    active recorder returns empty maps and reads nothing.
    """
    recorder = _ACTIVE_RECORDER
    if recorder is None:
        return {"staged": {}, "absolute": {}}
    return recorder.consume_declared(stage, extra=extra)


def stage_consumed_for_guest(recorder, stage, names):
    """Consume staged files and hand the captured bytes to the guest.

    For each basename in ``names``: read it through
    ``recorder.consume_staged`` (an explicit-consumption log entry),
    install the exact buffer returned under a FRESH backing
    inode (so no pre-existing writable mapping, descriptor or
    hard link can reach the bytes the guest will open),
    seal it read-only (executables keep +x, since the guest
    runs them), and return the hex digest. Returns ``{name:
    digest}`` with None for missing/unreadable files (fail
    closed downstream: no digest means no attested identity to
    compare guest reports against). The inode swap is
    unconditional: even byte-identical content gets new
    backing (a retained MAP_SHARED mapping, which chmod
    cannot revoke and inotify does not report, then refers
    only to the displaced inode), and the final bytes always
    equal the consumed buffer (a path swap between consume
    and replace is overwritten, never adopted). Every
    handed-off file is then watched until the run verifies
    it: any create, write, move, delete or permission event
    on a handed-off name — including a change restored
    before the check — voids the handoff at
    :func:`verify_staged_handoffs_now` (which the recorder
    runs at every case close), and a re-hash at verify time
    catches any mutation the monitor missed. Without a
    recorder (None) this reads nothing, seals nothing and
    returns no digests, like :func:`consume_declared_inputs`.
    """
    if recorder is None:
        return {}
    digests = {}
    for name in names:
        data = recorder.consume_staged(name, stage)
        if data is None:
            digests[name] = None
            continue
        path = os.path.join(stage, name)
        try:
            was_exec = bool(os.stat(path).st_mode & 0o111)
        except OSError:
            was_exec = False
        tmp = "%s.handoff-%d" % (path, os.getpid())
        try:
            with open(tmp, "wb") as handle:
                handle.write(data)
            os.replace(tmp, path)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        os.chmod(path, 0o555 if was_exec else 0o444)
        digests[name] = _sha256_bytes(data)
    _arm_staged_watch(
        stage,
        {
            name: digest
            for name, digest in digests.items()
            if digest is not None
        },
    )
    return digests


# Armed guest handoffs: abspath(stage) -> {"watch":
# _InputAliasWatch, "digests": {name: hex}}. The watch spans
# handoff until the run verifies it (the recorder checks at
# every case close); unrelated stage files written after
# handoff (guest transcripts) are not watched names and
# never taint the handoff.
_STAGE_WATCHES = {}


def _arm_staged_watch(stage, digests):
    """Watch ``stage`` for events on the handed-off ``digests``.

    Extends an existing watch when the suite hands off more
    names from the same stage later (generated scripts).
    Raises when pathname monitoring is unavailable: without
    the monitor a change-and-restore window cannot be
    refused, so the handoff fails closed instead of
    attesting through it.
    """
    if not digests:
        return
    key = os.path.abspath(stage)
    entry = _STAGE_WATCHES.get(key)
    if entry is None:
        entry = {
            "watch": _InputAliasWatch(stage),
            "digests": {},
        }
        _STAGE_WATCHES[key] = entry
    else:
        # Refuse on any event that predates this call: the
        # handoff for those names already spans this window.
        # (Raised as AssertionError so a fixture-context
        # tamper fails the run instead of miscoding as
        # infrastructure.)
        try:
            entry["watch"].check(names=sorted(entry["digests"]))
        except HarnessEnvironment as exc:
            raise AssertionError(
                "staged handoff voided before extension: %s" % exc
            )
        # The queue is now drained, so the only pending events
        # for these names are this call's own installs.
        entry["watch"].forgive_names(digests)
    entry["digests"].update(digests)


def verify_staged_handoffs_now():
    """Return mismatch entries for voided guest handoffs.

    For every armed stage: any monitor event on a handed-off
    name voids it (even a change restored before this check),
    and every handed-off file re-hashes against its captured
    digest (a mutation the monitor missed still mismatches
    here). A file restored byte-identically passes the
    re-hash but was already voided by its monitor events;
    only a run with neither events nor drift returns [].
    """
    mismatches = []
    for key in sorted(_STAGE_WATCHES):
        entry = _STAGE_WATCHES[key]
        names = sorted(entry["digests"])
        try:
            entry["watch"].check(names=names)
        except HarnessEnvironment:
            tainted = entry["watch"].tainted_name
            if tainted is None:
                mismatches.append(
                    "staged handoff monitor voided for %s: %s"
                    % (key, entry["watch"].tainted)
                )
            else:
                mismatches.append(
                    "staged handoff file changed during the run: "
                    "('%s', %r)" % (key, tainted)
                )
        for name in names:
            try:
                with open(os.path.join(key, name), "rb") as handle:
                    current = _sha256_bytes(handle.read())
            except OSError:
                current = None
            if current != entry["digests"][name]:
                mismatches.append(
                    "staged handoff bytes differ from the captured "
                    "buffer: ('%s', %r)" % (key, name)
                )
    return mismatches


def require_handed_digests(handed, names):
    """Return ``{name: digest}`` or refuse on any missing digest.

    Under an attestation context a missing/None handoff digest
    must be rejected before the guest launches: substituting a
    fresh filesystem hash would attest bytes the run never
    consumed. Callers without a recorder keep their explicit
    standalone fallback instead of calling this.
    """
    missing = sorted(name for name in names if handed.get(name) is None)
    if missing:
        raise AssertionError(
            "staged bytes missing under recorder for: %s"
            % ", ".join(missing)
        )
    return {name: handed[name] for name in names}


def disarm_staged_handoffs(stage=None):
    """Close staged-handoff watches (``stage`` or all)."""
    if stage is None:
        keys = list(_STAGE_WATCHES)
    else:
        keys = [os.path.abspath(stage)]
    for key in keys:
        entry = _STAGE_WATCHES.pop(key, None)
        if entry is not None:
            try:
                entry["watch"].close()
            except OSError:
                pass


def read_consumed(path):
    """Read ``path`` through the active recorder when there is one.

    The returned buffer is the hashed buffer: with an active
    recorder the read is logged as consumption, otherwise this
    is a plain read. Returns None when the file is unreadable.
    """
    recorder = _ACTIVE_RECORDER
    if recorder is None:
        return _read_file_bytes(path)
    return recorder.consume_absolute(path)


def open_consumed(path, mode="r", *, encoding=None, errors=None):
    """Hand a host reader the exact immutable buffer logged for it.

    Binary and text readers share one binary read; decoding,
    iteration and repeated reads operate on that buffer. An
    unreadable input raises instead of falling back to its path.
    Without an attestation context this is an ordinary read.
    """
    if mode not in ("r", "rt", "rb"):
        raise ValueError("open_consumed is read-only")
    if _ACTIVE_RECORDER is None:
        return open(path, mode, encoding=encoding, errors=errors)
    data = read_consumed(path)
    if data is None:
        raise OSError("cannot consume input %r" % (os.fspath(path),))
    stream = io.BufferedReader(io.BytesIO(data))
    if "b" not in mode:
        stream = io.TextIOWrapper(stream, encoding=encoding, errors=errors)
    return stream


class _InputAliasWatch:
    """Guard an extension-preserving alias in a pinned directory.

    The backing bytes are sealed. Only replacing the alias can change
    them; every such directory event invalidates this handoff, even if
    the original entry is restored before the consumer returns.
    """

    _CREATE = 0x100
    _MASK = (0x2 | 0x4 | 0x8 | 0x40 | 0x80 | _CREATE | 0x200 |
             0x400 | 0x800 | 0x2000 | 0x4000 | 0x8000 | 0x1000000)

    def __init__(self, directory):
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        try:
            init, add = libc.inotify_init1, libc.inotify_add_watch
        except AttributeError as exc:
            raise OSError("input pathname monitoring is unavailable") from exc
        init.argtypes, init.restype = [ctypes.c_int], ctypes.c_int
        add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        add.restype = ctypes.c_int
        self.fd = init(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        self.tainted = None
        self.tainted_name = None
        try:
            self.wd = add(self.fd, os.fsencode(directory), self._MASK)
            if self.wd < 0:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))
        except BaseException:
            try:
                os.close(self.fd)
            except OSError as exc:
                raise _input_cleanup_failure(
                    "input monitor setup teardown failed: %s" % exc
                ) from exc
            raise

    # Events that void the monitored set even when they carry
    # no watched name: queue overflow (events were lost),
    # watch removal, and the directory itself going away.
    _FATAL_MASK = 0x4000 | 0x8000 | 0x400 | 0x800 | 0x2000

    def check(self, *, created=None, names=None):
        import struct

        header = struct.Struct("=iIII")
        creation_seen = False
        watched = (
            None if names is None
            else set(os.fsencode(name) for name in names)
        )
        while self.tainted is None:
            try:
                events = os.read(self.fd, 65536)
            except BlockingIOError:
                break
            if not events:
                self.tainted = "input monitor returned no event stream"
                break
            offset = 0
            while offset < len(events):
                if len(events) - offset < header.size:
                    self.tainted = "input monitor returned a truncated event"
                    break
                wd, mask, _cookie, size = header.unpack_from(events, offset)
                offset += header.size
                if size > len(events) - offset:
                    self.tainted = "input monitor returned a truncated name"
                    break
                name = events[offset:offset + size].split(b"\0", 1)[0]
                offset += size
                if (created is not None and not creation_seen and
                        wd == self.wd and mask == self._CREATE and
                        name == os.fsencode(created)):
                    creation_seen = True
                    continue
                if watched is not None and name not in watched:
                    if mask & self._FATAL_MASK:
                        self.tainted = (
                            "input monitor lost events for %r"
                            % sorted(names)
                        )
                        self.tainted_name = None
                        break
                    continue
                self.tainted = "input pathname changed or its monitor lost events"
                try:
                    self.tainted_name = name.decode("utf-8", "replace")
                except (UnicodeError, ValueError):
                    self.tainted_name = None
                break
        if created is not None and not creation_seen and self.tainted is None:
            self.tainted = "input monitor did not observe alias publication"
        if self.tainted is not None:
            raise HarnessEnvironment(
                self.tainted, stage="TEST_RUN", availability="UNKNOWN",
                cause=self.tainted, exit_code=None,
            )

    def forgive_names(self, names):
        """Drain pending events, dropping ones for ``names`` only.

        A handoff extended with generated files must not trip
        over its own create/write/chmod events, which predate
        the extension. Events naming any other name taint
        immediately (that handoff predates this call, so the
        event falls inside its window), as do queue overflow,
        watch removal, or a truncated stream.
        """
        import struct

        header = struct.Struct("=iIII")
        forgiven = set(os.fsencode(name) for name in names)
        while self.tainted is None:
            try:
                events = os.read(self.fd, 65536)
            except BlockingIOError:
                break
            if not events:
                self.tainted = "input monitor returned no event stream"
                break
            offset = 0
            while offset < len(events):
                if len(events) - offset < header.size:
                    self.tainted = "input monitor returned a truncated event"
                    break
                _wd, mask, _cookie, size = header.unpack_from(
                    events, offset
                )
                offset += header.size
                if size > len(events) - offset:
                    self.tainted = "input monitor returned a truncated name"
                    break
                name = events[offset:offset + size].split(b"\0", 1)[0]
                offset += size
                if name in forgiven and not (mask & self._FATAL_MASK):
                    continue
                self.tainted = (
                    "input pathname changed or its monitor lost events"
                )
                try:
                    self.tainted_name = name.decode("utf-8", "replace")
                except (UnicodeError, ValueError):
                    self.tainted_name = None
                break

    def close(self):
        os.close(self.fd)


def _input_cleanup_failure(message):
    if _ACTIVE_RECORDER is not None:
        _ACTIVE_RECORDER._input_cleanup_errors.append(message)
    return HarnessEnvironment(
        message, stage="CLEANUP", availability="UNKNOWN",
        cause=message, exit_code=None,
    )


def _cleanup_input_alias(root, directory_fd, identity, name):
    """Retire our entry without recursively removing a mutable pathname."""
    try:
        if name is not None and directory_fd is not None:
            try:
                os.unlink(name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        current = os.stat(root, follow_symlinks=False)
        if identity != (current.st_dev, current.st_ino):
            raise OSError("owned input directory was moved or replaced")
        os.rmdir(root)
        # A replacement can race the pathname check. Prove removal of
        # the original directory while its descriptor is still held.
        if directory_fd is None or os.fstat(directory_fd).st_nlink != 0:
            raise OSError("owned input directory removal could not be established")
    except OSError as exc:
        raise _input_cleanup_failure(
            "input directory cleanup unresolved for %r: %s" % (root, exc)
        ) from exc


@contextlib.contextmanager
def consumed_path(path, *, preserve_name=False):
    """Adapt a path-only host consumer to the single-read boundary.

    Read the original once, log that buffer, and expose the same
    buffer in a sealed memfd for the duration of the call. Neither
    replacing the original nor writing/truncating the snapshot
    can change the bytes downstream reads. The proc descriptor
    path belongs to the kernel and has no replaceable directory
    entry. Compiler wrappers use an extension-preserving alias in
    a pinned directory, monitored from publication through the return
    of the synchronous consumer. Alias mutation, monitor uncertainty
    and teardown failure refuse the result. Closing the context retires
    the descriptor, including on setup or consumer failure.
    No mutable-path fallback is allowed if snapshot creation fails.

    This is a host handoff, not a guest execution identity claim.
    Callers still own every existing target/lease gate.
    """
    if _ACTIVE_RECORDER is None:
        yield path
        return
    fd = None
    try:
        data = read_consumed(path)
        if data is None:
            raise OSError("cannot consume input %r" % (os.fspath(path),))
        creator = getattr(os, "memfd_create", None)
        if creator is None:
            raise OSError("sealed input descriptors are unavailable")
        fd = creator("mojobpf-consumed", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        duplicate = os.dup(fd)
        try:
            handle = os.fdopen(duplicate, "wb")
        except BaseException:
            try:
                os.close(duplicate)
            except OSError as exc:
                raise _input_cleanup_failure(
                    "input writer descriptor teardown failed: %s" % exc
                ) from exc
            raise
        with handle:
            handle.write(data)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        if (os.fstat(fd).st_size != len(data) or
                os.pread(fd, len(data), 0) != data):
            raise OSError("sealed input descriptor differs from the logged buffer")
        descriptor = "/proc/%d/fd/%d" % (os.getpid(), fd)
        if preserve_name:
            root = tempfile.mkdtemp(prefix="mojobpf-consumed-")
            directory_fd, identity, published = None, None, None
            try:
                created = os.stat(root, follow_symlinks=False)
                identity = (created.st_dev, created.st_ino)
                directory_fd = os.open(
                    root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
                pinned = os.fstat(directory_fd)
                if identity != (pinned.st_dev, pinned.st_ino):
                    raise OSError("owned input directory changed before it was pinned")
                directory = "/proc/%d/fd/%d" % (os.getpid(), directory_fd)
                watch = _InputAliasWatch(directory)
                try:
                    name = os.path.basename(path)
                    os.symlink(descriptor, name, dir_fd=directory_fd)
                    published = name
                    watch.check(created=name)
                    yield os.path.join(directory, name)
                    watch.check()
                finally:
                    try:
                        watch.close()
                    except OSError as exc:
                        raise _input_cleanup_failure(
                            "input monitor teardown failed: %s" % exc
                        ) from exc
            finally:
                try:
                    _cleanup_input_alias(root, directory_fd, identity, published)
                finally:
                    if directory_fd is not None:
                        try:
                            os.close(directory_fd)
                        except OSError as exc:
                            raise _input_cleanup_failure(
                                "input directory descriptor teardown failed: %s" % exc
                            ) from exc
        else:
            yield descriptor
    except OSError as exc:
        raise HarnessEnvironment(
            "input snapshot failed for %r: %s" % (os.fspath(path), exc),
            stage="INFRA", availability="UNKNOWN", cause=str(exc),
            exit_code=None,
        ) from exc
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError as exc:
                raise _input_cleanup_failure(
                    "input snapshot teardown failed: %s" % exc
                ) from exc


def inspect_consumed(path, profile):
    """Inspect the logged buffer through the unchanged public inspector."""
    from mojobpf.inspect import inspect_object

    with consumed_path(path) as snapshot:
        return inspect_object(snapshot, profile)


def copy_consumed(source, destination):
    """Stage the buffer that was logged, without reopening its source."""
    with open_consumed(source, "rb") as handle:
        data = handle.read()
    with open(destination, "wb") as handle:
        handle.write(data)
    return destination


def verify_captured_project_inputs(raw, *, manifest, sources):
    """Reconcile the build driver's captured identities with logged buffers.

    ``manifest`` is a ``(logical_name, bytes)`` pair and ``sources`` is
    the corresponding source-pair sequence. This compares capture
    evidence, never a post-build reread of the mutable project copies.
    The driver's compiler-staging contract owns the later pipeline.
    """
    from mojobpf.evidence import EVIDENCE_SCHEMA_VERSION

    def pairs(entries):
        result = {}
        for key, value in entries:
            if key in result:
                raise ValueError("duplicate build evidence key %r" % key)
            result[key] = value
        return result

    def expected(pair):
        name, data = pair
        return {"path": name, "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data)}

    def check(record, wanted):
        if (not isinstance(record, dict) or set(record) != set(wanted) or
                type(record["size"]) is not int or record != wanted):
            raise ValueError("build captured different or malformed input bytes")

    try:
        doc = json.loads(raw, object_pairs_hook=pairs)
        if (not isinstance(doc, dict) or type(doc.get("schema_version")) is not int or
                doc["schema_version"] != EVIDENCE_SCHEMA_VERSION or
                doc.get("success") is not True):
            raise ValueError("missing successful build capture evidence")
        inputs = doc["inputs"]
        if not isinstance(inputs, dict):
            raise ValueError("missing captured build inputs")
        check(inputs["manifest"], expected(manifest))
        recorded = inputs["source"]
        if not isinstance(recorded, list) or len(recorded) != len(sources):
            raise ValueError("missing or duplicate captured source identities")
        for item, source in zip(recorded, sources):
            check(item, expected(source))
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise HarnessEnvironment(
            "build input capture does not match consumed project: %s" % exc,
            stage="TEST_RUN", availability="UNKNOWN", cause=str(exc),
            exit_code=None,
        ) from exc


def consumes_source(function):
    """Give a host compiler wrapper a snapshot of its source argument.

    The source's basename is preserved. These leased wrappers use
    explicit SDK include paths; this does not resolve arbitrary
    projects/import graphs or claim guest consumption.
    """
    @functools.wraps(function)
    def run(source, *args, **kwargs):
        with consumed_path(source, preserve_name=True) as snapshot:
            return function(snapshot, *args, **kwargs)
    return run


def compile_consumed(run, argv, source, **kwargs):
    """Handoff for compiler calls whose source is not a wrapper argument.

    Preserve a C control's diagnostic/debug source spelling so its
    existing object pin remains meaningful. Includes retain their
    explicit original search directory; toolchain inputs are separate
    from the declared primary source being consumed here.
    """
    if _ACTIVE_RECORDER is None:
        return run(argv, **kwargs)
    if source not in argv:
        raise ValueError("compiler source must be an explicit argv input")
    full = os.path.abspath(os.path.join(kwargs.get("cwd") or os.curdir, source))
    with consumed_path(full, preserve_name=True) as snapshot:
        command = [snapshot if token == source else token for token in argv]
        if source.endswith(".c"):
            command[1:1] = ["-ffile-prefix-map=%s=%s" % (snapshot, source),
                            "-iquote", os.path.dirname(full)]
        return run(command, **kwargs)


@contextlib.contextmanager
def consumed_arguments(argv, options):
    """Snapshot named host inputs for one synchronous command.

    The caller must perform its existing admission/lease checks
    first. No subprocess is started here and no guest claim is made.
    """
    result = list(argv)
    with contextlib.ExitStack() as stack:
        for index, token in enumerate(argv[:-1]):
            if token in options:
                result[index + 1] = stack.enter_context(
                    consumed_path(argv[index + 1])
                )
        yield result


_HASH_LINE_RE = re.compile(r"^([0-9a-f]{64})  (\S+)$")


def parse_reported_hashes(output):
    """Parse guest ``sha256sum`` lines into ``{name: digest}``.

    A name reported with two different digests is poisoned
    (maps to None): a forged duplicate line can never satisfy
    a consumption comparison. Names never reported are absent.
    """
    reported = {}
    poisoned = set()
    for line in output.splitlines():
        match = _HASH_LINE_RE.match(line.strip())
        if not match:
            continue
        digest, name = match.group(1), match.group(2)
        if name in poisoned:
            continue
        if name in reported and reported[name] != digest:
            poisoned.add(name)
            reported.pop(name, None)
            continue
        reported[name] = digest
    for name in poisoned:
        reported[name] = None
    return reported


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


def _read_file_bytes(path):
    """Return the file's bytes, or None if unreadable."""
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError:
        return None


def _snapshot_file_bytes(path, snapshot):
    """Return the file's bytes, reading once per snapshot.

    The first read of ``path`` is cached in ``snapshot`` and
    every later lookup of the same path reuses those exact
    bytes, so :meth:`SuiteRecorder.finish` hashes and verifies
    the same buffer instead of two independent reads that a
    mid-finish swap could straddle.
    """
    if path not in snapshot:
        snapshot[path] = _read_file_bytes(path)
    return snapshot[path]


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

    Input bytes seal before execution: absolute-path inputs
    hash at construction, staged inputs seal when their case
    begins, and :meth:`_end_case` fails any executing case
    (PASS, or a proof FAIL) whose bytes changed mid-case --
    or were never observed before execution -- at TEST_RUN (a
    swap is never sealed afterwards as the executed bytes,
    and bytes the seal never saw can never back a PASS). A
    case that claims no execution (INFRA_ERROR, NOT_RUN)
    still seals newly observed bytes at case end so
    :meth:`finish` guards them, and :meth:`finish` verifies
    the seals from a single read per path, so a
    post-completion swap fails at TEST_RUN, never as PASS.

    Attestation is consumption-bound on top of the seals:
    host readers use open_consumed or consumed_path. Both read
    the original once, log that buffer under its canonical absolute
    path, and hand the buffer (or a sealed snapshot) downstream.
    consume_absolute/consume_staged likewise return the logged
    buffer. Construction, begin seals and consume_declared are
    observations only: a bulk hash read cannot prove consumption.
    Finish requires explicit, unanimous consumed bytes for every
    declaration; contradictions or absent consumption fail at
    TEST_RUN. Observation-only reads never attest. Finish never substitutes a
    fresh filesystem read for the bytes that a consumer used.
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
                    if (
                        isinstance(entry, (tuple, list))
                        and len(entry) == 2
                        and entry[0] == "impl"
                        and isinstance(entry[1], str)
                        and entry[1]
                        and os.path.isabs(entry[1])
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
        self._input_cleanup_errors = []
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
        # entries seal per case in begin_case. Earliest
        # observation wins, so a mid-case change mismatches at
        # case end and a post-completion change at finish.
        self._sealed_entry_digests = {}
        # Consumption log (see the class docstring): maps log
        # keys -- normalized absolute file paths, independent of
        # declaration/read spelling -- to {"digests": [...], "explicit":
        # [...], "explicit_bytes": ...}.
        # Construction, begin and preflight reads are observations.
        # Only use-time buffer handoffs log explicit consumption.
        # Finish attests only unanimous explicit bytes. There is
        # no observation fallback, including for direct recorders.
        self._consumed = {}
        self._consumption_stages = set()
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

    def _log_consumed(self, key, data, explicit=False):
        """Append one consumption observation under ``key``.

        ``data`` is the exact buffer returned to the reader (or
        None when the file was unreadable). ``explicit`` marks
        consumption reads (fixtures, hosts); seal/preflight
        reads log as observations. First-observed bytes per
        tier win for attestation; any disagreement within the
        attesting tier voids it (see :meth:`_verify_consumed_now`).
        """
        key = os.path.abspath(key)
        parent = os.path.dirname(key)
        if parent in {os.path.abspath(stage) for stage in _OWNED_STAGES}:
            self._consumption_stages.add(parent)
        entry = self._consumed.setdefault(
            key,
            {
                "digests": [],
                "explicit": [],
                "explicit_bytes": None,
            },
        )
        entry["digests"].append(
            None if data is None else _sha256_bytes(data)
        )
        entry["explicit"].append(bool(explicit))
        if explicit and data is not None and entry["explicit_bytes"] is None:
            entry["explicit_bytes"] = data

    def consume_absolute(self, path):
        """Read an absolute-path input through the recorder.

        Returns the file's bytes (None when unreadable) and logs
        the exact buffer returned, so the hashed bytes are the
        executed bytes. The log key is the normalized absolute
        path.
        """
        path = os.path.abspath(path)
        data = _read_file_bytes(path)
        self._log_consumed(
            path, data, explicit=True
        )
        return data

    def consume_staged(self, basename, stage):
        """Read a staged input through the recorder.

        Returns the bytes of ``basename`` under ``stage`` (None
        when unreadable) and logs the exact buffer returned. The
        log key carries the stage, so bytes consumed from a stage
        the run never finishes from are never attested.
        """
        self._consumption_stages.add(os.path.abspath(stage))
        return self.consume_absolute(os.path.join(stage, basename))

    def consumed_staged_digest(self, basename, stage):
        """Return the attestable digest for a staged file.

        Returns the hex digest of the bytes the run would attest
        for ``basename`` under ``stage`` (see
        :meth:`_consumed_attested_bytes`), else None. Suites
        compare guest-reported hashes against this: the guest
        must report the bytes the run consumed.
        """
        data = self._consumed_attested_bytes(
            ("stage", basename), os.path.abspath(stage)
        )
        if data is None:
            return None
        return _sha256_bytes(data)

    def consume_declared(self, stage, extra=()):
        """Observe declared/staged bytes for preflight hash comparisons.

        A bulk scan is not execution. These reads only log seal-tier
        observations; they cannot satisfy consumption. Host
        consumers must use open_consumed/consumed_path (or use the
        bytes returned by consume_absolute/consume_staged) at the use.
        Guest-side use remains a separately deferred qualification.
        """
        staged, absolute, observed = {}, {}, {}

        def observe(path):
            key = os.path.abspath(path)
            if key not in observed:
                data = _read_file_bytes(path)
                self._log_consumed(key, data)
                observed[key] = None if data is None else _sha256_bytes(data)
            return observed[key]

        for classes in self._sealed_inputs.values():
            for kind in ("sources", "objects", "corpus"):
                for entry in classes.get(kind, []):
                    if isinstance(entry, str):
                        absolute[entry] = observe(entry)
                        continue
                    impl = self._impl_path(entry)
                    if impl is not None:
                        absolute[impl] = observe(impl)
                        continue
                    staged[entry[1]] = (
                        None if stage is None else
                        observe(os.path.join(stage, entry[1]))
                    )
        names = set(extra)
        if stage is not None:
            try:
                names.update(name for name in os.listdir(stage)
                             if os.path.isfile(os.path.join(stage, name)))
            except OSError:
                pass
        for name in sorted(names):
            if name not in staged:
                staged[name] = (None if stage is None else
                                observe(os.path.join(stage, name)))
        return {"staged": staged, "absolute": absolute}

    def begin_case(self, case_id):
        """Open a case: snapshots the owned census for leak diffing.

        The case's input bytes seal here, before the case body
        executes: a mid-case swap must mismatch at
        :meth:`_end_case`, never be sealed afterwards as the
        executed bytes. Suites stage their inputs before
        calling this (see each suite's pre-loop warmup): bytes
        first observed after begin can never back a PASS. The
        seal reads are observations only. Warmup and case-body
        consumers separately log the buffers they actually use.
        """
        if case_id not in self._sealed_case_ids:
            raise ValueError("begin_case: unknown case %r" % (case_id,))
        if case_id in self._begun:
            raise ValueError(
                "begin_case: case %r already begun" % (case_id,)
            )
        self._begun[case_id] = (
            census_snapshot() if self._subreaper_ok else None
        )
        self._seal_case_inputs(case_id)

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
        mismatches = self._verify_case_inputs_now(
            case_id, outcome
        )
        mismatches += self._verify_consumed_now(case_id, outcome)
        # Guest-handoff transients: the seal verifications above
        # compare end-state bytes, so a change restored before
        # this close would pass them while having executed
        # foreign bytes. The handoff monitor observed every
        # in-window event, and its re-hash catches anything
        # the monitor missed; either voids the attestation
        # through the same mismatch channel.
        mismatches += verify_staged_handoffs_now()
        # Seal-after-verify, and only newly observed bytes: an
        # input the fixture built mid-case (unobservable at
        # begin) seals here so :meth:`finish` still guards it,
        # but bytes already sealed at begin are never resealed
        # (a mid-case swap mismatches above instead of
        # becoming the new identity). An executing case with
        # never-observed inputs already mismatched above, so
        # nothing sealed here can back its PASS. The reseal
        # never logs consumption (post-execution reads are not
        # consumption), so it can never attest late bytes.
        self._seal_case_inputs(case_id, _log=False)
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
        if self._input_cleanup_errors:
            cleanup["residue"].extend(self._input_cleanup_errors)
            cleanup["status"] = "RESIDUE"
        if outcome == "PASS" and cleanup["status"] != "CLEAN":
            # A PASS with residue or an uncensused cleanup is no
            # PASS: the case becomes infrastructure-failed at
            # CLEANUP instead of emitting a record the contracts
            # would reject as malformed.
            outcome, stage = "INFRA_ERROR", "CLEANUP"
        if mismatches:
            # The attestation is void: the bytes the case ran
            # against no longer match the case-start seal, so
            # the case fails at TEST_RUN (never the pinned wire
            # stage, so no denial is satisfied) with the
            # swapped entries as residue.
            cleanup["residue"].extend(
                "input bytes changed during the case: %s" % item
                for item in mismatches
            )
            cleanup["status"] = "RESIDUE"
            outcome, stage = "FAIL", "TEST_RUN"
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

    @staticmethod
    def _impl_path(entry):
        """Return the absolute path for an impl entry, else None.

        ``("impl", abspath)`` names Python implementation code that
        executes before any recorder exists: it seals as evidence
        like an absolute source but is never demandable as
        executed bytes.
        """
        if (
            isinstance(entry, (tuple, list))
            and len(entry) == 2
            and entry[0] == "impl"
        ):
            return entry[1]
        return None

    def _seal_absolute_inputs(self):
        """Hash absolute-path inputs at plan construction.

        Construction observes bytes but executes nothing. It cannot
        satisfy the explicit consumption requirement.
        """
        for case_id in self._sealed_case_ids:
            classes = self._sealed_inputs.get(case_id, {})
            sealed = self._sealed_entry_digests.setdefault(case_id, {})
            for _class in ("sources", "objects", "corpus"):
                for entry in classes.get(_class, []):
                    absolute = (
                        entry if isinstance(entry, str)
                        else self._impl_path(entry)
                    )
                    if (
                        absolute is None
                        or not isinstance(absolute, str)
                        or not os.path.isabs(absolute)
                    ):
                        continue
                    key = self._entry_key(_class, entry)
                    data = _read_file_bytes(absolute)
                    self._log_consumed(
                        absolute,
                        data,
                    )
                    sealed[key] = (
                        "absolute",
                        None if data is None
                        else _sha256_bytes(data),
                    )

    @staticmethod
    def _seal_is_observed(record):
        """Return True when a seal record holds observed bytes."""
        kind, first = record
        if kind == "absolute":
            return first is not None
        return bool(first)

    def _seal_case_inputs(self, case_id, _log=True):
        """Seal a case's inputs (earliest observation wins).

        Called at :meth:`begin_case` (the pre-execution seal)
        and again at :meth:`_end_case` (after verification).
        ``_log`` mirrors the reads into the consumption log;
        only the begin seal logs (the end-of-case reseal of
        newly observed bytes never does: post-execution reads
        are not consumption).
        Absolute entries keep their construction seal when one
        exists; staged entries resolve each basename against
        the owned-stage registry and record every observed
        ``{stage: digest}`` pair (an empty map means the file
        was unobservable then, which stays lenient at finish
        for cases that claim no execution).
        Only unobserved records are ever replaced: bytes
        already sealed are never resealed, so a mid-case swap
        mismatches at case end instead of becoming the new
        identity. An input the fixture built mid-case
        (unobservable at begin) still seals here for the
        finish guard, but only a case that claims no execution
        may reach the finish with one: PASS and FAIL cases
        with never-observed inputs already failed in
        :meth:`_end_case`.
        """
        classes = self._sealed_inputs.get(case_id, {})
        sealed = self._sealed_entry_digests.setdefault(case_id, {})
        for _class in ("sources", "objects", "corpus"):
            for entry in classes.get(_class, []):
                key = self._entry_key(_class, entry)
                if (
                    key in sealed
                    and self._seal_is_observed(sealed[key])
                ):
                    continue
                absolute = (
                    entry if isinstance(entry, str)
                    else self._impl_path(entry)
                )
                if absolute is not None:
                    if isinstance(absolute, str) and os.path.isabs(
                        absolute
                    ):
                        data = _read_file_bytes(absolute)
                        if _log:
                            self._log_consumed(
                                absolute,
                                data,
                            )
                        sealed[key] = (
                            "absolute",
                            None if data is None
                            else _sha256_bytes(data),
                        )
                    continue
                observed = {}
                for stage in sorted(_OWNED_STAGES):
                    full = os.path.join(stage, entry[1])
                    data = _read_file_bytes(full)
                    if data is None:
                        continue
                    digest = _sha256_bytes(data)
                    absolute = os.path.abspath(stage)
                    observed[absolute] = digest
                    if _log:
                        self._log_consumed(
                            full, data
                        )
                sealed[key] = ("staged", observed)

    def _verify_case_inputs_now(self, case_id, outcome):
        """Return mismatches of current bytes vs the case-start seal.

        Compares the bytes observable now against the
        :meth:`begin_case` seal. Observed-then-changed (or
        observed-then-vanished) bytes always mismatch. Cases
        that claim execution (PASS, or a proof FAIL) are
        strict on top: an input never observed before
        execution -- unobservable at the begin seal, or
        appearing only in a stage created during the case --
        mismatches too, since the run attests only bytes that
        were both executed and unchanged since first
        observation. A case that claims no execution
        (INFRA_ERROR, NOT_RUN) stays lenient on unobserved
        entries (built mid-case, or never staged) and seals
        newly observed bytes afterwards in :meth:`_end_case`,
        so lease-gated and setup-failed cases keep their
        typed terminals.
        """
        sealed = self._sealed_entry_digests.get(case_id, {})
        if not sealed:
            return []
        strict = outcome in ("PASS", "FAIL")
        classes = self._sealed_inputs.get(case_id, {})
        bad = []
        for _class in ("sources", "objects", "corpus"):
            for entry in classes.get(_class, []):
                record = sealed.get(self._entry_key(_class, entry))
                if record is None:
                    continue
                kind, first = record
                absolute = (
                    entry if isinstance(entry, str)
                    else self._impl_path(entry)
                )
                if kind == "absolute" and absolute is not None:
                    if first is None:
                        # Never observed -- not at
                        # construction, so not before execution
                        # either. A PASS or FAIL over unreadable
                        # bytes would attest nothing; only a
                        # case that claims no execution may stay
                        # silent about it.
                        if strict:
                            bad.append(
                                "%s entry %r never observed "
                                "before execution"
                                % (_class, entry)
                            )
                        continue
                    if _digest_file_bytes(absolute) != first:
                        bad.append(
                            "%s entry %r changed after sealing"
                            % (_class, entry)
                        )
                else:
                    if strict:
                        for stage in sorted(_OWNED_STAGES):
                            if os.path.abspath(stage) in first:
                                continue
                            if _digest_file_bytes(
                                os.path.join(stage, entry[1])
                            ) is not None:
                                bad.append(
                                    "%s staged entry %r appeared "
                                    "in an unsealed stage during "
                                    "the case" % (_class, entry[1])
                                )
                                break
                    if not first:
                        # Unobservable at the begin seal: the
                        # fixture staged it mid-case (or never),
                        # so no pre-execution identity exists.
                        # Strict cases fail here instead of
                        # sealing the late bytes afterwards.
                        if strict:
                            bad.append(
                                "%s staged entry %r never observed "
                                "before execution"
                                % (_class, entry[1])
                            )
                        continue
                    for stage in sorted(first):
                        current = _digest_file_bytes(
                            os.path.join(stage, entry[1])
                        )
                        if current != first[stage]:
                            bad.append(
                                "%s staged entry %r changed after "
                                "sealing" % (_class, entry[1])
                            )
                            break
        return bad

    def _consumed_keys_for(self, entry):
        """Resolve every declaration to the same canonical file records.

        Stage membership is remembered independently of read spelling;
        consuming an absolute path under a stage cannot hide from a
        staged declaration, or vice versa. File replacement keeps the
        same key, so an A/B/A sandwich remains contradictory.
        """
        if isinstance(entry, str):
            key = os.path.abspath(entry)
            return [key] if key in self._consumed else []
        impl = self._impl_path(entry)
        if impl is not None:
            key = os.path.abspath(impl)
            return [key] if key in self._consumed else []
        stages = self._consumption_stages | {
            os.path.abspath(stage) for stage in _OWNED_STAGES
        }
        return sorted({
            os.path.abspath(os.path.join(stage, entry[1]))
            for stage in stages
        } & self._consumed.keys())

    @staticmethod
    def _tier_digests(record, explicit):
        """Return the one tier's digests (explicit or seal)."""
        return [
            digest
            for digest, marked in zip(
                record["digests"], record["explicit"]
            )
            if marked == explicit
        ]

    def _explicit_digests_for(self, entry):
        """Return ``[(key, digest)]`` explicit observations of ``entry``."""
        found = []
        for key in self._consumed_keys_for(entry):
            for digest, marked in zip(
                    self._consumed[key]["digests"],
                    self._consumed[key]["explicit"]):
                if marked:
                    found.append((key, digest))
        return found

    def _verify_consumed_now(self, case_id, outcome):
        """Return consumption mismatches for the ending case.

        An executing case (PASS, or a proof FAIL) fails when any
        declared input was explicitly consumed with different
        bytes across observations -- the run cannot attest one
        digest for two executed byte-strings --, when the
        explicitly consumed bytes differ from the same stage's
        seal, and when any declared input has
        no explicit consumption record (the fixture consumed
        outside the recorder, so the begin seal observed bytes
        no trusted read ever handed downstream). Seal-tier
        observations never mismatch here (the seal rules in
        :meth:`_verify_case_inputs_now` own them), and cases
        that claim no execution stay lenient: their inputs
        attest zeros. Inputs missing at every observation are
        left to :meth:`_verify_case_inputs_now`, which already
        reports them.
        """
        strict = outcome in ("PASS", "FAIL")
        if not strict:
            return []
        classes = self._sealed_inputs.get(case_id, {})
        sealed = self._sealed_entry_digests.get(case_id, {})
        had = {key for key, record in self._consumed.items()
               if any(record["explicit"])}
        bad = []
        for _class in ("sources", "objects", "corpus"):
            for entry in classes.get(_class, []):
                if self._impl_path(entry) is not None:
                    # Implementation evidence seals but never
                    # demands explicit consumption: the code ran
                    # before any recorder existed.
                    continue
                keys = self._consumed_keys_for(entry)
                if isinstance(entry, str):
                    label = "%s entry %r" % (_class, entry)
                else:
                    label = "%s staged entry %r" % (
                        _class, entry[1]
                    )
                observed = self._explicit_digests_for(entry)
                present = [
                    digest for _, digest in observed
                    if digest is not None
                ]
                if observed and present and (
                        len(observed) != len(present)
                        or any(item != present[0] for item in present)):
                    bad.append(
                        "%s was consumed with different "
                        "bytes" % (label,)
                    )
                    continue
                if present:
                    unanimous = present[0]
                    entry_key = self._entry_key(_class, entry)
                    if isinstance(entry, str):
                        pin = sealed.get(entry_key)
                        if (
                            pin is not None
                            and pin[0] == "absolute"
                            and pin[1] is not None
                            and pin[1] != unanimous
                        ):
                            bad.append(
                                "%s was consumed with different "
                                "bytes than sealed" % (label,)
                            )
                            continue
                    else:
                        pin = sealed.get(entry_key)
                        pinned = (
                            pin[1] if pin is not None
                            and pin[0] == "staged" else {}
                        )
                        for key in keys:
                            if not self._tier_digests(
                                    self._consumed[key], True):
                                continue
                            stage = os.path.dirname(key)
                            if (
                                stage in pinned
                                and pinned[stage] != unanimous
                            ):
                                bad.append(
                                    "%s was consumed with "
                                    "different bytes than sealed"
                                    % (label,)
                                )
                                break
                        else:
                            if not any(
                                    key in had for key in keys):
                                bad.append(
                                    "%s was never consumed before "
                                    "execution" % (label,)
                                )
                            continue
                        continue
                if not any(
                        key in had for key in keys):
                    bad.append(
                        "%s was never consumed before "
                        "execution" % (label,)
                    )
        return bad

    def _verify_sealed_inputs(self, stage_dir, snapshot=None):
        """Return ``{case_id: [mismatches]}`` for resealed inputs.

        Compares the finish-time bytes against the earliest
        seals. Only observed-then-changed (or
        observed-then-vanished) bytes mismatch; entries
        unobserved at seal time stay lenient (staged late, or
        finished from a directory the seal never resolved),
        with the finish-time hash authoritative. Cases that
        claimed execution with never-observed inputs already
        failed at :meth:`_end_case`, so the leniency here
        covers only cases that claim no execution. Attestation
        never uses these reads (see :meth:`_hash_inputs`); this
        is a tripwire only. Reads through ``snapshot`` so the
        caller keeps one read per path.
        """
        cache = {} if snapshot is None else snapshot
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
                    absolute = (
                        entry if isinstance(entry, str)
                        else self._impl_path(entry)
                    )
                    if kind == "absolute" and absolute is not None:
                        if first is None:
                            continue
                        data = _snapshot_file_bytes(absolute, cache)
                        current = (
                            None if data is None
                            else _sha256_bytes(data)
                        )
                        if current != first:
                            bad.append(
                                "%s entry %r changed after sealing"
                                % (_class, entry)
                            )
                    elif stage_key is not None and stage_key in first:
                        data = _snapshot_file_bytes(
                            os.path.join(stage_dir, entry[1]), cache
                        )
                        current = (
                            None if data is None
                            else _sha256_bytes(data)
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

    def _consumed_attested_bytes(self, entry, stage_key):
        """Return the logged bytes to attest for ``entry`` or None.

        Absolute entries resolve to their single log key, staged
        entries to the finish-stage log key. Explicit consumption
        observations are required: only their unanimous present
        bytes attest (a
        stage the run never consumed from attests nothing, and
        disagreement voids the attestation). Seal/preflight
        observations never attest, even on direct recorder calls.
        Total absence and missing observations void the
        attestation either way.
        """
        if isinstance(entry, str):
            keys = [os.path.abspath(entry)]
        elif stage_key is None:
            return None
        else:
            keys = [os.path.abspath(os.path.join(stage_key, entry[1]))]
        records = [
            self._consumed[key]
            for key in keys if key in self._consumed
        ]
        if not records:
            return None
        # Explicit precedence is entry-global: any explicit
        # observation under any key of this entry disables the
        # seal fallback for the whole entry.
        entry_explicit = []
        for key in self._consumed_keys_for(entry):
            entry_explicit += self._tier_digests(
                self._consumed[key], True
            )
        if entry_explicit:
            if (
                any(item is None for item in entry_explicit)
                or any(
                    item != entry_explicit[0]
                    for item in entry_explicit
                )
            ):
                return None
            # The finish key itself must carry explicit
            # observations: a stage the run never consumed from
            # attests nothing even when its seal observed bytes.
            if not self._tier_digests(records[0], True):
                return None
            return records[0]["explicit_bytes"]
        return None

    def _hash_inputs(self, stage_dir, snapshot=None):
        """Digest the declared per-case input classes.

        Returns ``{case_id: {"sources": ..., "objects": ...,
        "corpus": ...}}``. A class with no declared files digests
        to the empty-input hash, as does a class whose files
        total zero bytes (declared-but-empty backs no
        workload); a class with any missing file digests to
        zeros. Digests come only from the consumption log (see
        :meth:`_consumed_attested_bytes`): ``("stage", basename)``
        entries resolve against ``stage_dir`` (None means every
        staged entry is missing: nothing was built or staged),
        and an entry whose consumed bytes disagree -- or that
        was never consumed from the finish stage -- digests its
        class to zeros. No filesystem read happens here, so a
        finish-time swap can neither be attested nor straddle
        the attestation; :meth:`_verify_sealed_inputs` keeps its
        own single verification read per path.
        """
        if stage_dir is None:
            stage_key = None
        else:
            stage_key = os.path.abspath(stage_dir)
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
                    if self._impl_path(entry) is not None:
                        # Implementation evidence binds the
                        # earliest sealed digest (no fresh read,
                        # no execution claim); unsealed evidence
                        # zeroes the class like any missing file.
                        pin = self._sealed_entry_digests.get(
                            case_id, {}
                        ).get(self._entry_key(_class, entry))
                        if (
                            pin is None
                            or pin[0] != "absolute"
                            or pin[1] is None
                        ):
                            complete = False
                            break
                        digest.update(bytes.fromhex(pin[1]))
                        seen_bytes += len(bytes.fromhex(pin[1]))
                        digest.update(b"\x00")
                        continue
                    data = self._consumed_attested_bytes(
                        entry, stage_key
                    )
                    if data is None:
                        complete = False
                        break
                    digest.update(data)
                    seen_bytes += len(data)
                    digest.update(b"\x00")
                if not complete:
                    hashed[_class] = ZERO_SHA256
                elif seen_bytes == 0:
                    hashed[_class] = EMPTY_SHA256
                else:
                    hashed[_class] = digest.hexdigest()
            digests[case_id] = hashed
        return digests

    def _verify_consumed_finish(self, stage_dir):
        """Return ``{case_id: [mismatches]}`` for finish attestation.

        Every declaration must have unanimous consumption, including
        observations added after end_case. Staged entries additionally
        require consumption from the finish stage. Missing or
        contradictory consumption cannot leave a PASS with zero hashes.
        """
        stage_key = None if stage_dir is None else os.path.abspath(stage_dir)
        mismatches = {}
        for case_id in self._sealed_case_ids:
            classes = self._sealed_inputs.get(case_id, {})
            bad = []
            for _class in ("sources", "objects", "corpus"):
                for entry in classes.get(_class, []):
                    if self._impl_path(entry) is not None:
                        continue
                    if self._consumed_attested_bytes(
                            entry, stage_key) is None:
                        if isinstance(entry, str):
                            bad.append(
                                "%s entry %r lacks unanimous consumption"
                                % (_class, entry)
                            )
                        else:
                            bad.append(
                                "%s staged entry %r was never "
                                "consumed from the finish stage"
                                % (_class, entry[1])
                            )
            if bad:
                mismatches[case_id] = bad
        return mismatches

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
        """Finalize with immediate cleanup even if terminal setup fails."""
        clear_active_recorder(self)
        finished = False
        try:
            code = self._finish_results(
                stage_dir=stage_dir, unavailable_seen=unavailable_seen)
            finished = True
            return code
        finally:
            clear_active_recorder(self)
            disarm_staged_handoffs()
            if not finished:
                _discard_owned_stages_collected()

    def _finish_results(self, *, stage_dir=None, unavailable_seen=False):
        """Aggregate, emit plan/results/terminal, return the exit code.

        Gaps (cases the loop never ended) are recorded NOT_RUN.
        Run strays are reaped as hygiene and attributed leaks
        annotated. Declared inputs attest from the consumption
        log only, the byte seals are verified from a single
        read per path, and a finish stage the run never
        consumed from is rejected (an executing case whose
        observed bytes changed or vanished, whose consumed
        bytes disagree, or whose finish stage is unsealed fails
        at TEST_RUN), then owned stages are discarded with any
        removal failure folded into the terminal (a PASS it can
        no longer prove clean becomes INFRA_ERROR at CLEANUP)
        -- teardown always precedes the terminal. The exit
        derives from the aggregation verdict: 0 for PASS, 1 for
        FAIL, 3 for INCOMPLETE with lease-gated cases, else 2.
        Every path through the suites funnels here (or
        :meth:`finish_unrun`), so the exit always agrees with
        the emitted terminal record.
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
        if self._input_cleanup_errors:
            for stored in self._cases.values():
                stored["cleanup"]["residue"].extend(
                    item for item in self._input_cleanup_errors
                    if item not in stored["cleanup"]["residue"]
                )
                stored["cleanup"]["status"] = "RESIDUE"
                if stored["outcome"] == "PASS":
                    stored["outcome"] = "INFRA_ERROR"
                    stored["failure_stage"] = "CLEANUP"
        revisions = self._resolve_revisions()
        target = self._resolve_target()
        # Consumption-bound attestation: the digests come only
        # from the consumption log, so no finish-time read can
        # be attested or straddled; the seal verification below
        # keeps its own single read per path as a tripwire.
        clear_active_recorder(self)
        snapshot = {}
        digests = self._hash_inputs(stage_dir, snapshot)
        for case_id, bad in self._verify_sealed_inputs(
                stage_dir, snapshot).items():
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
        for case_id, bad in self._verify_consumed_finish(
                stage_dir).items():
            # The finish stage was never consumed from: bytes no
            # case consumed are never attested (their classes
            # already digest to zeros above), and an executing
            # case fails at TEST_RUN. Cases that claim no
            # execution keep their typed terminals, and cases
            # already failed at TEST_RUN keep their earlier
            # residue (no duplicate line).
            stored = self._cases[case_id]
            if stored["outcome"] not in ("PASS", "FAIL"):
                continue
            if (
                stored["outcome"] == "FAIL"
                and stored.get("failure_stage") == "TEST_RUN"
            ):
                continue
            stored["cleanup"]["residue"].extend(
                "input bytes not consumed from the finish "
                "stage: %s" % item
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
        clear_active_recorder(self)
        print("REFUSED: %s" % reason)
        for case_id in self._sealed_case_ids:
            self._cases[case_id] = {
                "outcome": "NOT_RUN",
                "failure_stage": "INFRA",
                "availability": "TOOLCHAIN_UNAVAILABLE",
                "cleanup": {"status": "NOT_CHECKED", "residue": []},
            }
        return self.finish(unavailable_seen=False)
