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
"""

import os
import signal
import subprocess
import time


class GuestTimeout(Exception):
    """A guest run exceeded its timeout; the owned tree is reaped.

    Carries the partial ``output``, the ``timeout`` seconds, and
    the stage ``log_path`` holding the partial transcript.
    """

    def __init__(self, output, timeout, log_path):
        super().__init__(
            "guest run timed out after %ds (partial log at %s)"
            % (timeout, log_path)
        )
        self.output = output
        self.timeout = timeout
        self.log_path = log_path


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
    """
    seen_groups = {pgid}
    deadline = time.monotonic() + 30
    first = True
    while time.monotonic() < deadline:
        table = _scan_processes()
        if not table and first:
            # No snapshot (no /proc): fall back to the guest
            # group alone.
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


def run_owned(argv, stage, timeout, log_name="guest.log"):
    """Run ``argv`` as an owned session leader; return (code, output).

    On timeout the whole owned tree is killed and reaped, the
    partial transcript is saved to the stage log, and
    :class:`GuestTimeout` is raised carrying the partial output.
    On interruption the owned tree is reaped, the partial
    transcript is saved, and the interruption propagates. The
    success transcript is saved to the stage log as well.
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
        kill_guest_tree(proc.pid)
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
        raise GuestTimeout(output, timeout, log_path)
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
