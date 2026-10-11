# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Deterministic pidfd ownership faults; no real process lifecycle changes."""

import errno
import importlib
import os
from types import SimpleNamespace

import pytest


BOOT = "12345678-1234-4567-9234-123456789abc"


@pytest.fixture
def guardian_module():
    try:
        return importlib.import_module("mojobpf.process_guardian")
    except ModuleNotFoundError as exc:
        if exc.name != "mojobpf.process_guardian":
            raise
        pytest.fail("retained-pidfd identity enforcement is absent", pytrace=False)


def stat_text(pid=101, ticks=1001, ppid=100, session=101, comm="worker (odd) name", state="S"):
    # Linux fields 3..22: state, ppid, pgrp, session, then fifteen fields and starttime.
    return f"{pid} ({comm}) {state} {ppid} {pid} {session} " + "0 " * 15 + str(ticks) + "\n"


class KernelModel:
    """A handle binds to one process object, even when its numeric PID repeats."""
    controller_pid = 100

    def __init__(self):
        self.current = {}
        self.handles = {}
        self.closed = []
        self.signals = []
        self.next_fd = 20
        self.before_stat = None
        self.stat_reads = 0
        self.open_error = None
        self.proc_error = None
        self.fdinfo_override = None
        self.signal_error = None

    def add(self, pid=101, ticks=1001, ppid=100, session=None, state="S"):
        item = SimpleNamespace(pid=pid, ticks=ticks, ppid=ppid, session=session or pid,
                               state=state, exited=state == "Z")
        self.current[pid] = item
        return item

    def host_boot_id(self):
        return BOOT

    def check_available(self):
        return None

    def open_pidfd(self, pid):
        if self.open_error is not None:
            raise OSError(self.open_error, "injected pidfd error")
        if pid not in self.current:
            raise ProcessLookupError(errno.ESRCH, "vanished child")
        fd = self.next_fd
        self.next_fd += 1
        self.handles[fd] = self.current[pid]
        return fd

    def close_pidfd(self, fd):
        self.closed.append(fd)

    def pidfd_exited(self, fd):
        return self.handles[fd].exited

    def read_fdinfo(self, fd):
        if self.fdinfo_override is not None:
            return self.fdinfo_override
        item = self.handles[fd]
        pid = item.pid if self.current.get(item.pid) is item else -1
        return f"pos:\t0\nflags:\t02000002\nPid:\t{pid}\nNSpid:\t{pid}\n"

    def read_stat(self, pid):
        self.stat_reads += 1
        if self.before_stat is not None:
            self.before_stat(self, self.stat_reads)
        if self.proc_error is not None:
            raise OSError(self.proc_error, "injected procfs error")
        item = self.current.get(pid)
        if item is None:
            raise FileNotFoundError(errno.ENOENT, "stat disappeared")
        return stat_text(item.pid, item.ticks, item.ppid, item.session, state=item.state)

    def signal_pidfd(self, fd, sig):
        if self.signal_error:
            raise OSError(self.signal_error, "injected signal error")
        item = self.handles[fd]
        self.signals.append((item, sig))

    def monotonic(self):
        return 12.5


def build_guardian(module, kernel, **limits):
    events = []
    return module.ProcessGuardian(limits=module.GuardLimits(**limits), journal=events.append,
                                  _backend=kernel), events


@pytest.fixture(autouse=True)
def no_numeric_signal(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("numeric PID/group signal escaped retained pidfd boundary")
    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(os, "killpg", forbidden)


def test_stat_comm_with_spaces_and_parentheses(guardian_module):
    record = guardian_module.parse_process_stat(stat_text(comm="a ) ( nested) tail"))
    assert record is not None, "valid Linux stat observation was not parsed"
    assert (record.pid, record.ppid, record.session_id, record.start_ticks) == (101, 100, 101, 1001)
    assert record.comm == "a ) ( nested) tail"


@pytest.mark.parametrize("raw", ["", "101 worker S 100", stat_text(ticks=0),
                                  stat_text(ppid=-1), stat_text().replace(" S ", " ? ")])
def test_malformed_stat_is_identity_failure(guardian_module, raw):
    with pytest.raises(guardian_module.GuardianError) as error:
        guardian_module.parse_process_stat(raw)
    assert error.value.code == "OWNERSHIP_UNKNOWN"


def test_zombie_runner_is_retained_before_reap(guardian_module):
    kernel = KernelModel()
    kernel.add(state="Z")
    guardian, events = build_guardian(guardian_module, kernel)
    identity = guardian.retain_runner(SimpleNamespace(pid=101))
    assert identity is not None, "direct zombie child has no retained identity"
    assert (identity.pid, identity.start_ticks, identity.host_boot_id) == (101, 1001, BOOT)
    assert len(guardian._entries) == 1
    assert kernel.closed == []
    assert events[-1]["event"] == "retained"


def test_vanished_hint_is_not_invented_identity(guardian_module):
    kernel = KernelModel()
    guardian, events = build_guardian(guardian_module, kernel)
    assert guardian._retain_candidate(101) is None
    assert guardian._entries == []
    assert events[-1]["event"] == "transient-hint"


def test_vanished_runner_is_terminal_failure(guardian_module):
    guardian, events = build_guardian(guardian_module, KernelModel())
    with pytest.raises(guardian_module.GuardianError) as error:
        guardian.retain_runner(SimpleNamespace(pid=101))
    assert error.value.code == "OWNERSHIP_UNKNOWN"


def test_changed_start_ticks_refuses_retention(guardian_module):
    kernel = KernelModel()
    item = kernel.add()
    kernel.before_stat = lambda model, n: setattr(item, "ticks", 1002) if n == 2 else None
    guardian, _ = build_guardian(guardian_module, kernel)
    with pytest.raises(guardian_module.GuardianError):
        guardian.retain_runner(SimpleNamespace(pid=101))
    assert guardian._entries == []
    assert kernel.closed == [20]


@pytest.mark.parametrize("raw", ["pos: 0\n", "Pid: -1\n", "Pid: 102\n", "Pid: 101\nPid: 102\n"])
def test_unknown_fdinfo_is_refused(guardian_module, raw):
    kernel = KernelModel()
    kernel.add()
    kernel.fdinfo_override = raw
    guardian, _ = build_guardian(guardian_module, kernel)
    with pytest.raises(guardian_module.GuardianError):
        guardian.retain_runner(SimpleNamespace(pid=101))
    assert guardian._entries == []
    assert kernel.closed == [20]


def test_unknown_parent_is_not_owned(guardian_module):
    kernel = KernelModel()
    kernel.add(ppid=500)
    guardian, _ = build_guardian(guardian_module, kernel)
    with pytest.raises(guardian_module.GuardianError):
        guardian._retain_candidate(101)
    assert kernel.signals == []
    assert kernel.closed == [20]


def test_parent_exit_during_acquisition_defers_to_adoption(guardian_module):
    kernel = KernelModel()
    parent = kernel.add()
    guardian, events = build_guardian(guardian_module, kernel)
    guardian.retain_runner(SimpleNamespace(pid=101))
    child = kernel.add(pid=102, ppid=101)
    kernel.before_stat = lambda model, n: setattr(parent, "exited", True) if n == 3 else None
    assert guardian._retain_candidate(102, parent=guardian._entries[0]) is None
    assert len(guardian._entries) == 1
    assert events[-1]["event"] == "defer-adoption"
    child.ppid = 100
    assert guardian._retain_candidate(102).identity.pid == 102


def test_same_tick_pid_reuse_keeps_two_handles(guardian_module):
    kernel = KernelModel()
    original = kernel.add()
    guardian, _ = build_guardian(guardian_module, kernel)
    guardian.retain_runner(SimpleNamespace(pid=101))
    old = guardian._entries[0]
    original.exited = True
    replacement = kernel.add()
    new = guardian._retain_candidate(101)
    assert old.identity == new.identity
    assert old.sequence != new.sequence
    assert guardian.projection_ambiguous
    assert guardian._signal_retained(old, 9) is False
    assert guardian._signal_retained(new, 9) is True
    assert kernel.signals == [(replacement, 9)]


def test_only_acquired_handles_can_be_signaled(guardian_module):
    kernel = KernelModel()
    child = kernel.add()
    guardian, _ = build_guardian(guardian_module, kernel)
    guardian.retain_runner(SimpleNamespace(pid=101))
    entry = guardian._entries[0]
    forged = SimpleNamespace(sequence=entry.sequence, identity=entry.identity, pidfd=entry.pidfd)
    with pytest.raises(guardian_module.GuardianError):
        guardian._signal_retained(forged, 9)
    assert guardian._signal_retained(entry, 9)
    assert kernel.signals == [(child, 9)]


@pytest.mark.parametrize("number", [errno.EMFILE, errno.EPERM, errno.ENOSYS])
def test_pidfd_failure_never_falls_back_to_numeric_signals(guardian_module, number):
    kernel = KernelModel()
    kernel.add()
    kernel.open_error = number
    guardian, events = build_guardian(guardian_module, kernel)
    with pytest.raises(guardian_module.GuardianError) as error:
        guardian.retain_runner(SimpleNamespace(pid=101))
    assert error.value.errno == number
    assert kernel.signals == []
    assert events[-1]["errno"] == number


@pytest.mark.parametrize("number", [errno.ENOENT, errno.EACCES])
def test_unreadable_procfs_is_terminal_for_runner(guardian_module, number):
    kernel = KernelModel()
    kernel.add()
    kernel.proc_error = number
    guardian, _ = build_guardian(guardian_module, kernel)
    with pytest.raises(guardian_module.GuardianError) as error:
        guardian.retain_runner(SimpleNamespace(pid=101))
    assert error.value.errno == number
    assert kernel.closed == [20]


def test_retained_process_cap_does_not_discard_prior_handle(guardian_module):
    kernel = KernelModel()
    kernel.add()
    guardian, _ = build_guardian(guardian_module, kernel, max_retained_processes=1, max_live_processes=1)
    guardian.retain_runner(SimpleNamespace(pid=101))
    kernel.add(pid=102)
    with pytest.raises(guardian_module.GuardianError):
        guardian._retain_candidate(102)
    assert len(guardian._entries) == 1
    assert guardian._entries[0].pidfd == 20
    assert 20 not in kernel.closed


def test_signal_errno_is_recorded_without_reopening_pid(guardian_module):
    kernel = KernelModel()
    kernel.add()
    guardian, events = build_guardian(guardian_module, kernel)
    guardian.retain_runner(SimpleNamespace(pid=101))
    kernel.signal_error = errno.EPERM
    with pytest.raises(guardian_module.GuardianError) as error:
        guardian._signal_retained(guardian._entries[0], 9)
    assert error.value.errno == errno.EPERM
    assert kernel.next_fd == 21
    assert events[-1]["event"] == "signal"
    assert events[-1]["errno"] == errno.EPERM


def test_linux_api_availability_check_is_read_only(guardian_module, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("availability inspection attempted lifecycle mutation")
    monkeypatch.setattr(os, "pidfd_open", forbidden)
    monkeypatch.setattr(os, "waitid", forbidden)
    guardian_module.check_linux_api_availability()


def test_missing_linux_api_is_typed_failure(guardian_module, monkeypatch):
    monkeypatch.delattr(os, "pidfd_open")
    with pytest.raises(guardian_module.GuardianError) as error:
        guardian_module.check_linux_api_availability()
    assert error.value.code == "OWNERSHIP_UNKNOWN"


def test_missing_stat_of_live_candidate_is_not_a_transient_hint(guardian_module):
    kernel = KernelModel()
    kernel.add()
    kernel.proc_error = errno.ENOENT
    guardian, _ = build_guardian(guardian_module, kernel)
    with pytest.raises(guardian_module.GuardianError) as error:
        guardian._retain_candidate(101)
    assert error.value.errno == errno.ENOENT
    assert kernel.closed == [20]


def test_journal_failure_retains_runner_ownership(guardian_module):
    kernel = KernelModel()
    kernel.add()
    def unwritable(record):
        raise OSError(errno.ENOSPC, "journal full")
    guardian = guardian_module.ProcessGuardian(limits=guardian_module.GuardLimits(),
                                               journal=unwritable, _backend=kernel)
    with pytest.raises(guardian_module.GuardianError) as error:
        guardian.retain_runner(SimpleNamespace(pid=101))
    assert error.value.code == "IO_FAILED"
    assert error.value.errno == errno.ENOSPC
    assert guardian._runner_entry is guardian._entries[0]
    assert kernel.closed == []


def test_candidate_fdinfo_io_error_is_typed(guardian_module):
    kernel = KernelModel()
    kernel.add()
    guardian, _ = build_guardian(guardian_module, kernel)
    guardian.retain_runner(SimpleNamespace(pid=101))
    def unreadable(fd):
        raise OSError(errno.EACCES, "fdinfo unavailable")
    kernel.read_fdinfo = unreadable
    with pytest.raises(guardian_module.GuardianError) as error:
        guardian._retain_candidate(101)
    assert error.value.errno == errno.EACCES
    assert kernel.closed == []


def test_proc_reads_are_bounded_during_acquisition(guardian_module):
    kernel = KernelModel()
    kernel.add()
    guardian, _ = build_guardian(guardian_module, kernel, max_proc_reads_per_tick=1)
    with pytest.raises(guardian_module.GuardianError):
        guardian.retain_runner(SimpleNamespace(pid=101))
    assert kernel.stat_reads == 0
    assert kernel.closed == [20]


def test_reparent_during_stat_reads_defers_to_adoption(guardian_module):
    kernel = KernelModel()
    parent = kernel.add()
    guardian, events = build_guardian(guardian_module, kernel)
    guardian.retain_runner(SimpleNamespace(pid=101))
    child = kernel.add(pid=102, ppid=101)
    def reparent(model, n):
        if n == 4:
            parent.exited = True
            child.ppid = model.controller_pid
    kernel.before_stat = reparent
    assert guardian._retain_candidate(102, parent=guardian._entries[0]) is None
    assert events[-1]["event"] == "defer-adoption"
    assert len(guardian._entries) == 1


@pytest.mark.parametrize("field", ["poll_seconds", "cleanup_seconds"])
def test_large_integer_time_bound_is_guardian_error(guardian_module, field):
    with pytest.raises(guardian_module.GuardianError) as error:
        guardian_module.GuardLimits(**{field: 10 ** 400})
    assert error.value.code == "OWNERSHIP_UNKNOWN"


@pytest.mark.parametrize("boundary", ["live-count", "stale-fdinfo", "signal-recovery", "parent-bracket",
                                      "acquisition-recovery"])
def test_secondary_pidfd_poll_error_is_recorded_and_typed(guardian_module, boundary):
    kernel = KernelModel()
    kernel.add()
    guardian, events = build_guardian(guardian_module, kernel)
    guardian.retain_runner(SimpleNamespace(pid=101))
    retained = guardian._entries[0]
    kernel.add(pid=102, ppid=101 if boundary == "parent-bracket" else 100)
    calls = 0
    original_poll = kernel.pidfd_exited
    if boundary == "stale-fdinfo":
        kernel.fdinfo_override = "Pid: -1\nNSpid: -1\n"
    if boundary == "signal-recovery":
        kernel.signal_error = errno.ESRCH
    if boundary == "acquisition-recovery":
        kernel.proc_error = errno.ENOENT
    fail_at = {"live-count": 1, "stale-fdinfo": 1, "signal-recovery": 2,
               "parent-bracket": 3, "acquisition-recovery": 3}[boundary]
    def failed_poll(fd):
        nonlocal calls
        calls += 1
        if calls == fail_at:
            raise OSError(errno.EBADF, "injected pidfd polling failure")
        return original_poll(fd)
    kernel.pidfd_exited = failed_poll
    with pytest.raises(guardian_module.GuardianError) as error:
        if boundary == "signal-recovery":
            guardian._signal_retained(retained, 9)
        elif boundary == "stale-fdinfo":
            guardian._retain_candidate(101)
        else:
            guardian._retain_candidate(102, parent=retained if boundary == "parent-bracket" else None)
    assert error.value.code == "OWNERSHIP_UNKNOWN"
    assert error.value.errno == errno.EBADF
    assert guardian._entries == [retained] and guardian._runner_entry is retained
    assert retained.pidfd not in kernel.closed
    assert kernel.signals == []
    assert events[-1]["event"] == "observation-failed" and events[-1]["errno"] == errno.EBADF
    if boundary == "signal-recovery":
        assert events[-2]["event"] == "signal" and events[-2]["errno"] == errno.ESRCH
    if boundary == "acquisition-recovery":
        assert kernel.closed == [21]


def test_signal_esrch_with_observed_exit_is_not_an_untyped_failure(guardian_module):
    kernel = KernelModel()
    process = kernel.add()
    guardian, events = build_guardian(guardian_module, kernel)
    guardian.retain_runner(SimpleNamespace(pid=101))
    def exited_before_signal(fd, sig):
        process.exited = True
        raise OSError(errno.ESRCH, "process exited")
    kernel.signal_pidfd = exited_before_signal
    assert guardian._signal_retained(guardian._entries[0], 9) is False
    assert events[-1]["event"] == "signal" and events[-1]["errno"] == errno.ESRCH
    assert kernel.closed == [] and kernel.signals == []
