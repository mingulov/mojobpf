# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Deterministic pidfd ownership faults; no real process lifecycle changes."""

import errno
import hashlib
import importlib
import json
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


class LifecycleKernel(KernelModel):
    """Bounded single-reaper kernel model; time advances only through pause."""
    def __init__(self):
        super().__init__()
        self.clock = 0.0
        self.wait_calls = []
        self.reaped = []
        self.scan_calls = []
        self.threads = {}
        self.subreaper = False
        self.subreaper_result = True
        self.sigchld_flags = 0
        self.cancel_handler = None
        self.cancel_on_open = False
        self.ignore_signals = False
        self.no_wait_observations = False
        self.on_signal = None
        self.before_reap = None

    def monotonic(self):
        return self.clock

    def pause(self, seconds):
        self.clock += seconds

    def tasks(self, pid, maximum):
        return self.threads.get(pid, [pid])[:maximum + 1]

    def read_children(self, pid, tid):
        self.scan_calls.append((pid, tid))
        pids = [item.pid for item in self.current.values() if item.ppid == pid
                and getattr(item, "parent_tid", pid) == tid]
        return " ".join(str(pid) for pid in sorted(pids))

    def read_stat(self, pid):
        if pid == self.controller_pid:
            return stat_text(pid=pid, ppid=1, session=pid, ticks=99)
        return super().read_stat(pid)

    def read_mountinfo(self):
        return "controlled raw mountinfo\n"

    def establish_sigchld(self):
        return {"default": True, "flags": self.sigchld_flags}

    def enable_subreaper(self):
        self.subreaper = self.subreaper_result
        return self.subreaper

    def install_cancellation(self, handler):
        self.cancel_handler = handler

    def restore_cancellation(self, release_step=None):
        if release_step is None:
            self.cancel_handler = None
            return
        for name in ("wakeup-fd", "sigint-handler", "sigterm-handler", "wake-read-close", "wake-write-close"):
            release_step(name, lambda: setattr(self, "cancel_handler", None))

    def open_pidfd(self, pid):
        fd = super().open_pidfd(pid)
        if self.cancel_on_open and self.cancel_handler is not None:
            self.cancel_handler(2, None)
        return fd

    def exit(self, item, status=0, code=None):
        item.exited, item.state = True, "Z"
        item.status = status
        item.code = os.CLD_EXITED if code is None else code
        for child in self.current.values():
            if child.ppid == item.pid:
                child.ppid = self.controller_pid
                child.parent_tid = self.controller_pid

    def signal_pidfd(self, fd, sig):
        super().signal_pidfd(fd, sig)
        item = self.handles[fd]
        if self.on_signal is not None:
            self.on_signal(item)
        if not self.ignore_signals:
            self.exit(item, sig, os.CLD_KILLED)

    def waitid(self, kind, identifier, options):
        self.wait_calls.append((kind, identifier, options))
        if self.no_wait_observations:
            return None
        if kind == os.P_ALL:
            children = [item for item in self.current.values() if item.ppid == self.controller_pid
                        and (options & 0x40000000 or not getattr(item, "clone_child", False))]
        else:
            item = self.handles[identifier]
            children = [item] if self.current.get(item.pid) is item and item.ppid == self.controller_pid else []
        if not children:
            raise ChildProcessError(errno.ECHILD, "no children")
        exited = sorted((item for item in children if item.exited), key=lambda item: item.pid)
        if not exited:
            return None
        item = exited[0]
        result = SimpleNamespace(si_pid=item.pid, si_code=getattr(item, "code", os.CLD_EXITED),
                                 si_status=getattr(item, "status", 0))
        if not options & os.WNOWAIT:
            if self.before_reap is not None:
                self.before_reap(item)
            self.reaped.append(item.pid)
            self.current.pop(item.pid)
        return result


def lifecycle(guardian_module, **limits):
    kernel = LifecycleKernel()
    guardian, events = build_guardian(guardian_module, kernel, cleanup_seconds=0.2, poll_seconds=0.05, **limits)
    guardian.prepare()
    process = SimpleNamespace(pid=101, returncode=None)
    kernel.add()
    guardian.retain_runner(process)
    return kernel, guardian, events, process


def test_none_from_waitid_is_not_echild(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    kernel.no_wait_observations = True
    proof = guardian.finish(reason="cancel", interrupt=True)
    assert proof["status"] == "INCOMPLETE" and proof["final_echild"] is False
    assert kernel.clock >= 0.2
    assert kernel.closed == []


def test_wall_includes_non_sigchld_children(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    kernel.add(pid=102).clone_child = True
    proof = guardian.finish(reason="cancel", interrupt=True)
    assert proof["status"] == "CLEAN"
    assert set(kernel.reaped) == {101, 102}
    assert all(options & 0x40000000 for _, _, options in kernel.wait_calls)
    assert any(options & os.WNOWAIT for _, _, options in kernel.wait_calls)
    assert any(not options & os.WNOWAIT for _, _, options in kernel.wait_calls)


def test_reap_requires_identity_capture(guardian_module):
    kernel, guardian, events, _ = lifecycle(guardian_module)
    kernel.add(pid=102, state="Z")
    def capture_required(item):
        assert any(entry.identity.pid == item.pid and entry.raw_stat and entry.raw_fdinfo
                   for entry in guardian._entries), "child reaped before identity acquisition"
        assert any(event["event"] == "wait-observed" and event["identity"]["pid"] == item.pid for event in events)
    kernel.before_reap = capture_required
    assert guardian.finish(reason="normal", interrupt=False)["status"] == "CLEAN"
    assert set(kernel.reaped) == {101, 102}


def test_descendant_discovered_after_runner_exit(guardian_module):
    kernel, guardian, _, process = lifecycle(guardian_module)
    kernel.add(pid=102, ppid=101)
    kernel.exit(kernel.current[101])
    guardian.observe()
    assert any(entry.identity.pid == 102 and entry.ownership_basis == "adopted-child" for entry in guardian._entries)
    assert guardian.finish(reason="normal", interrupt=False)["status"] == "CLEAN"
    assert process.returncode == 0


def test_late_child_during_cleanup(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    def late_fork(item):
        if item.pid == 101 and 102 not in kernel.current:
            kernel.add(pid=102, ppid=101)
    kernel.on_signal = late_fork
    proof = guardian.finish(reason="cancel", interrupt=True)
    assert proof["status"] == "CLEAN" and proof["adoptions"] >= 1
    assert [item.pid for item, _ in kernel.signals] == [101, 102]
    assert {entry.identity.pid for entry in guardian._entries} == {101, 102}


def test_sets_id_does_not_change_ownership(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    kernel.add(pid=102, ppid=101, session=777)
    observations = guardian.observe()
    assert any(item["identity"]["pid"] == 102 and item["session_id"] == 777 for item in observations)
    assert guardian.finish(reason="normal", interrupt=False)["status"] == "CLEAN"
    assert [item.pid for item, _ in kernel.signals] == [101, 102]


def test_nonleader_thread_child_is_discovered(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    kernel.threads[101] = [101, 103]
    kernel.add(pid=102, ppid=101).parent_tid = 103
    guardian.observe()
    assert (101, 103) in kernel.scan_calls
    assert any(entry.identity.pid == 102 and entry.ownership_basis == "observed-descendant" for entry in guardian._entries)
    assert guardian.finish(reason="cancel", interrupt=True)["status"] == "CLEAN"


def test_bounds_force_failure_and_cleanup(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module, max_live_processes=1)
    kernel.add(pid=102, ppid=101)
    with pytest.raises(guardian_module.GuardianError):
        guardian.observe()
    proof = guardian.finish(reason="bound", interrupt=False)
    assert proof["status"] == "INCOMPLETE" and proof["final_echild"] is True
    assert any(item["code"] == "OWNERSHIP_UNKNOWN" for item in proof["failures"])
    assert [item.pid for item, _ in kernel.signals] == [101, 102]


def test_unreadable_identity_quarantines(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    kernel.add(pid=102, ppid=101)
    kernel.proc_error = errno.EACCES
    with pytest.raises(guardian_module.GuardianError):
        guardian.observe()
    kernel.proc_error = None
    proof = guardian.finish(reason="identity", interrupt=False)
    assert proof["status"] == "INCOMPLETE" and proof["final_echild"] is True
    assert any(item["errno"] == errno.EACCES for item in proof["failures"])
    with pytest.raises(guardian_module.GuardianError):
        guardian.prepare()


def test_cancel_during_spawn_retains_child(guardian_module):
    kernel = LifecycleKernel()
    guardian, _ = build_guardian(guardian_module, kernel)
    guardian.prepare()
    kernel.add()
    kernel.cancel_on_open = True
    process = SimpleNamespace(pid=101, returncode=None)
    guardian.retain_runner(process)
    assert guardian.cancelled is True
    assert guardian._runner_entry is guardian._entries[0]
    proof = guardian.finish(reason="cancel", interrupt=True)
    assert proof["status"] == "CLEAN" and process.returncode == -9


def test_dead_pidfd_never_targets_replacement(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    old = kernel.add(pid=102, ppid=101)
    guardian.observe()
    old.exited = True
    replacement = kernel.add(pid=102, ppid=101)
    guardian.observe()
    assert guardian.projection_ambiguous
    assert guardian.finish(reason="cancel", interrupt=True)["status"] == "CLEAN"
    assert all(item is not old for item, _ in kernel.signals)
    assert any(item is replacement for item, _ in kernel.signals)


def test_normal_exit_drains_residue(guardian_module):
    kernel, guardian, _, process = lifecycle(guardian_module)
    child = kernel.add(pid=102, ppid=101)
    guardian.observe()
    kernel.exit(kernel.current[101])
    proof = guardian.finish(reason="normal", interrupt=False)
    assert proof["status"] == "CLEAN" and proof["final_echild"] is True
    assert process.returncode == 0 and kernel.signals == [(child, 9)]
    assert kernel.current == {} and len(kernel.closed) == 2


@pytest.mark.parametrize("defect", ["existing-child", "threads", "sigchld-flags", "subreaper-readback"])
def test_prepare_refuses_unverified_dedicated_process(guardian_module, defect):
    kernel = LifecycleKernel()
    if defect == "existing-child":
        kernel.add(pid=201)
    elif defect == "threads":
        kernel.threads[100] = [100, 104]
    elif defect == "sigchld-flags":
        kernel.sigchld_flags = 2
    else:
        kernel.subreaper_result = False
    guardian, _ = build_guardian(guardian_module, kernel)
    with pytest.raises(guardian_module.GuardianError) as error:
        guardian.prepare()
    assert error.value.code == "OWNERSHIP_UNKNOWN"
    assert kernel.signals == [] and kernel.reaped == []


def test_cleanup_deadline_uses_monotonic_clock(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    kernel.ignore_signals = True
    proof = guardian.finish(reason="cancel", interrupt=True)
    assert proof["status"] == "INCOMPLETE" and 0.2 <= kernel.clock <= 0.200001
    assert kernel.closed == [] and len(kernel.signals) == 1


@pytest.mark.parametrize("code,status,signed", [(os.CLD_EXITED, 7, 7), (os.CLD_KILLED, 9, -9), (os.CLD_DUMPED, 11, -11)])
def test_signed_exit_is_observed_without_reap_then_reaped_once(guardian_module, code, status, signed):
    kernel, guardian, _, process = lifecycle(guardian_module)
    kernel.exit(kernel.current[101], status, code)
    assert guardian.runner_exit() == signed
    assert process.returncode is None and kernel.reaped == []
    proof = guardian.finish(reason="normal", interrupt=False)
    assert proof["status"] == "CLEAN" and process.returncode == signed and kernel.reaped == [101]


def test_clean_epoch_closes_handles_before_next_epoch(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    assert guardian.finish(reason="cancel", interrupt=True)["status"] == "CLEAN"
    guardian.prepare()
    kernel.add(pid=201)
    process = SimpleNamespace(pid=201, returncode=None)
    guardian.retain_runner(process)
    assert len(guardian._entries) == 1 and guardian._runner_entry.identity.pid == 201
    assert guardian.finish(reason="normal", interrupt=False)["status"] == "CLEAN"
    assert kernel.closed == [20, 21]


def test_terminal_journal_failure_does_not_release_retained_handles(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    original = guardian._journal
    def failing(record):
        if record["event"] in {"cleanup-terminal", "cleanup-provisional"}:
            raise OSError(errno.ENOSPC, "terminal journal failed")
        original(record)
    guardian._journal = failing
    proof = guardian.finish(reason="normal", interrupt=False)
    assert proof["status"] == "INCOMPLETE" and proof["final_echild"] is True
    assert any(item["code"] == "IO_FAILED" for item in proof["failures"])
    assert kernel.closed == []


@pytest.mark.parametrize("bound", ["tasks", "reads", "retained"])
def test_resource_failure_remains_terminal_after_owned_cleanup(guardian_module, bound):
    limits = {"max_tasks_per_process": 1} if bound == "tasks" else (
        {"max_proc_reads_per_tick": 4} if bound == "reads" else
        {"max_live_processes": 2, "max_retained_processes": 2})
    kernel, guardian, _, _ = lifecycle(guardian_module, **limits)
    if bound == "tasks":
        kernel.threads[101] = [101, 103]
    elif bound == "retained":
        kernel.add(pid=102, ppid=101)
        kernel.add(pid=103, ppid=101)
    with pytest.raises(guardian_module.GuardianError) as error:
        guardian.observe()
    assert error.value.code == "OWNERSHIP_UNKNOWN"
    proof = guardian.finish(reason="resource", interrupt=False)
    assert proof["status"] == "INCOMPLETE"
    assert all(entry.pidfd not in kernel.closed for entry in guardian._entries)
    assert any(item["code"] == "OWNERSHIP_UNKNOWN" for item in proof["failures"])


def test_deadline_cannot_be_extended_by_journal_callback(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    original = guardian._journal
    def slow(record):
        original(record)
        if record["event"] == "cleanup-entered":
            kernel.clock = 0.3
    guardian._journal = slow
    proof = guardian.finish(reason="cancel", interrupt=True)
    assert proof["status"] == "INCOMPLETE"
    assert any(item["code"] == "CLEANUP_INCOMPLETE" for item in proof["failures"])
    assert kernel.closed == []


def test_each_terminal_transition_and_wait_status_is_journaled_once(guardian_module):
    kernel, guardian, events, _ = lifecycle(guardian_module)
    kernel.exit(kernel.current[101], 7)
    assert guardian.runner_exit() == guardian.runner_exit() == 7
    first = guardian.finish(reason="normal", interrupt=False)
    assert guardian.finish(reason="ignored-repeat", interrupt=True) == first
    for event in ("prepared", "cleanup-entered", "wait-observed", "reaped", "pidfd-exited", "echild", "cleanup-provisional", "cleanup-finalization"):
        assert sum(record["event"] == event for record in events) == 1, event
    assert [record["sequence"] for record in events] == list(range(1, len(events) + 1))


def test_observation_wait_status_is_not_mutable_internal_state(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    kernel.exit(kernel.current[101], 7)
    guardian.runner_exit()
    observations = guardian.observe()
    observations[0]["wait_status"]["exit_code"] = 55
    assert guardian.finish(reason="normal", interrupt=False)["runner_exit"] == 7


@pytest.mark.parametrize("result", [None, SimpleNamespace(si_pid=0)])
def test_prepare_requires_actual_echild_not_zero_wait_result(guardian_module, result):
    kernel = LifecycleKernel()
    kernel.waitid = lambda *args: result
    guardian, _ = build_guardian(guardian_module, kernel)
    with pytest.raises(guardian_module.GuardianError):
        guardian.prepare()
    assert kernel.subreaper is False and kernel.signals == []


def test_wait_api_failure_never_becomes_a_clean_drain(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    real_wait = kernel.waitid
    called = False
    def denied(kind, identifier, options):
        nonlocal called
        if not called:
            called = True
            raise OSError(errno.EINVAL, "unsupported wait mask")
        return real_wait(kind, identifier, options)
    kernel.waitid = denied
    proof = guardian.finish(reason="cancel", interrupt=True)
    assert proof["status"] == "INCOMPLETE" and proof["final_echild"] is True
    assert any(item["errno"] == errno.EINVAL for item in proof["failures"])
    assert kernel.closed == []


def test_live_retained_poll_failure_cleans_other_proven_handles(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    child = kernel.add(pid=102, ppid=101)
    guardian.observe()
    real_poll = kernel.pidfd_exited
    fail = True
    def denied(fd):
        nonlocal fail
        if fd == guardian._runner_entry.pidfd and fail:
            fail = False
            raise OSError(errno.EBADF, "retained poll uncertainty")
        return real_poll(fd)
    kernel.pidfd_exited = denied
    proof = guardian.finish(reason="cancel", interrupt=True)
    assert proof["status"] == "INCOMPLETE"
    assert (child, 9) in kernel.signals
    assert any(item["errno"] == errno.EBADF for item in proof["failures"])
    assert kernel.closed == []


def test_prepare_refuses_cleanup_budget_above_thirty_seconds(guardian_module):
    kernel = LifecycleKernel()
    guardian, _ = build_guardian(guardian_module, kernel, cleanup_seconds=31)
    with pytest.raises(guardian_module.GuardianError):
        guardian.prepare()
    assert kernel.subreaper is False


def test_terminal_journal_cannot_hide_expired_cleanup_budget(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    original = guardian._journal
    def slow(record):
        original(record)
        if record["event"] in {"cleanup-terminal", "cleanup-provisional"}:
            kernel.clock = 0.3
    guardian._journal = slow
    proof = guardian.finish(reason="normal", interrupt=False)
    assert proof["status"] == "INCOMPLETE" and kernel.closed == []
    assert any(item["code"] == "CLEANUP_INCOMPLETE" for item in proof["failures"])


@pytest.mark.parametrize("name", ["pidfd_open", "waitid", "pipe2"])
def test_noncallable_linux_wrapper_refuses_before_mutation(guardian_module, monkeypatch, name):
    monkeypatch.setattr(os, name, None)
    with pytest.raises(guardian_module.GuardianError) as error:
        guardian_module.check_linux_api_availability()
    assert error.value.code == "OWNERSHIP_UNKNOWN"


def test_missing_native_subreaper_symbol_is_typed_refusal(guardian_module, monkeypatch):
    monkeypatch.setattr(guardian_module.ctypes, "CDLL", lambda *args, **kwargs: SimpleNamespace())
    with pytest.raises(guardian_module.GuardianError) as error:
        guardian_module._LinuxBackend().establish_sigchld()
    assert error.value.code == "OWNERSHIP_UNKNOWN"


def test_prepare_never_discards_an_unsealed_identity_ledger(guardian_module):
    kernel = LifecycleKernel()
    kernel.add()
    guardian, _ = build_guardian(guardian_module, kernel)
    guardian.retain_runner(SimpleNamespace(pid=101, returncode=None))
    retained = guardian._entries[0]
    kernel.exit(kernel.current[101])
    kernel.current.pop(101)  # An outside reaper cannot authorize ledger reset.
    with pytest.raises(guardian_module.GuardianError):
        guardian.prepare()
    assert guardian._entries == [retained] and kernel.closed == []


@pytest.mark.parametrize("failed_polls", [1, 2, 3])
def test_transient_runner_poll_failure_retries_same_handle_before_descendant_signal(guardian_module, failed_polls):
    kernel, guardian, events, _ = lifecycle(guardian_module)
    kernel.add(pid=102, ppid=101)
    guardian.observe()
    retained = tuple(guardian._entries)
    original_handles = dict(kernel.handles)
    runner_fd = guardian._runner_entry.pidfd
    real_poll = kernel.pidfd_exited
    remaining = failed_polls
    def transient(fd):
        nonlocal remaining
        if fd == runner_fd and remaining:
            remaining -= 1
            raise OSError(errno.ENOMEM, "one-shot retained liveness fault")
        return real_poll(fd)
    kernel.pidfd_exited = transient
    proof = guardian.finish(reason="cancel", interrupt=True)
    assert kernel.current == {}, "recovered retained runner was never signaled or drained"
    assert [item.pid for item, _ in kernel.signals] == [101, 102]
    assert tuple(guardian._entries) == retained and kernel.handles == original_handles
    assert proof["status"] == "INCOMPLETE" and proof["final_echild"] is True
    assert proof["all_pidfds_exited"] is True and proof["unresolved_live"] == 0
    assert any(item["errno"] == errno.ENOMEM for item in proof["failures"])
    assert any(item["event"] == "observation-failed" and item["errno"] == errno.ENOMEM for item in events)
    assert kernel.closed == []
    with pytest.raises(guardian_module.GuardianError):
        guardian.prepare()


def test_transient_runner_signal_failure_retries_same_handle_before_descendant_signal(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    kernel.add(pid=102, ppid=101)
    guardian.observe()
    runner_fd = guardian._runner_entry.pidfd
    original_handles = dict(kernel.handles)
    real_signal = kernel.signal_pidfd
    attempts = []
    def transient(fd, sig):
        attempts.append(fd)
        if fd == runner_fd and attempts.count(fd) == 1:
            raise OSError(errno.ENOMEM, "one-shot retained signal fault")
        real_signal(fd, sig)
    kernel.signal_pidfd = transient
    proof = guardian.finish(reason="cancel", interrupt=True)
    assert kernel.current == {}, "failed syscall permanently consumed the runner's cleanup attempt"
    assert [item.pid for item, _ in kernel.signals] == [101, 102]
    assert attempts[:2] == [runner_fd, runner_fd]
    assert kernel.handles == original_handles
    assert proof["status"] == "INCOMPLETE" and proof["all_pidfds_exited"] is True
    assert any(item["errno"] == errno.ENOMEM for item in proof["failures"])
    assert kernel.closed == []


def test_persistent_runner_signal_failure_is_bounded_while_proven_child_is_drained(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    child = kernel.add(pid=102, ppid=101)
    guardian.observe()
    runner_fd = guardian._runner_entry.pidfd
    original_handles = dict(kernel.handles)
    real_signal = kernel.signal_pidfd
    attempts = []
    def failing(fd, sig):
        attempts.append(fd)
        if fd == runner_fd:
            raise OSError(errno.EBADF, "persistently unusable retained handle")
        real_signal(fd, sig)
    kernel.signal_pidfd = failing
    proof = guardian.finish(reason="cancel", interrupt=True)
    assert 1 < attempts.count(runner_fd) <= 3, "signal recovery is absent or unbounded"
    assert [item.pid for item in kernel.current.values() if not item.exited] == [101]
    assert child.exited is True and proof["final_echild"] is False
    assert kernel.signals == [(child, 9)] and kernel.handles == original_handles
    assert proof["status"] == "INCOMPLETE" and proof["unresolved_live"] == 1
    assert any(item["errno"] == errno.EBADF for item in proof["failures"])
    assert kernel.clock == pytest.approx(0.2) and kernel.closed == []


def test_post_signal_journal_failure_does_not_repeat_a_completed_syscall(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    kernel.ignore_signals = True
    real_journal = guardian._journal
    failed = False
    def failing(record):
        nonlocal failed
        if record["event"] == "signal" and record["sent"] and not failed:
            failed = True
            raise OSError(errno.ENOSPC, "signal record persisted unreliably")
        real_journal(record)
    guardian._journal = failing
    proof = guardian.finish(reason="cancel", interrupt=True)
    assert len(kernel.signals) == 1, "successful retained syscall was repeated after a journal fault"
    assert proof["status"] == "INCOMPLETE" and kernel.closed == []
    assert any(item["code"] == "IO_FAILED" and item["errno"] == errno.ENOSPC for item in proof["failures"])


@pytest.mark.parametrize("release", ["close", "restore"])
def test_late_final_release_cannot_return_clean(guardian_module, release):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    real_release = kernel.close_pidfd if release == "close" else kernel.restore_cancellation
    def late(*arguments):
        real_release(*arguments)
        kernel.clock = 0.3
    if release == "close":
        kernel.close_pidfd = late
    else:
        kernel.restore_cancellation = late
    proof = guardian.finish(reason="normal", interrupt=False)
    assert proof["status"] == "INCOMPLETE", "release completed beyond cleanup deadline but returned CLEAN"
    assert proof["final_echild"] is True and proof["all_pidfds_exited"] is True
    assert any(item["code"] == "CLEANUP_INCOMPLETE" for item in proof["failures"])
    with pytest.raises(guardian_module.GuardianError):
        guardian.prepare()


@pytest.mark.parametrize("fault", ["late-journal", "persist-then-error", "release-error"])
def test_serialized_finalization_fault_cannot_leave_an_authoritative_clean_event(guardian_module, fault):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    durable = []
    real_journal = guardian._journal
    def frozen_journal(record):
        durable.append(json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())
        real_journal(record)
        if record["event"] in {"cleanup-terminal", "cleanup-finalization"}:
            if fault == "late-journal":
                kernel.clock = 0.3
            elif fault == "persist-then-error":
                raise OSError(errno.ENOSPC, "record persisted before callback failed")
    guardian._journal = frozen_journal
    if fault == "release-error":
        def failing(*arguments):
            raise OSError(errno.EIO, "handler restore failed")
        kernel.restore_cancellation = failing
    proof = guardian.finish(reason="normal", interrupt=False)
    assert proof["status"] == "INCOMPLETE"
    assert proof["final_echild"] is True and proof["all_pidfds_exited"] is True
    records = [json.loads(raw) for raw in durable]
    authoritative_clean = [record for record in records if record.get("status") == "CLEAN"
                           and record.get("authoritative", True)]
    assert authoritative_clean == [], "fixed journal bytes still authorize CLEAN before fallible finalization"
    assert proof.get("completion_receipt") is None
    with pytest.raises(guardian_module.GuardianError):
        guardian.prepare()


def test_consumed_then_failed_close_never_uses_reused_descriptor_number(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    kernel.add(pid=102, ppid=101)
    guardian.observe()
    entry = guardian._runner_entry
    operations = []
    real_close = kernel.close_pidfd
    def uncertain(fd):
        operations.append(("close", fd))
        real_close(fd)
        kernel.handles[fd] = kernel.add(pid=999, ppid=1)
        raise OSError(errno.EIO, "original handle consumed, close acknowledgement failed")
    kernel.close_pidfd = uncertain
    proof = guardian.finish(reason="normal", interrupt=False)
    calls = list(operations)
    real_poll, real_signal = kernel.pidfd_exited, kernel.signal_pidfd
    def observed_poll(fd):
        operations.append(("poll", fd))
        return real_poll(fd)
    def observed_signal(fd, sig):
        operations.append(("signal", fd))
        return real_signal(fd, sig)
    kernel.pidfd_exited, kernel.signal_pidfd = observed_poll, observed_signal
    with pytest.raises(guardian_module.GuardianError):
        guardian._signal_retained(entry, 9)
    with pytest.raises(guardian_module.GuardianError):
        guardian._pidfd_exited(entry.pidfd)
    assert guardian.finish(reason="repeat", interrupt=True) == proof
    with pytest.raises(guardian_module.GuardianError):
        guardian.prepare()
    assert operations == calls == [("close", entry.pidfd)]
    assert proof["status"] == "INCOMPLETE" and proof.get("completion_receipt") is None
    assert [item["disposition"] for item in proof["pidfd_release"]] == ["CLOSE_UNKNOWN", "RETAINED"]
    assert proof["pidfd_release"][0]["errno"] == errno.EIO
    assert kernel.handles[entry.pidfd].pid == 999 and not kernel.handles[entry.pidfd].exited


def completion_epoch(module, *, callback_mutation=False, fault=None):
    kernel, durable = LifecycleKernel(), []
    def journal(record):
        if fault == "mutate-before-persist" and record["event"] == "retained":
            record["identity"]["pid"] = 999
        durable.append(json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n")
        if record["event"] == "cleanup-provisional" and fault in {"provisional-late", "provisional-error"}:
            if fault.endswith("late"):
                kernel.clock = 0.3
            else:
                raise OSError(errno.ENOSPC, "provisional bytes persisted but callback failed")
        if record["event"] in {"cleanup-finalization", "failure"} and fault in {"final-late", "final-error", "final-and-failure-error"}:
            if record["event"] == "cleanup-finalization" or fault == "final-and-failure-error":
                if fault.endswith("late"):
                    kernel.clock = 0.3
                else:
                    raise OSError(errno.ENOSPC, "persisted finalization without acknowledgement")
        if callback_mutation:
            record["sequence"] = True
            record["time"] = float("inf")
            if "identity" in record:
                record["identity"]["pid"] = 999
            if "processes" in record:
                record["processes"].clear()
    guardian = module.ProcessGuardian(limits=module.GuardLimits(cleanup_seconds=0.2, poll_seconds=0.05),
                                      journal=journal, _backend=kernel)
    guardian.prepare()
    kernel.add()
    guardian.retain_runner(SimpleNamespace(pid=101, returncode=None))
    proof = guardian.finish(reason="normal", interrupt=False)
    receipt = proof.get("completion_receipt")
    raw_receipt = None if receipt is None else json.dumps(receipt, sort_keys=True).encode()
    return kernel, guardian, proof, b"".join(durable), raw_receipt


def replay(module, journal, receipt):
    method = getattr(module, "replay_completion", None)
    assert callable(method), "bounded fixed-byte completion replay is absent"
    return method(journal, receipt)


def rebind_records(records, receipt):
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    receipt = json.loads(receipt)
    receipt["records_sha256"] = hashlib.sha256(canonical).hexdigest()
    return b"".join(json.dumps(record, sort_keys=True).encode() + b"\n" for record in records), json.dumps(receipt).encode()


def test_completion_receipt_replays_fixed_bytes_but_journal_alone_is_unsealed(guardian_module):
    _, _, proof, journal, receipt = completion_epoch(guardian_module)
    assert isinstance(proof.get("completion_receipt"), dict), "clean return has no post-callback acknowledgement"
    assert replay(guardian_module, journal, receipt)["status"] == "CLEAN"
    assert replay(guardian_module, journal, None)["status"] == "INCOMPLETE"
    assert all(record.get("status") != "CLEAN" for record in map(json.loads, journal.splitlines()))


def test_callback_and_return_mutations_do_not_change_internal_seal_or_reset(guardian_module):
    _, guardian, proof, journal, receipt = completion_epoch(guardian_module, callback_mutation=True)
    assert proof["status"] == "CLEAN", "callback mutated the guardian's retained identity or canonical ledger"
    assert proof["processes"][0]["identity"]["pid"] == 101
    proof["status"] = "INCOMPLETE"
    proof["processes"].clear()
    proof["completion_receipt"]["records_sha256"] = "0" * 64
    assert guardian.finish(reason="repeat", interrupt=True)["status"] == "CLEAN"
    assert replay(guardian_module, journal, receipt)["status"] == "CLEAN"
    guardian.prepare()


@pytest.mark.parametrize("suffix", ["failure", "partial", "complete-without-newline", "truncated-prefix"])
def test_receipt_never_discards_same_epoch_suffix_or_truncation(guardian_module, suffix):
    _, _, _, journal, receipt = completion_epoch(guardian_module)
    records = [json.loads(line) for line in journal.splitlines()]
    if suffix == "failure":
        journal += json.dumps({"sequence": records[-1]["sequence"] + 1, "time": records[-1]["time"],
                               "event": "failure", "code": "IO_FAILED", "errno": 5}).encode() + b"\n"
    elif suffix == "partial":
        journal += b'{"sequence":'
    elif suffix == "complete-without-newline":
        journal = journal[:-1]
    else:
        journal = b"\n".join(journal.splitlines()[:-1]) + b"\n"
    assert replay(guardian_module, journal, receipt)["status"] == "INCOMPLETE"


@pytest.mark.parametrize("change", ["boolean-sequence", "boolean-time", "gap", "backwards-time", "deadline", "ack-late", "ack-earlier", "unknown-receipt", "release-missing", "release-unknown", "restore-missing", "identity", "physical", "unknown-event"])
def test_recomputed_digest_does_not_override_invalid_completion_proof(guardian_module, change):
    _, _, _, journal, receipt = completion_epoch(guardian_module)
    records = [json.loads(line) for line in journal.splitlines()]
    seal = json.loads(receipt)
    terminal = records[-1]
    if change == "boolean-sequence":
        records[0]["sequence"] = True
    elif change == "boolean-time":
        records[0]["time"] = False
    elif change == "gap":
        records[1]["sequence"] += 1
    elif change == "backwards-time":
        records[0]["time"], records[1]["time"] = 0.02, 0.01
    elif change == "deadline":
        terminal["deadline"] = 0.1
    elif change == "ack-late":
        seal["acknowledged_at"] = seal["deadline"]
    elif change == "ack-earlier":
        seal["acknowledged_at"] = -1
    elif change == "unknown-receipt":
        seal["foreign"] = True
    elif change == "release-missing":
        terminal["pidfd_release"].clear()
    elif change == "release-unknown":
        terminal["pidfd_release"][0]["disposition"] = "CLOSE_UNKNOWN"
    elif change == "restore-missing":
        terminal["cancellation_restore"]["operations"].pop()
    elif change == "identity":
        terminal["pidfd_release"][0]["identity"]["pid"] = 999
    elif change == "physical":
        terminal["final_echild"] = False
    else:
        records[1]["event"] = "foreign"
    journal, receipt = rebind_records(records, json.dumps(seal).encode())
    assert replay(guardian_module, journal, receipt)["status"] == "INCOMPLETE"


@pytest.mark.parametrize("malformed", ["receipt-duplicate", "nested-duplicate", "journal-duplicate", "nonfinite", "deep", "record-count", "record-size", "total-size"])
def test_replay_strict_json_and_finite_bounds(guardian_module, malformed):
    _, _, _, journal, receipt = completion_epoch(guardian_module)
    if malformed == "receipt-duplicate":
        receipt = receipt[:-1] + b', "status":"CLEAN"}'
    elif malformed == "nested-duplicate":
        journal = journal.replace(b'"pid":101', b'"pid":101,"pid":101', 1)
    elif malformed == "journal-duplicate":
        journal = journal.replace(b'"sequence":1', b'"sequence":1,"sequence":1', 1)
    elif malformed == "nonfinite":
        receipt = receipt.replace(b'"acknowledged_at": 0.0', b'"acknowledged_at": NaN')
    elif malformed == "deep":
        journal = b'{"sequence":1,"time":0,"event":"prepared","deep":' + b'[' * 33 + b'0' + b']' * 33 + b'}\n'
    elif malformed == "record-count":
        journal = b'{}\n' * 65537
    elif malformed == "record-size":
        journal = b'{"padding":"' + b'x' * (16 * 1024 * 1024) + b'"}\n'
    else:
        journal = b'x' * (64 * 1024 * 1024 + 1)
    assert replay(guardian_module, journal, receipt)["status"] == "INCOMPLETE"


@pytest.mark.parametrize("field", ["retained-sequence", "final-boolean-proof", "final-boolean-deadline", "duplicate-finalization", "release-overlap", "restore-before-close", "receipt-boolean-time", "receipt-boolean-schema", "receipt-boolean-range"])
def test_replay_rejects_typed_and_release_order_inconsistency_with_matching_digest(guardian_module, field):
    _, _, _, journal, receipt = completion_epoch(guardian_module)
    records = [json.loads(line) for line in journal.splitlines()]
    seal = json.loads(receipt)
    final = records[-1]
    if field == "retained-sequence":
        next(record for record in records if record["event"] == "retained")["entry_sequence"] = True
    elif field == "final-boolean-proof":
        final["final_echild"] = 1
    elif field == "final-boolean-deadline":
        seal["deadline"] = 1
        next(record for record in records if record["event"] == "cleanup-entered")["deadline"] = 1
        final["deadline"] = True
    elif field == "duplicate-finalization":
        records.append(dict(final, sequence=final["sequence"] + 1))
        seal["epoch_last_sequence"] += 1
    elif field == "release-overlap":
        # One release cannot overlap cancellation restoration even if both
        # local outcome times fit below the deadline.
        final["pidfd_release"][0]["completed_at"] = 0.1
        final["time"] = seal["acknowledged_at"] = 0.15
    elif field == "restore-before-close":
        final["pidfd_release"][0]["completed_at"] = 0.05
        final["time"] = seal["acknowledged_at"] = 0.1
    elif field == "receipt-boolean-time":
        seal["acknowledged_at"] = False
    elif field == "receipt-boolean-schema":
        seal["schema_version"] = True
    else:
        seal["epoch_first_sequence"] = True
    journal, receipt = rebind_records(records, json.dumps(seal).encode())
    assert replay(guardian_module, journal, receipt)["status"] == "INCOMPLETE"


def test_fallible_result_serialization_precedes_last_deadline_check(guardian_module, monkeypatch):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    real_canonical = guardian_module._canonical_bytes
    def late(value):
        raw = real_canonical(value)
        if type(value) is dict and value.get("status") == "CLEAN" and "completion_receipt" in value:
            kernel.clock = 0.3
        return raw
    monkeypatch.setattr(guardian_module, "_canonical_bytes", late)
    proof = guardian.finish(reason="normal", interrupt=False)
    assert proof["status"] == "INCOMPLETE", "serialized result work ran after the last deadline check"
    assert proof.get("completion_receipt") is None
    with pytest.raises(guardian_module.GuardianError):
        guardian.prepare()


def test_failed_result_mutation_cannot_fabricate_an_internal_completion_receipt(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    kernel.ignore_signals = True
    proof = guardian.finish(reason="cancel", interrupt=True)
    proof.update(status="CLEAN", failures=[], completion_receipt={"status": "CLEAN"})
    with pytest.raises(guardian_module.GuardianError):
        guardian.prepare()
    assert guardian.finish(reason="repeat", interrupt=False)["status"] == "INCOMPLETE"


@pytest.mark.parametrize("fault", ["provisional-error", "provisional-late", "final-error", "final-late", "final-and-failure-error"])
def test_serialized_failed_or_late_callbacks_are_unsealed_even_after_persistence(guardian_module, fault):
    kernel, guardian, proof, journal, receipt = completion_epoch(guardian_module, fault=fault)
    assert proof["status"] == "INCOMPLETE" and receipt is None
    assert proof["final_echild"] is True and proof["all_pidfds_exited"] is True
    assert replay(guardian_module, journal, receipt)["status"] == "INCOMPLETE"
    assert bool(kernel.closed) is (not fault.startswith("provisional"))
    with pytest.raises(guardian_module.GuardianError):
        guardian.prepare()


def test_callback_mutating_persisted_bytes_cannot_change_canonical_receipt_digest(guardian_module):
    _, _, proof, journal, receipt = completion_epoch(guardian_module, fault="mutate-before-persist")
    assert proof["status"] == "CLEAN" and proof["processes"][0]["identity"]["pid"] == 101
    assert replay(guardian_module, journal, receipt)["status"] == "INCOMPLETE"


def test_partial_cancellation_restore_outcomes_are_truthful_and_unsealed(guardian_module):
    kernel, guardian, _, _ = lifecycle(guardian_module)
    def partial(release_step):
        for name in ("wakeup-fd", "sigint-handler", "sigterm-handler", "wake-read-close", "wake-write-close"):
            def action():
                if name == "sigterm-handler":
                    raise OSError(errno.EIO, "partial restoration")
            release_step(name, action)
    kernel.restore_cancellation = partial
    proof = guardian.finish(reason="normal", interrupt=False)
    assert proof["status"] == "INCOMPLETE" and proof["completion_receipt"] is None
    restore = proof["cancellation_restore"]
    assert restore["state"] == "UNKNOWN" and restore["errno"] == errno.EIO
    assert [operation["state"] for operation in restore["operations"]] == ["SUCCEEDED", "SUCCEEDED", "UNKNOWN", "UNATTEMPTED", "UNATTEMPTED"]
    assert [operation["errno"] for operation in restore["operations"]] == [None, None, errno.EIO, None, None]
    assert all(release["disposition"] == "CLOSED" for release in proof["pidfd_release"])


def test_clean_epochs_share_journal_only_through_explicit_opening_boundaries(guardian_module):
    kernel, guardian, events, _ = lifecycle(guardian_module)
    first = guardian.finish(reason="normal", interrupt=False)
    first_receipt = json.dumps(first["completion_receipt"]).encode()
    guardian.prepare()
    kernel.add(pid=201)
    guardian.retain_runner(SimpleNamespace(pid=201, returncode=None))
    second = guardian.finish(reason="normal", interrupt=False)
    journal = b"".join(json.dumps(event).encode() + b"\n" for event in events)
    assert replay(guardian_module, journal, first_receipt)["status"] == "CLEAN"
    assert replay(guardian_module, journal, json.dumps(second["completion_receipt"]).encode())["status"] == "CLEAN"


@pytest.mark.parametrize("field", ["exit-sequence-boolean", "reap-identity", "session-boolean", "raw-stat", "raw-fdinfo", "foreign-boot", "runner-exit"])
def test_replay_binds_typed_identity_observations_even_when_digest_is_recomputed(guardian_module, field):
    _, _, _, journal, receipt = completion_epoch(guardian_module)
    records = [json.loads(line) for line in journal.splitlines()]
    if field == "exit-sequence-boolean":
        next(record for record in records if record["event"] == "pidfd-exited")["entry_sequence"] = True
    elif field == "reap-identity":
        next(record for record in records if record["event"] == "reaped")["identity"]["pid"] = 999
    else:
        for record in records:
            if record["event"] == "retained" or record["event"] in {"cleanup-provisional", "cleanup-finalization"}:
                process = record if record["event"] == "retained" else record["processes"][0]
                if field == "session-boolean":
                    process["session_id"] = True
                elif field == "raw-stat":
                    process["raw_stat"] = [stat_text(ticks=9999)] * 2
                elif field == "raw-fdinfo":
                    process["raw_fdinfo"] = ["Pid:\t999\n"] * 2
                elif field == "foreign-boot":
                    process["identity"]["host_boot_id"] = "00000000-0000-0000-0000-000000000000"
                else:
                    if record["event"] != "retained":
                        record["runner_exit"] = 0
    journal, receipt = rebind_records(records, receipt)
    assert replay(guardian_module, journal, receipt)["status"] == "INCOMPLETE"


@pytest.mark.parametrize("bound", ["depth", "tokens", "record-bytes", "journal-bytes", "record-count"])
def test_replay_enforces_all_input_bounds_before_json_decoder(guardian_module, monkeypatch, bound):
    if bound == "depth":
        raw = b'[' * 33 + b'0' + b']' * 33 + b'\n'
    elif bound == "tokens":
        raw = b'[' + b'0,' * 250000 + b'0]\n'
    elif bound == "record-bytes":
        raw = b'x' * (16 * 1024 * 1024 + 1) + b'\n'
    elif bound == "journal-bytes":
        raw = b'x' * (64 * 1024 * 1024 + 1)
    else:
        raw = b'{}\n' * 65537
    def forbidden(*args, **kwargs):
        pytest.fail("JSON decoder ran before the replay input bound was enforced")
    monkeypatch.setattr(guardian_module.json, "loads", forbidden)
    proof = replay(guardian_module, raw, b"{}")
    assert proof["status"] == "INCOMPLETE" and proof["failures"]
