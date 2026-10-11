# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Bounded, sole-reaper Linux lifecycle management through retained pidfds.

Run in a dedicated single-threaded process. This is ownership management for
cooperative descendants, not a sandbox or containment after controller death.
Only a sealed kernel ECHILD drain permits another epoch or handle release.
"""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
import errno
import math
import os
from pathlib import Path
import re
import select
import signal
import sys
import time
from typing import Callable
from uuid import UUID


WAIT_WALL = 0x40000000
_STAT_LIMIT = 64 * 1024
_SA_NOCLDWAIT = 2


class _SigAction(ctypes.Structure):
    # Linux x86-64 libc ABI, deliberately refused on other architectures.
    _fields_ = [("handler", ctypes.c_void_p), ("mask", ctypes.c_ulong * 16),
                ("flags", ctypes.c_int), ("restorer", ctypes.c_void_p)]


class GuardianError(Exception):
    """Terminal identity/resource/recording failure, with the original errno."""

    def __init__(self, code: str, detail: str = "", *, errno: int | None = None):
        super().__init__(detail)
        self.code, self.detail, self.errno = code, detail, errno


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    start_ticks: int
    host_boot_id: str

    def __post_init__(self):
        if (type(self.pid) is not int or self.pid <= 0 or
                type(self.start_ticks) is not int or self.start_ticks <= 0):
            raise GuardianError("OWNERSHIP_UNKNOWN", "invalid process identity")
        _boot_id(self.host_boot_id)


@dataclass(frozen=True)
class GuardLimits:
    cleanup_seconds: float = 30.0
    poll_seconds: float = 0.05
    max_live_processes: int = 128
    max_retained_processes: int = 4096
    max_tasks_per_process: int = 128
    max_proc_reads_per_tick: int = 4096


    def __post_init__(self):
        for name in ("cleanup_seconds", "poll_seconds"):
            value = getattr(self, name)
            try:
                if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                    raise GuardianError("OWNERSHIP_UNKNOWN", "invalid guardian time bound")
            except OverflowError as exc:
                raise GuardianError("OWNERSHIP_UNKNOWN", "guardian time bound exceeds numeric range") from exc
        for name in ("max_live_processes", "max_retained_processes",
                     "max_tasks_per_process", "max_proc_reads_per_tick"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise GuardianError("OWNERSHIP_UNKNOWN", "invalid guardian resource bound")
        if self.max_live_processes > self.max_retained_processes:
            raise GuardianError("OWNERSHIP_UNKNOWN", "live bound exceeds retention bound")


@dataclass(frozen=True)
class ProcessStat:
    pid: int
    comm: str
    state: str
    ppid: int
    process_group: int
    session_id: int
    start_ticks: int


def _boot_id(value: str) -> str:
    try:
        if type(value) is not str or str(UUID(value)) != value:
            raise ValueError("noncanonical boot identity")
    except (ValueError, AttributeError) as exc:
        raise GuardianError("OWNERSHIP_UNKNOWN", "invalid host boot identity") from exc
    return value


def parse_process_stat(raw: str) -> ProcessStat:
    """Parse Linux stat without splitting spaces/parentheses inside comm."""
    try:
        if type(raw) is not str or len(raw) > _STAT_LIMIT or "\x00" in raw:
            raise ValueError("invalid stat bytes")
        head, separator, rest = raw.partition(" (")
        end = rest.rfind(") ")
        if not separator or end < 0 or not re.fullmatch(r"[1-9][0-9]*", head):
            raise ValueError("invalid stat header")
        fields = rest[end + 2:].split()
        if len(fields) < 20 or fields[0] not in {"R", "S", "D", "Z", "T", "t", "X", "x", "K", "W", "P", "I"}:
            raise ValueError("invalid stat fields")
        if any(re.fullmatch(r"-?[0-9]+", value) is None for value in fields[1:]):
            raise ValueError("nonnumeric stat field")
        ppid, group, session, ticks = (int(fields[i]) for i in (1, 2, 3, 19))
        if ppid < 0 or group <= 0 or session <= 0 or ticks <= 0:
            raise ValueError("invalid stat identity")
        return ProcessStat(int(head), rest[:end], fields[0], ppid, group, session, ticks)
    except (ValueError, IndexError) as exc:
        raise GuardianError("OWNERSHIP_UNKNOWN", "malformed process stat") from exc


def _fdinfo_pid(raw: str) -> int:
    if type(raw) is not str or len(raw) > _STAT_LIMIT:
        raise GuardianError("OWNERSHIP_UNKNOWN", "unreadable pidfd fdinfo")
    values = {}
    for line in raw.splitlines():
        key, separator, value = line.partition(":")
        if key in {"Pid", "NSpid"}:
            if not separator or key in values:
                raise GuardianError("OWNERSHIP_UNKNOWN", "ambiguous pidfd fdinfo")
            values[key] = value.strip()
    pid = values.get("Pid", "")
    if not re.fullmatch(r"[1-9][0-9]*", pid) or values.get("NSpid") != pid:
        raise GuardianError("OWNERSHIP_UNKNOWN", "unknown pidfd process/namespace identity")
    return int(pid)


def check_linux_api_availability() -> None:
    """Inspect Python API availability without signaling, waiting or prctl.

    Kernel support and the __WALL wait mask still need isolated lifecycle
    controls. The presence of a Python wrapper is not kernel qualification.
    """
    names = ("pidfd_open", "waitid", "P_PIDFD", "P_ALL", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT",
             "CLD_EXITED", "CLD_KILLED", "CLD_DUMPED", "pipe2")
    if (not sys.platform.startswith("linux") or any(not hasattr(os, name) for name in names)
            or any(not callable(getattr(os, name, None)) for name in ("pidfd_open", "waitid", "pipe2"))
            or not callable(getattr(signal, "pidfd_send_signal", None)) or not hasattr(select, "poll")):
        raise GuardianError("OWNERSHIP_UNKNOWN", "required Linux process APIs are unavailable")


class _LinuxBackend:
    """The production backend; no numeric signal or global procfs enumeration."""

    @property
    def controller_pid(self):
        return os.getpid()

    check_available = staticmethod(check_linux_api_availability)
    monotonic = staticmethod(time.monotonic)

    def host_boot_id(self):
        return _boot_id(Path("/proc/sys/kernel/random/boot_id").read_text().strip())

    def open_pidfd(self, pid):
        return os.pidfd_open(pid, 0)

    def close_pidfd(self, fd):
        os.close(fd)

    def pidfd_exited(self, fd):
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        events = poller.poll(0)
        if any(mask & (select.POLLNVAL | select.POLLERR) for _, mask in events):
            raise OSError(errno.EBADF, "invalid retained pidfd")
        return any(mask & (select.POLLIN | select.POLLHUP) for _, mask in events)

    def _read_proc(self, path):
        try:
            with open(path, "r", encoding="utf-8", errors="strict") as stream:
                raw = stream.read(_STAT_LIMIT + 1)
        except UnicodeError as exc:
            raise GuardianError("OWNERSHIP_UNKNOWN", "procfs observation is undecodable") from exc
        if len(raw) > _STAT_LIMIT:
            raise GuardianError("OWNERSHIP_UNKNOWN", "procfs observation exceeds read bound")
        return raw

    def read_stat(self, pid):
        return self._read_proc(f"/proc/{pid}/stat")

    def read_fdinfo(self, fd):
        return self._read_proc(f"/proc/self/fdinfo/{fd}")

    def signal_pidfd(self, fd, sig):
        signal.pidfd_send_signal(fd, sig, None, 0)

    def tasks(self, pid, maximum):
        tasks = []
        with os.scandir(f"/proc/{pid}/task") as entries:
            for entry in entries:
                if not re.fullmatch(r"[1-9][0-9]*", entry.name):
                    raise GuardianError("OWNERSHIP_UNKNOWN", "invalid process task entry")
                tasks.append(int(entry.name))
                if len(tasks) > maximum:
                    break
        return sorted(tasks)

    def read_children(self, pid, tid):
        return self._read_proc(f"/proc/{pid}/task/{tid}/children")

    def read_mountinfo(self):
        return self._read_proc("/proc/self/mountinfo")

    waitid = staticmethod(os.waitid if hasattr(os, "waitid") else None)

    def _libc(self):
        if (os.uname().machine != "x86_64" or ctypes.sizeof(ctypes.c_void_p) != 8
                or ctypes.sizeof(_SigAction) != 152):
            raise GuardianError("OWNERSHIP_UNKNOWN", "unsupported sigaction ABI")
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.sigaction.argtypes = [ctypes.c_int, ctypes.POINTER(_SigAction), ctypes.POINTER(_SigAction)]
            libc.sigaction.restype = ctypes.c_int
            libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
            libc.prctl.restype = ctypes.c_int
        except (AttributeError, OSError) as exc:
            raise GuardianError("OWNERSHIP_UNKNOWN", "required mapped libc API unavailable",
                                errno=getattr(exc, "errno", None)) from exc
        return libc

    def establish_sigchld(self):
        libc = self._libc()
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        action, actual = _SigAction(), _SigAction()
        if libc.sigaction(signal.SIGCHLD, ctypes.byref(action), None) != 0:
            raise OSError(ctypes.get_errno(), "sigaction set failed")
        if libc.sigaction(signal.SIGCHLD, None, ctypes.byref(actual)) != 0:
            raise OSError(ctypes.get_errno(), "sigaction readback failed")
        return {"default": actual.handler is None, "flags": actual.flags}

    def enable_subreaper(self):
        libc = self._libc()
        if libc.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "subreaper set failed")
        actual = ctypes.c_int()
        pointer = ctypes.cast(ctypes.byref(actual), ctypes.c_void_p).value
        if libc.prctl(37, pointer, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "subreaper readback failed")
        return actual.value == 1

    def install_cancellation(self, handler):
        self._wake_read, self._wake_write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        self._old_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        self._old_wakeup = None
        try:
            self._old_wakeup = signal.set_wakeup_fd(self._wake_write, warn_on_full_buffer=False)
            for sig in self._old_handlers:
                signal.signal(sig, handler)
        except (ValueError, OSError):
            if self._old_wakeup is not None:
                signal.set_wakeup_fd(self._old_wakeup)
                for sig, previous in self._old_handlers.items():
                    signal.signal(sig, previous)
            os.close(self._wake_read)
            os.close(self._wake_write)
            raise

    def pause(self, seconds):
        poller = select.poll()
        poller.register(self._wake_read, select.POLLIN)
        poller.poll(max(0, math.ceil(seconds * 1000)))
        try:
            os.read(self._wake_read, _STAT_LIMIT)
        except BlockingIOError:
            pass

    def restore_cancellation(self):
        signal.set_wakeup_fd(self._old_wakeup)
        for sig, handler in self._old_handlers.items():
            signal.signal(sig, handler)
        os.close(self._wake_read)
        os.close(self._wake_write)


@dataclass(frozen=True, eq=False)
class _RetainedProcess:
    sequence: int
    identity: ProcessIdentity
    pidfd: int
    role: str
    ownership_basis: str
    parent_sequence: int | None
    raw_stat: tuple[str, str]
    raw_fdinfo: tuple[str, str]


class ProcessGuardian:
    """Own one epoch in a dedicated controller, including adopted children.

    Call prepare before spawning, retain the Popen immediately, then observe
    and finish. Never poll/wait/kill that Popen through a second owner. Private
    backends support deterministic faults, never replacement via JSON or env.
    """

    def __init__(self, *, limits: GuardLimits, journal: Callable[[dict], None], _backend=None):
        if not isinstance(limits, GuardLimits) or not callable(journal):
            raise GuardianError("OWNERSHIP_UNKNOWN", "invalid guardian configuration")
        self._limits, self._journal = limits, journal
        self._backend = _LinuxBackend() if _backend is None else _backend
        self._entries: list[_RetainedProcess] = []
        self._event_sequence = 0
        self._runner_entry = None
        self._host_boot_id = None
        self.projection_ambiguous = False
        self._prepared = False
        self._cancelled = False
        self._cancel_signal = None
        self._runner_process = None
        self._failures = []
        self._wait_status = {}
        self._reaped = set()
        self._signaled = set()
        self._exit_observed = set()
        self._closed = set()
        self._result = None
        self._tick_reads = None
        self._scans = 0
        self._adoptions = 0
        self._last_echild = False
        self._subreaper = None
        self._mountinfo_before = None
        self._controller_identity = None
        self._cleanup_deadline = None
        self._echild_announced = False

    def check_available(self) -> None:
        self._backend.check_available()

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def _cancel(self, sig, frame):
        # Python executes this in its main thread. No exceptions, journal I/O
        # or ownership mutations occur asynchronously; wakeup_fd wakes pause.
        self._cancelled = True
        self._cancel_signal = sig

    def _failure(self, exc):
        if not isinstance(exc, GuardianError):
            exc = GuardianError("OWNERSHIP_UNKNOWN", str(exc), errno=getattr(exc, "errno", None))
        record = {"code": exc.code, "detail": exc.detail, "errno": exc.errno}
        if record not in self._failures:
            self._failures.append(record)
            try:
                self._emit("failure", **record)
            except GuardianError as journal_error:
                secondary = {"code": journal_error.code, "detail": journal_error.detail,
                             "errno": journal_error.errno}
                if secondary not in self._failures:
                    self._failures.append(secondary)
        return exc

    def _require_prepared(self):
        if not self._prepared or self._result is not None:
            raise GuardianError("OWNERSHIP_UNKNOWN", "no active prepared epoch")

    def _proc_read(self, method, *arguments):
        self._check_deadline()
        if self._tick_reads is not None:
            if self._tick_reads >= self._limits.max_proc_reads_per_tick:
                raise GuardianError("OWNERSHIP_UNKNOWN", "process scan read limit exceeded")
            self._tick_reads += 1
        return method(*arguments)

    def _check_deadline(self):
        if self._cleanup_deadline is not None and self._backend.monotonic() >= self._cleanup_deadline:
            raise GuardianError("CLEANUP_INCOMPLETE", "cleanup deadline exhausted")

    def _wait(self, kind, identifier, *, observe=True):
        options = os.WEXITED | os.WNOHANG | WAIT_WALL
        if observe:
            options |= os.WNOWAIT
        try:
            return self._backend.waitid(kind, identifier, options)
        except OSError as exc:
            if exc.errno == errno.ECHILD:
                raise
            raise GuardianError("OWNERSHIP_UNKNOWN", "child wait API failed", errno=exc.errno) from exc

    def prepare(self) -> None:
        if self._prepared and (self._result is None or self._result["status"] != "CLEAN"):
            raise GuardianError("OWNERSHIP_UNKNOWN", "previous epoch is active or quarantined")
        if self._entries and (self._result is None or self._result["status"] != "CLEAN"
                              or self._closed != {entry.sequence for entry in self._entries}):
            raise GuardianError("OWNERSHIP_UNKNOWN", "previous identity ledger is not sealed and released")
        if self._cancelled or self._failures:
            raise GuardianError("OWNERSHIP_UNKNOWN", "failed or cancelled controller cannot start an epoch")
        try:
            self.check_available()
            if self._limits.cleanup_seconds > 30:
                raise GuardianError("OWNERSHIP_UNKNOWN", "cleanup budget exceeds thirty seconds")
            pid = self._backend.controller_pid
            if self._backend.tasks(pid, self._limits.max_tasks_per_process) != [pid]:
                raise GuardianError("OWNERSHIP_UNKNOWN", "controller is not single threaded")
            own = parse_process_stat(self._backend.read_stat(pid))
            if own.pid != pid:
                raise GuardianError("OWNERSHIP_UNKNOWN", "own procfs identity mismatch")
            boot = _boot_id(self._backend.host_boot_id())
            # No empty procfs list or WNOHANG None substitutes for ECHILD.
            try:
                self._wait(os.P_ALL, 0)
            except OSError as exc:
                if exc.errno != errno.ECHILD:
                    raise
            else:
                raise GuardianError("OWNERSHIP_UNKNOWN", "controller has existing or unverified children")
            disposition = self._backend.establish_sigchld()
            if disposition.get("default") is not True or disposition.get("flags", _SA_NOCLDWAIT) & _SA_NOCLDWAIT:
                raise GuardianError("OWNERSHIP_UNKNOWN", "SIGCHLD is not explicitly waitable")
            if self._backend.enable_subreaper() is not True:
                raise GuardianError("OWNERSHIP_UNKNOWN", "subreaper readback failed")
            mountinfo = self._backend.read_mountinfo()
            self._backend.install_cancellation(self._cancel)
            self._entries, self._runner_entry, self._runner_process = [], None, None
            self._wait_status, self._reaped, self._signaled = {}, set(), set()
            self._exit_observed, self._closed = set(), set()
            self._result, self._last_echild = None, False
            self._cleanup_deadline, self._echild_announced = None, False
            self._scans, self._adoptions = 0, 0
            self.projection_ambiguous = False
            self._host_boot_id, self._controller_identity = boot, (pid, own.start_ticks)
            self._mountinfo_before, self._subreaper, self._prepared = mountinfo, True, True
            self._emit("prepared", controller_identity={"pid": pid, "start_ticks": own.start_ticks,
                       "host_boot_id": boot}, sigchld=disposition, subreaper_readback=True,
                       initial_echild=True, raw_mountinfo=mountinfo)
        except (GuardianError, OSError, ValueError) as exc:
            raise self._failure(exc)

    def observe(self) -> list[dict]:
        self._require_prepared()
        try:
            self._tick()
            return self._observations()
        except (GuardianError, OSError) as exc:
            raise self._failure(exc)

    def runner_exit(self) -> int | None:
        self._require_prepared()
        entry = self._runner_entry
        if entry is None:
            return None
        try:
            if entry.sequence not in self._wait_status:
                result = self._wait(os.P_PIDFD, entry.pidfd)
                if result is not None and result.si_pid:
                    self._record_wait(entry, result)
            status = self._wait_status.get(entry.sequence)
            return None if status is None else status["exit_code"]
        except (GuardianError, OSError) as exc:
            raise self._failure(exc)

    def finish(self, *, reason: str, interrupt: bool) -> dict:
        if self._result is not None:
            return self._result
        self._require_prepared()
        deadline = self._backend.monotonic() + self._limits.cleanup_seconds
        self._cleanup_deadline = deadline
        try:
            self._emit("cleanup-entered", reason=reason, interrupt=interrupt,
                       cancelled=self._cancelled, cancellation_signal=self._cancel_signal, deadline=deadline)
        except GuardianError as exc:
            self._failure(exc)
        # Runner always precedes descendant signals, including intentional
        # interruption. A concurrently exiting runner is handled by its fd.
        if self._runner_entry is not None:
            self._kill_once(self._runner_entry)
        all_exited, unresolved = False, len(self._entries)
        while True:
            try:
                self._tick()
            except (GuardianError, OSError) as exc:
                self._failure(exc)
            for entry in tuple(self._entries):
                self._kill_once(entry)
            # Every signal batch can cause adoption, including a late fork.
            try:
                self._tick()
            except (GuardianError, OSError) as exc:
                self._failure(exc)
            all_exited, unresolved = self._exit_proof()
            if self._backend.monotonic() >= deadline:
                self._failure(GuardianError("CLEANUP_INCOMPLETE", "cleanup deadline exhausted"))
                break
            if self._last_echild and all_exited:
                break
            remaining = deadline - self._backend.monotonic()
            if remaining <= 0:
                self._failure(GuardianError("CLEANUP_INCOMPLETE", "cleanup deadline exhausted"))
                break
            try:
                self._backend.pause(min(self._limits.poll_seconds, remaining))
            except OSError as exc:
                self._failure(exc)
                break
        mountinfo_after = None
        try:
            mountinfo_after = self._backend.read_mountinfo()
        except (GuardianError, OSError) as exc:
            self._failure(exc)
        result = {"status": "CLEAN" if not self._failures and self._last_echild and all_exited else "INCOMPLETE",
                  "subreaper_readback": self._subreaper, "scans": self._scans, "adoptions": self._adoptions,
                  "final_echild": self._last_echild, "unresolved_live": unresolved,
                  "all_pidfds_exited": all_exited, "mountinfo_before": self._mountinfo_before,
                  "mountinfo_after": mountinfo_after, "failures": self._failures.copy(),
                  "processes": self._observations(poll=False), "runner_exit": self._runner_signed_exit()}
        try:
            self._emit("cleanup-terminal", **result)
        except GuardianError as exc:
            self._failure(exc)
            result["status"], result["failures"] = "INCOMPLETE", self._failures.copy()
        if self._backend.monotonic() >= deadline:
            self._failure(GuardianError("CLEANUP_INCOMPLETE", "cleanup deadline exhausted"))
            result["status"], result["failures"] = "INCOMPLETE", self._failures.copy()
        # Sealing must precede closure. Unknown cleanup keeps the handles and
        # cancellation handlers; this controller cannot start another epoch.
        if result["status"] == "CLEAN":
            try:
                for entry in self._entries:
                    self._backend.close_pidfd(entry.pidfd)
                    self._closed.add(entry.sequence)
                self._backend.restore_cancellation()
            except OSError as exc:
                self._failure(GuardianError("IO_FAILED", "guardian handle release failed", errno=exc.errno))
                result["status"], result["failures"] = "INCOMPLETE", self._failures.copy()
        self._result = result
        return result

    def _kill_once(self, entry):
        if entry.sequence in self._signaled:
            return
        try:
            self._check_deadline()
            self._signal_retained(entry, signal.SIGKILL)
            self._signaled.add(entry.sequence)
        except (GuardianError, OSError) as exc:
            self._failure(exc)
            self._signaled.add(entry.sequence)

    def _exit_proof(self):
        unresolved = 0
        for entry in self._entries:
            try:
                exited = self._pidfd_exited(entry.pidfd, entry=entry)
                if exited and entry.sequence not in self._exit_observed:
                    self._emit("pidfd-exited", entry_sequence=entry.sequence, identity=vars(entry.identity))
                    self._exit_observed.add(entry.sequence)
                if not exited:
                    unresolved += 1
            except GuardianError as exc:
                self._failure(exc)
                unresolved += 1
        return unresolved == 0, unresolved

    def _runner_signed_exit(self):
        status = None if self._runner_entry is None else self._wait_status.get(self._runner_entry.sequence)
        return None if status is None else status["exit_code"]

    def _observations(self, *, poll=True):
        observations = []
        for entry in self._entries:
            exited = (entry.sequence in self._exit_observed if not poll else
                      self._pidfd_exited(entry.pidfd, entry=entry))
            observations.append({"sequence": entry.sequence, "identity": vars(entry.identity).copy(),
                                 "role": entry.role, "ownership_basis": entry.ownership_basis,
                                 "parent_sequence": entry.parent_sequence,
                                 "session_id": parse_process_stat(entry.raw_stat[-1]).session_id,
                                 "raw_stat": list(entry.raw_stat), "raw_fdinfo": list(entry.raw_fdinfo),
                                 "exited": exited, "wait_status": (None if entry.sequence not in self._wait_status
                                     else self._wait_status[entry.sequence].copy())})
        return observations

    def _tasks(self, pid):
        tasks = self._proc_read(self._backend.tasks, pid, self._limits.max_tasks_per_process)
        if (not tasks or len(tasks) > self._limits.max_tasks_per_process or len(set(tasks)) != len(tasks)
                or any(type(tid) is not int or tid <= 0 for tid in tasks)):
            raise GuardianError("OWNERSHIP_UNKNOWN", "process task limit or identity failed")
        return tasks

    def _scan(self):
        self._scans += 1
        controller = self._backend.controller_pid
        parents = [None] + list(self._entries)
        for parent in parents:
            pid = controller if parent is None else parent.identity.pid
            if parent is not None and not self._parent_live(parent):
                continue
            try:
                if parent is None:
                    own = parse_process_stat(self._proc_read(self._backend.read_stat, pid))
                    if (own.pid, own.start_ticks) != self._controller_identity:
                        raise GuardianError("OWNERSHIP_UNKNOWN", "controller procfs identity changed")
                tasks = self._tasks(pid)
                if parent is None and tasks != [controller]:
                    raise GuardianError("OWNERSHIP_UNKNOWN", "controller acquired another thread")
                for tid in tasks:
                    if parent is not None and not self._parent_live(parent):
                        break
                    raw = self._proc_read(self._backend.read_children, pid, tid)
                    if parent is not None and not self._parent_live(parent):
                        break
                    tokens = raw.split()
                    if len(tokens) > self._limits.max_retained_processes:
                        raise GuardianError("OWNERSHIP_UNKNOWN", "children hint limit exceeded")
                    for token in tokens:
                        if not re.fullmatch(r"[1-9][0-9]*", token):
                            raise GuardianError("OWNERSHIP_UNKNOWN", "malformed child discovery hint")
                        before = len(self._entries)
                        entry = self._retain_candidate(int(token), parent=parent)
                        if entry is not None and len(self._entries) != before and parent is None:
                            self._adoptions += 1
            except OSError as exc:
                if parent is not None and exc.errno in {errno.ENOENT, errno.ESRCH}:
                    if not self._parent_live(parent):
                        self._emit("defer-adoption", parent_sequence=parent.sequence, errno=exc.errno)
                        continue
                raise GuardianError("OWNERSHIP_UNKNOWN", "owned process discovery failed", errno=exc.errno) from exc

    def _record_wait(self, entry, result):
        if result.si_pid != entry.identity.pid:
            raise GuardianError("OWNERSHIP_UNKNOWN", "wait result does not bind retained identity")
        code, status = result.si_code, result.si_status
        if (type(status) is not int or code not in {os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED}
                or (code == os.CLD_EXITED and not 0 <= status <= 255)
                or (code != os.CLD_EXITED and not 0 < status < signal.NSIG)):
            raise GuardianError("OWNERSHIP_UNKNOWN", "invalid exited child wait status")
        signed = status if code == os.CLD_EXITED else -status
        value = {"code": code, "status": status, "exit_code": signed}
        previous = self._wait_status.get(entry.sequence)
        if previous is not None and previous != value:
            raise GuardianError("OWNERSHIP_UNKNOWN", "wait status changed before reap")
        if previous is None:
            self._wait_status[entry.sequence] = value
            self._emit("wait-observed", entry_sequence=entry.sequence, identity=vars(entry.identity), **value)

    def _tick(self):
        self._last_echild = False
        self._tick_reads = 0
        try:
            self._scan()
            for _ in range(self._limits.max_retained_processes + 1):
                self._check_deadline()
                try:
                    result = self._wait(os.P_ALL, 0)
                except OSError as exc:
                    if exc.errno != errno.ECHILD:
                        raise
                    self._last_echild = True
                    if not self._echild_announced:
                        self._emit("echild", final_candidate=True)
                        self._echild_announced = True
                    break
                if result is None or not result.si_pid:
                    break
                before = len(self._entries)
                entry = self._retain_candidate(result.si_pid)
                if entry is None:
                    raise GuardianError("OWNERSHIP_UNKNOWN", "waitable child could not be retained")
                if len(self._entries) != before:
                    self._adoptions += 1
                self._record_wait(entry, result)
                reaped = self._wait(os.P_PIDFD, entry.pidfd, observe=False)
                if reaped is None or not reaped.si_pid:
                    raise GuardianError("OWNERSHIP_UNKNOWN", "observed child was not reaped")
                self._record_wait(entry, reaped)
                if entry.sequence in self._reaped:
                    raise GuardianError("OWNERSHIP_UNKNOWN", "child reaped twice")
                self._reaped.add(entry.sequence)
                if entry is self._runner_entry:
                    self._runner_process.returncode = self._wait_status[entry.sequence]["exit_code"]
                self._emit("reaped", entry_sequence=entry.sequence, identity=vars(entry.identity),
                           **self._wait_status[entry.sequence])
                self._scan()
            else:
                raise GuardianError("OWNERSHIP_UNKNOWN", "child drain work bound exceeded")
        finally:
            self._tick_reads = None

    def _emit(self, event, **fields):
        self._event_sequence += 1
        record = {"sequence": self._event_sequence, "time": self._backend.monotonic(),
                  "event": event, **fields}
        try:
            self._journal(record)
        except Exception as exc:
            raise GuardianError("IO_FAILED", "ownership journal write failed", errno=getattr(exc, "errno", None)) from exc

    def _owned(self, entry):
        return any(item is entry for item in self._entries)

    def _pidfd_exited(self, fd, *, entry=None, pid_hint=None):
        """Keep liveness API failures typed, including recovery observations."""
        try:
            return self._backend.pidfd_exited(fd)
        except OSError as exc:
            self._emit("observation-failed", entry_sequence=None if entry is None else entry.sequence,
                       pid_hint=pid_hint, errno=exc.errno)
            raise GuardianError("OWNERSHIP_UNKNOWN", "pidfd liveness observation failed", errno=exc.errno) from exc

    def _parent_live(self, parent, read_fdinfo=None):
        if not self._owned(parent):
            raise GuardianError("OWNERSHIP_UNKNOWN", "parent handle is not retained")
        if read_fdinfo is None:
            read_fdinfo = lambda fd: self._proc_read(self._backend.read_fdinfo, fd)
        return (not self._pidfd_exited(parent.pidfd, entry=parent)
                and _fdinfo_pid(read_fdinfo(parent.pidfd)) == parent.identity.pid
                and not self._pidfd_exited(parent.pidfd, entry=parent))

    def retain_runner(self, process) -> ProcessIdentity:
        if self._runner_entry is not None:
            raise GuardianError("OWNERSHIP_UNKNOWN", "runner already retained")
        self._runner_process = process
        try:
            entry = self._acquire(process.pid, parent=None, runner=True)
            if entry is None:
                raise GuardianError("OWNERSHIP_UNKNOWN", "direct child disappeared before retention")
            self._runner_entry = entry
            return entry.identity
        except GuardianError as exc:
            if self._prepared:
                self._failure(exc)
            raise

    def _retain_candidate(self, pid, *, parent=None):
        # An unreaped retained zombie still has a positive fdinfo PID. A
        # reaped handle has Pid -1 and can never be reused for a replacement.
        for entry in self._entries:
            if entry.identity.pid == pid:
                try:
                    if _fdinfo_pid(self._proc_read(self._backend.read_fdinfo, entry.pidfd)) == pid:
                        return entry
                except GuardianError:
                    if not self._pidfd_exited(entry.pidfd, entry=entry):
                        raise
                except OSError as exc:
                    self._emit("observation-failed", entry_sequence=entry.sequence, errno=exc.errno)
                    raise GuardianError("OWNERSHIP_UNKNOWN", "retained fdinfo is unavailable", errno=exc.errno) from exc
        return self._acquire(pid, parent=parent, runner=False)

    def _acquire(self, pid, *, parent, runner):
        if type(pid) is not int or pid <= 0:
            raise GuardianError("OWNERSHIP_UNKNOWN", "invalid child hint")
        if len(self._entries) >= self._limits.max_retained_processes:
            raise GuardianError("OWNERSHIP_UNKNOWN", "retained process limit exceeded")
        live_count = sum(not self._pidfd_exited(e.pidfd, entry=e) for e in self._entries)
        if live_count >= self._limits.max_live_processes:
            raise GuardianError("OWNERSHIP_UNKNOWN", "live process limit exceeded")
        fd, retained = None, False
        proc_reads = 0
        def read(method, argument):
            nonlocal proc_reads
            if proc_reads >= self._limits.max_proc_reads_per_tick:
                raise GuardianError("OWNERSHIP_UNKNOWN", "process acquisition read limit exceeded")
            proc_reads += 1
            return self._proc_read(method, argument)
        def read_fdinfo(handle):
            return read(self._backend.read_fdinfo, handle)
        try:
            if parent is not None and not self._parent_live(parent, read_fdinfo):
                self._emit("defer-adoption", pid_hint=pid)
                return None
            fd = self._backend.open_pidfd(pid)
            first_fdinfo = read_fdinfo(fd)
            if _fdinfo_pid(first_fdinfo) != pid:
                raise GuardianError("OWNERSHIP_UNKNOWN", "pidfd does not bind child hint")
            initially_exited = self._pidfd_exited(fd, pid_hint=pid)
            first_raw = read(self._backend.read_stat, pid)
            first = parse_process_stat(first_raw)
            second_raw = read(self._backend.read_stat, pid)
            second = parse_process_stat(second_raw)
            finally_exited = self._pidfd_exited(fd, pid_hint=pid)
            second_fdinfo = read_fdinfo(fd)
            if _fdinfo_pid(second_fdinfo) != pid:
                raise GuardianError("OWNERSHIP_UNKNOWN", "pidfd identity changed during acquisition")
            if parent is not None and not self._parent_live(parent, read_fdinfo):
                self._emit("defer-adoption", pid_hint=pid)
                return None
            if ((first.pid, first.start_ticks, first.ppid, first.session_id) !=
                    (second.pid, second.start_ticks, second.ppid, second.session_id) or first.pid != pid):
                raise GuardianError("OWNERSHIP_UNKNOWN", "process identity changed during acquisition")
            expected_parent = self._backend.controller_pid if parent is None else parent.identity.pid
            if first.ppid != expected_parent:
                raise GuardianError("OWNERSHIP_UNKNOWN", "child parent is outside proven ownership")
            if runner and first.session_id != pid:
                raise GuardianError("OWNERSHIP_UNKNOWN", "runner session does not match runner PID")
            if initially_exited or finally_exited:
                if second.state != "Z" or first.ppid != self._backend.controller_pid:
                    self._emit("defer-adoption", pid_hint=pid)
                    return None
            if self._host_boot_id is None:
                self._host_boot_id = _boot_id(self._backend.host_boot_id())
            identity = ProcessIdentity(pid, first.start_ticks, self._host_boot_id)
            basis = "spawn-child" if runner else ("adopted-child" if parent is None else "observed-descendant")
            entry = _RetainedProcess(len(self._entries) + 1, identity, fd,
                                     "runner" if runner else "descendant", basis,
                                     parent.sequence if parent is not None else None,
                                     (first_raw, second_raw), (first_fdinfo, second_fdinfo))
            if any(old.identity.pid == pid for old in self._entries):
                self.projection_ambiguous = True
            self._entries.append(entry)
            retained = True  # A journal failure must not lose this owned handle.
            if runner:
                self._runner_entry = entry
            self._emit("retained", entry_sequence=entry.sequence, identity=vars(identity),
                       role=entry.role, ownership_basis=basis, parent_sequence=entry.parent_sequence,
                       raw_stat=list(entry.raw_stat), raw_fdinfo=list(entry.raw_fdinfo))
            return entry
        except OSError as exc:
            if (not runner and exc.errno in {errno.ENOENT, errno.ESRCH}
                    and (fd is None or self._pidfd_exited(fd, pid_hint=pid))):
                self._emit("transient-hint", pid_hint=pid, errno=exc.errno)
                return None
            self._emit("acquisition-failed", pid_hint=pid, errno=exc.errno)
            raise GuardianError("OWNERSHIP_UNKNOWN", "identity acquisition failed", errno=exc.errno) from exc
        finally:
            if fd is not None and not retained:
                self._backend.close_pidfd(fd)

    def _signal_retained(self, entry, sig) -> bool:
        if not self._owned(entry):
            raise GuardianError("OWNERSHIP_UNKNOWN", "signal handle was not acquired by this guardian")
        if not isinstance(sig, int) or isinstance(sig, bool) or sig <= 0 or sig >= signal.NSIG:
            raise GuardianError("OWNERSHIP_UNKNOWN", "invalid retained signal")
        try:
            if self._pidfd_exited(entry.pidfd, entry=entry):
                self._emit("signal", entry_sequence=entry.sequence, signal=int(sig), errno=None,
                           sent=False, already_exited=True)
                return False
            self._backend.signal_pidfd(entry.pidfd, int(sig))
        except OSError as exc:
            self._emit("signal", entry_sequence=entry.sequence, signal=int(sig), errno=exc.errno,
                       sent=False, already_exited=False)
            if exc.errno == errno.ESRCH and self._pidfd_exited(entry.pidfd, entry=entry):
                return False
            raise GuardianError("OWNERSHIP_UNKNOWN", "retained signal failed", errno=exc.errno) from exc
        self._emit("signal", entry_sequence=entry.sequence, signal=int(sig), errno=None,
                   sent=True, already_exited=False)
        return True
