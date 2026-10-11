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
import hashlib
import json
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
_SIGNAL_RETRY_BATCH = 3
_SIGNAL_ATTEMPT_LIMIT = 3
_JOURNAL_LIMIT = 64 * 1024 * 1024
_RECORD_LIMIT = 16 * 1024 * 1024
_RECORD_COUNT_LIMIT = 65536
_JSON_DEPTH_LIMIT = 32
_JSON_NODE_LIMIT = 250000
_CANCELLATION_OPERATIONS = ("wakeup-fd", "sigint-handler", "sigterm-handler", "wake-read-close", "wake-write-close")


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

    def restore_cancellation(self, release_step):
        release_step("wakeup-fd", lambda: signal.set_wakeup_fd(self._old_wakeup))
        release_step("sigint-handler", lambda: signal.signal(signal.SIGINT, self._old_handlers[signal.SIGINT]))
        release_step("sigterm-handler", lambda: signal.signal(signal.SIGTERM, self._old_handlers[signal.SIGTERM]))
        release_step("wake-read-close", lambda: os.close(self._wake_read))
        release_step("wake-write-close", lambda: os.close(self._wake_write))


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


@dataclass
class _SignalProgress:
    state: str = "pending"
    checks: int = 0
    attempts: int = 0

    def journal_fields(self):
        return {"signal_state": self.state, "signal_check": self.checks,
                "signal_attempt": self.attempts}


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
        self._signal_progress = {}
        self._exit_observed = set()
        self._closed = set()
        self._result = None
        self._completion_receipt = None
        self._epoch_records = []
        self._epoch_bytes = 0
        self._unusable_fds = set()
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
        if self._prepared and (self._result is None or self._completion_receipt is None):
            raise GuardianError("OWNERSHIP_UNKNOWN", "previous epoch is active or quarantined")
        if self._entries and (self._result is None or self._completion_receipt is None
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
            self._wait_status, self._reaped, self._signal_progress = {}, set(), {}
            self._exit_observed, self._closed = set(), set()
            self._result, self._last_echild = None, False
            self._completion_receipt, self._epoch_records, self._epoch_bytes = None, [], 0
            self._unusable_fds = set()
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
            return json.loads(self._result)
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
        result = {"status": "DRAINED" if self._last_echild and all_exited else "INCOMPLETE",
                  "subreaper_readback": self._subreaper, "scans": self._scans, "adoptions": self._adoptions,
                  "final_echild": self._last_echild, "unresolved_live": unresolved,
                  "all_pidfds_exited": all_exited, "mountinfo_before": self._mountinfo_before,
                  "mountinfo_after": mountinfo_after, "failures": self._failures.copy(),
                  "processes": self._observations(poll=False), "runner_exit": self._runner_signed_exit()}
        try:
            self._emit("cleanup-provisional", authoritative=False, **result)
        except GuardianError as exc:
            self._failure(exc)
        releases = [{"entry_sequence": entry.sequence, "identity": vars(entry.identity).copy(),
                     "disposition": "RETAINED", "attempted_at": None, "completed_at": None, "errno": None}
                    for entry in self._entries]
        restore = {"state": "UNATTEMPTED", "attempted_at": None, "completed_at": None, "errno": None,
                   "operations": [{"operation": name, "state": "UNATTEMPTED", "attempted_at": None,
                                   "completed_at": None, "errno": None} for name in _CANCELLATION_OPERATIONS]}
        try:
            self._check_deadline()
            if not self._failures and result["status"] == "DRAINED":
                for entry, release in zip(self._entries, releases):
                    self._check_deadline()
                    release["attempted_at"] = self._backend.monotonic()
                    release["disposition"] = "CLOSE_UNKNOWN"
                    # A close can consume the number and then raise. Neither a
                    # failed acknowledgement nor later fd reuse permits retry.
                    self._unusable_fds.add(entry.pidfd)
                    try:
                        self._backend.close_pidfd(entry.pidfd)
                    except Exception as exc:
                        release["errno"] = getattr(exc, "errno", None)
                        raise GuardianError("IO_FAILED", "guardian pidfd close uncertain", errno=release["errno"]) from exc
                    release["disposition"] = "CLOSED"
                    release["completed_at"] = self._backend.monotonic()
                    self._closed.add(entry.sequence)
                    self._check_deadline()
                self._restore_cancellation(restore)
        except (GuardianError, OSError) as exc:
            self._failure(exc)
        result.update(pidfd_release=releases, cancellation_restore=restore,
                      failures=self._failures.copy(), deadline=deadline)
        candidate = not self._failures and result["status"] == "DRAINED" and restore["state"] == "SUCCEEDED"
        result["status"] = "CANDIDATE_CLEAN" if candidate else "INCOMPLETE"
        try:
            self._emit("cleanup-finalization", authoritative=False, **result)
            # Hashing and copying are done before the final clock observation.
            digest = _records_digest(self._epoch_records)
            returned = json.loads(_canonical_bytes(result))
            acknowledged_at = self._backend.monotonic()
            _proof_require(_finite_time(acknowledged_at) and acknowledged_at >= json.loads(self._epoch_records[-1])["time"],
                           "final acknowledgement time is invalid")
            if acknowledged_at >= deadline:
                raise GuardianError("CLEANUP_INCOMPLETE", "cleanup deadline exhausted")
            if candidate:
                receipt = {"schema_version": 1, "epoch_first_sequence": json.loads(self._epoch_records[0])["sequence"],
                           "epoch_last_sequence": self._event_sequence, "records_sha256": digest,
                           "deadline": deadline, "acknowledged_at": acknowledged_at, "status": "CLEAN"}
                receipt_snapshot = _canonical_bytes(receipt)
                returned["status"], returned["completion_receipt"] = "CLEAN", receipt
            else:
                returned["completion_receipt"] = None
            cached_result = _canonical_bytes(returned)
            checked_at = self._backend.monotonic()
            _proof_require(_finite_time(checked_at) and checked_at >= acknowledged_at, "final completion time is invalid")
            if checked_at >= deadline:
                raise GuardianError("CLEANUP_INCOMPLETE", "cleanup deadline exhausted")
            # No fallible release, serialization or journal callback follows
            # this final check. Mutable returned objects are separate copies.
            if candidate:
                self._completion_receipt = receipt_snapshot
            self._result = cached_result
        except GuardianError as exc:
            self._failure(exc)
            returned = json.loads(_canonical_bytes(result))
            returned.update(status="INCOMPLETE", failures=self._failures.copy(), completion_receipt=None)
            self._result = _canonical_bytes(returned)
        return returned

    def _restore_cancellation(self, restore):
        self._check_deadline()
        restore.update(state="UNKNOWN", attempted_at=self._backend.monotonic())
        def release_step(name, action):
            pending = next((step for step in restore["operations"] if step["state"] == "UNATTEMPTED"), None)
            if pending is None or pending["operation"] != name:
                raise GuardianError("IO_FAILED", "cancellation restoration order is invalid")
            self._check_deadline()
            pending.update(state="UNKNOWN", attempted_at=self._backend.monotonic())
            try:
                action()
            except Exception as exc:
                pending["errno"] = getattr(exc, "errno", None)
                raise GuardianError("IO_FAILED", "cancellation restoration operation uncertain", errno=pending["errno"]) from exc
            pending.update(state="SUCCEEDED", completed_at=self._backend.monotonic())
            self._check_deadline()
        try:
            self._backend.restore_cancellation(release_step)
            if any(step["state"] != "SUCCEEDED" for step in restore["operations"]):
                raise GuardianError("IO_FAILED", "cancellation restoration is incomplete")
            restore.update(state="SUCCEEDED", completed_at=self._backend.monotonic())
            self._check_deadline()
        except Exception as exc:
            restore["errno"] = getattr(exc, "errno", None)
            if isinstance(exc, GuardianError):
                raise
            raise GuardianError("IO_FAILED", "cancellation restoration uncertain", errno=restore["errno"]) from exc

    def _kill_once(self, entry):
        progress = self._signal_progress.setdefault(entry.sequence, _SignalProgress())
        # Only confirmed death or a completed syscall consumes the signal.
        # Retry uncertainty through this same fd before descendants, without
        # reopening a PID or forgetting the first failure/quarantine decision.
        for _ in range(_SIGNAL_RETRY_BATCH):
            if progress.state in {"completed", "exited"} or progress.attempts >= _SIGNAL_ATTEMPT_LIMIT:
                break
            try:
                self._check_deadline()
                progress.checks += 1
                self._signal_retained(entry, signal.SIGKILL, _progress=progress)
            except (GuardianError, OSError) as exc:
                self._failure(exc)
                if self._backend.monotonic() >= self._cleanup_deadline:
                    break

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
            _proof_require(_finite_time(record["time"]) and record["time"] >= 0
                           and (not self._epoch_records or record["time"] >= json.loads(self._epoch_records[-1])["time"]),
                           "ownership journal clock is invalid")
            canonical = _canonical_bytes(record)
            if len(self._epoch_records) >= _RECORD_COUNT_LIMIT or self._epoch_bytes + len(canonical) > _JOURNAL_LIMIT:
                raise GuardianError("IO_FAILED", "ownership journal exceeds its bound")
            self._epoch_records.append(canonical)
            self._epoch_bytes += len(canonical)
            # The callback gets a separate object. Frozen dataclass dictionaries
            # and nested result facts never escape into that mutable argument.
            self._journal(json.loads(canonical))
        except Exception as exc:
            raise GuardianError("IO_FAILED", "ownership journal write failed", errno=getattr(exc, "errno", None)) from exc

    def _owned(self, entry):
        return any(item is entry for item in self._entries)

    def _pidfd_exited(self, fd, *, entry=None, pid_hint=None):
        """Keep liveness API failures typed, including recovery observations."""
        if fd in self._unusable_fds:
            raise GuardianError("OWNERSHIP_UNKNOWN", "released or uncertain pidfd is unusable")
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

    def _signal_retained(self, entry, sig, *, _progress=None) -> bool:
        if not self._owned(entry):
            raise GuardianError("OWNERSHIP_UNKNOWN", "signal handle was not acquired by this guardian")
        if entry.pidfd in self._unusable_fds:
            raise GuardianError("OWNERSHIP_UNKNOWN", "released or uncertain signal handle is unusable")
        if not isinstance(sig, int) or isinstance(sig, bool) or sig <= 0 or sig >= signal.NSIG:
            raise GuardianError("OWNERSHIP_UNKNOWN", "invalid retained signal")
        try:
            if self._pidfd_exited(entry.pidfd, entry=entry):
                if _progress is not None:
                    _progress.state = "exited"
                self._emit("signal", entry_sequence=entry.sequence, signal=int(sig), errno=None,
                           sent=False, already_exited=True,
                           **({} if _progress is None else _progress.journal_fields()))
                return False
            if _progress is not None:
                _progress.state = "attempted"
                _progress.attempts += 1
            self._backend.signal_pidfd(entry.pidfd, int(sig))
            # Record the completed side effect before a fallible journal call.
            if _progress is not None:
                _progress.state = "completed"
        except OSError as exc:
            self._emit("signal", entry_sequence=entry.sequence, signal=int(sig), errno=exc.errno,
                       sent=False, already_exited=False,
                       **({} if _progress is None else _progress.journal_fields()))
            if exc.errno == errno.ESRCH and self._pidfd_exited(entry.pidfd, entry=entry):
                if _progress is not None:
                    _progress.state = "exited"
                return False
            raise GuardianError("OWNERSHIP_UNKNOWN", "retained signal failed", errno=exc.errno) from exc
        self._emit("signal", entry_sequence=entry.sequence, signal=int(sig), errno=None,
                   sent=True, already_exited=False,
                   **({} if _progress is None else _progress.journal_fields()))
        return True


def _proof_require(condition, detail):
    if not condition:
        raise GuardianError("EVIDENCE_INVALID", detail)


def _finite_time(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def _bounded_shape(value):
    pending, nodes = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        _proof_require(nodes <= _JSON_NODE_LIMIT, "JSON node bound exceeded")
        if type(item) in (dict, list):
            _proof_require(depth < _JSON_DEPTH_LIMIT, "JSON nesting bound exceeded")
            if type(item) is dict:
                _proof_require(all(type(key) is str for key in item), "JSON object key is invalid")
                pending.extend((child, depth + 1) for child in item.values())
            else:
                pending.extend((child, depth + 1) for child in item)
        elif type(item) is float:
            _proof_require(math.isfinite(item), "nonfinite JSON value")
        else:
            _proof_require(type(item) in (str, int, bool, type(None)), "unsupported JSON value")


def _canonical_bytes(value):
    _bounded_shape(value)
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise GuardianError("EVIDENCE_INVALID", "JSON canonicalization failed") from exc
    _proof_require(len(raw) <= _RECORD_LIMIT, "JSON record byte bound exceeded")
    return raw


def _records_digest(records):
    digest = hashlib.sha256(b"[")
    for index, raw in enumerate(records):
        if index:
            digest.update(b",")
        digest.update(raw)
    digest.update(b"]")
    return digest.hexdigest()


def _strict_json(raw, limit):
    _proof_require(type(raw) is bytes and 0 < len(raw) <= limit, "JSON input byte bound exceeded")
    # Bound nesting before the decoder allocates recursive containers. Brackets
    # within strings and escaped quotes do not affect depth.
    depth, quoted, escaped, tokens, bare = 0, False, False, 0, False
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
            tokens += 1
            bare = False
        elif char in (91, 123):
            depth += 1
            tokens += 1
            bare = False
            _proof_require(depth <= _JSON_DEPTH_LIMIT, "JSON nesting bound exceeded")
        elif char in (93, 125):
            depth -= 1
            bare = False
            _proof_require(depth >= 0, "JSON nesting is invalid")
        elif char in (9, 10, 13, 32, 44, 58):
            bare = False
        elif not bare:
            tokens += 1
            bare = True
        _proof_require(tokens <= _JSON_NODE_LIMIT, "JSON token bound exceeded")
    def pairs(items):
        result = {}
        for key, value in items:
            _proof_require(key not in result, "duplicate JSON object key")
            result[key] = value
        return result
    def constant(value):
        raise GuardianError("EVIDENCE_INVALID", "nonfinite JSON constant")
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise GuardianError("EVIDENCE_INVALID", "invalid JSON input") from exc
    _bounded_shape(result)
    return result


def _identity_proof(value):
    _proof_require(type(value) is dict and set(value) == {"pid", "start_ticks", "host_boot_id"}, "invalid proof identity shape")
    return ProcessIdentity(**value)


def _release_proof(final, processes, drained, acknowledged):
    releases = final.get("pidfd_release")
    _proof_require(type(releases) is list and len(releases) == len(processes), "pidfd release set mismatch")
    seen = set()
    prior_release = drained
    for release in releases:
        _proof_require(type(release) is dict and set(release) == {"entry_sequence", "identity", "disposition", "attempted_at", "completed_at", "errno"}, "invalid pidfd release shape")
        sequence = release["entry_sequence"]
        _proof_require(type(sequence) is int and sequence in processes and sequence not in seen, "pidfd release sequence mismatch")
        seen.add(sequence)
        _identity_proof(release["identity"])
        _proof_require(release["identity"] == processes[sequence]["identity"] and release["disposition"] == "CLOSED" and release["errno"] is None, "pidfd release is not confirmed")
        _proof_require(_finite_time(release["attempted_at"]) and _finite_time(release["completed_at"])
                       and prior_release <= release["attempted_at"] <= release["completed_at"] <= final["time"] <= acknowledged,
                       "pidfd release chronology is invalid")
        prior_release = release["completed_at"]
    restore = final.get("cancellation_restore")
    _proof_require(type(restore) is dict and set(restore) == {"state", "attempted_at", "completed_at", "errno", "operations"}, "invalid cancellation restore shape")
    _proof_require(restore["state"] == "SUCCEEDED" and restore["errno"] is None and _finite_time(restore["attempted_at"])
                   and _finite_time(restore["completed_at"])
                   and prior_release <= restore["attempted_at"] <= restore["completed_at"] <= final["time"], "cancellation restore is incomplete or late")
    operations = restore["operations"]
    _proof_require(type(operations) is list and len(operations) == len(_CANCELLATION_OPERATIONS), "cancellation restore set mismatch")
    prior = restore["attempted_at"]
    for operation, name in zip(operations, _CANCELLATION_OPERATIONS):
        _proof_require(type(operation) is dict and set(operation) == {"operation", "state", "attempted_at", "completed_at", "errno"}, "invalid cancellation operation shape")
        _proof_require(operation["operation"] == name and operation["state"] == "SUCCEEDED" and operation["errno"] is None
                       and _finite_time(operation["attempted_at"]) and _finite_time(operation["completed_at"])
                       and prior <= operation["attempted_at"] <= operation["completed_at"] <= restore["completed_at"],
                       "cancellation operation chronology is invalid")
        prior = operation["completed_at"]


def replay_completion(journal_bytes: bytes, receipt_bytes: bytes | None) -> dict:
    """Check externally admitted immutable JSONL and separate receipt bytes.

    This validates consistency, not admission or independent callback latency.
    Callers must byte-pin both artifacts and refuse advancement on any failure.
    Bounds: 64 MiB journal, 65536 records, 16 MiB per record, 4096-byte receipt,
    32 container levels and 250000 JSON value nodes per record. A later epoch
    begins only at an explicit prepared record; a same-epoch suffix is retained.
    """
    proof = {"status": "INCOMPLETE", "failures": [], "physical_drain": None, "release": None}
    try:
        _proof_require(type(journal_bytes) is bytes and 0 < len(journal_bytes) <= _JOURNAL_LIMIT, "journal byte bound exceeded")
        _proof_require(journal_bytes.endswith(b"\n") and journal_bytes.count(b"\n") <= _RECORD_COUNT_LIMIT, "journal record bound or suffix is invalid")
        records = [_strict_json(line, _RECORD_LIMIT) for line in journal_bytes.splitlines()]
        known_events = {"prepared", "cleanup-entered", "cleanup-provisional", "cleanup-finalization", "failure",
                        "pidfd-exited", "defer-adoption", "wait-observed", "echild", "reaped", "observation-failed",
                        "retained", "transient-hint", "acquisition-failed", "signal"}
        previous_sequence, previous_time = None, None
        for record in records:
            _proof_require(type(record) is dict and type(record.get("sequence")) is int and record["sequence"] > 0,
                           "journal sequence is invalid")
            _proof_require(_finite_time(record.get("time")) and record["time"] >= 0, "journal time is invalid")
            _proof_require(record.get("event") in known_events, "unknown journal event")
            for field in ("entry_sequence", "parent_sequence"):
                if field in record:
                    value = record[field]
                    _proof_require(value is None or type(value) is int and value > 0, "journal identity sequence is invalid")
            if "identity" in record:
                _identity_proof(record["identity"])
            _proof_require(previous_sequence is None or record["sequence"] == previous_sequence + 1, "journal sequence is not contiguous")
            _proof_require(previous_time is None or record["time"] >= previous_time, "journal time moved backwards")
            previous_sequence, previous_time = record["sequence"], record["time"]
        _proof_require(receipt_bytes is not None, "completion receipt is absent")
        receipt = _strict_json(receipt_bytes, 4096)
        _proof_require(type(receipt) is dict and set(receipt) == {"schema_version", "epoch_first_sequence", "epoch_last_sequence", "records_sha256", "deadline", "acknowledged_at", "status"}, "completion receipt fields are invalid")
        _proof_require(type(receipt["schema_version"]) is int and receipt["schema_version"] == 1 and receipt["status"] == "CLEAN", "completion receipt contract is invalid")
        first, last = receipt["epoch_first_sequence"], receipt["epoch_last_sequence"]
        _proof_require(type(first) is int and type(last) is int and 0 < first <= last, "receipt sequence range is invalid")
        starts = [index for index, record in enumerate(records) if record["event"] == "prepared" and record["sequence"] == first]
        _proof_require(len(starts) == 1, "receipt does not begin a complete epoch")
        start = starts[0]
        end = next((index for index in range(start + 1, len(records)) if records[index]["event"] == "prepared"), len(records))
        epoch = records[start:end]
        _proof_require(epoch[-1]["sequence"] == last and epoch[-1]["event"] == "cleanup-finalization", "receipt discards epoch suffix or misses finalization")
        _proof_require(type(receipt["records_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", receipt["records_sha256"]), "receipt digest format is invalid")
        _proof_require(receipt["records_sha256"] == _records_digest([_canonical_bytes(record) for record in epoch]), "receipt record digest mismatch")
        _proof_require(_finite_time(receipt["deadline"]) and _finite_time(receipt["acknowledged_at"])
                       and epoch[-1]["time"] <= receipt["acknowledged_at"] < receipt["deadline"], "receipt acknowledgement is late or invalid")
        def single(event):
            found = [record for record in epoch if record["event"] == event]
            _proof_require(len(found) == 1, "epoch event is missing or repeated: " + event)
            return found[0]
        opening, entered, provisional, final = epoch[0], single("cleanup-entered"), single("cleanup-provisional"), epoch[-1]
        _proof_require(single("cleanup-finalization") is final, "finalization event is repeated")
        controller_identity = _identity_proof(opening.get("controller_identity"))
        _proof_require(opening.get("subreaper_readback") is True and opening.get("initial_echild") is True
                       and type(opening.get("sigchld")) is dict and opening["sigchld"].get("default") is True
                       and type(opening["sigchld"].get("flags")) is int and not opening["sigchld"]["flags"] & _SA_NOCLDWAIT,
                       "epoch opening is not a proven subreaper")
        _proof_require(entered["sequence"] < provisional["sequence"] < final["sequence"]
                       and entered.get("deadline") == final.get("deadline") == receipt["deadline"]
                       and _finite_time(entered.get("deadline")) and _finite_time(final.get("deadline"))
                       and entered["time"] < receipt["deadline"], "epoch deadline or event ordering is invalid")
        _proof_require(not any(record["event"] in {"failure", "observation-failed", "acquisition-failed"} for record in epoch), "epoch contains ownership or recording failure")
        _proof_require(provisional.get("authoritative") is False and final.get("authoritative") is False
                       and provisional.get("status") == "DRAINED" and final.get("status") == "CANDIDATE_CLEAN", "epoch is only an incomplete candidate")
        physical_fields = {"subreaper_readback", "scans", "adoptions", "final_echild", "unresolved_live", "all_pidfds_exited", "mountinfo_before", "mountinfo_after", "failures", "processes", "runner_exit"}
        _proof_require(all(field in provisional and field in final for field in physical_fields)
                       and _canonical_bytes({field: final[field] for field in physical_fields})
                       == _canonical_bytes({field: provisional[field] for field in physical_fields}), "physical drain changed during release")
        _proof_require(provisional["subreaper_readback"] is True and provisional["final_echild"] is True
                       and provisional["all_pidfds_exited"] is True and type(provisional["unresolved_live"]) is int
                       and provisional["unresolved_live"] == 0 and provisional["failures"] == [], "physical drain is incomplete")
        _proof_require(all(type(provisional[field]) is int and provisional[field] >= 0 for field in ("scans", "adoptions"))
                       and type(provisional["mountinfo_before"]) is str and type(provisional["mountinfo_after"]) is str,
                       "physical drain diagnostics are invalid")
        _proof_require(any(record["event"] == "echild" and record.get("final_candidate") is True for record in epoch), "physical drain lacks kernel ECHILD")
        _proof_require(type(provisional["processes"]) is list and len(provisional["processes"]) <= 4096, "process proof bound exceeded")
        processes, retained = {}, {}
        for record in epoch:
            if record["event"] == "retained":
                sequence = record.get("entry_sequence")
                _proof_require(type(sequence) is int and sequence > 0 and sequence not in retained, "retained sequence is invalid")
                retained[sequence] = record
        for process in provisional["processes"]:
            _proof_require(type(process) is dict and type(process.get("sequence")) is int
                           and process["sequence"] > 0 and process["sequence"] not in processes, "process proof sequence is invalid")
            sequence = process["sequence"]
            identity = _identity_proof(process.get("identity"))
            _proof_require(identity.host_boot_id == controller_identity.host_boot_id, "process proof boot identity mismatch")
            _proof_require(process.get("exited") is True and sequence in retained, "process identity is not retained and exited")
            captured = retained[sequence]
            _proof_require(all(process.get(field) == captured.get(field) for field in ("identity", "role", "ownership_basis", "parent_sequence", "raw_stat", "raw_fdinfo")), "retained process proof mismatch")
            raw_stat, raw_fdinfo = process.get("raw_stat"), process.get("raw_fdinfo")
            _proof_require(type(raw_stat) is list and len(raw_stat) == 2 and type(raw_fdinfo) is list and len(raw_fdinfo) == 2,
                           "process raw observation pair is missing")
            stats = [parse_process_stat(raw) for raw in raw_stat]
            _proof_require(all((stat.pid, stat.start_ticks, stat.ppid, stat.session_id)
                               == (identity.pid, identity.start_ticks, stats[0].ppid, stats[0].session_id) for stat in stats)
                           and all(_fdinfo_pid(raw) == identity.pid for raw in raw_fdinfo), "raw process identity bracket mismatch")
            _proof_require(type(process.get("session_id")) is int and process["session_id"] == stats[0].session_id,
                           "process session identity mismatch")
            parent = process.get("parent_sequence")
            _proof_require(parent is None or type(parent) is int and parent in processes and parent < sequence,
                           "process parent sequence is invalid")
            _proof_require(stats[0].ppid == (controller_identity.pid if parent is None else processes[parent]["identity"]["pid"]),
                           "raw process parent does not bind ownership")
            _proof_require((process.get("role") == "runner" and process.get("ownership_basis") == "spawn-child"
                            and parent is None and process["session_id"] == identity.pid)
                           or (process.get("role") == "descendant" and process.get("ownership_basis")
                               == ("adopted-child" if parent is None else "observed-descendant")), "process ownership basis is invalid")
            _proof_require(any(record["event"] == "pidfd-exited" and record.get("entry_sequence") == sequence
                               and record.get("identity") == process["identity"] for record in epoch), "process lacks exit readiness")
            _proof_require("wait_status" in process, "process wait status field is missing")
            status = process["wait_status"]
            if status is None:
                # An observed descendant can be reaped by its live parent.
                # Its retained exit/ECHILD proof cannot invent a controller wait.
                _proof_require(process["ownership_basis"] == "observed-descendant"
                               and not any(record["event"] in {"wait-observed", "reaped"}
                                           and record.get("entry_sequence") == sequence for record in epoch),
                               "process lacks required controller wait status")
            else:
                _proof_require(type(status) is dict and set(status) == {"code", "status", "exit_code"}
                               and all(type(value) is int for value in status.values()), "process wait status is invalid")
                _proof_require(status["code"] in {os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED}
                               and ((status["code"] == os.CLD_EXITED and 0 <= status["status"] <= 255 and status["exit_code"] == status["status"])
                                    or (status["code"] != os.CLD_EXITED and 0 < status["status"] < signal.NSIG and status["exit_code"] == -status["status"])), "process signed wait status mismatch")
                _proof_require(any(record["event"] == "reaped" and record.get("entry_sequence") == sequence
                                   and record.get("identity") == process["identity"]
                                   and all(record.get(field) == status[field] for field in status) for record in epoch), "process lacks matching reap")
            processes[sequence] = process
        _proof_require(set(processes) == set(retained), "retained process set mismatch")
        runners = [process for process in processes.values() if process["role"] == "runner"]
        _proof_require(len(runners) <= 1 and (provisional["runner_exit"] is None if not runners else
                       type(provisional["runner_exit"]) is int and provisional["runner_exit"] == runners[0]["wait_status"]["exit_code"]),
                       "runner signed exit does not match observed wait")
        proof["physical_drain"] = provisional
        # Release follows provisional physical drain. Callback return latency
        # remains the synchronous acknowledgement trust assumption.
        _release_proof(final, processes, provisional["time"], receipt["acknowledged_at"])
        proof.update(status="CLEAN", release={"pidfd_release": final["pidfd_release"], "cancellation_restore": final["cancellation_restore"]})
    except (GuardianError, KeyError, TypeError, ValueError, OverflowError) as exc:
        proof["failures"] = [{"code": "EVIDENCE_INVALID", "detail": str(exc), "errno": getattr(exc, "errno", None)}]
    return proof
