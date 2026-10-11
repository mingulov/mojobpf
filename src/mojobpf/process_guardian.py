# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Retained-pidfd identity primitives for a Linux process guardian.

This module does not yet provide a subreaper lifecycle or a cleanup proof.
API inspection is read-only. Acquired handles remain owned until a future
single-reaper lifecycle seals their journal and proves the final child drain.
That drain must use Linux __WALL, distinguish None from ECHILD, and establish
SIGCHLD default disposition without SA_NOCLDWAIT before any runner spawn.
"""

from __future__ import annotations

from dataclasses import dataclass
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
    names = ("pidfd_open", "waitid", "P_PIDFD", "P_ALL", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")
    if (not sys.platform.startswith("linux") or any(not hasattr(os, name) for name in names)
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
    """Acquire and signal proven identities; this is not yet a lifecycle API.

    The dedicated controller must establish waitable SIGCHLD/subreaper
    semantics before retain_runner. Backends are injected through a private
    constructor argument for deterministic faults, never from JSON or env.
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

    def check_available(self) -> None:
        self._backend.check_available()

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
        read_fdinfo = self._backend.read_fdinfo if read_fdinfo is None else read_fdinfo
        return (not self._pidfd_exited(parent.pidfd, entry=parent)
                and _fdinfo_pid(read_fdinfo(parent.pidfd)) == parent.identity.pid
                and not self._pidfd_exited(parent.pidfd, entry=parent))

    def retain_runner(self, process) -> ProcessIdentity:
        if self._runner_entry is not None:
            raise GuardianError("OWNERSHIP_UNKNOWN", "runner already retained")
        entry = self._acquire(process.pid, parent=None, runner=True)
        if entry is None:
            raise GuardianError("OWNERSHIP_UNKNOWN", "direct child disappeared before retention")
        self._runner_entry = entry
        return entry.identity

    def _retain_candidate(self, pid, *, parent=None):
        # An unreaped retained zombie still has a positive fdinfo PID. A
        # reaped handle has Pid -1 and can never be reused for a replacement.
        for entry in self._entries:
            if entry.identity.pid == pid:
                try:
                    if _fdinfo_pid(self._backend.read_fdinfo(entry.pidfd)) == pid:
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
            return method(argument)
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
