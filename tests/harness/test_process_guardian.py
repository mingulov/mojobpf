# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Bounded Linux controls with an independent pidfd/zombie-status observer.

The controller and its at-most-two fixture descendants run only in isolated
subprocesses. Self-exit is an uncredited safeguard. No process groups, global
process census, external services or numeric signals are used.
"""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import threading
import time

from mojobpf.process_guardian import GuardLimits, ProcessGuardian, WAIT_WALL, check_linux_api_availability


CONTROL_SECONDS = 5.0
CLEANUP_SECONDS = 5.0
FALLBACK_SECONDS = 20.0
_CONTROLS_UNCERTAIN = False


def _send(fd, record):
    raw = (json.dumps(record, sort_keys=True) + "\n").encode()
    while raw:
        raw = raw[os.write(fd, raw):]


def _command(fd, text):
    _send(fd, {"command": text})


class _Lines:
    def __init__(self, fd):
        self.fd, self.buffer = fd, b""

    def next(self, deadline):
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("bounded pipe handshake expired")
            poller = select.poll()
            poller.register(self.fd, select.POLLIN | select.POLLHUP)
            if not poller.poll(max(1, int(remaining * 1000))):
                continue
            chunk = os.read(self.fd, 65536)
            if not chunk:
                raise EOFError("handshake pipe closed")
            self.buffer += chunk
            if len(self.buffer) > 1024 * 1024:
                raise ValueError("handshake stream exceeds bound")
        raw, self.buffer = self.buffer.split(b"\n", 1)
        return json.loads(raw)


def _raw_stat(pid):
    raw = Path(f"/proc/{pid}/stat").read_text()
    tail = raw[raw.rfind(") ") + 2:].split()
    return raw, tail


def _ready(fd):
    poller = select.poll()
    poller.register(fd, select.POLLIN)
    events = poller.poll(0)
    if any(mask & (select.POLLERR | select.POLLNVAL) for _, mask in events):
        raise OSError("observer pidfd is invalid")
    return any(mask & (select.POLLIN | select.POLLHUP) for _, mask in events)


def _fixture_report(fd, role, **extra):
    pid = os.getpid()
    raw, tail = _raw_stat(pid)
    _send(fd, {"kind": "fixture", "role": role, "pid": pid,
               "start_ticks": int(tail[19]), "session_id": int(tail[3]),
               "nice": os.getpriority(os.PRIO_PROCESS, 0), "raw_stat": raw, **extra})


def _held_child(report, hold):
    os.setsid()
    _fixture_report(report, "child")
    poller = select.poll()
    poller.register(hold, select.POLLIN | select.POLLHUP)
    poller.poll(int(FALLBACK_SECONDS * 1000))
    os._exit(88)  # Never credited as guardian cleanup.


def _runner(case, report, commands, hold):
    _fixture_report(report, "runner")
    if case == "immediate":
        os._exit(7)
    deadline = time.monotonic() + FALLBACK_SECONDS
    lines = _Lines(commands)
    child_created = False
    worker_release = threading.Event()
    def fork_one():
        child = os.fork()
        if child == 0:
            _held_child(report, hold)
        _send(report, {"kind": "forked", "pid": child, "thread_id": threading.get_native_id(),
                       "runner_pid": os.getpid()})
        if case == "nonleader":
            worker_release.wait(FALLBACK_SECONDS)
    while True:
        try:
            command = lines.next(deadline)["command"]
        except (TimeoutError, EOFError):
            os._exit(88)
        if command == "fork":
            if child_created:
                os._exit(89)
            child_created = True
            if case == "nonleader":
                threading.Thread(target=fork_one, daemon=True).start()
            else:
                fork_one()
        elif command == "exit":
            os._exit(0)
        else:
            os._exit(89)


def _controller(case, report, acknowledgements, hold, directory):
    directory = Path(directory)
    lines = _Lines(acknowledgements)
    control_deadline = time.monotonic() + CONTROL_SECONDS
    epoch_start = time.monotonic()
    cleanup_deadline = None
    command_write = None
    with (directory / "guardian-journal.jsonl").open("w") as journal_file:
        def journal(record):
            journal_file.write(json.dumps(record, sort_keys=True) + "\n")
            journal_file.flush()
            _send(report, {"kind": "guardian", "record": record})
            if record["event"] == "cleanup-entered" and case == "late":
                _send(report, {"kind": "late-window"})
                _command(command_write, "fork")
                assert lines.next(cleanup_deadline)["command"] == "child-captured"
            if record["event"] == "wait-observed":
                assert lines.next(cleanup_deadline or control_deadline)["command"] == "wait-verified"
        guard = ProcessGuardian(limits=GuardLimits(cleanup_seconds=CLEANUP_SECONDS), journal=journal)
        guard.prepare()
        nice_before = os.getpriority(os.PRIO_PROCESS, 0)
        nice_after = os.nice(10)
        _send(report, {"kind": "prepared", "pid": os.getpid(), "nice_before": nice_before,
                       "nice_after": nice_after, "threads": [entry.name for entry in Path("/proc/self/task").iterdir()]})
        command_read, command_write = os.pipe2(os.O_CLOEXEC)
        with (directory / "runner.stdout").open("wb") as stdout, (directory / "runner.stderr").open("wb") as stderr:
            process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--runner", case,
                                        str(report), str(command_read), str(hold)], start_new_session=True,
                                       stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                       close_fds=True, pass_fds=(report, command_read, hold))
            os.close(command_read)
            _send(report, {"kind": "spawned", "pid": process.pid})
            assert lines.next(control_deadline)["command"] == "runner-captured"
            guard.retain_runner(process)
            if case in {"adopt", "normal", "nonleader", "sigint", "sigterm"}:
                _command(command_write, "fork")
                assert lines.next(control_deadline)["command"] == "child-captured"
                if case == "adopt":
                    _command(command_write, "exit")
                else:
                    while len(guard.observe()) < 2:
                        if time.monotonic() >= control_deadline:
                            raise TimeoutError("descendant was not observed")
                        guard._backend.pause(0.005)
                    _send(report, {"kind": "observed", "processes": guard.observe()})
                    assert lines.next(control_deadline)["command"] == "observed-ack"
                    if case in {"normal", "nonleader"}:
                        _command(command_write, "exit")
                if case in {"adopt", "normal", "nonleader"}:
                    while guard.runner_exit() is None:
                        if time.monotonic() >= control_deadline:
                            raise TimeoutError("runner did not exit")
                        guard._backend.pause(0.005)
            elif case == "late":
                _send(report, {"kind": "cancel-ready"})
                assert lines.next(control_deadline)["command"] == "cancel-ack"
            if case in {"late", "sigint", "sigterm"}:
                while not guard.cancelled:
                    if time.monotonic() >= control_deadline:
                        raise TimeoutError("cancellation was not observed")
                    guard._backend.pause(0.005)
            cleanup_deadline = time.monotonic() + CLEANUP_SECONDS
            proof = guard.finish(reason="cancel" if guard.cancelled else "normal", interrupt=guard.cancelled)
            _send(report, {"kind": "result", "proof": proof, "returncode": process.returncode,
                           "cancelled": guard.cancelled, "elapsed": time.monotonic() - epoch_start})
            os.close(command_write)


# Independent outer observer. Its subreaper is only an emergency authority for
# its sole known controller tree; it never runs guardian.prepare in pytest.
class _ObserverAction(ctypes.Structure):
    _fields_ = [("handler", ctypes.c_void_p), ("mask", ctypes.c_ulong * 16),
                ("flags", ctypes.c_int), ("restorer", ctypes.c_void_p)]


def _observer_libc():
    assert sys.platform == "linux" and os.uname().machine == "x86_64"
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    libc.sigaction.argtypes = [ctypes.c_int, ctypes.POINTER(_ObserverAction), ctypes.POINTER(_ObserverAction)]
    libc.sigaction.restype = ctypes.c_int
    return libc


def _get_subreaper(libc):
    value = ctypes.c_int()
    pointer = ctypes.cast(ctypes.byref(value), ctypes.c_void_p).value
    assert libc.prctl(37, pointer, 0, 0, 0) == 0, ctypes.get_errno()
    return value.value


def _set_subreaper(libc, value):
    assert libc.prctl(36, value, 0, 0, 0) == 0, ctypes.get_errno()
    assert _get_subreaper(libc) == value


def _own_children():
    assert [entry.name for entry in Path("/proc/self/task").iterdir()] == [str(os.getpid())]
    raw = Path(f"/proc/self/task/{os.getpid()}/children").read_text()
    return [int(value) for value in raw.split()]


def _kernel_echild():
    try:
        os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT | WAIT_WALL)
    except ChildProcessError as exc:
        assert exc.errno == 10
        return True
    return False


def _capture(pid, role):
    fd = os.pidfd_open(pid, 0)
    try:
        first_info = Path(f"/proc/self/fdinfo/{fd}").read_text()
        first_raw, first = _raw_stat(pid)
        second_raw, second = _raw_stat(pid)
        second_info = Path(f"/proc/self/fdinfo/{fd}").read_text()
        assert f"Pid:\t{pid}\n" in first_info and f"Pid:\t{pid}\n" in second_info
        assert first[19] == second[19] and first[1] == second[1]
        return {"pid": pid, "fd": fd, "role": role, "start_ticks": int(first[19]),
                "raw_stat": [first_raw, second_raw], "raw_fdinfo": [first_info, second_info]}
    except BaseException:
        os.close(fd)
        raise


def _wait_zombie(entry, deadline):
    while not _ready(entry["fd"]):
        if time.monotonic() >= deadline:
            raise TimeoutError("immediate child did not exit before safeguard")
        time.sleep(0.001)


def _emergency_cleanup(entries, controller, *, journal=None):
    deadline = time.monotonic() + CLEANUP_SECONDS
    emergency = [] if journal is None else journal
    uncertainty = []
    def failed(event, error, **fields):
        record = {"event": event, "error": repr(error), "errno": getattr(error, "errno", None), **fields}
        emergency.append(record)
        uncertainty.append(record)
    def readiness(entry):
        try:
            return _ready(entry["fd"])
        except OSError as error:
            failed("readiness-failed", error, pid=entry["pid"])
            return None
    while time.monotonic() < deadline:
        # Only immediate children of this isolated observer, or children read
        # through still-live, retained parents in this one fixture tree.
        parents = [None] + list(entries.values())
        for parent in parents:
            if parent is not None and readiness(parent) is not False:
                continue
            pid = os.getpid() if parent is None else parent["pid"]
            try:
                tasks = list(Path(f"/proc/{pid}/task").iterdir())
                assert len(tasks) <= 2, "emergency native-thread budget exceeded"
                for task in tasks:
                    raw = (task / "children").read_text()
                    if parent is not None and readiness(parent) is not False:
                        break
                    tokens = raw.split()
                    assert len(tokens) <= 3, "emergency children budget exceeded"
                    for token in tokens:
                        child_pid = int(token)
                        if child_pid not in entries:
                            assert len(entries) < 3, "emergency fixture process budget exceeded"
                            entry = _capture(child_pid, "emergency-adoption")
                            try:
                                assert int(_raw_stat(child_pid)[1][1]) == pid
                                assert parent is None or readiness(parent) is False
                            except BaseException:
                                os.close(entry["fd"])
                                raise
                            entries[child_pid] = entry
                            emergency.append({"event": "retained", "pid": child_pid})
            except (OSError, AssertionError) as error:
                if not (isinstance(error, FileNotFoundError) and parent is not None
                        and readiness(parent) is True):
                    failed("discovery-failed", error, parent_pid=pid)
        for entry in list(entries.values()):
            if readiness(entry) is False:
                try:
                    signal.pidfd_send_signal(entry["fd"], signal.SIGKILL)
                    emergency.append({"event": "signal", "pid": entry["pid"], "signal": 9})
                except OSError as error:
                    if error.errno == 3 and readiness(entry) is True:
                        emergency.append({"event": "signal-race", "pid": entry["pid"], "errno": error.errno})
                    else:
                        failed("signal-failed", error, pid=entry["pid"])
        for _ in range(4):
            try:
                observed = os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT | WAIT_WALL)
            except ChildProcessError:
                break
            except OSError as error:
                failed("wait-failed", error)
                break
            if observed is None or not observed.si_pid:
                break
            try:
                entry = entries[observed.si_pid]
                actual = os.waitid(os.P_PIDFD, entry["fd"], os.WEXITED | os.WNOHANG | WAIT_WALL)
                assert actual is not None and actual.si_pid == observed.si_pid
                signed = actual.si_status if actual.si_code == os.CLD_EXITED else -actual.si_status
                emergency.append({"event": "reaped", "pid": actual.si_pid, "exit_code": signed})
                if actual.si_pid == controller.pid:
                    controller.returncode = signed
            except (OSError, KeyError, AssertionError) as error:
                failed("reap-failed", error, pid=observed.si_pid)
                break
        try:
            drained = (all(readiness(entry) is True for entry in entries.values())
                       and _kernel_echild() and _own_children() == [])
        except (OSError, AssertionError) as error:
            failed("drain-proof-failed", error)
            drained = False
        if drained:
            if uncertainty:
                raise RuntimeError("uncertain fixture ownership; known handles cleaned, further controls refused")
            return emergency
        time.sleep(0.005)
    raise RuntimeError("uncertain fixture ownership/cleanup: further controls refused")


def _run_control(case, directory):
    global _CONTROLS_UNCERTAIN
    assert not _CONTROLS_UNCERTAIN, "prior uncertain cleanup forbids further controls"
    check_linux_api_availability()
    libc = _observer_libc()
    action = _ObserverAction()
    assert libc.sigaction(signal.SIGCHLD, None, ctypes.byref(action)) == 0
    assert action.handler is None and not action.flags & 2
    baseline_children = _own_children()
    assert baseline_children == [] and _kernel_echild()
    old_subreaper = _get_subreaper(libc)
    _set_subreaper(libc, 1)
    parent_nice = os.getpriority(os.PRIO_PROCESS, 0)
    sentinel = _capture(os.getpid(), "outside-sentinel")
    entries, messages, statuses, result = {}, [], [], None
    forked_children, reported_children, acknowledged_children = set(), set(), set()
    report_read, report_write = os.pipe2(os.O_CLOEXEC)
    ack_read, ack_write = os.pipe2(os.O_CLOEXEC)
    hold_read, hold_write = os.pipe2(os.O_CLOEXEC)
    observer_deadline = time.monotonic() + CONTROL_SECONDS + CLEANUP_SECONDS
    controller = None
    emergency = []
    proof = {"case": case, "baseline_children": baseline_children, "baseline_echild": True,
             "host": list(os.uname()), "python": sys.version, "python_executable": sys.executable,
             "python_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
             "host_boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
             "parent_pid": os.getpid(), "parent_nice": parent_nice, "sentinel": sentinel,
             "start_monotonic": time.monotonic()}
    try:
        with (directory / "controller.stdout").open("wb") as stdout, (directory / "controller.stderr").open("wb") as stderr:
            # Use the current public package location, without modifying sys.path
            # or requiring a sibling checkout or private coordination path.
            environment = dict(os.environ)
            import mojobpf
            environment["PYTHONPATH"] = str(Path(mojobpf.__file__).resolve().parent.parent)
            controller = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--controller", case,
                                           str(report_write), str(ack_read), str(hold_read), str(directory)],
                                          stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                          close_fds=True, pass_fds=(report_write, ack_read, hold_read), env=environment)
            entries[controller.pid] = _capture(controller.pid, "controller")
            for fd in (report_write, ack_read, hold_read):
                os.close(fd)
            report_write = ack_read = hold_read = None
            lines = _Lines(report_read)
            while result is None:
                message = lines.next(observer_deadline)
                messages.append(message)
                kind = message["kind"]
                if kind in {"spawned", "forked"}:
                    pid = message["pid"]
                    if pid not in entries:
                        assert len(entries) < 3
                        entries[pid] = _capture(pid, "runner" if kind == "spawned" else "child")
                    if kind == "forked" and case == "nonleader":
                        assert message["thread_id"] != message["runner_pid"]
                        raw = Path(f'/proc/{message["runner_pid"]}/task/{message["thread_id"]}/children').read_text()
                        assert str(pid) in raw.split()
                        proof["nonleader_children"] = {"tid": message["thread_id"], "raw": raw}
                    if kind == "forked":
                        forked_children.add(pid)
                        if pid in reported_children and pid not in acknowledged_children:
                            _command(ack_write, "child-captured")
                            acknowledged_children.add(pid)
                elif kind == "prepared":
                    assert message["nice_after"] == min(19, message["nice_before"] + 10)
                    assert message["threads"] == [str(controller.pid)]
                    proof["controller_nice"] = message["nice_after"]
                elif kind == "fixture":
                    pid = message["pid"]
                    if pid not in entries:
                        assert len(entries) < 3
                        entries[pid] = _capture(pid, message["role"])
                    entry = entries[pid]
                    assert message["start_ticks"] == entry["start_ticks"]
                    assert message["nice"] == proof["controller_nice"]
                    assert message["session_id"] == pid
                    if message["role"] == "runner":
                        if case == "immediate":
                            _wait_zombie(entry, observer_deadline)
                            proof["immediate_ready_before_retention"] = True
                        _command(ack_write, "runner-captured")
                    else:
                        reported_children.add(pid)
                        if pid in forked_children and pid not in acknowledged_children:
                            _command(ack_write, "child-captured")
                            acknowledged_children.add(pid)
                elif kind == "observed":
                    assert len(message["processes"]) == 2
                    child = [item for item in message["processes"] if item["role"] == "descendant"][0]
                    assert child["ownership_basis"] == "observed-descendant"
                    if case in {"sigint", "sigterm"}:
                        signal.pidfd_send_signal(entries[controller.pid]["fd"], signal.SIGINT if case == "sigint" else signal.SIGTERM)
                    _command(ack_write, "observed-ack")
                elif kind == "cancel-ready":
                    signal.pidfd_send_signal(entries[controller.pid]["fd"], signal.SIGINT)
                    _command(ack_write, "cancel-ack")
                elif kind == "guardian" and message["record"]["event"] == "wait-observed":
                    record = message["record"]
                    entry = entries[record["identity"]["pid"]]
                    assert _ready(entry["fd"])
                    raw, fields = _raw_stat(entry["pid"])
                    assert fields[0] == "Z" and int(fields[19]) == entry["start_ticks"]
                    assert record["identity"]["start_ticks"] == entry["start_ticks"]
                    kernel_signed = os.waitstatus_to_exitcode(int(fields[49]))
                    assert kernel_signed == record["exit_code"]
                    statuses.append({"pid": entry["pid"], "start_ticks": entry["start_ticks"],
                                     "raw_zombie_stat": raw, "kernel_signed": kernel_signed,
                                     "guardian_wait": record})
                    _command(ack_write, "wait-verified")
                elif kind == "result":
                    result = message
            _wait_zombie(entries[controller.pid], observer_deadline)
            actual = os.waitid(os.P_PIDFD, entries[controller.pid]["fd"], os.WEXITED | os.WNOHANG | WAIT_WALL)
            assert actual is not None and actual.si_code == os.CLD_EXITED and actual.si_status == 0
            controller.returncode = 0
        assert result["proof"]["status"] == "CLEAN", result
        assert result["proof"]["final_echild"] and result["proof"]["all_pidfds_exited"]
        assert result["proof"]["unresolved_live"] == 0 and result["proof"]["failures"] == []
        assert result["elapsed"] < CONTROL_SECONDS + CLEANUP_SECONDS < FALLBACK_SECONDS
        expected_runner = 7 if case == "immediate" else (-9 if case in {"late", "sigint", "sigterm"} else 0)
        assert result["returncode"] == result["proof"]["runner_exit"] == expected_runner
        fixture_entries = [entry for entry in entries.values() if entry["role"] != "controller"]
        assert len(fixture_entries) == (1 if case == "immediate" else 2)
        assert {status["pid"] for status in statuses} == {entry["pid"] for entry in fixture_entries}
        for entry in fixture_entries:
            assert _ready(entry["fd"])
            status = [value for value in statuses if value["pid"] == entry["pid"]][0]
            assert status["kernel_signed"] == (expected_runner if entry["role"] == "runner" else -9)
        owned = {entry["pid"] for entry in fixture_entries}
        signaled = [message["record"] for message in messages if message["kind"] == "guardian" and message["record"]["event"] == "signal"]
        process_sequences = {item["sequence"]: item["identity"]["pid"] for item in result["proof"]["processes"]}
        assert all(process_sequences[item["entry_sequence"]] in owned for item in signaled)
        if case in {"late", "sigint", "sigterm"}:
            sent = [item for item in signaled if item["sent"]]
            runner_pid = next(entry["pid"] for entry in fixture_entries if entry["role"] == "runner")
            assert process_sequences[sent[0]["entry_sequence"]] == runner_pid
            assert result["cancelled"] is True
        if case == "adopt":
            assert result["proof"]["adoptions"] >= 1
            assert any(item["ownership_basis"] == "adopted-child" for item in result["proof"]["processes"])
        if case == "late":
            kinds = [message["kind"] for message in messages]
            assert "late-window" in kinds and kinds.index("late-window") < kinds.index("forked")
            first_signal = next(index for index, message in enumerate(messages)
                                if message["kind"] == "guardian" and message["record"]["event"] == "signal")
            assert kinds.index("forked") < first_signal
        assert _own_children() == [] and _kernel_echild()
        assert not _ready(sentinel["fd"])
        assert os.getpriority(os.PRIO_PROCESS, 0) == parent_nice
        proof["qualified"] = True
    finally:
        try:
            if controller is not None and (controller.returncode is None or not _kernel_echild() or _own_children()):
                _emergency_cleanup(entries, controller, journal=emergency)
            proof["final_children"] = _own_children()
            proof["final_echild"] = _kernel_echild()
            proof["final_readiness"] = {str(pid): _ready(entry["fd"]) for pid, entry in entries.items()}
            proof["sentinel_ready"] = _ready(sentinel["fd"])
            _set_subreaper(libc, old_subreaper)
        except BaseException as error:
            _CONTROLS_UNCERTAIN = True
            proof["uncertain_cleanup"] = repr(error)
            raise
        finally:
            proof.update({"entries": entries, "messages": messages, "wait_statuses": statuses,
                          "result": result, "emergency": emergency, "end_monotonic": time.monotonic()})
            (directory / "observer-proof.json").write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
            for entry in entries.values():
                os.close(entry["fd"])
            os.close(sentinel["fd"])
            for fd in (report_read, report_write, ack_read, ack_write, hold_read, hold_write):
                if fd is not None:
                    os.close(fd)


if __name__ == "__main__":
    if sys.argv[1] == "--runner":
        _runner(sys.argv[2], *(int(value) for value in sys.argv[3:6]))
    elif sys.argv[1] == "--controller":
        _controller(sys.argv[2], *(int(value) for value in sys.argv[3:6]), sys.argv[6])
    else:
        raise ValueError("unknown fixture role")
    sys.exit(0)


import pytest


@pytest.mark.parametrize("case", ["immediate", "adopt", "late", "sigint", "sigterm", "normal", "nonleader"])
def test_bounded_owned_process_control(case, tmp_path):
    _run_control(case, tmp_path)


def _model_emergency(monkeypatch, *, discovery_failure=False, exit_race=False):
    from types import SimpleNamespace
    module = sys.modules[__name__]
    dead, signals = [False], []
    def children():
        if discovery_failure:
            raise FileNotFoundError(2, "injected discovery failure")
        return ""
    class Task:
        def __truediv__(self, name):
            return SimpleNamespace(read_text=children)
    monkeypatch.setattr(module, "Path", lambda path: SimpleNamespace(iterdir=lambda: [Task()]))
    monkeypatch.setattr(os, "getpid", lambda: 100)
    monkeypatch.setattr(module, "_ready", lambda fd: dead[0])
    monkeypatch.setattr(module, "_kernel_echild", lambda: True)
    monkeypatch.setattr(module, "_own_children", lambda: [])
    def no_child(*args):
        raise ChildProcessError(10, "model ECHILD")
    monkeypatch.setattr(os, "waitid", no_child)
    def send(fd, sig):
        signals.append((fd, sig))
        dead[0] = True
        if exit_race:
            raise ProcessLookupError(3, "exited between readiness and signal")
    monkeypatch.setattr(signal, "pidfd_send_signal", send)
    entries = {101: {"pid": 101, "fd": 21, "role": "controller"}}
    return entries, SimpleNamespace(pid=101, returncode=None), dead, signals


def test_emergency_observer_handles_proven_exit_race(monkeypatch):
    entries, controller, dead, signals = _model_emergency(monkeypatch, exit_race=True)
    journal = _emergency_cleanup(entries, controller)
    assert dead[0] and signals == [(21, signal.SIGKILL)]
    assert any(record["event"] == "signal-race" and record["errno"] == 3 for record in journal)


def test_emergency_discovery_failure_still_cleans_known_handles(monkeypatch):
    entries, controller, dead, signals = _model_emergency(monkeypatch, discovery_failure=True)
    with pytest.raises(RuntimeError, match="uncertain"):
        _emergency_cleanup(entries, controller)
    assert dead[0] and signals == [(21, signal.SIGKILL)]
