# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Core audit: the relocation shapes validate and every other refuses.

Drives ``compiler/audit.py`` over the genuine frontend output for
``tests/core/core_read.mojo`` (which must validate as mode
``"core"`` with exactly the frozen core count vector) and over
mutations of that genuine IR, one per prohibited relocation
behavior, asserting each rejection carries its exact MBPF3xx code
at stage ``adapter.audit``:

* an unknown ``__mojobpf_core_*`` spelling (another type or
  field, or a guarded read of the optional field) is an unknown
  external (``MBPF303``);
* a malformed relocation call (wrong operand or result shape) is
  a call-form violation (``MBPF313``/``MBPF314``);
* a second field read, a read without the existence check, or
  relocation calls inside another program shape match no
  supported shape (``MBPF307``);
* a relocation read of anything but the checked lookup result is
  an operand violation (``MBPF314``);
* core counts under the wrong entrypoint are an entry/shape
  mismatch (``MBPF302``).

Runnable directly (``python3 tests/core/test_core_audit.py``) or
under any ``test_``-style runner. Standard library only. Needs
the Mojo compiler on PATH; a missing compiler is an environment
failure, never a pass.
"""

import os
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "compiler"))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

import audit
from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402

CORE_SOURCE = os.path.join(REPO_ROOT, "tests", "core", "core_read.mojo")
SDK_INCLUDE = os.path.join(
    REPO_ROOT, "src", "mojobpf", "resources", "sdk"
)

STAGE = "adapter.audit"


class EnvironmentFailure(Exception):
    """A required tool is missing; the suite cannot run here."""


def mojo_emit(source):
    if shutil.which("mojo") is None:
        raise EnvironmentFailure("mojo compiler not found on PATH")
    workdir = tempfile.mkdtemp(prefix="core-audit-")
    try:
        out_path = os.path.join(workdir, "out.ll")
        argv = [
            "mojo", "build", "--emit", "llvm",
            *FRONTEND_TARGET_FLAGS,
            "-I", SDK_INCLUDE, "-o", out_path, source,
        ]
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,
        )
        if proc.returncode != 0 or not os.path.isfile(out_path):
            raise AssertionError(
                "frontend failed for %s (exit %d):\n%s\n%s"
                % (source, proc.returncode, proc.stdout, proc.stderr)
            )
        with open(out_path, "r", encoding="utf-8") as handle:
            return handle.read()
    finally:
        shutil.rmtree(workdir)


def mutate(raw, old, new, count=1):
    assert raw.count(old) == count, (
        "expected %d occurrence(s) of %r, found %d"
        % (count, old[:60], raw.count(old))
    )
    return raw.replace(old, new)


def assert_rejected(text, code, label):
    try:
        audit.validate(text)
    except audit.AuditError as exc:
        assert exc.code == code, (
            "%s: expected code %s, got %s (%s)"
            % (label, code, exc.code, exc)
        )
        assert exc.stage == STAGE, (
            "%s: expected stage %s, got %s" % (label, STAGE, exc.stage)
        )
        print("PASS %s -> %s/%s" % (label, exc.code, exc.stage))
        return
    raise AssertionError(
        "%s: audit accepted input it must reject with %s"
        % (label, code)
    )


def test_genuine_core_program_validates():
    raw = mojo_emit(CORE_SOURCE)
    program = audit.scan(raw)
    assert program.mode == "core", (
        "core_read.mojo validated as %s, expected core" % program.mode
    )
    assert program.family == "core", program.family
    assert program.entries == 1, program.entries
    assert program.counts == {
        "empty": 1,
        "mapaddr": 1,
        "keyslot": 1,
        "keyslot1": 0,
        "keyslotN": 0,
        "kindtag": 0,
        "hashtag": 0,
        "lrutag": 0,
        "pcpuhashtag": 0,
        "valslot": 0,
        "rbmapaddr": 0,
        "rbsize": 0,
        "eventslot": 0,
        "eventslotN": 0,
        "lookup": 1,
        "update": 0,
        "delete": 0,
        "pid": 0,
        "ktime": 0,
        "cpu": 0,
        "output": 0,
        "reserve": 0,
        "submit": 0,
        "discard": 0,
        "coreread": 1,
        "coreexists": 1,
        "skbload": 0,
        "skbstore": 0,
    }, program.counts
    print("PASS genuine core program validates (core)")


def test_unknown_field_spelling_refused():
    raw = mojo_emit(CORE_SOURCE)
    other = raw.replace(
        "__mojobpf_core_read_task_pid_v1",
        "__mojobpf_core_read_task_comm_v1",
    )
    assert_rejected(other, "MBPF303", "unknown-field read")


def test_unknown_exists_spelling_refused():
    raw = mojo_emit(CORE_SOURCE)
    other = raw.replace(
        "__mojobpf_core_exists_task_scx_v1",
        "__mojobpf_core_exists_task_ksm_v1",
    )
    assert_rejected(other, "MBPF303", "unknown-field exists")


def test_guarded_optional_read_refused():
    raw = mojo_emit(CORE_SOURCE)
    # The optional field admits an existence check only; a read
    # spelling for it is not reserved.
    other = raw.replace(
        "__mojobpf_core_exists_task_scx_v1()",
        "__mojobpf_core_read_task_scx_v1()",
    )
    other = other.replace(
        "__mojobpf_core_exists_task_scx_v1",
        "__mojobpf_core_read_task_scx_v1",
    )
    assert_rejected(other, "MBPF303", "optional-field read")


def test_malformed_read_operand_refused():
    raw = mojo_emit(CORE_SOURCE)
    call = None
    for line in raw.splitlines():
        if "__mojobpf_core_read_task_pid_v1" in line and "call " in line:
            call = line.strip()
    assert call is not None
    other = mutate(raw, call, call.replace("(ptr ", "(i64 0, ptr "))
    assert_rejected(other, "MBPF314", "malformed read operand")


def test_malformed_read_result_refused():
    raw = mojo_emit(CORE_SOURCE)
    call = None
    for line in raw.splitlines():
        if "__mojobpf_core_read_task_pid_v1" in line and "call " in line:
            call = line.strip()
    assert call is not None
    other = mutate(raw, call, call.replace("call i32 @", "call i64 @"))
    assert_rejected(other, "MBPF314", "malformed read result")


def test_malformed_exists_operands_refused():
    raw = mojo_emit(CORE_SOURCE)
    call = None
    for line in raw.splitlines():
        if "__mojobpf_core_exists_task_scx_v1" in line and "call " in line:
            call = line.strip()
    assert call is not None
    other = mutate(raw, call, call.replace("()", "(i32 0)"))
    assert_rejected(other, "MBPF314", "malformed exists operands")


def test_second_read_refused():
    raw = mojo_emit(CORE_SOURCE)
    call = None
    for line in raw.splitlines():
        if "__mojobpf_core_read_task_pid_v1" in line and "call " in line:
            call = line.strip()
    assert call is not None
    extra = call.replace("%", "%second_", 1)
    other = mutate(raw, call, call + "\n  " + extra)
    assert_rejected(other, "MBPF307", "second field read")


def test_read_without_exists_refused():
    raw = mojo_emit(CORE_SOURCE)
    call = None
    for line in raw.splitlines():
        if "__mojobpf_core_exists_task_scx_v1" in line and "call " in line:
            call = line.strip()
    assert call is not None
    decl = audit.COREEXISTS_DECL_LINE
    other = mutate(raw, call + "\n", "")
    other = mutate(other, decl + "\n", "")
    assert_rejected(other, "MBPF307", "read without exists")


def test_bad_provenance_refused():
    raw = mojo_emit(CORE_SOURCE)
    call = None
    for line in raw.splitlines():
        if "__mojobpf_core_read_task_pid_v1" in line and "call " in line:
            call = line.strip()
    assert call is not None
    keyslot = None
    for line in raw.splitlines():
        if audit.KEYSLOT_CALL_RE.match(line.strip()):
            keyslot = audit.KEYSLOT_CALL_RE.match(line.strip()).group(1)
    assert keyslot is not None
    operand = call.rsplit("%", 1)[1].rstrip(")")
    other = mutate(raw, call, call.replace("%" + operand, "%" + keyslot))
    assert_rejected(other, "MBPF314", "read of unchecked pointer")


def test_wrong_entrypoint_refused():
    raw = mojo_emit(CORE_SOURCE)
    other = mutate(
        raw,
        "define dso_local i32 @xdp_entry",
        "define dso_local i32 @trace_entry",
    )
    assert_rejected(other, "MBPF302", "core counts under trace_entry")


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    names = sorted(k for k in globals() if k.startswith("test_"))
    for name in names:
        try:
            globals()[name]()
        except EnvironmentFailure as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            return 2
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
        else:
            print("PASS %s" % name)
    if failures:
        return 1
    print("core audit: genuine program validates, %d negatives refuse"
          % (len(names) - 1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
