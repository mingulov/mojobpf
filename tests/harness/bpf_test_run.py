# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Minimal BPF load / test-run / unload harness (bpftool-driven).

Contract revision 2. Revision 1 established the flags, JSON keys, and
exit numbers below (all unchanged); revision 2 corrects two
classifications: explicit verifier evidence at load now reports
``verifier``/4 even when permission substrings appear alongside it, and
a version-probe failure reports the coherent environment triple
(stage ``setup``, classification ``environment``, exit 3).

Admission addendum (same result contract): the pin path is always
contained to an owned root (``--owned-root``, default
``/sys/fs/bpf``), always bound to the run's ownership token
(``--ownership-token``, mandatory), so the default root spans
only the owned run root, and the bpftool binary is always
admitted against its pins before it executes: ``--bpftool-sha256``
and ``--bpftool-version`` are mandatory together (the version
accompanies the byte identity; version-only pinning admits
nothing), with ``--bpftool-exec-sha256`` required exactly when
the entry is a launcher. There is no unadmitted execution path:
a missing pin or token is refused with the ``setup``/6 triple
before any execution, as are pin and admission violations.

  python3 tests/harness/bpf_test_run.py --object OBJ --expect-action N \
      [--data-in FILE] [--repeat 1] [--pin-path PATH] [--bpftool BIN] \
      [--owned-root DIR] [--ownership-token TOKEN] \
      [--bpftool-sha256 SHA] [--bpftool-exec-sha256 SHA] \
      [--bpftool-version VER] [--output FILE] [--timeout SECS]

Behavior: record the object hash, load exactly one program with
``bpftool prog load``, execute one kernel test-run
(``bpftool prog run ... repeat N``), require the return value to equal
``--expect-action`` exactly, then unpin (unload). Cleanup is attempted even
when the run step fails.

Failure layers stay distinct (exit code in parentheses):

  * ``setup`` (6): missing input file, missing bpftool binary, pin
    path outside the owned root, or bpftool/pin admission refusal.
  * ``environment`` (3): tooling/permission failure, e.g. load denied with
    "Operation not permitted" when run without the required capabilities
    and without verifier evidence.
  * ``verifier`` (4): the kernel verifier rejected the program. Explicit
    verifier evidence takes precedence over permission substrings: a
    verifier denial that surfaces as EACCES is still a verifier failure.
  * ``loader`` (5): libbpf/bpftool could not load the object for another
    reason (bad ELF, stale pin path, ...).
  * ``runtime`` (1): the test-run executed but the return value differs from
    the expectation, or the run itself errored.

Exit 0 means the observed return value matched the expectation. Exit 2 is
reserved for CLI usage errors. A JSON result is always written (to stdout,
or to ``--output``); a one-line human summary goes to stderr.

Privileged load/test-run must happen inside the approved disposable VM; this
script performs no privilege escalation itself.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

CONTRACT_VERSION = 2

EXIT_PASS = 0
EXIT_RUNTIME = 1
# EXIT 2 is reserved for CLI usage errors (argparse).
EXIT_ENVIRONMENT = 3
EXIT_VERIFIER = 4
EXIT_LOADER = 5
EXIT_SETUP = 6

DEFAULT_PIN_PATH = "/sys/fs/bpf/mojobpf_control"
DEFAULT_OWNED_ROOT = "/sys/fs/bpf"
DEFAULT_REPEAT = 1
DEFAULT_TIMEOUT = 120
CHAIN_LIMIT = 8
SCRIPT_LIMIT = 65536
# Placeholder input when the caller passes no packet: a minimum-size
# Ethernet frame of zero bytes. Packet-sensitive tests must pass --data-in.
DEFAULT_FRAME_SIZE = 60

_PERMISSION_PATTERNS = (
    "operation not permitted",
    "permission denied",
    "eacces",
    "eperm",
    "unprivileged",
    "cap_sys_admin",
    "cap_bpf",
)

_VERIFIER_PATTERNS = (
    "verifier",
    "rejected",
    "invalid opcode",
    "invalid access",
    "invalid mem access",
    "prog load log",  # libbpf framing around the kernel verifier log
    "not ok",
    "processed 0 insns",  # libbpf verifier-log trailer; no bare "processed"
    "r0 !read_ok",
    "r0 invalid",
    "unknown func",
    "invalid func",
)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
_VAR_RE = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"
)


def _read_script_text(path):
    """Return the script text, or None when not a readable script."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(2)
            if head != b"#!":
                return None
            rest = handle.read(SCRIPT_LIMIT)
    except OSError:
        return None
    try:
        return (head + rest).decode("utf-8")
    except UnicodeDecodeError:
        return None


def _has_shebang(path):
    """True when the file starts with ``#!`` (or cannot be read)."""
    try:
        with open(path, "rb") as handle:
            return handle.read(2) == b"#!"
    except OSError:
        return True


def _unquote(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _expand_vars(target, assigns):
    def _one(match):
        name = (
            match.group(1)
            if match.group(1) is not None
            else match.group(2)
        )
        if name not in assigns:
            raise KeyError(name)
        return assigns[name]

    try:
        expanded = _VAR_RE.sub(_one, target)
    except KeyError:
        return None
    if "$" in expanded:
        return None
    return expanded


def _is_exec_line(stripped):
    """True when a stripped line is a shell ``exec`` invocation.

    Staged copy of the shared execution contract's predicate:
    the separator is any shell word break (space or tab).
    ``exec`` glued to any other byte (a shell operator or a
    name byte) names some other command, never an exec
    invocation; carriage return, vertical tab and form feed
    split the physical line instead, leaving a bare ``exec``
    without a target.
    """
    return stripped == "exec" or (
        stripped.startswith("exec")
        and stripped[4:5] in (" ", "\t")
    )


def _exec_target(text):
    """Return the script's exec target, or None when not unique."""
    assigns = {}
    exec_lines = []
    seen_exec = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ASSIGN_RE.match(stripped)
        if match is not None:
            if not seen_exec:
                assigns[match.group(1)] = _unquote(
                    match.group(2).strip()
                )
            continue
        if _is_exec_line(stripped):
            exec_lines.append(stripped)
            seen_exec = True
    if len(exec_lines) != 1:
        return None
    try:
        tokens = shlex.split(exec_lines[0], posix=True)
    except ValueError:
        return None
    args = tokens[1:]
    while args and args[0] in ("-c", "-l"):
        args = args[1:]
    if len(args) >= 2 and args[0] == "-a":
        args = args[2:]
    if not args or args[0].startswith("-"):
        return None
    return _expand_vars(args[0], assigns)


def _count_exec_lines(text):
    """Count the script's ``exec`` lines (comments aside)."""
    count = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if _is_exec_line(stripped):
            count += 1
    return count


def classify_exec_chain(entry):
    """Classify a launcher entry without executing it.

    Static and bounded: while the current file is a script, take its
    single ``exec`` target (``$NAME``/``${NAME}`` expanded from the
    script's own assignments only) and continue there. Returns
    ``(kind, target, note)`` where ``kind`` is ``"direct"`` (the
    entry is itself the executed image), ``"launcher"`` (``target``
    is the final image's realpath), or ``"unknown"`` (the chain
    does not resolve: unreadable, ambiguous, dangling, cyclic,
    relative, or over the depth bound -- ``note`` says why).
    Unknown chains must be rejected, never treated as direct.
    """
    try:
        seen = {os.path.realpath(entry)}
    except OSError:
        return ("unknown", None, "entry is not resolvable")
    current = entry
    for _ in range(CHAIN_LIMIT):
        text = _read_script_text(current)
        if text is None:
            if current != entry and not _has_shebang(current):
                return ("launcher", current, "")
            if current == entry:
                return ("direct", None, "")
            return (
                "unknown",
                None,
                "launcher hop %r is not analyzable" % (current,),
            )
        target = _exec_target(text)
        if target is None:
            if _count_exec_lines(text) == 0:
                # A script with no exec line runs directly: it is
                # the chain terminus unless it is the entry itself.
                if current != entry:
                    return ("launcher", current, "")
                return ("direct", None, "")
            if _count_exec_lines(text) > 1:
                return (
                    "unknown",
                    None,
                    "ambiguous exec lines in launcher entry",
                )
            return (
                "unknown",
                None,
                "unresolvable exec target in launcher entry",
            )
        if not os.path.isabs(target):
            return (
                "unknown",
                None,
                "relative exec target %r resolves against the "
                "runtime directory" % (target,),
            )
        if not os.path.isfile(target):
            return (
                "unknown",
                None,
                "dangling exec target %r" % (target,),
            )
        try:
            resolved = os.path.realpath(target)
        except OSError:
            return (
                "unknown",
                None,
                "exec target %r is not resolvable" % (target,),
            )
        if resolved in seen:
            return (
                "unknown",
                None,
                "cyclic exec chain at %r" % (resolved,),
            )
        seen.add(resolved)
        current = resolved
    return (
        "unknown",
        None,
        "exec chain exceeds the depth bound",
    )


def follow_exec_target(entry):
    """Resolve a launcher entry to the image it execs, if any.

    Static and bounded: while the current file is a script, take its
    single ``exec`` target (``$NAME``/``${NAME}`` expanded from the
    script's own assignments only) and continue there. Returns the
    final image's realpath, or None when the entry is itself the
    executed image or the chain does not resolve (unreadable,
    ambiguous, dangling, cyclic or over the depth bound).

    This is the staged copy of the shared ``exec_chain`` follower:
    the guest stage carries only this file, so the logic is mirrored
    here and pinned to parity by
    ``tests/unit/test_portability_locks.py``. Admission uses
    :func:`classify_exec_chain` instead, which distinguishes an
    unresolvable chain from a directly executed entry.
    """
    kind, target, _note = classify_exec_chain(entry)
    if kind == "launcher":
        return target
    return None


def validate_owned_pin(pin_path, owned_root, token):
    """Check the pin path against the run's owned root.

    Returns None when the pin is inside the owned root (and, when a
    token is given, inside the token directory), else a refusal note.
    Malformed inputs are refused, never normalized into shape.
    Containment is checked lexically first, then resolved: both
    paths are resolved through existing symlinks and compared
    again, so an escape through an ancestor symlink is refused.
    """
    if not owned_root or not os.path.isabs(owned_root):
        return "owned root %r is not absolute" % (owned_root,)
    if os.path.normpath(owned_root) != owned_root:
        return "owned root %r is malformed" % (owned_root,)
    if not pin_path or not os.path.isabs(pin_path):
        return "pin path %r is not absolute" % (pin_path,)
    if os.path.normpath(pin_path) != pin_path:
        return "pin path %r is malformed" % (pin_path,)
    if pin_path == owned_root:
        return "pin path %r is the owned root itself" % (pin_path,)
    try:
        common = os.path.commonpath([owned_root, pin_path])
    except ValueError:
        return "pin path %r is outside the owned root" % (pin_path,)
    if common != owned_root:
        return "pin path %r is outside the owned root" % (pin_path,)
    resolved_root = os.path.realpath(owned_root)
    resolved_pin = os.path.realpath(pin_path)
    if resolved_pin == resolved_root:
        return "pin path %r resolves to the owned root itself" % (
            pin_path,
        )
    try:
        resolved_common = os.path.commonpath(
            [resolved_root, resolved_pin]
        )
    except ValueError:
        return "pin path %r resolves outside the owned root" % (
            pin_path,
        )
    if resolved_common != resolved_root:
        return "pin path %r resolves outside the owned root" % (
            pin_path,
        )
    if token is not None:
        if (
            not token
            or token in (".", "..")
            or os.sep in token
            or (os.altsep is not None and os.altsep in token)
            or os.path.normpath(token) != token
        ):
            return "ownership token %r is malformed" % (token,)
        token_dir = os.path.join(owned_root, token)
        if pin_path != token_dir and os.path.commonpath(
            [token_dir, pin_path]
        ) != token_dir:
            return "pin path %r carries another run's ownership token" % (
                pin_path,
            )
        resolved_token_dir = os.path.realpath(token_dir)
        try:
            token_common = os.path.commonpath(
                [resolved_root, resolved_token_dir]
            )
        except ValueError:
            token_common = None
        if token_common != resolved_root:
            return "ownership token %r resolves outside the owned root" % (
                token,
            )
        if resolved_pin != resolved_token_dir and os.path.commonpath(
            [resolved_token_dir, resolved_pin]
        ) != resolved_token_dir:
            return (
                "pin path %r resolves outside the owned run's "
                "directory" % (pin_path,)
            )
    return None


def admit_bpftool(path, expected_sha256, expected_exec_sha256):
    """Admit the bpftool entry against its pins before execution.

    Returns ``(realpath, entry_sha256, exec_path, exec_sha256, note)``
    with ``note`` None on admission, else the refusal note. No
    process starts on any path through this function.
    """
    try:
        realpath = os.path.realpath(path)
        entry_sha256 = sha256_file(realpath)
    except OSError as exc:
        return (
            None,
            None,
            None,
            None,
            "cannot hash bpftool binary %s: %s" % (path, exc),
        )
    if entry_sha256 != expected_sha256:
        return (
            realpath,
            entry_sha256,
            None,
            None,
            "bpftool admission refused: entry hash %s does not match "
            "the pinned hash" % entry_sha256,
        )
    chain_kind, exec_path, chain_note = classify_exec_chain(realpath)
    if chain_kind == "unknown":
        return (
            realpath,
            entry_sha256,
            None,
            None,
            "bpftool admission refused: unresolvable launcher "
            "chain (%s)" % chain_note,
        )
    exec_sha256 = None
    if exec_path is not None:
        try:
            exec_sha256 = sha256_file(exec_path)
        except OSError as exc:
            return (
                realpath,
                entry_sha256,
                exec_path,
                None,
                "cannot hash bpftool exec image %s: %s" % (exec_path, exc),
            )
    if exec_path is not None and expected_exec_sha256 is None:
        return (
            realpath,
            entry_sha256,
            exec_path,
            exec_sha256,
            "bpftool admission refused: launcher exec chain is not "
            "pinned",
        )
    if exec_path is None and expected_exec_sha256 is not None:
        return (
            realpath,
            entry_sha256,
            None,
            None,
            "bpftool admission refused: exec chain pinned but the "
            "entry is its own image",
        )
    if exec_sha256 != expected_exec_sha256:
        return (
            realpath,
            entry_sha256,
            exec_path,
            exec_sha256,
            "bpftool admission refused: exec image hash %s does not "
            "match the pinned hash" % exec_sha256,
        )
    return (realpath, entry_sha256, exec_path, exec_sha256, None)


def run_command(argv, timeout):
    """Run argv, capturing text output. Never raises on nonzero exit."""
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return {
            "argv": list(argv),
            "exit_code": completed.returncode,
            "stdout": completed.stdout.decode("utf-8", "replace"),
            "stderr": completed.stderr.decode("utf-8", "replace"),
            "timeout": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "argv": list(argv),
            "exit_code": None,
            "stdout": (exc.stdout or b"").decode("utf-8", "replace"),
            "stderr": (exc.stderr or b"").decode("utf-8", "replace"),
            "timeout": True,
        }


def classify_load_failure(record):
    blob = (record.get("stdout", "") + "\n" + record.get("stderr", "")).lower()
    if record.get("timeout"):
        return "environment"
    if any(pattern in blob for pattern in _VERIFIER_PATTERNS):
        return "verifier"
    if any(pattern in blob for pattern in _PERMISSION_PATTERNS):
        return "environment"
    return "loader"


def parse_return_value(text):
    match = re.search(r"return value:\s*(\d+)", text, re.IGNORECASE)
    if match is None:
        return None
    return int(match.group(1))


def build_parser():
    parser = argparse.ArgumentParser(
        description="Load one BPF program, run one kernel test-run, unload."
    )
    parser.add_argument("--object", required=True, help="BPF ELF object to load")
    parser.add_argument(
        "--expect-action",
        required=True,
        type=int,
        help="Required exact test-run return value",
    )
    parser.add_argument(
        "--data-in",
        default=None,
        help="Packet bytes for the test-run (default: 60 zero bytes)",
    )
    parser.add_argument("--repeat", type=int, default=DEFAULT_REPEAT)
    parser.add_argument("--pin-path", default=DEFAULT_PIN_PATH)
    parser.add_argument("--owned-root", default=DEFAULT_OWNED_ROOT)
    parser.add_argument("--ownership-token", default=None)
    parser.add_argument("--bpftool", default="bpftool")
    parser.add_argument("--bpftool-sha256", default=None)
    parser.add_argument("--bpftool-exec-sha256", default=None)
    parser.add_argument("--bpftool-version", default=None)
    parser.add_argument("--output", default=None)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    return parser


def emit(result, output_path):
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if output_path:
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not __debug__:
        sys.stderr.write(
            "REFUSED: must not run under python -O (checks stripped)\n"
        )
        return 2
    commands = []
    result = {
        "tool": "bpf_test_run",
        "contract_version": CONTRACT_VERSION,
        "status": "fail",
        "stage": "setup",
        "classification": "setup",
        "expected_action": args.expect_action,
        "actual_action": None,
        "repeat": args.repeat,
        "pin_path": args.pin_path,
        "object": {"path": args.object, "sha256": None},
        "data_in": {"path": args.data_in, "sha256": None, "size": None},
        "bpftool": {"path": None, "version": None},
        "runtime": {"uid": os.geteuid(), "kernel_release": platform.release()},
        "commands": commands,
        "cleanup_ok": None,
        "note": None,
    }

    def fail(stage, classification, exit_code, note=None):
        result["stage"] = stage
        result["classification"] = classification
        result["note"] = note
        emit(result, args.output)
        sys.stderr.write(
            "FAIL stage=%s classification=%s expected=%s actual=%s\n"
            % (stage, classification, args.expect_action, result["actual_action"])
        )
        return exit_code

    pin_note = validate_owned_pin(
        args.pin_path, args.owned_root, args.ownership_token
    )
    if pin_note is not None:
        return fail("setup", "setup", EXIT_SETUP, pin_note)
    if args.bpftool_sha256 is None:
        return fail(
            "setup",
            "setup",
            EXIT_SETUP,
            "bpftool admission refused: --bpftool-sha256 is "
            "mandatory (no unadmitted execution path)",
        )
    if args.bpftool_version is None:
        return fail(
            "setup",
            "setup",
            EXIT_SETUP,
            "bpftool admission refused: --bpftool-version is "
            "mandatory alongside the entry pin",
        )
    if args.ownership_token is None:
        return fail(
            "setup",
            "setup",
            EXIT_SETUP,
            "run ownership refused: --ownership-token is mandatory "
            "(pins are contained to the owned run root)",
        )
    result["admission"] = {
        "bpftool_admitted": None,
        "owned_root": args.owned_root,
        "ownership_token": args.ownership_token,
    }

    if not os.path.isfile(args.object):
        return fail("setup", "setup", EXIT_SETUP, "object file not found")
    result["object"]["sha256"] = sha256_file(args.object)

    data_path = args.data_in
    generated_data = None
    try:
        if data_path is None:
            with tempfile.NamedTemporaryFile(
                prefix="bpf_test_run_", suffix=".bin", delete=False
            ) as handle:
                # The allocated name registers for cleanup before
                # the first write: a write failure must still
                # unlink the owned packet.
                generated_data = handle.name
                handle.write(b"\x00" * DEFAULT_FRAME_SIZE)
            data_path = generated_data
            result["data_in"]["path"] = (
                "generated:%d-zero-bytes" % DEFAULT_FRAME_SIZE
            )
        if not os.path.isfile(data_path):
            return fail(
                "setup", "setup", EXIT_SETUP, "data-in file not found"
            )
        result["data_in"]["sha256"] = sha256_file(data_path)
        result["data_in"]["size"] = os.path.getsize(data_path)

        bpftool_path = shutil.which(args.bpftool)
        if bpftool_path is None:
            return fail(
                "setup", "setup", EXIT_SETUP, "bpftool binary not found"
            )
        result["bpftool"]["path"] = bpftool_path
        (
            admitted_realpath,
            entry_sha256,
            exec_path,
            exec_sha256,
            admission_note,
        ) = admit_bpftool(
            bpftool_path,
            args.bpftool_sha256,
            args.bpftool_exec_sha256,
        )
        result["bpftool"]["entry_sha256"] = entry_sha256
        result["bpftool"]["exec_path"] = exec_path
        result["bpftool"]["exec_sha256"] = exec_sha256
        if admission_note is not None:
            result["admission"]["bpftool_admitted"] = False
            return fail(
                "setup", "setup", EXIT_SETUP, admission_note
            )
        result["admission"]["bpftool_admitted"] = True
        bpftool_argv0 = admitted_realpath
        result["bpftool"]["path"] = admitted_realpath
        version_record = run_command(
            [bpftool_argv0, "version"], args.timeout
        )
        commands.append(version_record)
        if version_record["exit_code"] == 0:
            first_line = version_record["stdout"].splitlines()
            result["bpftool"]["version"] = (
                first_line[0] if first_line else ""
            )
        else:
            return fail(
                "setup",
                "environment",
                EXIT_ENVIRONMENT,
                "bpftool version failed",
            )
        if result["bpftool"]["version"] != args.bpftool_version:
            return fail(
                "setup",
                "setup",
                EXIT_SETUP,
                "bpftool version %r does not match the pinned "
                "version %r"
                % (result["bpftool"]["version"], args.bpftool_version),
            )

        pin_note = validate_owned_pin(
            args.pin_path, args.owned_root, args.ownership_token
        )
        if pin_note is not None:
            return fail("setup", "setup", EXIT_SETUP, pin_note)
        load_record = run_command(
            [bpftool_argv0, "prog", "load", args.object, args.pin_path],
            args.timeout,
        )
        commands.append(load_record)
        if load_record["exit_code"] != 0:
            classification = classify_load_failure(load_record)
            exit_code = {
                "environment": EXIT_ENVIRONMENT,
                "verifier": EXIT_VERIFIER,
            }.get(classification, EXIT_LOADER)
            return fail("load", classification, exit_code)

        outcome = None
        unload_note = None
        try:
            run_record = run_command(
                [
                    bpftool_argv0,
                    "prog",
                    "run",
                    "pinned",
                    args.pin_path,
                    "data_in",
                    data_path,
                    "repeat",
                    str(args.repeat),
                ],
                args.timeout,
            )
            commands.append(run_record)
            if run_record["exit_code"] != 0:
                blob = (
                    run_record["stdout"] + "\n" + run_record["stderr"]
                ).lower()
                if run_record["timeout"] or any(
                    pattern in blob for pattern in _PERMISSION_PATTERNS
                ):
                    outcome = (
                        "run", "environment", EXIT_ENVIRONMENT, None
                    )
                else:
                    outcome = (
                        "run",
                        "runtime",
                        EXIT_RUNTIME,
                        "test-run command failed",
                    )
            else:
                actual = parse_return_value(
                    run_record["stdout"] + run_record["stderr"]
                )
                result["actual_action"] = actual
                if actual is None:
                    outcome = (
                        "run",
                        "runtime",
                        EXIT_RUNTIME,
                        "could not parse return value",
                    )
                elif actual != args.expect_action:
                    outcome = (
                        "run",
                        "runtime",
                        EXIT_RUNTIME,
                        "return value mismatch",
                    )
        finally:
            unload_pin_note = validate_owned_pin(
                args.pin_path, args.owned_root, args.ownership_token
            )
            if unload_pin_note is not None:
                unload_note = unload_pin_note
                result["cleanup_ok"] = False
            else:
                unload_record = run_command(
                    ["rm", "-f", args.pin_path], args.timeout
                )
                commands.append(unload_record)
                result["cleanup_ok"] = (
                    unload_record["exit_code"] == 0
                    and not os.path.exists(args.pin_path)
                )

        if outcome is not None:
            return fail(*outcome)

        if not result["cleanup_ok"]:
            return fail(
                "unload",
                "environment",
                EXIT_ENVIRONMENT,
                unload_note or "pin path remains",
            )
        result["status"] = "pass"
        result["stage"] = "run"
        result["classification"] = None
        emit(result, args.output)
        sys.stderr.write(
            "PASS action=%s expected=%s\n"
            % (result["actual_action"], args.expect_action)
        )
        return EXIT_PASS
    finally:
        if generated_data is not None:
            try:
                os.unlink(generated_data)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
