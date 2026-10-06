# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Minimal BPF load / test-run / unload harness (bpftool-driven).

Frozen contract revision 1 (consumed additively by later work; do not change
existing flags, JSON keys, or exit codes -- extend only):

  python3 tests/harness/bpf_test_run.py --object OBJ --expect-action N \
      [--data-in FILE] [--repeat 1] [--pin-path PATH] [--bpftool BIN] \
      [--output FILE] [--timeout SECS]

Behavior: record the object hash, load exactly one program with
``bpftool prog load``, execute one kernel test-run
(``bpftool prog run ... repeat N``), require the return value to equal
``--expect-action`` exactly, then unpin (unload). Cleanup is attempted even
when the run step fails.

Failure layers stay distinct (exit code in parentheses):

  * ``setup`` (6): missing input file or missing bpftool binary.
  * ``environment`` (3): tooling/permission failure, e.g. load denied with
    "Operation not permitted" when run without the required capabilities.
  * ``verifier`` (4): the kernel verifier rejected the program.
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
import shutil
import subprocess
import sys
import tempfile

CONTRACT_VERSION = 1

EXIT_PASS = 0
EXIT_RUNTIME = 1
# EXIT 2 is reserved for CLI usage errors (argparse).
EXIT_ENVIRONMENT = 3
EXIT_VERIFIER = 4
EXIT_LOADER = 5
EXIT_SETUP = 6

DEFAULT_PIN_PATH = "/sys/fs/bpf/mojobpf_control"
DEFAULT_REPEAT = 1
DEFAULT_TIMEOUT = 120
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
    if any(pattern in blob for pattern in _PERMISSION_PATTERNS):
        return "environment"
    if any(pattern in blob for pattern in _VERIFIER_PATTERNS):
        return "verifier"
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
    parser.add_argument("--bpftool", default="bpftool")
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

    if not os.path.isfile(args.object):
        return fail("setup", "setup", EXIT_SETUP, "object file not found")
    result["object"]["sha256"] = sha256_file(args.object)

    data_path = args.data_in
    generated_data = None
    if data_path is None:
        with tempfile.NamedTemporaryFile(
            prefix="bpf_test_run_", suffix=".bin", delete=False
        ) as handle:
            handle.write(b"\x00" * DEFAULT_FRAME_SIZE)
            generated_data = handle.name
        data_path = generated_data
        result["data_in"]["path"] = "generated:%d-zero-bytes" % DEFAULT_FRAME_SIZE
    if not os.path.isfile(data_path):
        return fail("setup", "setup", EXIT_SETUP, "data-in file not found")
    result["data_in"]["sha256"] = sha256_file(data_path)
    result["data_in"]["size"] = os.path.getsize(data_path)

    bpftool_path = shutil.which(args.bpftool)
    if bpftool_path is None:
        return fail("setup", "setup", EXIT_SETUP, "bpftool binary not found")
    result["bpftool"]["path"] = bpftool_path
    version_record = run_command([bpftool_path, "version"], args.timeout)
    commands.append(version_record)
    if version_record["exit_code"] == 0:
        first_line = version_record["stdout"].splitlines()
        result["bpftool"]["version"] = first_line[0] if first_line else ""
    else:
        return fail("setup", "environment", EXIT_SETUP, "bpftool version failed")

    load_record = run_command(
        [bpftool_path, "prog", "load", args.object, args.pin_path], args.timeout
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
    try:
        run_record = run_command(
            [
                bpftool_path,
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
            blob = (run_record["stdout"] + "\n" + run_record["stderr"]).lower()
            if run_record["timeout"] or any(
                pattern in blob for pattern in _PERMISSION_PATTERNS
            ):
                outcome = ("run", "environment", EXIT_ENVIRONMENT, None)
            else:
                outcome = ("run", "runtime", EXIT_RUNTIME, "test-run command failed")
        else:
            actual = parse_return_value(run_record["stdout"] + run_record["stderr"])
            result["actual_action"] = actual
            if actual is None:
                outcome = (
                    "run",
                    "runtime",
                    EXIT_RUNTIME,
                    "could not parse return value",
                )
            elif actual != args.expect_action:
                outcome = ("run", "runtime", EXIT_RUNTIME, "return value mismatch")
    finally:
        if generated_data is not None:
            try:
                os.unlink(generated_data)
            except OSError:
                pass
        unload_record = run_command(["rm", "-f", args.pin_path], args.timeout)
        commands.append(unload_record)
        result["cleanup_ok"] = (
            unload_record["exit_code"] == 0 and not os.path.exists(args.pin_path)
        )

    if outcome is not None:
        return fail(*outcome)

    if not result["cleanup_ok"]:
        return fail("unload", "environment", EXIT_ENVIRONMENT, "pin path remains")
    result["status"] = "pass"
    result["stage"] = "run"
    result["classification"] = None
    emit(result, args.output)
    sys.stderr.write(
        "PASS action=%s expected=%s\n" % (result["actual_action"], args.expect_action)
    )
    return EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
