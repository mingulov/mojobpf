# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Guest-backed load-and-unload verification for BPF objects.

:func:`run_verification` boots one disposable Linux guest through the
``vng`` runner, loads exactly one program there with ``bpftool prog
load``, unloads it again by removing its pin, and reports what
happened. The wrapper itself runs unprivileged on the host: it never
loads a program on the host, never runs ``bpftool prog run``, never
attaches a program to any hook, and never creates links, map pins, or
network state. The guest script it stages contains no attach, run, or
link primitives (pinned by ``tests/unit/test_verify.py``), and every
guest-side command is recorded in the result so the absence of
attachment is auditable per run.

The runner is admitted through ``execution-contract-v1`` before any
guest boots: the ``vng`` entry, its ``exec`` chain, the Python
interpreter behind its console script, the ``virtme_ng`` package
modules it imports, the ``virtme-run`` launcher ``vng`` invokes
through a shell plus its ``virtme.*`` implementation, and the
selected QEMU emulator are all hash-checked against the kernels
lock, and the lock's distribution bindings are enforced. Only the
admitted chain runs -- under the sanitized environment with a
``PATH`` farm forcing the admitted ``vng``/``virtme-run``/QEMU
binaries. An arbitrary ``vng`` on ``PATH`` or a ``PYTHONPATH``
package shadow is refused before any process starts.

Failure layers stay distinct, mirroring the kernel test-run harness
(``tests/harness/bpf_test_run.py``, contract revision 2):

* ``setup``: the object, the runner, or the stage is unusable.
* ``preflight`` / ``environment``: the guest cannot host this object
  (kernel BTF missing while required, the requested program type,
  map type, or trace event unsupported, no privilege), so no load
  is attempted or the load was denied without verifier evidence.
* ``verifier``: the kernel verifier rejected the program. Explicit
  verifier evidence takes precedence over permission substrings.
* ``loader``: libbpf/bpftool could not load the object for another
  reason (not an eBPF object, truncated ELF, ...).
* ``timeout``: the guest command exceeded its budget. The whole
  runner process group is killed and reaped, so no stray emulator
  survives; the result is a timeout, never a pass.

The guest command runs in its own process group
(``start_new_session=True``); timeouts, SIGTERM, and SIGINT all kill
that group before returning, and the result records whether the group
was reaped cleanly.

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import struct
import subprocess
import sys
import tempfile
import time

from .execution import (
    AdmissionError,
    ExecutionPins,
    ExecutionRequest,
    admit_execution,
    build_path_farm,
    farm_path_prefix,
    popen_admitted,
    qemu_pins,
    runner_pins,
    summarize,
    verify_emulator_claim,
    verify_runner_dependencies,
    verify_runner_distribution,
    virtme_run_pins,
)

TOOL_NAME = "mojobpf-verify-kernel"
RESULT_SCHEMA = 1

DEFAULT_PIN_PATH = "/sys/fs/bpf/mojobpf_verify"
DEFAULT_RELEASE = "v6.12"
DEFAULT_TIMEOUT = 600
DEFAULT_KERNEL_BTF = "/sys/kernel/btf/vmlinux"
DEFAULT_PROG_TYPE = "xdp"

RELEASE_ENV_VAR = "MOJOBPF_VNG_RELEASE"

# Guest-script exit codes (distinct from the harness contract: this
# wrapper never test-runs, so it owns its own small numbers).
GUEST_PREFLIGHT_UNAVAILABLE = 10
GUEST_LOAD_FAILED = 11

# Load-failure classification patterns. These mirror the kernel
# test-run harness (contract revision 2) verbatim so one message
# classifies identically in both tools; tests/unit/test_verify.py
# pins the two lists against each other. Verifier patterns are
# checked before permission patterns.
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

# Primitives that must never appear in the staged guest script.
# Read-only listings (``prog list``, ``map list``, ``link list``) are
# allowed: they observe owned resources without attaching anything.
_FORBIDDEN_GUEST_TOKENS = (
    "attach",
    "detach",
    "prog run",
    "link pin",
    "map pin",
    "net attach",
    "tc filter",
    "test-run",
)

# Staged object name inside the guest stage (fixed so hostile source
# file names can never reach the guest shell command line).
STAGED_OBJECT_NAME = "verify-target.o"

# Allowed shape for every value interpolated into the guest script.
# ``\Z`` (not ``$``) anchors the end so a trailing newline can never
# slip through: ``$`` also matches before a trailing newline.
_SAFE_TOKEN = re.compile(r"^/?[A-Za-z0-9_][A-Za-z0-9_.,:/=@-]*\Z")

# Map-type and trace-selector names are matched literally in the guest
# (never as patterns) and interpolated into shell double quotes, so
# they are restricted to identifier characters. Every bpftool-known
# map_type name matches this shape, as does every tracefs
# category/event name the preflight supports (tracepoint names are
# C identifiers, and categories such as ``9p`` still match);
# hyphenated categories (``intel-sst``) and anything else are
# necessarily unsupported and fail closed here instead of probing
# something they did not name.
_NAME_TOKEN = re.compile(r"[A-Za-z0-9_]+")


def sha256_file(path: str) -> str:
    """Return the hex SHA-256 of a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def classify_load_output(stdout: str, stderr: str, timed_out: bool) -> str:
    """Classify a failed ``bpftool prog load`` as verifier/environment/loader."""
    if timed_out:
        return "environment"
    blob = (stdout + "\n" + stderr).lower()
    if any(pattern in blob for pattern in _VERIFIER_PATTERNS):
        return "verifier"
    if any(pattern in blob for pattern in _PERMISSION_PATTERNS):
        return "environment"
    return "loader"


def read_elf_sections(path: str) -> tuple[list[str], bytes | None]:
    """Return ``(section names, license bytes or None)`` for an ELF file.

    Raises ``ValueError`` when the file is not a parseable 64-bit
    little-endian ELF object. The parse is informational only: callers
    must still attempt the genuine load so the loader's own verdict
    (not this reader) decides the classification.
    """
    with open(path, "rb") as handle:
        image = handle.read()
    if len(image) < 64 or image[0:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if image[4] != 2 or image[5] != 1 or image[6] != 1:
        raise ValueError("not a 64-bit little-endian ELF file")
    (
        _etype, _machine, _eversion, _entry, _phoff, shoff,
        _flags, _ehsize, _phentsize, _phnum, shentsize, shnum,
        shstrndx,
    ) = struct.unpack("<HHIQQQIHHHHHH", image[16:64])
    if shentsize < 64 or shoff + shentsize * shnum > len(image):
        raise ValueError("bad section table")
    raw_sections = []
    for index in range(shnum):
        base = shoff + index * shentsize
        (_name, _kind, _flags, _addr, offset, size) = struct.unpack(
            "<IIQQQQ", image[base:base + 40]
        )
        if offset + size > len(image):
            raise ValueError("section %d runs past end" % index)
        raw_sections.append((_name, offset, size))
    names: list[str] = []
    strtab = b""
    if raw_sections:
        if shstrndx >= len(raw_sections):
            raise ValueError("bad section-name table")
        _name, offset, size = raw_sections[shstrndx]
        strtab = image[offset:offset + size]
    for name_off, _offset, _size in raw_sections:
        end = strtab.find(b"\x00", name_off)
        if name_off >= len(strtab) or end < 0:
            names.append("")
        else:
            names.append(strtab[name_off:end].decode("ascii", "replace"))
    license_bytes: bytes | None = None
    for (name, (_name_off, offset, size)) in zip(names, raw_sections):
        if name == "license":
            license_bytes = image[offset:offset + size]
    return names, license_bytes


GUEST_SCRIPT_TEMPLATE = """#!/bin/bash
# Staged by mojobpf verify --kernel. Loads one object, unloads it
# again, and reports. No hook binding, no program execution.
set -u
export PYTHONDONTWRITEBYTECODE=1
STAGE="{stage}"
OBJ="$STAGE/{object_name}"
PIN="{pin}"
PROG_TYPE="{prog_type}"
BTF_PATH="{btf_path}"
REQUIRE_BTF="{require_btf}"
AS_USER="{as_user}"
cd "$STAGE"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin verify_kernel ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
bpftool version | head -2
echo "=== staged hashes ==="
sha256sum {object_name}
if [ -e "$BTF_PATH" ]; then echo "kernel_btf=present"; else echo "kernel_btf=absent"; fi
echo "guest-cmd: bpftool feature probe kernel"
bpftool feature probe kernel > "$STAGE/feature.txt" 2>&1
PROBE_LINE=$(grep -F "program_type $PROG_TYPE is" "$STAGE/feature.txt" | head -1 || true)
echo "probe_line=$PROBE_LINE"
case "$PROBE_LINE" in
  *"is NOT available"*) SUPPORTED=0 ;;
  *"is available"*) SUPPORTED=1 ;;
  *) SUPPORTED=unknown ;;
esac
echo "prog_type_supported=$SUPPORTED"
echo "guest-cmd: probe map types and trace event"
MAP_TYPES="{map_types}"
TRACE_EVENT="{trace_event}"
MAP_PREFLIGHT_OK=1
MAP_FAILED=""
for MAP_TYPE in $MAP_TYPES; do
  MAP_PROBE_LINE=$(grep -F "map_type $MAP_TYPE is" "$STAGE/feature.txt" | head -1 || true)
  echo "map_probe_line[$MAP_TYPE]=$MAP_PROBE_LINE"
  case "$MAP_PROBE_LINE" in
    *"is NOT available"*) MAP_SUPPORTED=0 ;;
    *"is available"*) MAP_SUPPORTED=1 ;;
    *) MAP_SUPPORTED=unknown ;;
  esac
  echo "map_type_supported[$MAP_TYPE]=$MAP_SUPPORTED"
  if [ "$MAP_SUPPORTED" != "1" ]; then MAP_PREFLIGHT_OK=0; MAP_FAILED="$MAP_TYPE"; fi
done
echo "map_preflight_ok=$MAP_PREFLIGHT_OK"
echo "map_failed=$MAP_FAILED"
TRACE_SUPPORTED=unknown
TRACE_ID_PATH=""
if [ -n "$TRACE_EVENT" ]; then
  TRACE_CAT=$(echo "$TRACE_EVENT" | cut -d: -f1)
  TRACE_NAME=$(echo "$TRACE_EVENT" | cut -d: -f2)
  for TRACE_ROOT in /sys/kernel/tracing/events /sys/kernel/debug/tracing/events; do
    if [ -e "$TRACE_ROOT/$TRACE_CAT/$TRACE_NAME/id" ]; then TRACE_ID_PATH="$TRACE_ROOT/$TRACE_CAT/$TRACE_NAME/id"; break; fi
  done
  if [ -n "$TRACE_ID_PATH" ]; then TRACE_SUPPORTED=1; else TRACE_SUPPORTED=0; fi
fi
echo "trace_event_supported=$TRACE_SUPPORTED"
echo "trace_event_id=$TRACE_ID_PATH"
echo "guest-cmd: bpftool prog list; bpftool map list; bpftool link list; ls /sys/fs/bpf"
echo "=== BEGIN snapshot-before ==="
bpftool prog list 2>&1 | head -40
bpftool map list 2>&1 | head -40
bpftool link list 2>&1 | head -40
ls /sys/fs/bpf/ 2>&1
echo "=== END snapshot-before ==="
if [ "$REQUIRE_BTF" = "1" ] && [ ! -e "$BTF_PATH" ]; then
  echo "PREFLIGHT_UNAVAILABLE missing-btf"
  echo "=== end verify_kernel ==="
  exit {guest_preflight}
fi
if [ "$SUPPORTED" != "1" ]; then
  echo "PREFLIGHT_UNAVAILABLE unsupported-prog-type"
  echo "=== end verify_kernel ==="
  exit {guest_preflight}
fi
if [ "$MAP_PREFLIGHT_OK" != "1" ]; then
  echo "PREFLIGHT_UNAVAILABLE unsupported-map-type"
  echo "=== end verify_kernel ==="
  exit {guest_preflight}
fi
if [ -n "$TRACE_EVENT" ] && [ "$TRACE_SUPPORTED" != "1" ]; then
  echo "PREFLIGHT_UNAVAILABLE unsupported-trace-event"
  echo "=== end verify_kernel ==="
  exit {guest_preflight}
fi
if [ -n "$AS_USER" ]; then
  id "$AS_USER" >/dev/null 2>&1 || {{
    echo "PREFLIGHT_UNAVAILABLE unknown-user"
    echo "=== end verify_kernel ==="
    exit {guest_preflight}
  }}
  AS_GID=$(id -g "$AS_USER")
  LOAD_RUN="setpriv --reuid=$AS_USER --regid=$AS_GID --clear-groups bpftool"
else
  LOAD_RUN="bpftool"
fi
echo "guest-cmd: $LOAD_RUN prog load $OBJ $PIN"
# Unquoted LOAD_RUN word-splits deliberately (bpftool or setpriv prefix).
$LOAD_RUN prog load "$OBJ" "$PIN" >"$STAGE/load.out" 2>&1
LOAD_EXIT=$?
echo "load_exit=$LOAD_EXIT"
echo "=== BEGIN load-log ==="
cat "$STAGE/load.out"
echo "=== END load-log ==="
if [ "$LOAD_EXIT" -ne 0 ]; then
  echo "=== end verify_kernel ==="
  exit {guest_load_failed}
fi
echo "guest-cmd: rm -f $PIN"
rm -f "$PIN"
# Pin removal is synchronous, but the kernel may free the program
# asynchronously (observed: still listed for ~2s under emulation),
# so quiesce on two identical consecutive listings before the
# after-snapshot. Bounded: 60 polls, 1s apart.
QUIESCED=0
QUIESCE_WAITS=0
PREV="__unset__"
for i in $(seq 1 60); do
  QUIESCE_WAITS=$i
  if [ -e "$PIN" ]; then sleep 1; continue; fi
  CUR=$(bpftool prog list 2>&1; bpftool map list 2>&1; bpftool link list 2>&1)
  if [ "$PREV" != "__unset__" ] && [ "$CUR" = "$PREV" ]; then
    QUIESCED=1
    break
  fi
  PREV="$CUR"
  sleep 1
done
if [ "$QUIESCED" = "1" ]; then echo "unload_ok=1"; else echo "unload_ok=0"; fi
echo "quiesced=$QUIESCED"
echo "quiesce_waits=$QUIESCE_WAITS"
echo "guest-cmd: bpftool prog list; bpftool map list; bpftool link list; ls /sys/fs/bpf"
echo "=== BEGIN snapshot-after ==="
bpftool prog list 2>&1 | head -40
bpftool map list 2>&1 | head -40
bpftool link list 2>&1 | head -40
ls /sys/fs/bpf/ 2>&1
echo "=== END snapshot-after ==="
echo "=== end verify_kernel ==="
"""


class VerifyError(Exception):
    """Setup failure: the verification could not be attempted."""


class VerifyInterrupted(Exception):
    """The verification was interrupted; the guest group was killed."""


class VerifyRequest:
    """Inputs for one load-and-unload verification."""

    def __init__(
        self,
        object_path: str,
        release: str | None = None,
        accelerator: str = "tcg",
        vng_path: str | None = None,
        pin_path: str = DEFAULT_PIN_PATH,
        prog_type: str = DEFAULT_PROG_TYPE,
        map_types: tuple[str, ...] | list[str] = (),
        trace_event: str | None = None,
        require_btf: str = "auto",
        kernel_btf: str = DEFAULT_KERNEL_BTF,
        as_user: str | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        kernels_lock: str | None = None,
    ) -> None:
        if accelerator not in ("tcg", "kvm"):
            raise VerifyError("accelerator must be 'tcg' or 'kvm'")
        if require_btf not in ("auto", "yes", "no"):
            raise VerifyError("require_btf must be 'auto', 'yes', or 'no'")
        if timeout <= 0:
            raise VerifyError("timeout must be positive")
        if kernels_lock is not None and not isinstance(kernels_lock, str):
            raise VerifyError("kernels lock path must be a string or None")
        if not pin_path.startswith("/sys/fs/bpf/"):
            raise VerifyError("pin path must live under /sys/fs/bpf/")
        if isinstance(map_types, str) or not isinstance(
            map_types, (tuple, list)
        ):
            raise VerifyError("map_types must be a tuple or list of names")
        for label, value in (
            ("release", release or ""),
            ("pin path", pin_path),
            ("program type", prog_type),
            ("kernel BTF path", kernel_btf),
        ):
            if value and _SAFE_TOKEN.match(value) is None:
                raise VerifyError(
                    "%s carries characters outside [A-Za-z0-9_.,:/=@-]: %r"
                    % (label, value)
                )
        for map_type in map_types:
            if not isinstance(map_type, str) or (
                _NAME_TOKEN.fullmatch(map_type) is None
            ):
                raise VerifyError(
                    "map type must look like an identifier "
                    "[A-Za-z0-9_]: %r" % (map_type,)
                )
        if trace_event is not None:
            if not isinstance(trace_event, str):
                raise VerifyError(
                    "trace event must look like 'category:name': %r"
                    % (trace_event,)
                )
            parts = trace_event.split(":")
            if (
                len(parts) != 2
                or _NAME_TOKEN.fullmatch(parts[0]) is None
                or _NAME_TOKEN.fullmatch(parts[1]) is None
            ):
                raise VerifyError(
                    "trace event must look like 'category:name' with "
                    "identifier components [A-Za-z0-9_]: %r"
                    % (trace_event,)
                )
        if as_user is not None and _SAFE_TOKEN.match(as_user) is None:
            raise VerifyError("user name carries unsafe characters: %r" % as_user)
        self.object_path = object_path
        self.release = (
            release
            if release is not None
            else os.environ.get(RELEASE_ENV_VAR, DEFAULT_RELEASE)
        )
        self.accelerator = accelerator
        self.vng_path = vng_path
        self.pin_path = pin_path
        self.prog_type = prog_type
        self.map_types = tuple(map_types)
        self.trace_event = trace_event
        self.require_btf = require_btf
        self.kernel_btf = kernel_btf
        self.as_user = as_user
        self.timeout = timeout
        self.kernels_lock = kernels_lock


def _parse_marked_block(output: str, tag: str) -> str | None:
    match = re.search(
        r"=== BEGIN %s ===\n(.*?)\n=== END %s ===" % (
            re.escape(tag), re.escape(tag),
        ),
        output,
        re.DOTALL,
    )
    return match.group(1) if match else None


def _parse_line_value(output: str, key: str) -> str | None:
    match = re.search(r"^%s=(.*)$" % re.escape(key), output, re.MULTILINE)
    return match.group(1).strip() if match else None


def default_kernels_lock() -> str | None:
    """Return the checkout's kernels lockfile path, or None.

    Resolves ``ci/kernels.lock.json`` relative to this package, so
    checkout use needs no flag. Installed contexts without the
    file must pass an explicit lock.
    """
    candidate = os.path.join(
        os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        ),
        "ci",
        "kernels.lock.json",
    )
    if os.path.isfile(candidate):
        return candidate
    return None


def _load_runner_pins(lock_path: str) -> tuple[dict, dict | None]:
    """Load the kernels lock's runner pins plus distribution (no probing)."""
    if not os.path.isfile(lock_path):
        raise VerifyError("kernels lock not found: %s" % lock_path)
    try:
        with open(lock_path, encoding="utf-8") as handle:
            lock = json.load(handle)
    except (OSError, ValueError) as exc:
        raise VerifyError(
            "kernels lock %s is unreadable: %s" % (lock_path, exc)
        )
    if not isinstance(lock, dict) or lock.get("schema_version") != 1:
        raise VerifyError("kernels lock schema_version must be 1")
    runner = lock.get("runner")
    if not isinstance(runner, dict) or runner.get("name") != "vng":
        raise VerifyError("kernels lock runner must name vng")
    for key in ("version", "sha256", "qemu"):
        if not runner.get(key):
            raise VerifyError("kernels lock runner lacks %s" % key)
    distribution = lock.get("distribution")
    if distribution is not None and not isinstance(distribution, dict):
        raise VerifyError("kernels lock distribution must be a mapping")
    return runner, distribution


def _runner_pins(runner: dict) -> ExecutionPins:
    """Build vng admission pins from the lock's runner record."""
    try:
        return runner_pins(runner)
    except ValueError as exc:
        raise VerifyError("kernels lock runner is malformed: %s" % (exc,))


def _launcher_pins(runner: dict) -> tuple[str, ExecutionPins]:
    """Build virtme-run admission pins from the lock's runner record."""
    try:
        return virtme_run_pins(runner)
    except ValueError as exc:
        raise VerifyError("kernels lock %s" % (exc,))


def _probe_vng(
    vng_path: str | None,
    *,
    kernels_lock: str | None = None,
    farm_parent: str | None = None,
    timeout: int = 60,
) -> dict:
    """Admit the vng runner plus its launcher and emulator.

    Resolves ``vng_path`` (or ``vng`` on ``PATH``) exactly once,
    hash-checks the entry, its ``exec`` chain, the console-script
    interpreter and the runner package modules, enforces the
    lock's distribution bindings, admits the locked
    ``virtme-run`` launcher and QEMU emulator the same way, and
    only then probes versions through the admitted chains. Any
    mismatch raises :class:`VerifyError` before any entry probe
    starts. Returns the runner record with the
    ``execution``/``virtme_run_execution``/``qemu_execution``
    admissions and the ``farm`` directory forcing admitted
    ``vng``/``virtme-run``/QEMU resolution; the caller owns farm
    cleanup.
    """
    lock_path = kernels_lock or default_kernels_lock()
    if lock_path is None:
        raise VerifyError(
            "kernels lock not found (pass --kernels-lock or run from "
            "a checkout carrying ci/kernels.lock.json)"
        )
    runner, distribution = _load_runner_pins(lock_path)
    trust_root = "lock:%s" % (lock_path,)
    try:
        static_admitted = admit_execution(
            ExecutionRequest(
                name="vng",
                argv0=vng_path or "vng",
                allow_path_lookup=vng_path is None,
                version_argv=("--version",),
                probe_version=False,
                trust_root=trust_root,
            ),
            _runner_pins(runner),
            probe_timeout=timeout,
        )
    except AdmissionError as exc:
        raise VerifyError("runner admission refused: %s" % (exc,))
    # Distribution bindings BEFORE any entry probe: the probes
    # execute distribution code (vng imports its dependencies at
    # startup), so unverified content must never reach them. The
    # emulator claim is checked against the lock's pinned version
    # here; the observed version is checked again after the
    # emulator probe below.
    try:
        verify_runner_dependencies(distribution, static_admitted)
        expected_qemu = runner.get("qemu")
        if expected_qemu is not None:
            verify_emulator_claim(distribution, expected_qemu)
    except ValueError as exc:
        raise VerifyError(
            "kernels lock distribution is malformed: %s" % (exc,)
        )
    except AdmissionError as exc:
        raise VerifyError("runner distribution refused: %s" % (exc,))
    try:
        admitted = admit_execution(
            ExecutionRequest(
                name="vng",
                argv0=vng_path or "vng",
                allow_path_lookup=vng_path is None,
                version_argv=("--version",),
                probe_version=True,
                trust_root=trust_root,
            ),
            _runner_pins(runner),
            probe_timeout=timeout,
        )
    except AdmissionError as exc:
        raise VerifyError("runner admission refused: %s" % (exc,))
    except UnicodeDecodeError as exc:
        raise VerifyError(
            "runner version probe printed undecodable output: %s" % (exc,)
        )
    try:
        qemu_binary, emulator_pins = qemu_pins(runner)
    except ValueError as exc:
        raise VerifyError("kernels lock %s" % (exc,))
    try:
        qemu_admitted = admit_execution(
            ExecutionRequest(
                name=qemu_binary,
                argv0=qemu_binary,
                version_argv=("--version",),
                probe_version=True,
                trust_root=trust_root,
            ),
            emulator_pins,
            probe_timeout=timeout,
        )
    except AdmissionError as exc:
        raise VerifyError("emulator admission refused: %s" % (exc,))
    except UnicodeDecodeError as exc:
        raise VerifyError(
            "emulator version probe printed undecodable output: %s" % (exc,)
        )
    launcher_name, launcher_pins = _launcher_pins(runner)
    try:
        launcher_admitted = admit_execution(
            ExecutionRequest(
                name=launcher_name,
                argv0=launcher_name,
                version_argv=("--help",),
                probe_version=True,
                trust_root=trust_root,
            ),
            launcher_pins,
            probe_timeout=timeout,
        )
    except AdmissionError as exc:
        raise VerifyError("launcher admission refused: %s" % (exc,))
    except UnicodeDecodeError as exc:
        raise VerifyError(
            "launcher probe printed undecodable output: %s" % (exc,)
        )
    # Post-probe half: the emulator claim against the OBSERVED
    # version (dependencies were already enforced pre-probe and
    # are re-checked here for a single final verdict).
    try:
        verify_runner_distribution(
            distribution, admitted, qemu_admitted.version
        )
    except ValueError as exc:
        raise VerifyError(
            "kernels lock distribution is malformed: %s" % (exc,)
        )
    except AdmissionError as exc:
        raise VerifyError("runner distribution refused: %s" % (exc,))
    try:
        farm = build_path_farm(
            {
                "vng": admitted.entry.realpath,
                launcher_name: launcher_admitted.entry.realpath,
                qemu_binary: qemu_admitted.image.realpath,
            },
            parent=farm_parent,
        )
    except (ValueError, OSError) as exc:
        raise VerifyError("cannot stage the admitted PATH farm: %s" % (exc,))
    image = admitted.image
    return {
        "path": admitted.entry.path,
        "realpath": admitted.entry.realpath,
        "sha256": admitted.entry.sha256,
        "version": admitted.version,
        "exec_path": (
            image.realpath if image.realpath != admitted.entry.realpath
            else None
        ),
        "exec_sha256": (
            image.sha256 if image.realpath != admitted.entry.realpath
            else None
        ),
        "interpreter": (
            {
                "path": admitted.interpreter.path,
                "realpath": admitted.interpreter.realpath,
                "sha256": admitted.interpreter.sha256,
            }
            if admitted.interpreter is not None
            else None
        ),
        "modules": {
            item.name: item.identity.sha256 for item in admitted.modules
        },
        "qemu": {
            "binary": qemu_binary,
            "path": qemu_admitted.entry.path,
            "realpath": qemu_admitted.image.realpath,
            "sha256": qemu_admitted.image.sha256,
            "version": qemu_admitted.version,
        },
        "virtme_run": {
            "binary": launcher_name,
            "path": launcher_admitted.entry.path,
            "realpath": launcher_admitted.entry.realpath,
            "sha256": launcher_admitted.entry.sha256,
            "version": launcher_admitted.version,
        },
        "farm": farm,
        "digest": admitted.digest,
        "execution": admitted,
        "virtme_run_execution": launcher_admitted,
        "qemu_execution": qemu_admitted,
    }


def _runner_attestation(runner: dict) -> dict:
    """Return the JSON-safe runner attestation for the result."""
    attestation = {
        key: value
        for key, value in runner.items()
        if key
        not in ("execution", "virtme_run_execution", "qemu_execution")
    }
    attestation["admission"] = summarize(runner["execution"])
    attestation["virtme_run_admission"] = summarize(
        runner["virtme_run_execution"]
    )
    attestation["qemu_admission"] = summarize(runner["qemu_execution"])
    return attestation


def _group_members(pgid: int) -> list[dict]:
    """Snapshot the process-group members as [{pid, state, comm}].

    Zombies (state ``Z``) and dead tasks (``X``) hold no resources;
    only their already-dead parent (or init) can reap them, so
    liveness checks ignore them while still reporting them.
    """
    members = []
    try:
        pids = [entry for entry in os.listdir("/proc") if entry.isdigit()]
    except OSError:
        return members
    for pid in pids:
        try:
            with open("/proc/%s/stat" % pid, encoding="utf-8") as handle:
                fields = handle.read().rsplit(")", 1)
        except OSError:
            continue
        if len(fields) != 2:
            continue
        comm = fields[0].split("(", 1)[1] if "(" in fields[0] else ""
        rest = fields[1].split()
        if len(rest) < 3:
            continue
        try:
            member_pgid = int(rest[2])
        except ValueError:
            continue
        if member_pgid != pgid:
            continue
        members.append(
            {"pid": int(pid), "state": rest[0], "comm": comm}
        )
    return sorted(members, key=lambda item: item["pid"])


def _group_reaped(pgid: int) -> bool:
    """Return True when no live (non-zombie) group member remains."""
    return all(
        item["state"] in ("Z", "X") for item in _group_members(pgid)
    )


def _kill_group(pgid: int) -> bool:
    """SIGKILL a process group; return True when no live member remains."""
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if _group_reaped(pgid):
            return True
        time.sleep(0.2)
    return _group_reaped(pgid)


def run_verification(request: VerifyRequest) -> dict:
    """Boot one guest, load/unload the object there, return the result.

    Raises :class:`VerifyError` for setup failures and
    :class:`VerifyInterrupted` when SIGTERM/SIGINT arrives (the guest
    process group is killed first). Any other outcome, including
    timeouts and guest-side failures, is returned as a result dict;
    nothing here raises on a nonzero guest exit.
    """
    if not os.path.isfile(request.object_path):
        raise VerifyError("object not found: %s" % request.object_path)
    stage = tempfile.mkdtemp(prefix="mojobpf-verify-")
    runner = _probe_vng(
        request.vng_path,
        kernels_lock=request.kernels_lock,
        farm_parent=stage,
    )
    try:
        sections, license_bytes = read_elf_sections(request.object_path)
        elf_error: str | None = None
    except (OSError, ValueError) as exc:
        sections, license_bytes, elf_error = [], None, str(exc)
    has_btf = any(name in (".BTF", ".BTF.ext") for name in sections)
    if request.require_btf == "auto":
        require_btf_flag = "1" if has_btf else "0"
    else:
        require_btf_flag = "1" if request.require_btf == "yes" else "0"
    with open(request.object_path, "rb") as handle:
        staged_bytes = handle.read()
    staged_object = os.path.join(stage, STAGED_OBJECT_NAME)
    with open(staged_object, "wb") as handle:
        handle.write(staged_bytes)
    script = GUEST_SCRIPT_TEMPLATE.format(
        stage=stage,
        object_name=STAGED_OBJECT_NAME,
        pin=request.pin_path,
        prog_type=request.prog_type,
        map_types=" ".join(request.map_types),
        trace_event=request.trace_event or "",
        btf_path=request.kernel_btf,
        require_btf=require_btf_flag,
        as_user=request.as_user or "",
        guest_preflight=GUEST_PREFLIGHT_UNAVAILABLE,
        guest_load_failed=GUEST_LOAD_FAILED,
    )
    for token in _FORBIDDEN_GUEST_TOKENS:
        if token in script:
            raise VerifyError(
                "staged guest script carries forbidden token %r" % token
            )
    script_path = os.path.join(stage, "guest_verify.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    os.chmod(staged_object, 0o644)
    os.chmod(script_path, 0o644)
    os.chmod(stage, 0o755)

    argv = ["vng", "--run", request.release]
    if request.accelerator == "tcg":
        argv.append("--disable-kvm")
    argv += ["--exec", "bash %s" % script_path]
    # The runner spawns through its admission: the captured entry
    # (honoring --vng even off PATH) under the sanitized
    # environment, with the PATH farm forcing the admitted
    # vng/virtme-run/QEMU chain however the runner resolves them.
    execution = runner["execution"]
    argv[0] = execution.argv_prefix[0]
    child_env_extra = {"PATH": farm_path_prefix(runner["farm"])}

    result: dict = {
        "tool": TOOL_NAME,
        "schema": RESULT_SCHEMA,
        "status": "fail",
        "stage": "setup",
        "classification": None,
        "object": {
            "path": request.object_path,
            "sha256": sha256_file(request.object_path),
            "size": len(staged_bytes),
            "sections": sections,
            "license": (
                license_bytes.decode("ascii", "replace").rstrip("\x00")
                if license_bytes is not None
                else None
            ),
            "has_btf": has_btf,
            "elf_parse_error": elf_error,
        },
        "runner": dict(
            _runner_attestation(runner),
            release=request.release,
            accelerator=request.accelerator,
            argv=argv,
        ),
        "guest": {
            "kernel": None,
            "id": None,
            "btf": None,
            "prog_type": request.prog_type,
            "prog_type_supported": None,
            "probe_line": None,
            "map_types": list(request.map_types),
            "map_types_supported": {},
            "map_probe_lines": {},
            "trace_event": request.trace_event,
            "trace_event_supported": None,
            "trace_event_id": None,
        },
        "preflight": {
            "require_btf": request.require_btf,
            "require_btf_effective": require_btf_flag == "1",
            "kernel_btf_path": request.kernel_btf,
            "as_user": request.as_user,
            "map_types": list(request.map_types),
            "trace_event": request.trace_event,
            "unavailable_reason": None,
        },
        "load": {"attempted": False, "exit": None, "log_excerpt": None},
        "unload": {
            "attempted": False,
            "ok": None,
            "pin_absent": None,
            "quiesced": None,
            "quiesce_waits": None,
        },
        "guest_commands": [],
        "resources": {"before": None, "after": None},
        "child": {
            "exit": None,
            "timed_out": False,
            "group_killed": False,
            "group_reaped": None,
            "group_members": None,
        },
        "stage_path": stage,
        "note": None,
    }

    proc: subprocess.Popen | None = None
    # start_new_session makes the child a session/group leader, so
    # its pid is the group id for the whole run. It is captured here,
    # never re-derived after the child exits (pid reuse would risk
    # signalling an unrelated group).
    child_pgid: int | None = None
    previous_sigterm = signal.getsignal(signal.SIGTERM)
    previous_sigint = signal.getsignal(signal.SIGINT)

    def _handle_signal(signum, _frame):
        if proc is not None and proc.poll() is None:
            if child_pgid is not None:
                result["child"]["group_killed"] = True
                result["child"]["group_reaped"] = _kill_group(child_pgid)
                result["child"]["group_members"] = _group_members(
                    child_pgid
                )
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass
        raise VerifyInterrupted("signal %d during guest run" % signum)

    output = ""
    try:
        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)
        try:
            proc = popen_admitted(
                execution,
                argv[1:],
                env_extra=child_env_extra,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
        except AdmissionError as exc:
            raise VerifyError("runner spawn refused: %s" % (exc,))
        except OSError as exc:
            raise VerifyError("failed to start vng: %s" % exc)
        child_pgid = proc.pid
        deadline = time.monotonic() + request.timeout
        child_crashed = False
        stdout, stderr = "", ""
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result["child"]["timed_out"] = True
                result["child"]["group_killed"] = True
                result["child"]["group_reaped"] = _kill_group(child_pgid)
                result["child"]["group_members"] = _group_members(
                    child_pgid
                )
                try:
                    stdout, stderr = proc.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout, stderr = proc.communicate()
                break
            try:
                stdout, stderr = proc.communicate(
                    timeout=min(5, remaining)
                )
                break
            except subprocess.TimeoutExpired:
                if proc.poll() is None:
                    continue
                # The runner died but orphaned group members still
                # hold the pipes: fail closed and reap the group
                # rather than trusting a transcript nobody owns.
                child_crashed = True
                result["child"]["group_killed"] = True
                result["child"]["group_reaped"] = _kill_group(child_pgid)
                result["child"]["group_members"] = _group_members(
                    child_pgid
                )
                try:
                    stdout, stderr = proc.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout, stderr = proc.communicate()
                break
        output = (stdout or "") + (stderr or "")
        result["child"]["exit"] = proc.returncode
        if not child_crashed and not result["child"]["timed_out"]:
            # A failed runner can still orphan a live emulator in our
            # group; sweep it so no stray survives a failed run.
            # Clean guest exits need no sweep; anything else with
            # live runner-like members gets one.
            members = _group_members(child_pgid)
            live = [
                item
                for item in members
                if item["state"] not in ("Z", "X")
            ]
            if (
                live
                and proc.returncode
                not in (
                    0,
                    GUEST_PREFLIGHT_UNAVAILABLE,
                    GUEST_LOAD_FAILED,
                )
                and all(
                    item["comm"].startswith(
                        ("qemu", "vng", "virtme", "python")
                    )
                    for item in live
                )
            ):
                result["child"]["group_killed"] = True
                result["child"]["group_reaped"] = _kill_group(child_pgid)
                members = _group_members(child_pgid)
            elif not live:
                result["child"]["group_reaped"] = True
            result["child"]["group_members"] = members
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)
        signal.signal(signal.SIGINT, previous_sigint)

    if child_crashed:
        result["status"] = "fail"
        result["stage"] = "run"
        result["classification"] = "environment"
        result["note"] = (
            "runner died (exit %s); orphaned group killed "
            "(reaped: %s); transcript untrusted, never a pass"
            % (
                result["child"]["exit"],
                result["child"]["group_reaped"],
            )
        )
        return result

    # The stage directory is always kept for audit (inputs, guest
    # script, hashes); result["stage_path"] records where.
    result["guest"]["kernel"] = _guest_kernel(output)
    result["guest"]["id"] = _parse_colon_value(output, "guest-id")
    btf = _parse_line_value(output, "kernel_btf")
    result["guest"]["btf"] = btf
    result["guest"]["probe_line"] = _parse_line_value(output, "probe_line")
    supported = _parse_line_value(output, "prog_type_supported")
    result["guest"]["prog_type_supported"] = {
        "1": True, "0": False,
    }.get(supported or "", None)
    for map_type in request.map_types:
        result["guest"]["map_probe_lines"][map_type] = _parse_line_value(
            output, "map_probe_line[%s]" % map_type
        )
        map_supported = _parse_line_value(
            output, "map_type_supported[%s]" % map_type
        )
        result["guest"]["map_types_supported"][map_type] = {
            "1": True, "0": False,
        }.get(map_supported or "", None)
    if request.trace_event is not None:
        trace_supported = _parse_line_value(output, "trace_event_supported")
        result["guest"]["trace_event_supported"] = {
            "1": True, "0": False,
        }.get(trace_supported or "", None)
        result["guest"]["trace_event_id"] = _parse_line_value(
            output, "trace_event_id"
        ) or None
    result["resources"]["before"] = _parse_marked_block(
        output, "snapshot-before"
    )
    result["resources"]["after"] = _parse_marked_block(output, "snapshot-after")
    result["guest_commands"] = re.findall(
        r"^guest-cmd: (.*)$", output, re.MULTILINE
    )

    if result["child"]["timed_out"]:
        result["status"] = "timeout"
        result["stage"] = "run"
        result["classification"] = "environment"
        result["note"] = (
            "guest command exceeded %ds; runner process group killed "
            "(reaped: %s)" % (
                request.timeout, result["child"]["group_reaped"],
            )
        )
        return result

    preflight = re.search(
        r"^PREFLIGHT_UNAVAILABLE (\S+)$", output, re.MULTILINE
    )
    if preflight is not None or (
        result["child"]["exit"] == GUEST_PREFLIGHT_UNAVAILABLE
    ):
        reason = preflight.group(1) if preflight else "unknown"
        result["status"] = "unavailable"
        result["stage"] = "preflight"
        result["classification"] = "environment"
        result["preflight"]["unavailable_reason"] = reason
        result["note"] = "no load attempted: %s" % reason
        return result

    load_exit_raw = _parse_line_value(output, "load_exit")
    load_log = _parse_marked_block(output, "load-log")
    if load_exit_raw is None or load_log is None:
        result["status"] = "fail"
        result["stage"] = "run"
        result["classification"] = "environment"
        result["note"] = (
            "guest transcript lacks the load section "
            "(exit %s); environment failure, never a pass"
            % (result["child"]["exit"],)
        )
        return result
    result["load"]["attempted"] = True
    try:
        load_exit = int(load_exit_raw)
    except ValueError:
        load_exit = -1
    result["load"]["exit"] = load_exit
    result["load"]["log_excerpt"] = load_log[-4000:]
    if load_exit != 0:
        classification = classify_load_output(load_log, "", False)
        result["status"] = "load-failed"
        result["stage"] = "load"
        result["classification"] = classification
        return result

    result["unload"]["attempted"] = True
    unload_ok = _parse_line_value(output, "unload_ok")
    pin_absent = unload_ok == "1"
    result["unload"]["ok"] = pin_absent
    result["unload"]["pin_absent"] = pin_absent
    quiesced = _parse_line_value(output, "quiesced")
    waits = _parse_line_value(output, "quiesce_waits")
    result["unload"]["quiesced"] = quiesced == "1"
    try:
        result["unload"]["quiesce_waits"] = int(waits or "")
    except ValueError:
        result["unload"]["quiesce_waits"] = None
    if not pin_absent:
        result["status"] = "fail"
        result["stage"] = "unload"
        result["classification"] = "environment"
        result["note"] = (
            "guest resources did not quiesce after unload "
            "(pin %s, quiesced=%s)" % (request.pin_path, quiesced)
        )
        return result
    if result["child"]["exit"] != 0:
        # The guest transcript shows a clean load and unload, but
        # the runner itself exited nonzero (a runner fault after
        # the guest finished, never a clean run): fail closed.
        result["status"] = "fail"
        result["stage"] = "run"
        result["classification"] = "environment"
        result["note"] = (
            "runner exited %s after a successful guest "
            "transcript; environment failure, never a pass"
            % (result["child"]["exit"],)
        )
        return result
    result["status"] = "pass"
    result["stage"] = "done"
    result["classification"] = None
    return result


def _guest_kernel(output: str) -> str | None:
    match = re.search(r"^guest-kernel: (\S+)$", output, re.MULTILINE)
    return match.group(1) if match else None


def _parse_colon_value(output: str, key: str) -> str | None:
    match = re.search(r"^%s: (.*)$" % re.escape(key), output, re.MULTILINE)
    return match.group(1).strip() if match else None


def format_summary(result: dict) -> str:
    """Return the human-readable one-block summary of a result."""
    lines = [
        "%s: status=%s stage=%s" % (
            TOOL_NAME, result.get("status"), result.get("stage"),
        ),
    ]
    classification = result.get("classification")
    if classification:
        lines.append("classification: %s" % classification)
    obj = result.get("object", {})
    lines.append(
        "object: %s (sha256 %s)" % (
            obj.get("path"), (obj.get("sha256") or "")[:16],
        )
    )
    guest = result.get("guest", {})
    lines.append(
        "guest: kernel=%s btf=%s prog_type=%s supported=%s" % (
            guest.get("kernel"), guest.get("btf"),
            guest.get("prog_type"), guest.get("prog_type_supported"),
        )
    )
    load = result.get("load", {})
    lines.append(
        "load: attempted=%s exit=%s" % (
            load.get("attempted"), load.get("exit"),
        )
    )
    unload = result.get("unload", {})
    lines.append(
        "unload: attempted=%s pin_absent=%s" % (
            unload.get("attempted"), unload.get("pin_absent"),
        )
    )
    note = result.get("note")
    if note:
        lines.append("note: %s" % note)
    lines.append("guest commands: load/unload only; no attach, no test-run")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    """Entry point used by ``mojobpf verify --kernel`` (see cli.py)."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="mojobpf verify",
        description=(
            "Load one object inside a disposable guest and unload it "
            "again. Never loads on the host, never attaches."
        ),
    )
    parser.add_argument("--kernel", action="store_true", required=True)
    parser.add_argument("--object", required=True)
    parser.add_argument("--release", default=None)
    parser.add_argument("--accelerator", default="tcg", choices=("tcg", "kvm"))
    parser.add_argument("--vng", default=None)
    parser.add_argument("--kernels-lock", default=None)
    parser.add_argument("--pin-path", default=DEFAULT_PIN_PATH)
    parser.add_argument("--prog-type", default=DEFAULT_PROG_TYPE)
    parser.add_argument("--map-type", dest="map_type", action="append",
                        default=None)
    parser.add_argument("--trace-event", default=None)
    parser.add_argument(
        "--require-btf", default="auto", choices=("auto", "yes", "no")
    )
    parser.add_argument("--kernel-btf", default=DEFAULT_KERNEL_BTF)
    parser.add_argument("--as-user", default=None)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--output", default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        request = VerifyRequest(
            object_path=args.object,
            release=args.release,
            accelerator=args.accelerator,
            vng_path=args.vng,
            pin_path=args.pin_path,
            prog_type=args.prog_type,
            map_types=tuple(args.map_type or ()),
            trace_event=args.trace_event,
            require_btf=args.require_btf,
            kernel_btf=args.kernel_btf,
            as_user=args.as_user,
            timeout=args.timeout,
            kernels_lock=args.kernels_lock,
        )
    except VerifyError as exc:
        sys.stderr.write("mojobpf verify: %s\n" % exc)
        return 2
    try:
        result = run_verification(request)
    except VerifyError as exc:
        sys.stderr.write("mojobpf verify: %s\n" % exc)
        return 2
    except VerifyInterrupted as exc:
        sys.stderr.write("mojobpf verify: %s\n" % exc)
        return 130
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    if args.json:
        sys.stdout.write(text)
    else:
        sys.stdout.write(format_summary(result))
    status = result.get("status")
    classification = result.get("classification")
    if status == "pass":
        return 0
    if classification == "environment":
        return 3
    if status == "load-failed":
        return 4 if classification == "verifier" else 5
    return 3


if __name__ == "__main__":
    sys.exit(main())
