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

:func:`verify_bytes` verifies exactly one captured byte string: the
same bytes are inspected, staged, hashed and attested, so a file
replaced between two reads cannot split those identities.
:func:`run_verification` captures an object file once and delegates
to it. The effective release is validated after environment/default
selection and resolved to a lane in the kernels lock before any
spawn; the stage travels to the guest script as argv (never
interpolated); owned staging keeps restrictive permissions and is
removed on success, failure and interruption unless evidence
retention was requested.

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
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from . import sealed_fs
from .diagnostics import Diagnostic
from .elf_reader import (
    ElfError,
    parse_elf,
    parse_elf_sections,
    section_bytes,
)

# ``parse_elf`` stays imported (unused here) so verification and
# inspection resolve one shared reader object
# (``mojobpf.inspect.parse_elf is mojobpf.verify.parse_elf``).
from .execution import (
    AdmittedExecution,
    AdmissionError,
    EXECUTION_CONTRACT_VERSION,
    ExecutionPins,
    ExecutionRequest,
    FORM_CONSOLE_SCRIPT,
    FORM_EXEC_LAUNCHER,
    PYTHON_ENV_SET,
    SPAWN_ENV_UNSET,
    _admission_digest,
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
RESULT_SCHEMA = 2

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
# Staged script name inside the guest stage (fixed for the same
# reason; the host compares the guest-reported hashes of both).
STAGED_SCRIPT_NAME = "guest_verify.sh"

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


def read_elf_sections_bytes(image: bytes) -> tuple[list[str], bytes | None]:
    """Return ``(section names, license bytes or None)`` for ELF bytes.

    Raises ``ValueError`` when the shared bytes-based reader
    (:mod:`mojobpf.elf_reader`) rejects the capture. The shared
    reader always runs first -- this function performs no
    pre-check that could skip it, so inspection and verification
    never disagree about one capture's container; only the error
    vocabulary stays local (``ValueError`` here, structural
    findings there). Symbol tables are not decoded (verification
    never consumed symbols, and symbol-table shapes cannot fail
    this read). The shared decode is total over the ELF
    identity: it records ``EI_VERSION`` without accepting or
    rejecting any value. After that decode, verification
    applies its own base-pinned EI_VERSION acceptance mapping:
    before the shared reader, verification rejected
    ``EI_VERSION != 1`` while inspection accepted it, so this
    path keeps verification's historical rejection, with its
    historical message, as base-behavior preservation (not a new
    rule). Base applied that EI_VERSION mapping before decoding
    the section table, so the mapping also takes precedence
    when the shared reader itself fails: a capture that is both
    EI-nonstandard and section-malformed still reports the
    historical EI error verbatim. The parse is informational
    only: callers must still attempt the genuine load so the
    loader's own verdict (not this reader) decides the
    classification. Verification inspects exactly these captured
    bytes (never a re-read path), so the inspected section set
    cannot describe other bytes than the staged and attested
    ones.
    """
    try:
        elf = parse_elf_sections(image, "<verify-bytes>")
    except ElfError as exc:
        # Base check order: base rejected EI_VERSION != 1 with
        # its historical message before looking at the section
        # table. The shared reader already ran above -- this is
        # not a pre-check and never skips the decode; it only
        # reads the captured identity byte to select the
        # base-pinned vocabulary for the failure.
        if len(image) > 6 and image[6] != 1:
            raise ValueError(
                "not a 64-bit little-endian ELF file"
            ) from None
        raise ValueError(
            "%s: %s" % (exc.code, exc.explanation)
        ) from None
    if elf.ei_version != 1:
        raise ValueError("not a 64-bit little-endian ELF file")
    names = [section.name for section in elf.sections]
    license_bytes: bytes | None = None
    for section in elf.sections:
        if section.name == "license":
            license_bytes = section_bytes(elf, section)
    return names, license_bytes


def read_elf_sections(path: str) -> tuple[list[str], bytes | None]:
    """Return ``(section names, license bytes or None)`` for an ELF file.

    Reads the path once and parses the captured bytes. Kept for
    path-based callers; the verification path captures the object
    bytes first and parses the same bytes it stages and attests.
    """
    with open(path, "rb") as handle:
        image = handle.read()
    return read_elf_sections_bytes(image)


GUEST_SCRIPT_TEMPLATE = """#!/bin/bash
# Staged by mojobpf verify --kernel. Loads one object, unloads it
# again, and reports. No hook binding, no program execution.
set -u
export PYTHONDONTWRITEBYTECODE=1
# The stage travels as argv ($1), never interpolated into this
# script: TMPDIR-controlled stage paths may carry spaces, quotes,
# dollar signs or backticks, and interpolation would evaluate them.
STAGE="${{1:?missing stage argument}}"
OBJ="$STAGE/{object_name}"
PIN="{pin}"
PROG_TYPE="{prog_type}"
BTF_PATH="{btf_path}"
REQUIRE_BTF="{require_btf}"
AS_USER="{as_user}"
cd "$STAGE"
list_filtered() {{
  # bpftool 7.6 observes its own ephemeral iterator maps
  # (pid_iter.*) with per-run IDs and PIDs, and leaks its
  # skeleton maps (libbpf_global, libbpf_det_bind), so raw
  # `map list` output never repeats identically across runs.
  # Drop exactly those tool-owned entries and the ephemeral
  # pids lines so the quiesce comparison below can stabilize;
  # suite maps always pass through.
  bpftool map list 2>&1 | awk '
    /^[0-9]+:/ {{ skip = ($0 ~ /name (pid_iter\\.[A-Za-z0-9_.]*|libbpf_global|libbpf_det_bind)( |$)/) }}
    skip {{ next }}
    /^[[:space:]]+pids / {{ next }}
    {{ print }}'
}}
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin verify_kernel ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
bpftool version | head -2
echo "=== staged hashes ==="
sha256sum {object_name}
sha256sum {script_name}
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
echo "=== BEGIN map-types ==="
grep -F "map_type " "$STAGE/feature.txt" || true
echo "=== END map-types ==="
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
list_filtered | head -40
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
# Hash the staged inputs immediately before the load (and again
# after it below): the host requires every print to match the
# capture, so a substitution between capture and load cannot
# hide (A1M4-3).
sha256sum {object_name} {script_name}
# Unquoted LOAD_RUN word-splits deliberately (bpftool or setpriv prefix).
$LOAD_RUN prog load "$OBJ" "$PIN" >"$STAGE/load.out" 2>&1
LOAD_EXIT=$?
echo "load_exit=$LOAD_EXIT"
echo "=== BEGIN load-log ==="
cat "$STAGE/load.out"
echo "=== END load-log ==="
sha256sum {object_name} {script_name}
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
  CUR=$(bpftool prog list 2>&1; list_filtered; bpftool link list 2>&1)
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
list_filtered | head -40
bpftool link list 2>&1 | head -40
ls /sys/fs/bpf/ 2>&1
echo "=== END snapshot-after ==="
echo "=== end verify_kernel ==="
"""


class VerifyError(Exception):
    """Setup failure: the verification could not be attempted."""


class VerifyInterrupted(Exception):
    """The verification was interrupted; the guest group was killed."""


def _require_safe_token(label: str, value: str) -> None:
    """Reject a guest-script value outside the safe token shape."""
    if value and _SAFE_TOKEN.match(value) is None:
        raise VerifyError(
            "%s carries characters outside [A-Za-z0-9_.,:/=@-]: %r"
            % (label, value)
        )


def _require_map_types(
    map_types: tuple[str, ...] | list[str],
) -> tuple[str, ...]:
    """Validate guest map-type names; return them as a tuple."""
    if isinstance(map_types, str) or not isinstance(map_types, (tuple, list)):
        raise VerifyError("map_types must be a tuple or list of names")
    for map_type in map_types:
        if not isinstance(map_type, str) or (
            _NAME_TOKEN.fullmatch(map_type) is None
        ):
            raise VerifyError(
                "map type must look like an identifier "
                "[A-Za-z0-9_]: %r" % (map_type,)
            )
    return tuple(map_types)


def _require_trace_event(trace_event: str | None) -> None:
    """Validate a ``category:name`` guest trace selector."""
    if trace_event is None:
        return
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
        keep_evidence: bool = False,
    ) -> None:
        if accelerator not in ("tcg", "kvm"):
            raise VerifyError("accelerator must be 'tcg' or 'kvm'")
        if require_btf not in ("auto", "yes", "no"):
            raise VerifyError("require_btf must be 'auto', 'yes', or 'no'")
        if timeout <= 0:
            raise VerifyError("timeout must be positive")
        if kernels_lock is not None and not isinstance(kernels_lock, str):
            raise VerifyError("kernels lock path must be a string or None")
        if not isinstance(keep_evidence, bool):
            raise VerifyError("keep_evidence must be a bool")
        if not pin_path.startswith("/sys/fs/bpf/"):
            raise VerifyError("pin path must live under /sys/fs/bpf/")
        # The effective release is selected first (explicit flag,
        # then the environment, then the default) and validated
        # after selection, so an ambient value gets the same
        # token check as an explicit one.
        effective_release = (
            release
            if release is not None
            else os.environ.get(RELEASE_ENV_VAR, DEFAULT_RELEASE)
        )
        for label, value in (
            ("release", effective_release),
            ("pin path", pin_path),
            ("program type", prog_type),
            ("kernel BTF path", kernel_btf),
        ):
            _require_safe_token(label, value)
        validated_map_types = _require_map_types(map_types)
        _require_trace_event(trace_event)
        if as_user is not None and _SAFE_TOKEN.match(as_user) is None:
            raise VerifyError("user name carries unsafe characters: %r" % as_user)
        self.object_path = object_path
        self.release = effective_release
        self.accelerator = accelerator
        self.vng_path = vng_path
        self.pin_path = pin_path
        self.prog_type = prog_type
        self.map_types = validated_map_types
        self.trace_event = trace_event
        self.require_btf = require_btf
        self.kernel_btf = kernel_btf
        self.as_user = as_user
        self.timeout = timeout
        self.kernels_lock = kernels_lock
        self.keep_evidence = keep_evidence


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


def _require_lock_path(kernels_lock: str | None) -> str:
    """Return the kernels lock path or raise a setup error."""
    lock_path = kernels_lock or default_kernels_lock()
    if lock_path is None:
        raise VerifyError(
            "kernels lock not found (pass --kernels-lock or run from "
            "a checkout carrying ci/kernels.lock.json)"
        )
    return lock_path


def _load_lock_document(lock_path: str) -> dict:
    """Load and schema-check the kernels lock document."""
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
    return lock


LANE_REQUIRED_KEYS = (
    "id",
    "release",
    "accelerator",
    "kernel_release",
    "kernel_debs",
    "vng_argv_prefix",
)


def _load_lanes(lock_path: str) -> list[dict]:
    """Return the lock's validated kernel lanes."""
    lock = _load_lock_document(lock_path)
    lanes = lock.get("lanes")
    if not isinstance(lanes, list) or not lanes:
        raise VerifyError(
            "kernels lock %s carries no lanes" % (lock_path,)
        )
    for lane in lanes:
        if not isinstance(lane, dict):
            raise VerifyError(
                "kernels lock %s carries a malformed lane: %r"
                % (lock_path, lane)
            )
        for key in LANE_REQUIRED_KEYS:
            if key not in lane:
                raise VerifyError(
                    "kernels lock lane %r lacks %s"
                    % (lane.get("id", lane), key)
                )
    return lanes


def resolve_lane(
    release: str,
    accelerator: str,
    kernels_lock: str | None = None,
) -> dict:
    """Resolve the effective release/accelerator to a locked lane.

    Validates the effective release token after environment/default
    selection and requires the pair to match a lane in the kernels
    lock, so a stale or ambient release can never silently prove
    the wrong kernel. Returns the lane mapping. Raises
    :class:`VerifyError` before any process starts.
    """
    _require_safe_token("release", release)
    if accelerator not in ("tcg", "kvm"):
        raise VerifyError("accelerator must be 'tcg' or 'kvm'")
    lock_path = _require_lock_path(kernels_lock)
    lanes = _load_lanes(lock_path)
    for lane in lanes:
        if (
            lane["release"] == release
            and lane["accelerator"] == accelerator
        ):
            return dict(lane)
    available = ", ".join(
        "%s/%s" % (lane["release"], lane["accelerator"])
        for lane in lanes
    )
    raise VerifyError(
        "release %r with accelerator %r matches no lane in %s "
        "(available: %s)" % (release, accelerator, lock_path, available)
    )


def _load_runner_pins(lock_path: str) -> tuple[dict, dict | None]:
    """Load the kernels lock's runner pins plus distribution (no probing)."""
    lock = _load_lock_document(lock_path)
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
    lock_path = _require_lock_path(kernels_lock)
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
            # errors="replace": a foreign comm may hold
            # non-UTF-8 bytes; the numeric tail still parses,
            # so membership stays attributable instead of
            # crashing the snapshot.
            with open("/proc/%s/stat" % pid, encoding="utf-8",
                      errors="replace") as handle:
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


def _read_object_bytes(object_path: str) -> bytes:
    """Read an object file once; the single capture for verification."""
    try:
        with open(object_path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise VerifyError(
            "object %s is unreadable: %s" % (object_path, exc)
        )


def guest_exec_command(script_path: str, stage: str) -> str:
    """Return the guest ``--exec`` command running the staged script.

    Both paths are shell-quoted and the stage travels as the
    script's argv ($1), never interpolated into the script body, so
    TMPDIR-controlled paths with spaces, quotes, dollar signs or
    backticks cannot evaluate in the guest shell. The runner hands
    this string to the guest shell (virtme writes it to its init
    script and runs it with bash), so quoting here is load-bearing.
    """
    return "bash %s %s" % (
        shlex.quote(script_path), shlex.quote(stage),
    )


def _remove_owned_tree(path: str) -> str | None:
    """Remove one owned tree; return an error string, or None."""
    try:
        shutil.rmtree(path)
    except OSError as exc:
        return "%s: %s" % (path, exc)
    if os.path.lexists(path):
        return "%s: still present after removal" % path
    return None


def _close_inner_watch(watch) -> None:
    """Close an inner-stage monitor unless None; never raises."""
    if watch is None:
        return
    try:
        watch.close()
    except OSError:
        pass


# Proved pinned removals: abspath entries whose removal was
# established on a held descriptor. A pinned stage absent
# without a proof was relocated, not removed (A1M5-2).
_PINNED_REMOVED = set()


def _teardown_owned_pair(stage, stage_pin, farm, errors):
    """Remove the stage and farm; append error strings.

    Centralized pre-result teardown (A1M5-3): every
    result-less signal, staging and preparation arm uses
    this (callers own the keep-evidence gate). A sealed
    stage is removed through its pinned identity, so a
    substitute is refused instead of deleted; absence
    pre-seal stays a clean skip for idempotent
    double-teardown.
    """
    if stage is not None:
        if stage_pin is not None:
            error = _remove_pinned_tree(stage, stage_pin)
        elif os.path.lexists(stage):
            error = _remove_owned_tree(stage)
        else:
            error = None
        if error is not None:
            errors.append(error)
    if farm is not None and os.path.lexists(farm):
        error = _remove_owned_tree(farm)
        if error is not None:
            errors.append(error)


def _remove_pinned_tree(path: str, pin) -> str | None:
    """Remove the pinned tree; return an error string, or None."""
    key = os.path.abspath(path)
    try:
        parent_fd = os.open(
            os.path.dirname(key),
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
        )
    except OSError as exc:
        return "%s: %s" % (path, exc)
    try:
        proved = sealed_fs.rmtree_owned(
            parent_fd, os.path.basename(key), pin
        )
    except (AssertionError, OSError) as exc:
        return "%s: %s" % (path, exc)
    finally:
        try:
            os.close(parent_fd)
        except OSError:
            pass
    if proved:
        _PINNED_REMOVED.add(key)
    if key not in _PINNED_REMOVED:
        return (
            "%s: vanished without removal proof; contents "
            "unaccounted" % path
        )
    if os.path.lexists(path):
        return "%s: still present after removal" % path
    return None


def _inner_stage_violation(
    output: str,
    stage: str,
    pin,
    snaps: dict,
    watch,
    expected: dict,
) -> str | None:
    """Return the inner-stage integrity violation, if any.

    Binds the guest result to the staged bytes three ways
    (A1M4-3): every guest-printed staged hash must match the
    host capture, the name monitor must be clean, and the
    post-run snapshots must equal the pre-run ones. Returns
    the failure note, or None when the binding holds.
    """
    if pin is None or not snaps or watch is None:
        return (
            "inner stage was never sealed; environment "
            "failure, never a pass"
        )
    prints: dict[str, list[str]] = {}
    # sha256sum does not escape spaces, so the filename
    # runs to end-of-line and may be an absolute path
    # under a whitespace-containing TMPDIR (A1M5-4); the
    # basename decides which staged entry a line binds.
    for digest, name in re.findall(
        r"^([0-9a-f]{64})  (.+)$", output, re.MULTILINE
    ):
        prints.setdefault(
            os.path.basename(name.strip()), []
        ).append(digest)
    for name, want in sorted(expected.items()):
        seen = prints.get(name, [])
        if not seen:
            return (
                "guest transcript lacks staged hashes for %r; "
                "no loaded evidence, environment failure, never "
                "a pass" % (name,)
            )
        for got in seen:
            if got != want:
                return (
                    "guest loaded %r bytes (%s...) that differ "
                    "from the capture (%s...); environment "
                    "failure, never a pass"
                    % (name, got[:16], want[:16])
                )
    try:
        watch.check(names=sorted(expected))
    except OSError as exc:
        return (
            "inner stage file changed during verification: "
            "%s; environment failure, never a pass" % (exc,)
        )
    try:
        dirfd = sealed_fs.open_owned_dir(stage, pin)
    except (AssertionError, OSError):
        return (
            "inner stage directory substituted during "
            "verification; environment failure, never a pass"
        )
    try:
        for name, want in sorted(snaps.items()):
            if sealed_fs.snapshot_at(dirfd, name) != want:
                return (
                    "inner stage file %r touched during "
                    "verification; environment failure, never a "
                    "pass" % (name,)
                )
    except OSError as exc:
        # An unreadable stage fails closed through the same
        # gate-failure path (with its cleanup), never as a
        # raw escaping error that leaks the stage (A1M5-3).
        return (
            "inner stage unreadable during verification: "
            "%s; environment failure, never a pass" % (exc,)
        )
    finally:
        try:
            os.close(dirfd)
        except OSError:
            pass
    return None


def _discard_owned(
    result: dict,
    stage: str,
    farm: str | None,
    keep_evidence: bool,
    stage_pin=None,
) -> None:
    """Remove owned staging/farm unless kept; record cleanup status."""
    cleanup = result.get("cleanup")
    if not isinstance(cleanup, dict):
        cleanup = {"staging_removed": False, "kept": False, "error": None}
        result["cleanup"] = cleanup
    cleanup["kept"] = bool(keep_evidence)
    if keep_evidence:
        cleanup["staging_removed"] = False
        return
    errors = []
    for index, owned in enumerate((stage, farm)):
        if owned is None:
            continue
        # The stage (index 0) carries attested bytes, so its
        # removal binds to the pinned identity once staging
        # seals it; the farm and the pre-seal stage keep the
        # pathname removal. A pinned stage is always
        # presented for removal, even when absent: only a
        # recorded proof establishes CLEAN, never pathname
        # absence alone (A1M5-2).
        pinned_branch = index == 0 and stage_pin is not None
        if not pinned_branch and not os.path.lexists(owned):
            # Already-removed trees are skipped so an
            # interruption during cleanup can safely discard
            # twice (retry what a partial first pass left
            # behind, without reporting the removed trees as
            # failures).
            continue
        if pinned_branch:
            error = _remove_pinned_tree(owned, stage_pin)
        else:
            error = _remove_owned_tree(owned)
        if error is not None:
            errors.append(error)
    cleanup["error"] = "; ".join(errors) if errors else None
    cleanup["staging_removed"] = (
        cleanup["error"] is None
        and not os.path.lexists(stage)
        and (farm is None or not os.path.lexists(farm))
    )


def _cleanup_suffix(result: dict) -> str:
    """Render a failed-cleanup suffix for a setup error message."""
    cleanup = result.get("cleanup")
    error = cleanup.get("error") if isinstance(cleanup, dict) else None
    if error:
        return "; staging cleanup failed: %s" % error
    return ""


def _require_lane(lane: dict) -> dict:
    """Return the lane mapping or reject a malformed lane."""
    if not isinstance(lane, dict):
        raise VerifyError(
            "lane must be a kernels-lock lane mapping, got %s"
            % type(lane).__name__
        )
    for key in LANE_REQUIRED_KEYS:
        if key not in lane:
            raise VerifyError(
                "lane %r lacks %s" % (lane.get("id", lane), key)
            )
    prefix = lane["vng_argv_prefix"]
    if (
        not isinstance(prefix, list)
        or not prefix
        or prefix[0] != "vng"
        or any(not isinstance(word, str) for word in prefix)
    ):
        raise VerifyError(
            "lane %r carries a malformed vng_argv_prefix: %r"
            % (lane.get("id", lane), prefix)
        )
    return lane


def _require_record_matches_pins(
    label: str, record: AdmittedExecution, pins: ExecutionPins,
    expected_name: str,
) -> None:
    """Reject an admitted record that drifts from its lock pins.

    Mirrors admission's own comparisons (see
    :func:`mojobpf.execution.admit_execution`): the expected
    entry name, every present pin (version, entry, exec,
    interpreter, module table), the launcher/exec binding, and
    the exact spawn parameters admission derives from the chain
    (``argv_prefix`` is the admitted entry path; the env
    sanitization is the standard unset list plus the hardening
    overlay with ``PYTHONPATH`` exactly when the pins admit
    module roots). A record admitted under other pins -- or
    under none -- or copied with substituted spawn parameters
    and a recomputed digest is an unapproved runner chain.
    """
    if record.name != expected_name:
        raise VerifyError(
            "unapproved runner chain: %s is admitted as %r, want %r"
            % (label, record.name, expected_name)
        )
    if record.argv_prefix != (record.entry.path,):
        raise VerifyError(
            "unapproved runner chain: %s spawn argv %r is not the "
            "admitted entry %r"
            % (label, record.argv_prefix, record.entry.path)
        )
    if record.env_unset != SPAWN_ENV_UNSET:
        raise VerifyError(
            "unapproved runner chain: %s env sanitization does not "
            "match the admission" % (label,)
        )
    expected_env_set = list(PYTHON_ENV_SET)
    if pins.python_path:
        expected_env_set.append(
            ("PYTHONPATH", os.pathsep.join(pins.python_path))
        )
    if record.env_set != tuple(sorted(expected_env_set)):
        raise VerifyError(
            "unapproved runner chain: %s env overlay does not match "
            "the admission" % (label,)
        )
    if pins.version is not None and record.version != pins.version:
        raise VerifyError(
            "unapproved runner chain: %s version %r does not match "
            "the pinned %r" % (label, record.version, pins.version)
        )
    if (
        pins.entry_sha256 is not None
        and record.entry.sha256 != pins.entry_sha256
    ):
        raise VerifyError(
            "unapproved runner chain: %s entry hash %s does not "
            "match the pin" % (label, record.entry.sha256)
        )
    if record.form == FORM_EXEC_LAUNCHER:
        if not pins.exec_pin_present:
            raise VerifyError(
                "unapproved runner chain: %s is a launcher but the "
                "lock carries no exec pin" % (label,)
            )
        if record.image.sha256 != pins.exec_sha256:
            raise VerifyError(
                "unapproved runner chain: %s exec image hash %s "
                "does not match the pin"
                % (label, record.image.sha256)
            )
    elif pins.exec_pin_present and pins.exec_sha256 is not None:
        raise VerifyError(
            "unapproved runner chain: %s has no exec chain but the "
            "lock pins exec %s" % (label, pins.exec_sha256)
        )
    elif (
        pins.exec_pin_present
        and record.image.realpath != record.entry.realpath
    ):
        raise VerifyError(
            "unapproved runner chain: %s entry must be its own "
            "image under an explicit null exec pin" % (label,)
        )
    if pins.modules:
        if record.form != FORM_CONSOLE_SCRIPT:
            raise VerifyError(
                "unapproved runner chain: %s pins %d modules but is "
                "%s, not a console script"
                % (label, len(pins.modules), record.form)
            )
        if not pins.interpreter_pin_present:
            raise VerifyError(
                "unapproved runner chain: %s pins modules but no "
                "interpreter is pinned" % (label,)
            )
    if pins.interpreter_pin_present and (
        record.interpreter is None
        or record.interpreter.sha256 != pins.interpreter_sha256
    ):
        raise VerifyError(
            "unapproved runner chain: %s interpreter does not "
            "match the pin" % (label,)
        )
    observed_modules = {
        item.name: item.identity.sha256 for item in record.modules
    }
    if observed_modules != dict(pins.modules):
        raise VerifyError(
            "unapproved runner chain: %s module table does not "
            "match the pins" % (label,)
        )


def _require_runner_attestation(
    execution: dict, records: dict[str, AdmittedExecution]
) -> None:
    """Reject a runner record whose attestation drifts from its chains.

    The displayed attestation (digests, hashes, versions, module
    table) must describe the same three admissions that spawn,
    so approved records cannot be mixed with forged values. The
    displayed digest is recomputed from the record's content,
    never trusted from its own digest field.
    """
    admitted = records["execution"]
    launcher = records["virtme_run_execution"]
    emulator = records["qemu_execution"]
    for key in (
        "digest", "path", "realpath", "sha256", "version",
        "exec_path", "exec_sha256", "interpreter", "modules",
        "qemu", "virtme_run",
    ):
        if key not in execution:
            raise VerifyError(
                "unapproved runner chain: admitted runner record "
                "lacks attestation %r" % (key,)
            )
    if execution["digest"] != _admission_digest(admitted):
        raise VerifyError(
            "unapproved runner chain: runner digest does not match "
            "the vng admission"
        )
    for key, identity in (
        ("path", admitted.entry.path),
        ("realpath", admitted.entry.realpath),
        ("sha256", admitted.entry.sha256),
        ("version", admitted.version),
    ):
        if execution[key] != identity:
            raise VerifyError(
                "unapproved runner chain: runner %r does not match "
                "the vng admission" % (key,)
            )
    own_image = admitted.image.realpath == admitted.entry.realpath
    if execution["exec_path"] != (
        None if own_image else admitted.image.realpath
    ):
        raise VerifyError(
            "unapproved runner chain: runner exec path does not "
            "match the vng admission"
        )
    if execution["exec_sha256"] != (
        None if own_image else admitted.image.sha256
    ):
        raise VerifyError(
            "unapproved runner chain: runner exec hash does not "
            "match the vng admission"
        )
    interpreter = execution["interpreter"]
    if admitted.interpreter is None:
        if interpreter is not None:
            raise VerifyError(
                "unapproved runner chain: runner interpreter does "
                "not match the vng admission"
            )
    elif (
        not isinstance(interpreter, dict)
        or interpreter.get("sha256") != admitted.interpreter.sha256
    ):
        raise VerifyError(
            "unapproved runner chain: runner interpreter does not "
            "match the vng admission"
        )
    if execution["modules"] != {
        item.name: item.identity.sha256 for item in admitted.modules
    }:
        raise VerifyError(
            "unapproved runner chain: runner module table does not "
            "match the vng admission"
        )
    for key, record, image in (
        ("virtme_run", launcher, launcher.entry),
        ("qemu", emulator, emulator.image),
    ):
        section = execution[key]
        if not isinstance(section, dict):
            raise VerifyError(
                "unapproved runner chain: runner %r is not an "
                "attestation mapping" % (key,)
            )
        if section.get("sha256") != image.sha256:
            raise VerifyError(
                "unapproved runner chain: runner %s hash does not "
                "match its admission" % (key,)
            )
        if section.get("version") != record.version:
            raise VerifyError(
                "unapproved runner chain: runner %s version does "
                "not match its admission" % (key,)
            )
        if section.get("realpath") != image.realpath:
            raise VerifyError(
                "unapproved runner chain: runner %s path does not "
                "match its admission" % (key,)
            )


def _require_admitted_execution(execution: dict) -> dict:
    """Return the runner record or reject an unapproved chain.

    The admission boundary for :func:`verify_bytes`: the three
    admission records must be genuine ``execution-contract-v1``
    admissions sharing one kernels-lock trust root, each matching
    that root's pins (names, versions, entry/exec/interpreter
    hashes, module tables, spawn argv and env sanitization) with
    a matching admission digest; the
    runner attestation must describe those same admissions; and
    the owned PATH farm must carry exactly the expected names,
    each resolving to its admitted target. Anything else --
    including an empty farm -- is rejected before any staging or
    spawn.
    """
    if not isinstance(execution, dict):
        raise VerifyError(
            "unapproved runner chain: expected the admitted "
            "runner record, got %s" % type(execution).__name__
        )
    for key in (
        "execution", "virtme_run_execution", "qemu_execution", "farm",
    ):
        if key not in execution:
            raise VerifyError(
                "unapproved runner chain: admitted runner record "
                "lacks %r" % (key,)
            )
    farm = execution["farm"]
    if (
        not isinstance(farm, str)
        or not os.path.isdir(farm)
        or not os.path.basename(farm).startswith("mojobpf-farm-")
    ):
        raise VerifyError(
            "unapproved runner chain: PATH farm is not an owned "
            "admission farm: %r" % (farm,)
        )
    try:
        entries = os.listdir(farm)
    except OSError as exc:
        raise VerifyError(
            "unapproved runner chain: PATH farm is unreadable: %s" % (exc,)
        )
    if not entries:
        raise VerifyError(
            "unapproved runner chain: PATH farm is empty: %r" % (farm,)
        )
    if [
        entry
        for entry in entries
        if not os.path.islink(os.path.join(farm, entry))
    ]:
        raise VerifyError(
            "unapproved runner chain: PATH farm carries non-link entries"
        )
    records: dict[str, AdmittedExecution] = {}
    for key in ("execution", "virtme_run_execution", "qemu_execution"):
        record = execution[key]
        if not isinstance(record, AdmittedExecution):
            raise VerifyError(
                "unapproved runner chain: %r is not an admitted "
                "execution record, got %s"
                % (key, type(record).__name__)
            )
        if record.contract != EXECUTION_CONTRACT_VERSION:
            raise VerifyError(
                "unapproved runner chain: %r carries contract %r, "
                "want %r"
                % (key, record.contract, EXECUTION_CONTRACT_VERSION)
            )
        if record.digest != _admission_digest(record):
            raise VerifyError(
                "unapproved runner chain: %r admission digest does "
                "not match its record" % (key,)
            )
        records[key] = record
    trust_roots = {record.trust_root for record in records.values()}
    if len(trust_roots) != 1:
        raise VerifyError(
            "unapproved runner chain: admission trust roots differ: %s"
            % (sorted(trust_roots),)
        )
    trust_root = trust_roots.pop()
    if not trust_root:
        raise VerifyError(
            "unapproved runner chain: admissions carry an empty "
            "trust root"
        )
    if not trust_root.startswith("lock:"):
        raise VerifyError(
            "unapproved runner chain: admission trust root %r is "
            "not a kernels lock" % (trust_root,)
        )
    lock_path = trust_root[len("lock:"):]
    try:
        runner_lock, _distribution = _load_runner_pins(lock_path)
    except VerifyError as exc:
        raise VerifyError(
            "unapproved runner chain: trust-root lock unusable: %s" % (exc,)
        )
    try:
        vng_pins = runner_pins(runner_lock)
        launcher_name, launcher_pins = virtme_run_pins(runner_lock)
        qemu_binary, emulator_pins = qemu_pins(runner_lock)
    except ValueError as exc:
        raise VerifyError(
            "unapproved runner chain: trust-root runner pins "
            "malformed: %s" % (exc,)
        )
    _require_record_matches_pins(
        "vng", records["execution"], vng_pins, "vng"
    )
    _require_record_matches_pins(
        launcher_name,
        records["virtme_run_execution"],
        launcher_pins,
        launcher_name,
    )
    _require_record_matches_pins(
        qemu_binary,
        records["qemu_execution"],
        emulator_pins,
        qemu_binary,
    )
    _require_runner_attestation(execution, records)
    expected_farm = {
        "vng": records["execution"].entry.realpath,
        launcher_name: records["virtme_run_execution"].entry.realpath,
        qemu_binary: records["qemu_execution"].image.realpath,
    }
    if set(entries) != set(expected_farm):
        raise VerifyError(
            "unapproved runner chain: PATH farm carries %s, want %s"
            % (sorted(entries), sorted(expected_farm))
        )
    for name in entries:
        if (
            os.path.realpath(os.path.join(farm, name))
            != expected_farm[name]
        ):
            raise VerifyError(
                "unapproved runner chain: PATH farm entry %r does "
                "not resolve to its admitted target" % (name,)
            )
    return execution


def _render_guest_script(
    *,
    pin_path: str,
    prog_type: str,
    map_types: tuple[str, ...],
    trace_event: str | None,
    kernel_btf: str,
    require_btf_flag: str,
    as_user: str | None,
) -> str:
    """Render the guest script from validated values only.

    The stage path is deliberately not an input: it travels as the
    script's argv ($1), never interpolated. Rejects the render when
    a forbidden attach/run/link token appears. The guest hashes
    the staged object and its own fixed script name around the
    load so the host can bind the loaded bytes to the capture
    (A1M4-3).
    """
    script = GUEST_SCRIPT_TEMPLATE.format(
        object_name=STAGED_OBJECT_NAME,
        script_name=STAGED_SCRIPT_NAME,
        pin=pin_path,
        prog_type=prog_type,
        map_types=" ".join(map_types),
        trace_event=trace_event or "",
        btf_path=kernel_btf,
        require_btf=require_btf_flag,
        as_user=as_user or "",
        guest_preflight=GUEST_PREFLIGHT_UNAVAILABLE,
        guest_load_failed=GUEST_LOAD_FAILED,
    )
    for token in _FORBIDDEN_GUEST_TOKENS:
        if token in script:
            raise VerifyError(
                "staged guest script carries forbidden token %r" % token
            )
    return script


def verify_bytes(
    object_bytes: bytes,
    lane: dict,
    execution: dict,
    *,
    object_path: str | None = None,
    pin_path: str = DEFAULT_PIN_PATH,
    prog_type: str = DEFAULT_PROG_TYPE,
    map_types: tuple[str, ...] | list[str] = (),
    trace_event: str | None = None,
    require_btf: str = "auto",
    kernel_btf: str = DEFAULT_KERNEL_BTF,
    as_user: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    keep_evidence: bool = False,
) -> dict:
    """Verify exactly the captured object bytes in the locked lane.

    Inspects, stages, hashes and attests the same ``object_bytes``:
    no path is re-read after capture, so a concurrent replacement
    cannot make the attested digest describe bytes the guest never
    ran. ``lane`` is the resolved kernels-lock lane (see
    :func:`resolve_lane`) and ``execution`` is the admitted runner
    record from admission (the ``execution-contract-v1`` chain
    plus its PATH farm); anything else is rejected at the
    admission boundary before any staging or spawn.

    The owned stage keeps restrictive permissions (0700 directory,
    0600 files) and is removed on success, failure and
    interruption unless ``keep_evidence`` is true; the result's
    ``cleanup`` record reports the outcome, and a failed cleanup
    stays visible there. Ownership of the admission PATH farm
    transfers here: it is removed with the stage unless evidence
    is kept. The result reports the lane's expected guest kernel
    fingerprint alongside the guest's actual one.

    Raises :class:`VerifyError` for setup failures and
    :class:`VerifyInterrupted` when SIGTERM/SIGINT arrives (the guest
    process group is killed and owned staging is removed first).
    Any other outcome, including timeouts and guest-side failures,
    is returned as a result dict; nothing here raises on a nonzero
    guest exit.
    """
    if not isinstance(object_bytes, (bytes, bytearray)):
        raise VerifyError(
            "object bytes must be bytes, got %s"
            % type(object_bytes).__name__
        )
    captured = bytes(object_bytes)
    lane = _require_lane(lane)
    runner = _require_admitted_execution(execution)
    if require_btf not in ("auto", "yes", "no"):
        raise VerifyError("require_btf must be 'auto', 'yes', or 'no'")
    if timeout <= 0:
        raise VerifyError("timeout must be positive")
    if not isinstance(keep_evidence, bool):
        raise VerifyError("keep_evidence must be a bool")
    if not pin_path.startswith("/sys/fs/bpf/"):
        raise VerifyError("pin path must live under /sys/fs/bpf/")
    validated_map_types = _require_map_types(map_types)
    _require_trace_event(trace_event)
    for label, value in (
        ("pin path", pin_path),
        ("program type", prog_type),
        ("kernel BTF path", kernel_btf),
    ):
        _require_safe_token(label, value)
    if as_user is not None and _SAFE_TOKEN.match(as_user) is None:
        raise VerifyError("user name carries unsafe characters: %r" % as_user)
    try:
        sections, license_bytes = read_elf_sections_bytes(captured)
        elf_error: str | None = None
    except ValueError as exc:
        sections, license_bytes, elf_error = [], None, str(exc)
    has_btf = any(name in (".BTF", ".BTF.ext") for name in sections)
    if require_btf == "auto":
        require_btf_flag = "1" if has_btf else "0"
    else:
        require_btf_flag = "1" if require_btf == "yes" else "0"
    object_sha256 = hashlib.sha256(captured).hexdigest()
    stage: str | None = None
    result: dict | None = None
    proc: subprocess.Popen | None = None
    # Inner-stage bindings (A1M4-3): pinned directory identity,
    # pre-run tamper snapshots, rendered script digest, and the
    # name monitor held from staging until the guest result is
    # parsed. Initialized here so every phase handler below can
    # reference them (a signal during staging sees Nones).
    stage_pin: tuple | None = None
    staged_snaps: dict = {}
    script_sha256: str | None = None
    stage_watch = None
    # start_new_session makes the child a session/group leader, so
    # its pid is the group id for the whole run. It is captured here,
    # never re-derived after the child exits (pid reuse would risk
    # signalling an unrelated group).
    child_pgid: int | None = None
    previous_sigterm = signal.getsignal(signal.SIGTERM)
    previous_sigint = signal.getsignal(signal.SIGINT)
    # Teardown errors the signal handler records when no result
    # record exists yet (staging and early preparation); the phase
    # handlers below merge them into the raised error.
    early_cleanup_errors: list[str] = []
    # Non-reentrant handler discipline (A1M14-1): the OS mask
    # cannot exclude a cross-thread trip, so a nested
    # cancellation can land mid-body and would abort the
    # outer pass (losing the drain with the guard already
    # popped). While handler_active, nested entries only
    # record their signal and return; the outer pass
    # completes teardown and raises once, with the nested
    # arrivals merged into its message. The check-and-set
    # itself is not atomic (no pure-Python form is); a
    # trip inside it runs a second full pass, which still
    # drains idempotently before raising while the
    # abandoned pass's drain-finally covers its window.
    handler_active = False
    nested_during_handler: list[int] = []

    def _handle_signal_inner(signum):
        nonlocal stage_watch
        # Delivery is blocked across the handler body: the teardown
        # and restoration below run once per pass. The incoming
        # mask is restored just before raising, so a pending nested
        # signal reaches this handler again only once the lifecycle
        # is already torn down and restored.
        signal.pthread_sigmask(
            signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT}
        )
        # Handler-side lease-guard cleanup first (A1M13-1):
        # this handler can run before the install guard's
        # release path is entered (or land mid-release via
        # a cross-thread trip despite the mask); retiring
        # active leases and draining their break
        # notifications here removes the fatal signal
        # before the raise below. Failures join the
        # interruption message; the empty case is a no-op.
        lease_failures = sealed_fs._release_active_lease_guards()
        attempted = False
        if result is not None and child_pgid is not None:
            runner_alive = proc is not None and proc.poll() is None
            descendants = [
                item
                for item in _group_members(child_pgid)
                if item["state"] not in ("Z", "X")
            ]
            if runner_alive or descendants:
                attempted = True
                result["child"]["group_killed"] = True
                result["child"]["group_reaped"] = _kill_group(child_pgid)
                result["child"]["group_members"] = _group_members(
                    child_pgid
                )
        if proc is not None and proc.poll() is None:
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass
        phase = "staging" if result is None else "guest run"
        message = "signal %d during %s" % (signum, phase)
        if attempted and result["child"]["group_reaped"] is False:
            message += (
                "; process cleanup failed: runner group %d not reaped"
                % (child_pgid,)
            )
        # Full lifecycle teardown here, not only in the phase
        # handlers: the raise below may land on an instruction
        # without exception-table protection (a `try:`-line NOP, or
        # the handler-restoration sequence itself) and bypass every
        # `except`/`finally` below, so teardown and restoration must
        # already be done when it executes. The phase handlers and
        # the `finally` re-run the same idempotent teardown and
        # restoration as a backstop. The cleanup report is merged
        # into the message here for the same reason: a landing that
        # bypasses the phase handlers would otherwise drop recorded
        # cleanup failures (the outer handler passes marked
        # interruptions through unchanged).
        if result is not None:
            _discard_owned(
                result, stage, runner["farm"], keep_evidence,
                stage_pin=stage_pin,
            )
            message += _cleanup_suffix(result)
        elif not keep_evidence:
            _teardown_owned_pair(
                stage, stage_pin, runner["farm"],
                early_cleanup_errors,
            )
            if early_cleanup_errors:
                message += "; staging cleanup failed: %s" % (
                    "; ".join(early_cleanup_errors)
                )
        for failure in lease_failures:
            message += "; %s" % failure
        # Close and clear the monitor in signal-owned teardown
        # (A1M5-3): the raise below may bypass every
        # `except`/`finally` (including the exit backstop
        # that also closes it), so the monitor must already
        # be closed when it executes. Idempotent via close().
        _close_inner_watch(stage_watch)
        stage_watch = None
        signal.signal(signal.SIGTERM, previous_sigterm)
        signal.signal(signal.SIGINT, previous_sigint)
        # The install lease helper may be on the stack with a
        # break notification pending under its mask (A1M10-1):
        # restoring the bare incoming mask then would deliver
        # a pending SIGIO to its default (fatal) disposition
        # here, before the raise below unwinds through the
        # helper's release-and-drain. Only in that case keep
        # the lease signals blocked: the helper drains them on
        # unwind, and the exit backstop restores the exact
        # incoming mask after. Off the lease window the mask
        # restores exactly (R4 item 2); no lease notification
        # can be pending there (the helper drains at exit).
        if sealed_fs._lease_held_in_this_thread():
            restore_mask = saved_mask | {signal.SIGIO, signal.SIGPOLL}
        else:
            restore_mask = saved_mask
        signal.pthread_sigmask(signal.SIG_SETMASK, restore_mask)
        # Merge arrivals nested during this pass (A1M14-1):
        # draining (not a snapshot) so a signal landing on
        # the merge itself is still attributed. An arrival
        # in the two bytecodes after the loop stays
        # recorded but misses the message; the raise still
        # carries the interruption itself.
        while nested_during_handler:
            message += "; nested signal %d during handler" % (
                nested_during_handler.pop(0)
            )
        interrupted = VerifyInterrupted(message)
        interrupted._mojobpf_teardown_done = True
        raise interrupted

    def _handle_signal(signum, _frame):
        nonlocal handler_active
        if handler_active:
            nested_during_handler.append(signum)
            return
        handler_active = True
        try:
            _handle_signal_inner(signum)
        finally:
            handler_active = False

    # One protected lifecycle: these handlers cover staging, runner
    # preparation, spawn, communication, postprocessing and cleanup
    # together, and are restored only after the last of them.
    # Delivery is blocked across installation (as across the spawn
    # registration window below): a signal arriving between the two
    # installs stays pending until the lifecycle try is entered, so
    # it raises inside protection and the finally below restores
    # both handlers instead of leaving the first one behind.
    # The incoming mask is saved here and restored exactly (via
    # SIG_SETMASK) on every exit path below: an incoming mask that
    # blocks SIGTERM/SIGINT must survive the lifecycle unchanged.
    saved_mask = signal.pthread_sigmask(
        signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT}
    )
    try:
        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)
    except BaseException:
        # Installation failed (for example outside the main
        # thread): the two installs share preconditions, so nothing
        # was installed; restore the incoming mask and re-raise.
        signal.pthread_sigmask(signal.SIG_SETMASK, saved_mask)
        raise
    try:
        signal.pthread_sigmask(signal.SIG_SETMASK, saved_mask)
        try:
            stage = tempfile.mkdtemp(prefix="mojobpf-verify-")
            # Restrictive staging: mkdtemp already yields 0700, but the
            # mode is set explicitly so an odd umask cannot widen it.
            os.chmod(stage, 0o700)
            # Sealed inner staging (A1M4-3): the object and the
            # script are published through unnamed temporaries
            # (no pathname reaches either while writable, so no
            # mapping or descriptor to the published inodes can
            # pre-exist), sealed read-only before publication,
            # and verified to be the sealed inodes holding the
            # captured bytes. The directory identity is pinned
            # at the first open (a fresh mkdtemp name cannot be
            # predicted, so the pin predates any same-uid
            # observer) and every later step binds to it; a
            # name monitor observes the two staged names until
            # the guest result is parsed.
            stage_fd = os.open(
                stage,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                | os.O_CLOEXEC,
            )
            try:
                pinned = os.fstat(stage_fd)
                stage_pin = (pinned.st_dev, pinned.st_ino)
                script_text = _render_guest_script(
                    pin_path=pin_path,
                    prog_type=prog_type,
                    map_types=validated_map_types,
                    trace_event=trace_event,
                    kernel_btf=kernel_btf,
                    require_btf_flag=require_btf_flag,
                    as_user=as_user,
                )
                script_bytes = script_text.encode("utf-8")
                script_sha256 = hashlib.sha256(
                    script_bytes
                ).hexdigest()
                _, object_snap = sealed_fs.install_sealed(
                    stage_fd, STAGED_OBJECT_NAME, captured, 0o444
                )
                _, script_snap = sealed_fs.install_sealed(
                    stage_fd, STAGED_SCRIPT_NAME, script_bytes,
                    0o444,
                )
                # The baselines are the installer-held inodes,
                # never later pathname reads (A1M6-1).
                installed_snaps = {
                    STAGED_OBJECT_NAME: object_snap,
                    STAGED_SCRIPT_NAME: script_snap,
                }
                stage_watch = sealed_fs.NameWatch(
                    "/proc/self/fd/%d" % stage_fd
                )
                # Re-verify under the monitor (A1M5-1): a
                # substitution after install verification but
                # before the arm predates all observation, so
                # the snapshots below must be taken over
                # entries re-proven to be the sealed inodes
                # holding the captured bytes.
                for name, data in (
                    (STAGED_OBJECT_NAME, captured),
                    (STAGED_SCRIPT_NAME, script_bytes),
                ):
                    if (
                        sealed_fs.snapshot_at(stage_fd, name)
                        != installed_snaps[name]
                    ):
                        raise AssertionError(
                            "staged %r is no longer the sealed "
                            "inode" % name
                        )
                    fd = os.open(
                        name,
                        os.O_RDONLY | os.O_NOFOLLOW
                        | os.O_CLOEXEC,
                        dir_fd=stage_fd,
                    )
                    try:
                        chunks = []
                        while True:
                            block = os.read(fd, 65536)
                            if not block:
                                break
                            chunks.append(block)
                    finally:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                    if b"".join(chunks) != bytes(data):
                        raise AssertionError(
                            "staged %r bytes differ from the "
                            "capture" % name
                        )
                staged_snaps = installed_snaps
            finally:
                try:
                    os.close(stage_fd)
                except OSError:
                    pass
            script_path = os.path.join(stage, STAGED_SCRIPT_NAME)
        except VerifyInterrupted as exc:
            # A signal during staging: no child exists yet, so the
            # handler killed nothing; the partial stage is removed here
            # unless evidence is kept, and a failed cleanup stays
            # visible on the raised error. The handler already ran the
            # same teardown, so the retry below is idempotent (already
            # removed trees are skipped, never reported as failures)
            # and merges the cleanup failures the handler recorded.
            # Interruptions the handler raised already carry that
            # report (cleanup failures included); they pass through
            # unchanged so each failure is reported exactly once.
            if getattr(exc, "_mojobpf_teardown_done", False):
                raise
            if not keep_evidence:
                _teardown_owned_pair(
                    stage, stage_pin, None,
                    early_cleanup_errors,
                )
            if early_cleanup_errors:
                wrapped = VerifyInterrupted(
                    "%s; staging cleanup failed: %s"
                    % (exc, "; ".join(early_cleanup_errors))
                )
                wrapped._mojobpf_teardown_done = True
                raise wrapped from exc
            exc._mojobpf_teardown_done = True
            raise
        except VerifyError as exc:
            if not keep_evidence:
                errors = []
                _teardown_owned_pair(
                    stage, stage_pin, None, errors
                )
                if errors:
                    raise VerifyError(
                        "%s; staging cleanup failed: %s"
                        % (exc, "; ".join(errors))
                    ) from exc
            raise
        except OSError as exc:
            if not keep_evidence:
                errors = []
                _teardown_owned_pair(
                    stage, stage_pin, None, errors
                )
                suffix = (
                    "; staging cleanup failed: %s"
                    % "; ".join(errors)
                    if errors
                    else ""
                )
            else:
                suffix = ""
            raise VerifyError(
                "cannot stage the verification: %s%s" % (exc, suffix)
            )
        except BaseException:
            # KeyboardInterrupt (or any other abrupt failure) during
            # staging must not leak the partial stage either, unless
            # evidence retention was requested.
            if not keep_evidence:
                _teardown_owned_pair(stage, stage_pin, None, [])
            raise
        assert stage is not None

        # The runner invocation prefix is the lane's pinned argv (never
        # reassembled from parts), extended with the quoted guest command.
        try:
            argv = list(lane["vng_argv_prefix"]) + [
                "--exec", guest_exec_command(script_path, stage),
            ]
            # The runner spawns through its admission: the captured entry
            # (honoring --vng even off PATH) under the sanitized
            # environment, with the PATH farm forcing the admitted
            # vng/virtme-run/QEMU chain however the runner resolves them.
            admitted = runner["execution"]
            argv[0] = admitted.argv_prefix[0]
            child_env_extra = {"PATH": farm_path_prefix(runner["farm"])}

            result = {
                "tool": TOOL_NAME,
                "schema": RESULT_SCHEMA,
                "status": "fail",
                "stage": "setup",
                "classification": None,
                "object": {
                    "path": object_path,
                    "sha256": object_sha256,
                    "size": len(captured),
                    "sections": sections,
                    "license": (
                        license_bytes.decode("ascii", "replace").rstrip("\x00")
                        if license_bytes is not None
                        else None
                    ),
                    "has_btf": has_btf,
                    "elf_parse_error": elf_error,
                },
                "lane": {
                    "id": lane["id"],
                    "release": lane["release"],
                    "accelerator": lane["accelerator"],
                    "kernel_release": lane["kernel_release"],
                    "kernel_debs": lane["kernel_debs"],
                    "vng_argv_prefix": lane["vng_argv_prefix"],
                },
                "runner": dict(
                    _runner_attestation(runner),
                    release=lane["release"],
                    accelerator=lane["accelerator"],
                    argv=argv,
                ),
                "guest": {
                    "kernel": None,
                    "kernel_expected": lane["kernel_release"],
                    "id": None,
                    "btf": None,
                    "prog_type": prog_type,
                    "prog_type_supported": None,
                    "probe_line": None,
                    "map_types": list(validated_map_types),
                    "map_types_supported": {},
                    "map_probe_lines": {},
                    "trace_event": trace_event,
                    "trace_event_supported": None,
                    "trace_event_id": None,
                },
                "preflight": {
                    "require_btf": require_btf,
                    "require_btf_effective": require_btf_flag == "1",
                    "kernel_btf_path": kernel_btf,
                    "as_user": as_user,
                    "map_types": list(validated_map_types),
                    "trace_event": trace_event,
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
                "cleanup": {
                    "staging_removed": False,
                    "kept": bool(keep_evidence),
                    "error": None,
                },
                "note": None,
            }

            output = ""
        except VerifyInterrupted as exc:
            # Interrupted during runner preparation (before the run
            # block): no child exists yet, so the handler killed
            # nothing; owned stage and farm are removed here unless
            # evidence is kept, and a failed cleanup stays visible
            # on the raised error. The handler already ran the same
            # teardown, so the retry below only removes what a
            # partial first pass left behind, and merges the cleanup
            # failures the handler recorded. Interruptions the
            # handler raised already carry that report (cleanup
            # failures included); they pass through unchanged so
            # each failure is reported exactly once.
            if getattr(exc, "_mojobpf_teardown_done", False):
                raise
            if not keep_evidence:
                errors = []
                _teardown_owned_pair(
                    stage, stage_pin, runner["farm"], errors
                )
                errors = list(early_cleanup_errors) + errors
                if errors:
                    wrapped = VerifyInterrupted(
                        "%s; staging cleanup failed: %s"
                        % (exc, "; ".join(errors))
                    )
                    wrapped._mojobpf_teardown_done = True
                    raise wrapped from exc
            exc._mojobpf_teardown_done = True
            raise
        except BaseException as exc:
            # Any other abrupt preparation failure must not leak the
            # owned stage or farm either, unless evidence retention
            # was requested. Cleanup failures for both trees are
            # collected and reported alongside the triggering error
            # (no child exists yet this early, so there is no group
            # to reap here).
            if not keep_evidence:
                errors = []
                _teardown_owned_pair(
                    stage, stage_pin, runner["farm"], errors
                )
                if errors and isinstance(
                    exc, (VerifyError, VerifyInterrupted)
                ):
                    raise type(exc)(
                        "%s; staging cleanup failed: %s"
                        % (exc, "; ".join(errors))
                    ) from exc
            raise

        try:
            try:
                # The registration window (child created but not yet
                # published to the handler) is closed by blocking
                # delivery across it: a signal arriving mid-spawn stays
                # pending until the child and its group id are
                # published below, so the handler always observes a
                # registered child and terminates it.
                signal.pthread_sigmask(
                    signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT}
                )
                try:
                    proc = popen_admitted(
                        admitted,
                        argv[1:],
                        env_extra=child_env_extra,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        start_new_session=True,
                    )
                except AdmissionError as exc:
                    _discard_owned(
                        result, stage, runner["farm"], keep_evidence,
                        stage_pin=stage_pin,
                    )
                    raise VerifyError(
                        "runner spawn refused: %s%s"
                        % (exc, _cleanup_suffix(result))
                    )
                except OSError as exc:
                    _discard_owned(
                        result, stage, runner["farm"], keep_evidence,
                        stage_pin=stage_pin,
                    )
                    raise VerifyError(
                        "failed to start vng: %s%s"
                        % (exc, _cleanup_suffix(result))
                    )
                child_pgid = proc.pid
            finally:
                # The registration window closes back to the incoming
                # mask, never to an unconditional unblock.
                signal.pthread_sigmask(
                    signal.SIG_SETMASK, saved_mask
                )
            deadline = time.monotonic() + timeout
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
                _discard_owned(
                    result, stage, runner["farm"], keep_evidence,
                    stage_pin=stage_pin,
                )
                return result

            # result["stage_path"] records the owned stage; it is removed
            # on every return below unless evidence is kept (see
            # _discard_owned), and result["cleanup"] reports the outcome.
            result["guest"]["kernel"] = _guest_kernel(output)
            result["guest"]["id"] = _parse_colon_value(output, "guest-id")
            btf = _parse_line_value(output, "kernel_btf")
            result["guest"]["btf"] = btf
            result["guest"]["probe_line"] = _parse_line_value(
                output, "probe_line"
            )
            supported = _parse_line_value(output, "prog_type_supported")
            result["guest"]["prog_type_supported"] = {
                "1": True, "0": False,
            }.get(supported or "", None)
            for map_type in validated_map_types:
                result["guest"]["map_probe_lines"][map_type] = (
                    _parse_line_value(
                        output, "map_probe_line[%s]" % map_type
                    )
                )
                map_supported = _parse_line_value(
                    output, "map_type_supported[%s]" % map_type
                )
                result["guest"]["map_types_supported"][map_type] = {
                    "1": True, "0": False,
                }.get(map_supported or "", None)
            result["guest"]["map_type_section"] = _parse_marked_block(
                output, "map-types"
            )
            if trace_event is not None:
                trace_supported = _parse_line_value(
                    output, "trace_event_supported"
                )
                result["guest"]["trace_event_supported"] = {
                    "1": True, "0": False,
                }.get(trace_supported or "", None)
                result["guest"]["trace_event_id"] = _parse_line_value(
                    output, "trace_event_id"
                ) or None
            result["resources"]["before"] = _parse_marked_block(
                output, "snapshot-before"
            )
            result["resources"]["after"] = _parse_marked_block(
                output, "snapshot-after"
            )
            result["guest_commands"] = re.findall(
                r"^guest-cmd: (.*)$", output, re.MULTILINE
            )

            # A run cut short by the deadline reports timeout
            # before any transcript gate runs: the incomplete
            # output is expected, not tampering. The integrity
            # gate below still guards every run that was not
            # cut short.
            if result["child"]["timed_out"]:
                _close_inner_watch(stage_watch)
                stage_watch = None
                result["status"] = "timeout"
                result["stage"] = "run"
                result["classification"] = "environment"
                result["note"] = (
                    "guest command exceeded %ds; runner process group killed "
                    "(reaped: %s)" % (
                        timeout, result["child"]["group_reaped"],
                    )
                )
                _discard_owned(
                    result, stage, runner["farm"], keep_evidence,
                    stage_pin=stage_pin,
                )
                return result

            # Inner-stage integrity gate (A1M4-3): bind the
            # guest result to the staged bytes before any
            # verdict is selected. A substitution after
            # capture must fail here even when the host-side
            # digests still match.
            violation = _inner_stage_violation(
                output, stage, stage_pin, staged_snaps,
                stage_watch,
                {
                    STAGED_OBJECT_NAME: object_sha256,
                    STAGED_SCRIPT_NAME: script_sha256,
                },
            )
            _close_inner_watch(stage_watch)
            stage_watch = None
            if violation is not None:
                result["status"] = "fail"
                result["stage"] = "run"
                result["classification"] = "environment"
                result["note"] = violation
                _discard_owned(
                    result, stage, runner["farm"], keep_evidence,
                    stage_pin=stage_pin,
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
                _discard_owned(
                    result, stage, runner["farm"], keep_evidence,
                    stage_pin=stage_pin,
                )
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
                _discard_owned(
                    result, stage, runner["farm"], keep_evidence,
                    stage_pin=stage_pin,
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
                _discard_owned(
                    result, stage, runner["farm"], keep_evidence,
                    stage_pin=stage_pin,
                )
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
                    "(pin %s, quiesced=%s)" % (pin_path, quiesced)
                )
                _discard_owned(
                    result, stage, runner["farm"], keep_evidence,
                    stage_pin=stage_pin,
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
                _discard_owned(
                    result, stage, runner["farm"], keep_evidence,
                    stage_pin=stage_pin,
                )
                return result
            result["status"] = "pass"
            result["stage"] = "done"
            result["classification"] = None
            _discard_owned(
                result, stage, runner["farm"], keep_evidence,
                stage_pin=stage_pin,
            )
            return result
        except VerifyInterrupted as exc:
            # The guest group is already dead (the handler killed it);
            # owned staging is removed here unless evidence is kept, and
            # a failed cleanup stays visible on the raised error.
            # Interruptions the handler raised already carry that
            # report (cleanup failures included); they pass through
            # unchanged so each failure is reported exactly once.
            if getattr(exc, "_mojobpf_teardown_done", False):
                raise
            _discard_owned(
                result, stage, runner["farm"], keep_evidence,
                stage_pin=stage_pin,
            )
            suffix = _cleanup_suffix(result)
            if suffix:
                wrapped = VerifyInterrupted("%s%s" % (exc, suffix))
                wrapped._mojobpf_teardown_done = True
                raise wrapped from exc
            exc._mojobpf_teardown_done = True
            raise
        except UnicodeDecodeError as exc:
            # Undecodable runner output: kill any surviving group
            # members first (the runner itself may already have exited
            # while orphaning a live emulator), then reap the runner,
            # remove owned staging, and report a setup failure (never a
            # pass, never a leak).
            if child_pgid is not None:
                members = _group_members(child_pgid)
                live = [
                    item
                    for item in members
                    if item["state"] not in ("Z", "X")
                ]
                if live:
                    result["child"]["group_killed"] = True
                    result["child"]["group_reaped"] = _kill_group(child_pgid)
                    result["child"]["group_members"] = _group_members(
                        child_pgid
                    )
                else:
                    result["child"]["group_members"] = members
                    if result["child"]["group_reaped"] is None:
                        result["child"]["group_reaped"] = True
            if proc is not None:
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                result["child"]["exit"] = proc.returncode
            _discard_owned(
                result, stage, runner["farm"], keep_evidence,
                stage_pin=stage_pin,
            )
            group_note = ""
            if result["child"]["group_reaped"] is False:
                group_note = (
                    "; process cleanup failed: runner group %d not reaped"
                    % (child_pgid,)
                )
            raise VerifyError(
                "runner printed undecodable output: %s%s%s"
                % (exc, group_note, _cleanup_suffix(result))
            )
    except VerifyInterrupted as exc:
        # An interruption no phase handler saw: either a signal that
        # landed on a lifecycle transition between the phase blocks
        # above, or one that arrived during handler installation and
        # stayed pending until the mask restore above. The signal
        # handler already ran the full lifecycle teardown (live child
        # group, owned stage and farm); the teardown below re-runs it
        # idempotently as a backstop, so nothing leaks from a
        # transition point, and a failed cleanup stays visible on the
        # raised error. Interruptions already torn down carry the
        # marker and pass through with their report (cleanup
        # failures included) unchanged.
        if getattr(exc, "_mojobpf_teardown_done", False):
            raise
        if child_pgid is not None and result is not None:
            live = [
                item
                for item in _group_members(child_pgid)
                if item["state"] not in ("Z", "X")
            ]
            if live:
                result["child"]["group_killed"] = True
                result["child"]["group_reaped"] = _kill_group(
                    child_pgid
                )
                result["child"]["group_members"] = _group_members(
                    child_pgid
                )
        if result is not None:
            _discard_owned(
                result, stage, runner["farm"], keep_evidence,
                stage_pin=stage_pin,
            )
            suffix = _cleanup_suffix(result)
            if suffix:
                wrapped = VerifyInterrupted("%s%s" % (exc, suffix))
                wrapped._mojobpf_teardown_done = True
                raise wrapped from exc
        elif not keep_evidence:
            errors = []
            _teardown_owned_pair(
                stage, stage_pin, runner["farm"], errors
            )
            errors = list(early_cleanup_errors) + errors
            if errors:
                wrapped = VerifyInterrupted(
                    "%s; staging cleanup failed: %s"
                    % (exc, "; ".join(errors))
                )
                wrapped._mojobpf_teardown_done = True
                raise wrapped from exc
        exc._mojobpf_teardown_done = True
        raise
    finally:
        # Restoration is atomic with respect to delivery as well: a
        # signal arriving between the two restores would otherwise
        # raise through the half-restored pair and leave one behind.
        # Delivery held here reaches the previous handlers once the
        # lifecycle is over, which is the correct disposition then.
        # (On interruption paths the handler already restored this
        # same pair and mask; this backstop is idempotent.) The mask
        # is restored to exactly the incoming one, after teardown
        # and handler restoration are both complete.
        signal.pthread_sigmask(
            signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT}
        )
        try:
            signal.signal(signal.SIGTERM, previous_sigterm)
            signal.signal(signal.SIGINT, previous_sigint)
        finally:
            # Idempotent inner-watch close: the gate closes early on
            # the happy path; this covers every raise/return that
            # bypasses it (None-safe before staging arms it).
            _close_inner_watch(stage_watch)
            signal.pthread_sigmask(
                signal.SIG_SETMASK, saved_mask
            )


def run_verification(request: VerifyRequest) -> dict:
    """Boot one guest, load/unload the object there, return the result.

    Captures the object file's bytes once, resolves the effective
    release/accelerator to a locked lane, admits the runner chain,
    and verifies exactly the captured bytes via :func:`verify_bytes`.

    Raises :class:`VerifyError` for setup failures and
    :class:`VerifyInterrupted` when SIGTERM/SIGINT arrives (the guest
    process group is killed and owned staging is removed first).
    Any other outcome, including timeouts and guest-side failures,
    is returned as a result dict; nothing here raises on a nonzero
    guest exit.
    """
    if not os.path.isfile(request.object_path):
        raise VerifyError("object not found: %s" % request.object_path)
    object_bytes = _read_object_bytes(request.object_path)
    lane = resolve_lane(
        request.release, request.accelerator, request.kernels_lock
    )
    runner = _probe_vng(
        request.vng_path,
        kernels_lock=request.kernels_lock,
    )
    try:
        return verify_bytes(
            object_bytes,
            lane,
            runner,
            object_path=request.object_path,
            pin_path=request.pin_path,
            prog_type=request.prog_type,
            map_types=request.map_types,
            trace_event=request.trace_event,
            require_btf=request.require_btf,
            kernel_btf=request.kernel_btf,
            as_user=request.as_user,
            timeout=request.timeout,
            keep_evidence=request.keep_evidence,
        )
    except BaseException as exc:
        # Farm ownership transfers to verify_bytes once it stages;
        # when it raises before (or without) taking ownership, the
        # farm is removed here instead of leaking, unless evidence
        # is kept. Removals that verify_bytes already performed are
        # skipped, and a farm that cannot be removed is reported on
        # the in-flight setup or interruption error.
        if not request.keep_evidence and os.path.lexists(runner["farm"]):
            error = _remove_owned_tree(runner["farm"])
            if error is not None and isinstance(
                exc, (VerifyError, VerifyInterrupted)
            ):
                raise type(exc)(
                    "%s; PATH farm cleanup failed: %s" % (exc, error)
                ) from exc
        raise


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
    lane = result.get("lane", {})
    lines.append(
        "lane: %s (release %s/%s, expected kernel %s)" % (
            lane.get("id"), lane.get("release"),
            lane.get("accelerator"), lane.get("kernel_release"),
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
    cleanup = result.get("cleanup", {})
    lines.append(
        "staging: %s (kept=%s%s)" % (
            result.get("stage_path"),
            cleanup.get("kept"),
            (
                "; cleanup failed: %s" % cleanup.get("error")
                if cleanup.get("error")
                else ""
            ),
        )
    )
    note = result.get("note")
    if note:
        lines.append("note: %s" % note)
    lines.append("guest commands: load/unload only; no attach, no test-run")
    return "\n".join(lines) + "\n"


STAGE_VERIFY_LOAD = "verify.load"

CODE_LOADER_FAILED = "MBPF501"
CODE_VERIFIER_REJECTED = "MBPF502"


def verification_diagnostic(result: dict) -> Diagnostic | None:
    """Return the stable diagnostic for a load failure, if any.

    ``load-failed`` with classification ``verifier`` yields
    ``MBPF502``; any other ``load-failed`` yields ``MBPF501``
    (loader). Every other outcome yields ``None``. The diagnostic
    classifies at a stable level; the raw loader log stays in the
    result document and evidence, never inside the code.
    """
    if result.get("status") != "load-failed":
        return None
    where = result.get("object", {}).get("path")
    if result.get("classification") == "verifier":
        return Diagnostic(
            code=CODE_VERIFIER_REJECTED,
            stage=STAGE_VERIFY_LOAD,
            severity="error",
            explanation=(
                "the kernel verifier rejected the program; "
                "the raw verifier log is preserved in the "
                "result document"
            ),
            location=where,
            remedy=(
                "narrow the program to the supported subset "
                "and re-run mojobpf verify"
            ),
        )
    return Diagnostic(
        code=CODE_LOADER_FAILED,
        stage=STAGE_VERIFY_LOAD,
        severity="error",
        explanation=(
            "the loader failed to load the object "
            "(not a verifier rejection); "
            "the raw loader log is preserved in the "
            "result document"
        ),
        location=where,
        remedy="inspect the object and the load log, then re-run",
    )


def main(argv: list[str] | None = None) -> int:
    """Standalone ``mojobpf verify`` entry (``python -m`` use).

    The installed ``mojobpf verify`` command lives in ``cli.py``
    and carries the same exit mapping; keep the two aligned.
    """
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
    parser.add_argument(
        "--keep-evidence",
        action="store_true",
        help="keep the owned stage and PATH farm instead of removing them",
    )
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
            keep_evidence=args.keep_evidence,
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
        diagnostic = verification_diagnostic(result)
        if diagnostic is not None:
            sys.stderr.write("%s\n" % diagnostic)
        return 5
    return 3


if __name__ == "__main__":
    sys.exit(main())
