# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Versioned JSON file interface around the exact-match IR adapter.

The build driver invokes this service once per program as a plain
subprocess (file interface, never a long-lived compiler service)::

    python3 adapter_service.py --request req.json --response resp.json

The request names the input IR path, the manifest path, the target
profile ID, the output directory and the diagnostic mode. The response
names the generated adapted IR and carries structured diagnostics.
Every diagnostic dict uses the same six keys as the build driver's
``Diagnostic`` model (``code``, ``stage``, ``severity``,
``explanation``, ``location``, ``remedy``).

This service performs no transformation of its own: it validates the
request, delegates to :mod:`mojo_ir_adapter` (``validate`` then
``adapt``, imported from the sibling file in this directory), and
reports the outcome, with one in-lane tool step between the two: the
LLVM verifier (``opt -passes=verify``) runs over the input IR so
malformed modules fail here instead of deferring to llc. Its
transform semantics are therefore exactly the sibling's; this file
must never grow its own IR rewriting.

The service emits ``MBPF212`` for its own failures (malformed JSON,
unknown field, unsupported version, mode or profile, unreadable
input, unwritable output, unloadable adapter, internal transform
failure), ``MBPF106`` at ``adapter.verify`` when the LLVM verifier
rejects the input, ``MBPF103`` when no usable verifier resolves, and
propagates the audit's exact ``MBPF3xx`` diagnostics unchanged for
rejected input IR.

Stages: ``adapter.request`` (request validation),
``adapter.transform`` (shape validation, adaptation, output writing),
``adapter.verify`` (in-lane LLVM verification), and
``toolchain.discovery`` (verifier resolution).

Supported vocabulary is deliberately narrow and every unknown value
fails loudly: request ``schema_version`` must be 1, ``profile_id``
must name a target profile admitted by the sibling admission
descriptor (today the base, CO-RE, hash, reservation, subprogram,
and uprobe capability profiles), and ``diagnostic_mode`` must be
``text`` (plain explanations; the field is reserved for future
modes). Profile admission reads ``admission.json`` beside this
service fresh on every request -- the same bytes the host lookup
reads from the packaged lane -- with no import-environment
supplement: without the descriptor, no profile is admitted, in
every lane. Every descriptor entry is validated with the same
strictness as the host lookup (same required field set, same
per-field shapes, same key agreement): a malformed entry fails
the request closed instead of admitting by name alone.

Exit codes: 0 when the response reports success, 1 when a response
reporting failure was written, 2 when no response could be written
(unusable invocation or unwritable response path). Callers must treat
a missing or malformed response as a failure even when the exit code
is 0.

The service reads and writes regular files only. Its only
subprocesses are the verifier resolution (``llvm-config --bindir``,
skipped when ``MOJOBPF_OPT`` names the verifier directly) and the
verifier itself (``opt -passes=verify -disable-output`` over the
input IR, never over edited output); it needs no privilege and never
loads BPF programs.

Standard library only. The service never imports the host
package: admission comes solely from the sibling descriptor.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys

ADAPTER_SCHEMA_VERSION = 1

# Standalone admission descriptor (``admission.json``), generated
# from the authoritative capability registry at build time and
# shipped byte-identically beside this service in both lanes.
# Admission requires these bytes: every load below fails closed
# (a missing, malformed, or versioned descriptor admits
# nothing), and no import-environment lookup supplements it, so
# host lookup and this subprocess always agree.
ADMISSION_FILENAME = "admission.json"
ADMISSION_SCHEMA_VERSION = 1


def _admission_path():
    """Return the sibling admission descriptor path."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, ADMISSION_FILENAME)


_PROFILE_FIELD_NAMES = (
    "profile_id",
    "byte_order",
    "cpu",
    "allowed_pairs",
    "allowed_map_types",
    "allowed_key_types",
    "allowed_value_types",
    "allowed_max_entries",
    "allowed_ringbuf_sizes",
    "helper_ids",
    "btf_scope",
    "entry_return",
    "entry_parameters",
    "core_supported",
    "subprog_supported",
)


def _validate_admission_entry(profile_id, entry):
    """Validate one descriptor entry with host-lookup strictness.

    Duplicates the host ``mojobpf.capabilities`` entry
    validation exactly: the same required field set, the same
    per-field shapes, and the same key agreement. This service
    is stdlib-only and never imports the host package, so the
    rules are mirrored here instead of shared by import; the
    shared malformed-descriptor test proves both sides agree
    on malformed inputs. Raises ``ValueError`` on any drift.
    """
    if not isinstance(profile_id, str) or not profile_id:
        raise ValueError(
            "admission descriptor carries a bad profile id: %r"
            % (profile_id,)
        )
    if not isinstance(entry, dict) or set(entry) != set(
        _PROFILE_FIELD_NAMES
    ):
        raise ValueError(
            "admission descriptor entry %r is misshapen" % (profile_id,)
        )

    def _text(name):
        value = entry[name]
        if not isinstance(value, str) or not value:
            raise ValueError(
                "admission descriptor entry %r field %r must be a "
                "non-empty string" % (profile_id, name)
            )
        return value

    def _strs(name):
        value = entry[name]
        if not isinstance(value, list) or not all(
            isinstance(item, str) and item for item in value
        ):
            raise ValueError(
                "admission descriptor entry %r field %r must be a "
                "list of non-empty strings" % (profile_id, name)
            )
        return tuple(value)

    def _ints(name):
        value = entry[name]
        if not isinstance(value, list) or not all(
            _is_int(item) for item in value
        ):
            raise ValueError(
                "admission descriptor entry %r field %r must be a "
                "list of integers" % (profile_id, name)
            )
        return tuple(value)

    def _flag(name):
        value = entry[name]
        if type(value) is not bool:
            raise ValueError(
                "admission descriptor entry %r field %r must be a "
                "boolean" % (profile_id, name)
            )
        return value

    pairs = entry["allowed_pairs"]
    if not isinstance(pairs, list) or not all(
        isinstance(pair, list)
        and len(pair) == 2
        and all(isinstance(part, str) and part for part in pair)
        for pair in pairs
    ):
        raise ValueError(
            "admission descriptor entry %r field 'allowed_pairs' "
            "must be a list of string pairs" % (profile_id,)
        )
    _text("profile_id")
    _text("byte_order")
    _text("cpu")
    _strs("allowed_map_types")
    _strs("allowed_key_types")
    _strs("allowed_value_types")
    _ints("allowed_max_entries")
    _ints("allowed_ringbuf_sizes")
    _ints("helper_ids")
    _text("btf_scope")
    _text("entry_return")
    _strs("entry_parameters")
    _flag("core_supported")
    _flag("subprog_supported")
    if entry["profile_id"] != profile_id:
        raise ValueError(
            "admission descriptor entry %r disagrees with its key"
            % (profile_id,)
        )


def _load_admission_ids():
    """Return the admitted profile IDs from the sibling descriptor.

    Reads the descriptor fresh on every call and validates
    every entry with host-lookup strictness. Raises
    ``OSError`` when the descriptor cannot be read and
    ``ValueError`` when it is malformed: without these bytes,
    no profile is admitted.
    """
    path = _admission_path()
    with open(path, "r", encoding="utf-8") as handle:
        raw = handle.read()
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "admission descriptor is not valid JSON: %s" % exc
        ) from None
    if not isinstance(document, dict):
        raise ValueError("admission descriptor must be a JSON object")
    version = document.get("schema_version")
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != ADMISSION_SCHEMA_VERSION
    ):
        raise ValueError(
            "admission descriptor schema_version %r is not %d"
            % (version, ADMISSION_SCHEMA_VERSION)
        )
    profiles = document.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise ValueError("admission descriptor names no profiles")
    for profile_id, entry in profiles.items():
        _validate_admission_entry(profile_id, entry)
    return tuple(profiles)


def __getattr__(name):
    # Lazy admission view: reading ``SUPPORTED_PROFILE_IDS``
    # loads the sibling descriptor fresh (failing closed when it
    # is missing or malformed), so importing this service never
    # performs admission I/O of its own -- ``--help`` and other
    # non-request uses run without the descriptor, while every
    # request resolves admission from current bytes.
    if name == "SUPPORTED_PROFILE_IDS":
        return _load_admission_ids()
    raise AttributeError(
        "module %r has no attribute %r" % (__name__, name)
    )

SUPPORTED_DIAGNOSTIC_MODES = ("text",)

STAGE_ADAPTER_REQUEST = "adapter.request"
STAGE_ADAPTER_TRANSFORM = "adapter.transform"
STAGE_ADAPTER_VERIFY = "adapter.verify"
STAGE_TOOLCHAIN_DISCOVERY = "toolchain.discovery"

CODE_RE = re.compile(r"^MBPF[1-7][0-9]{2}$")

ADAPTED_FILENAME = "adapted.ll"

# Bound a rejection message carried into a diagnostic explanation so a
# hostile multi-megabyte IR line cannot bloat the response document.
EXPLANATION_LIMIT = 2000

_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "input_ir",
        "manifest_path",
        "profile_id",
        "output_dir",
        "diagnostic_mode",
    }
)


def _diagnostic(
    code,
    stage,
    explanation,
    location=None,
    remedy=None,
    severity="error",
):
    assert CODE_RE.match(code), "invalid diagnostic code: %r" % (code,)
    return {
        "code": code,
        "stage": stage,
        "severity": severity,
        "explanation": explanation,
        "location": location,
        "remedy": remedy,
    }


def _request_failure(explanation, location=None, remedy=None):
    return _diagnostic(
        "MBPF212",
        STAGE_ADAPTER_REQUEST,
        explanation,
        location=location,
        remedy=remedy,
    )


def _response(ok, outputs, diagnostics):
    return {
        "schema_version": ADAPTER_SCHEMA_VERSION,
        "ok": ok,
        "outputs": outputs,
        "diagnostics": diagnostics,
    }


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _load_adapter():
    """Import the sibling exact-match adapter from this directory."""
    here = os.path.dirname(os.path.abspath(__file__))
    sibling = os.path.join(here, "mojo_ir_adapter.py")
    spec = importlib.util.spec_from_file_location(
        "mojo_ir_adapter", sibling
    )
    if spec is None or spec.loader is None:
        raise OSError("cannot load sibling adapter: %s" % sibling)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bounded(text):
    if len(text) > EXPLANATION_LIMIT:
        return text[:EXPLANATION_LIMIT] + "...[truncated]"
    return text


# In-lane LLVM verification. After the audit admits the input IR and
# before exact-match editing, the service runs the LLVM verifier over
# the input file so malformed IR fails here with MBPF106 instead of
# deferring to llc. The verifier resolves like the test-owned
# llvm_tool helper: an explicit MOJOBPF_OPT path wins, otherwise
# llvm-config (MOJOBPF_LLVM_CONFIG or PATH) names the bindir holding
# opt. There is no PATH fallback: a missing or broken toolchain is
# loud (MBPF103), never silently substituted. Both environment inputs
# are unpinned tool paths, like MOJOBPF_LLVM_CONFIG before them; the
# production trust root is the driver's prior lockfile admission of
# the same LLVM family.
VERIFY_TIMEOUT_S = 120

# Spawn allowlist for the llvm-config/opt children (mirrors
# mojobpf.execution.SPAWN_ENV_ALLOW, inlined because this service
# is standalone stdlib-only): loader-injection and interpreter
# names never pass; only these names and prefixes do. No
# interpreter overlay: both children are native tools.
_SPAWN_ENV_ALLOW = frozenset(
    {
        "PATH",
        "HOME",
        "TMPDIR",
        "MODULAR_HOME",
        "LANG",
        "TZ",
        "PYTHONHASHSEED",
    }
)
_SPAWN_ENV_ALLOW_PREFIXES = (
    "LC_",
    "MOJO_",
    "MODULAR_",
    "LLVM_",
    "MOJOBPF_",
)
_SPAWN_ENV_UNSET = (
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "BASH_ENV",
    "ENV",
)


def _spawn_env():
    """Filter the ambient down to the spawn allowlist."""
    child = {}
    for name, value in os.environ.items():
        if name in _SPAWN_ENV_UNSET:
            continue
        if name in _SPAWN_ENV_ALLOW or name.startswith(
            _SPAWN_ENV_ALLOW_PREFIXES
        ):
            child[name] = value
    return child


def _is_executable_file(path):
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _resolve_verifier():
    """Return (opt_path, None) or (None, reason). Never raises."""
    override = os.environ.get("MOJOBPF_OPT")
    if override:
        if _is_executable_file(override):
            return (override, None)
        return (None, "MOJOBPF_OPT names an unusable verifier: %r" % (override,))
    config = os.environ.get("MOJOBPF_LLVM_CONFIG") or shutil.which(
        "llvm-config"
    )
    if not config:
        return (None, "llvm-config not found on PATH and MOJOBPF_OPT is unset")
    try:
        proc = subprocess.run(
            [config, "--bindir"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=VERIFY_TIMEOUT_S,
            env=_spawn_env(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return (None, "llvm-config --bindir failed: %s" % exc)
    bindir = (proc.stdout or "").strip().splitlines()
    if proc.returncode != 0 or not bindir:
        return (None, "llvm-config --bindir failed (exit %d)" % proc.returncode)
    candidate = os.path.join(bindir[0], "opt")
    if _is_executable_file(candidate):
        return (candidate, None)
    return (None, "no executable opt beside llvm-config bindir %r" % (bindir[0],))


def _verify_ir(input_ir):
    """Run the LLVM verifier; return None or a failure diagnostic."""
    opt, reason = _resolve_verifier()
    if opt is None:
        return _diagnostic(
            "MBPF103",
            STAGE_TOOLCHAIN_DISCOVERY,
            "in-lane LLVM verification needs opt: %s" % _bounded(reason),
            location="tool:opt",
            remedy="install the pinned LLVM toolchain so llvm-config "
            "resolves, or point MOJOBPF_OPT at its opt",
        )
    try:
        proc = subprocess.run(
            [opt, "-passes=verify", "-disable-output", input_ir],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=VERIFY_TIMEOUT_S,
            env=_spawn_env(),
        )
    except subprocess.TimeoutExpired:
        return _diagnostic(
            "MBPF103",
            STAGE_TOOLCHAIN_DISCOVERY,
            "in-lane LLVM verification timed out after %ds" % VERIFY_TIMEOUT_S,
            location="tool:opt",
            remedy="retry with a responsive toolchain; report a "
            "reproducible hang as a bug",
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return _diagnostic(
            "MBPF103",
            STAGE_TOOLCHAIN_DISCOVERY,
            "in-lane LLVM verification could not run opt: %s" % _bounded(str(exc)),
            location="tool:opt",
            remedy="install the pinned LLVM toolchain so llvm-config "
            "resolves, or point MOJOBPF_OPT at its opt",
        )
    if proc.returncode == 0:
        return None
    first = ""
    for line in (proc.stderr or "").splitlines():
        if line.strip():
            first = line.strip()
            break
    if not first:
        first = "exit %d with no error output" % proc.returncode
    return _diagnostic(
        "MBPF106",
        STAGE_ADAPTER_VERIFY,
        "LLVM verifier rejected the input IR: %s" % _bounded(first),
        location=input_ir,
        remedy="fix the reported IR error; the log excerpt names it",
    )


def handle_request(request_path, response_path):
    """Serve one JSON request; return the process exit code.

    A response document is written whenever the response path allows
    it, including for malformed requests. Returns 2 only when no
    response could be written.
    """
    try:
        with open(request_path, "r", encoding="utf-8") as handle:
            raw_request = handle.read()
    except OSError as exc:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "cannot read adapter request: %s" % exc,
                        location=request_path,
                        remedy="check the request path and file permissions",
                    )
                ],
            ),
        )
    try:
        request = json.loads(raw_request)
    except json.JSONDecodeError as exc:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "adapter request is not valid JSON: %s" % exc,
                        location=request_path,
                        remedy="send a JSON object with the documented "
                        "request fields",
                    )
                ],
            ),
        )
    if not isinstance(request, dict):
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "adapter request must be a JSON object",
                        location=request_path,
                        remedy="send a JSON object with the documented "
                        "request fields",
                    )
                ],
            ),
        )
    for key in request:
        if key not in _REQUEST_FIELDS:
            return _write_response(
                response_path,
                _response(
                    False,
                    {},
                    [
                        _request_failure(
                            "unknown adapter request field: %r" % (key,),
                            location="%s: %s" % (request_path, key),
                            remedy="remove the unknown field",
                        )
                    ],
                ),
            )
    missing = _REQUEST_FIELDS - set(request)
    if missing:
        name = sorted(missing)[0]
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "adapter request lacks required field: %r" % (name,),
                        location="%s: %s" % (request_path, name),
                        remedy="provide all request fields: %s"
                        % ", ".join(sorted(_REQUEST_FIELDS)),
                    )
                ],
            ),
        )
    version = request["schema_version"]
    if not _is_int(version) or version != ADAPTER_SCHEMA_VERSION:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "unsupported adapter request schema_version %r; "
                        "this service reads version %d"
                        % (version, ADAPTER_SCHEMA_VERSION),
                        location="%s: schema_version" % request_path,
                        remedy="send schema_version %d"
                        % ADAPTER_SCHEMA_VERSION,
                    )
                ],
            ),
        )
    for key in ("input_ir", "manifest_path", "profile_id", "output_dir",
                "diagnostic_mode"):
        if not isinstance(request[key], str) or not request[key]:
            return _write_response(
                response_path,
                _response(
                    False,
                    {},
                    [
                        _request_failure(
                            "adapter request field %r must be a non-empty "
                            "string" % (key,),
                            location="%s: %s" % (request_path, key),
                            remedy="set %r to a non-empty string" % (key,),
                        )
                    ],
                ),
            )
    try:
        admitted_ids = _load_admission_ids()
    except (OSError, ValueError) as exc:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "adapter admission descriptor is unusable: %s"
                        % exc,
                        location=_admission_path(),
                        remedy="restore admission.json beside the "
                        "adapter service (reinstall the mojobpf "
                        "package for the packaged lane)",
                    )
                ],
            ),
        )
    if request["profile_id"] not in admitted_ids:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "unsupported target profile: %r"
                        % (request["profile_id"],),
                        location="%s: profile_id" % request_path,
                        remedy="use one of: %s"
                        % ", ".join(admitted_ids),
                    )
                ],
            ),
        )
    if request["diagnostic_mode"] not in SUPPORTED_DIAGNOSTIC_MODES:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "unsupported diagnostic_mode: %r"
                        % (request["diagnostic_mode"],),
                        location="%s: diagnostic_mode" % request_path,
                        remedy="use one of: %s"
                        % ", ".join(SUPPORTED_DIAGNOSTIC_MODES),
                    )
                ],
            ),
        )
    if not os.path.isfile(request["input_ir"]):
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "input IR not found: %r" % (request["input_ir"],),
                        location="%s: input_ir" % request_path,
                        remedy="point input_ir at the frontend's LLVM IR "
                        "output",
                    )
                ],
            ),
        )
    if not os.path.isfile(request["manifest_path"]):
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "manifest not found: %r"
                        % (request["manifest_path"],),
                        location="%s: manifest_path" % request_path,
                        remedy="point manifest_path at the project manifest",
                    )
                ],
            ),
        )
    try:
        os.makedirs(request["output_dir"], exist_ok=True)
    except OSError as exc:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "cannot create output directory %r: %s"
                        % (request["output_dir"], exc),
                        location="%s: output_dir" % request_path,
                        remedy="use a writable output directory",
                    )
                ],
            ),
        )
    if not os.path.isdir(request["output_dir"]):
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "output directory is not a directory: %r"
                        % (request["output_dir"],),
                        location="%s: output_dir" % request_path,
                        remedy="use a writable output directory",
                    )
                ],
            ),
        )
    try:
        with open(request["input_ir"], "r", encoding="utf-8") as handle:
            text = handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _request_failure(
                        "cannot read input IR: %s" % exc,
                        location=request["input_ir"],
                        remedy="check the input IR path and file permissions",
                    )
                ],
            ),
        )
    try:
        adapter = _load_adapter()
    except OSError as exc:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _diagnostic(
                        "MBPF212",
                        STAGE_ADAPTER_TRANSFORM,
                        "cannot load the IR adapter: %s" % exc,
                        location="mojo_ir_adapter.py",
                        remedy="restore the adapter next to this service",
                    )
                ],
            ),
        )
    try:
        adapter.validate(text)
        verify_failed = _verify_ir(request["input_ir"])
        if verify_failed is not None:
            return _write_response(
                response_path,
                _response(False, {}, [verify_failed]),
            )
        adapted = adapter.adapt(text)
    except adapter.AdapterError as exc:
        # Structured audit rejections propagate unchanged: the exact
        # MBPF3xx code, audit stage, IR location and remedy survive
        # the service boundary verbatim.
        return _write_response(
            response_path,
            _response(False, {}, [exc.to_diagnostic()]),
        )
    except Exception as exc:
        # Anything else from the transform is an internal adapter
        # failure, never presented as unsupported user IR.
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _diagnostic(
                        "MBPF212",
                        STAGE_ADAPTER_TRANSFORM,
                        "adapter failed internally: %s"
                        % _bounded(str(exc)),
                        location=request["input_ir"],
                        remedy="report this adapter failure as a bug",
                    )
                ],
            ),
        )
    adapted_path = os.path.join(request["output_dir"], ADAPTED_FILENAME)
    try:
        with open(adapted_path, "w", encoding="utf-8") as handle:
            handle.write(adapted)
    except OSError as exc:
        return _write_response(
            response_path,
            _response(
                False,
                {},
                [
                    _diagnostic(
                        "MBPF212",
                        STAGE_ADAPTER_TRANSFORM,
                        "cannot write adapted IR: %s" % exc,
                        location=adapted_path,
                        remedy="use a writable output directory",
                    )
                ],
            ),
        )
    return _write_response(
        response_path,
        _response(True, {"adapted_ir": adapted_path}, []),
    )


def _write_response(response_path, document):
    """Write the response document; return 0/1, or 2 if unwritable."""
    try:
        with open(response_path, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError as exc:
        sys.stderr.write(
            "adapter service: cannot write response %r: %s\n"
            % (response_path, exc)
        )
        return 2
    return 0 if document["ok"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Serve one versioned JSON adapter request."
    )
    parser.add_argument("--request", required=True, help="request JSON file")
    parser.add_argument(
        "--response", required=True, help="response JSON file to write"
    )
    args = parser.parse_args(argv)
    return handle_request(args.request, args.response)


if __name__ == "__main__":
    sys.exit(main())
