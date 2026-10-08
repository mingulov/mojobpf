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
reports the outcome. Its transform semantics are therefore exactly the
sibling's; this file must never grow its own IR rewriting.

The service emits ``MBPF212`` for its own failures (malformed JSON,
unknown field, unsupported version, mode or profile, unreadable
input, unwritable output, unloadable adapter, internal transform
failure) and propagates the audit's exact ``MBPF3xx`` diagnostics
unchanged for rejected input IR.

Stages: ``adapter.request`` (request validation) and
``adapter.transform`` (shape validation, adaptation, output writing).

Supported vocabulary is deliberately narrow and every unknown value
fails loudly: request ``schema_version`` must be 1, ``profile_id``
must name a registered target profile (today the base, CO-RE, hash,
and reservation capability profiles), and ``diagnostic_mode`` must
be ``text`` (plain explanations; the field is reserved for future
modes).

Exit codes: 0 when the response reports success, 1 when a response
reporting failure was written, 2 when no response could be written
(unusable invocation or unwritable response path). Callers must treat
a missing or malformed response as a failure even when the exit code
is 0.

The service reads and writes regular files only. It spawns no
subprocess, needs no privilege, and never loads BPF programs.

Standard library only.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys

ADAPTER_SCHEMA_VERSION = 1

SUPPORTED_PROFILE_IDS = (
    "linux-bpfel-v3",
    "linux-bpfel-v3-core",
    "linux-bpfel-v3-hash",
    "linux-bpfel-v3-reserve",
)

SUPPORTED_DIAGNOSTIC_MODES = ("text",)

STAGE_ADAPTER_REQUEST = "adapter.request"
STAGE_ADAPTER_TRANSFORM = "adapter.transform"

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
    if request["profile_id"] not in SUPPORTED_PROFILE_IDS:
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
                        % ", ".join(SUPPORTED_PROFILE_IDS),
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
