# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Materialize the capability coverage ledger.

Reads three inputs -- the capability registry, the target matrix,
and the pinned library API row extract (stamped from the
independently packaged API coverage artifact by
extract_api_rows.py) -- and emits one cell per record x
required-target x path, each cell evaluated to QUALIFIED,
OPEN, or NOT_APPLICABLE.

Status rules: a producer cell is QUALIFIED only when its record
is IMPLEMENTED and tested, carries at least one evidence
reference, and has neither a record blocker nor a matching
family blocker. A consumer cell additionally requires the
joined library row to be applicable without a blocker, with
all raw/forwarding/typed layers present-or-inapplicable and
every evidence layer PASS. Absent matrix targets resolve
through the matrix absent list only: BLOCKED_* entries keep
cells OPEN with the excuse rationale, while justified
NOT_APPLICABLE entries exclude them. Record blockers never
excuse an absent target; they only deny qualification and
annotate the rationale.

All failure modes are fail-closed: unowned records, owners
outside the registry package list, duplicate package IDs or
titles, unknown userspace surfaces, states, or evidence
levels, malformed evidence references or blockers,
duplicate record/API-row identities, duplicate required
targets, records with no cells, unsupported API artifact
versions, unknown row values, required targets missing from
the matrix without an excuse, contradictory matrices,
missing or dangling consumer rows, unjustified exclusions,
and malformed cost cases each raise CoverageError.
"""

import argparse
import hashlib
import json
import math
import os
import re
import secrets
import sys

LEDGER_FORMAT_VERSION = 1

# SHA-256 of schemas/capability.schema.json. The registry gate
# refuses any sidecar bytes that differ, so behavior cannot
# drift from the reviewed inventory contract. Pinned by test
# to the tree file; update in the same commit as the schema.
CAPABILITY_SCHEMA_SHA256 = (
    "2d5ab6cb8f01fb0a0040420c623ac1b167e2a72240fbba10e496282c311af099"
)

KNOWN_SURFACES = frozenset(
    {
        "load-attach",
        "map-ops",
        "event-consume",
        "section-convention",
        "raw-syscall",
        "library-symbol",
        "option-flag",
        "not-applicable",
    }
)

KNOWN_STATES = frozenset(
    {
        "REPORTED",
        "AUDITED",
        "IN_PROGRESS",
        "IMPLEMENTED",
        "QUALIFIED",
        "BLOCKED_UPSTREAM",
        "BLOCKED_TOOLCHAIN",
        "BLOCKED_HARDWARE",
        "PLANNED",
    }
)

KNOWN_EVIDENCE_LEVELS = frozenset(
    {"none", "reported", "audited", "tested"}
)

RECORD_BLOCKER_STATUSES = frozenset(
    {
        "BLOCKED_UPSTREAM",
        "BLOCKED_TOOLCHAIN",
        "BLOCKED_HARDWARE",
        "PLANNED",
    }
)

MATRIX_EXCUSE_STATUSES = frozenset(
    {
        "BLOCKED_UPSTREAM",
        "BLOCKED_TOOLCHAIN",
        "BLOCKED_HARDWARE",
        "PLANNED",
        "NOT_APPLICABLE",
    }
)

COST_PATTERN = re.compile(r"[A-Z][A-Z0-9]*(-[A-Z0-9]+)+")

API_SCHEMA_VERSION = 1

EXPECTED_LAYERS = frozenset(
    {
        "source",
        "native_host",
        "mojo_host",
        "installed_host",
        "target_runtime",
        "binary_abi",
    }
)

KNOWN_OUTCOMES = frozenset({"NOT_RUN", "PASS", "FAIL", "BLOCKED"})

KNOWN_APPLICABILITY = frozenset({"required", "excluded"})

RAW_STATUSES = frozenset({"ABSENT", "SOURCE_PRESENT", "NOT_APPLICABLE"})
RAW_PRESENT = frozenset({"SOURCE_PRESENT", "NOT_APPLICABLE"})

ADAPTER_STATUSES = frozenset(
    {
        "ABSENT",
        "SOURCE_PRESENT_PARTIAL",
        "SOURCE_PRESENT_COMPLETE",
        "NOT_APPLICABLE",
    }
)
ADAPTER_PRESENT = frozenset(
    {
        "SOURCE_PRESENT_PARTIAL",
        "SOURCE_PRESENT_COMPLETE",
        "NOT_APPLICABLE",
    }
)


class CoverageError(Exception):
    """Raised when ledger inputs cannot be joined into a closed ledger."""


def _parse_json_bytes(raw, path):
    """Parse JSON bytes, refusing ambiguity and odd constants."""
    try:
        text = raw.decode("utf-8")
    except ValueError as exc:
        raise CoverageError(f"{path} is not valid UTF-8: {exc}")

    def _refuse_dups(pairs):
        seen = set()
        document = {}
        for key, value in pairs:
            if key in seen:
                raise CoverageError(
                    f"{path} has a duplicate key {key!r}"
                )
            seen.add(key)
            document[key] = value
        return document

    def _refuse_constant(token):
        raise CoverageError(
            f"{path} uses non-standard constant {token}"
        )

    def _refuse_nonfinite(text_value):
        value = float(text_value)
        if not math.isfinite(value):
            raise CoverageError(
                f"{path} uses non-finite number {text_value}"
            )
        return value

    try:
        return json.loads(
            text,
            object_pairs_hook=_refuse_dups,
            parse_constant=_refuse_constant,
            parse_float=_refuse_nonfinite,
        )
    except CoverageError:
        raise
    except ValueError as exc:
        raise CoverageError(f"{path} is not valid JSON: {exc}")


def _load_json_strict(path):
    """Load JSON, refusing duplicate object keys.

    Duplicate keys parse silently under last-key-wins, so two
    byte-distinct files could claim one content hash. Every
    ledger input loads through here; ambiguous bytes fail.
    """
    with open(path, "rb") as handle:
        raw = handle.read()
    return _parse_json_bytes(raw, path)


def dump_ledger(ledger):
    """Serialize a ledger to its canonical committed bytes."""
    return (
        json.dumps(ledger, indent=2, sort_keys=True, allow_nan=False)
        + "\n"
    )


def _atomic_write_text(path, text, _opener=open):
    """Write text atomically: temp file plus rename.

    A mid-write failure must never truncate an existing
    output. The temp name carries an unguessable token and
    opens with exclusive creation, so a predicted name
    can neither clobber nor follow an unrelated file;
    the opener seam exists for fault-injection tests.
    No raw descriptors are handled here at all, so there
    is no descriptor ownership to split: only the temp
    path is ever cleaned up.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    tmp = os.path.join(
        directory,
        ".%s.%s.tmp" % (os.path.basename(path), secrets.token_hex(8)),
    )
    try:
        handle = _opener(tmp, "x", encoding="utf-8")
    except FileExistsError:
        # Exclusive creation refused: the path belongs to
        # someone else, so there is nothing of ours to clean.
        raise
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        with handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _well_formed_blocker(blocker):
    if not isinstance(blocker, dict):
        return False
    status = blocker.get("status", "")
    if not isinstance(status, str):
        return False
    if status not in RECORD_BLOCKER_STATUSES:
        return False
    detail = blocker.get("detail", "")
    if not isinstance(detail, str) or not detail.strip():
        return False
    action = blocker.get("next_action", "")
    if not isinstance(action, str):
        return False
    return True


def _string_list(value):
    return isinstance(value, list) and all(
        isinstance(item, str) and item.strip() for item in value
    )


def _check_helper_entries(ident, entries):
    if not isinstance(entries, list):
        raise CoverageError(
            f"record {ident} has malformed helpers_or_kfuncs "
            "(must be a list)"
        )
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"name", "kind", "callable"}
            or not isinstance(entry["name"], str)
            or not entry["name"].strip()
            or entry["kind"] not in ("helper", "kfunc")
            or not isinstance(entry["callable"], bool)
        ):
            raise CoverageError(
                f"record {ident} has a malformed helpers_or_kfuncs "
                "entry (name, kind helper|kfunc, callable bool)"
            )


def _canonical_bytes(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _sha256(payload):
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _rationale_of(excuse):
    rationale = {
        "status": excuse.get("status", ""),
        "detail": excuse.get("detail", ""),
    }
    if excuse.get("next_action"):
        rationale["next_action"] = excuse["next_action"]
    raw_refs = excuse.get("source_refs", [])
    if not isinstance(raw_refs, list):
        raise CoverageError(
            "excuse for %s has scalar source_refs "
            "(must be a list of non-blank strings)"
            % excuse.get("target", excuse.get("status", "row"))
        )
    refs = [
        ref
        for ref in raw_refs
        if isinstance(ref, str) and ref.strip()
    ]
    if refs:
        rationale["source_refs"] = refs
    return rationale


def _combined_rationale(primary, secondary):
    rationale = _rationale_of(primary)
    detail = secondary.get("detail", "")
    if detail:
        rationale["detail"] = "%s; record: %s" % (
            rationale["detail"],
            detail,
        )
    return rationale


def _verdict(row):
    layers = []
    for entry in row.get("evidence_cells", []):
        layers.append(
            {
                "layer": entry.get("layer", ""),
                "outcome": entry.get("outcome", ""),
                "target_profile": entry.get("target_profile", ""),
            }
        )
    blocker = row.get("blocker")
    return {
        "applicability": row.get("applicability", ""),
        "blocker": (
            None
            if blocker is None
            else {
                "reason": blocker.get("reason", ""),
                "next_action": blocker.get("next_action", ""),
            }
        ),
        "raw_status": row.get("raw_declaration", {}).get("status", ""),
        "forwarding_status": row.get("forwarding_adapter", {}).get(
            "status", ""
        ),
        "typed_status": row.get("typed_workflow", {}).get("status", ""),
        "layers": layers,
    }


def _producer_qualified(record, family_blocked):
    if record.get("blocker"):
        return False
    if family_blocked:
        return False
    if record.get("implementation_state") != "IMPLEMENTED":
        return False
    if record.get("evidence_level") != "tested":
        return False
    if not record.get("evidence_refs"):
        return False
    return True


def _consumer_qualified(producer_ok, row, contract_ok, runtime_ok):
    if not producer_ok:
        return False
    if row.get("applicability") != "required":
        return False
    if row.get("blocker") is not None:
        return False
    if row.get("raw_declaration", {}).get("status", "") not in RAW_PRESENT:
        return False
    for key in ("forwarding_adapter", "typed_workflow"):
        if row.get(key, {}).get("status", "") not in ADAPTER_PRESENT:
            return False
    cells = row.get("evidence_cells", [])
    if {cell.get("layer", "") for cell in cells} != EXPECTED_LAYERS:
        return False
    for cell in cells:
        if cell.get("outcome") != "PASS":
            return False
        # Source-contract evidence never satisfies the runtime
        # gate: only runtime-admitted profiles close runtime.
        allowed = (
            runtime_ok
            if cell.get("layer", "") == "target_runtime"
            else contract_ok
        )
        if cell.get("target_profile", "") not in allowed:
            return False
    return True


def _cell(record, target, path, status, package_title, rationale=None, row=None):
    obligations = {"lifecycle": []}
    cost_cases = record.get("cost_cases", [])
    if cost_cases:
        obligations["cost_cases"] = list(cost_cases)
    entry = {
        "id": f"{record['id']}@{target}#{path}",
        "record": record["id"],
        "target": target,
        "path": path,
        "status": status,
        "implementation": {
            # Human-readable owning-package title, not the
            # internal package ID: the ledger ships in source
            # distributions, where internal IDs are refused.
            # Join titles to the registry packages list for IDs.
            "package_title": package_title,
            "state": record.get("implementation_state", ""),
            "evidence_level": record.get("evidence_level", ""),
        },
        "qualification": {
            "positive_tests": list(record.get("positive_tests", [])),
            "negative_tests": list(record.get("negative_tests", [])),
            "interaction_tests": list(record.get("interaction_tests", [])),
        },
        "obligations": obligations,
        "applicability": {
            "predicate": record.get("applicability_predicate", ""),
            "evidence_refs": list(record.get("evidence_refs", [])),
            "upstream_refs": list(record.get("upstream_source_refs", [])),
        },
        "legal_context": {
            "program_types": list(record.get("program_types", [])),
            "attach_types": list(record.get("attach_types", [])),
            "link_types": list(record.get("link_types", [])),
            "map_types": list(record.get("map_types", [])),
            "helpers_or_kfuncs": list(record.get("helpers_or_kfuncs", [])),
            "callable_context_predicates": list(
                record.get("callable_context_predicates", [])
            ),
        },
        "producer": {
            "scope_required": True,
            "family": record.get("family", ""),
        },
    }
    if rationale is not None:
        entry["rationale"] = rationale
    if row is not None:
        entry["consumer"] = {
            "api_row": row.get("id", ""),
            "verdict": _verdict(row),
        }
    return entry


def _check_records(records, packages):
    seen = set()
    for record in records:
        if not isinstance(record, dict):
            raise CoverageError("registry record must be an object")
        ident = record.get("id", "")
        if not isinstance(ident, str) or not ident.strip():
            raise CoverageError(
                "registry record id must be a non-blank string"
            )
        if ident in seen:
            raise CoverageError(f"duplicate record id: {ident}")
        seen.add(ident)
        owner = record.get("owner_task", "")
        if not isinstance(owner, str) or not owner.strip():
            raise CoverageError(
                f"record {ident} is unowned (owner_task must be "
                "a non-blank string)"
            )
        if owner not in packages:
            raise CoverageError(
                f"record {ident} has unknown owner {owner} "
                "(not in the registry package list)"
            )
        family = record.get("family", "")
        if not isinstance(family, str) or not family.strip():
            raise CoverageError(
                f"record {ident} has malformed family "
                "(must be a non-blank string)"
            )
        surface = record.get("userspace_api_surface", "")
        if not isinstance(surface, str) or surface not in KNOWN_SURFACES:
            raise CoverageError(
                f"record {ident} has unknown userspace surface "
                f"{surface!r}"
            )
        state = record.get("implementation_state", "")
        if not isinstance(state, str) or state not in KNOWN_STATES:
            raise CoverageError(
                f"record {ident} has unknown implementation state "
                f"{state!r}"
            )
        level = record.get("evidence_level", "")
        if not isinstance(level, str) or level not in KNOWN_EVIDENCE_LEVELS:
            raise CoverageError(
                f"record {ident} has unknown evidence level {level!r}"
            )
        if record.get("scope_required") is not True:
            raise CoverageError(
                f"record {ident} has malformed scope_required "
                "(must be exactly true)"
            )
        refs = record.get("evidence_refs", [])
        if not isinstance(refs, list) or any(
            not isinstance(ref, str) or not ref.strip() for ref in refs
        ):
            raise CoverageError(
                f"record {ident} has malformed evidence_refs "
                "(must be a list of non-blank strings)"
            )
        upstream = record.get("upstream_source_refs", [])
        if not isinstance(upstream, list) or any(
            not isinstance(ref, str) or not ref.strip()
            for ref in upstream
        ):
            raise CoverageError(
                f"record {ident} has malformed upstream_source_refs "
                "(must be a list of non-blank strings)"
            )
        blocker = record.get("blocker")
        if blocker is not None and not _well_formed_blocker(blocker):
            raise CoverageError(
                f"record {ident} has a malformed blocker "
                "(status and detail must be non-blank)"
            )
        cost_cases = record.get("cost_cases", [])
        if not isinstance(cost_cases, list) or any(
            not isinstance(case, str) or not COST_PATTERN.fullmatch(case)
            for case in cost_cases
        ):
            raise CoverageError(
                f"record {ident} has malformed cost_cases "
                "(must be a list of case IDs)"
            )
        targets = record.get("targets_required", [])
        if not _string_list(targets) or any(
            not _clean_target(target) for target in targets
        ):
            raise CoverageError(
                f"record {ident} has malformed targets_required "
                "(must be non-blank targets without line breaks)"
            )
        if len(set(targets)) != len(targets):
            raise CoverageError(
                f"record {ident} has a duplicate target "
                "in targets_required"
            )
        for key in (
            "positive_tests",
            "negative_tests",
            "interaction_tests",
            "program_types",
            "attach_types",
            "link_types",
            "map_types",
            "callable_context_predicates",
        ):
            if not _string_list(record.get(key, [])):
                raise CoverageError(
                    f"record {ident} has malformed {key} "
                    "(must be a list of non-blank strings)"
                )
        _check_helper_entries(ident, record.get("helpers_or_kfuncs", []))


ROW_REQUIRED_KEYS = (
    "id",
    "workflow",
    "applicability",
    "raw_declaration",
    "forwarding_adapter",
    "typed_workflow",
    "tests",
    "evidence_cells",
    "blocker",
)

ANCHOR_REQUIRED_KEYS = (
    "path",
    "sha256",
    "symbol",
    "start_line",
    "end_line",
    "span_sha256",
)

HEX64_PATTERN = re.compile(r"[0-9a-f]{64}")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")


def _check_anchor(ident, layer, ref):
    # Mirrors the pinned API contract's source-anchor shape
    # (api-coverage v1 $defs/anchor); re-review on pin bump.
    where = f"API row {ident} layer {layer} anchor"
    if not isinstance(ref, dict):
        raise CoverageError(f"{where} is not an object")
    for key in ANCHOR_REQUIRED_KEYS:
        if key not in ref:
            raise CoverageError(f"{where} is missing {key!r}")
    extra = set(ref) - set(ANCHOR_REQUIRED_KEYS)
    if extra:
        raise CoverageError(
            f"{where} has forbidden extra keys {sorted(extra)}"
        )
    for key in ("path", "symbol"):
        value = ref[key]
        if not isinstance(value, str) or not value.strip():
            raise CoverageError(f"{where} has a blank {key}")
    for key in ("sha256", "span_sha256"):
        value = ref[key]
        if not isinstance(value, str) or not HEX64_PATTERN.fullmatch(value):
            raise CoverageError(f"{where} has a malformed {key}")
    for key in ("start_line", "end_line"):
        value = ref[key]
        if type(value) is not int or value < 1:
            raise CoverageError(f"{where} has a malformed {key}")
    if ref["start_line"] > ref["end_line"]:
        raise CoverageError(f"{where} has a reversed line range")


def _check_row(row):
    if not isinstance(row, dict):
        raise CoverageError("API coverage row must be an object")
    ident = row.get("id", "")
    if not isinstance(ident, str) or not ident.strip():
        raise CoverageError("API coverage row is missing its id")
    for key in ROW_REQUIRED_KEYS:
        if key not in row:
            raise CoverageError(
                f"API row {ident} is missing required key {key!r}"
            )
    applicability = row.get("applicability", "")
    if not isinstance(applicability, str):
        raise CoverageError(
            f"API row {ident} has unknown applicability "
            f"{applicability!r}"
        )
    if applicability not in KNOWN_APPLICABILITY:
        raise CoverageError(
            f"API row {ident} has unknown applicability "
            f"{applicability!r}"
        )
    columns = (
        ("raw_declaration", RAW_STATUSES),
        ("forwarding_adapter", ADAPTER_STATUSES),
        ("typed_workflow", ADAPTER_STATUSES),
    )
    for key, allowed in columns:
        column = row.get(key, {})
        if not isinstance(column, dict):
            raise CoverageError(
                f"API row {ident} has malformed {key} "
                "(must be an object)"
            )
        status = column.get("status", "")
        if not isinstance(status, str) or status not in allowed:
            raise CoverageError(
                f"API row {ident} has unknown {key} status "
                f"{status!r}"
            )
    blocker = row.get("blocker")
    if blocker is not None and (
        not isinstance(blocker, dict)
        or not isinstance(blocker.get("reason", ""), str)
        or not blocker.get("reason", "").strip()
        or not isinstance(blocker.get("next_action", ""), str)
        or not blocker.get("next_action", "").strip()
    ):
        raise CoverageError(
            f"API row {ident} has a malformed blocker "
            "(reason and next_action must be non-blank)"
        )
    cells = row.get("evidence_cells", [])
    if not isinstance(cells, list):
        raise CoverageError(
            f"API row {ident} has malformed evidence_cells "
            "(must be a list)"
        )
    seen_layers = set()
    for entry in cells:
        if not isinstance(entry, dict):
            raise CoverageError(
                f"API row {ident} has a malformed evidence cell "
                "(must be an object)"
            )
        layer = entry.get("layer", "")
        if not isinstance(layer, str) or layer not in EXPECTED_LAYERS:
            raise CoverageError(
                f"API row {ident} has unknown layer {layer!r}"
            )
        if layer in seen_layers:
            raise CoverageError(
                f"API row {ident} has a duplicate layer {layer!r}"
            )
        seen_layers.add(layer)
        if entry.get("id", "") != layer:
            raise CoverageError(
                f"API row {ident} has an evidence cell whose id "
                "does not match its layer"
            )
        outcome = entry.get("outcome", "")
        if not isinstance(outcome, str) or outcome not in KNOWN_OUTCOMES:
            raise CoverageError(
                f"API row {ident} has unknown outcome {outcome!r}"
            )
        if not isinstance(entry.get("evidence_refs"), list):
            raise CoverageError(
                f"API row {ident} layer {layer} is missing "
                "its evidence_refs list"
            )
        for ref in entry["evidence_refs"]:
            _check_anchor(ident, layer, ref)
        profile = entry.get("target_profile", "")
        if not isinstance(profile, str) or not profile.strip():
            raise CoverageError(
                f"API row {ident} layer {layer} has a blank "
                "target_profile"
            )


def _check_api_rows(api_coverage):
    version = api_coverage.get("schema_version")
    if type(version) is not int or version != API_SCHEMA_VERSION:
        raise CoverageError(
            "API coverage schema_version %r is not supported "
            "(this materializer reads %d)"
            % (version, API_SCHEMA_VERSION)
        )
    rows = api_coverage.get("rows", [])
    if not isinstance(rows, list):
        raise CoverageError("API coverage rows must be a list")
    api_rows = {}
    for row in rows:
        _check_row(row)
        ident = row.get("id", "")
        if ident in api_rows:
            raise CoverageError(f"duplicate API row id: {ident}")
        api_rows[ident] = row
    return api_rows


LINE_BREAKS = frozenset(["\r", "\n", "\u0085", "\u2028", "\u2029"])


def _clean_target(target):
    return (
        isinstance(target, str)
        and bool(target.strip())
        and not any(mark in target for mark in LINE_BREAKS)
    )


def _check_matrix(matrix):
    raw_profiles = matrix.get("profiles", [])
    if not isinstance(raw_profiles, list):
        raise CoverageError(
            "matrix profiles must be a list of target names"
        )
    for profile in raw_profiles:
        if not _clean_target(profile):
            raise CoverageError(
                f"matrix profile {profile!r} is not a clean target "
                "name (must be non-blank, without line breaks)"
            )
    profiles = set(raw_profiles)
    raw_absent = matrix.get("absent", [])
    if not isinstance(raw_absent, list):
        raise CoverageError("matrix absent must be a list of entries")
    absent = {}
    for entry in raw_absent:
        if not isinstance(entry, dict):
            raise CoverageError(
                "matrix absent entry must be an object"
            )
        target = entry.get("target", "")
        if not _clean_target(target):
            raise CoverageError(
                "matrix absent entry has no clean target "
                "(must be a non-blank string without line breaks)"
            )
        if target in absent:
            raise CoverageError(
                f"matrix lists absent target {target} twice"
            )
        absent[target] = entry
    contradictory = sorted(profiles & set(absent))
    if contradictory:
        raise CoverageError(
            "matrix target %s is both provisioned and absent"
            % contradictory[0]
        )
    for target, entry in absent.items():
        status = entry.get("status", "")
        if not isinstance(status, str) or (
            status not in MATRIX_EXCUSE_STATUSES
        ):
            raise CoverageError(
                f"matrix absent target {target} has unknown status "
                f"{status!r}"
            )
        detail = entry.get("detail", "")
        if not isinstance(detail, str) or not detail.strip():
            raise CoverageError(
                f"matrix absent target {target} has no detail"
            )
        refs = entry.get("source_refs", [])
        if not isinstance(refs, list):
            raise CoverageError(
                f"matrix absent target {target} has scalar "
                "source_refs (must be a list)"
            )
        if any(
            not isinstance(ref, str) or not ref.strip() for ref in refs
        ):
            raise CoverageError(
                f"matrix absent target {target} has malformed "
                "source_refs (must all be non-blank strings)"
            )
        action = entry.get("next_action", "")
        if not isinstance(action, str):
            raise CoverageError(
                f"matrix absent target {target} has a non-string "
                "next_action"
            )
        if status == "NOT_APPLICABLE" and not refs:
            raise CoverageError(
                f"matrix exclusion of {target} is unjustified "
                "(NOT_APPLICABLE needs non-blank source_refs)"
            )
    evidence_profiles = _profile_mapping(
        matrix.get("evidence_profiles"), profiles, "evidence_profiles"
    )
    runtime_profiles = _profile_mapping(
        matrix.get("runtime_profiles"), profiles, "runtime_profiles"
    )
    for profile in profiles:
        overlap = evidence_profiles[profile] & runtime_profiles[profile]
        if overlap:
            raise CoverageError(
                f"matrix profile {profile} lists {sorted(overlap)} "
                "as both contract and runtime evidence (the gates "
                "must not overlap)"
            )
    all_contract = set().union(*evidence_profiles.values(), set())
    all_runtime = set().union(*runtime_profiles.values(), set())
    cross = all_contract & all_runtime
    if cross:
        raise CoverageError(
            "matrix admits %s as contract evidence for one target "
            "and runtime evidence for another (a profile has one "
            "meaning across targets)" % sorted(cross)
        )
    for name, mapping in (
        ("evidence_profiles", evidence_profiles),
        ("runtime_profiles", runtime_profiles),
    ):
        for profile in profiles:
            for item in mapping[profile]:
                if "unqualified" in item.lower():
                    raise CoverageError(
                        f"matrix {name} for {profile} admits "
                        f"{item!r}, which is marked unqualified "
                        "and can never qualify a cell"
                    )
    return profiles, absent, evidence_profiles, runtime_profiles


def _profile_mapping(raw_mapping, profiles, name):
    if not isinstance(raw_mapping, dict):
        raise CoverageError(
            f"matrix is missing {name} "
            "(every profile must declare its accepted row profiles)"
        )
    mapping = {}
    for profile in profiles:
        accepted = raw_mapping.get(profile)
        if not isinstance(accepted, list) or any(
            not isinstance(item, str) or not item.strip()
            for item in accepted
        ):
            raise CoverageError(
                f"matrix {name} for {profile} must be "
                "a list of non-blank strings"
            )
        mapping[profile] = frozenset(accepted)
    return mapping


def materialize_coverage(registry, matrix, api_coverage):
    """Join registry, matrix, and API coverage into a ledger dict."""
    for name, document in (
        ("registry", registry),
        ("matrix", matrix),
        ("api_coverage", api_coverage),
    ):
        if not isinstance(document, dict):
            raise CoverageError(f"{name} must be an object")
    provenance = api_coverage.get("api_provenance", {})
    if not isinstance(provenance, dict):
        raise CoverageError("API provenance must be an object")
    for key in ("repo", "rev", "path", "artifact_sha256"):
        value = provenance.get(key, "")
        if not isinstance(value, str) or not value.strip():
            raise CoverageError(
                f"API provenance is missing {key!r} "
                "(the extract header must stamp it)"
            )
    if not HEX64_PATTERN.fullmatch(provenance["artifact_sha256"]):
        raise CoverageError(
            "API provenance artifact_sha256 is malformed "
            "(must be 64 hex digits)"
        )
    if not COMMIT_PATTERN.fullmatch(provenance["rev"]):
        raise CoverageError(
            "API provenance revision %r is not a full commit ID "
            "(mutable refs cannot pin bytes)"
            % provenance["rev"]
        )
    records = registry.get("records", [])
    if not isinstance(records, list):
        raise CoverageError("registry records must be a list")
    raw_packages = registry.get("packages", [])
    if not isinstance(raw_packages, list):
        raise CoverageError("registry packages must be a list")
    packages = {}
    titles = set()
    for package in raw_packages:
        if not isinstance(package, dict):
            raise CoverageError("registry package must be an object")
        ident = package.get("id", "")
        title = package.get("title", "")
        if not isinstance(ident, str) or not ident.strip():
            raise CoverageError("registry package is missing its id")
        if not isinstance(title, str) or not title.strip():
            raise CoverageError(
                f"package {ident} is missing its title"
            )
        if ident in packages:
            raise CoverageError(f"duplicate package id: {ident}")
        if title in titles:
            raise CoverageError(
                f"duplicate package title {title!r} "
                "(the title join must stay unambiguous)"
            )
        packages[ident] = title
        titles.add(title)
    raw_blockers = registry.get("blockers", [])
    if not isinstance(raw_blockers, list):
        raise CoverageError("registry blockers must be a list")
    family_blockers = {}
    for blocker in raw_blockers:
        if not isinstance(blocker, dict):
            raise CoverageError("registry blocker must be an object")
        for key in (
            "id",
            "family",
            "status",
            "detail",
            "source_refs",
            "next_action",
        ):
            if key not in blocker:
                raise CoverageError(
                    "family blocker %s is missing required key %r"
                    % (blocker.get("id", "?"), key)
                )
        ident = blocker.get("id", "")
        if not isinstance(ident, str) or not ident.strip():
            raise CoverageError("family blocker id must be non-blank")
        status = blocker.get("status", "")
        if not isinstance(status, str) or (
            status not in RECORD_BLOCKER_STATUSES
        ):
            raise CoverageError(
                f"family blocker {ident} has unknown status "
                f"{blocker.get('status')!r}"
            )
        detail = blocker.get("detail", "")
        if not isinstance(detail, str) or not detail.strip():
            raise CoverageError(
                f"family blocker {ident} has a blank detail"
            )
        refs = blocker.get("source_refs", [])
        if (
            not isinstance(refs, list)
            or not refs
            or any(
                not isinstance(ref, str) or not ref.strip()
                for ref in refs
            )
        ):
            raise CoverageError(
                f"family blocker {ident} needs non-blank source_refs"
            )
        action = blocker.get("next_action", "")
        if not isinstance(action, str):
            raise CoverageError(
                f"family blocker {ident} has a non-string next_action"
            )
        family = blocker.get("family")
        if family is not None and not isinstance(family, str):
            raise CoverageError(
                f"family blocker {ident} has a non-string family"
            )
        if isinstance(family, str) and family:
            family_blockers[family] = blocker
    matched_blockers = {family: 0 for family in family_blockers}

    _check_records(records, packages)
    api_rows = _check_api_rows(api_coverage)
    profiles, absent, evidence_profiles, runtime_profiles = _check_matrix(
        matrix
    )

    # Consumer join: every library-symbol record must resolve to an
    # API row of the form function:<symbol>, where <symbol> is the
    # record's api: suffix.
    joined_rows = set()
    for record in records:
        if record.get("userspace_api_surface") != "library-symbol":
            continue
        ident = record["id"]
        if ":" not in ident or not ident.startswith("api:"):
            raise CoverageError(
                f"record {ident} must use an api: record id "
                "to join the consumer ledger"
            )
        row_id = "function:%s" % ident.split(":", 1)[1]
        if row_id not in api_rows:
            raise CoverageError(
                f"record {ident} has no consumer row "
                f"(missing API row {row_id})"
            )
        joined_rows.add(row_id)

    for row_id in sorted(api_rows):
        if row_id not in joined_rows and row_id.startswith("function:"):
            raise CoverageError(
                f"API row {row_id} is dangling "
                "(no library-symbol record joins to it)"
            )

    cells = []
    for record in sorted(records, key=lambda entry: entry["id"]):
        package_title = packages[record["owner_task"]]
        family_blocker = family_blockers.get(record.get("family", ""))
        family_blocked = family_blocker is not None
        producer_ok = _producer_qualified(record, family_blocked)
        record_cells = []
        for target in sorted(record.get("targets_required", [])):
            before = len(record_cells)
            if target in profiles:
                rationale = None
                if record.get("blocker") and family_blocker:
                    rationale = _combined_rationale(
                        record["blocker"], family_blocker
                    )
                elif record.get("blocker"):
                    rationale = _rationale_of(record["blocker"])
                elif family_blocker:
                    rationale = _rationale_of(
                        {
                            "status": family_blocker.get("status", ""),
                            "detail": family_blocker.get("detail", ""),
                            "next_action": family_blocker.get(
                                "next_action", ""
                            ),
                            "source_refs": family_blocker.get(
                                "source_refs", []
                            ),
                        }
                    )
                status = "QUALIFIED" if producer_ok else "OPEN"
                # Consumer cells sort before producer cells for the
                # same record and target, so they are emitted first
                # and the ledger stays in cell-id order.
                if (
                    record.get("userspace_api_surface")
                    == "library-symbol"
                ):
                    row = api_rows[
                        "function:%s" % record["id"].split(":", 1)[1]
                    ]
                    outcome = _consumer_outcome(
                        producer_ok,
                        row,
                        status,
                        rationale,
                        evidence_profiles[target],
                        runtime_profiles[target],
                    )
                    record_cells.append(
                        _cell(
                            record, target, "consumer", outcome[0],
                            package_title, outcome[1], row=row,
                        )
                    )
                record_cells.append(
                    _cell(
                        record, target, "producer", status,
                        package_title, rationale,
                    )
                )
            else:
                excuse = absent.get(target)
                if excuse is None:
                    raise CoverageError(
                        f"record {record['id']} requires target "
                        f"{target}, which is absent from the matrix "
                        "and has no excuse"
                    )
                rationale = _rationale_of(excuse)
                if record.get("blocker"):
                    rationale = _combined_rationale(
                        excuse, record["blocker"]
                    )
                if excuse.get("status") == "NOT_APPLICABLE":
                    status = "NOT_APPLICABLE"
                else:
                    status = "OPEN"
                if (
                    record.get("userspace_api_surface")
                    == "library-symbol"
                ):
                    row = api_rows[
                        "function:%s" % record["id"].split(":", 1)[1]
                    ]
                    if row.get("applicability") == "excluded":
                        outcome = _consumer_outcome(
                            False,
                            row,
                            status,
                            rationale,
                            frozenset(),
                            frozenset(),
                        )
                    else:
                        outcome = (status, rationale)
                    record_cells.append(
                        _cell(
                            record, target, "consumer", outcome[0],
                            package_title, outcome[1], row=row,
                        )
                    )
                record_cells.append(
                    _cell(
                        record, target, "producer", status,
                        package_title, rationale,
                    )
                )
            if family_blocker is not None:
                grown = len(record_cells) - before
                matched_blockers[record["family"]] += grown
        if not record_cells:
            raise CoverageError(
                f"record {record['id']} produced no cells "
                "(targets_required is empty)"
            )
        cells.extend(record_cells)

    # Record order does not imply cell-id order (a record id can
    # prefix another: 'detach@...' sorts after 'detach2@...'),
    # so the ledger is sorted explicitly by cell id.
    cells.sort(key=lambda entry: entry["id"])

    blockers = []
    for blocker in registry.get("blockers", []):
        family = blocker.get("family", "")
        blockers.append(
            {
                "id": blocker.get("id", ""),
                "family": family,
                "status": blocker.get("status", ""),
                "matched_cells": (
                    matched_blockers.get(family, 0) if family else 0
                ),
            }
        )

    return {
        "ledger_version": LEDGER_FORMAT_VERSION,
        "inputs": {
            "registry_sha256": _sha256(registry),
            "matrix_sha256": _sha256(matrix),
            "api_coverage_sha256": _sha256(api_coverage),
            "api_provenance": {
                "repo": provenance["repo"],
                "rev": provenance["rev"],
                "path": provenance["path"],
            },
            "api_artifact_sha256": provenance["artifact_sha256"],
            "record_count": len(records),
            "cell_count": len(cells),
        },
        "blockers": blockers,
        "cells": cells,
    }


def _consumer_outcome(
    producer_ok,
    row,
    producer_status,
    producer_rationale,
    contract_ok,
    runtime_ok,
):
    """Return the (status, rationale) pair for a consumer cell."""
    if row.get("applicability") == "excluded":
        raise CoverageError(
            "API row %s is excluded; admitted rows cannot be "
            "excluded under API contract v1" % row.get("id", "")
        )
    if _consumer_qualified(producer_ok, row, contract_ok, runtime_ok):
        return "QUALIFIED", None
    if producer_status == "OPEN":
        return "OPEN", producer_rationale
    return "OPEN", None


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Materialize the capability coverage ledger."
    )
    parser.add_argument("--registry", required=True)
    parser.add_argument("--matrix", required=True)
    parser.add_argument(
        "--api-coverage",
        required=True,
        help="pinned API row extract from extract_api_rows.py",
    )
    parser.add_argument(
        "--schema",
        required=True,
        help=(
            "coverage ledger schema; capability.schema.json "
            "must sit beside it for the registry gate"
        ),
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    try:
        registry = _load_json_strict(args.registry)
        matrix = _load_json_strict(args.matrix)
        api_coverage = _load_json_strict(args.api_coverage)
        schema = _load_json_strict(args.schema)
    except CoverageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    try:
        from jsonschema import Draft202012Validator
        from jsonschema.exceptions import SchemaError
    except ImportError:
        print(
            "error: jsonschema is required to validate the ledger",
            file=sys.stderr,
        )
        return 2
    Draft202012Validator.check_schema(schema)
    sidecar_path = os.path.join(
        os.path.dirname(os.path.abspath(args.schema)),
        "capability.schema.json",
    )
    try:
        with open(sidecar_path, "rb") as handle:
            sidecar_bytes = handle.read()
    except OSError as exc:
        print(
            f"error: cannot load capability schema: {exc}",
            file=sys.stderr,
        )
        return 1
    if (
        hashlib.sha256(sidecar_bytes).hexdigest()
        != CAPABILITY_SCHEMA_SHA256
    ):
        print(
            "error: capability schema does not match the pinned "
            "bytes (refusing to run the gate against a foreign "
            "schema)",
            file=sys.stderr,
        )
        return 1
    try:
        capability_schema = _parse_json_bytes(
            sidecar_bytes, sidecar_path
        )
    except CoverageError as exc:
        print(f"error: cannot load capability schema: {exc}", file=sys.stderr)
        return 1
    try:
        Draft202012Validator.check_schema(capability_schema)
        capability_validator = Draft202012Validator(capability_schema)
        registry_errors = list(
            capability_validator.iter_errors(registry)
        )
    except SchemaError as exc:
        print(
            f"error: capability schema is invalid: {exc.message}",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:
        print(
            "error: capability schema unusable (%s): %s"
            % (type(exc).__name__, exc),
            file=sys.stderr,
        )
        return 1
    if registry_errors:
        print(
            "error: registry does not match capability schema: %s"
            % registry_errors[0].message,
            file=sys.stderr,
        )
        return 1
    try:
        ledger = materialize_coverage(registry, matrix, api_coverage)
    except CoverageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    Draft202012Validator(schema).validate(ledger)
    # Serialize before opening the destination: a failure must
    # never truncate an existing output.
    try:
        text = dump_ledger(ledger)
    except ValueError as exc:
        print(f"error: cannot serialize ledger: {exc}", file=sys.stderr)
        return 1
    try:
        _atomic_write_text(args.output, text)
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return 1
    print(
        f"materialized {ledger['inputs']['cell_count']} cells "
        f"from {ledger['inputs']['record_count']} records"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
