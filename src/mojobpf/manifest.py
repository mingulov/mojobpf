# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Project manifest model and manifest parsing.

A manifest (TOML, see ``schemas/manifest.schema.json``) describes one
build: schema version, project, target profile, artifact licenses,
programs and maps. :func:`parse_manifest` validates a manifest file and
returns a versioned :class:`ProjectManifest` model. Every malformed input
fails deterministically with a stable diagnostic code; unknown schema
versions are never partially interpreted.

The target-profile registry lives in :mod:`mojobpf.capabilities`,
the one production profile/helper descriptor source; this module
re-exports its names so existing importers keep working. Manifest
values outside the named profile are rejected with a deterministic
code. Broader profiles are registered only after their own
validation; nothing here is aspirational.

Check order inside :func:`parse_manifest` is fixed and the first failure
wins: file readability, TOML syntax, top-level shape, schema version,
unknown fields, required tables and value types, profile membership,
requested capabilities, names, duplicate entries, section/program-type
pairs, the single-probe limit, map sizes and types, source-path
escapes, then missing sources.

Program source paths resolve relative to the manifest file. Absolute
paths and paths escaping the manifest directory are rejected, as are
missing sources.

Standard library only.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .capabilities import (
    SUPPORTED_PROFILE_IDS,
    SUPPORTED_PROFILES,
    ProfileError,
    TargetProfile,
    lookup_profile,
    profile_digest,
)
from .diagnostics import (
    STAGE_MANIFEST_PARSE,
    Diagnostic,
    MojobpfError,
    SEVERITY_ERROR,
)
from .models import is_int

MANIFEST_SCHEMA_VERSION = 1

# Absolute structural bound for map entry counts: max_entries is a
# 32-bit field, so values outside 1..0xFFFFFFFF are never meaningful.
# The target profile may narrow this range further.
MIN_MAP_ENTRIES = 1
MAX_MAP_ENTRIES = 0xFFFFFFFF

# Names used for ELF/BTF/kernel objects and exported symbols must be
# conservative: start with a letter or underscore, then letters, digits
# or underscores (C identifier shape).
SYMBOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Project and artifact names allow dots and dashes as well.
SHORT_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


class ManifestError(MojobpfError):
    """A manifest could not be parsed or validated."""


# The target-profile registry (ProfileError, TargetProfile,
# SUPPORTED_PROFILES, SUPPORTED_PROFILE_IDS, profile_digest,
# lookup_profile) lives in :mod:`mojobpf.capabilities` and is
# re-exported here (see the import above) so existing
# ``mojobpf.manifest`` importers keep working.


@dataclass(frozen=True)
class ProjectInfo:
    """The ``[project]`` table: the built project's name."""

    name: str


@dataclass(frozen=True)
class TargetInfo:
    """The ``[target]`` table: profile identifier and CO-RE request."""

    profile: str
    core: bool


@dataclass(frozen=True)
class ArtifactInfo:
    """The ``[artifact]`` table: object name and license declarations."""

    name: str
    source_license: str
    kernel_license: str


@dataclass(frozen=True)
class ProgramEntry:
    """One ``[[programs]]`` entry: source, symbol, type and section."""

    source: str
    entry: str
    program_type: str
    section: str


@dataclass(frozen=True)
class MapEntry:
    """One ``[[maps]]`` entry: name, types and entry count."""

    name: str
    map_type: str
    key_type: str
    value_type: str
    max_entries: int


@dataclass(frozen=True)
class ProjectManifest:
    """Versioned, validated view of one manifest file.

    ``manifest_path`` is the manifest location the program sources resolve
    against. ``programs`` and ``maps`` are in manifest order.
    """

    schema_version: int
    project: ProjectInfo
    target: TargetInfo
    artifact: ArtifactInfo
    programs: tuple[ProgramEntry, ...]
    maps: tuple[MapEntry, ...]
    manifest_path: str


_TOP_LEVEL_KEYS = frozenset(
    {"schema_version", "project", "target", "artifact", "programs", "maps"}
)
_PROJECT_KEYS = frozenset({"name"})
_TARGET_KEYS = frozenset({"profile", "core"})
_ARTIFACT_KEYS = frozenset({"name", "source_license", "kernel_license"})
_PROGRAM_KEYS = frozenset({"source", "entry", "program_type", "section"})
_MAP_KEYS = frozenset(
    {"name", "map_type", "key_type", "value_type", "max_entries"}
)

SUPPORTED_MAP_NAMES = ("mojobpf_map0", "mojobpf_map1")
"""Map declarations the build routes emit.

Route-independent (every route emits a subset of these), so the
name gate lives at parse (``MBPF214``). Entry roots are NOT
listed here: they differ per route (the native route accepts
any entry symbol), so ``MBPF213``/``MBPF217`` stay at
``build.setup`` where the route is known.
"""


def _fail(
    code: str, explanation: str, location: str, remedy: str
) -> ManifestError:
    return ManifestError(
        Diagnostic(
            code=code,
            stage=STAGE_MANIFEST_PARSE,
            severity=SEVERITY_ERROR,
            explanation=explanation,
            location=location,
            remedy=remedy,
        )
    )


def parse_manifest(path: str | Path) -> ProjectManifest:
    """Parse and validate the manifest at ``path``.

    Returns a :class:`ProjectManifest` on success. Every malformed input
    raises :class:`ManifestError` (or :class:`ProfileError` for an
    unknown profile) carrying a deterministic diagnostic code:

    * ``MBPF101``: unsupported target profile.
    * ``MBPF201``: unsupported ``schema_version``.
    * ``MBPF202``: unknown field.
    * ``MBPF203``: duplicate program entry name.
    * ``MBPF204``: duplicate map name.
    * ``MBPF205``: invalid map size or type.
    * ``MBPF206``: conflicting or unsupported section/program-type pair.
    * ``MBPF207``: source path escape (absolute or outside the manifest).
    * ``MBPF208``: missing program source.
    * ``MBPF209``: malformed manifest (syntax, shape or value type).
    * ``MBPF210``: invalid name for ELF/BTF/kernel-object use.
    * ``MBPF211``: manifest requests a capability outside the profile.
    * ``MBPF214``: map name no build route emits.
    * ``MBPF215``: map count/shape outside the state-plus-ringbuf form.

    Entry roots (``MBPF213``) and root/pair pins (``MBPF217``) are
    route-dependent and stay at ``build.setup``.
    """
    manifest_path = Path(path)
    where = str(manifest_path)
    try:
        raw = manifest_path.read_bytes()
    except OSError as exc:
        raise _fail(
            "MBPF209",
            "cannot read manifest: %s" % exc,
            where,
            "check the manifest path and file permissions",
        ) from None
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise _fail(
            "MBPF209",
            "manifest is not valid UTF-8 TOML: %s" % exc,
            where,
            "fix the manifest syntax",
        ) from None
    if not isinstance(data, dict):
        raise _fail(
            "MBPF209",
            "manifest top level must be a table",
            where,
            "fix the manifest syntax",
        )

    version = data.get("schema_version")
    if not is_int(version):
        raise _fail(
            "MBPF209",
            "schema_version must be an integer",
            "%s: schema_version" % where,
            "set schema_version = %d" % MANIFEST_SCHEMA_VERSION,
        )
    if version != MANIFEST_SCHEMA_VERSION:
        raise _fail(
            "MBPF201",
            "unsupported schema_version %r; this driver reads version %d"
            % (version, MANIFEST_SCHEMA_VERSION),
            "%s: schema_version" % where,
            "set schema_version = %d or use a matching driver"
            % MANIFEST_SCHEMA_VERSION,
        )

    for key in data:
        if key not in _TOP_LEVEL_KEYS:
            raise _fail(
                "MBPF202",
                "unknown manifest field: %r" % (key,),
                "%s: %s" % (where, key),
                "remove the unknown field",
            )

    project = _require_table(data, where, "project")
    target = _require_table(data, where, "target")
    artifact = _require_table(data, where, "artifact")
    programs_raw = data.get("programs", None)
    if programs_raw is None:
        raise _fail(
            "MBPF209",
            "manifest requires a programs list",
            "%s: programs" % where,
            "add at least one [[programs]] entry",
        )
    if not isinstance(programs_raw, list) or not programs_raw:
        raise _fail(
            "MBPF209",
            "programs must be a non-empty list",
            "%s: programs" % where,
            "add at least one [[programs]] entry",
        )
    maps_raw = data.get("maps", [])
    if not isinstance(maps_raw, list):
        raise _fail(
            "MBPF209",
            "maps must be a list",
            "%s: maps" % where,
            "use [[maps]] entries or omit the maps list",
        )

    _check_keys(project, _PROJECT_KEYS, where, "project")
    _check_keys(target, _TARGET_KEYS, where, "target")
    _check_keys(artifact, _ARTIFACT_KEYS, where, "artifact")

    project_name = _require_str(project, where, "project", "name")
    profile_id = _require_str(target, where, "target", "profile")
    core = target.get("core", False)
    if not isinstance(core, bool):
        raise _fail(
            "MBPF209",
            "target.core must be a boolean",
            "%s: target.core" % where,
            "set core = true or core = false",
        )
    artifact_name = _require_str(artifact, where, "artifact", "name")
    source_license = _require_str(
        artifact, where, "artifact", "source_license"
    )
    kernel_license = _require_str(
        artifact, where, "artifact", "kernel_license"
    )
    _check_license_form(source_license, where, "artifact.source_license")
    _check_license_form(kernel_license, where, "artifact.kernel_license")

    try:
        profile = lookup_profile(profile_id)
    except ProfileError as exc:
        old = exc.diagnostic
        raise ProfileError(
            Diagnostic(
                code=old.code,
                stage=old.stage,
                severity=old.severity,
                explanation=old.explanation,
                location="%s: target.profile" % where,
                remedy=old.remedy,
            )
        ) from None

    if core and not profile.core_supported:
        raise _fail(
            "MBPF211",
            "profile %r does not support CO-RE (core = true)"
            % (profile_id,),
            "%s: target.core" % where,
            "set core = false",
        )

    _check_short_name(project_name, where, "project.name")
    _check_short_name(artifact_name, where, "artifact.name")

    programs: list[ProgramEntry] = []
    seen_entries: set[str] = set()
    for index, item in enumerate(programs_raw):
        slot = "programs[%d]" % index
        if not isinstance(item, dict):
            raise _fail(
                "MBPF209",
                "%s must be a table" % slot,
                "%s: %s" % (where, slot),
                "fix the [[programs]] entry",
            )
        _check_keys(item, _PROGRAM_KEYS, where, slot)
        source = _require_str(item, where, slot, "source")
        entry = _require_str(item, where, slot, "entry")
        program_type = _require_str(item, where, slot, "program_type")
        section = _require_str(item, where, slot, "section")
        if not SYMBOL_NAME_RE.match(entry):
            raise _fail(
                "MBPF210",
                "invalid program entry name: %r" % (entry,),
                "%s: %s.entry" % (where, slot),
                "use letters, digits and underscores, starting with "
                "a letter or underscore",
            )
        if entry in seen_entries:
            raise _fail(
                "MBPF203",
                "duplicate program entry name: %r" % (entry,),
                "%s: %s.entry" % (where, slot),
                "give each [[programs]] entry a unique entry name",
            )
        seen_entries.add(entry)
        if (program_type, section) not in profile.allowed_pairs:
            raise _fail(
                "MBPF206",
                "program_type %r with section %r is not supported by "
                "profile %r"
                % (program_type, section, profile.profile_id),
                "%s: %s" % (where, slot),
                "use one of: %s"
                % ", ".join(
                    "%s/%s" % pair for pair in profile.allowed_pairs
                ),
            )
        if not source:
            raise _fail(
                "MBPF209",
                "program source must not be empty",
                "%s: %s.source" % (where, slot),
                "point source at a Mojo file next to the manifest",
            )
        programs.append(
            ProgramEntry(
                source=source,
                entry=entry,
                program_type=program_type,
                section=section,
            )
        )

    uprobe_count = sum(
        1
        for program in programs
        if (program.program_type, program.section)
        == ("uprobe", "uprobe")
    )
    if uprobe_count > 1:
        raise _fail(
            "MBPF211",
            "profile %r admits at most one uprobe program per "
            "build, but the manifest declares %d uprobe programs"
            % (profile_id, uprobe_count),
            "%s: programs" % where,
            "declare exactly one [[programs]] entry with "
            'program_type = "uprobe" and section = "uprobe"; '
            "multi-probe graphs need a reviewed route",
        )
    if uprobe_count == 1 and len(programs) > 1:
        raise _fail(
            "MBPF211",
            "profile %r admits a single uprobe program per "
            "build, but the manifest pairs it with %d other "
            "program(s)" % (profile_id, len(programs) - 1),
            "%s: programs" % where,
            "declare exactly one [[programs]] entry with "
            'program_type = "uprobe" and section = "uprobe"; '
            "wider builds need a reviewed route",
        )

    maps: list[MapEntry] = []
    seen_maps: set[str] = set()
    for index, item in enumerate(maps_raw):
        slot = "maps[%d]" % index
        if not isinstance(item, dict):
            raise _fail(
                "MBPF209",
                "%s must be a table" % slot,
                "%s: %s" % (where, slot),
                "fix the [[maps]] entry",
            )
        _check_keys(item, _MAP_KEYS, where, slot)
        name = _require_str(item, where, slot, "name")
        map_type = _require_str(item, where, slot, "map_type")
        key_type = _require_str(item, where, slot, "key_type")
        value_type = _require_str(item, where, slot, "value_type")
        max_entries = item.get("max_entries")
        if not is_int(max_entries):
            raise _fail(
                "MBPF209",
                "maps max_entries must be an integer",
                "%s: %s.max_entries" % (where, slot),
                "set max_entries to a positive integer",
            )
        if not SYMBOL_NAME_RE.match(name):
            raise _fail(
                "MBPF210",
                "invalid map name: %r" % (name,),
                "%s: %s.name" % (where, slot),
                "use letters, digits and underscores, starting with "
                "a letter or underscore",
            )
        if name in seen_maps:
            raise _fail(
                "MBPF204",
                "duplicate map name: %r" % (name,),
                "%s: %s.name" % (where, slot),
                "give each [[maps]] entry a unique name",
            )
        seen_maps.add(name)
        problem = _map_problem(
            profile, map_type, key_type, value_type, max_entries
        )
        if problem is not None:
            raise _fail(
                "MBPF205",
                problem,
                "%s: %s" % (where, slot),
                "use map_type in {%s}, key_type in {%s}, value_type in "
                "{%s} and max_entries in {%s} (ringbuf maps use "
                "key_type/value_type none and max_entries in {%s})"
                % (
                    ", ".join(profile.allowed_map_types),
                    ", ".join(profile.allowed_key_types),
                    ", ".join(profile.allowed_value_types),
                    ", ".join(str(v) for v in profile.allowed_max_entries),
                    ", ".join(
                        str(v) for v in profile.allowed_ringbuf_sizes
                    ),
                ),
            )
        maps.append(
            MapEntry(
                name=name,
                map_type=map_type,
                key_type=key_type,
                value_type=value_type,
                max_entries=max_entries,
            )
        )

    base = manifest_path.parent.resolve()
    for program in programs:
        candidate = Path(program.source)
        if candidate.is_absolute():
            raise _fail(
                "MBPF207",
                "program source must be relative to the manifest: %r"
                % (program.source,),
                "%s: source %r" % (where, program.source),
                "use a relative path inside the project directory",
            )
        resolved = (base / candidate).resolve()
        try:
            inside = resolved.is_relative_to(base)
        except ValueError:
            inside = False
        if not inside:
            raise _fail(
                "MBPF207",
                "program source escapes the manifest directory: %r"
                % (program.source,),
                "%s: source %r" % (where, program.source),
                "keep sources inside the project directory",
            )
        if not resolved.is_file():
            raise _fail(
                "MBPF208",
                "program source not found: %r" % (program.source,),
                "%s: source %r" % (where, program.source),
                "create the source file or fix the source path",
            )

    if len(maps) > 2:
        raise _fail(
            "MBPF215",
            "manifest declares %d maps; this route supports at most "
            "a state map plus its ring-buffer companion" % len(maps),
            "%s: maps" % where,
            "declare at most one map, or the event pair of a state "
            "map plus its ring-buffer companion; wider shapes need "
            "a reviewed route",
        )
    if len(maps) == 2 and (
        sum(entry.map_type == "ringbuf" for entry in maps) != 1
    ):
        raise _fail(
            "MBPF215",
            "manifest declares 2 maps; the pair must be one state "
            "map plus its ring-buffer companion (map_type ringbuf)",
            "%s: maps" % where,
            "declare at most one map, or the event pair of a state "
            "map plus its ring-buffer companion; wider shapes need "
            "a reviewed route",
        )
    for index, entry in enumerate(maps):
        if entry.name not in SUPPORTED_MAP_NAMES:
            raise _fail(
                "MBPF214",
                "map name %r is not a supported map declaration "
                "(supported: %s)"
                % (entry.name, ", ".join(SUPPORTED_MAP_NAMES)),
                "%s: maps[%d].name" % (where, index),
                "declare map %r; wider shapes need a reviewed route"
                % (SUPPORTED_MAP_NAMES[0],),
            )

    return ProjectManifest(
        schema_version=MANIFEST_SCHEMA_VERSION,
        project=ProjectInfo(name=project_name),
        target=TargetInfo(profile=profile_id, core=core),
        artifact=ArtifactInfo(
            name=artifact_name,
            source_license=source_license,
            kernel_license=kernel_license,
        ),
        programs=tuple(programs),
        maps=tuple(maps),
        manifest_path=where,
    )


def _require_table(data: dict, where: str, key: str) -> dict:
    value = data.get(key)
    if not isinstance(value, dict):
        raise _fail(
            "MBPF209",
            "manifest requires a [%s] table" % key,
            "%s: %s" % (where, key),
            "add the [%s] table" % key,
        )
    return value


def _check_keys(item: dict, allowed: frozenset, where: str, slot: str) -> None:
    for key in item:
        if key not in allowed:
            raise _fail(
                "MBPF202",
                "unknown manifest field: %r" % (key,),
                "%s: %s.%s" % (where, slot, key),
                "remove the unknown field",
            )


def _require_str(item: dict, where: str, slot: str, key: str) -> str:
    value = item.get(key)
    if not isinstance(value, str):
        raise _fail(
            "MBPF209",
            "%s.%s must be a string" % (slot, key),
            "%s: %s.%s" % (where, slot, key),
            "set %s.%s to a string" % (slot, key),
        )
    return value


def _check_license_form(value: str, where: str, slot: str) -> None:
    if not value.strip():
        raise _fail(
            "MBPF209",
            "%s must not be empty" % slot,
            "%s: %s" % (where, slot),
            "declare an SPDX license expression",
        )
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise _fail(
            "MBPF209",
            "%s must not carry control characters" % slot,
            "%s: %s" % (where, slot),
            "declare a single-line SPDX license expression",
        )


def _check_short_name(value: str, where: str, slot: str) -> None:
    if not SHORT_NAME_RE.match(value):
        raise _fail(
            "MBPF210",
            "invalid name: %r" % (value,),
            "%s: %s" % (where, slot),
            "use letters, digits, underscores, dots and dashes, "
            "starting with a letter, digit or underscore",
        )


def _map_problem(
    profile: TargetProfile,
    map_type: str,
    key_type: str,
    value_type: str,
    max_entries: int,
) -> str | None:
    if map_type not in profile.allowed_map_types:
        return "map_type %r is not supported by profile %r" % (
            map_type,
            profile.profile_id,
        )
    if map_type == "ringbuf":
        if key_type != "none" or value_type != "none":
            return (
                "ringbuf maps carry no key/value vocabulary "
                "(key_type %r value_type %r)"
                % (key_type, value_type)
            )
        if not MIN_MAP_ENTRIES <= max_entries <= MAX_MAP_ENTRIES:
            return (
                "max_entries %r is outside the structural range "
                "%d..%d" % (max_entries, MIN_MAP_ENTRIES, MAX_MAP_ENTRIES)
            )
        if max_entries not in profile.allowed_ringbuf_sizes:
            return "max_entries %r is not supported by profile %r" % (
                max_entries,
                profile.profile_id,
            )
        return None
    if key_type not in profile.allowed_key_types:
        return "key_type %r is not supported by profile %r" % (
            key_type,
            profile.profile_id,
        )
    if value_type not in profile.allowed_value_types:
        return "value_type %r is not supported by profile %r" % (
            value_type,
            profile.profile_id,
        )
    if not MIN_MAP_ENTRIES <= max_entries <= MAX_MAP_ENTRIES:
        return "max_entries %r is outside the structural range %d..%d" % (
            max_entries,
            MIN_MAP_ENTRIES,
            MAX_MAP_ENTRIES,
        )
    if max_entries not in profile.allowed_max_entries:
        return "max_entries %r is not supported by profile %r" % (
            max_entries,
            profile.profile_id,
        )
    return None
