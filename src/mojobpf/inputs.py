# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""build-snapshot-v1: capture the complete build inputs before compiling.

:func:`capture_build_inputs` resolves the manifest, program sources,
transitive Mojo imports, SDK files, source grants, toolchain identity
and influential environment into one immutable :class:`BuildSnapshot`
and stages every consumed input byte-for-byte into a private capture
root. The pipeline then compiles *from the staged copies*
(:meth:`BuildSnapshot.program_paths` plus
:meth:`BuildSnapshot.frontend_search_path`) and the provenance layer
hashes the same staged bytes, so a concurrent change to the project
directory can neither alter the compiled object nor forge the
attributed hashes: the build consumes the snapshot or rejects, never
reports the clean hash for changed consumed bytes.

Import model: the pinned Mojo frontend (1.1.0) offers no
dependency-output mode (``mojo build --help`` lists no
``--emit-dependencies``/``-MD`` spelling), so the snapshot cannot
prefer compiler dependency output and instead implements the bounded
supported import grammar below plus the captured allowed-root tree:

* ``import a``, ``import a, b.c``, ``import a as x``;
* ``from a import b``, ``from a import b, c``,
  ``from a import b as c``, ``from a.b import (c, d)`` on one line
  or parenthesized across lines, with backslash continuations and
  ``;``/``:``-separated statements (``if x: import a`` counts);
* comments and string literals (including triple-quoted blocks)
  never contribute imports.

Anything else that could name a module is rejected, never silently
skipped: relative imports (``from . import x``), wildcard imports
(``from x import *``), dynamic machinery (``__import__``,
``importlib``), unresolved modules (no file under the source
directory, the manifest directory or the SDK, and not ``std.*``),
and malformed import statements. ``std.*`` modules resolve inside
the toolchain and are bound through the toolchain distribution
record, not hashed per file. A module resolving to a package
directory seals every ``.mojo`` file beneath it (a documented
superset: the seal stays truthful because capture-time bytes, not
names, feed provenance and cache identity).

Isolation assumptions (reviewed per the snapshot checkpoint): the
snapshot guards benign concurrent source changes (an editor saving,
a checkout updating, a second build writing nearby files) by
single-read capture into a private root the compiler alone is
pointed at, with read-only staged files and byte re-verification at
every boundary. It does not defend against arbitrary code running
as the same account: such code can rewrite the private root itself,
so hostile multi-tenant builds need a stronger sandbox (separate
UID, mount namespace or disposable VM) recorded as a separate
requirement, not claimed here. Likewise ``eval``/``exec``
string-constructed imports are outside the static model and stay
unsupported: only the named dynamic machinery above is detected.

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field

from .diagnostics import Diagnostic, MojobpfError, SEVERITY_ERROR
from .inspect import (
    InspectionError,
    SourceGrantRecord,
    validate_source_grants,
)
from .manifest import (
    ManifestError,
    ProfileError,
    ProjectManifest,
    lookup_profile,
    parse_manifest,
    profile_digest,
)

#: Version of the input-snapshot record produced here.
INPUT_SNAPSHOT_VERSION = 1

#: Published contract name consumed by the build, evidence and
#: packaging layers.
SNAPSHOT_CONTRACT = "build-snapshot-v1"

#: Pipeline stage for capture/grammar/resolution failures
#: (``MBPF106``).
STAGE_BUILD_INPUTS = "build.inputs"

#: Environment variables always captured when present.
ENVIRONMENT_BASE_NAMES = ("PATH", "MODULAR_HOME")

#: Extra environment prefixes captured when present (any variable
#: starting with one of these names joins the snapshot identity).
ENVIRONMENT_EXTRA_PREFIXES = ("MOJO_", "MODULAR_", "LLVM_")

#: Top-level module roots provided by the toolchain itself. Only
#: ``std`` is recognized: any other unresolved root is rejected
#: rather than assumed builtin.
STDLIB_ROOTS = ("std",)

_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_DOTTED = r"%s(?:\.%s)*" % (_IDENT, _IDENT)
_IDENT_RE = re.compile(r"^%s$" % _IDENT)
_DOTTED_RE = re.compile(r"^%s$" % _DOTTED)
_IMPORT_HEAD_RE = re.compile(r"^import\b(.*)$", re.S)
_FROM_HEAD_RE = re.compile(r"^from\b(.*)$", re.S)
_DYNAMIC_RE = re.compile(r"\b(__import__|importlib)\b")


class InputError(MojobpfError):
    """A build-input capture, grammar or identity check failed."""


def _fail(explanation: str, location: str | None,
          remedy: str) -> InputError:
    return InputError(
        Diagnostic(
            code="MBPF106",
            stage=STAGE_BUILD_INPUTS,
            severity=SEVERITY_ERROR,
            explanation=explanation,
            location=location,
            remedy=remedy,
        )
    )


def stable_env_value(value: str) -> str:
    """Return the stable recording of one environment value.

    Values holding path separators are recorded by hash, so stable
    bytes never embed absolute paths; plain values are kept
    verbatim.
    """
    if "/" in value or "\\" in value:
        return "sha256:" + hashlib.sha256(
            value.encode("utf-8", errors="replace")
        ).hexdigest()
    return value


def capture_environment(
    overrides: dict[str, str] | None = None,
) -> tuple[tuple[str, str], ...]:
    """Capture the influential compiler environment stably.

    Records :data:`ENVIRONMENT_BASE_NAMES` plus any ambient
    variable starting with :data:`ENVIRONMENT_EXTRA_PREFIXES`,
    each with :func:`stable_env_value`. ``overrides`` (the test
    seam) replaces or adds entries after the ambient capture.
    Returns ``(name, value)`` pairs sorted by name.
    """
    entries: dict[str, str] = {}
    for name in ENVIRONMENT_BASE_NAMES:
        if name in os.environ:
            entries[name] = stable_env_value(os.environ[name])
    for name in sorted(os.environ):
        if name in entries:
            continue
        if name.startswith(ENVIRONMENT_EXTRA_PREFIXES):
            entries[name] = stable_env_value(os.environ[name])
    if overrides is not None:
        for name, value in overrides.items():
            entries[str(name)] = stable_env_value(str(value))
    return tuple((name, entries[name]) for name in sorted(entries))


def _mask_line(line: str, triple: str | None
               ) -> tuple[str, str | None]:
    """Blank strings and cut comments on one physical line.

    String contents (single, double and triple quoted) become
    spaces so import keywords inside literals can never match;
    a ``#`` outside any string ends the code. ``triple`` carries
    the unterminated triple-quote delimiter across lines.
    """
    out: list[str] = []
    pos = 0
    size = len(line)
    if triple is not None:
        end = line.find(triple)
        if end < 0:
            return ("", triple)
        out.append(" " * (end + len(triple)))
        pos = end + len(triple)
        triple = None
    while pos < size:
        char = line[pos]
        if char == "#":
            break
        if line.startswith("'''", pos) or line.startswith('"""', pos):
            delimiter = line[pos:pos + 3]
            end = line.find(delimiter, pos + 3)
            if end < 0:
                out.append(" " * (size - pos))
                return ("".join(out), delimiter)
            out.append(" " * (end + 3 - pos))
            pos = end + 3
            continue
        if char == "'" or char == '"':
            end = pos + 1
            while end < size and line[end] != char:
                if line[end] == "\\":
                    end += 1
                end += 1
            end = min(end + 1, size)
            out.append(" " * (end - pos))
            pos = end
            continue
        out.append(char)
        pos += 1
    return ("".join(out), triple)


def _masked_lines(text: str) -> list[tuple[int, str]]:
    """Return ``(lineno, masked)`` for every physical line."""
    masked: list[tuple[int, str]] = []
    triple: str | None = None
    for lineno, line in enumerate(text.split("\n"), 1):
        code, triple = _mask_line(line, triple)
        masked.append((lineno, code))
    return masked


def _has_continuation(stripped: str) -> bool:
    """Whether a line ends in an odd-backslash continuation."""
    count = len(stripped) - len(stripped.rstrip("\\"))
    return count % 2 == 1


def _join_continuations(
    masked: list[tuple[int, str]],
) -> list[tuple[int, str]]:
    """Join backslash and paren continuations into logical lines.

    A line ending in an odd-backslash ``\\`` joins its successor;
    lines are then accumulated while ``()/[]/{}`` stay unbalanced.
    Returns ``(start_lineno, text)`` per logical line.
    """
    joined: list[tuple[int, str]] = []
    index = 0
    size = len(masked)
    while index < size:
        lineno, text = masked[index]
        index += 1
        stripped = text.rstrip()
        while _has_continuation(stripped):
            stripped = stripped[:-1]
            if index >= size:
                break
            _, following = masked[index]
            index += 1
            stripped = stripped + following.rstrip()
        joined.append((lineno, stripped))
    logical: list[tuple[int, str]] = []
    index = 0
    while index < len(joined):
        lineno, text = joined[index]
        index += 1
        depth = 0
        for char in text:
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth = max(0, depth - 1)
        while depth > 0 and index < len(joined):
            _, following = joined[index]
            index += 1
            text += "\n" + following
            for char in following:
                if char in "([{":
                    depth += 1
                elif char in ")]}":
                    depth = max(0, depth - 1)
        logical.append((lineno, text))
    return logical


def _split_statements(text: str) -> list[str]:
    """Split one logical line on top-level ``;`` and ``:``.

    Only depth-zero separators split, so slices, subscripts,
    annotations inside brackets and lambdas stay whole while
    ``if x: import a`` still exposes its import statement.
    """
    parts: list[str] = []
    depth = 0
    start = 0
    for pos, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif depth == 0 and char in ";:":
            parts.append(text[start:pos])
            start = pos + 1
    parts.append(text[start:])
    return parts


def _split_top_commas(text: str) -> list[str]:
    """Split on depth-zero commas (import item lists)."""
    parts: list[str] = []
    depth = 0
    start = 0
    for pos, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif depth == 0 and char == ",":
            parts.append(text[start:pos])
            start = pos + 1
    parts.append(text[start:])
    return parts


def _parse_import_item(item: str, where: str) -> str:
    """Parse one ``import`` list item; return its module."""
    text = " ".join(item.split())
    if not text:
        raise _fail(
            "unsupported empty import in %s" % (where,),
            where,
            "name one dotted module per import item",
        )
    words = text.split(" as ")
    if len(words) > 2:
        raise _fail(
            "unsupported import item %r in %s" % (item.strip(), where),
            where,
            "spell imports as 'import a.b' or 'import a as x'",
        )
    module = words[0].strip()
    if _DOTTED_RE.match(module) is None:
        raise _fail(
            "unsupported import item %r in %s"
            % (item.strip(), where),
            where,
            "spell imports as 'import a.b' or 'import a as x'",
        )
    if len(words) == 2:
        alias = words[1].strip()
        if _IDENT_RE.match(alias) is None or " " in alias:
            raise _fail(
                "unsupported import alias %r in %s"
                % (item.strip(), where),
                where,
                "spell aliases as 'import a as x'",
            )
    return module


def _parse_from_items(items: str, where: str) -> None:
    """Validate one ``from`` import name list (names need no capture).

    Only the source module feeds file resolution; the imported
    names are validated so wildcard, dotted or malformed lists
    reject instead of slipping through.
    """
    text = " ".join(items.split())
    if not text:
        raise _fail(
            "unsupported empty from-import in %s" % (where,),
            where,
            "name the imported members explicitly",
        )
    if text.startswith("("):
        if not text.endswith(")"):
            raise _fail(
                "unsupported from-import list %r in %s"
                % (items.strip(), where),
                where,
                "spell from-imports as 'from a import b, c'",
            )
        text = text[1:-1].strip()
    if text.endswith(","):
        text = text[:-1].strip()
    for item in _split_top_commas(text):
        name = " ".join(item.split())
        if not name:
            raise _fail(
                "unsupported empty from-import in %s" % (where,),
                where,
                "name the imported members explicitly",
            )
        if name == "*":
            raise _fail(
                "unsupported wildcard import in %s" % (where,),
                where,
                "name the imported members explicitly",
            )
        words = name.split(" as ")
        if len(words) > 2:
            raise _fail(
                "unsupported from-import item %r in %s"
                % (item.strip(), where),
                where,
                "spell from-imports as 'from a import b, c'",
            )
        if _IDENT_RE.match(words[0].strip()) is None:
            raise _fail(
                "unsupported from-import item %r in %s"
                % (item.strip(), where),
                where,
                "spell from-imports as 'from a import b, c'",
            )
        if len(words) == 2 and (
            _IDENT_RE.match(words[1].strip()) is None
            or " " in words[1].strip()
        ):
            raise _fail(
                "unsupported from-import alias %r in %s"
                % (item.strip(), where),
                where,
                "spell aliases as 'from a import b as c'",
            )


_FROM_MODULE_RE = re.compile(
    r"^(\.*)(%s)?\s+import\b(.*)$" % _DOTTED, re.S
)


def _parse_statement(
    statement: str, where: str, found: list[str],
) -> None:
    """Parse one masked statement, appending imported modules."""
    text = statement.strip()
    if not text:
        return
    if _DYNAMIC_RE.search(text) is not None:
        raise _fail(
            "unsupported dynamic import in %s" % (where,),
            where,
            "spell imports as static 'import a'/'from a import b' "
            "statements",
        )
    match = _IMPORT_HEAD_RE.match(text)
    if match is not None:
        rest = match.group(1).strip()
        if rest.endswith(","):
            rest = rest[:-1].strip()
        if not rest:
            raise _fail(
                "unsupported empty import in %s" % (where,),
                where,
                "spell imports as 'import a.b' or 'import a as x'",
            )
        for item in _split_top_commas(rest):
            found.append(_parse_import_item(item, where))
        return
    match = _FROM_HEAD_RE.match(text)
    if match is None:
        return
    rest = match.group(1).strip()
    module_match = _FROM_MODULE_RE.match(rest)
    if module_match is None:
        raise _fail(
            "unsupported from-import %r in %s"
            % (statement.strip()[:60], where),
            where,
            "spell from-imports as 'from a import b, c'",
        )
    if module_match.group(1):
        raise _fail(
            "unsupported relative import in %s" % (where,),
            where,
            "spell imports as absolute dotted modules",
        )
    module = module_match.group(2)
    if not module:
        raise _fail(
            "unsupported from-import %r in %s"
            % (statement.strip()[:60], where),
            where,
            "spell from-imports as 'from a import b, c'",
        )
    _parse_from_items(module_match.group(3), where)
    found.append(module)


def parse_mojo_imports_text(
    text: str, display_path: str
) -> tuple[str, ...]:
    """Return the dotted modules imported by Mojo source ``text``.

    Applies the bounded supported import grammar (see the module
    docstring); unsupported constructs raise :class:`InputError`
    (``MBPF106``) naming ``display_path:line``. Modules repeat
    nothing: first-appearance order, deduplicated.
    """
    found: list[str] = []
    for lineno, logical in _join_continuations(_masked_lines(text)):
        where = "%s:%d" % (display_path, lineno)
        for statement in _split_statements(logical):
            _parse_statement(statement, where, found)
    ordered: dict[str, None] = {}
    for module in found:
        ordered.setdefault(module)
    return tuple(ordered)


def parse_mojo_imports(path: str) -> tuple[str, ...]:
    """Return the dotted modules imported by the Mojo file ``path``.

    Unreadable files and decoding failures raise
    :class:`InputError` (``MBPF106``); see
    :func:`parse_mojo_imports_text` for the grammar.
    """
    try:
        with open(path, "rb") as handle:
            content = handle.read()
    except OSError as exc:
        raise _fail(
            "cannot read Mojo source %r: %s" % (path, exc),
            path,
            "check the source path and permissions",
        ) from None
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _fail(
            "Mojo source %r is not UTF-8: %s" % (path, exc),
            path,
            "keep Mojo sources in UTF-8",
        ) from None
    return parse_mojo_imports_text(text, path)


def module_resolves_to_sdk(module: str, sdk_dir: str) -> bool:
    """Whether a dotted module is provided by the packaged SDK.

    A module resolves into the SDK through a module file (the
    full dotted path or its root) or through a package
    directory: a bare ``from mojobpf import packet`` yields the
    ``mojobpf`` root, which the SDK provides as a directory of
    module files. SDK-first precedence matches the frontend,
    which searches the packaged ``-I`` directory.
    """
    segments = module.split(".")
    if os.path.isdir(os.path.join(sdk_dir, *segments)):
        return True
    if os.path.isdir(os.path.join(sdk_dir, segments[0])):
        return True
    return any(
        os.path.isfile(path)
        for path in (
            os.path.join(sdk_dir, *segments) + ".mojo",
            os.path.join(sdk_dir, segments[0]) + ".mojo",
        )
    )


def _package_mojo_files(directory: str) -> tuple[str, ...]:
    """Return every ``.mojo`` file under ``directory``, sorted."""
    found: list[str] = []
    for root, dirs, files in os.walk(directory):
        dirs.sort()
        for name in sorted(files):
            if not name.endswith(".mojo"):
                continue
            candidate = os.path.join(root, name)
            if os.path.isfile(candidate):
                found.append(os.path.realpath(candidate))
    return tuple(found)


def resolve_module(
    module: str,
    *,
    source_dir: str,
    project_dir: str,
    sdk_dir: str,
) -> tuple[str, ...] | None:
    """Resolve a dotted module to origin file paths.

    Returns ``()`` for toolchain-provided (``std.*``) and
    SDK-provided modules (covered by the distribution binding
    and the wholesale SDK capture, respectively), a tuple of
    realpaths for project modules (a module file, or every
    ``.mojo`` file under a package directory as a documented
    superset), and ``None`` when the module resolves nowhere.
    Search order matches the frontend: the importing file's
    directory first, then the manifest directory.
    """
    if module in STDLIB_ROOTS or module.startswith("std."):
        return ()
    if module_resolves_to_sdk(module, sdk_dir):
        return ()
    segments = module.split(".")
    candidates = [
        os.path.join(source_dir, *segments) + ".mojo",
        os.path.join(project_dir, *segments) + ".mojo",
    ]
    if len(segments) > 1:
        candidates += [
            os.path.join(source_dir, segments[0]) + ".mojo",
            os.path.join(project_dir, segments[0]) + ".mojo",
        ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return (os.path.realpath(candidate),)
    for directory in (
        os.path.join(source_dir, *segments),
        os.path.join(project_dir, *segments),
    ):
        if not os.path.isdir(directory):
            continue
        files = _package_mojo_files(directory)
        if files:
            return files
    return None


def discover_imports(
    source_files: tuple[str, ...] | list[str],
    *,
    project_dir: str,
    sdk_dir: str,
) -> tuple[str, ...]:
    """Find the non-SDK modules imported by ``source_files``.

    Follows imports transitively to a fixpoint (import cycles
    terminate: each file is scanned once). Unresolved modules
    and unsupported import constructs raise :class:`InputError`
    (``MBPF106``) instead of dropping out of the sealed set.
    Returns origin realpaths, sorted.
    """
    _files, _sdk_hit = _discover_graph(
        tuple(source_files),
        project_dir=project_dir,
        sdk_dir=sdk_dir,
    )
    return _files


def _discover_graph(
    source_files: tuple[str, ...],
    *,
    project_dir: str,
    sdk_dir: str,
) -> tuple[tuple[str, ...], bool]:
    """Return ``(import realpaths, sdk_hit)`` for ``source_files``."""
    discovered: dict[str, None] = {}
    scanned: set[str] = set()
    sdk_hit = False
    queue = list(source_files)
    while queue:
        source = queue.pop(0)
        try:
            identity = os.path.realpath(source)
        except OSError:
            continue
        if identity in scanned:
            continue
        scanned.add(identity)
        source_dir = os.path.dirname(os.path.abspath(source))
        for module in parse_mojo_imports(source):
            if module in STDLIB_ROOTS or module.startswith("std."):
                continue
            if module_resolves_to_sdk(module, sdk_dir):
                sdk_hit = True
                continue
            resolved = resolve_module(
                module,
                source_dir=source_dir,
                project_dir=project_dir,
                sdk_dir=sdk_dir,
            )
            if resolved is None:
                raise _fail(
                    "unresolved import %r in %s: no module file "
                    "under the source directory, the manifest "
                    "directory or the SDK" % (module, source),
                    source,
                    "add the module file or fix the import spelling",
                )
            for path in resolved:
                if path not in discovered and path not in scanned:
                    discovered[path] = None
                    queue.append(path)
    return (tuple(sorted(discovered)), sdk_hit)


def canonical_manifest_bytes(manifest: ProjectManifest) -> bytes:
    """Serialize a manifest to canonical bytes (sorted keys, UTF-8).

    The encoding fixes field order and separators; the manifest
    path is a location, not content, and is excluded, so the
    same declarations captured anywhere compare equal.
    """
    if not isinstance(manifest, ProjectManifest):
        raise TypeError("canonical_manifest_bytes requires a ProjectManifest")
    document = {
        "schema_version": manifest.schema_version,
        "project": {"name": manifest.project.name},
        "target": {
            "profile": manifest.target.profile,
            "core": manifest.target.core,
        },
        "artifact": {
            "name": manifest.artifact.name,
            "source_license": manifest.artifact.source_license,
            "kernel_license": manifest.artifact.kernel_license,
        },
        "programs": [
            {
                "source": program.source,
                "entry": program.entry,
                "program_type": program.program_type,
                "section": program.section,
            }
            for program in manifest.programs
        ],
        "maps": [
            {
                "name": entry.name,
                "map_type": entry.map_type,
                "key_type": entry.key_type,
                "value_type": entry.value_type,
                "max_entries": entry.max_entries,
            }
            for entry in manifest.maps
        ],
    }
    text = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return (text + "\n").encode("ascii")


@dataclass(frozen=True)
class SnapshotTool:
    """One admitted compiler tool identity (never a path)."""

    name: str
    version: str
    sha256: str


@dataclass(frozen=True)
class ToolchainInputs:
    """The toolchain side of a build-input capture.

    ``tools`` holds the admitted ``mojo``/``llc`` identities in
    pipeline order; ``distribution`` holds ``"<kind> <platform>
    <file> <sha256>"`` records binding the native closure and
    the Mojo install (empty when the lockfile carries no
    distribution record); ``lockfile_sha256`` hashes the pin
    document itself (``None`` when no lockfile backs the
    capture).
    """

    tools: tuple[SnapshotTool, ...] = ()
    distribution: tuple[str, ...] = ()
    lockfile_sha256: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "tools", tuple(self.tools))
        object.__setattr__(
            self, "distribution", tuple(self.distribution)
        )


@dataclass(frozen=True)
class SdkInputs:
    """The SDK side of a build-input capture."""

    sdk_dir: str
    version: str


@dataclass(frozen=True)
class CapturedFile:
    """One captured input file: logical name plus staged bytes.

    ``logical`` is the stable relative path (project-relative
    for programs and imports, ``sdk/``-prefixed for SDK files);
    ``origin`` is the absolute source path the bytes were read
    from; ``staged`` is the private capture-root copy actually
    passed to the compiler. Only ``logical``/``sha256``/``size``
    are stable: ``origin`` and ``staged`` never serialize and
    never participate in equality, so identical inputs captured
    in two roots compare equal.
    """

    logical: str
    origin: str = field(compare=False)
    staged: str = field(compare=False)
    sha256: str = ""
    size: int = 0

    def to_dict(self) -> dict[str, str | int]:
        """Return a stable plain-data mapping of this file."""
        return {
            "path": self.logical,
            "sha256": self.sha256,
            "size": self.size,
        }


def _read_once(path: str) -> bytes:
    """Read a build input once; failures are ``MBPF106``."""
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise _fail(
            "cannot read build input %r: %s" % (path, exc),
            path,
            "check the input path and permissions",
        ) from None


def _write_staged(path: str, content: bytes) -> None:
    """Write staged bytes plus a read-only guard bit."""
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(content)
        os.chmod(path, 0o444)
    except OSError as exc:
        raise _fail(
            "cannot stage build input %r: %s" % (path, exc),
            path,
            "use a writable work_parent directory with free space",
        ) from None


def _hash_bytes(content: bytes) -> tuple[str, int]:
    return (hashlib.sha256(content).hexdigest(), len(content))


@dataclass(frozen=True)
class BuildSnapshot:
    """The complete captured inputs of one build (``build-snapshot-v1``).

    ``manifest_bytes`` is the canonical manifest;
    ``manifest_digest`` hashes the staged manifest copy;
    ``programs``/``imports``/``sdk`` hold every consumed file
    with the staged bytes the compiler reads; ``grants`` is the
    validated source-grant record over the staged bytes;
    ``flags`` carries the relevant build flag spellings;
    ``environment``/``stdlib``/``compiler`` bind the influential
    environment, the toolchain distribution and the admitted
    tools. ``root``/``project_root``/``sdk_root`` and every
    ``origin``/``staged`` path are capture-local: they never
    serialize and never participate in equality.
    """

    schema_version: int
    contract: str
    manifest_bytes: bytes
    manifest_digest: str
    manifest_staged: str = field(compare=False)
    programs: tuple[CapturedFile, ...] = ()
    imports: tuple[CapturedFile, ...] = ()
    sdk: tuple[CapturedFile, ...] = ()
    source_license: str = ""
    grants: SourceGrantRecord | None = None
    flags: tuple[str, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()
    stdlib: tuple[str, ...] = ()
    compiler: tuple[str, ...] = ()
    profile_id: str = ""
    profile_sha256: str = ""
    sdk_needed: bool = False
    sdk_version: str = ""
    root: str = field(default="", compare=False)
    project_root: str = field(default="", compare=False)
    sdk_root: str | None = field(default=None, compare=False)
    project_dir: str = field(default="", compare=False)
    sdk_dir: str = field(default="", compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "programs", tuple(self.programs))
        object.__setattr__(self, "imports", tuple(self.imports))
        object.__setattr__(self, "sdk", tuple(self.sdk))
        object.__setattr__(self, "flags", tuple(self.flags))
        object.__setattr__(
            self, "environment", tuple(self.environment)
        )
        object.__setattr__(self, "stdlib", tuple(self.stdlib))
        object.__setattr__(self, "compiler", tuple(self.compiler))

    def program_paths(self) -> tuple[str, ...]:
        """Return the staged program paths in manifest order.

        These are the paths actually passed to the compiler.
        """
        return tuple(item.staged for item in self.programs)

    def program_origins(self) -> tuple[str, ...]:
        """Return the origin program paths in manifest order."""
        return tuple(item.origin for item in self.programs)

    def frontend_search_path(self) -> str | None:
        """Return the staged ``-I`` directory, if the build needs one."""
        if not self.sdk_needed:
            return None
        return self.sdk_root

    def display_replacements(self) -> tuple[tuple[str, str], ...]:
        """Return ``(staged_root, origin_dir)`` mapping pairs."""
        pairs: list[tuple[str, str]] = []
        if self.project_root and self.project_dir:
            pairs.append(
                (os.path.normpath(self.project_root),
                 os.path.normpath(self.project_dir))
            )
        if self.sdk_root and self.sdk_dir:
            pairs.append(
                (os.path.normpath(self.sdk_root),
                 os.path.normpath(self.sdk_dir))
            )
        return tuple(pairs)

    def display_path(self, path: str) -> str:
        """Map a staged path back to its user-facing origin path."""
        candidate = os.path.normpath(path)
        for staged, origin in self.display_replacements():
            if candidate == staged:
                return origin
            if candidate.startswith(staged + os.sep):
                return origin + candidate[len(staged):]
        return path

    def display_text(self, text: str) -> str:
        """Rewrite staged-root prefixes inside free text to origins.

        Frontend error lines and step explanations quote the
        staged paths the tools saw; users must see the project
        paths they own instead.
        """
        rewritten = text
        for staged, origin in self.display_replacements():
            rewritten = rewritten.replace(staged, origin)
        return rewritten

    def _expected_staged(self) -> dict[str, tuple[str, str]]:
        """Map staged path -> ``(logical, sha256)`` for every file."""
        expected: dict[str, tuple[str, str]] = {
            os.path.normpath(self.manifest_staged): (
                os.path.basename(self.manifest_staged),
                self.manifest_digest,
            )
        }
        for item in self.programs + self.imports + self.sdk:
            expected[os.path.normpath(item.staged)] = (
                item.logical, item.sha256,
            )
        return expected

    def verify(self) -> None:
        """Re-verify the staged bytes against the capture record.

        Re-hashes every staged file and re-enumerates the staged
        trees: changed, missing or newly appeared files raise
        :class:`InputError` (``MBPF106``) instead of compiling or
        attributing foreign bytes. Call at every snapshot
        boundary (before compiling, before publishing).
        """
        expected = self._expected_staged()
        observed: dict[str, str] = {}
        for tree in [self.project_root] + (
            [self.sdk_root] if self.sdk_root is not None else []
        ):
            if not tree or not os.path.isdir(tree):
                continue
            for root, dirs, files in os.walk(tree):
                dirs.sort()
                for name in sorted(files):
                    path = os.path.join(root, name)
                    if not os.path.isfile(path):
                        continue
                    try:
                        with open(path, "rb") as handle:
                            content = handle.read()
                    except OSError as exc:
                        raise _fail(
                            "captured build input %r became "
                            "unreadable: %s"
                            % (self.display_path(path), exc),
                            self.display_path(path),
                            "rebuild without modifying inputs while "
                            "the build runs",
                        ) from None
                    observed[os.path.normpath(path)] = (
                        hashlib.sha256(content).hexdigest()
                    )
        for path in sorted(set(observed) - set(expected)):
            raise _fail(
                "unexpected file %r appeared in the captured "
                "build inputs; rejecting instead of compiling "
                "uncaptured bytes" % (self.display_path(path),),
                self.display_path(path),
                "rebuild without modifying inputs while the build runs",
            )
        for path in sorted(set(expected) - set(observed)):
            raise _fail(
                "captured build input %r went missing after "
                "capture; rejecting instead of compiling without it"
                % (self.display_path(path),),
                self.display_path(path),
                "rebuild without modifying inputs while the build runs",
            )
        for path in sorted(expected):
            _logical, digest = expected[path]
            if observed[path] != digest:
                raise _fail(
                    "captured build input %r changed after "
                    "capture; rejecting instead of attributing the "
                    "clean hash to changed bytes"
                    % (self.display_path(path),),
                    self.display_path(path),
                    "rebuild without modifying inputs while the build runs",
                )

    def dispose(self) -> None:
        """Remove the private capture root (best effort, no raise)."""
        if self.root:
            shutil.rmtree(self.root, ignore_errors=True)


def _snapshot_tool_identities(
    toolchain: ToolchainInputs,
) -> tuple[str, ...]:
    """Format ``"<name> <version> <sha256>"`` per admitted tool."""
    formatted: list[str] = []
    for tool in toolchain.tools:
        version = tool.version or "unknown-version"
        digest = tool.sha256 or "unknown-sha256"
        formatted.append(
            "%s %s %s" % (tool.name, version, digest)
        )
    return tuple(formatted)


def _snapshot_stdlib_identities(
    toolchain: ToolchainInputs,
) -> tuple[str, ...]:
    """Format the stdlib/distribution identity strings.

    The Mojo standard library resolves inside the toolchain
    install, so its identity is the lockfile's distribution
    record plus the lockfile bytes themselves; a capture
    without either says ``unbound`` explicitly instead of
    silently omitting the class.
    """
    if not toolchain.distribution and toolchain.lockfile_sha256 is None:
        return ("stdlib distribution unbound no-toolchain-binding",)
    identities: list[str] = []
    if toolchain.distribution:
        identities.extend(
            "stdlib distribution %s" % record
            for record in toolchain.distribution
        )
    else:
        identities.append(
            "stdlib distribution unbound no-distribution-record"
        )
    if toolchain.lockfile_sha256 is not None:
        identities.append(
            "stdlib lockfile %s" % toolchain.lockfile_sha256
        )
    return tuple(identities)


def _resolve_lexical(
    module: str,
    *,
    source_dir: str,
    project_dir: str,
) -> tuple[str, ...] | None:
    """Resolve a module to lexical origin paths (no symlink chase).

    Same search order as :func:`resolve_module`, but returns the
    lexical candidate paths so capture can mirror the exact
    layout the frontend resolves. Package directories yield
    their lexical ``.mojo`` members.
    """
    segments = module.split(".")
    candidates = [
        os.path.join(source_dir, *segments) + ".mojo",
        os.path.join(project_dir, *segments) + ".mojo",
    ]
    if len(segments) > 1:
        candidates += [
            os.path.join(source_dir, segments[0]) + ".mojo",
            os.path.join(project_dir, segments[0]) + ".mojo",
        ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return (candidate,)
    for directory in (
        os.path.join(source_dir, *segments),
        os.path.join(project_dir, *segments),
    ):
        if not os.path.isdir(directory):
            continue
        found: list[str] = []
        for root, dirs, files in os.walk(directory):
            dirs.sort()
            for name in sorted(files):
                if not name.endswith(".mojo"):
                    continue
                candidate = os.path.join(root, name)
                if os.path.isfile(candidate):
                    found.append(candidate)
        if found:
            return tuple(found)
    return None


def _stable_rel(path: str, root: str) -> str:
    return os.path.relpath(path, root).replace(os.sep, "/")


def capture_build_inputs(
    manifest: ProjectManifest,
    toolchain: ToolchainInputs,
    sdk: SdkInputs,
    *,
    environment: dict[str, str] | None = None,
    work_parent: str | None = None,
) -> BuildSnapshot:
    """Capture every input of one build into a private root.

    Reads the manifest, program sources, transitive imports and
    (when needed) the whole SDK exactly once each, stages the
    bytes into a fresh private directory, validates the source
    grants over the staged bytes, and binds the toolchain
    distribution, lockfile, profile, flags placeholder and
    environment. Returns the immutable :class:`BuildSnapshot`
    whose staged paths feed the compiler and whose hashes feed
    provenance and cache identity. Any failure raises
    :class:`InputError` (``MBPF106``) -- or the license gate's
    :class:`InspectionError` for grant mismatches -- after
    removing the capture root, so a failed capture stages
    nothing usable.

    The caller sets :attr:`BuildSnapshot.flags` afterwards
    (e.g. via :func:`dataclasses.replace`), since the flag
    spellings depend on the captured ``sdk_needed`` verdict.
    """
    if not isinstance(manifest, ProjectManifest):
        raise TypeError("capture_build_inputs requires a ProjectManifest")
    if not isinstance(toolchain, ToolchainInputs):
        raise TypeError("capture_build_inputs requires ToolchainInputs")
    if not isinstance(sdk, SdkInputs):
        raise TypeError("capture_build_inputs requires SdkInputs")
    if not os.path.isabs(manifest.manifest_path):
        raise _fail(
            "manifest path %r is not absolute; callers must absolutize "
            "it (the build driver does at entry)"
            % (manifest.manifest_path,),
            manifest.manifest_path,
            "parse the manifest from an absolute path",
        )
    try:
        resolved_profile = lookup_profile(manifest.target.profile)
    except ProfileError as exc:
        raise _fail(
            "target profile %r is not supported"
            % (manifest.target.profile,),
            "%s: target.profile" % manifest.manifest_path,
            exc.diagnostic.remedy,
        ) from None
    profile_sha = profile_digest(resolved_profile)
    canonical = canonical_manifest_bytes(manifest)

    project_dir = os.path.dirname(os.path.abspath(manifest.manifest_path))
    try:
        root = tempfile.mkdtemp(prefix="mojobpf-inputs-", dir=work_parent)
    except (OSError, FileNotFoundError) as exc:
        raise _fail(
            "cannot create input capture directory: %s" % exc,
            work_parent or tempfile.gettempdir(),
            "use a writable work_parent directory",
        ) from None
    project_root = os.path.join(root, "project")
    sdk_root = os.path.join(root, "sdk")
    try:
        return _capture_inside(
            manifest, toolchain, sdk, canonical, profile_sha,
            project_dir, root, project_root, sdk_root,
            environment,
        )
    except (InputError, InspectionError):
        shutil.rmtree(root, ignore_errors=True)
        raise


def _capture_inside(
    manifest: ProjectManifest,
    toolchain: ToolchainInputs,
    sdk: SdkInputs,
    canonical: bytes,
    profile_sha: str,
    project_dir: str,
    root: str,
    project_root: str,
    sdk_root: str,
    environment: dict[str, str] | None,
) -> BuildSnapshot:
    # Every origin file is read exactly once; the returned bytes
    # are staged, hashed and parsed from that single read, so a
    # concurrent modification can neither split the capture nor
    # slip an unscanned import past discovery.
    staged_by_realpath: dict[str, CapturedFile] = {}
    logical_owners: dict[str, str] = {}
    staged_programs: list[CapturedFile] = []

    def _claim(logical: str, origin: str, staged: str,
               digest: str, size: int) -> CapturedFile:
        owner = logical_owners.get(logical)
        if owner is not None and owner != os.path.realpath(origin):
            raise _fail(
                "conflicting build inputs map to %r" % (logical,),
                origin,
                "keep program and import paths distinct",
            )
        record = CapturedFile(
            logical=logical,
            origin=os.path.abspath(origin),
            staged=staged,
            sha256=digest,
            size=size,
        )
        logical_owners[logical] = os.path.realpath(origin)
        staged_by_realpath[os.path.realpath(origin)] = record
        return record

    def _stage_project_file(
        lexical_origin: str, logical: str,
    ) -> CapturedFile:
        identity = os.path.realpath(lexical_origin)
        known = staged_by_realpath.get(identity)
        if known is not None:
            return known
        content = _read_once(lexical_origin)
        staged = os.path.join(
            project_root, *logical.split("/")
        )
        _write_staged(staged, content)
        digest, size = _hash_bytes(content)
        return _claim(logical, lexical_origin, staged, digest, size)

    for program in manifest.programs:
        lexical = os.path.normpath(program.source)
        if (
            os.path.isabs(program.source)
            or lexical == ".."
            or lexical.startswith(".." + os.sep)
        ):
            raise _fail(
                "program source escapes the manifest directory: %r"
                % (program.source,),
                "%s: source %r"
                % (manifest.manifest_path, program.source),
                "keep sources inside the project directory",
            )
        logical = lexical.replace(os.sep, "/")
        origin = os.path.join(project_dir, lexical)
        if not os.path.isfile(origin):
            raise _fail(
                "program source not found: %r" % (program.source,),
                "%s: source %r"
                % (manifest.manifest_path, program.source),
                "create the source file or fix the source path",
            )
        staged_programs.append(_stage_project_file(origin, logical))

    # Import walk over the staged bytes: each staged file is
    # parsed once, new modules resolve against the origin
    # directories and stage immediately, and cycles terminate on
    # the staged set.
    import_records: dict[str, CapturedFile] = {}
    program_identities = {
        os.path.realpath(item.origin) for item in staged_programs
    }
    sdk_hit = False
    queue = list(staged_programs)
    scanned: set[str] = set()
    while queue:
        current = queue.pop(0)
        identity = os.path.realpath(current.origin)
        if identity in scanned:
            continue
        scanned.add(identity)
        with open(current.staged, "rb") as handle:
            staged_bytes = handle.read()
        try:
            staged_text = staged_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _fail(
                "Mojo source %r is not UTF-8: %s"
                % (current.origin, exc),
                current.origin,
                "keep Mojo sources in UTF-8",
            ) from None
        modules = parse_mojo_imports_text(staged_text, current.origin)
        if not modules:
            continue
        source_dir = os.path.dirname(
            os.path.abspath(current.origin)
        )
        for module in modules:
            if module in STDLIB_ROOTS or module.startswith("std."):
                continue
            if module_resolves_to_sdk(module, sdk.sdk_dir):
                sdk_hit = True
                continue
            resolved = _resolve_lexical(
                module,
                source_dir=source_dir,
                project_dir=project_dir,
            )
            if resolved is None:
                raise _fail(
                    "unresolved import %r in %s: no module file "
                    "under the source directory, the manifest "
                    "directory or the SDK" % (module, current.origin),
                    current.origin,
                    "add the module file or fix the import spelling",
                )
            for lexical_origin in resolved:
                logical = _stable_rel(
                    os.path.abspath(lexical_origin),
                    os.path.abspath(project_dir),
                )
                if (
                    os.path.isabs(logical)
                    or logical == ".."
                    or logical.startswith("../")
                ):
                    raise _fail(
                        "import %r in %s resolves outside the "
                        "project directory: %r"
                        % (module, current.origin, lexical_origin),
                        current.origin,
                        "keep imported modules inside the project "
                        "directory",
                    )
                record = _stage_project_file(
                    lexical_origin, logical
                )
                record_identity = os.path.realpath(record.origin)
                if (
                    record_identity not in import_records
                    and record_identity not in program_identities
                ):
                    import_records[record_identity] = record
                    queue.append(record)

    sdk_needed = bool(manifest.maps) or sdk_hit
    staged_sdk: list[CapturedFile] = []
    if sdk_needed:
        if not os.path.isdir(sdk.sdk_dir):
            raise _fail(
                "SDK directory missing: %s" % sdk.sdk_dir,
                sdk.sdk_dir,
                "reinstall the mojobpf package; the SDK resolves "
                "through package resources",
            )
        sdk_files: list[str] = []
        for walk_root, dirs, files in os.walk(sdk.sdk_dir):
            dirs.sort()
            for name in sorted(files):
                candidate = os.path.join(walk_root, name)
                if os.path.isfile(candidate):
                    sdk_files.append(candidate)
        for origin in sdk_files:
            content = _read_once(origin)
            logical = "sdk/" + _stable_rel(
                os.path.abspath(origin), os.path.abspath(sdk.sdk_dir)
            )
            staged = os.path.join(
                sdk_root,
                *logical[len("sdk/"):].split("/"),
            )
            _write_staged(staged, content)
            digest, size = _hash_bytes(content)
            staged_sdk.append(
                CapturedFile(
                    logical=logical,
                    origin=os.path.abspath(origin),
                    staged=staged,
                    sha256=digest,
                    size=size,
                )
            )

    # The staged manifest must parse to the same canonical
    # manifest the caller admitted: a file swapped between the
    # admission parse and this capture rejects here instead of
    # compiling under stale declarations.
    manifest_content = _read_once(manifest.manifest_path)
    manifest_name = os.path.basename(manifest.manifest_path)
    if manifest_name in logical_owners:
        raise _fail(
            "conflicting build inputs map to %r" % (manifest_name,),
            manifest.manifest_path,
            "keep program and import paths distinct",
        )
    manifest_staged = os.path.join(project_root, manifest_name)
    _write_staged(manifest_staged, manifest_content)
    try:
        reparsed = parse_manifest(manifest_staged)
    except (ManifestError, ProfileError) as exc:
        raise _fail(
            "captured manifest %r failed to re-parse: %s"
            % (manifest.manifest_path, exc.diagnostic.explanation),
            manifest.manifest_path,
            "rebuild without modifying inputs while the build runs",
        ) from None
    if canonical_manifest_bytes(reparsed) != canonical:
        raise _fail(
            "manifest %r changed between admission and capture; "
            "rejecting instead of compiling under stale declarations"
            % (manifest.manifest_path,),
            manifest.manifest_path,
            "rebuild without modifying inputs while the build runs",
        )
    manifest_digest, _manifest_size = _hash_bytes(manifest_content)

    grants = validate_source_grants(
        manifest.artifact.source_license,
        [item.staged for item in staged_programs],
        [item.staged for item in staged_sdk],
        project_dir=project_root,
        imported_sources=[item.staged for item in import_records.values()],
    )
    ordered_imports = tuple(
        record
        for _identity, record in sorted(
            import_records.items(), key=lambda pair: pair[1].logical
        )
    )
    return BuildSnapshot(
        schema_version=INPUT_SNAPSHOT_VERSION,
        contract=SNAPSHOT_CONTRACT,
        manifest_bytes=canonical,
        manifest_digest=manifest_digest,
        manifest_staged=manifest_staged,
        programs=tuple(staged_programs),
        imports=ordered_imports,
        sdk=tuple(staged_sdk),
        source_license=manifest.artifact.source_license,
        grants=grants,
        flags=(),
        environment=capture_environment(environment),
        stdlib=_snapshot_stdlib_identities(toolchain),
        compiler=_snapshot_tool_identities(toolchain),
        profile_id=manifest.target.profile,
        profile_sha256=profile_sha,
        sdk_needed=sdk_needed,
        sdk_version=sdk.version,
        root=root,
        project_root=project_root,
        sdk_root=sdk_root if sdk_needed else None,
        project_dir=os.path.abspath(project_dir),
        sdk_dir=os.path.abspath(sdk.sdk_dir),
    )
