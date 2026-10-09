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
from collections.abc import Mapping
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

#: Logical names of the installed standard-library payload files
#: hashed into the snapshot identity (see
#: :func:`stdlib_payload_identities`).
STDLIB_PAYLOAD_NAMES = ("std.mojoc", "modular.cfg")

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


def _selected_environment(
    overrides: dict[str, str] | None,
) -> dict[str, str]:
    """Return the raw influential compiler environment by name.

    Selects :data:`ENVIRONMENT_BASE_NAMES` plus any ambient
    variable starting with :data:`ENVIRONMENT_EXTRA_PREFIXES`;
    ``overrides`` (the test seam, or the build driver's
    pre-captured pins) replaces or adds entries after the
    ambient capture. The ambient environment is read exactly
    once, so selection never mixes two ambient states.
    """
    ambient = dict(os.environ)
    entries: dict[str, str] = {}
    for name in ENVIRONMENT_BASE_NAMES:
        if name in ambient:
            entries[name] = ambient[name]
    for name in sorted(ambient):
        if name in entries:
            continue
        if name.startswith(ENVIRONMENT_EXTRA_PREFIXES):
            entries[name] = ambient[name]
    if overrides is not None:
        for name, value in overrides.items():
            entries[str(name)] = str(value)
    return entries


@dataclass(frozen=True)
class PinnedEnvironment:
    """The compiler-material environment from one ambient read.

    ``recorded`` holds the stable ``(name, value)`` pairs for
    evidence and cache identity; ``spawn`` holds the same names
    with verbatim values for process spawn; ``unset`` names the
    :data:`ENVIRONMENT_BASE_NAMES` absent from the read, so
    spawn withholds a variable added after capture just as it
    enforces a recorded value. All three derive from a single
    ambient read, so they can never disagree.
    """

    recorded: tuple[tuple[str, str], ...] = ()
    spawn: tuple[tuple[str, str], ...] = ()
    unset: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "recorded", tuple(self.recorded)
        )
        object.__setattr__(self, "spawn", tuple(self.spawn))
        object.__setattr__(self, "unset", tuple(self.unset))


def capture_pinned_environment(
    overrides: dict[str, str] | None = None,
) -> PinnedEnvironment:
    """Pin the influential compiler environment, present and absent.

    One ambient read yields the stable recorded pairs, the raw
    spawn pairs and the absent base names together; callers
    must use all three from one call instead of reading the
    ambient environment again.
    """
    entries = _selected_environment(overrides)
    return PinnedEnvironment(
        recorded=tuple(
            (name, stable_env_value(entries[name]))
            for name in sorted(entries)
        ),
        spawn=tuple(
            (name, entries[name]) for name in sorted(entries)
        ),
        unset=tuple(
            name for name in ENVIRONMENT_BASE_NAMES
            if name not in entries
        ),
    )


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
    return capture_pinned_environment(overrides).recorded


def capture_spawn_environment(
    overrides: dict[str, str] | None = None,
) -> tuple[tuple[str, str], ...]:
    """Capture the raw influential compiler environment for spawn.

    Same names as :func:`capture_environment`, but verbatim
    values: the recorded environment hashes path values, which
    spawn cannot consume, so the snapshot pins these raw bytes
    and every pipeline step spawns under them. The recorded
    environment therefore IS the spawn environment: a
    post-capture ambient change cannot silently diverge
    compilation from evidence. Returns ``(name, value)`` pairs
    sorted by name.
    """
    return capture_pinned_environment(overrides).spawn


def spawn_scrub_names(
    *,
    pinned: Mapping[str, str],
    unset: tuple[str, ...] | list[str],
    ambient: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Name the variables spawn must withhold from the ambient.

    ``pinned`` maps the snapshot's recorded names to their raw
    values and ``unset`` lists its absent base names; every
    unset name is withheld, and so is any ambient variable
    starting with :data:`ENVIRONMENT_EXTRA_PREFIXES` that the
    snapshot did not record (added after capture). The result
    drains the ambient environment down to exactly the
    recorded set before the pinned overlay applies.
    """
    table = os.environ if ambient is None else ambient
    names = set(unset)
    for name in table:
        if (
            name not in pinned
            and name.startswith(ENVIRONMENT_EXTRA_PREFIXES)
        ):
            names.add(name)
    return tuple(sorted(names))


def build_spawn_env(
    *,
    ambient: Mapping[str, str],
    admission_unset: tuple[str, ...] | list[str] = (),
    admission_set: (
        tuple[tuple[str, str], ...] | list[tuple[str, str]]
    ) = (),
    pinned: Mapping[str, str],
    unset: tuple[str, ...] | list[str],
    redirect: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build a child environment purely from one ambient snapshot.

    ``ambient`` is the single spawn-time snapshot (the inert
    remainder only: identity, locale and output-shaping
    variables the admission keeps by design). The admission
    overlay applies first (``execution-contract-v1``
    sanitization order: unset names dropped, then set values
    overlaid), then the snapshot pin (absent names and unpinned
    compiler-material additions withheld, pinned values
    enforced), then ``redirect`` (documented consumption
    overrides such as the staged standard-library home, which
    intentionally replace the pinned value for one step). The
    global environment is never read or modified here: the
    caller snapshots ``dict(os.environ)`` once. Pair with
    :func:`check_spawn_env`, which proves the compiler-material
    subset equals the pin plus redirect immediately before
    process creation.
    """
    child = dict(ambient)
    for name in admission_unset:
        child.pop(name, None)
    for name, value in admission_set:
        child[name] = value
    for name in spawn_scrub_names(
        pinned=pinned, unset=unset, ambient=child
    ):
        child.pop(name, None)
    for name, value in pinned.items():
        child[name] = value
    if redirect:
        for name, value in redirect.items():
            child[name] = value
    return child


def check_spawn_env(
    child: Mapping[str, str],
    *,
    pinned: Mapping[str, str],
    unset: tuple[str, ...] | list[str],
    redirect: Mapping[str, str] | None = None,
) -> str | None:
    """Re-check a spawn environment against the snapshot pin.

    Returns ``None`` when the child carries exactly the pinned
    compiler-material set (pinned values enforced, absent names
    withheld, redirect overrides applied, no unpinned extras);
    otherwise returns the first divergence so the caller fails
    the spawn closed. Call after :func:`build_spawn_env`,
    immediately before process creation.
    """
    overrides = redirect or {}
    for name, value in pinned.items():
        if name in overrides:
            continue
        if child.get(name) != value:
            return (
                "pinned environment variable %r diverged from "
                "the snapshot pin" % (name,)
            )
    for name in unset:
        if name in overrides:
            continue
        if name in child:
            return (
                "environment variable %r was absent at capture "
                "but is present at spawn" % (name,)
            )
    for name, value in overrides.items():
        if child.get(name) != value:
            return (
                "redirected environment variable %r diverged "
                "from its consumption binding" % (name,)
            )
    for name in child:
        if name in pinned or name in overrides:
            continue
        if name in ENVIRONMENT_BASE_NAMES or name.startswith(
            ENVIRONMENT_EXTRA_PREFIXES
        ):
            return (
                "unpinned compiler-material variable %r would "
                "reach the child" % (name,)
            )
    return None


def _find_unescaped(text: str, delimiter: str, start: int) -> int:
    """Return the first unescaped ``delimiter`` at/after ``start``.

    An occurrence preceded by an odd run of backslashes is string
    content (``\\"`` inside a triple-quoted literal), not the
    string's end; only backslashes on this physical line count,
    since a backslash-newline is a line continuation that escapes
    nothing on the next line. Returns -1 when no unescaped
    occurrence remains.
    """
    index = text.find(delimiter, start)
    while index >= 0:
        backslashes = 0
        probe = index - 1
        while probe >= 0 and text[probe] == "\\":
            backslashes += 1
            probe -= 1
        if backslashes % 2 == 0:
            return index
        index = text.find(delimiter, index + 1)
    return -1


def _mask_line(line: str, triple: str | None
               ) -> tuple[str, str | None]:
    """Blank strings and cut comments on one physical line.

    String contents (single, double and triple quoted) become
    spaces so import keywords inside literals can never match;
    a ``#`` outside any string ends the code. ``triple`` carries
    the unterminated triple-quote delimiter across lines.
    Escaped quotes never open or close a string: a delimiter
    preceded by an odd run of backslashes is literal content.
    """
    out: list[str] = []
    pos = 0
    size = len(line)
    if triple is not None:
        end = _find_unescaped(line, triple, 0)
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
            end = _find_unescaped(line, delimiter, pos + 3)
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

    A module resolves into the SDK only through its full dotted
    path: a module file (``mojobpf/packet.mojo``) or a package
    directory (the bare ``mojobpf`` root, which a ``from
    mojobpf import packet`` names and the SDK provides as a
    directory of module files). A bare root directory never
    admits deeper names on its own: ``mojobpf.no_such_module``
    resolves nowhere and rejects at capture instead of
    deferring to the frontend. SDK-first precedence matches the
    frontend, which searches the packaged ``-I`` directory.
    """
    segments = module.split(".")
    if os.path.isdir(os.path.join(sdk_dir, *segments)):
        return True
    if os.path.isfile(os.path.join(sdk_dir, *segments) + ".mojo"):
        return True
    return False


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
    <sha256>"`` records binding the native closure and
    the Mojo install (empty when the lockfile carries no
    distribution record); ``lockfile_sha256`` hashes the pin
    document itself (``None`` when no lockfile backs the
    capture); ``stdlib_payload`` holds the
    :func:`stdlib_payload_identities` entries hashing the
    installed standard-library bytes the admitted toolchain
    resolves (empty when the caller binds no payload);
    ``stdlib_payload_paths`` holds the parallel
    :func:`stdlib_payload_paths` ``(logical, path)`` pairs so
    every snapshot boundary can re-hash the same install
    files (empty when the caller binds no paths, in which
    case the payload is attested but not re-verified).
    """

    tools: tuple[SnapshotTool, ...] = ()
    distribution: tuple[str, ...] = ()
    lockfile_sha256: str | None = None
    stdlib_payload: tuple[str, ...] = ()
    stdlib_payload_paths: tuple[tuple[str, str | None], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "tools", tuple(self.tools))
        object.__setattr__(
            self, "distribution", tuple(self.distribution)
        )
        object.__setattr__(
            self, "stdlib_payload", tuple(self.stdlib_payload)
        )
        object.__setattr__(
            self, "stdlib_payload_paths",
            tuple(self.stdlib_payload_paths),
        )


@dataclass(frozen=True)
class StdlibSealEntry:
    """One hashed stdlib payload file plus its expected digest.

    ``logical`` is the stable payload name (``std.mojoc`` /
    ``modular.cfg``); ``path`` is the install path hashed at
    capture (``None`` when unresolvable); ``sha256`` is the
    capture digest, or ``"missing"`` when the file was missing
    or unreadable. ``staged`` is the private capture-root copy
    the compiler consumes (``None`` when the file was not
    captured); ``staged_sha256`` is the expected digest of
    those staged bytes, which differs from ``sha256`` only for
    a re-pointed ``modular.cfg`` (see
    :func:`repoint_cfg_import_path`). Capture-local: never
    serializes and never participates in equality.
    """

    logical: str
    path: str | None = None
    sha256: str = "missing"
    staged: str | None = None
    staged_sha256: str | None = None


def _split_cfg_lines(cfg: bytes) -> list[tuple[bytes, bytes]]:
    """Split config bytes into ``(content, ending)`` pairs.

    The single line-boundary rule shared by parsing and
    rewriting: every break the parser sees the rewriter sees too
    (CR, LF and CRLF alike -- the pinned frontend honors
    bare-CR configs, so LF-only splitting would accept a live
    directory the rewriter cannot redirect). Endings are
    preserved so rewriting changes values only, never layout,
    and splitting then rejoining round-trips the input exactly.
    """
    lines: list[tuple[bytes, bytes]] = []
    for chunk in cfg.splitlines(keepends=True):
        if chunk.endswith(b"\r\n"):
            lines.append((chunk[:-2], chunk[-2:]))
        elif chunk.endswith(b"\r") or chunk.endswith(b"\n"):
            lines.append((chunk[:-1], chunk[-1:]))
        else:
            lines.append((chunk, b""))
    return lines


def _cfg_import_path_match(stripped: str) -> tuple[bool, str]:
    """Match one stripped config line against the payload key.

    The single key rule shared by parsing and rewriting: only a
    line whose text before the first ``=`` is exactly
    ``import_path`` (case-insensitively, as the pinned frontend
    resolves it) selects the payload. ``import_path_alias`` and
    any other spelling are inert on both sides, matching the
    frontend, which ignores them. Returns ``(is_key, value)``
    with the stripped value (``""`` when empty).
    """
    key, sep, value = stripped.partition("=")
    if not sep or key.strip().lower() != "import_path":
        return (False, "")
    return (True, value.strip())


def parse_cfg_import_path(cfg: bytes) -> str | None:
    """Return the stdlib directory a ``modular.cfg`` selects, if any.

    Applies the shared config rule (:func:`_split_cfg_lines`
    plus :func:`_cfg_import_path_match`): the first exact
    ``import_path`` line (case-insensitive) wins, and its value
    is the text after the first ``=``, stripped. Returns ``None``
    when no line selects a directory (no key, or an empty value),
    in which case the payload falls back to the binary-prefix
    guess (see :func:`stdlib_payload_paths`). Because the
    rewriter shares the same rule, every directory returned here
    is one the rewriter provably redirects.
    """
    for content, _ending in _split_cfg_lines(cfg):
        is_key, value = _cfg_import_path_match(
            content.decode("utf-8", "replace").strip()
        )
        if is_key:
            return value or None
    return None


def stdlib_payload_paths(
    *,
    mojo_binary: str | None,
    modular_home: str | None,
) -> tuple[tuple[str, str | None], ...]:
    """Resolve the installed stdlib payload files by logical name.

    The frontend consumes the install configuration
    (``modular.cfg`` under ``MODULAR_HOME``) and the compiled
    standard library through that file's ``import_path`` key, so
    the ``std.mojoc`` path is the configured selection -- the
    directory the live config names -- and only falls back to
    the binary-prefix guess (``lib/mojo/std.mojoc`` under the
    admitted ``mojo`` binary's install prefix) when the config
    is missing, unreadable or selects nothing. Returns
    ``(logical, path)`` pairs in identity order; ``path`` is
    ``None`` when the file is unresolvable. Callers hash these
    paths together with :func:`stdlib_payload_identities` and
    bind both halves, so snapshot boundaries re-hash the same
    install files instead of trusting the hash-time bytes.
    """
    if modular_home:
        cfg_path: str | None = os.path.join(
            modular_home, "modular.cfg"
        )
    else:
        cfg_path = None
    selection: str | None = None
    if cfg_path is not None:
        try:
            with open(cfg_path, "rb") as handle:
                cfg_bytes = handle.read()
        except OSError:
            cfg_bytes = None
        if cfg_bytes is not None:
            selection = parse_cfg_import_path(cfg_bytes)
    if selection:
        std_path: str | None = os.path.join(
            selection, "std.mojoc"
        )
    elif mojo_binary:
        prefix = os.path.dirname(
            os.path.dirname(os.path.realpath(mojo_binary))
        )
        std_path = os.path.join(prefix, "lib", "mojo", "std.mojoc")
    else:
        std_path = None
    return (("std.mojoc", std_path), ("modular.cfg", cfg_path))


def stdlib_payload_identities(
    *,
    mojo_binary: str | None,
    modular_home: str | None,
) -> tuple[str, ...]:
    """Hash the installed stdlib payload the toolchain resolves.

    Each :func:`stdlib_payload_paths` file's content hash
    joins the identity as ``"stdlib payload <name>
    <sha256>"``; the lockfile's distribution record alone
    cannot see those bytes. The ``std.mojoc`` entry hashes the
    configured selection (see :func:`stdlib_payload_paths`),
    so a swapped selection changes the identity even when the
    binary-prefix file is untouched. Missing or unreadable
    files say ``"missing"`` explicitly instead of silently
    omitting the class; logical names (never absolute paths)
    keep the entries stable across installs.
    """
    entries: list[str] = []
    for logical, path in stdlib_payload_paths(
        mojo_binary=mojo_binary, modular_home=modular_home
    ):
        digest: str | None = None
        if path is not None:
            try:
                with open(path, "rb") as handle:
                    digest = hashlib.sha256(
                        handle.read()
                    ).hexdigest()
            except OSError:
                digest = None
        entries.append(
            "stdlib payload %s %s" % (logical, digest or "missing")
        )
    return tuple(entries)


def repoint_cfg_import_path(
    cfg: bytes, staged_dir: str
) -> bytes | None:
    """Re-point a modular.cfg's import_path at the staged payload.

    The Mojo frontend resolves ``modular.cfg`` through
    ``MODULAR_HOME`` and the compiled standard library through
    that file's ``import_path`` key, so staging the payload
    bytes alone does not bind consumption: the staged config
    must name the staged directory. Applies the shared config
    rule (:func:`_split_cfg_lines` plus
    :func:`_cfg_import_path_match`), so exactly the lines the
    parser accepts are redirected: returns the captured bytes
    with every exact ``import_path`` line's non-empty value
    replaced (the key, spacing and line ending are preserved;
    nothing else changes), or ``None`` when the config carries
    no such key, in which case the caller stages it verbatim.
    Lines with an empty value stay verbatim like a missing key:
    the frontend consumes nothing either way.
    """
    found = False
    rewritten: list[bytes] = []
    for content, ending in _split_cfg_lines(cfg):
        is_key, value = _cfg_import_path_match(
            content.decode("utf-8", "replace").strip()
        )
        if is_key and value:
            prefix, _, _ = content.partition(b"=")
            content = prefix + b"= " + os.fsencode(staged_dir)
            found = True
        rewritten.append(content + ending)
    if not found:
        return None
    return b"".join(rewritten)


def _check_staged_cfg_selection(
    staged_content: bytes, stdlib_dir: str, where: str | None,
) -> None:
    """Reject a staged config that escapes the staged payload.

    Re-resolves the staged ``modular.cfg`` bytes with the same
    parser (:func:`parse_cfg_import_path`) and requires the
    selection to be exactly the staged payload directory -- or
    nothing, when the captured config selected nothing and
    staged verbatim. Anything else means a live directory
    survived redirection, so capture fails closed (``MBPF106``)
    instead of staging an unbound config the frontend would
    resolve against the live install.
    """
    staged = parse_cfg_import_path(staged_content)
    if staged is None:
        return
    if os.path.normpath(staged) != os.path.normpath(stdlib_dir):
        raise _fail(
            "staged modular.cfg selects %r instead of the staged "
            "standard library payload; rejecting instead of "
            "compiling against unbound live bytes" % (staged,),
            where,
            "rebuild without modifying the toolchain while the "
            "build runs",
        )


def _check_configured_stdlib_selection(
    seal: tuple[StdlibSealEntry, ...] | list[StdlibSealEntry],
    cfg_content: bytes,
) -> None:
    """Bind the sealed payload to the configured selection.

    Re-parses the seal-verified ``modular.cfg`` bytes (the same
    single read staging compared against the seal, so a config
    swapped between the driver's hashing and this read cannot
    split the binding) and requires the seal to cover exactly
    the directory the frontend will consume: a relative
    selection, a sealed path naming another file, a missing
    seal entry, or a selected payload the seal left unbound
    all fail closed (``MBPF106``) instead of staging one
    library while the frontend would consume another -- or
    accepting ``missing`` while the live path still resolves.
    A config selecting nothing needs no binding.
    """
    selection = parse_cfg_import_path(cfg_content)
    if not selection:
        return
    if not os.path.isabs(selection):
        raise _fail(
            "modular.cfg selects a relative standard library "
            "directory %r, which cannot be bound (build steps "
            "resolve it against the work directory, not the "
            "capture directory); rejecting instead of staging "
            "unattributed bytes" % (selection,),
            selection,
            "point the toolchain's import_path at an absolute "
            "directory",
        )
    selected = os.path.normpath(
        os.path.join(selection, "std.mojoc")
    )
    for entry in seal:
        if entry.logical != "std.mojoc":
            continue
        if entry.path is None or os.path.normpath(
            entry.path
        ) != selected:
            raise _fail(
                "modular.cfg selects standard library payload "
                "%r but the capture sealed %r; rejecting "
                "instead of staging unattributed bytes"
                % (selected, entry.path),
                selected,
                "rebuild without modifying the toolchain "
                "while the build runs",
            )
        if entry.sha256 == "missing":
            raise _fail(
                "modular.cfg selects standard library payload "
                "%r but its std.mojoc is missing or unreadable; "
                "rejecting instead of compiling against "
                "unattributed live bytes" % (selected,),
                selected,
                "repair the toolchain install or point its "
                "import_path at a directory carrying std.mojoc",
            )
        return
    raise _fail(
        "modular.cfg selects standard library payload %r but "
        "the capture sealed no std.mojoc entry; rejecting "
        "instead of compiling against unattributed live bytes"
        % (selected,),
        selected,
        "bind the configured payload before capturing",
    )


def _stage_stdlib_payload(
    seal: tuple[StdlibSealEntry, ...],
    stdlib_dir: str,
) -> tuple[tuple[StdlibSealEntry, ...], str | None]:
    """Stage the sealed payload bytes for consumption binding.

    Reads each sealed live file once and compares it against
    the seal: anything that changed, appeared, disappeared or
    became (un)readable between the driver's toolchain hashing
    and this read fails closed (``MBPF106``) instead of staging
    unattributed bytes. The seal-verified config then binds
    the sealed payload to the directory the frontend will
    consume (see :func:`_check_configured_stdlib_selection`):
    a configured selection stages its own bytes, never the
    binary-prefix guess, and an unbindable selection rejects.
    A ``modular.cfg`` selecting nothing stages verbatim when
    no ``std.mojoc`` was captured; otherwise the staged config
    is re-pointed at the staged directory (see
    :func:`repoint_cfg_import_path`) so the frontend consumes
    staged bytes for both files. Every staged config is then
    re-resolved with the same parser (see
    :func:`_check_staged_cfg_selection`): anything still
    selecting a live directory rejects instead of staging an
    unbound config. Returns the seal with staged
    paths plus the staged ``MODULAR_HOME`` replacement, or
    ``None`` when no config was captured (the frontend then
    runs exactly as without staging).
    """
    if not seal:
        return seal, None
    staged: list[StdlibSealEntry] = []
    payload_bytes: dict[str, bytes] = {}
    for entry in seal:
        if entry.path is None:
            staged.append(entry)
            continue
        try:
            with open(entry.path, "rb") as handle:
                content: bytes | None = handle.read()
        except OSError:
            content = None
        if content is None:
            if entry.sha256 != "missing":
                raise _fail(
                    "installed standard library file %r became "
                    "unreadable between toolchain hashing and "
                    "capture; rejecting instead of staging "
                    "unattributed bytes" % (entry.logical,),
                    entry.path,
                    "rebuild without modifying the toolchain "
                    "while the build runs",
                )
            staged.append(entry)
            continue
        if hashlib.sha256(content).hexdigest() != entry.sha256:
            raise _fail(
                "installed standard library file %r changed "
                "between toolchain hashing and capture; "
                "rejecting instead of staging unattributed "
                "bytes" % (entry.logical,),
                entry.path,
                "rebuild without modifying the toolchain "
                "while the build runs",
            )
        payload_bytes[entry.logical] = content
        staged.append(entry)
    if not payload_bytes:
        return tuple(staged), None
    cfg_content = payload_bytes.get("modular.cfg")
    if cfg_content is not None:
        _check_configured_stdlib_selection(staged, cfg_content)
    try:
        os.makedirs(stdlib_dir, exist_ok=True)
    except OSError as exc:
        raise _fail(
            "cannot stage standard library payload %r: %s"
            % (stdlib_dir, exc),
            stdlib_dir,
            "use a writable work_parent directory with free space",
        ) from None
    std_staged = "std.mojoc" in payload_bytes
    final: list[StdlibSealEntry] = []
    for entry in staged:
        content = payload_bytes.get(entry.logical)
        if content is None:
            final.append(entry)
            continue
        staged_content = content
        if entry.logical == "modular.cfg":
            if std_staged:
                rewritten = repoint_cfg_import_path(
                    content, stdlib_dir
                )
                if rewritten is not None:
                    staged_content = rewritten
            _check_staged_cfg_selection(
                staged_content, stdlib_dir,
                entry.path or entry.logical,
            )
        staged_path = os.path.join(stdlib_dir, entry.logical)
        _write_staged(staged_path, staged_content)
        final.append(
            StdlibSealEntry(
                logical=entry.logical,
                path=entry.path,
                sha256=entry.sha256,
                staged=staged_path,
                staged_sha256=hashlib.sha256(
                    staged_content
                ).hexdigest(),
            )
        )
    consumption_home = (
        stdlib_dir if "modular.cfg" in payload_bytes else None
    )
    return tuple(final), consumption_home


def _seal_stdlib_payload(
    toolchain: ToolchainInputs,
) -> tuple[StdlibSealEntry, ...]:
    """Pair hashed payload identities with their install paths.

    The build driver binds both halves; captures binding
    identities without paths skip re-verification (nothing
    records where to re-read). A bound path list that does
    not line up with the identities fails closed instead of
    re-verifying the wrong files. Staged consumption paths are
    filled in later by :func:`_stage_stdlib_payload`.
    """
    paths = toolchain.stdlib_payload_paths
    if not paths:
        return ()
    payload = toolchain.stdlib_payload
    if len(paths) != len(payload):
        raise _fail(
            "stdlib payload binding carries %d paths for %d "
            "identities; rejecting instead of re-verifying "
            "the wrong files" % (len(paths), len(payload)),
            None,
            "bind one install path per payload identity",
        )
    seal: list[StdlibSealEntry] = []
    for (logical, path), entry in zip(paths, payload):
        parts = entry.split(" ")
        if (
            len(parts) != 4
            or parts[0] != "stdlib"
            or parts[1] != "payload"
            or parts[2] != logical
        ):
            raise _fail(
                "stdlib payload identity %r does not match "
                "its bound path; rejecting instead of "
                "re-verifying the wrong file" % (entry,),
                path,
                "bind one install path per payload identity",
            )
        seal.append(
            StdlibSealEntry(
                logical=logical, path=path, sha256=parts[3]
            )
        )
    return tuple(seal)


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


def _remap_capture_text(
    text: str,
    pairs: tuple[tuple[str, str], ...],
) -> str:
    """Rewrite staged-root prefixes in free text to origins."""
    rewritten = text
    for staged, origin in pairs:
        rewritten = rewritten.replace(staged, origin)
    return rewritten


def _remap_capture_diagnostic(
    diagnostic: Diagnostic,
    pairs: tuple[tuple[str, str], ...],
) -> Diagnostic:
    """Rewrite staged paths in a capture diagnostic to origins.

    Capture-time checks (notably source-grant validation) see
    the staged copies; users must see the project paths they
    own instead, since cleanup removes the staged root.
    """
    location = diagnostic.location
    if location is not None:
        location = _remap_capture_text(location, pairs)
    return Diagnostic(
        code=diagnostic.code,
        stage=diagnostic.stage,
        severity=diagnostic.severity,
        explanation=_remap_capture_text(
            diagnostic.explanation, pairs
        ),
        location=location,
        remedy=diagnostic.remedy,
    )


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
    tools. ``spawn_environment`` pins the raw (verbatim)
    influential environment every pipeline step spawns under,
    so the recorded environment IS the spawn environment.
    ``spawn_unset`` pins the base names absent at capture, so
    a variable added after capture is withheld from spawn
    exactly like a recorded value is enforced.
    ``stdlib_seal`` pins the install paths behind the hashed
    payload identities so every boundary re-hashes them, plus
    the staged consumption copies the frontend reads (see
    ``stdlib_consumption_home``). ``root``/``project_root``/
    ``sdk_root``, ``spawn_environment``/``spawn_unset``/
    ``stdlib_seal``/``stdlib_consumption_home`` and every
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
    spawn_environment: tuple[tuple[str, str], ...] = field(
        default=(), compare=False
    )
    spawn_unset: tuple[str, ...] = field(
        default=(), compare=False
    )
    stdlib_seal: tuple[StdlibSealEntry, ...] = field(
        default=(), compare=False
    )
    stdlib_consumption_home: str | None = field(
        default=None, compare=False
    )
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
        object.__setattr__(
            self, "spawn_environment", tuple(self.spawn_environment)
        )
        object.__setattr__(
            self, "spawn_unset", tuple(self.spawn_unset)
        )
        object.__setattr__(
            self, "stdlib_seal", tuple(self.stdlib_seal)
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
        trees, then re-hashes the sealed stdlib payload files
        (both the live install files and the staged consumption
        copies): changed, missing or newly appeared files raise
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
        for entry in self.stdlib_seal:
            observed_digest: str | None = None
            if entry.path is not None:
                try:
                    with open(entry.path, "rb") as handle:
                        observed_digest = hashlib.sha256(
                            handle.read()
                        ).hexdigest()
                except OSError:
                    observed_digest = None
            if (observed_digest or "missing") != entry.sha256:
                raise _fail(
                    "installed standard library file %r changed "
                    "after capture; rejecting instead of "
                    "attributing the clean identity to swapped "
                    "bytes" % (entry.logical,),
                    entry.path or entry.logical,
                    "rebuild without modifying the toolchain "
                    "while the build runs",
                )
            if entry.staged is None:
                continue
            try:
                with open(entry.staged, "rb") as handle:
                    staged_digest: str | None = hashlib.sha256(
                        handle.read()
                    ).hexdigest()
            except OSError:
                staged_digest = None
            if staged_digest is None:
                raise _fail(
                    "staged standard library file %r became "
                    "unreadable after capture; rejecting instead "
                    "of compiling without it" % (entry.logical,),
                    entry.path or entry.logical,
                    "rebuild without modifying inputs while "
                    "the build runs",
                )
            if staged_digest != entry.staged_sha256:
                raise _fail(
                    "staged standard library file %r changed "
                    "after capture; rejecting instead of "
                    "compiling unattributed bytes"
                    % (entry.logical,),
                    entry.path or entry.logical,
                    "rebuild without modifying inputs while "
                    "the build runs",
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
    record plus the lockfile bytes themselves plus the
    installed payload files the admitted toolchain resolves
    (see :func:`stdlib_payload_identities`); a capture
    without a class says ``unbound`` explicitly instead of
    silently omitting it.
    """
    if not toolchain.distribution and toolchain.lockfile_sha256 is None:
        identities: list[str] = [
            "stdlib distribution unbound no-toolchain-binding"
        ]
    else:
        identities = []
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
    if toolchain.stdlib_payload:
        identities.extend(toolchain.stdlib_payload)
    else:
        identities.append(
            "stdlib payload unbound no-payload-binding"
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
    pinned_environment: PinnedEnvironment | None = None,
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

    ``pinned_environment`` passes the build driver's single
    ambient pin through verbatim (no second ambient read), so
    payload resolution, recording and spawn share one read;
    ``environment`` is the legacy test seam merged over a fresh
    ambient read. Passing both is a ``TypeError``.

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
    if environment is not None and pinned_environment is not None:
        raise TypeError(
            "pass either environment or pinned_environment, not both"
        )
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
            environment, pinned_environment,
        )
    except BaseException:
        # Every exit path retires the capture root -- expected
        # capture/grant failures, unexpected OSErrors, and
        # interruptions alike -- so a failed capture stages
        # nothing usable and leaves no residue behind.
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
    pinned_environment: PinnedEnvironment | None,
) -> BuildSnapshot:
    # Every origin file is read exactly once; the returned bytes
    # are staged, hashed and parsed from that single read, so a
    # concurrent modification can neither split the capture nor
    # slip an unscanned import past discovery. Likewise the
    # influential environment is pinned once -- recorded, spawn
    # and absent names from a single ambient read -- so the
    # recorded environment IS the spawn environment in every
    # direction (changed, added or removed after capture). The
    # build driver passes its pin through (no second ambient
    # read); direct callers take one fresh read here.
    if pinned_environment is not None:
        pinned = pinned_environment
    else:
        pinned = capture_pinned_environment(environment)
    stdlib_seal = _seal_stdlib_payload(toolchain)
    stdlib_seal, consumption_home = _stage_stdlib_payload(
        stdlib_seal, os.path.join(root, "stdlib")
    )
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
        if known is not None and known.logical == logical:
            return known
        # A distinct logical path stages even when it shares
        # bytes with a staged file (a symlinked helper): the
        # frontend resolves lexical module names, so every
        # admitted name needs its own staged copy.
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
    # the staged set. The scanned set keys on staged paths, not
    # origin realpaths: aliases stage separately, so every
    # separately captured body is scanned even when the shared
    # file changed between the alias reads.
    import_records: dict[str, CapturedFile] = {}
    program_logicals = {
        item.logical for item in staged_programs
    }
    sdk_hit = False
    queue = list(staged_programs)
    scanned: set[str] = set()
    while queue:
        current = queue.pop(0)
        identity = os.path.normpath(current.staged)
        if identity in scanned:
            continue
        scanned.add(identity)
        try:
            with open(current.staged, "rb") as handle:
                staged_bytes = handle.read()
        except OSError as exc:
            raise _fail(
                "captured build input %r became unreadable "
                "during capture: %s" % (current.origin, exc),
                current.origin,
                "rebuild without modifying inputs while the "
                "build runs",
            ) from None
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
                if record.logical in program_logicals:
                    continue
                if record.logical not in import_records:
                    import_records[record.logical] = record
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

    try:
        grants = validate_source_grants(
            manifest.artifact.source_license,
            [item.staged for item in staged_programs],
            [item.staged for item in staged_sdk],
            project_dir=project_root,
            imported_sources=[
                item.staged for item in import_records.values()
            ],
        )
    except InspectionError as exc:
        # The gate saw staged copies; report the origins the
        # user owns (same pairs
        # :meth:`BuildSnapshot.display_replacements` will
        # publish once the snapshot exists).
        pairs = (
            (
                os.path.normpath(project_root),
                os.path.normpath(project_dir),
            ),
        )
        if sdk.sdk_dir:
            pairs = pairs + ((
                os.path.normpath(sdk_root),
                os.path.normpath(sdk.sdk_dir),
            ),)
        raise InspectionError(
            _remap_capture_diagnostic(exc.diagnostic, pairs)
        ) from None
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
        environment=pinned.recorded,
        spawn_environment=pinned.spawn,
        spawn_unset=pinned.unset,
        stdlib_seal=stdlib_seal,
        stdlib_consumption_home=consumption_home,
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
