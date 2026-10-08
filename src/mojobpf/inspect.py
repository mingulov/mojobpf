# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Final-object inspection and license-declaration checks.

:func:`inspect_object` reads a built object file and reports three
kinds of results: structural findings (malformed or inconsistent
object bytes), unsupported-feature findings (well-formed bytes outside
the named target profile), and observations (neutral facts such as
section names, license payloads and observed helper IDs). Inspection
describes bytes; it never claims the kernel will accept an object.

License handling separates three surfaces that must not be confused:

* source grants: the SPDX expression declared by the manifest, checked
  against the SPDX headers of the program sources;
* dependency terms: SDK, standard-library and third-party grants,
  recorded separately with hashes and never flattened into one
  convenient expression;
* kernel declaration: the exact bytes of the ELF ``license`` section,
  an explicit loader-facing string that affects kernel API
  eligibility but creates no license grant.

:func:`validate_source_grants` checks the first two surfaces before
compilation. :func:`validate_declaration_pair` checks the declared
``(source, kernel)`` pair against a versioned mapping table that
currently qualifies exactly one pair; every other pair -- including
every GPL-shaped pair -- is rejected, and a compound (``AND``/``OR``)
source expression is rejected as an unsupported mixed arrangement
rather than flattened. :func:`check_object_license` compares the
final ELF payload against the validated declaration byte for byte,
deriving the expected bytes from the validated value without
substitution. :func:`verify_object` runs the full pre-publication
gate: inspection plus pair, requirement and payload checks.

Negatives enforced here, each with a stable code:

* Apache sources paired with a ``GPL`` kernel string: ``MBPF704``.
* dual-licensed sources paired with the literal SPDX expression as
  the kernel string: ``MBPF703`` (compound source) or ``MBPF704``.
* a GPL-only helper under an Apache declaration: the supported
  profile holds no GPL-restricted helper, and the helper registry
  records the GPL-only witness (ID 35), so the license preflight
  names it with ``MBPF709`` while any unrecorded helper ID,
  unknown program type or kfunc use fails closed with ``MBPF706``.
* wrong ELF bytes (missing, extra, conflicting or unterminated
  license payload, or bytes differing from the validated
  declaration): ``MBPF403`` at inspection, ``MBPF705`` at the
  declaration gate.

New diagnostic codes (all ``error``):

* ``MBPF401``: the object cannot be read or is not a 64-bit
  little-endian ELF object.
* ``MBPF402``: malformed ELF internals (headers, sections, symbols).
* ``MBPF403``: missing or malformed license payload, or no
  executable section.
* ``MBPF404``: unknown external symbols (undefined names outside the
  admitted set, which is empty for the supported profile).
* ``MBPF405``: inconsistent object metadata (relocations, code
  sizes, map/BTF pairing).
* ``MBPF406``: machine type, object type or program section outside
  the named profile.
* ``MBPF407``: unsupported code or metadata feature (non-plain
  calls, unknown helper IDs, CO-RE-style metadata, or
  relocation records outside the pinned CO-RE shapes).
* ``MBPF701``: malformed SPDX expression.
* ``MBPF702``: a program source header disagrees with the declared
  source grant.
* ``MBPF703``: unsupported mixed-license arrangement.
* ``MBPF704``: the ``(source, kernel)`` declaration pair is not in
  the versioned mapping, the kernel string is malformed, or the
  program requires GPL coverage no mapped pair provides.
* ``MBPF705``: the ELF license payload is ambiguous or differs from
  the validated declaration.
* ``MBPF706``: a licensing requirement cannot be established
  (unrecorded helper ID, unknown program type, kfunc use).
* ``MBPF709``: a recorded GPL-only helper is used under a kernel
  declaration the kernel does not recognize as GPL-compatible.
* ``MBPF707``: a source file carries no SPDX header, or a license
  file cannot be read.

New stages: ``inspect.object`` (structural and profile findings),
``inspect.license`` (grant, pair, requirement and payload checks).

Standard library only.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
from dataclasses import dataclass

from .diagnostics import Diagnostic, MojobpfError, SEVERITY_ERROR
from .helpers import lookup_helper
from .manifest import TargetProfile, lookup_profile

INSPECTION_SCHEMA_VERSION = 1

# Version of the (source_license, kernel_license) mapping below. A new
# pair needs a reviewed mapping entry, emitter support and a version
# bump together; string equality between an SPDX expression and a
# kernel declaration is never the matching rule.
LICENSE_MAPPING_VERSION = 1

# The only qualified declaration pair for the current route: both the
# source grant and the kernel-facing declaration are the project
# default, and the emitter writes exactly these bytes. Every other
# pair -- including MIT, GPL and dual-licensed rows -- stays rejected
# until its own reviewed mapping lands (OTHERS-REJECTED rule).
LICENSE_PAIRS = (
    (
        "Apache-2.0 WITH LLVM-exception",
        "Apache-2.0 WITH LLVM-exception",
    ),
)

# Kernel-recognized GPL-compatible license declarations, per the
# kernel licensing documentation. Membership here answers only
# whether the kernel treats a declaration as GPL-compatible; it never
# approves a pair (that is the mapping table's job) and never creates
# a grant.
GPL_RECOGNIZED_DECLARATIONS = (
    "GPL",
    "GPL v2",
    "GPL and additional rights",
    "Dual BSD/GPL",
    "Dual MIT/GPL",
    "Dual MPL/GPL",
)

STAGE_INSPECT_OBJECT = "inspect.object"
STAGE_INSPECT_LICENSE = "inspect.license"

# Per-profile GPL-restricted helpers and program types. Both sets are
# empty for the supported profile: helpers 1, 2, 3, 5, 8, 14, and
# 130 and the XDP and tracepoint programs need no GPL-compatible
# declaration. Unknown IDs never reach these sets; they fail
# closed with MBPF706 first.
# Per-profile GPL-restricted sets. All supported profiles admit no
# GPL-only helper or program type (the minimal CO-RE slice uses the
# existing lookup helper only; the hash slice uses the existing
# lookup/update/delete helpers only; the reservation slice uses
# the non-GPL ring-buffer helpers 131, 132, and 133 only; the
# uprobe slice uses the existing lookup/update helpers only), so
# all sets stay empty; a profile without an entry here fails
# closed at the license preflight.
_GPL_ONLY_HELPERS = {
    "linux-bpfel-v3": frozenset(),
    "linux-bpfel-v3-core": frozenset(),
    "linux-bpfel-v3-hash": frozenset(),
    "linux-bpfel-v3-reserve": frozenset(),
    "linux-bpfel-v3-subprog": frozenset(),
    "linux-bpfel-v3-uprobe": frozenset(),
}
_GPL_ONLY_PROGRAMS = {
    "linux-bpfel-v3": frozenset(),
    "linux-bpfel-v3-core": frozenset(),
    "linux-bpfel-v3-hash": frozenset(),
    "linux-bpfel-v3-reserve": frozenset(),
    "linux-bpfel-v3-subprog": frozenset(),
    "linux-bpfel-v3-uprobe": frozenset(),
}

EM_BPF = 247
ET_REL = 1
SHF_EXECINSTR = 0x4
SHT_SYMTAB = 2
SHT_RELA = 4
SHT_REL = 9
SHT_NOBITS = 8
SHN_UNDEF = 0
STT_FUNC = 2
# Relocation types the pinned backend emits across the supported
# shapes (surveyed over classifier, array, per-CPU, hash, combined,
# tracepoint, event, reserve, core, subprogram and uprobe objects):
# 1 in program sections (.relxdp/.reltracepoint/.reluprobe), 2 in
# frame/debug sections, 3 in .rel.debug_info, 4 in .rel.BTF and
# .rel.BTF.ext, 10 at subprogram call sites. Any other relocation
# type fails closed here (MBPF405).
_ADMITTED_RELOC_TYPES = frozenset({1, 2, 3, 4, 10})
BPF_OP_CALL = 0x85
BPF_OP_PSEUDO_CALL = 0x8D
BPF_OP_LD_IMM64 = 0x18

SPDX_TAG = "SPDX-License-Identifier:"
HEADER_SCAN_LINES = 10

_LINK_STAGES = frozenset({"build.link", "adapter.link", "link"})
_LINK_TOOLS = frozenset({"ld", "ld.lld", "ld.bfd", "llvm-link", "bpf-linker"})

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+\-]*$")
_RESERVED_WORDS = frozenset({"AND", "OR", "WITH"})

STDLIB_NOTE = (
    "Mojo standard-library terms ship with the toolchain release "
    "named in the build provenance; see the toolchain report and "
    "notices. No file hash is claimed here because the standard "
    "library is resolved inside the toolchain, not from project "
    "files."
)


class InspectionError(MojobpfError):
    """An inspection or license check failed with a stable code."""


def _fail(code: str, stage: str, explanation: str,
          location: str | None, remedy: str) -> InspectionError:
    return InspectionError(
        Diagnostic(
            code=code,
            stage=stage,
            severity=SEVERITY_ERROR,
            explanation=explanation,
            location=location,
            remedy=remedy,
        )
    )


@dataclass(frozen=True)
class SpdxExpression:
    """A parsed SPDX license expression.

    ``text`` is the normalized single-space form. ``licenses`` holds
    the license identifiers (``WITH`` exceptions are tracked
    separately in ``exceptions``). ``compound`` is true when the
    expression joins grants with ``AND``/``OR`` -- an arrangement,
    not one grant.
    """

    text: str
    licenses: frozenset[str]
    exceptions: frozenset[str]
    compound: bool


def _spdx_tokens(text: str) -> list[str]:
    spaced = text.replace("(", " ( ").replace(")", " ) ")
    return spaced.split()


def _parse_spdx_primary(tokens: list[str], where: str) -> SpdxExpression:
    if not tokens:
        raise _fail(
            "MBPF701",
            STAGE_INSPECT_LICENSE,
            "malformed SPDX expression %r: unexpected end" % (where,),
            None,
            "use '<license>' or '<license> WITH <exception>', "
            "joined with AND/OR",
        )
    token = tokens.pop(0)
    if token == "(":
        inner = _parse_spdx_or(tokens, where)
        if not tokens or tokens.pop(0) != ")":
            raise _fail(
                "MBPF701",
                STAGE_INSPECT_LICENSE,
                "malformed SPDX expression %r: unbalanced parenthesis"
                % (where,),
                None,
                "balance the parentheses",
            )
        return inner
    if token in _RESERVED_WORDS or token == ")":
        raise _fail(
            "MBPF701",
            STAGE_INSPECT_LICENSE,
            "malformed SPDX expression %r: unexpected %r" % (where, token),
            None,
            "use '<license>' or '<license> WITH <exception>', "
            "joined with AND/OR",
        )
    if not _ID_RE.match(token):
        raise _fail(
            "MBPF701",
            STAGE_INSPECT_LICENSE,
            "malformed SPDX expression %r: bad identifier %r"
            % (where, token),
            None,
            "use SPDX license identifiers",
        )
    license_id = token
    exceptions: set[str] = set()
    if tokens[:1] == ["WITH"]:
        tokens.pop(0)
        if not tokens:
            raise _fail(
                "MBPF701",
                STAGE_INSPECT_LICENSE,
                "malformed SPDX expression %r: WITH without exception"
                % (where,),
                None,
                "name the exception after WITH",
            )
        excused = tokens.pop(0)
        if excused in _RESERVED_WORDS or not _ID_RE.match(excused):
            raise _fail(
                "MBPF701",
                STAGE_INSPECT_LICENSE,
                "malformed SPDX expression %r: bad exception %r"
                % (where, excused),
                None,
                "name an SPDX exception after WITH",
            )
        exceptions.add(excused)
    text = license_id
    if exceptions:
        text += " WITH " + sorted(exceptions)[0]
    return SpdxExpression(
        text=text,
        licenses=frozenset({license_id}),
        exceptions=frozenset(exceptions),
        compound=False,
    )


def _parse_spdx_or(tokens: list[str], where: str) -> SpdxExpression:
    left = _parse_spdx_primary(tokens, where)
    parts = [left.text]
    licenses = set(left.licenses)
    exceptions = set(left.exceptions)
    compound = False
    while tokens[:1] in (["AND"], ["OR"]):
        operator = tokens.pop(0)
        compound = True
        right = _parse_spdx_primary(tokens, where)
        parts.append(operator)
        parts.append(right.text)
        licenses.update(right.licenses)
        exceptions.update(right.exceptions)
        compound = compound or right.compound
    return SpdxExpression(
        text=" ".join(parts),
        licenses=frozenset(licenses),
        exceptions=frozenset(exceptions),
        compound=compound,
    )


def parse_spdx_expression(text: object) -> SpdxExpression:
    """Parse ``text`` as an SPDX license expression.

    Accepts license identifiers with optional ``WITH`` exceptions,
    joined with ``AND``/``OR`` and parentheses. Raises
    :class:`InspectionError` (``MBPF701``) on malformed input. This
    checks syntax only; whether the parsed grant is usable is decided
    by the grant and pair checks, never here.
    """
    if not isinstance(text, str) or not text.strip():
        raise _fail(
            "MBPF701",
            STAGE_INSPECT_LICENSE,
            "malformed SPDX expression %r: not a non-empty string"
            % (text,),
            None,
            "declare the source grant as an SPDX expression",
        )
    tokens = _spdx_tokens(text.strip())
    parsed = _parse_spdx_or(tokens, text)
    if tokens:
        raise _fail(
            "MBPF701",
            STAGE_INSPECT_LICENSE,
            "malformed SPDX expression %r: trailing %r" % (text, tokens[0]),
            None,
            "use '<license>' or '<license> WITH <exception>', "
            "joined with AND/OR",
        )
    return parsed


@dataclass(frozen=True)
class ExtraGrant:
    """A caller-attributed grant for a license text or vendored file.

    Full license texts carry no machine-readable header, so the
    caller attributes their grant explicitly in ``spdx``. ``None``
    extracts the grant from the file's SPDX header instead. The
    attributed grant is compared against the declared source grant;
    attribution detects contradictions but cannot establish
    ownership.
    """

    name: str
    path: str
    spdx: str | None


@dataclass(frozen=True)
class DependencyGrant:
    """One recorded source or dependency grant with its file hash."""

    name: str
    path: str
    spdx: str
    sha256: str
    size: int

    def to_dict(self) -> dict[str, str | int]:
        """Return a stable plain-data mapping of this grant."""
        return {
            "name": self.name,
            "path": self.path,
            "spdx": self.spdx,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True)
class SourceGrantRecord:
    """Validated source and dependency grants for one build.

    ``programs`` holds the project-authored program sources, ``sdk``
    the incorporated SDK files, and ``extra`` the caller-attributed
    license texts and third-party files, each with its own grant and
    hash. ``stdlib_note`` explains the standard-library attribution,
    which is toolchain-scoped rather than file-scoped.
    """

    source_license: str
    programs: tuple[DependencyGrant, ...]
    sdk: tuple[DependencyGrant, ...]
    extra: tuple[DependencyGrant, ...]
    stdlib_note: str

    def to_dict(self) -> dict:
        """Return a stable plain-data mapping of this record."""
        return {
            "source_license": self.source_license,
            "programs": [grant.to_dict() for grant in self.programs],
            "sdk": [grant.to_dict() for grant in self.sdk],
            "extra": [grant.to_dict() for grant in self.extra],
            "stdlib_note": self.stdlib_note,
        }


def _stable_grant_path(path: str, project_dir: str | None) -> str:
    if project_dir is not None:
        try:
            relative = os.path.relpath(path, project_dir)
        except ValueError:
            relative = ""
        if relative and not relative.startswith(".." + os.sep):
            if relative != ".." and not os.path.isabs(relative):
                return relative.replace(os.sep, "/")
    return os.path.basename(path)


def _read_grant_file(path: str) -> tuple[bytes, str]:
    try:
        with open(path, "rb") as handle:
            content = handle.read()
    except OSError as exc:
        raise _fail(
            "MBPF707",
            STAGE_INSPECT_LICENSE,
            "cannot read licensed file %r: %s" % (path, exc),
            path,
            "check the file path and permissions",
        ) from None
    return content, hashlib.sha256(content).hexdigest()


def _header_grants(content: bytes, path: str) -> tuple[str, ...]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _fail(
            "MBPF707",
            STAGE_INSPECT_LICENSE,
            "licensed file %r is not UTF-8: %s" % (path, exc),
            path,
            "keep licensed sources in UTF-8",
        ) from None
    found: list[str] = []
    for line in text.splitlines()[:HEADER_SCAN_LINES]:
        index = line.find(SPDX_TAG)
        if index < 0:
            continue
        candidate = line[index + len(SPDX_TAG):].strip()
        for closer in ("-->", "*/"):
            if candidate.endswith(closer):
                candidate = candidate[: -len(closer)].strip()
        if candidate and candidate not in found:
            found.append(candidate)
    return tuple(found)


def _grant_record(name: str, path: str, spdx: str, content: bytes,
                  digest: str, project_dir: str | None) -> DependencyGrant:
    return DependencyGrant(
        name=name,
        path=_stable_grant_path(path, project_dir),
        spdx=spdx,
        sha256=digest,
        size=len(content),
    )


def validate_source_grants(
    source_license: str,
    program_sources: list[str] | tuple[str, ...],
    sdk_sources: list[str] | tuple[str, ...] = (),
    extra_grants: list[ExtraGrant] | tuple[ExtraGrant, ...] = (),
    project_dir: str | None = None,
) -> SourceGrantRecord:
    """Validate program and dependency grants against the declaration.

    Parses ``source_license`` as SPDX, then requires every program
    source header, every SDK file header and every attributed extra
    grant to name exactly that grant. Distinct grants across files
    are rejected as unsupported mixed arrangements (``MBPF703``)
    rather than flattened; a header disagreeing with the declaration
    is ``MBPF702``; missing headers and unreadable files are
    ``MBPF707``. Returns the recorded grants with hashes.
    """
    declared = parse_spdx_expression(source_license)
    if declared.compound:
        raise _fail(
            "MBPF703",
            STAGE_INSPECT_LICENSE,
            "unsupported mixed-license arrangement %r: compound source "
            "expressions are not flattened" % (declared.text,),
            None,
            "declare one homogeneous source grant",
        )
    wanted = declared.text
    programs: list[DependencyGrant] = []
    for path in program_sources:
        content, digest = _read_grant_file(path)
        headers = _header_grants(content, path)
        if not headers:
            raise _fail(
                "MBPF707",
                STAGE_INSPECT_LICENSE,
                "program source %r carries no SPDX header" % (path,),
                path,
                "add an '%s ...' header line" % SPDX_TAG,
            )
        if len(headers) > 1:
            raise _fail(
                "MBPF703",
                STAGE_INSPECT_LICENSE,
                "unsupported mixed-license arrangement in %r: %r"
                % (path, list(headers)),
                path,
                "keep one SPDX grant per program source",
            )
        header = parse_spdx_expression(headers[0])
        if header.text != wanted:
            raise _fail(
                "MBPF702",
                STAGE_INSPECT_LICENSE,
                "program source %r grants %r, declared source grant is "
                "%r" % (path, header.text, wanted),
                path,
                "align the header with the declared source grant",
            )
        programs.append(
            _grant_record(
                "program source", path, header.text, content, digest,
                project_dir,
            )
        )
    sdk: list[DependencyGrant] = []
    for path in sdk_sources:
        content, digest = _read_grant_file(path)
        headers = _header_grants(content, path)
        if not headers:
            raise _fail(
                "MBPF707",
                STAGE_INSPECT_LICENSE,
                "SDK file %r carries no SPDX header" % (path,),
                path,
                "record the SDK file's grant explicitly",
            )
        if len(headers) > 1:
            raise _fail(
                "MBPF703",
                STAGE_INSPECT_LICENSE,
                "unsupported mixed-license arrangement in %r: %r"
                % (path, list(headers)),
                path,
                "keep one SPDX grant per SDK file",
            )
        header = parse_spdx_expression(headers[0])
        if header.text != wanted:
            raise _fail(
                "MBPF703",
                STAGE_INSPECT_LICENSE,
                "unsupported mixed-license arrangement: SDK file %r "
                "grants %r, program sources grant %r"
                % (path, header.text, wanted),
                path,
                "use SDK files under the declared source grant",
            )
        sdk.append(
            _grant_record(
                "SDK file", path, header.text, content, digest,
                project_dir,
            )
        )
    extra: list[DependencyGrant] = []
    for grant in extra_grants:
        if not isinstance(grant, ExtraGrant):
            raise TypeError("extra_grants must hold ExtraGrant items")
        content, digest = _read_grant_file(grant.path)
        if not content:
            raise _fail(
                "MBPF707",
                STAGE_INSPECT_LICENSE,
                "license file %r (%s) is empty" % (grant.path, grant.name),
                grant.path,
                "ship the full license text",
            )
        if grant.spdx is None:
            headers = _header_grants(content, grant.path)
            if not headers:
                raise _fail(
                    "MBPF707",
                    STAGE_INSPECT_LICENSE,
                    "file %r (%s) carries no SPDX header"
                    % (grant.path, grant.name),
                    grant.path,
                    "attribute its grant explicitly or add a header",
                )
            if len(headers) > 1:
                raise _fail(
                    "MBPF703",
                    STAGE_INSPECT_LICENSE,
                    "unsupported mixed-license arrangement in %r: %r"
                    % (grant.path, list(headers)),
                    grant.path,
                    "keep one SPDX grant per file",
                )
            claimed = parse_spdx_expression(headers[0]).text
        else:
            claimed = parse_spdx_expression(grant.spdx).text
        if claimed != wanted:
            raise _fail(
                "MBPF703",
                STAGE_INSPECT_LICENSE,
                "unsupported mixed-license arrangement: %s %r grants "
                "%r, program sources grant %r"
                % (grant.name, grant.path, claimed, wanted),
                grant.path,
                "record a homogeneous grant set or seek a reviewed "
                "mapping for the combination",
            )
        extra.append(
            _grant_record(
                grant.name, grant.path, claimed, content, digest,
                project_dir,
            )
        )
    return SourceGrantRecord(
        source_license=wanted,
        programs=tuple(programs),
        sdk=tuple(sdk),
        extra=tuple(extra),
        stdlib_note=STDLIB_NOTE,
    )


@dataclass(frozen=True)
class ValidatedDeclaration:
    """A declaration pair accepted by the versioned mapping.

    ``expected_license_bytes`` derives the exact ELF payload from the
    validated kernel string (ASCII encoding plus the NUL terminator)
    without substitution: the emitter must write these bytes
    unchanged.
    """

    source_license: str
    kernel_license: str
    mapping_version: int

    @property
    def expected_license_bytes(self) -> bytes:
        """Return the exact required ``license`` section bytes."""
        return self.kernel_license.encode("ascii") + b"\x00"


def _resolve_profile(profile: str | TargetProfile) -> TargetProfile:
    if isinstance(profile, TargetProfile):
        return profile
    if isinstance(profile, str):
        return lookup_profile(profile)
    raise TypeError("profile must be an identifier or a TargetProfile")


def validate_declaration_pair(
    source_license: str,
    kernel_license: str,
    *,
    requires_gpl: bool = False,
) -> ValidatedDeclaration:
    """Validate a ``(source, kernel)`` declaration pair for one route.

    The source side must parse as SPDX and must not be compound;
    the kernel side must be a non-empty ASCII string without NUL
    bytes (kernel declarations are loader strings, not SPDX, so the
    check is structural, not SPDX-shaped); the pair must appear in
    the versioned mapping; and a GPL requirement must be covered by
    a mapped GPL pair. Only the qualified pair validates today, so
    every GPL-shaped pair -- however the requirement arose -- fails
    with ``MBPF704``. Check order is fixed and the first failure
    wins: source syntax (``MBPF701``), compound source
    (``MBPF703``), kernel-string shape and pair membership
    (``MBPF704``), GPL coverage (``MBPF704``).
    """
    declared = parse_spdx_expression(source_license)
    if declared.compound:
        raise _fail(
            "MBPF703",
            STAGE_INSPECT_LICENSE,
            "unsupported mixed-license arrangement %r: compound source "
            "expressions are not flattened" % (declared.text,),
            None,
            "declare one homogeneous source grant",
        )
    if not isinstance(kernel_license, str):
        raise TypeError("kernel_license must be a string")
    if not kernel_license:
        raise _fail(
            "MBPF704",
            STAGE_INSPECT_LICENSE,
            "declaration pair %r is not in license mapping version %d: "
            "the kernel declaration must not be empty"
            % ((declared.text, kernel_license), LICENSE_MAPPING_VERSION),
            None,
            "declare the exact kernel license string",
        )
    if "\x00" in kernel_license:
        raise _fail(
            "MBPF704",
            STAGE_INSPECT_LICENSE,
            "declaration pair %r is not in license mapping version %d: "
            "the kernel declaration must not embed NUL bytes"
            % ((declared.text, kernel_license), LICENSE_MAPPING_VERSION),
            None,
            "declare the exact kernel license string",
        )
    try:
        kernel_license.encode("ascii")
    except UnicodeEncodeError:
        raise _fail(
            "MBPF704",
            STAGE_INSPECT_LICENSE,
            "declaration pair %r is not in license mapping version %d: "
            "the kernel declaration must be ASCII"
            % ((declared.text, kernel_license), LICENSE_MAPPING_VERSION),
            None,
            "declare the exact kernel license string",
        ) from None
    if (declared.text, kernel_license) not in LICENSE_PAIRS:
        raise _fail(
            "MBPF704",
            STAGE_INSPECT_LICENSE,
            "declaration pair %r is not in license mapping version %d; "
            "only %r is qualified"
            % (
                (declared.text, kernel_license),
                LICENSE_MAPPING_VERSION,
                list(LICENSE_PAIRS),
            ),
            None,
            "use the qualified pair or seek a reviewed mapping",
        )
    if requires_gpl:
        recognized = kernel_recognizes_as_gpl(kernel_license)
        raise _fail(
            "MBPF704",
            STAGE_INSPECT_LICENSE,
            "program requires a GPL-compatible declaration but pair %r "
            "provides none (kernel-recognized: %s)"
            % ((declared.text, kernel_license), recognized),
            None,
            "restrict the program to non-GPL facilities",
        )
    return ValidatedDeclaration(
        source_license=declared.text,
        kernel_license=kernel_license,
        mapping_version=LICENSE_MAPPING_VERSION,
    )


def kernel_recognizes_as_gpl(declaration: str) -> bool:
    """Tell whether the kernel treats ``declaration`` as GPL-compatible.

    This answers only the kernel-recognition half of the GPL rule;
    whether a program may use GPL-restricted facilities additionally
    needs a mapped pair and supporting grants.
    """
    return declaration in GPL_RECOGNIZED_DECLARATIONS


def requires_gpl(
    helper_ids: list[int] | tuple[int, ...],
    program_types: list[str] | tuple[str, ...],
    kfuncs: list[str] | tuple[str, ...],
    profile: str | TargetProfile,
) -> bool:
    """Tell whether a program needs a GPL-compatible declaration.

    Unrecorded helper IDs, unknown program types, any kfunc use
    and a profile with no recorded GPL-restriction entry fail
    closed with ``MBPF706``: requirements that cannot be
    established are never assumed satisfiable. A helper the
    registry records as GPL-only establishes its requirement and
    returns True, even though no profile admits it. Otherwise the
    profile's GPL-restricted sets decide; both are empty for the
    supported profile, so established profile programs never
    require GPL coverage today.
    """
    resolved = _resolve_profile(profile)
    for helper_id in helper_ids:
        if helper_id in resolved.helper_ids:
            continue
        known = lookup_helper(helper_id)
        if known is not None and known.gpl_only:
            continue
        raise _fail(
            "MBPF706",
            STAGE_INSPECT_LICENSE,
            "cannot establish licensing requirements: helper ID %r "
            "is outside profile %r (supported IDs: %s)"
            % (
                helper_id,
                resolved.profile_id,
                ", ".join(str(h) for h in resolved.helper_ids),
            ),
            None,
            "use only helpers of the named profile",
        )
    allowed_programs = {pair[0] for pair in resolved.allowed_pairs}
    for program_type in program_types:
        if program_type not in allowed_programs:
            raise _fail(
                "MBPF706",
                STAGE_INSPECT_LICENSE,
                "cannot establish licensing requirements: program type "
                "%r is outside profile %r (supported: %s)"
                % (
                    program_type,
                    resolved.profile_id,
                    ", ".join(sorted(allowed_programs)),
                ),
                None,
                "use only program types of the named profile",
            )
    for kfunc in kfuncs:
        raise _fail(
            "MBPF706",
            STAGE_INSPECT_LICENSE,
            "cannot establish licensing requirements: kfunc use %r is "
            "outside profile %r" % (kfunc, resolved.profile_id),
            None,
            "avoid kfunc calls under this profile",
        )
    if resolved.profile_id not in _GPL_ONLY_HELPERS or (
        resolved.profile_id not in _GPL_ONLY_PROGRAMS
    ):
        raise _fail(
            "MBPF706",
            STAGE_INSPECT_LICENSE,
            "cannot establish licensing requirements: profile %r "
            "has no GPL-restriction entry" % (resolved.profile_id,),
            None,
            "use a profile with recorded GPL restrictions",
        )
    gpl_helpers = _GPL_ONLY_HELPERS[resolved.profile_id]
    gpl_programs = _GPL_ONLY_PROGRAMS[resolved.profile_id]
    for helper_id in helper_ids:
        known = lookup_helper(helper_id)
        if known is not None and known.gpl_only:
            return True
    return any(h in gpl_helpers for h in helper_ids) or any(
        p in gpl_programs for p in program_types
    )


def preflight_helper_licenses(
    helper_ids: list[int] | tuple[int, ...],
    kernel_license: str,
    profile: str | TargetProfile,
) -> None:
    """Preflight-check used helpers against the kernel declaration.

    Every registry-recorded GPL-only helper needs a declaration
    the kernel recognizes as GPL-compatible; the first one that
    lacks it raises ``MBPF709`` naming the helper ID and symbol
    and quoting the declaration unchanged. Helpers the registry
    does not record are skipped here: availability is
    :func:`requires_gpl`'s verdict (``MBPF706``), not the
    preflight's. A GPL-recognized declaration passes the
    preflight even though the declaration-pair gate still refuses
    unmapped GPL pairs.

    The declaration is only read, never rewritten: the remedy
    restricts the program (``restrict the program to non-GPL
    facilities``) instead of suggesting a declaration change.
    """
    resolved = _resolve_profile(profile)
    if not isinstance(kernel_license, str):
        raise TypeError("kernel_license must be a string")
    for helper_id in helper_ids:
        known = lookup_helper(helper_id)
        if known is None or not known.gpl_only:
            continue
        if kernel_recognizes_as_gpl(kernel_license):
            continue
        raise _fail(
            "MBPF709",
            STAGE_INSPECT_LICENSE,
            "helper %d (%s) is GPL-only but kernel license %r is "
            "not a kernel-recognized GPL-compatible declaration "
            "under profile %r"
            % (
                known.helper_id,
                known.kernel_name,
                kernel_license,
                resolved.profile_id,
            ),
            None,
            "restrict the program to non-GPL facilities",
        )


@dataclass(frozen=True)
class Observation:
    """One neutral inspection fact about an object file."""

    location: str | None
    explanation: str

    def to_dict(self) -> dict[str, str | None]:
        """Return a stable plain-data mapping of this observation."""
        return {"location": self.location, "explanation": self.explanation}


@dataclass(frozen=True)
class InspectionReport:
    """Versioned outcome of inspecting one object file.

    ``structural`` holds malformed-byte findings (``MBPF401``-``405``),
    ``unsupported`` holds outside-the-profile findings (``MBPF406``,
    ``MBPF407``), and ``license`` holds declaration-gate findings
    (``MBPF7xx``; empty for :func:`inspect_object`, which takes no
    declaration). ``observations`` holds neutral facts. ``ok`` is true
    only when all three finding buckets are empty. A clean report
    describes bytes only; it never claims kernel acceptance.
    """

    schema_version: int
    path: str
    profile_id: str
    ok: bool
    structural: tuple[Diagnostic, ...]
    unsupported: tuple[Diagnostic, ...]
    license: tuple[Diagnostic, ...]
    observations: tuple[Observation, ...]

    def to_dict(self) -> dict:
        """Return a plain-data mapping of this report."""
        return {
            "schema_version": self.schema_version,
            "path": self.path,
            "profile_id": self.profile_id,
            "ok": self.ok,
            "structural": [item.to_dict() for item in self.structural],
            "unsupported": [item.to_dict() for item in self.unsupported],
            "license": [item.to_dict() for item in self.license],
            "observations": [item.to_dict() for item in self.observations],
        }


class _ElfError(Exception):
    """Internal parse failure carrying a finding, not a traceback."""

    def __init__(self, code: str, explanation: str, location: str) -> None:
        super().__init__(explanation)
        self.code = code
        self.explanation = explanation
        self.location = location


@dataclass
class _Section:
    index: int
    name: str
    name_off: int
    type: int
    flags: int
    offset: int
    size: int
    link: int
    info: int
    entsize: int


@dataclass
class _Symbol:
    name: str
    type: int
    shndx: int
    value: int
    size: int


@dataclass
class _Elf:
    image: bytes
    machine: int
    objtype: int
    sections: list[_Section]
    symbols: list[_Symbol]


@dataclass
class _CodeFacts:
    helper_ids: list[int]
    has_pseudo_call: bool
    call_count: int
    subprog_calls: int


def _read_object_bytes(path: str) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise _fail(
            "MBPF401",
            STAGE_INSPECT_OBJECT,
            "cannot read object file %r: %s" % (path, exc),
            path,
            "check the object path and permissions",
        ) from None


def _parse_elf(image: bytes, path: str) -> _Elf:
    """Parse a 64-bit little-endian ELF object, failing closed."""
    if len(image) < 64 or image[:4] != b"\x7fELF":
        raise _ElfError("MBPF401", "not an ELF object file", path)
    if image[4] != 2:
        raise _ElfError("MBPF401", "not a 64-bit object file", path)
    if image[5] != 1:
        raise _ElfError("MBPF401", "not a little-endian object file", path)
    try:
        (objtype, machine, _version) = struct.unpack_from("<HHI", image, 16)
        (e_shoff,) = struct.unpack_from("<Q", image, 40)
        (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
            "<HHH", image, 58
        )
    except struct.error:
        raise _ElfError("MBPF401", "truncated ELF header", path) from None
    if e_shentsize != 0 and e_shentsize < 64:
        raise _ElfError("MBPF402", "bad section header size", path)
    if e_shnum == 0 and e_shoff != 0:
        raise _ElfError(
            "MBPF402", "extended section numbering is not supported", path
        )
    if e_shnum != 0 and e_shoff + e_shnum * e_shentsize > len(image):
        raise _ElfError("MBPF402", "section table runs past end", path)
    sections: list[_Section] = []
    for index in range(e_shnum):
        off = e_shoff + index * e_shentsize
        try:
            fields = struct.unpack_from("<IIQQQQIIQQ", image, off)
        except struct.error:
            raise _ElfError(
                "MBPF402", "truncated section header %d" % index, path
            ) from None
        (name, stype, flags, _addr, sec_off, size, link, info,
         _align, entsize) = fields
        if stype != SHT_NOBITS and sec_off + size > len(image):
            raise _ElfError(
                "MBPF402",
                "section %d contents run past end of file" % index,
                path,
            )
        sections.append(
            _Section(index, "", name, stype, flags, sec_off, size, link,
                     info, entsize)
        )
    if sections:
        if e_shstrndx >= len(sections):
            raise _ElfError("MBPF402", "bad section-name table", path)
        strtab = sections[e_shstrndx]
        for section in sections:
            raw = _cstr(
                image, strtab.offset, strtab.size, section.name_off,
                path,
            )
            try:
                section.name = raw.decode("ascii")
            except UnicodeDecodeError:
                raise _ElfError(
                    "MBPF402",
                    "section %d name is not ASCII" % section.index,
                    path,
                ) from None
    symbols: list[_Symbol] = []
    for section in sections:
        if section.type != SHT_SYMTAB:
            continue
        stride = section.entsize or 24
        if stride < 24 or section.size % stride != 0:
            raise _ElfError(
                "MBPF402",
                "symbol table %r has a bad entry size" % section.name,
                path,
            )
        if section.link >= len(sections):
            raise _ElfError(
                "MBPF402",
                "symbol table %r links a missing string table"
                % section.name,
                path,
            )
        strsec = sections[section.link]
        for entry in range(section.size // stride):
            off = section.offset + entry * stride
            try:
                (st_name, st_info, _other, st_shndx, st_value,
                 st_size) = struct.unpack_from("<IBBHQQ", image, off)
            except struct.error:
                raise _ElfError(
                    "MBPF402", "truncated symbol table entry", path
                ) from None
            raw = _cstr(image, strsec.offset, strsec.size, st_name, path)
            try:
                name = raw.decode("ascii")
            except UnicodeDecodeError:
                raise _ElfError(
                    "MBPF402", "symbol name is not ASCII", path
                ) from None
            symbols.append(
                _Symbol(name, st_info & 0xF, st_shndx, st_value, st_size)
            )
    return _Elf(image, machine, objtype, sections, symbols)


def _cstr(image: bytes, base: int, size: int, off: int,
          path: str) -> bytes:
    """Read a NUL-terminated string; fail closed on bad bounds."""
    if off >= size:
        raise _ElfError("MBPF402", "string offset past table end", path)
    end = image.find(b"\x00", base + off, base + size)
    if end < 0:
        raise _ElfError("MBPF402", "unterminated table string", path)
    return image[base + off:end]


def _section_bytes(elf: _Elf, section: _Section) -> bytes:
    if section.type == SHT_NOBITS:
        return b""
    return elf.image[section.offset:section.offset + section.size]


def _object_finding(code: str, explanation: str, location: str | None,
                    remedy: str) -> Diagnostic:
    return Diagnostic(
        code=code,
        stage=STAGE_INSPECT_OBJECT,
        severity=SEVERITY_ERROR,
        explanation=explanation,
        location=location,
        remedy=remedy,
    )


def _decode_calls(elf: _Elf, executable: list[_Section],
                  facts: _CodeFacts, structural: list[Diagnostic],
                  unsupported: list[Diagnostic],
                  profile: TargetProfile) -> None:
    """Decode call instructions; record helper IDs and call findings.

    A static subprogram call (opcode ``0x85`` with source register
    1 and immediate ``-1``, the linker's unresolved static-call
    form) is admitted only under a profile with
    ``subprog_supported``, and only when an XDP entry section is
    present (checked after decoding); every other non-plain call
    form stays outside every profile.
    """
    for section in executable:
        code = _section_bytes(elf, section)
        if len(code) % 8 != 0:
            structural.append(
                _object_finding(
                    "MBPF405",
                    "executable section %r holds %d bytes, not an "
                    "instruction multiple" % (section.name, len(code)),
                    "section:%s" % section.name,
                    "rebuild the object with the pinned backend",
                )
            )
            continue
        offset = 0
        while offset < len(code):
            opcode = code[offset]
            if opcode == BPF_OP_LD_IMM64:
                if offset + 16 > len(code):
                    structural.append(
                        _object_finding(
                            "MBPF405",
                            "truncated wide load in section %r"
                            % (section.name,),
                            "section:%s+0x%x" % (section.name, offset),
                            "rebuild the object with the pinned backend",
                        )
                    )
                    break
                offset += 16
                continue
            if opcode == BPF_OP_CALL:
                facts.call_count += 1
                src = (code[offset + 1] >> 4) & 0xF
                (imm,) = struct.unpack_from("<i", code, offset + 4)
                if src == 0:
                    facts.helper_ids.append(imm)
                    if imm not in profile.helper_ids:
                        unsupported.append(
                            _object_finding(
                                "MBPF407",
                                "call to helper ID %d in section %r is "
                                "outside profile %r (supported IDs: %s)"
                                % (
                                    imm,
                                    section.name,
                                    profile.profile_id,
                                    ", ".join(
                                        str(h)
                                        for h in profile.helper_ids
                                    ),
                                ),
                                "section:%s+0x%x"
                                % (section.name, offset),
                                "use only helpers of the named profile",
                            )
                        )
                elif (
                    src == 1
                    and imm == -1
                    and profile.subprog_supported
                ):
                    facts.subprog_calls += 1
                else:
                    facts.has_pseudo_call = True
                    unsupported.append(
                        _object_finding(
                            "MBPF407",
                            "non-plain call form in section %r "
                            "(opcode 0x85 with source register %d)"
                            % (section.name, src),
                            "section:%s+0x%x" % (section.name, offset),
                            "use plain helper calls only",
                        )
                    )
            elif opcode == BPF_OP_PSEUDO_CALL:
                facts.call_count += 1
                facts.has_pseudo_call = True
                unsupported.append(
                    _object_finding(
                        "MBPF407",
                        "pseudo call in section %r is outside profile "
                        "%r" % (section.name, profile.profile_id),
                        "section:%s+0x%x" % (section.name, offset),
                        "avoid subprogram and kfunc calls under this "
                        "profile",
                    )
                )
            offset += 8


def _inspect_parsed(path: str, elf: _Elf,
                    profile: TargetProfile) -> tuple[InspectionReport,
                                                    _CodeFacts,
                                                    list[str]]:
    """Check a parsed object; return report, code facts, program types."""
    structural: list[Diagnostic] = []
    unsupported: list[Diagnostic] = []
    observations: list[Observation] = []
    facts = _CodeFacts([], False, 0, 0)

    if elf.objtype != ET_REL:
        unsupported.append(
            _object_finding(
                "MBPF406",
                "object type %d is not a relocatable object" % elf.objtype,
                path,
                "inspect relocatable objects built for the profile",
            )
        )
    is_bpf = elf.machine == EM_BPF
    if not is_bpf:
        unsupported.append(
            _object_finding(
                "MBPF406",
                "machine type %d is not EM_BPF (%d)"
                % (elf.machine, EM_BPF),
                path,
                "inspect objects built for the BPF profile",
            )
        )

    names = [section.name for section in elf.sections]
    observations.append(
        Observation(
            None,
            "sections in order: %s" % (", ".join(names) or "(none)",),
        )
    )

    license_sections = [s for s in elf.sections if s.name == "license"]
    if not license_sections:
        structural.append(
            _object_finding(
                "MBPF403",
                "missing license section",
                path,
                "rebuild so the object carries exactly one license "
                "payload",
            )
        )
    elif len(license_sections) > 1:
        structural.append(
            _object_finding(
                "MBPF403",
                "conflicting license declarations: %d license sections"
                % len(license_sections),
                path,
                "rebuild so the object carries exactly one license "
                "payload",
            )
        )
    else:
        payload = _section_bytes(elf, license_sections[0])
        problem = _license_payload_problem(payload)
        if problem is not None:
            structural.append(
                _object_finding(
                    "MBPF403", problem, "section:license",
                    "rebuild so the object carries exactly one "
                    "NUL-terminated license payload",
                )
            )
        else:
            observations.append(
                Observation(
                    "section:license",
                    "license payload: %r" % (payload,),
                )
            )

    executable = [
        s for s in elf.sections
        if s.flags & SHF_EXECINSTR and s.size > 0
    ]
    empty_exec = sorted(
        s.name for s in elf.sections
        if s.flags & SHF_EXECINSTR and s.size == 0
    )
    if empty_exec:
        observations.append(
            Observation(
                None,
                "empty executable sections: %s" % ", ".join(empty_exec),
            )
        )
    if not executable:
        structural.append(
            _object_finding(
                "MBPF403",
                "no non-empty executable section",
                path,
                "inspect objects holding at least one program",
            )
        )
    allowed_sections = {pair[1] for pair in profile.allowed_pairs}
    program_types: list[str] = []
    section_of_type = {pair[1]: pair[0] for pair in profile.allowed_pairs}
    for section in executable:
        if section.name not in allowed_sections:
            if section.name == ".text" and profile.subprog_supported:
                observations.append(
                    Observation(
                        "section:.text",
                        "subprogram section .text holds %d bytes"
                        % (section.size,),
                    )
                )
                continue
            unsupported.append(
                _object_finding(
                    "MBPF406",
                    "executable section %r is outside profile %r "
                    "(supported: %s)"
                    % (
                        section.name,
                        profile.profile_id,
                        ", ".join(sorted(allowed_sections)),
                    ),
                    "section:%s" % section.name,
                    "use only program sections of the named profile",
                )
            )
            program_types.append(section.name)
        else:
            program_types.append(section_of_type[section.name])

    undefined = sorted(
        {s.name for s in elf.symbols if s.shndx == SHN_UNDEF and s.name}
    )
    if undefined:
        structural.append(
            _object_finding(
                "MBPF404",
                "unknown external symbols: %s" % ", ".join(undefined),
                path,
                "resolve every external symbol before publication",
            )
        )
    defined_funcs = sorted(
        s.name for s in elf.symbols
        if s.type == STT_FUNC and s.shndx != SHN_UNDEF and s.name
    )
    observations.append(
        Observation(
            None,
            "defined functions: %s" % (", ".join(defined_funcs) or "(none)"),
        )
    )

    for section in elf.sections:
        if section.type not in (SHT_REL, SHT_RELA):
            continue
        expected = 24 if section.type == SHT_RELA else 16
        stride = section.entsize or expected
        if stride < expected or section.size % stride != 0:
            structural.append(
                _object_finding(
                    "MBPF405",
                    "relocation section %r has a bad entry size"
                    % (section.name,),
                    "section:%s" % section.name,
                    "rebuild the object with the pinned backend",
                )
            )
            continue
        if section.info >= len(elf.sections):
            structural.append(
                _object_finding(
                    "MBPF405",
                    "relocation section %r targets missing section %d"
                    % (section.name, section.info),
                    "section:%s" % section.name,
                    "rebuild the object with the pinned backend",
                )
            )
            continue
        if section.link >= len(elf.sections):
            structural.append(
                _object_finding(
                    "MBPF405",
                    "relocation section %r links missing section %d"
                    % (section.name, section.link),
                    "section:%s" % section.name,
                    "rebuild the object with the pinned backend",
                )
            )
            continue
        linked = elf.sections[section.link]
        if linked.type != SHT_SYMTAB:
            structural.append(
                _object_finding(
                    "MBPF405",
                    "relocation section %r links non-symbol "
                    "section %d (%r)"
                    % (section.name, section.link, linked.name),
                    "section:%s" % section.name,
                    "rebuild the object with the pinned backend",
                )
            )
            continue
        sym_stride = linked.entsize or 24
        sym_count = (
            linked.size // sym_stride if sym_stride >= 24 else 0
        )
        target = elf.sections[section.info]
        raw = _section_bytes(elf, section)
        for entry in range(section.size // stride):
            (at, info) = struct.unpack_from(
                "<QQ", raw, entry * stride
            )
            if at >= target.size:
                structural.append(
                    _object_finding(
                        "MBPF405",
                        "relocation %d in %r points past %r (%d >= %d)"
                        % (
                            entry,
                            section.name,
                            target.name,
                            at,
                            target.size,
                        ),
                        "section:%s" % section.name,
                        "rebuild the object with the pinned backend",
                    )
                )
            sym = info >> 32
            rel_type = info & 0xFFFFFFFF
            if sym >= sym_count:
                structural.append(
                    _object_finding(
                        "MBPF405",
                        "relocation %d in %r names missing symbol "
                        "%d (>= %d)"
                        % (entry, section.name, sym, sym_count),
                        "section:%s" % section.name,
                        "rebuild the object with the pinned backend",
                    )
                )
            if rel_type not in _ADMITTED_RELOC_TYPES:
                structural.append(
                    _object_finding(
                        "MBPF405",
                        "relocation %d in %r has unsupported type %d"
                        % (entry, section.name, rel_type),
                        "section:%s" % section.name,
                        "rebuild the object with the pinned backend",
                    )
                )

    maps_present = any(s.name == ".maps" for s in elf.sections)
    btf_present = any(s.name == ".BTF" for s in elf.sections)
    if maps_present != btf_present:
        structural.append(
            _object_finding(
                "MBPF405",
                "inconsistent map metadata: .maps present: %s, .BTF "
                "present: %s" % (maps_present, btf_present),
                path,
                "rebuild so map definitions and map BTF agree",
            )
        )
    observations.append(
        Observation(
            None,
            "map metadata: .maps present: %s, .BTF present: %s"
            % (maps_present, btf_present),
        )
    )
    ext_section = None
    btf_section = None
    for section in elf.sections:
        if section.name == ".BTF.ext":
            ext_section = section
        elif section.name == ".BTF":
            btf_section = section
    if ext_section is not None:
        if profile.core_supported:
            if btf_section is None:
                structural.append(
                    _object_finding(
                        "MBPF402",
                        "object carries .BTF.ext relocation records "
                        "but no .BTF types",
                        "section:.BTF.ext",
                        "rebuild the object with the pinned backend",
                    )
                )
            else:
                try:
                    shapes = _core_relo_shapes(
                        _section_bytes(elf, btf_section),
                        _section_bytes(elf, ext_section),
                        path,
                    )
                except _ElfError as exc:
                    structural.append(
                        _object_finding(
                            exc.code,
                            exc.explanation,
                            "section:.BTF.ext",
                            "rebuild the object with the pinned "
                            "backend",
                        )
                    )
                else:
                    want = sorted(CORE_RELO_SHAPES, key=repr)
                    if sorted(shapes, key=repr) != want:
                        unsupported.append(
                            _object_finding(
                                "MBPF407",
                                _core_shape_refusal(shapes),
                                "section:.BTF.ext",
                                "emit only the pinned task_struct.pid "
                                "byte-offset read and task_struct.scx "
                                "existence check; wider relocations "
                                "need a reviewed route",
                            )
                        )
                    else:
                        observations.append(
                            Observation(
                                None,
                                ".BTF.ext carries the 2 pinned CO-RE "
                                "relocations (task_struct.pid 0:1 "
                                "kind 0 at 96; task_struct.scx 0:4 "
                                "kind 2 at 112)",
                            )
                        )
        else:
            unsupported.append(
                _object_finding(
                    "MBPF407",
                    ".BTF.ext metadata is outside profile %r"
                    % (profile.profile_id,),
                    "section:.BTF.ext",
                    "avoid CO-RE-style metadata under this profile",
                )
            )

    if is_bpf:
        _decode_calls(elf, executable, facts, structural, unsupported,
                      profile)
    observations.append(
        Observation(
            None,
            "helper IDs observed: %s"
            % (", ".join(str(h) for h in sorted(set(facts.helper_ids)))
               or "(none)",),
        )
    )
    observations.append(
        Observation(None, "call instructions: %d" % facts.call_count)
    )
    if facts.subprog_calls:
        observations.append(
            Observation(
                None,
                "subprogram calls: %d" % facts.subprog_calls,
            )
        )
        if profile.subprog_supported and "xdp" not in program_types:
            unsupported.append(
                _object_finding(
                    "MBPF407",
                    "subprogram calls require an XDP entry section "
                    "under profile %r (entry sections: %s)"
                    % (
                        profile.profile_id,
                        ", ".join(program_types) or "(none)",
                    ),
                    "section:.text",
                    "place static calls on a classifier program only",
                )
            )

    report = InspectionReport(
        schema_version=INSPECTION_SCHEMA_VERSION,
        path=path,
        profile_id=profile.profile_id,
        ok=not structural and not unsupported,
        structural=tuple(structural),
        unsupported=tuple(unsupported),
        license=(),
        observations=tuple(observations),
    )
    return report, facts, program_types


def _license_payload_problem(payload: bytes) -> str | None:
    """Describe a malformed license payload, or None when well-formed."""
    if not payload:
        return "license payload is empty"
    if payload[-1:] != b"\x00":
        return "license payload is missing its NUL terminator"
    if b"\x00" in payload[:-1]:
        return "license payload holds extra NUL-separated data"
    try:
        payload[:-1].decode("ascii")
    except UnicodeDecodeError:
        return "license payload is not ASCII"
    return None


def _elf_error_report(path: str, profile: TargetProfile,
                      error: _ElfError) -> InspectionReport:
    finding = Diagnostic(
        code=error.code,
        stage=STAGE_INSPECT_OBJECT,
        severity=SEVERITY_ERROR,
        explanation=error.explanation,
        location=error.location,
        remedy="rebuild the object with the pinned toolchain",
    )
    return InspectionReport(
        schema_version=INSPECTION_SCHEMA_VERSION,
        path=path,
        profile_id=profile.profile_id,
        ok=False,
        structural=(finding,),
        unsupported=(),
        license=(),
        observations=(),
    )


def object_map_names(path: str) -> tuple[str, ...]:
    """Return the defined symbols in the object's ``.maps`` section.

    Sorted names of symbols that are defined (not undefined) in a
    section named ``.maps``. An object without that section yields an
    empty tuple. An unreadable file raises :class:`InspectionError`
    (``MBPF401``), as does an unparseable object (with its own
    ``MBPF40x`` code). Builds compare this emitted set against the
    manifest's declared maps before publication.
    """
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("path must be a string or path-like object")
    where = os.fspath(path)
    image = _read_object_bytes(where)
    try:
        elf = _parse_elf(image, where)
    except _ElfError as exc:
        raise _fail(
            exc.code,
            STAGE_INSPECT_OBJECT,
            "cannot list the map symbols of %r: %s"
            % (where, exc.explanation),
            where,
            "rebuild the object with the pinned toolchain",
        ) from None
    by_index = {section.index: section for section in elf.sections}
    names: set[str] = set()
    for symbol in elf.symbols:
        if not symbol.name or symbol.shndx == SHN_UNDEF:
            continue
        section = by_index.get(symbol.shndx)
        if section is not None and section.name == ".maps":
            names.add(symbol.name)
    return tuple(sorted(names))


def _btf_string(strings: bytes, off: int, path: str) -> str:
    if off < 0 or off >= len(strings):
        raise _ElfError("MBPF402", "BTF string offset past table end",
                        path)
    end = strings.find(b"\x00", off)
    if end < 0:
        raise _ElfError("MBPF402", "unterminated BTF string", path)
    try:
        return strings[off:end].decode("ascii")
    except UnicodeDecodeError:
        raise _ElfError("MBPF402", "non-ASCII BTF string", path) from None


def _parse_btf_types(blob: bytes, path: str
                     ) -> tuple[list[tuple[str, int, object]], bytes]:
    """Parse the ``.BTF`` type section into records plus strings.

    Returns ([(name, kind, payload)], strings) with 1-based type
    IDs in list order; payloads are the member lists for
    STRUCT/UNION, the ARRAY element counts, the VAR/FUNC targets,
    and the DATASEC entries. Raises :class:`_ElfError`
    (``MBPF402``) when the BTF does not parse.
    """
    if len(blob) < 24:
        raise _ElfError("MBPF402", "truncated BTF header", path)
    try:
        (magic, version, _flags, hdr_len) = struct.unpack_from(
            "<HBBI", blob, 0
        )
        (type_off, type_len, str_off, str_len) = struct.unpack_from(
            "<IIII", blob, 8
        )
    except struct.error:
        raise _ElfError("MBPF402", "truncated BTF header", path) from None
    if magic != 0xEB9F or version != 1 or hdr_len != 24:
        raise _ElfError("MBPF402", "bad BTF header", path)
    if type_off != 0 or str_off != type_len:
        raise _ElfError("MBPF402", "unexpected BTF layout", path)
    if len(blob) != 24 + type_len + str_len:
        raise _ElfError("MBPF402", "BTF size mismatch", path)
    strings = blob[24 + type_len:]
    records: list[tuple[str, int, object]] = []
    pos, end = 24, 24 + type_len
    while pos < end:
        if pos + 12 > end:
            raise _ElfError("MBPF402", "truncated BTF record", path)
        try:
            (name_off, info, size_or_type) = struct.unpack_from(
                "<III", blob, pos
            )
        except struct.error:
            raise _ElfError(
                "MBPF402", "truncated BTF record", path
            ) from None
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        pos += 12
        name = _btf_string(strings, name_off, path)
        if kind == 1:  # INT
            if pos + 4 > end:
                raise _ElfError(
                    "MBPF402", "truncated BTF record", path
                )
            pos += 4
            payload: object = None
        elif kind in (2, 12):  # PTR, FUNC
            payload = size_or_type
        elif kind == 13:  # FUNC_PROTO
            if pos + 8 * vlen > end:
                raise _ElfError(
                    "MBPF402", "truncated BTF record", path
                )
            pos += 8 * vlen
            payload = size_or_type
        elif kind == 3:  # ARRAY
            if pos + 12 > end:
                raise _ElfError(
                    "MBPF402", "truncated BTF record", path
                )
            try:
                (_elem, _index, nelems) = struct.unpack_from(
                    "<III", blob, pos
                )
            except struct.error:
                raise _ElfError(
                    "MBPF402", "truncated BTF record", path
                ) from None
            pos += 12
            payload = nelems
        elif kind in (4, 5):  # STRUCT, UNION
            members = []
            for _ in range(vlen):
                if pos + 12 > end:
                    raise _ElfError(
                        "MBPF402", "truncated BTF record", path
                    )
                try:
                    (m_name, m_type, m_off) = struct.unpack_from(
                        "<III", blob, pos
                    )
                except struct.error:
                    raise _ElfError(
                        "MBPF402", "truncated BTF record", path
                    ) from None
                pos += 12
                members.append(
                    (_btf_string(strings, m_name, path), m_type, m_off)
                )
            payload = members
        elif kind == 14:  # VAR
            if pos + 4 > end:
                raise _ElfError(
                    "MBPF402", "truncated BTF record", path
                )
            pos += 4
            payload = size_or_type
        elif kind == 15:  # DATASEC
            entries = []
            for _ in range(vlen):
                if pos + 12 > end:
                    raise _ElfError(
                        "MBPF402", "truncated BTF record", path
                    )
                try:
                    (e_type, e_off, e_size) = struct.unpack_from(
                        "<III", blob, pos
                    )
                except struct.error:
                    raise _ElfError(
                        "MBPF402", "truncated BTF record", path
                    ) from None
                pos += 12
                entries.append((e_type, e_off, e_size))
            payload = entries
        else:
            raise _ElfError(
                "MBPF402", "unexpected BTF kind %d" % kind, path
            )
        records.append((name, kind, payload))
    if pos != end:
        raise _ElfError("MBPF402", "BTF type section overrun", path)
    return records, strings


def _parse_btf_map_attrs(blob: bytes, path: str) -> dict[str, dict]:
    """Resolve ``.maps`` VARs to their attribute bounds by name.

    Returns {var name: {"type": int, "key_size": int,
    "value_size": int, "max_entries": int}} by walking DATASEC
    ``.maps`` -> VAR -> STRUCT members -> member pointer targets ->
    ARRAY bounds. Keyed maps bind all four attributes; ring-buffer
    maps bind exactly type and max_entries (their key and value
    sizes resolve to zero, matching the kernel ring-buffer
    contract) and any other member set fails closed. Raises
    :class:`_ElfError` (``MBPF402``) when the BTF does not parse
    or the attribute chain breaks anywhere.
    """
    records, _strings = _parse_btf_types(blob, path)

    def record(type_id: int) -> tuple[str, int, object]:
        if type_id < 1 or type_id > len(records):
            raise _ElfError(
                "MBPF402", "BTF type id %d out of range" % type_id,
                path,
            )
        return records[type_id - 1]

    found: dict[str, dict] = {}
    for name, kind, payload in records:
        if kind != 15 or name != ".maps" or not isinstance(payload, list):
            continue
        for entry in payload:
            var_name, var_kind, var_target = record(entry[0])
            if var_kind != 14 or not isinstance(var_target, int):
                raise _ElfError(
                    "MBPF402", "BTF .maps entry is not a VAR", path
                )
            _struct_name, struct_kind, members = record(var_target)
            if struct_kind != 4 or not isinstance(members, list):
                raise _ElfError(
                    "MBPF402", "BTF map VAR has no STRUCT", path
                )
            attrs: dict[str, int] = {}
            for member_name, member_type, _ in members:
                _ptr_name, ptr_kind, ptr_target = record(member_type)
                if ptr_kind != 2 or not isinstance(ptr_target, int):
                    raise _ElfError(
                        "MBPF402",
                        "BTF map member %r is not a pointer" % member_name,
                        path,
                    )
                _arr_name, arr_kind, nelems = record(ptr_target)
                if arr_kind != 3 or not isinstance(nelems, int):
                    raise _ElfError(
                        "MBPF402",
                        "BTF map member %r has no ARRAY bound"
                        % member_name,
                        path,
                    )
                attrs[member_name] = nelems
            if set(attrs) == {"type", "max_entries"}:
                if attrs["type"] != 27:
                    raise _ElfError(
                        "MBPF402",
                        "BTF map VAR %r binds only type and "
                        "max_entries but is not a ring-buffer map "
                        "(type %d)" % (var_name, attrs["type"]),
                        path,
                    )
                attrs["key_size"] = 0
                attrs["value_size"] = 0
            else:
                for field in ("type", "key_size", "value_size",
                              "max_entries"):
                    if field not in attrs:
                        raise _ElfError(
                            "MBPF402",
                            "BTF map VAR %r lacks %r" % (
                                var_name, field,
                            ),
                            path,
                        )
            found[var_name] = attrs
    return found


# The only admitted CO-RE relocation shapes, as (section, type,
# member, kind, accessor, insn_off): the pinned
# ``task_struct.pid`` byte-offset read at instruction offset 96
# plus the pinned ``task_struct.scx`` existence check at
# instruction offset 112. Any other ``.BTF.ext`` content is
# refused.
CORE_RELO_SHAPES = (
    ("xdp", "task_struct", "pid", 0, "0:1", 96),
    ("xdp", "task_struct", "scx", 2, "0:4", 112),
)


def _core_relo_shapes(btf_blob: bytes, ext_blob: bytes, path: str
                      ) -> list[tuple[str, str, str | None, int,
                                       str, int]]:
    """Resolve every ``.BTF.ext`` core relocation to its shape.

    Returns one (section, type, member, kind, accessor,
    insn_off) tuple per relocation record across every info
    section in the core blob; ``member`` is None when the
    accessor does not select a single struct member (such
    shapes never match the pinned set), and ``insn_off`` is
    the relocated instruction byte offset. Raises
    :class:`_ElfError` (``MBPF402``) on malformed
    bytes: a bad ``.BTF.ext`` header, overrunning tables, an
    unparseable record size, or dangling type, string, or member
    references.
    """
    if len(ext_blob) < 32:
        raise _ElfError("MBPF402", "truncated .BTF.ext header", path)
    try:
        (magic, version, _flags, hdr_len) = struct.unpack_from(
            "<HBBI", ext_blob, 0
        )
        (func_off, func_len, line_off, line_len,
         core_off, core_len) = struct.unpack_from(
            "<IIIIII", ext_blob, 8
        )
    except struct.error:
        raise _ElfError(
            "MBPF402", "truncated .BTF.ext header", path
        ) from None
    if magic != 0xEB9F or version != 1 or hdr_len != 32:
        raise _ElfError("MBPF402", "bad .BTF.ext header", path)
    for label, start, size in (
        ("func", func_off, func_len),
        ("line", line_off, line_len),
        ("core", core_off, core_len),
    ):
        if hdr_len + start + size > len(ext_blob):
            raise _ElfError(
                "MBPF402",
                ".BTF.ext %s table overruns the section" % label,
                path,
            )
    records, strings = _parse_btf_types(btf_blob, path)

    def record(type_id: int) -> tuple[str, int, object]:
        if type_id < 1 or type_id > len(records):
            raise _ElfError(
                "MBPF402", "BTF type id %d out of range" % type_id,
                path,
            )
        return records[type_id - 1]

    blob = ext_blob[hdr_len + core_off:hdr_len + core_off + core_len]
    if not blob:
        return []
    if len(blob) < 4:
        raise _ElfError(
            "MBPF402", "truncated .BTF.ext core blob", path
        )
    (record_size,) = struct.unpack_from("<I", blob, 0)
    if record_size != 16:
        raise _ElfError(
            "MBPF402",
            "unsupported .BTF.ext core record size %d" % record_size,
            path,
        )
    shapes: list[tuple[str, str, str | None, int,
                      str, int]] = []
    pos = 4
    while pos < len(blob):
        if pos + 8 > len(blob):
            raise _ElfError(
                "MBPF402", "truncated .BTF.ext info section", path
            )
        sec_name_off, num_info = struct.unpack_from("<II", blob, pos)
        pos += 8
        section = _btf_string(strings, sec_name_off, path)
        for _ in range(num_info):
            if pos + 16 > len(blob):
                raise _ElfError(
                    "MBPF402", "truncated .BTF.ext record", path
                )
            (insn_off, type_id, acc_off, kind) = struct.unpack_from(
                "<IIII", blob, pos
            )
            pos += 16
            access = _btf_string(strings, acc_off, path)
            try:
                accessors = [
                    int(part) for part in access.split(":")
                ]
            except ValueError:
                raise _ElfError(
                    "MBPF402",
                    "bad .BTF.ext accessor %r" % (access,),
                    path,
                ) from None
            name, type_kind, payload = record(type_id)
            member: str | None = None
            if (
                type_kind in (4, 5)
                and isinstance(payload, list)
                and len(accessors) == 2
                and accessors[0] == 0
            ):
                index = accessors[1]
                if index < 0 or index >= len(payload):
                    raise _ElfError(
                        "MBPF402",
                        ".BTF.ext member index %d out of range for %r"
                        % (index, name),
                        path,
                    )
                member = payload[index][0]
            shapes.append(
                (section, name, member, kind, access, insn_off)
            )
    return shapes


def _core_shape_refusal(
    shapes: list[tuple[str, str, str | None, int, str, int]],
) -> str:
    """Explain why parsed relocation shapes miss the pinned set."""
    pinned = (
        "the pinned task_struct.pid 0:1 kind-0 read at insn "
        "offset 96 plus the pinned task_struct.scx 0:4 kind-2 "
        "check at insn offset 112"
    )
    if not shapes:
        return (
            ".BTF.ext carries no CO-RE relocation records, "
            "expected exactly " + pinned
        )
    for section, name, member, kind, access, insn_off in shapes:
        key = (section, name, member, kind, access, insn_off)
        if key not in CORE_RELO_SHAPES:
            return (
                ".BTF.ext relocation (%s %s.%s kind %d access %s "
                "at insn offset %d) is outside the pinned set, "
                "expected exactly %s"
                % (section, name, member or "?", kind, access,
                   insn_off, pinned)
            )
    return (
        ".BTF.ext carries %d CO-RE relocation records, expected "
        "exactly %s" % (len(shapes), pinned)
    )


def object_map_specs(path: str) -> tuple[tuple[str, int, int], ...]:
    """Return ``(name, map_type, max_entries)`` per emitted map.

    The map kind and entry count live in the ``.BTF``
    map-attribute records (the ``.maps`` bytes are all zero), so
    this resolves them by name through DATASEC ``.maps``. An
    object without map BTF yields an empty tuple. An unreadable
    file raises :class:`InspectionError` (``MBPF401``); an
    unparseable object or BTF blob raises with its own ``MBPF40x``
    code. Builds compare the emitted set against the manifest's
    declared maps before publication.
    """
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("path must be a string or path-like object")
    where = os.fspath(path)
    image = _read_object_bytes(where)
    try:
        elf = _parse_elf(image, where)
    except _ElfError as exc:
        raise _fail(
            exc.code,
            STAGE_INSPECT_OBJECT,
            "cannot list the map symbols of %r: %s"
            % (where, exc.explanation),
            where,
            "rebuild the object with the pinned toolchain",
        ) from None
    blob = None
    for section in elf.sections:
        if section.name == ".BTF":
            blob = _section_bytes(elf, section)
            break
    if blob is None:
        return ()
    try:
        attrs = _parse_btf_map_attrs(blob, where)
    except _ElfError as exc:
        raise _fail(
            exc.code,
            STAGE_INSPECT_OBJECT,
            "cannot read the map attributes of %r: %s"
            % (where, exc.explanation),
            where,
            "rebuild the object with the pinned toolchain",
        ) from None
    return tuple(
        sorted(
            (name, spec["type"], spec["max_entries"])
            for name, spec in attrs.items()
        )
    )


def object_map_value_sizes(path: str) -> dict[str, int]:
    """Return the BTF-declared value size per emitted map.

    Resolves each ``.maps`` VAR's ``value_size`` ARRAY bound
    through the same attribute chain as :func:`object_map_specs`
    (ring-buffer maps resolve to zero, matching their contract).
    An object without map BTF yields an empty dict. Errors match
    :func:`object_map_specs`. Builds compare the emitted sizes
    against the manifest's declared value types before
    publication.
    """
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("path must be a string or path-like object")
    where = os.fspath(path)
    image = _read_object_bytes(where)
    try:
        elf = _parse_elf(image, where)
    except _ElfError as exc:
        raise _fail(
            exc.code,
            STAGE_INSPECT_OBJECT,
            "cannot list the map symbols of %r: %s"
            % (where, exc.explanation),
            where,
            "rebuild the object with the pinned toolchain",
        ) from None
    blob = None
    for section in elf.sections:
        if section.name == ".BTF":
            blob = _section_bytes(elf, section)
            break
    if blob is None:
        return {}
    try:
        attrs = _parse_btf_map_attrs(blob, where)
    except _ElfError as exc:
        raise _fail(
            exc.code,
            STAGE_INSPECT_OBJECT,
            "cannot read the map attributes of %r: %s"
            % (where, exc.explanation),
            where,
            "rebuild the object with the pinned toolchain",
        ) from None
    return {
        name: spec["value_size"] for name, spec in attrs.items()
    }


def object_has_btf_ext(path: str) -> bool:
    """Report whether the object carries a ``.BTF.ext`` section.

    Only the core shape emits relocation metadata, so the driver
    uses this to check the manifest's CO-RE flag against the
    artifact: requested relocations must be present and present
    relocations must be requested. Presence alone is never
    acceptance: the build gate runs :func:`verify_object` first,
    which parses and validates the relocation record content.
    An unreadable file raises :class:`InspectionError`
    (``MBPF401``); an unparseable object raises with its own
    ``MBPF40x`` code.
    """
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("path must be a string or path-like object")
    where = os.fspath(path)
    image = _read_object_bytes(where)
    try:
        elf = _parse_elf(image, where)
    except _ElfError as exc:
        raise _fail(
            exc.code,
            STAGE_INSPECT_OBJECT,
            "cannot list the sections of %r: %s"
            % (where, exc.explanation),
            where,
            "rebuild the object with the pinned toolchain",
        ) from None
    return any(section.name == ".BTF.ext" for section in elf.sections)


def object_section_names(path: str) -> tuple[str, ...]:
    """Return the ELF section names carried by one object file.

    The driver uses this to check the built artifact against the
    manifest program it was built for: the declared program
    section must be present, so an object built from a mismatched
    source can never publish under the wrong program entry. An
    unreadable file raises :class:`InspectionError` (``MBPF401``);
    an unparseable object raises with its own ``MBPF40x`` code.
    """
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("path must be a string or path-like object")
    where = os.fspath(path)
    image = _read_object_bytes(where)
    try:
        elf = _parse_elf(image, where)
    except _ElfError as exc:
        raise _fail(
            exc.code,
            STAGE_INSPECT_OBJECT,
            "cannot list the sections of %r: %s"
            % (where, exc.explanation),
            where,
            "rebuild the object with the pinned toolchain",
        ) from None
    return tuple(section.name for section in elf.sections)


def inspect_object(path: str, profile: str | TargetProfile
                   ) -> InspectionReport:
    """Inspect one object file against a target profile.

    Returns an :class:`InspectionReport` with structural findings,
    unsupported-feature findings and observations. Unparseable input
    yields a report (never a crash); only an unreadable file raises
    :class:`InspectionError` (``MBPF401``), and an unknown profile
    raises the profile error (``MBPF101``). The license bucket stays
    empty: judging the declaration needs :func:`verify_object`.
    """
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("path must be a string or path-like object")
    resolved = _resolve_profile(profile)
    where = os.fspath(path)
    image = _read_object_bytes(where)
    try:
        elf = _parse_elf(image, where)
    except _ElfError as exc:
        return _elf_error_report(where, resolved, exc)
    report, _, _ = _inspect_parsed(where, elf, resolved)
    return report


def check_object_license(path: str, declaration: ValidatedDeclaration
                         ) -> bytes:
    """Check an object's license payload against a validated declaration.

    Requires exactly one unambiguous NUL-terminated payload equal to
    the declaration's expected bytes. Any deviation -- missing,
    extra, conflicting, unterminated or differing bytes -- raises
    :class:`InspectionError` (``MBPF705``). Returns the verified
    payload. Only a :class:`ValidatedDeclaration` is accepted, so
    the compared value always passed pair validation unchanged.
    """
    if not isinstance(declaration, ValidatedDeclaration):
        raise TypeError("declaration must be a ValidatedDeclaration")
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("path must be a string or path-like object")
    where = os.fspath(path)
    image = _read_object_bytes(where)
    try:
        elf = _parse_elf(image, where)
    except _ElfError as exc:
        raise _fail(
            "MBPF705",
            STAGE_INSPECT_LICENSE,
            "cannot establish the license payload of %r: %s"
            % (where, exc.explanation),
            where,
            "rebuild the object with the pinned toolchain",
        ) from None
    found = [s for s in elf.sections if s.name == "license"]
    if len(found) != 1:
        raise _fail(
            "MBPF705",
            STAGE_INSPECT_LICENSE,
            "object %r carries %d license sections, expected exactly "
            "one" % (where, len(found)),
            where,
            "rebuild so the object carries exactly one license payload",
        )
    payload = _section_bytes(elf, found[0])
    problem = _license_payload_problem(payload)
    if problem is not None:
        raise _fail(
            "MBPF705",
            STAGE_INSPECT_LICENSE,
            "object %r: %s" % (where, problem),
            "section:license",
            "rebuild so the object carries exactly one NUL-terminated "
            "license payload",
        )
    expected = declaration.expected_license_bytes
    if payload != expected:
        raise _fail(
            "MBPF705",
            STAGE_INSPECT_LICENSE,
            "object %r declares license %r, validated declaration is "
            "%r" % (where, payload, expected),
            "section:license",
            "rebuild with the validated declaration",
        )
    return payload


def verify_object(path: str, profile: str | TargetProfile,
                  source_license: str, kernel_license: str
                  ) -> InspectionReport:
    """Run the full pre-publication gate over one object file.

    Combines :func:`inspect_object` with the declaration checks, in
    fixed order: licensing requirements from the observed helpers,
    program types and calls (``MBPF706``), the helper-license
    preflight (``MBPF709``), the declaration pair
    (``MBPF701``/``703``/``704``), then the ELF payload
    (``MBPF705``, skipped while the pair is invalid). Every failing
    layer appends its diagnostics to the report's license bucket, so
    one call surfaces every violated layer at once.
    """
    resolved = _resolve_profile(profile)
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("path must be a string or path-like object")
    where = os.fspath(path)
    image = _read_object_bytes(where)
    try:
        elf = _parse_elf(image, where)
    except _ElfError as exc:
        return _elf_error_report(where, resolved, exc)
    report, facts, program_types = _inspect_parsed(where, elf, resolved)
    licensed: list[Diagnostic] = []
    observed_ids = tuple(sorted(set(facts.helper_ids)))
    try:
        need = requires_gpl(
            observed_ids,
            tuple(program_types),
            ("pseudo-call",) if facts.has_pseudo_call else (),
            resolved,
        )
    except InspectionError as exc:
        licensed.append(exc.diagnostic)
        need = False
    try:
        preflight_helper_licenses(observed_ids, kernel_license, resolved)
    except InspectionError as exc:
        licensed.append(exc.diagnostic)
    try:
        validated = validate_declaration_pair(
            source_license, kernel_license, requires_gpl=need
        )
    except InspectionError as exc:
        licensed.append(exc.diagnostic)
        validated = None
    if validated is not None:
        try:
            check_object_license(where, validated)
        except InspectionError as exc:
            licensed.append(exc.diagnostic)
    return InspectionReport(
        schema_version=INSPECTION_SCHEMA_VERSION,
        path=where,
        profile_id=resolved.profile_id,
        ok=not report.structural and not report.unsupported
        and not licensed,
        structural=report.structural,
        unsupported=report.unsupported,
        license=tuple(licensed),
        observations=report.observations,
    )


def assert_no_link_step(commands: object) -> None:
    """Assert that no build command links objects together.

    The license payload is checked on the final object before
    publication; a link step after inspection would need a recheck.
    No link step exists in the pipeline today, so this asserts that:
    any link-like stage or linker argv raises ``AssertionError``
    rather than silently skipping the recheck. When linking lands,
    this tripwire is replaced by recheck logic.
    """
    if commands is None:
        raise TypeError("commands must be a sequence of command records")
    found: list[str] = []
    for record in commands:  # type: ignore[union-attr]
        stage = getattr(record, "stage", "")
        argv = getattr(record, "argv", ())
        if stage in _LINK_STAGES:
            found.append("stage %r" % (stage,))
            continue
        for token in argv:
            if os.path.basename(str(token)) in _LINK_TOOLS:
                found.append("tool %r" % (token,))
                break
    if found:
        raise AssertionError(
            "link step present (%s); license payloads need a recheck "
            "after linking" % (", ".join(sorted(set(found))),)
        )
