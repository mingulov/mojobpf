# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Stable diagnostic model for manifest, profile and toolchain checks.

Every failure carries a stable machine-readable code, the pipeline stage
that raised it, a severity, a human-readable explanation, an optional
location and an actionable remedy. Codes are part of the public contract:
once issued, a code keeps its meaning and new failures receive new codes.

Implemented families:

* ``MBPF1xx``: environment, toolchain and target-profile failures.
* ``MBPF2xx``: manifest and schema failures.

Severity vocabulary: ``"error"``, ``"warning"``, ``"note"``.

Stage vocabulary: ``"manifest.parse"``, ``"profile.resolve"``,
``"toolchain.discovery"``, ``"toolchain.match"``.

Standard library only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CODE_RE = re.compile(r"^MBPF[1-7][0-9]{2}$")

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"
SEVERITY_NOTE = "note"
SEVERITIES = (SEVERITY_ERROR, SEVERITY_WARNING, SEVERITY_NOTE)

STAGE_MANIFEST_PARSE = "manifest.parse"
STAGE_PROFILE_RESOLVE = "profile.resolve"
STAGE_TOOLCHAIN_DISCOVERY = "toolchain.discovery"
STAGE_TOOLCHAIN_MATCH = "toolchain.match"


@dataclass(frozen=True)
class Diagnostic:
    """One stable, actionable failure or observation.

    ``code`` is the frozen machine-readable identifier (for example
    ``"MBPF101"``). ``stage`` names the pipeline step that raised it.
    ``severity`` is one of ``"error"``, ``"warning"`` or ``"note"``.
    ``explanation`` describes the failure in plain language. ``location``
    optionally points at the offending input (file, section, tool name).
    ``remedy`` optionally tells the caller how to proceed; it never
    invents a successful fallback.
    """

    code: str
    stage: str
    severity: str
    explanation: str
    location: str | None = None
    remedy: str | None = None

    def __post_init__(self) -> None:
        if not CODE_RE.match(self.code):
            raise ValueError("invalid diagnostic code: %r" % (self.code,))
        if self.severity not in SEVERITIES:
            raise ValueError("invalid severity: %r" % (self.severity,))
        if not self.stage:
            raise ValueError("diagnostic stage must not be empty")
        if not self.explanation:
            raise ValueError("diagnostic explanation must not be empty")

    def to_dict(self) -> dict[str, str | None]:
        """Return a stable plain-data mapping of this diagnostic."""
        return {
            "code": self.code,
            "stage": self.stage,
            "severity": self.severity,
            "explanation": self.explanation,
            "location": self.location,
            "remedy": self.remedy,
        }


class MojobpfError(Exception):
    """Base error carrying exactly one stable :class:`Diagnostic`."""

    def __init__(self, diagnostic: Diagnostic) -> None:
        if not isinstance(diagnostic, Diagnostic):
            raise ValueError("MojobpfError requires a Diagnostic")
        self.diagnostic = diagnostic
        super().__init__(str(diagnostic))

    def __str__(self) -> str:
        parts = [
            "%s (%s/%s): %s"
            % (
                self.diagnostic.code,
                self.diagnostic.stage,
                self.diagnostic.severity,
                self.diagnostic.explanation,
            )
        ]
        if self.diagnostic.location:
            parts.append("location: %s" % self.diagnostic.location)
        if self.diagnostic.remedy:
            parts.append("remedy: %s" % self.diagnostic.remedy)
        return "; ".join(parts)
