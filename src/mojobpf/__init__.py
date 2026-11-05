# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""MojoBPF build driver: manifests, profiles, toolchain and diagnostics.

This package compiles Mojo-authored Linux eBPF programs into standard
BPF ELF objects through validated toolchains and profiles. It starts
with the frozen contracts: the project manifest model, the
target-profile registry, toolchain discovery with lockfile matching,
and the stable diagnostic vocabulary.
"""

from .diagnostics import Diagnostic, MojobpfError
from .manifest import (
    SUPPORTED_PROFILE_IDS,
    SUPPORTED_PROFILES,
    ArtifactInfo,
    ManifestError,
    MapEntry,
    ProfileError,
    ProgramEntry,
    ProjectInfo,
    ProjectManifest,
    TargetInfo,
    TargetProfile,
    lookup_profile,
    parse_manifest,
)
from .toolchain import (
    ToolchainConfig,
    ToolchainReport,
    ToolInfo,
    probe_toolchain,
)

__version__ = "0.3.0a1"

__all__ = [
    "ArtifactInfo",
    "Diagnostic",
    "ManifestError",
    "MapEntry",
    "MojobpfError",
    "ProfileError",
    "ProgramEntry",
    "ProjectInfo",
    "ProjectManifest",
    "SUPPORTED_PROFILE_IDS",
    "SUPPORTED_PROFILES",
    "TargetInfo",
    "TargetProfile",
    "ToolInfo",
    "ToolchainConfig",
    "ToolchainReport",
    "__version__",
    "lookup_profile",
    "parse_manifest",
    "probe_toolchain",
]
