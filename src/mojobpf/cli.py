# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Command line for manifests, builds, inspection and toolchain reports.

Commands (all unprivileged; there are deliberately no run, load or
attach commands)::

    mojobpf build --manifest mojobpf.toml --out-dir build \\
        [--adapter adapter_service.py] [--lockfile lock.json]
        [--save-temps]
    mojobpf check --manifest mojobpf.toml [--lockfile lock.json] [--json]
    mojobpf doctor [--lockfile lock.json] [--json]
    mojobpf inspect --object prog.bpf.o [--profile linux-bpfel-v3]
        [--source-license S --kernel-license K] [--json]

``build`` compiles every program in the manifest through the reusable
:func:`mojobpf.build.build_project` interface and publishes the
objects plus the provenance sidecar. Tools are admitted against the
lockfile before anything compiles. Without ``--adapter`` the
packaged adapter service is used, so installed builds need no
repository-relative paths; an explicit path still selects any other
service. ``check`` validates the manifest, the target profile and
toolchain discovery without writing outputs, and additionally
validates the lockfile match when ``--lockfile`` is given.
``doctor`` reports the tool and SDK versions, platform, toolchain
availability, versions, lockfile match status, target candidates
and kernel-test capability without changing anything. ``inspect``
describes one object file against a target profile; with both
license flags it additionally runs the declaration gate and judges
the object, otherwise it only reports.

Entry (installed console script)::

    mojobpf <command> ...

(from a checkout, ``PYTHONPATH=src python3 -m mojobpf.cli`` from the
repository root behaves the same).

Supported platform: Linux. Any other operating system is refused
with exit 3 before any command runs (``--help`` still works).

Exit codes: 0 for successful requested work, 2 for usage or manifest
errors, 3 for an unavailable environment (unsupported platform,
missing or broken build tools, lockfile mismatch, missing packaged
adapter), 4 for a compile, structural, or declaration failure, 130
when interrupted (the build path already removed its partial
outputs and kept no partial result).

Standard library only.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import platform
import shutil
import sys

from . import __version__ as TOOL_VERSION
from .build import BuildRequest, build_project, default_adapter_path
from .evidence import publication_recovery
from .inspect import InspectionError, inspect_object, verify_object
from .manifest import (
    SUPPORTED_PROFILE_IDS,
    ManifestError,
    ProfileError,
    lookup_profile,
    parse_manifest,
)
from .sdk import SDK_VERSION
from .toolchain import ToolchainConfig, probe_toolchain

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_ENVIRONMENT = 3
EXIT_COMPILE = 4
EXIT_INTERRUPTED = 130

# Diagnostic codes that mean the manifest (or its profile request)
# is unusable: exit 2. MBPF212 stays a compile failure (exit 4):
# a malformed adapter response or driver-built bad request is not a
# manifest-meaning error. MBPF102/104 (pin mismatch, lockfile
# problem) mean the environment is unusable: exit 3.
MANIFEST_EXIT_CODES = frozenset(
    ["MBPF101"]
    + ["MBPF%03d" % code for code in range(201, 212)]
    + ["MBPF%03d" % code for code in range(213, 217)]
)
ENVIRONMENT_EXIT_CODES = frozenset(["MBPF102", "MBPF103", "MBPF104"])


def _format_diagnostic(diagnostic) -> str:
    parts = [
        "%s (%s/%s): %s"
        % (
            diagnostic.code,
            diagnostic.stage,
            diagnostic.severity,
            diagnostic.explanation,
        )
    ]
    if diagnostic.location:
        parts.append("location: %s" % diagnostic.location)
    if diagnostic.remedy:
        parts.append("remedy: %s" % diagnostic.remedy)
    return "; ".join(parts)


def _build_exit_code(result) -> int:
    if result.success:
        return EXIT_OK
    for diagnostic in result.diagnostics:
        code = diagnostic.code
        if code in MANIFEST_EXIT_CODES:
            return EXIT_USAGE
        if code in ENVIRONMENT_EXIT_CODES:
            return EXIT_ENVIRONMENT
    return EXIT_COMPILE


def _command_build(args) -> int:
    adapter = args.adapter
    if adapter is None:
        adapter = default_adapter_path()
        if not os.path.isfile(adapter):
            sys.stderr.write(
                "mojobpf build: packaged adapter not found at %s; "
                "reinstall the mojobpf package or pass --adapter\n"
                % adapter
            )
            return EXIT_ENVIRONMENT
    try:
        request = BuildRequest(
            manifest_path=args.manifest,
            out_dir=args.out_dir,
            adapter_path=adapter,
            save_temps=args.save_temps,
            lockfile_path=args.lockfile,
        )
    except ValueError as exc:
        sys.stderr.write("mojobpf build: %s\n" % exc)
        return EXIT_USAGE
    try:
        result = build_project(request)
    except KeyboardInterrupt as interrupted:
        recovery = publication_recovery(interrupted)
        if recovery is not None and not recovery.complete:
            sys.stderr.write(
                "mojobpf build: interrupted; rollback incomplete: "
                "predecessors not restored: %s; restore them from "
                "the retained recovery backups, then republish\n"
                % "; ".join(recovery.failures)
            )
        else:
            sys.stderr.write(
                "mojobpf build: interrupted; partial outputs removed, "
                "no partial result kept\n"
            )
        return EXIT_INTERRUPTED
    if result.success:
        for artifact in result.artifacts:
            sys.stdout.write(
                "built %s (%d bytes, sha256 %s)\n"
                % (artifact.path, artifact.size, artifact.sha256)
            )
        if result.work_dir is not None:
            sys.stdout.write("temps kept at %s\n" % result.work_dir)
        for diagnostic in result.diagnostics:
            sys.stdout.write("%s\n" % _format_diagnostic(diagnostic))
        return EXIT_OK
    for diagnostic in result.diagnostics:
        sys.stderr.write("%s\n" % _format_diagnostic(diagnostic))
    if result.work_dir is not None:
        sys.stderr.write("temps kept at %s\n" % result.work_dir)
    return _build_exit_code(result)


def _command_check(args) -> int:
    try:
        manifest = parse_manifest(args.manifest)
    except (ManifestError, ProfileError) as exc:
        sys.stderr.write("%s\n" % _format_diagnostic(exc.diagnostic))
        return EXIT_USAGE
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=args.lockfile)
    )
    if args.json:
        sys.stdout.write(
            json.dumps(
                {
                    "manifest": dataclasses.asdict(manifest),
                    "toolchain": dataclasses.asdict(report),
                },
                indent=2,
                sort_keys=True,
            )
        )
        sys.stdout.write("\n")
    else:
        sys.stdout.write(
            "manifest OK: %s (profile %s, %d program(s), %d map(s))\n"
            % (
                manifest.manifest_path,
                manifest.target.profile,
                len(manifest.programs),
                len(manifest.maps),
            )
        )
        for tool in report.tools:
            if tool.status == "present":
                sys.stdout.write(
                    "tool %s: present (%s)\n" % (tool.name, tool.version)
                )
            else:
                sys.stdout.write("tool %s: %s\n" % (tool.name, tool.status))
    broken = [tool for tool in report.tools if tool.status != "present"]
    if broken:
        if not args.json:
            for diagnostic in report.diagnostics:
                if diagnostic.code == "MBPF103":
                    sys.stderr.write(
                        "%s\n" % _format_diagnostic(diagnostic)
                    )
        return EXIT_ENVIRONMENT
    if args.lockfile is not None and not report.supported:
        if not args.json:
            for diagnostic in report.diagnostics:
                if diagnostic.code in (
                    "MBPF102", "MBPF104", "MBPF105",
                ):
                    sys.stderr.write(
                        "%s\n" % _format_diagnostic(diagnostic)
                    )
        return EXIT_ENVIRONMENT
    return EXIT_OK


def _package_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def _command_doctor(args) -> int:
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=args.lockfile)
    )
    guest_tool = shutil.which("vng")
    kernel_capable = guest_tool is not None
    host = "%s/%s" % (sys.platform, platform.machine())
    if args.json:
        sys.stdout.write(
            json.dumps(
                {
                    "mojobpf_version": TOOL_VERSION,
                    "sdk_version": SDK_VERSION,
                    "package_path": _package_dir(),
                    "platform": host,
                    "toolchain": dataclasses.asdict(report),
                    "kernel_test_runner": guest_tool,
                    "kernel_test_capable": kernel_capable,
                },
                indent=2,
                sort_keys=True,
            )
        )
        sys.stdout.write("\n")
        return EXIT_OK
    sys.stdout.write("mojobpf doctor\n")
    sys.stdout.write(
        "mojobpf %s (sdk %s) at %s\n"
        % (TOOL_VERSION, SDK_VERSION, _package_dir())
    )
    sys.stdout.write("platform: %s\n" % host)
    for tool in report.tools:
        if tool.status == "present":
            sys.stdout.write(
                "tool %s: present %s at %s\n"
                % (tool.name, tool.version, tool.path)
            )
        else:
            sys.stdout.write("tool %s: %s\n" % (tool.name, tool.status))
    if args.lockfile is not None:
        sys.stdout.write(
            "lockfile %s: %s\n" % (args.lockfile, report.lockfile_status)
        )
    sys.stdout.write(
        "target candidates: %s\n" % ", ".join(SUPPORTED_PROFILE_IDS)
    )
    if kernel_capable:
        sys.stdout.write(
            "kernel tests: runner available at %s\n" % guest_tool
        )
    else:
        sys.stdout.write(
            "kernel tests: no runner on PATH "
            "(compile-only work is unaffected)\n"
        )
    return EXIT_OK


def _command_inspect(args) -> int:
    try:
        profile = lookup_profile(args.profile)
    except ProfileError as exc:
        sys.stderr.write("%s\n" % _format_diagnostic(exc.diagnostic))
        return EXIT_USAGE
    if (args.source_license is None) != (args.kernel_license is None):
        sys.stderr.write(
            "mojobpf inspect: --source-license and --kernel-license "
            "must be given together\n"
        )
        return EXIT_USAGE
    try:
        if args.source_license is None:
            result = inspect_object(args.object, profile)
        else:
            result = verify_object(
                args.object,
                profile,
                args.source_license,
                args.kernel_license,
            )
    except InspectionError as exc:
        sys.stderr.write("%s\n" % _format_diagnostic(exc.diagnostic))
        return EXIT_COMPILE
    if args.json:
        sys.stdout.write(
            json.dumps(result.to_dict(), indent=2, sort_keys=True)
        )
        sys.stdout.write("\n")
    else:
        sys.stdout.write(
            "object %s (profile %s): %s\n"
            % (
                args.object,
                result.profile_id,
                "ok" if result.ok else "findings present",
            )
        )
        for bucket in (
            result.structural, result.unsupported, result.license,
        ):
            for diagnostic in bucket:
                sys.stdout.write(
                    "%s\n" % _format_diagnostic(diagnostic)
                )
        for observation in result.observations:
            if observation.location:
                sys.stdout.write(
                    "observation %s: %s\n"
                    % (observation.location, observation.explanation)
                )
            else:
                sys.stdout.write(
                    "observation: %s\n" % observation.explanation
                )
    if args.source_license is None:
        return EXIT_OK
    return EXIT_OK if result.ok else EXIT_COMPILE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mojobpf", description="MojoBPF build driver"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="build a project manifest")
    build.add_argument("--manifest", required=True, help="manifest file")
    build.add_argument("--out-dir", required=True, help="output directory")
    build.add_argument(
        "--adapter",
        default=None,
        help="adapter service script "
        "(default: the packaged adapter)",
    )
    build.add_argument(
        "--lockfile",
        default=None,
        help="pinned toolchain lockfile for tool admission",
    )
    build.add_argument(
        "--save-temps",
        action="store_true",
        help="keep the per-build work directory",
    )
    build.set_defaults(func=_command_build)

    check = sub.add_parser(
        "check", help="validate a manifest and the toolchain"
    )
    check.add_argument("--manifest", required=True, help="manifest file")
    check.add_argument(
        "--lockfile",
        default=None,
        help="pinned toolchain lockfile to validate against",
    )
    check.add_argument(
        "--json", action="store_true", help="print a JSON report"
    )
    check.set_defaults(func=_command_check)

    doctor = sub.add_parser("doctor", help="report toolchain status")
    doctor.add_argument(
        "--lockfile",
        default=None,
        help="pinned toolchain lockfile to match against",
    )
    doctor.add_argument(
        "--json", action="store_true", help="print a JSON report"
    )
    doctor.set_defaults(func=_command_doctor)

    inspect = sub.add_parser(
        "inspect", help="describe an object file against a profile"
    )
    inspect.add_argument(
        "--object", required=True, help="object file to inspect"
    )
    inspect.add_argument(
        "--profile",
        default="linux-bpfel-v3",
        help="target profile (default: linux-bpfel-v3)",
    )
    inspect.add_argument(
        "--source-license",
        default=None,
        help="declared source grant "
        "(with --kernel-license, runs the declaration gate)",
    )
    inspect.add_argument(
        "--kernel-license",
        default=None,
        help="declared kernel license string "
        "(with --source-license, runs the declaration gate)",
    )
    inspect.add_argument(
        "--json", action="store_true", help="print a JSON report"
    )
    inspect.set_defaults(func=_command_inspect)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if sys.platform != "linux":
        sys.stderr.write(
            "mojobpf: unsupported platform %r: Linux is required; "
            "see the installation documentation for the "
            "qualified host\n" % (sys.platform,)
        )
        return EXIT_ENVIRONMENT
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
