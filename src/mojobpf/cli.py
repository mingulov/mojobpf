# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Minimal command line for manifests, builds and toolchain reports.

Commands (all unprivileged; there are deliberately no run, load or
attach commands)::

    mojobpf build --manifest mojobpf.toml --out-dir build \\
        --adapter compiler/adapter_service.py [--save-temps]
    mojobpf check --manifest mojobpf.toml [--json]
    mojobpf doctor [--json]

``build`` compiles every program in the manifest through the reusable
:func:`mojobpf.build.build_project` interface and publishes the
objects. ``check`` validates the manifest, the target profile and
toolchain discovery without writing outputs. ``doctor`` reports
toolchain availability, versions, target candidates and kernel-test
capability without changing anything.

Entry until packaging owns a console script::

    PYTHONPATH=src python3 -m mojobpf.cli <command> ...

(run from the repository root; with an installed package the
``PYTHONPATH`` prefix is unnecessary).

Exit codes: 0 for successful requested work, 2 for usage or manifest
errors, 3 for an unavailable environment (missing or broken build
tools), 4 for a compile or structural failure, 130 when interrupted
(the build path already removed its partial outputs).

Standard library only.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import shutil
import sys

from .build import BuildRequest, build_project
from .manifest import (
    SUPPORTED_PROFILE_IDS,
    ManifestError,
    ProfileError,
    parse_manifest,
)
from .toolchain import ToolchainConfig, probe_toolchain

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_ENVIRONMENT = 3
EXIT_COMPILE = 4
EXIT_INTERRUPTED = 130

# Diagnostic codes that mean the manifest (or its profile request)
# is unusable: exit 2. Every other failure -- including MBPF212, a
# malformed adapter response or driver-built bad request -- is a
# compile or structural failure and maps to exit 4.
MANIFEST_EXIT_CODES = frozenset(
    ["MBPF101"] + ["MBPF%03d" % code for code in range(201, 212)]
)


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
        if code == "MBPF103":
            return EXIT_ENVIRONMENT
    return EXIT_COMPILE


def _command_build(args) -> int:
    try:
        request = BuildRequest(
            manifest_path=args.manifest,
            out_dir=args.out_dir,
            adapter_path=args.adapter,
            save_temps=args.save_temps,
        )
    except ValueError as exc:
        sys.stderr.write("mojobpf build: %s\n" % exc)
        return EXIT_USAGE
    try:
        result = build_project(request)
    except KeyboardInterrupt:
        sys.stderr.write(
            "mojobpf build: interrupted; partial outputs removed\n"
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
    report = probe_toolchain(ToolchainConfig())
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
    return EXIT_OK


def _command_doctor(args) -> int:
    report = probe_toolchain(ToolchainConfig())
    guest_tool = shutil.which("vng")
    kernel_capable = guest_tool is not None
    if args.json:
        sys.stdout.write(
            json.dumps(
                {
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
    for tool in report.tools:
        if tool.status == "present":
            sys.stdout.write(
                "tool %s: present %s at %s\n"
                % (tool.name, tool.version, tool.path)
            )
        else:
            sys.stdout.write("tool %s: %s\n" % (tool.name, tool.status))
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mojobpf", description="MojoBPF build driver"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="build a project manifest")
    build.add_argument("--manifest", required=True, help="manifest file")
    build.add_argument("--out-dir", required=True, help="output directory")
    build.add_argument(
        "--adapter", required=True, help="adapter service script"
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
        "--json", action="store_true", help="print a JSON report"
    )
    check.set_defaults(func=_command_check)

    doctor = sub.add_parser("doctor", help="report toolchain status")
    doctor.add_argument(
        "--json", action="store_true", help="print a JSON report"
    )
    doctor.set_defaults(func=_command_doctor)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
