# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Command line for manifests, builds, inspection and toolchain reports.

Commands (all host-side work is unprivileged; there are deliberately
no host load, run, or attach commands)::

    mojobpf build --manifest mojobpf.toml --out-dir build \\
        [--adapter adapter_service.py] [--lockfile lock.json]
        [--save-temps]
    mojobpf check --manifest mojobpf.toml [--lockfile lock.json] [--json]
    mojobpf doctor [--lockfile lock.json] [--json]
    mojobpf inspect --object prog.bpf.o [--profile linux-bpfel-v3]
        [--source-license S --kernel-license K] [--json]
    mojobpf verify --kernel --object prog.bpf.o [--release v6.12]
        [--prog-type xdp] [--timeout SECS] [--kernels-lock lock.json]
        [--keep-evidence] [--json]

``build`` compiles every program in the manifest through the reusable
:func:`mojobpf.build.build_project` interface and publishes the
objects plus the provenance sidecar. Tools are admitted against the
lockfile before anything compiles. Without ``--adapter`` the
packaged adapter service is used, so installed builds need no
repository-relative paths; an explicit path still selects any other
service. ``check`` validates the manifest, the target profile and
toolchain discovery without writing outputs; without ``--lockfile``
it reports discovery only and says so (pins not validated), while
with ``--lockfile`` it additionally validates the lockfile match.
``doctor`` is informational discovery only: it reports the tool and
SDK versions, platform, toolchain availability, versions, observed
lockfile status, target candidates and kernel-test capability
without changing anything, always exits 0, and never qualifies
pins (only ``check``/``build`` with ``--lockfile`` do that).
``inspect``
describes one object file against a target profile; with both
license flags it additionally runs the declaration gate and judges
the object, otherwise it only reports. ``verify --kernel`` boots one
disposable guest through the ``vng`` runner, loads the object there,
unloads it again, and classifies loader versus verifier failures; it
never loads on the host, never test-runs, and never attaches a hook.

Entry (installed console script)::

    mojobpf <command> ...

(from a checkout, ``PYTHONPATH=src python3 -m mojobpf.cli`` from the
repository root behaves the same).

Supported platform: Linux. Any other operating system is refused
with exit 3 before any command runs (``--help`` still works).

Exit codes: 0 for successful requested work, 2 for usage or manifest
errors, 3 for an unavailable environment (unsupported platform,
missing or broken build tools, lockfile mismatch, missing packaged
adapter, or a ``verify --kernel`` guest that cannot host the object),
4 for a compile, structural, declaration, or kernel-verifier failure,
5 when ``verify --kernel`` proves the loader (not the verifier)
rejected the object, 130 when interrupted (the build path already
removed its partial outputs and kept no partial result; the verify
path already killed the guest runner group and removed its owned
staging unless ``--keep-evidence`` was given).

``verify --kernel`` setup failures are usage failures (exit 2),
not environment failures: a bad flag value, a missing or unreadable
object, an unavailable runner (missing or refused ``vng`` chain),
a missing or unreadable kernels lock, an unlisted release/lane, or
a refused spawn all exit 2 with the cause on stderr. Any failure
after the runner spawns exits 3: a runner that exits before
producing any guest transcript (no guest kernel observed),
preflight unavailable, timeout, permission-denied load, or a
runner fault later in the run; a kernel-verifier rejection exits
4 and a loader rejection exits 5.

Standard library only.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import tempfile
import platform
import re
import shutil
import subprocess
import sys

from . import __version__ as TOOL_VERSION
from .build import BuildRequest, build_project, default_adapter_path
from .diagnostics import Diagnostic
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
from .verify import VerifyError, VerifyInterrupted, VerifyRequest

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_ENVIRONMENT = 3
EXIT_COMPILE = 4
EXIT_VERIFY_LOADER = 5
EXIT_TEST = 6
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
    if args.lockfile is None and not args.json:
        # Discovery without validation must say so on every path:
        # automation must never mistake "ran fine" for "qualified".
        for diagnostic in report.diagnostics:
            if diagnostic.code == "MBPF105":
                sys.stderr.write(
                    "%s\n" % _format_diagnostic(diagnostic)
                )
    broken = [tool for tool in report.tools if tool.status != "present"]
    compile_result = None
    adapter_missing = False
    if args.lockfile is not None and not broken and report.supported:
        # Compilation needs admitted tools, so it runs only with a
        # lockfile; without one check stays a discovery probe.
        adapter = args.adapter
        if adapter is None:
            adapter = default_adapter_path()
            if not os.path.isfile(adapter):
                adapter_missing = True
        if not adapter_missing:
            scratch = tempfile.mkdtemp(prefix="mojobpf-check-")
            try:
                compile_result = build_project(
                    BuildRequest(
                        manifest_path=args.manifest,
                        out_dir=scratch,
                        adapter_path=adapter,
                        lockfile_path=args.lockfile,
                    )
                )
            finally:
                shutil.rmtree(scratch, ignore_errors=True)
    if args.json:
        if compile_result is None:
            compile_verdict = None
        else:
            compile_verdict = {
                "success": compile_result.success,
                "diagnostics": [
                    _format_diagnostic(item)
                    for item in compile_result.diagnostics
                ],
            }
        sys.stdout.write(
            json.dumps(
                {
                    "manifest": dataclasses.asdict(manifest),
                    "toolchain": dataclasses.asdict(report),
                    "compile": compile_verdict,
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
        if args.lockfile is None:
            # Discovery without compilation must say so on stdout
            # too: exit 0 here never means "compiles".
            sys.stdout.write(
                "compile: skipped (no lockfile supplied; pass "
                "--lockfile to compile)\n"
            )
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
    if adapter_missing:
        sys.stderr.write(
            "mojobpf check: packaged adapter not found; "
            "reinstall the mojobpf package or pass --adapter\n"
        )
        return EXIT_ENVIRONMENT
    if compile_result is not None:
        if compile_result.success:
            if not args.json:
                sys.stdout.write(
                    "compile OK: %s (%d program(s))\n"
                    % (manifest.manifest_path, len(manifest.programs))
                )
            return EXIT_OK
        if not args.json:
            for diagnostic in compile_result.diagnostics:
                sys.stderr.write(
                    "%s\n" % _format_diagnostic(diagnostic)
                )
        return _build_exit_code(compile_result)
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
                    "discovery_only": True,
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
        "informational discovery only: pins are qualified by "
        "check/build with --lockfile, never here\n"
    )
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
            "lockfile %s: %s (observed; qualification verdicts "
            "come from check/build)\n"
            % (args.lockfile, report.lockfile_status)
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
    if args.object_pos and args.object:
        sys.stderr.write(
            "mojobpf inspect: --object and OBJECT are mutually exclusive\n"
        )
        return EXIT_USAGE
    args.object = args.object or args.object_pos
    if args.object is None:
        sys.stderr.write(
            "mojobpf inspect: one of --object or OBJECT is required\n"
        )
        return EXIT_USAGE
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
        return (
            EXIT_OK
            if (result.ok or args.report_only)
            else EXIT_COMPILE
        )
    return EXIT_OK if result.ok else EXIT_COMPILE


def _command_verify(args) -> int:
    from .verify import (
        format_summary,
        run_verification,
        verification_diagnostic,
    )

    if args.object_pos and args.object:
        sys.stderr.write(
            "mojobpf verify: --object and OBJECT are mutually exclusive\n"
        )
        return EXIT_USAGE
    args.object = args.object or args.object_pos
    if args.object is None:
        sys.stderr.write(
            "mojobpf verify: one of --object or OBJECT is required\n"
        )
        return EXIT_USAGE
    try:
        request = VerifyRequest(
            object_path=args.object,
            release=args.release,
            accelerator=args.accelerator,
            vng_path=args.vng,
            pin_path=args.pin_path,
            prog_type=args.prog_type,
            map_types=tuple(args.map_type or ()),
            trace_event=args.trace_event,
            require_btf=args.require_btf,
            kernel_btf=args.kernel_btf,
            as_user=args.as_user,
            timeout=args.timeout,
            kernels_lock=args.kernels_lock,
            keep_evidence=args.keep_evidence,
        )
    except VerifyError as exc:
        sys.stderr.write("mojobpf verify: %s\n" % exc)
        return EXIT_USAGE
    try:
        result = run_verification(request)
    except VerifyError as exc:
        sys.stderr.write("mojobpf verify: %s\n" % exc)
        return EXIT_USAGE
    except VerifyInterrupted as exc:
        sys.stderr.write("mojobpf verify: %s\n" % exc)
        return EXIT_INTERRUPTED
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    if args.json:
        sys.stdout.write(text)
    else:
        sys.stdout.write(format_summary(result))
    status = result.get("status")
    classification = result.get("classification")
    if status == "pass":
        return EXIT_OK
    if classification == "environment":
        # Unavailable preflight, timeout, interruption fallout, and
        # permission-denied loads are all environment outcomes.
        return EXIT_ENVIRONMENT
    if status == "load-failed":
        diagnostic = verification_diagnostic(result)
        if diagnostic is not None:
            sys.stderr.write(
                "%s\n" % _format_diagnostic(diagnostic)
            )
        return EXIT_VERIFY_LOADER
    return EXIT_ENVIRONMENT


def _pytest_executed(output: str) -> bool:
    """Return True when pytest output records executed tests.

    Counts ``passed``/``xfailed``/``xpassed`` outcomes from the
    summary counts; a run with none of those (all skipped, or
    nothing collected) executed nothing. Unparseable output
    counts as not executed: under ``--require-kernel`` the
    caller demands proof of execution.
    """
    for match in re.finditer(
        r"(\d+)\s+(passed|xfailed|xpassed)", output
    ):
        if int(match.group(1)) >= 1:
            return True
    return False


def _default_suite_root() -> str:
    return os.path.join(
        os.path.dirname(os.path.dirname(_package_dir())), "tests"
    )


def _command_test(args) -> int:
    suite = args.suite
    if (
        os.sep in suite
        or (os.altsep is not None and os.altsep in suite)
        or ".." in suite
    ):
        sys.stderr.write(
            "mojobpf test: invalid suite name %r\n" % (suite,)
        )
        return EXIT_USAGE
    root = (
        args.suite_path
        if args.suite_path is not None
        else _default_suite_root()
    )
    suitedir = os.path.join(root, suite)
    if not os.path.isdir(suitedir):
        sys.stderr.write(
            "mojobpf test: suite '%s' not found at %s\n"
            % (suite, suitedir)
        )
        if args.suite_path is None:
            sys.stderr.write(
                "mojobpf test: the test corpus ships with the "
                "project checkout, not the installed package; "
                "pass --suite-path\n"
            )
        return EXIT_USAGE
    if suite == "kernel" and shutil.which("vng") is None:
        if args.require_kernel:
            sys.stderr.write(
                "mojobpf test: suite 'kernel' requires the vng "
                "guest runner on PATH (--require-kernel)\n"
            )
            return EXIT_ENVIRONMENT
        sys.stdout.write(
            "mojobpf test: suite 'kernel' skipped: vng guest "
            "runner not on PATH\n"
        )
        return EXIT_OK
    try:
        import pytest  # noqa: F401
    except ImportError:
        sys.stderr.write(
            "mojobpf test: pytest is not installed; cannot run "
            "suite '%s'\n" % (suite,)
        )
        return EXIT_ENVIRONMENT
    proc = subprocess.run(
        [
            sys.executable, "-m", "pytest", suitedir,
            "-q", "-p", "no:cacheprovider",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    sys.stdout.write(proc.stdout)
    if proc.returncode == 0:
        if (
            args.require_kernel
            and suite == "kernel"
            and not _pytest_executed(proc.stdout)
        ):
            sys.stderr.write(
                "mojobpf test: suite 'kernel' requires executed "
                "kernel tests (--require-kernel), but every test "
                "skipped\n"
            )
            return EXIT_ENVIRONMENT
        return EXIT_OK
    sys.stderr.write(
        "%s\n"
        % _format_diagnostic(
            Diagnostic(
                code="MBPF601",
                stage="test.run",
                severity="error",
                explanation=(
                    "test suite '%s' failed (pytest exit %d); "
                    "the full suite output is shown above"
                    % (suite, proc.returncode)
                ),
                location=suitedir,
                remedy="fix the failing tests and re-run mojobpf test",
            )
        )
    )
    return EXIT_TEST


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
        help="pinned toolchain lockfile for tool admission "
        "(required: the build fails without one)",
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
        "--adapter",
        default=None,
        help="adapter service script "
        "(default: the packaged adapter)",
    )
    check.add_argument(
        "--lockfile",
        default=None,
        help="pinned toolchain lockfile to validate against "
        "(default: none; discovery without validation)",
    )
    check.add_argument(
        "--json", action="store_true", help="print a JSON report"
    )
    check.set_defaults(func=_command_check)

    doctor = sub.add_parser("doctor", help="report toolchain status")
    doctor.add_argument(
        "--lockfile",
        default=None,
        help="pinned toolchain lockfile to match against "
        "(default: none; discovery only)",
    )
    doctor.add_argument(
        "--json", action="store_true", help="print a JSON report"
    )
    doctor.set_defaults(func=_command_doctor)

    inspect = sub.add_parser(
        "inspect", help="describe an object file against a profile"
    )
    inspect.add_argument(
        "--object", required=False, help="object file to inspect"
    )
    inspect.add_argument(
        "object_pos",
        nargs="?",
        default=None,
        help="object file to inspect (positional alias for --object)",
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
    inspect.add_argument(
        "--report-only",
        action="store_true",
        help="print findings but exit 0 even when findings are present",
    )
    inspect.set_defaults(func=_command_inspect)

    verify = sub.add_parser(
        "verify",
        help="load/unload an object in a disposable guest (never attach)",
    )
    verify.add_argument(
        "--kernel",
        action="store_true",
        required=True,
        help="run the guest load-and-unload check",
    )
    verify.add_argument(
        "--object",
        required=False,
        help="object file to load in the guest",
    )
    verify.add_argument(
        "object_pos",
        nargs="?",
        default=None,
        help="object file to load (positional alias for --object)",
    )
    verify.add_argument(
        "--release",
        default=None,
        help="guest kernel release "
        "(default: $MOJOBPF_VNG_RELEASE or v6.12)",
    )
    verify.add_argument(
        "--accelerator",
        default="tcg",
        choices=("tcg", "kvm"),
        help="guest acceleration (default: tcg)",
    )
    verify.add_argument(
        "--vng",
        default=None,
        help="runner binary (default: vng on PATH)",
    )
    verify.add_argument(
        "--kernels-lock",
        default=None,
        help="kernels lockfile pinning the runner and lanes "
        "(default: the checkout's ci/kernels.lock.json)",
    )
    verify.add_argument(
        "--keep-evidence",
        action="store_true",
        help="keep the owned stage and PATH farm instead of "
        "removing them (default: remove on success, failure "
        "and interruption)",
    )
    verify.add_argument(
        "--pin-path",
        default="/sys/fs/bpf/mojobpf_verify",
        help="guest pin path for the load",
    )
    verify.add_argument(
        "--prog-type",
        default="xdp",
        help="required guest program type "
        "(preflight; default: xdp)",
    )
    verify.add_argument(
        "--map-type",
        dest="map_type",
        action="append",
        default=None,
        help="required guest map type (preflight; repeatable)",
    )
    verify.add_argument(
        "--trace-event",
        default=None,
        help="required guest trace event as category:name (preflight)",
    )
    verify.add_argument(
        "--require-btf",
        default="auto",
        choices=("auto", "yes", "no"),
        help="require guest kernel BTF (auto: when the object "
        "carries BTF sections)",
    )
    verify.add_argument(
        "--kernel-btf",
        default="/sys/kernel/btf/vmlinux",
        help="guest kernel BTF path to check",
    )
    verify.add_argument(
        "--as-user",
        default=None,
        help="load as this guest user instead of root",
    )
    verify.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="guest command budget in seconds",
    )
    verify.add_argument(
        "--output", default=None, help="write the JSON result here too"
    )
    verify.add_argument(
        "--json", action="store_true", help="print the JSON result"
    )
    verify.set_defaults(func=_command_verify)

    test = sub.add_parser(
        "test", help="run a project test suite (developer command)"
    )
    test.add_argument(
        "--suite", required=True, help="suite name (e.g. compile, kernel)"
    )
    test.add_argument(
        "--suite-path",
        default=None,
        help="test tree root holding <suite>/ "
        "(default: the checked-out project's tests/)",
    )
    test.add_argument(
        "--require-kernel",
        action="store_true",
        help="fail when kernel execution is unavailable, or no "
        "kernel test executes, instead of skipping",
    )
    test.set_defaults(func=_command_test)
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
