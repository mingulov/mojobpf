# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Optimization-setting invariants: release is pinned, the rest explicit.

The build driver invokes the frontend with fixed release flags
(``mojo build --emit llvm``, the compiler default) and the backend
with fixed flags (``llc -mtriple=bpfel -mcpu=v3 -filetype=obj``).
There is no optimization knob anywhere on that route, so no setting
can be silently changed: this suite proves the supported settings
produce identical audit-passing IR, that every unsupported setting
fails loudly with its own evidence, and that the driver records
exactly the pinned invocations.

Covered matrix (canonical classifier and map programs, genuine
frontend output):

* supported: default flags, byte-identical to explicit ``-O1``,
  ``-O2`` and ``-O3``; every output validates with its expected mode;
* unsupported, rejected by the preflight audit: ``-O0`` and
  ``--no-optimization`` (``MBPF310``: unoptimized IR keeps stack
  allocations);
* unsupported, rejected by the preflight audit: ``-g`` (``MBPF302``:
  debug metadata changes the entrypoint header);
* unsupported, rejected by the frontend itself:
  ``--target-triple`` (no BPF target info in the host compiler).

Driver pins: a real ``build_project`` run records a frontend command
without any optimization, debug or target spelling and a backend
command spelling exactly the pinned triple/cpu/filetype with no
``-O`` or ``-mllvm`` widening; the request model carries no
optimization field. The backend flags are load-bearing (``llc -O0``
emits a different object), so pinning them matters. A backend
failure surfaces explicitly (``MBPF106`` at ``build.backend``),
demonstrated with the excessive-frame subset program.

Requires the working Mojo compiler and LLVM ``llc`` on PATH plus the
repository lockfile (tool admission). A missing tool is reported as
an environment failure; a wrong verdict is a proof failure. Neither
ever passes.

Runnable directly (``python3
tests/ir/test_optimization_invariants.py``) or under any
``test_``-style runner. Standard library only.
"""

import os
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "compiler"))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

import audit
from mojobpf.build import BuildRequest, build_project

CLASSIFIER_SOURCE = os.path.join(
    REPO_ROOT, "examples", "xdp_pass", "xdp_pass.mojo"
)
MAP_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "map_roundtrip.mojo"
)
STACK_ARRAY_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "subset", "subset_stack_array.mojo"
)
DEEP_STACK_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "subset", "subset_deep_stack.mojo"
)
SDK_INCLUDE = os.path.join(
    REPO_ROOT, "src", "mojobpf", "resources", "sdk"
)
SERVICE = os.path.join(REPO_ROOT, "compiler", "adapter_service.py")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
LOCKFILE = os.path.join(REPO_ROOT, "toolchains.lock.json")

STAGE = "adapter.audit"

# The only supported optimization spellings: the driver default plus
# the explicit levels the qualified frontend maps to identical IR.
RELEASE_LEVELS = ("-O1", "-O2", "-O3")

# Spellings the recorded driver invocations must never contain.
FORBIDDEN_FRONTEND_FLAGS = (
    "-O0", "-O1", "-O2", "-O3", "-O",
    "--no-optimization", "--optimization-level",
    "-g", "-g0", "-g1", "-g2", "--debug-level",
    "--target-triple", "--target-cpu",
)
FORBIDDEN_BACKEND_FLAGS = ("-O0", "-O1", "-O2", "-O3", "-O", "-mllvm")

TARGET_TRIPLE_ERROR = "No available targets are compatible"
BACKEND_STACK_ERROR = "BPF stack limit is exceeded"

MANIFEST_TEMPLATE = """\
schema_version = 1

[project]
name = "{project}"

[target]
profile = "linux-bpfel-v3"
core = false

[artifact]
name = "{artifact}"
source_license = "Apache-2.0 WITH LLVM-exception"
kernel_license = "Apache-2.0 WITH LLVM-exception"

[[programs]]
source = "{source}"
entry = "{entry}"
program_type = "xdp"
section = "xdp"
{maps}"""

MAPS_BLOCK = """\
[[maps]]
name = "mojobpf_map0"
map_type = "array"
key_type = "u32"
value_type = "u64"
max_entries = 1
"""


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def check_tools():
    for tool in ("mojo", "llc"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (
        CLASSIFIER_SOURCE, MAP_SOURCE, STACK_ARRAY_SOURCE,
        DEEP_STACK_SOURCE, SDK_INCLUDE, SERVICE, ADAPTER, LOCKFILE,
    ):
        if not os.path.exists(path):
            raise EnvironmentFailure("missing repo path: %s" % path)


def mojo_emit(source, extra_args=()):
    """Compile one Mojo source to IR; return (proc, text or None)."""
    if shutil.which("mojo") is None:
        raise EnvironmentFailure("mojo compiler not found on PATH")
    workdir = tempfile.mkdtemp(prefix="opt-invariants-")
    out_path = os.path.join(workdir, "out.ll")
    argv = (
        ["mojo", "build", "--emit", "llvm"]
        + list(extra_args)
        + ["-I", SDK_INCLUDE, "-o", out_path, source]
    )
    proc = subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0 or not os.path.isfile(out_path):
        return proc, None
    with open(out_path, "r", encoding="utf-8") as handle:
        return proc, handle.read()


def assert_rejected(text, code, stage):
    try:
        audit.validate(text)
    except audit.AuditError as exc:
        assert exc.code == code, (
            "expected code %s, got %s (%s)" % (code, exc.code, exc)
        )
        assert exc.stage == stage, (
            "expected stage %s, got %s" % (stage, exc.stage)
        )
        return exc
    raise AssertionError(
        "audit accepted input it must reject with %s" % code
    )


def test_release_settings_identical():
    """Default flags equal -O1/-O2/-O3 and all outputs validate."""
    check_tools()
    for source, mode in (
        (CLASSIFIER_SOURCE, "classifier"),
        (MAP_SOURCE, "map"),
    ):
        _, default_text = mojo_emit(source)
        assert default_text is not None, (
            "default frontend run failed for %s" % source
        )
        assert audit.validate(default_text) == mode
        for level in RELEASE_LEVELS:
            _, level_text = mojo_emit(source, extra_args=(level,))
            assert level_text is not None, (
                "%s frontend run failed for %s" % (level, source)
            )
            assert level_text == default_text, (
                "%s output differs from the default for %s"
                % (level, os.path.basename(source))
            )
            assert audit.validate(level_text) == mode
        print(
            "PASS %s: default == %s, mode %s"
            % (os.path.basename(source), "/".join(RELEASE_LEVELS), mode)
        )


def test_no_optimization_rejected_explicitly():
    """-O0 keeps stack allocations; the audit refuses them loudly."""
    check_tools()
    for spelling in ("-O0", "--no-optimization"):
        _, text = mojo_emit(STACK_ARRAY_SOURCE, extra_args=(spelling,))
        assert text is not None, (
            "%s frontend run failed unexpectedly" % spelling
        )
        exc = assert_rejected(text, "MBPF310", STAGE)
        assert "alloca" in exc.explanation, (
            "MBPF310 must name the stack allocation"
        )
        print("PASS %s -> MBPF310 (%s)" % (spelling, exc.location))


def test_debug_info_rejected_explicitly():
    """-g changes the entrypoint header; the audit refuses it loudly."""
    check_tools()
    _, text = mojo_emit(CLASSIFIER_SOURCE, extra_args=("-g",))
    assert text is not None, "-g frontend run failed unexpectedly"
    exc = assert_rejected(text, "MBPF302", STAGE)
    print("PASS -g -> MBPF302 (%s)" % exc.location)


def test_target_override_rejected_explicitly():
    """Triple overrides fail in the frontend, never silently."""
    check_tools()
    proc, text = mojo_emit(
        CLASSIFIER_SOURCE,
        extra_args=("--target-triple", "bpfel-unknown-none"),
    )
    assert proc.returncode != 0, (
        "frontend must reject a foreign target triple"
    )
    assert text is None, "rejected run must emit no IR"
    assert TARGET_TRIPLE_ERROR in (proc.stderr or ""), (
        "frontend must name the missing target, got:\n%s"
        % (proc.stderr or "")[-800:]
    )
    print("PASS --target-triple rejected at source")


def write_project(source, with_maps=False):
    parent = tempfile.mkdtemp(prefix="opt-driver-")
    root = os.path.join(parent, "proj")
    os.makedirs(root)
    filename = os.path.basename(source)
    shutil.copyfile(source, os.path.join(root, filename))
    manifest_path = os.path.join(root, "mojobpf.toml")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(
            MANIFEST_TEMPLATE.format(
                project="opt-proj",
                artifact="opt_obj",
                source=filename,
                entry="xdp_entry",
                maps=MAPS_BLOCK if with_maps else "",
            )
        )
    return manifest_path, os.path.join(root, "out")


def test_driver_pins_release_invocation():
    """The driver records exactly the pinned flags and offers no knob."""
    check_tools()
    assert "optimization" not in BuildRequest.__dataclass_fields__, (
        "BuildRequest must carry no optimization setting to change"
    )
    manifest_path, out_dir = write_project(CLASSIFIER_SOURCE)
    result = build_project(
        BuildRequest(
            manifest_path=manifest_path,
            out_dir=out_dir,
            adapter_path=SERVICE,
            lockfile_path=LOCKFILE,
        )
    )
    assert result.success is True, result.diagnostics
    stages = [record.stage for record in result.commands]
    assert stages == [
        "build.frontend", "build.adapter", "build.backend",
    ], stages
    frontend = result.commands[0].argv
    assert frontend[1:4] == ("build", "--emit", "llvm"), frontend
    for flag in FORBIDDEN_FRONTEND_FLAGS:
        assert flag not in frontend, (
            "recorded frontend invocation must not contain %r: %r"
            % (flag, frontend)
        )
    backend = result.commands[2].argv
    assert backend[1:4] == (
        "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
    ), backend
    for flag in FORBIDDEN_BACKEND_FLAGS:
        assert flag not in backend, (
            "recorded backend invocation must not contain %r: %r"
            % (flag, backend)
        )
    print("PASS driver records exactly the pinned invocations")


def test_backend_flags_load_bearing():
    """Unpinned backend flags change the object, so pinning matters."""
    check_tools()
    workdir = tempfile.mkdtemp(prefix="opt-backend-")
    raw_path = os.path.join(workdir, "raw.ll")
    adapted_path = os.path.join(workdir, "adapted.bpf.ll")
    _, text = mojo_emit(CLASSIFIER_SOURCE)
    assert text is not None
    with open(raw_path, "w", encoding="utf-8") as handle:
        handle.write(text)
    proc = subprocess.run(
        [sys.executable, ADAPTER,
         "--input", raw_path, "--output", adapted_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=600,
    )
    assert proc.returncode == 0 and os.path.isfile(adapted_path), (
        "adapter failed (exit %d):\n%s" % (proc.returncode, proc.stderr)
    )
    pinned_path = os.path.join(workdir, "pinned.bpf.o")
    relaxed_path = os.path.join(workdir, "relaxed.bpf.o")
    for extra, target in (([], pinned_path), (["-O0"], relaxed_path)):
        proc = subprocess.run(
            ["llc", "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj"]
            + extra + [adapted_path, "-o", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600,
        )
        assert proc.returncode == 0 and os.path.isfile(target), (
            "llc %s failed (exit %d):\n%s"
            % (" ".join(extra) or "pinned", proc.returncode, proc.stderr)
        )
    with open(pinned_path, "rb") as handle:
        pinned = handle.read()
    with open(relaxed_path, "rb") as handle:
        relaxed = handle.read()
    assert pinned != relaxed, (
        "backend optimization flags must be load-bearing"
    )
    print(
        "PASS pinned backend object differs from llc -O0 "
        "(%d vs %d bytes)" % (len(pinned), len(relaxed))
    )


def test_backend_failure_surfaced_explicitly():
    """An excessive frame fails the driver build with its own code."""
    check_tools()
    # The manifest declares the map only so the driver passes the
    # packaged SDK import path (it does so exactly when maps are
    # declared); the program itself is a classifier, and the build
    # stops at the backend failure before map reconciliation runs.
    manifest_path, out_dir = write_project(DEEP_STACK_SOURCE, True)
    result = build_project(
        BuildRequest(
            manifest_path=manifest_path,
            out_dir=out_dir,
            adapter_path=SERVICE,
            lockfile_path=LOCKFILE,
        )
    )
    assert result.success is False, "excessive frame must fail the build"
    assert result.artifacts == (), "failing build reported artifacts"
    codes = [(item.code, item.stage) for item in result.diagnostics]
    assert ("MBPF106", "build.backend") in codes, (
        "backend failure must surface as MBPF106 at build.backend, "
        "got %r" % (codes,)
    )
    backend = result.commands[-1]
    assert backend.stage == "build.backend"
    assert backend.status == "failed", backend.status
    assert BACKEND_STACK_ERROR in (backend.log_excerpt or ""), (
        "backend record must retain the stack-limit error"
    )
    print("PASS excessive frame -> MBPF106 at build.backend")


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    names = sorted(k for k in globals() if k.startswith("test_"))
    for name in names:
        try:
            globals()[name]()
        except EnvironmentFailure as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            return 2
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
        else:
            print("PASS %s" % name)
    if failures:
        return 1
    print("optimization invariants: release pinned, the rest explicit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
