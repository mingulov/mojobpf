# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Diagnostic catalog: every code pins its exact rendering plus controls.

For each stable ``MBPF`` code the suite proves three things:

* the trigger refuses with exactly this code at its stage, and the
  rendered diagnostic (code, stage, severity, explanation,
  location, remedy) matches the pinned string character for
  character after temporary-path normalization;
* a neighboring-valid control still passes, so no diagnostic can
  mask a regression;
* driver-path audit refusals (``MBPF3xx`` reached through
  ``build_project``) carry an accurate source ``file:line`` plus
  the offending source excerpt, mapped through verified line
  tables; direct-audit IR probes keep their IR line locations.

Trigger layers: manifest/toolchain/gate/license/evidence codes run
against the library directly (no toolchain needed for those
cases); audit ``MBPF3xx`` codes with a genuine Mojo spelling plus
the build-step codes (``MBPF106``/``MBPF107``/``MBPF216``/``MBPF218``) run
through the genuine driver; object codes (``MBPF4xx``) run against
synthetic ELF images shared with the artifact-contract suite.
Seven audit codes have no Mojo spelling (the frontend cannot emit
their shapes, or only rejected flag combinations produce them):
they pin the IR-level rendering with a one-line neighboring-valid
IR mutant each. ``MBPF301`` is an adapter-internal consistency
check (never a program finding) and pins its direct-call form.

Requires the working Mojo compiler and LLVM ``llc`` on PATH for
the driver cases. A missing tool is reported as an environment
failure; a wrong verdict or rendering is a proof failure. Neither
ever passes.

Runnable directly (``python3
tests/compile/test_diagnostic_catalog.py``) or under any
``test_``-style runner. Standard library only.
"""

import contextlib
import hashlib
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "compiler"))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

import audit
from mojobpf import cli as cli_module  # noqa: E402
from mojobpf import evidence as evidence_module  # noqa: E402
from mojobpf import inspect as inspect_module  # noqa: E402
from mojobpf.build import (  # noqa: E402
    BuildRequest,
    _interpret_response,
    _reconcile_manifest,
    build_project,
    default_adapter_path,
)
from mojobpf.diagnostics import MojobpfError  # noqa: E402
from mojobpf.manifest import (  # noqa: E402
    ManifestError,
    ProfileError,
    parse_manifest,
)
from mojobpf.toolchain import (  # noqa: E402
    REQUIRED_TOOLS,
    ToolchainConfig,
    probe_toolchain,
)

SERVICE = os.path.join(REPO_ROOT, "compiler", "adapter_service.py")
LOCKFILE = os.path.join(REPO_ROOT, "toolchains.lock.json")
FIXTURE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "unsupported"
)
SUBSET_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "subset"
)
COMPILE_DIR = os.path.dirname(os.path.abspath(__file__))
CONTRACT_PATH = os.path.join(
    REPO_ROOT, "tests", "elf", "test_artifact_contract.py"
)

CLASSIFIER_SOURCE = os.path.join(
    REPO_ROOT, "examples", "xdp_pass", "xdp_pass.mojo"
)
MAP_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "map_roundtrip.mojo"
)
MUTATED_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "map_roundtrip_mutated.mojo"
)
COMBINED_SOURCE = os.path.join(
    REPO_ROOT, "examples", "packet_counter", "packet_counter.mojo"
)
BAD_SOURCE = os.path.join(REPO_ROOT, "tests", "compile", "probe_bad.mojo")
DEEP_STACK_SOURCE = os.path.join(
    SUBSET_DIR, "subset_deep_stack.mojo"
)
BAD_HELPER_SOURCE = os.path.join(SUBSET_DIR, "subset_bad_helper.mojo")
ESCAPE_SOURCE = os.path.join(SUBSET_DIR, "subset_escape_value.mojo")
GETNEXT_SOURCE = os.path.join(
    COMPILE_DIR, "maps_getnext_attempt.mojo"
)
CONTENT_SOURCE = os.path.join(
    COMPILE_DIR, "counter_content_attempt.mojo"
)
TRACEPOINT_SOURCE = os.path.join(
    REPO_ROOT, "examples", "tracepoint_counter", "counter.mojo"
)
TRACEPOINT_CTX_SOURCE = os.path.join(
    COMPILE_DIR, "tracepoint_ctx_attempt.mojo"
)
UPROBE_SOURCE = os.path.join(
    REPO_ROOT, "examples", "uprobe_counter", "counter.mojo"
)
UPROBE_REG_SOURCE = os.path.join(
    COMPILE_DIR, "uprobe_reg_attempt.mojo"
)

APACHE = "Apache-2.0 WITH LLVM-exception"

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

TRACEPOINT_MANIFEST_TEMPLATE = """\
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
entry = "trace_entry"
program_type = "tracepoint"
section = "tracepoint/syscalls/sys_enter_getpid"
{maps}"""

MAPS_BLOCK_TEMPLATE = """\
[[maps]]
name = "mojobpf_map0"
map_type = "{map_type}"
key_type = "u32"
value_type = "u64"
max_entries = {max_entries}
"""

UPROBE_MANIFEST_TEMPLATE = """\
schema_version = 1

[project]
name = "{project}"

[target]
profile = "linux-bpfel-v3-uprobe"
core = false

[artifact]
name = "{artifact}"
source_license = "Apache-2.0 WITH LLVM-exception"
kernel_license = "Apache-2.0 WITH LLVM-exception"

[[programs]]
source = "{source}"
entry = "uprobe_entry"
program_type = "uprobe"
section = "uprobe"
{maps}"""


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def check_tools():
    for tool in ("mojo", "llc"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (
        CLASSIFIER_SOURCE, MAP_SOURCE, MUTATED_SOURCE,
        COMBINED_SOURCE, BAD_SOURCE, DEEP_STACK_SOURCE,
        BAD_HELPER_SOURCE, ESCAPE_SOURCE, GETNEXT_SOURCE,
        CONTENT_SOURCE, TRACEPOINT_SOURCE,
        TRACEPOINT_CTX_SOURCE, UPROBE_SOURCE, UPROBE_REG_SOURCE,
        SERVICE, LOCKFILE, CONTRACT_PATH,
    ):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)


def _load_contract():
    """Load the artifact-contract suite for its ELF builders."""
    spec = importlib.util.spec_from_file_location(
        "catalog_contract", CONTRACT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rendered(diagnostic):
    """The user-visible CLI rendering of one diagnostic."""
    return cli_module._format_diagnostic(diagnostic)


def normalize(text, *roots):
    """Replace temporary roots (plus repo root) with placeholders.

    The system temp base maps to ``/tmp``, so pins holding
    ``/tmp/<work>`` also match under a nested ``TMPDIR``; the repo
    root maps before the base so a checkout under the temp base
    still normalizes.
    """
    if text is None:
        return None
    for root in roots:
        text = text.replace(root, "<tmp>")
    text = text.replace(REPO_ROOT, "<repo>")
    tmp_base = os.path.normpath(tempfile.gettempdir())
    if tmp_base not in ("/tmp", "/"):
        text = text.replace(tmp_base, "/tmp")
    return re.sub(
        r"mojobpf-build-[^/\'\"\s:]+", "<work>", text
    )


def assert_shape(diagnostic):
    """Assert the frozen six-field diagnostic shape."""
    assert set(diagnostic.to_dict()) == {
        "code", "stage", "severity", "explanation", "location",
        "remedy",
    }, diagnostic.to_dict()
    assert re.match(r"^MBPF[1-7][0-9]{2}$", diagnostic.code)
    assert diagnostic.stage
    assert diagnostic.severity in ("error", "warning", "note")
    assert diagnostic.explanation


def assert_rendered(diagnostic, expected, *roots, extra=()):
    """Assert shape plus exact normalized CLI rendering."""
    assert_shape(diagnostic)
    text = rendered(diagnostic)
    for old, new in extra:
        if old:
            text = text.replace(old, new)
    observed = normalize(text, *roots)
    if os.environ.get("MOJOBPF_CATALOG_DUMP"):
        print("DUMP %s: %r" % (diagnostic.code, observed))
        return
    assert observed == expected, (
        "rendering mismatch:\n  observed: %r\n  expected: %r"
        % (observed, expected)
    )


def tool_extra():
    """Placeholder mapping for ambient tool binary paths."""
    return (
        (shutil.which("mojo"), "<mojo>"),
        (shutil.which("llc"), "<llc>"),
    )


def assert_audit_rendered(exc, expected):
    """Assert exact rendering of a direct audit rejection."""
    assert re.match(r"^MBPF3[0-9]{2}$", exc.code)
    assert exc.stage == "adapter.audit"
    assert exc.severity == "error"
    assert exc.explanation
    observed = audit_rendered(exc)
    if os.environ.get("MOJOBPF_CATALOG_DUMP"):
        print("DUMP %s: %r" % (exc.code, observed))
        return
    assert observed == expected, (
        "rendering mismatch:\n  observed: %r\n  expected: %r"
        % (observed, expected)
    )


def stage_project(source_text, filename, manifest_text):
    """Stage inline sources plus a manifest; return (root, paths)."""
    root = tempfile.mkdtemp(prefix="diag-catalog-")
    proj = os.path.join(root, "proj")
    os.makedirs(proj)
    staged = os.path.join(proj, filename)
    with open(staged, "w", encoding="utf-8") as handle:
        handle.write(source_text)
    manifest_path = os.path.join(proj, "mojobpf.toml")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(manifest_text)
    return root, manifest_path, os.path.join(proj, "out")


def copy_project(source, manifest_text):
    """Stage a tree source file plus a manifest; return paths."""
    root = tempfile.mkdtemp(prefix="diag-catalog-")
    proj = os.path.join(root, "proj")
    os.makedirs(proj)
    filename = os.path.basename(source)
    shutil.copyfile(source, os.path.join(proj, filename))
    manifest_path = os.path.join(proj, "mojobpf.toml")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(manifest_text)
    return root, manifest_path, os.path.join(proj, "out")


def xdp_manifest(filename, entry, artifact, max_entries=None):
    if max_entries is None:
        maps = ""
    else:
        maps = MAPS_BLOCK_TEMPLATE.format(
            map_type="array", max_entries=max_entries
        )
    return MANIFEST_TEMPLATE.format(
        project="%s-proj" % entry,
        artifact=artifact,
        source=filename,
        entry=entry,
        maps=maps,
    )


def tracepoint_manifest(filename, artifact, max_entries=2):
    maps = MAPS_BLOCK_TEMPLATE.format(
        map_type="array", max_entries=max_entries
    )
    return TRACEPOINT_MANIFEST_TEMPLATE.format(
        project="tracepoint-proj",
        artifact=artifact,
        source=filename,
        maps=maps,
    )


def uprobe_manifest(filename, artifact, max_entries=2):
    maps = MAPS_BLOCK_TEMPLATE.format(
        map_type="array", max_entries=max_entries
    )
    return UPROBE_MANIFEST_TEMPLATE.format(
        project="uprobe-proj",
        artifact=artifact,
        source=filename,
        maps=maps,
    )


def build(manifest_path, out_dir):
    return build_project(
        BuildRequest(
            manifest_path=manifest_path,
            out_dir=out_dir,
            adapter_path=SERVICE,
            lockfile_path=LOCKFILE,
        )
    )


def assert_failure(result, out_dir):
    assert result.success is False, "failing build reported success"
    assert result.artifacts == (), "failing build reported artifacts"
    assert result.diagnostics, "failing build carried no diagnostics"
    assert not os.path.exists(out_dir) or (
        [
            name
            for name in os.listdir(out_dir)
            if name.endswith(".bpf.o")
        ]
        == []
    ), "failing build left an object behind"


def assert_no_diagnose_record(result):
    assert "build.diagnose" not in [
        record.stage for record in result.commands
    ], "valid builds never run the diagnose re-emit"


def assert_audit_rejected(text, code):
    try:
        audit.validate(text)
    except audit.AuditError as exc:
        assert exc.code == code, (
            "expected code %s, got %s (%s)" % (code, exc.code, exc)
        )
        assert exc.stage == "adapter.audit", exc.stage
        return exc
    raise AssertionError(
        "audit accepted input it must reject with %s" % code
    )


def read_fixture(name):
    path = os.path.join(FIXTURE_DIR, name)
    if not os.path.isfile(path):
        raise EnvironmentFailure("missing fixture: %s" % path)
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def audit_rendered(exc):
    """CLI-style rendering of a direct audit rejection."""
    parts = [
        "%s (%s/%s): %s"
        % (exc.code, exc.stage, exc.severity, exc.explanation)
    ]
    if exc.location:
        parts.append("location: %s" % exc.location)
    if exc.remedy:
        parts.append("remedy: %s" % exc.remedy)
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Manifest and profile codes (MBPF101, MBPF201-MBPF211).
# ---------------------------------------------------------------------------

CATALOG_MANIFEST = """\
schema_version = 1

[project]
name = "packet-counter"

[target]
profile = "linux-bpfel-v3"
core = false

[artifact]
name = "packet_counter"
source_license = "Apache-2.0 WITH LLVM-exception"
kernel_license = "Apache-2.0 WITH LLVM-exception"

[[programs]]
source = "src/xdp.mojo"
entry = "xdp_entry"
program_type = "xdp"
section = "xdp"

[[maps]]
name = "mojobpf_map0"
map_type = "array"
key_type = "u32"
value_type = "u64"
max_entries = 1
"""


def write_manifest_project(manifest_text, sources=("src/xdp.mojo",)):
    root = tempfile.mkdtemp(prefix="manifest-catalog-")
    manifest_path = os.path.join(root, "mojobpf.toml")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(manifest_text)
    for source in sources:
        full = os.path.join(root, source)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as handle:
            handle.write("# fixture source\n")
    return root, manifest_path


def manifest_trigger(manifest_text, code, sources=("src/xdp.mojo",)):
    root, manifest_path = write_manifest_project(
        manifest_text, sources
    )
    try:
        parse_manifest(manifest_path)
    except (ManifestError, ProfileError) as exc:
        assert exc.diagnostic.code == code, (
            "expected %s, got %s (%s)"
            % (code, exc.diagnostic.code, exc.diagnostic.explanation)
        )
        assert exc.diagnostic.severity == "error"
        return exc.diagnostic, root
    raise AssertionError("expected failure %s, manifest parsed" % code)


def manifest_neighbor(manifest_text, sources=("src/xdp.mojo",)):
    _root, manifest_path = write_manifest_project(
        manifest_text, sources
    )
    return parse_manifest(manifest_path)


def mutate_manifest(text, anchor, replacement):
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.strip() == anchor.strip():
            lines[index] = replacement
            return "".join(lines)
    raise AssertionError("anchor not found: %r" % anchor)


def test_manifest_201_unknown_schema_version():
    text = mutate_manifest(
        CATALOG_MANIFEST, "schema_version = 1", "schema_version = 99\n"
    )
    diagnostic, root = manifest_trigger(text, "MBPF201")
    assert_rendered(diagnostic, (
            'MBPF201 (manifest.parse/error): unsupported schema_version '
            '99; this driver reads version 1; location: '
            '<tmp>/mojobpf.toml: schema_version; remedy: set '
            'schema_version = 1 or use a matching driver'
        ), root)
    manifest = manifest_neighbor(CATALOG_MANIFEST)
    assert manifest.schema_version == 1
    print("PASS MBPF201 exact + neighbor parses")


def test_manifest_202_unknown_field():
    text = CATALOG_MANIFEST + '\n[extra]\nkey = "value"\n'
    diagnostic, root = manifest_trigger(text, "MBPF202")
    assert_rendered(diagnostic, (
            'MBPF202 (manifest.parse/error): unknown manifest field: '
            "'extra'; location: <tmp>/mojobpf.toml: extra; remedy: "
            'remove the unknown field'
        ), root)
    manifest = manifest_neighbor(CATALOG_MANIFEST)
    assert manifest.project.name == "packet-counter"
    print("PASS MBPF202 exact + neighbor parses")


def test_manifest_203_duplicate_entry():
    extra = (
        '\n[[programs]]\nsource = "src/other.mojo"\n'
        'entry = "xdp_entry"\nprogram_type = "xdp"\nsection = "xdp"\n'
    )
    text = CATALOG_MANIFEST.split("[[maps]]")[0] + extra
    diagnostic, root = manifest_trigger(
        text, "MBPF203", sources=("src/xdp.mojo", "src/other.mojo")
    )
    assert_rendered(diagnostic, (
            'MBPF203 (manifest.parse/error): duplicate program entry '
            "name: 'xdp_entry'; location: <tmp>/mojobpf.toml: "
            'programs[1].entry; remedy: give each [[programs]] entry a '
            'unique entry name'
        ), root)
    neighbor = text.replace('entry = "xdp_entry"\n', 'entry = "x2"\n', 1)
    manifest = manifest_neighbor(
        neighbor, sources=("src/xdp.mojo", "src/other.mojo")
    )
    assert [p.entry for p in manifest.programs] == ["x2", "xdp_entry"]
    print("PASS MBPF203 exact + neighbor parses")


def test_manifest_204_duplicate_map():
    extra = (
        '\n[[maps]]\nname = "mojobpf_map0"\nmap_type = "array"\n'
        'key_type = "u32"\nvalue_type = "u64"\nmax_entries = 1\n'
    )
    diagnostic, root = manifest_trigger(
        CATALOG_MANIFEST + extra, "MBPF204"
    )
    assert_rendered(diagnostic, (
            'MBPF204 (manifest.parse/error): duplicate map name: '
            "'mojobpf_map0'; location: <tmp>/mojobpf.toml: maps[1].name; "
            'remedy: give each [[maps]] entry a unique name'
        ), root)
    manifest = manifest_neighbor(CATALOG_MANIFEST)
    assert [m.name for m in manifest.maps] == ["mojobpf_map0"]
    print("PASS MBPF204 exact + neighbor parses")


def test_manifest_205_bad_map_spec():
    text = mutate_manifest(
        CATALOG_MANIFEST, "max_entries = 1", "max_entries = 0\n"
    )
    diagnostic, root = manifest_trigger(text, "MBPF205")
    assert_rendered(diagnostic, (
            'MBPF205 (manifest.parse/error): max_entries 0 is outside '
            'the structural range 1..4294967295; location: '
            '<tmp>/mojobpf.toml: maps[0]; remedy: use map_type in '
            '{array, percpu_array, ringbuf}, key_type in {u32}, '
            'value_type in {u64} and max_entries in {1, 2, 3, 4} '
            '(ringbuf maps use key_type/value_type none and max_entries '
            'in {4096, 131072})'
        ), root)
    manifest = manifest_neighbor(CATALOG_MANIFEST)
    assert manifest.maps[0].max_entries == 1
    print("PASS MBPF205 exact + neighbor parses")


def test_manifest_206_section_pair_conflict():
    text = mutate_manifest(
        CATALOG_MANIFEST, 'section = "xdp"', 'section = "kprobe"\n'
    )
    diagnostic, root = manifest_trigger(text, "MBPF206")
    assert_rendered(diagnostic, (
            "MBPF206 (manifest.parse/error): program_type 'xdp' with "
            "section 'kprobe' is not supported by profile "
            "'linux-bpfel-v3'; location: <tmp>/mojobpf.toml: "
            'programs[0]; remedy: use one of: xdp/xdp, '
            'tracepoint/tracepoint/syscalls/sys_enter_getpid'
        ), root)
    manifest = manifest_neighbor(CATALOG_MANIFEST)
    assert manifest.programs[0].section == "xdp"
    print("PASS MBPF206 exact + neighbor parses")


def test_manifest_207_source_escape():
    text = mutate_manifest(
        CATALOG_MANIFEST,
        'source = "src/xdp.mojo"',
        'source = "../evil.mojo"\n',
    )
    diagnostic, root = manifest_trigger(text, "MBPF207")
    assert_rendered(diagnostic, (
            'MBPF207 (manifest.parse/error): program source escapes the '
            "manifest directory: '../evil.mojo'; location: "
            "<tmp>/mojobpf.toml: source '../evil.mojo'; remedy: keep "
            'sources inside the project directory'
        ), root)
    manifest = manifest_neighbor(CATALOG_MANIFEST)
    assert manifest.programs[0].source == "src/xdp.mojo"
    print("PASS MBPF207 exact + neighbor parses")


def test_manifest_208_missing_source():
    diagnostic, root = manifest_trigger(
        CATALOG_MANIFEST, "MBPF208", sources=()
    )
    assert_rendered(diagnostic, (
            'MBPF208 (manifest.parse/error): program source not found: '
            "'src/xdp.mojo'; location: <tmp>/mojobpf.toml: source "
            "'src/xdp.mojo'; remedy: create the source file or fix the "
            'source path'
        ), root)
    manifest = manifest_neighbor(CATALOG_MANIFEST)
    assert manifest.programs[0].source == "src/xdp.mojo"
    print("PASS MBPF208 exact + neighbor parses")


def test_manifest_209_missing_manifest_file():
    # The missing-file trigger keeps the pin free of TOML-parser
    # wording; the malformed-TOML variant pins its code below.
    missing = os.path.join(
        tempfile.mkdtemp(prefix="manifest-catalog-"),
        "mojobpf.toml",
    )
    try:
        parse_manifest(missing)
    except ManifestError as exc:
        assert exc.diagnostic.code == "MBPF209", exc.diagnostic
        assert_rendered(
            exc.diagnostic, (
            'MBPF209 (manifest.parse/error): cannot read manifest: '
            "[Errno 2] No such file or directory: '<tmp>/mojobpf.toml'; "
            'location: <tmp>/mojobpf.toml; remedy: check the manifest '
            'path and file permissions'
        ), os.path.dirname(missing)
        )
    else:
        raise AssertionError("expected MBPF209 for a missing file")
    _diagnostic, _root = manifest_trigger(
        "schema_version = [unclosed\n", "MBPF209"
    )
    manifest = manifest_neighbor(CATALOG_MANIFEST)
    assert manifest.schema_version == 1
    print("PASS MBPF209 exact + neighbor parses")


def test_manifest_210_invalid_name():
    text = mutate_manifest(
        CATALOG_MANIFEST,
        'entry = "xdp_entry"',
        'entry = "9bad-name!"\n',
    )
    diagnostic, root = manifest_trigger(text, "MBPF210")
    assert_rendered(diagnostic, (
            'MBPF210 (manifest.parse/error): invalid program entry name: '
            "'9bad-name!'; location: <tmp>/mojobpf.toml: "
            'programs[0].entry; remedy: use letters, digits and '
            'underscores, starting with a letter or underscore'
        ), root)
    manifest = manifest_neighbor(CATALOG_MANIFEST)
    assert manifest.programs[0].entry == "xdp_entry"
    print("PASS MBPF210 exact + neighbor parses")


def test_manifest_211_capability_outside_profile():
    text = mutate_manifest(
        CATALOG_MANIFEST, "core = false", "core = true\n"
    )
    diagnostic, root = manifest_trigger(text, "MBPF211")
    assert_rendered(diagnostic, (
            "MBPF211 (manifest.parse/error): profile 'linux-bpfel-v3' "
            'does not support CO-RE (core = true); location: '
            '<tmp>/mojobpf.toml: target.core; remedy: set core = false'
        ), root)
    manifest = manifest_neighbor(CATALOG_MANIFEST)
    assert manifest.target.core is False
    print("PASS MBPF211 exact + neighbor parses")


def test_manifest_211_single_uprobe_program():
    text = mutate_manifest(
        CATALOG_MANIFEST,
        'profile = "linux-bpfel-v3"',
        'profile = "linux-bpfel-v3-uprobe"\n',
    )
    text = mutate_manifest(
        text, 'entry = "xdp_entry"', 'entry = "uprobe_entry"\n'
    )
    text = mutate_manifest(
        text, 'program_type = "xdp"', 'program_type = "uprobe"\n'
    )
    text = mutate_manifest(
        text, 'section = "xdp"', 'section = "uprobe"\n'
    )
    text = text.split("[[maps]]")[0] + (
        '\n[[programs]]\nsource = "src/other.mojo"\n'
        'entry = "uprobe_entry_two"\nprogram_type = "uprobe"\n'
        'section = "uprobe"\n'
    )
    diagnostic, root = manifest_trigger(
        text, "MBPF211", sources=("src/xdp.mojo", "src/other.mojo")
    )
    assert_rendered(diagnostic, (
            "MBPF211 (manifest.parse/error): profile "
            "'linux-bpfel-v3-uprobe' admits at most one uprobe "
            'program per build, but the manifest declares 2 uprobe '
            'programs; location: <tmp>/mojobpf.toml: programs; '
            'remedy: declare exactly one [[programs]] entry with '
            'program_type = "uprobe" and section = "uprobe"; '
            'multi-probe graphs need a reviewed route'
        ), root)
    manifest = manifest_neighbor(CATALOG_MANIFEST)
    assert manifest.target.profile == "linux-bpfel-v3"
    print("PASS MBPF211 single-probe exact")


def test_profile_101_unsupported_profile():
    text = mutate_manifest(
        CATALOG_MANIFEST,
        'profile = "linux-bpfel-v3"',
        'profile = "linux-bpfeb-v9"\n',
    )
    diagnostic, root = manifest_trigger(text, "MBPF101")
    assert diagnostic.stage == "profile.resolve", diagnostic
    assert_rendered(diagnostic, (
            'MBPF101 (profile.resolve/error): unsupported target '
            "profile: 'linux-bpfeb-v9'; location: <tmp>/mojobpf.toml: "
            'target.profile; remedy: use one of: linux-bpfel-v3, '
            'linux-bpfel-v3-core, linux-bpfel-v3-hash, '
            'linux-bpfel-v3-lru, linux-bpfel-v3-net, '
            'linux-bpfel-v3-reserve, '
            'linux-bpfel-v3-subprog, linux-bpfel-v3-uprobe'
        ), root)
    manifest = manifest_neighbor(CATALOG_MANIFEST)
    assert manifest.target.profile == "linux-bpfel-v3"
    print("PASS MBPF101 exact + neighbor parses")


# ---------------------------------------------------------------------------
# Toolchain codes (MBPF102-MBPF105).
# ---------------------------------------------------------------------------

FIXTURE_TOOL_VERSIONS = {
    "mojo": "Mojo 9.9.9 (fixture)",
    "llc": "Fixture LLVM version 1.2.3",
    "bpftool": "bpftool v0.0-fixture",
    "python3": "Python 9.9.9-fixture",
}

FIXTURE_TOOL_BINARY = {
    "mojo": "mojo",
    "llc": "llc",
    "bpftool": "bpftool",
    "python": "python3",
}


def write_tool_bindir(missing=()):
    tmpdir = tempfile.mkdtemp(prefix="toolchain-catalog-")
    bindir = os.path.join(tmpdir, "bin")
    os.makedirs(bindir)
    versions = {}
    for key in REQUIRED_TOOLS:
        if key in missing:
            continue
        binary = FIXTURE_TOOL_BINARY[key]
        text = FIXTURE_TOOL_VERSIONS[binary]
        path = os.path.join(bindir, binary)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\necho '%s'\n" % text)
        os.chmod(path, 0o755)
        versions[key] = text
    return bindir, versions


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_fixture_lockfile(bindir, versions, mutate=None):
    tools = {}
    for name in REQUIRED_TOOLS:
        binary = FIXTURE_TOOL_BINARY[name]
        tools[name] = {
            "path": os.path.join(bindir, binary),
            "status": "present",
            "version": versions[name],
            "sha256": sha256_of(os.path.join(bindir, binary)),
        }
    data = {
        "generated_by": "fixture",
        "schema_version": 1,
        "status": "draft",
        "tools": tools,
    }
    if mutate is not None:
        mutate(data)
    path = os.path.join(
        tempfile.mkdtemp(prefix="lockfile-catalog-"),
        "toolchains.lock.json",
    )
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    return path


@contextlib.contextmanager
def isolated_path(value):
    old = os.environ.get("PATH")
    os.environ["PATH"] = value
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = old


def test_toolchain_105_note_without_lockfile():
    bindir, _versions = write_tool_bindir()
    report = probe_toolchain(ToolchainConfig(search_paths=(bindir,)))
    assert [item.code for item in report.diagnostics] == ["MBPF105"]
    diagnostic = report.diagnostics[0]
    assert diagnostic.severity == "note"
    assert_rendered(diagnostic, (
            'MBPF105 (toolchain.match/note): no lockfile supplied; '
            'reporting discovery without validation; remedy: pass a '
            'lockfile_path to validate the toolchain'
        ), bindir)
    lockfile = write_fixture_lockfile(bindir, _versions)
    neighbor = probe_toolchain(
        ToolchainConfig(lockfile_path=lockfile, search_paths=(bindir,))
    )
    assert neighbor.supported is True
    assert neighbor.diagnostics == ()
    print("PASS MBPF105 exact + neighbor validates")


def test_toolchain_102_pin_mismatch():
    bindir, versions = write_tool_bindir()

    def mutate(data):
        data["tools"]["llc"]["version"] = "Wrong LLVM version 0.0.0"

    lockfile = write_fixture_lockfile(bindir, versions, mutate=mutate)
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=lockfile, search_paths=(bindir,))
    )
    assert [item.code for item in report.diagnostics] == ["MBPF102"]
    assert_rendered(
        report.diagnostics[0], (
            "MBPF102 (toolchain.match/error): tool 'llc' does not match "
            "the lockfile pin (found version 'Fixture LLVM version "
            "1.2.3'); location: <tmp>/toolchains.lock.json: tools.llc; "
            'remedy: install the pinned llc or re-pin the lockfile deliberately'
        ), bindir, os.path.dirname(lockfile)
    )
    good = write_fixture_lockfile(bindir, versions)
    neighbor = probe_toolchain(
        ToolchainConfig(lockfile_path=good, search_paths=(bindir,))
    )
    assert neighbor.supported is True
    assert neighbor.diagnostics == ()
    print("PASS MBPF102 exact + neighbor validates")


def test_toolchain_103_missing_tool():
    bindir, _versions = write_tool_bindir(missing=("bpftool",))
    empty = tempfile.mkdtemp(prefix="empty-path-")
    with isolated_path(empty):
        report = probe_toolchain(
            ToolchainConfig(search_paths=(bindir,))
        )
    codes = [item.code for item in report.diagnostics]
    assert "MBPF103" in codes, codes
    diagnostic = next(
        item for item in report.diagnostics if item.code == "MBPF103"
    )
    assert "bpftool" in diagnostic.explanation, diagnostic
    assert_rendered(diagnostic, (
            'MBPF103 (toolchain.discovery/error): required tool not '
            'found on PATH: bpftool; location: tool:bpftool; remedy: '
            'install bpftool or fix PATH; no substitute tool is used'
        ), bindir, empty)
    full, versions = write_tool_bindir()
    lockfile = write_fixture_lockfile(full, versions)
    with isolated_path(empty):
        neighbor = probe_toolchain(
            ToolchainConfig(
                lockfile_path=lockfile, search_paths=(full,)
            )
        )
    assert neighbor.supported is True
    assert neighbor.diagnostics == ()
    print("PASS MBPF103 exact + neighbor validates")


def test_toolchain_104_unreadable_lockfile():
    bindir, _versions = write_tool_bindir()
    missing = os.path.join(bindir, "no-such-lock.json")
    report = probe_toolchain(
        ToolchainConfig(lockfile_path=missing, search_paths=(bindir,))
    )
    assert [item.code for item in report.diagnostics] == ["MBPF104"]
    assert_rendered(report.diagnostics[0], (
            'MBPF104 (toolchain.match/error): cannot read lockfile: '
            '[Errno 2] No such file or directory: '
            "'<tmp>/no-such-lock.json'; location: "
            '<tmp>/no-such-lock.json; remedy: check the lockfile path '
            'and file permissions'
        ), bindir)
    lockfile = write_fixture_lockfile(bindir, _versions)
    neighbor = probe_toolchain(
        ToolchainConfig(lockfile_path=lockfile, search_paths=(bindir,))
    )
    assert neighbor.supported is True
    assert neighbor.diagnostics == ()
    print("PASS MBPF104 exact + neighbor validates")


# ---------------------------------------------------------------------------
# Driver gate codes (MBPF212-MBPF217 except MBPF216, which needs a build).
# ---------------------------------------------------------------------------

GATE_MANIFEST = """\
schema_version = 1

[project]
name = "gate-proj"

[target]
profile = "linux-bpfel-v3"
core = false

[artifact]
name = "gate_obj"
source_license = "Apache-2.0 WITH LLVM-exception"
kernel_license = "Apache-2.0 WITH LLVM-exception"

[[programs]]
source = "main.mojo"
entry = "xdp_entry"
program_type = "xdp"
section = "xdp"
"""

GATE_MAP = """\
[[maps]]
name = "mojobpf_map0"
map_type = "array"
key_type = "u32"
value_type = "u64"
max_entries = 1
"""


def parse_gate_manifest(manifest_text, sources=("main.mojo",)):
    root = tempfile.mkdtemp(prefix="gate-catalog-")
    manifest_path = os.path.join(root, "mojobpf.toml")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(manifest_text)
    for source in sources:
        with open(os.path.join(root, source), "w",
                  encoding="utf-8") as handle:
            handle.write("# fixture source\n")
    return root, parse_manifest(manifest_path)


def test_gate_213_unsupported_entry_root():
    text = GATE_MANIFEST.replace(
        'entry = "xdp_entry"', 'entry = "xdp_b"', 1
    )
    root, manifest = parse_gate_manifest(text)
    diagnostic = _reconcile_manifest(manifest)
    assert diagnostic is not None and diagnostic.code == "MBPF213"
    assert diagnostic.stage == "build.setup", diagnostic
    assert_rendered(diagnostic, (
            "MBPF213 (build.setup/error): program entry 'xdp_b' is not a "
            'supported export root (supported: xdp_entry, trace_entry, '
            "uprobe_entry, socket_entry, tc_entry); location: "
            "<tmp>/mojobpf.toml: "
            "programs[0].entry; remedy: declare entry 'xdp_entry'; "
            'wider roots need a reviewed route'
        ), root)
    _nroot, neighbor = parse_gate_manifest(GATE_MANIFEST)
    assert _reconcile_manifest(neighbor) is None
    print("PASS MBPF213 exact + neighbor reconciles")


def test_gate_214_unsupported_map_name():
    text = GATE_MANIFEST + GATE_MAP.replace(
        'name = "mojobpf_map0"', 'name = "packet_counts"'
    )
    diagnostic, root = manifest_trigger(
        text, "MBPF214", sources=("main.mojo",)
    )
    assert diagnostic.stage == "manifest.parse", diagnostic
    assert_rendered(diagnostic, (
            "MBPF214 (manifest.parse/error): map name 'packet_counts' "
            'is not a supported map declaration (supported: '
            'mojobpf_map0, mojobpf_map1); location: <tmp>/mojobpf.toml: '
            "maps[0].name; remedy: declare map 'mojobpf_map0'; wider "
            'shapes need a reviewed route'
        ), root)
    manifest = manifest_neighbor(
        GATE_MANIFEST + GATE_MAP, sources=("main.mojo",)
    )
    assert [m.name for m in manifest.maps] == ["mojobpf_map0"]
    print("PASS MBPF214 exact + neighbor parses")


def test_gate_215_extra_maps():
    text = GATE_MANIFEST + GATE_MAP + GATE_MAP.replace(
        'name = "mojobpf_map0"', 'name = "mojobpf_map1"'
    )
    diagnostic, root = manifest_trigger(
        text, "MBPF215", sources=("main.mojo",)
    )
    assert diagnostic.stage == "manifest.parse", diagnostic
    assert_rendered(diagnostic, (
            'MBPF215 (manifest.parse/error): manifest declares 2 maps; '
            'the pair must be one state map plus its ring-buffer '
            'companion (map_type ringbuf); location: '
            '<tmp>/mojobpf.toml: maps; remedy: declare at most one map, '
            'or the event pair of a state map plus its ring-buffer '
            'companion; wider shapes need a reviewed route'
        ), root)
    manifest = manifest_neighbor(
        GATE_MANIFEST + GATE_MAP, sources=("main.mojo",)
    )
    assert [m.name for m in manifest.maps] == ["mojobpf_map0"]
    print("PASS MBPF215 exact + neighbor parses")


def test_gate_217_entry_pair_mismatch():
    text = GATE_MANIFEST.replace(
        'program_type = "xdp"', 'program_type = "tracepoint"', 1
    ).replace(
        'section = "xdp"',
        'section = "tracepoint/syscalls/sys_enter_getpid"',
        1,
    )
    root, manifest = parse_gate_manifest(text)
    diagnostic = _reconcile_manifest(manifest)
    assert diagnostic is not None and diagnostic.code == "MBPF217"
    assert diagnostic.stage == "build.setup", diagnostic
    assert_rendered(diagnostic, (
            "MBPF217 (build.setup/error): program entry 'xdp_entry' pins "
            "program_type 'xdp' with section 'xdp', but the manifest "
            "declares program_type 'tracepoint' with section "
            "'tracepoint/syscalls/sys_enter_getpid'; location: "
            '<tmp>/mojobpf.toml: programs[0]; remedy: declare '
            "program_type 'xdp' with section 'xdp' for entry 'xdp_entry'"
        ), root)
    _nroot, neighbor = parse_gate_manifest(GATE_MANIFEST)
    assert _reconcile_manifest(neighbor) is None
    print("PASS MBPF217 exact + neighbor reconciles")


def test_gate_212_malformed_adapter_response():
    root = tempfile.mkdtemp(prefix="adapter-catalog-")
    response_path = os.path.join(root, "response.json")
    diagnostics = []
    adapted = _interpret_response(
        ["not", "an", "object"], response_path, diagnostics,
        exit_code=0, adapter_dir=root,
    )
    assert adapted is None
    assert [item.code for item in diagnostics] == ["MBPF212"]
    assert diagnostics[0].stage == "build.adapter"
    assert_rendered(diagnostics[0], (
            'MBPF212 (build.adapter/error): malformed adapter response: '
            'not an object; location: <tmp>/response.json; remedy: check '
            'the adapter service script'
        ), root)
    staged = os.path.join(root, "adapted.bpf.ll")
    with open(staged, "w", encoding="utf-8") as handle:
        handle.write("; adapted\n")
    neighbor_diagnostics = []
    good = _interpret_response(
        {
            "schema_version": 1,
            "ok": True,
            "outputs": {"adapted_ir": staged, "route": "lane-a"},
            "diagnostics": [],
        },
        response_path,
        neighbor_diagnostics,
        exit_code=0,
        adapter_dir=root,
    )
    assert good == (staged, "lane-a"), neighbor_diagnostics
    assert neighbor_diagnostics == []
    print("PASS MBPF212 exact + neighbor interprets")


# ---------------------------------------------------------------------------
# Audit codes without a Mojo spelling (IR-level rendering + IR neighbor).
# ---------------------------------------------------------------------------

IR_NEIGHBORS = {
    # Fixture -> (expected code, offending line, neighboring line,
    # expected neighbor mode). Each neighbor differs from its
    # trigger by the minimum that removes the prohibited shape.
    "unwind_invoke.ll": (
        "MBPF304",
        "  invoke void @f() to label %ok unwind label %fail\n"
        "ok:\n  ret i32 2\nfail:\n  ret i32 1",
        "  br label %ok\nok:\n  ret i32 2",
        "classifier",
    ),
    "static_alloca.ll": (
        "MBPF310",
        "  %3 = alloca i32, align 4\n",
        "",
        "classifier",
    ),
    "ptrtoint_op.ll": (
        "MBPF311",
        "  %3 = ptrtoint ptr %0 to i64",
        "  %3 = add i64 %1, 0",
        "classifier",
    ),
    "pseudo_decl_attrs.ll": (
        "MBPF313",
        "declare i64 @__mojobpf_lookup_v1(i64, ptr) nounwind #0",
        "declare i64 @__mojobpf_lookup_v1(i64, ptr) #0",
        "map",
    ),
    "undefined_ssa_use.ll": (
        "MBPF315",
        "%a = add i64 %99, 1",
        "%a = add i64 %1, 1",
        "classifier",
    ),
    "ptr_store_map_mem.ll": (
        "MBPF316",
        "18:\n  store i64 %4, ptr %9, align 8\n  br label %15",
        "18:\n  store i64 %11, ptr %9, align 8\n  br label %15",
        "map",
    ),
}


EXPECTED_IR_RENDERINGS = {
    'MBPF304': (
            'MBPF304 (adapter.audit/error): unwinding, TLS, constructor, '
            "or intrinsic machinery 'invoke' is not in the audited "
            "subset: 'invoke void @f() to label %ok unwind label %fail'; "
            'location: line 12; remedy: remove runtime, allocator, '
            'unwinding, TLS, constructor, and intrinsic use from the '
            'reachable graph'
        ),
    'MBPF310': (
            "MBPF310 (adapter.audit/error): stack allocation 'alloca' is "
            "not in the audited subset: '%3 = alloca i32, align 4'; "
            'location: line 12; remedy: keep no LLVM-managed frame '
            'objects; use the audited slot shapes for key and value '
            'storage'
        ),
    'MBPF311': (
            'MBPF311 (adapter.audit/error): poison/undef, address space, '
            "or pointer/integer erasure 'ptrtoint' is not in the audited "
            "subset: '%3 = ptrtoint ptr %0 to i64'; location: line 13; "
            'remedy: initialize every value and keep pointers typed; '
            'only the adapter introduces the lowered helper callee form'
        ),
    'MBPF313': (
            'MBPF313 (adapter.audit/error): reserved helper declaration '
            "deviates from its exact admitted signature: 'declare i64 "
            "@__mojobpf_lookup_v1(i64, ptr) nounwind #0'; location: line "
            '30; remedy: use the SDK helper wrappers unchanged'
        ),
    'MBPF315': (
            'MBPF315 (adapter.audit/error): SSA value %99 is used at '
            'line 14 but never defined; location: line 14; remedy: '
            'define every used value exactly once'
        ),
    'MBPF316': (
            'MBPF316 (adapter.audit/error): lookup-derived value %4 '
            'stored into map memory would persist a kernel address: '
            "'store i64 %4, ptr %9, align 8'; location: line 31; remedy: "
            'store only loaded values and computed scalars; never store '
            'a lookup result, a value derived from one, or a pointer'
        ),
}


def test_audit_ir_codes_exact_with_neighbors():
    for name in sorted(IR_NEIGHBORS):
        code, old, new, mode = IR_NEIGHBORS[name]
        text = read_fixture(name)
        exc = assert_audit_rejected(text, code)
        assert_audit_rendered(exc, EXPECTED_IR_RENDERINGS[code])
        assert text.count(old) == 1, (name, old)
        neighbor = text.replace(old, new)
        observed = audit.validate(neighbor)
        assert observed == mode, (
            "%s neighbor validated as %s, expected %s"
            % (name, observed, mode)
        )
        print("PASS %s exact + neighbor validates" % code)


def test_audit_301_fallback_direct():
    try:
        audit.check_graph_preserved(["a"], ["b"], {})
    except audit.AuditError as exc:
        assert exc.code == "MBPF301", exc.code
        assert exc.stage == "adapter.audit"
        assert exc.location is None
        assert_audit_rendered(exc, (
            'MBPF301 (adapter.audit/error): lowering altered body line 1 '
            "beyond the admitted callee edit: 'a' -> 'b'; remedy: report "
            'this adapter failure as a bug'
        ))
    else:
        raise AssertionError("expected MBPF301 for altered bodies")
    assert audit.check_graph_preserved(["a"], ["a"], {}) is None
    print("PASS MBPF301 exact + neighbor preserves")


# ---------------------------------------------------------------------------
# Audit codes with a Mojo spelling (driver file:line + excerpt rendering).
# ---------------------------------------------------------------------------

DIAG_SPDX = "# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception\n"
DIAG_PKT_IMPORT = (
    "from mojobpf.packet import GUARD_ACTION, XDP_DROP, XDP_PASS, "
    "XdpCtx, load_u8, packet_addr, packet_base, packet_short\n"
)
DIAG_SIG = (
    "\n\n@export\n"
    'def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") '
    "-> Int32:\n"
)
DIAG_GUARD = (
    "    var pkt = XdpCtx.from_ctx(ctx)\n"
    "    if packet_short(pkt, 15):\n"
    "        return Int32(GUARD_ACTION)\n"
    "    var base = packet_base(packet_addr(pkt, 0))\n"
    "    var eth_last = load_u8(base, 14)\n"
)

DIAG_ENTRY_TRIGGER = (
    DIAG_SPDX
    + DIAG_PKT_IMPORT
    + "\n\n@export\n"
    "def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin], "
    'extra: Int32) abi("C") -> Int32:\n'
    + DIAG_GUARD
    + "    if (eth_last & 1) == 1:\n"
    "        return Int32(XDP_DROP)\n"
    "    return Int32(XDP_PASS)\n"
)
DIAG_ENTRY_NEIGHBOR = DIAG_ENTRY_TRIGGER.replace(", extra: Int32", "")

DIAG_FLOAT_TRIGGER = (
    DIAG_SPDX
    + DIAG_PKT_IMPORT
    + DIAG_SIG
    + DIAG_GUARD
    + "    var x = Float32(Int(eth_last)) + Float32(0.5)\n"
    + "    if x > Float32(1.0):\n"
    "        return Int32(XDP_DROP)\n"
    "    return Int32(XDP_PASS)\n"
)
DIAG_FLOAT_NEIGHBOR = DIAG_FLOAT_TRIGGER.replace(
    "var x = Float32(Int(eth_last)) + Float32(0.5)",
    "var x = Int(eth_last) + 1",
).replace("if x > Float32(1.0):", "if x > 1:")

DIAG_EXCEPT_TRIGGER = (
    DIAG_SPDX
    + DIAG_PKT_IMPORT
    + DIAG_SIG
    + DIAG_GUARD
    + '    try:\n        if eth_last == 0:\n            raise Error("boom")\n'
    "    except:\n"
    "        return Int32(XDP_DROP)\n"
    "    return Int32(XDP_PASS)\n"
)
DIAG_EXCEPT_NEIGHBOR = DIAG_EXCEPT_TRIGGER.replace(
    '    try:\n        if eth_last == 0:\n            raise Error("boom")\n'
    "    except:\n        return Int32(XDP_DROP)",
    "    if eth_last == 0:\n        return Int32(XDP_DROP)",
)

DIAG_SELF_TRIGGER = (
    DIAG_SPDX
    + DIAG_PKT_IMPORT
    + DIAG_SIG
    + DIAG_GUARD
    + "    if eth_last == 0:\n"
    "        return Int32(XDP_PASS)\n"
    "    return xdp_entry(ctx) + Int32(1)\n"
)
DIAG_SELF_NEIGHBOR = DIAG_SELF_TRIGGER.replace(
    "    return xdp_entry(ctx) + Int32(1)", "    return Int32(3)"
)

DIAG_NOASM_NEIGHBOR = (
    DIAG_SPDX
    + DIAG_PKT_IMPORT
    + DIAG_SIG
    + DIAG_GUARD
    + "    if eth_last == 0:\n"
    "        return Int32(XDP_DROP)\n"
    "    return Int32(XDP_PASS)\n"
)

DIAG_SLOT_NEIGHBOR = (
    DIAG_SPDX
    + "from mojobpf.helpers import bpf_map_lookup, bpf_map_update\n"
    + "from mojobpf.maps import BPF_ANY, MapHandle, key_slot, "
    "value_slot\n"
    + "from mojobpf.packet import XdpCtx, packet_addr, packet_base\n"
    + DIAG_SIG
    + "    var pkt = XdpCtx.from_ctx(ctx)\n"
    + "    var base = packet_base(packet_addr(pkt, 0))\n"
    + "    var key = key_slot()\n"
    + "    var found = bpf_map_lookup(MapHandle.load().addr, key)\n"
    + "    if found.is_null():\n"
    "        return Int32(2)\n"
    "    var slot = value_slot()\n"
    "    var old = found.unsafe_value_ptr()[unsafe_offset=0]\n"
    "    slot[unsafe_offset=0] = old + 1\n"
    "    _ = bpf_map_update(MapHandle.load().addr, key_slot(), "
    "slot, Int64(BPF_ANY))\n"
    "    return Int32(2)\n"
)

DIAG_PRESSURE_TRIGGER = (
    DIAG_SPDX
    + "from mojobpf.helpers import bpf_map_lookup, bpf_map_update\n"
    + "from mojobpf.maps import MapHandle, key_slot, value_slot\n"
    + DIAG_SIG
    + "    var key = key_slot()\n"
    + "    var found = bpf_map_lookup(MapHandle.load().addr, key)\n"
    + "    if found.is_null():\n"
    "        return Int32(2)\n"
    "    var slot = value_slot()\n"
    "    var old = found.unsafe_value_ptr()[unsafe_offset=0]\n"
    "    slot[unsafe_offset=0] = old + 1\n"
    "    var key2 = key_slot()\n"
    "    _ = bpf_map_update(MapHandle.load().addr, key, slot, "
    "Int64(0))\n"
    "    return Int32(2)\n"
)
DIAG_PRESSURE_NEIGHBOR = DIAG_PRESSURE_TRIGGER.replace(
    "bpf_map_update(MapHandle.load().addr, key, slot, ",
    "bpf_map_update(MapHandle.load().addr, key2, slot, ",
)


def driver_trigger_inline(source_text, filename, manifest_text):
    """Build inline Mojo expecting refusal; return (diag, root)."""
    root, manifest_path, out_dir = stage_project(
        source_text, filename, manifest_text
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    assert "build.diagnose" in [
        record.stage for record in result.commands
    ], "audit failures run the diagnose re-emit"
    return result.diagnostics[0], root


def driver_trigger_file(source, manifest_text):
    """Build a tree source expecting refusal; return (diag, root)."""
    root, manifest_path, out_dir = copy_project(
        source, manifest_text
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    assert "build.diagnose" in [
        record.stage for record in result.commands
    ], "audit failures run the diagnose re-emit"
    return result.diagnostics[0], root


def driver_neighbor_inline(source_text, filename, manifest_text):
    """Build inline Mojo expecting success; return the result."""
    _root, manifest_path, out_dir = stage_project(
        source_text, filename, manifest_text
    )
    result = build(manifest_path, out_dir)
    assert result.success is True, result.diagnostics
    assert [item.role for item in result.artifacts] == [
        "object", "evidence",
    ]
    assert_no_diagnose_record(result)
    return result


def driver_neighbor_file(source, manifest_text):
    """Build a tree source expecting success; return the result."""
    _root, manifest_path, out_dir = copy_project(
        source, manifest_text
    )
    result = build(manifest_path, out_dir)
    assert result.success is True, result.diagnostics
    assert [item.role for item in result.artifacts] == [
        "object", "evidence",
    ]
    assert_no_diagnose_record(result)
    return result


def test_driver_302_entry_shape():
    check_tools()
    diagnostic, root = driver_trigger_inline(
        DIAG_ENTRY_TRIGGER, "diag_entry_args.mojo",
        xdp_manifest("diag_entry_args.mojo", "xdp_entry", "d302"),
    )
    assert diagnostic.code == "MBPF302", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic
    assert_rendered(diagnostic, (
            'MBPF302 (adapter.audit/error): unexpected definition (only '
            'one complete i32 @xdp_entry(ptr...), @trace_entry(ptr...), '
            '@uprobe_entry(ptr...), @socket_entry(ptr...), or '
            "@tc_entry(ptr...) #0 header, nothing after '{', "
            "allowed): 'define dso_local "
            "i32 @xdp_entry(ptr noundef %0, i32 noundef %1) #0 {'; "
            'location: <tmp>/proj/diag_entry_args.mojo:6: def '
            'xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin], extra: '
            'Int32) abi("C") -> Int32:; remedy: expose exactly one C-ABI '
            'entrypoint taking the context pointer'
        ), root)
    driver_neighbor_inline(
        DIAG_ENTRY_NEIGHBOR, "diag_entry_ok.mojo",
        xdp_manifest("diag_entry_ok.mojo", "xdp_entry", "d302n"),
    )
    print("PASS MBPF302 exact + neighbor builds")


def test_driver_303_unreserved_call():
    check_tools()
    diagnostic, root = driver_trigger_file(
        GETNEXT_SOURCE,
        xdp_manifest(
            "maps_getnext_attempt.mojo", "xdp_entry", "d303",
            max_entries=1,
        ),
    )
    assert diagnostic.code == "MBPF303", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic
    assert_rendered(diagnostic, (
            'MBPF303 (adapter.audit/error): only the known call shapes '
            'are allowed; unexpected direct call to '
            "@__mojobpf_get_next_key_v1: '%5 = call i64 "
            "@__mojobpf_get_next_key_v1(i64 %4, ptr %2, ptr %3)'; "
            'location: <tmp>/proj/maps_getnext_attempt.mojo:22:     var '
            'rc = external_call["__mojobpf_get_next_key_v1", Int64](; '
            'remedy: use only the reviewed SDK wrappers; the rejection '
            'names the first unexpected call'
        ), root)
    # Neighbor mutants derive from the trigger file, so the refusal
    # pins to the offending construct rather than to the file: the
    # unreserved call becomes the reserved delete spelling on the
    # same skeleton (trigger header comments describe the trigger).
    with open(GETNEXT_SOURCE, encoding="utf-8") as handle:
        trigger_text = handle.read()
    neighbor_text = trigger_text.replace(
        "from std.ffi import external_call\n",
        "from mojobpf.helpers import bpf_map_delete\n",
    ).replace(
        "    var out = key_slot()\n"
        '    var rc = external_call["__mojobpf_get_next_key_v1", Int64](\n'
        "        MapHandle.load().addr, key, out\n"
        "    )\n",
        "    var rc = bpf_map_delete(MapHandle.load().addr, key)\n",
    )
    assert "__mojobpf_get_next_key_v1" not in neighbor_text
    assert "var out = key_slot()" not in neighbor_text
    driver_neighbor_inline(
        neighbor_text, "diag_getnext_ok.mojo",
        xdp_manifest(
            "diag_getnext_ok.mojo", "xdp_entry", "d303n",
            max_entries=1,
        ),
    )
    print("PASS MBPF303 exact + neighbor builds")


def test_driver_305_float_operation():
    check_tools()
    diagnostic, root = driver_trigger_inline(
        DIAG_FLOAT_TRIGGER, "diag_float_op.mojo",
        xdp_manifest("diag_float_op.mojo", "xdp_entry", "d305"),
    )
    assert diagnostic.code == "MBPF305", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic
    assert_rendered(diagnostic, (
            'MBPF305 (adapter.audit/error): floating-point or '
            "unsupported vector operation 'sitofp' is not in the audited "
            "subset: '%15 = sitofp i64 %14 to float'; location: "
            '<tmp>/proj/diag_float_op.mojo:12:     var x = '
            'Float32(Int(eth_last)) + Float32(0.5); remedy: use '
            'fixed-width integer scalars only'
        ), root)
    driver_neighbor_inline(
        DIAG_FLOAT_NEIGHBOR, "diag_float_ok.mojo",
        xdp_manifest("diag_float_ok.mojo", "xdp_entry", "d305n"),
    )
    print("PASS MBPF305 exact + neighbor builds")


def test_driver_306_unqualified_helper():
    check_tools()
    diagnostic, root = driver_trigger_file(
        BAD_HELPER_SOURCE,
        xdp_manifest(
            "subset_bad_helper.mojo", "xdp_entry", "d306"
        ),
    )
    assert diagnostic.code == "MBPF306", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic
    assert_rendered(diagnostic, (
            'MBPF306 (adapter.audit/error): helper invocations must use '
            "the reserved call form, never inline assembly: '%11 = call "
            'i64 asm sideeffect "call 9", "={r0}"()\'; location: '
            '<tmp>/proj/subset_bad_helper.mojo:18:     ](); remedy: use '
            'the SDK helper wrappers unchanged'
        ), root)
    driver_neighbor_inline(
        DIAG_NOASM_NEIGHBOR, "diag_noasm_ok.mojo",
        xdp_manifest("diag_noasm_ok.mojo", "xdp_entry", "d306n"),
    )
    print("PASS MBPF306 exact + neighbor builds")


def test_driver_307_shape_family():
    check_tools()
    diagnostic, root = driver_trigger_file(
        CONTENT_SOURCE,
        xdp_manifest(
            "counter_content_attempt.mojo", "xdp_entry", "d307",
            max_entries=1,
        ),
    )
    assert diagnostic.code == "MBPF307", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic
    assert_rendered(diagnostic, (
            'MBPF307 (adapter.audit/error): map programs need one map '
            'count family over dense keys 0..N-1 (N read-modify-write '
            'pairs or N deletions, each call with its map reference '
            "shapes), found {'empty': 2, 'mapaddr': 2, 'keyslot': 2, "
            "'keyslot1': 0, 'keyslotN': 0, 'kindtag': 0, 'hashtag': 0, "
            "'lrutag': 0, 'valslot': 1, 'rbmapaddr': 0, 'rbsize': 0, "
            "'eventslot': 0, "
            "'eventslotN': 0, 'lookup': 1, 'update': 1, 'delete': 0, "
            "'pid': 0, 'ktime': 0, 'cpu': 0, 'output': 0, 'reserve': 0, "
            "'submit': 0, 'discard': 0, 'coreread': 0, "
            "'coreexists': 0, 'skbload': 0, 'skbstore': 0}; location: "
            '<tmp>/proj/counter_content_attempt.mojo:29: def '
            'xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> '
            'Int32:; remedy: pair every helper call with its map '
            'reference shapes and cover exactly keys 0..N-1'
        ), root)
    # Neighbor mutant of the trigger file: dropping the packet
    # guard leaves the single read-modify-write pair, which is the
    # qualified map family (trigger header comments describe the
    # trigger).
    with open(CONTENT_SOURCE, encoding="utf-8") as handle:
        trigger_text = handle.read()
    guard = (
        "    var pkt = XdpCtx.from_ctx(ctx)\n"
        "    var is_drop = False\n"
        "    if packet_short(pkt, 15):\n"
        "        is_drop = False\n"
        "    else:\n"
        "        var base = packet_base(packet_addr(pkt, 0))\n"
        "        var eth_last = load_u8(base, 14)\n"
        "        is_drop = (eth_last & 1) == 1\n"
        "    if is_drop:\n"
        "        return Int32(XDP_DROP)\n"
    )
    assert trigger_text.count(guard) == 1
    neighbor_text = trigger_text.replace(guard, "")
    assert "is_drop" not in neighbor_text
    driver_neighbor_inline(
        neighbor_text, "diag_content_ok.mojo",
        xdp_manifest(
            "diag_content_ok.mojo", "xdp_entry", "d307n",
            max_entries=1,
        ),
    )
    print("PASS MBPF307 exact + neighbor builds")


def test_driver_308_liveness():
    check_tools()
    diagnostic, root = driver_trigger_inline(
        DIAG_PRESSURE_TRIGGER, "diag_pressure.mojo",
        xdp_manifest(
            "diag_pressure.mojo", "xdp_entry", "d308",
            max_entries=1,
        ),
    )
    assert diagnostic.code == "MBPF308", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic
    assert_rendered(diagnostic, (
            'MBPF308 (adapter.audit/error): SSA value %2 defined at line '
            '7 is used at line 24, across the lookup helper call at line '
            '9: values must not be kept live across helper calls; '
            'location: <tmp>/proj/diag_pressure.mojo:9:     var found = '
            'bpf_map_lookup(MapHandle.load().addr, key); remedy: '
            'recompute or reload every value used after a helper call '
            'from state defined after it'
        ), root)
    driver_neighbor_inline(
        DIAG_PRESSURE_NEIGHBOR, "diag_pressure_ok.mojo",
        xdp_manifest(
            "diag_pressure_ok.mojo", "xdp_entry", "d308n",
            max_entries=1,
        ),
    )
    print("PASS MBPF308 exact + neighbor builds")


def test_driver_309_module_global_keeps_ir_line():
    # Synthesized globals carry no debug location and the -g1
    # re-emit diverges textually on this shape (phi operand
    # order), so the alignment check stands the mapping down and
    # the IR line is kept: the honest outcome, pinned here.
    check_tools()
    diagnostic, root = driver_trigger_inline(
        DIAG_EXCEPT_TRIGGER, "diag_except_global.mojo",
        xdp_manifest(
            "diag_except_global.mojo", "xdp_entry", "d309"
        ),
    )
    assert diagnostic.code == "MBPF309", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic
    assert diagnostic.location == "line 6", diagnostic.location
    assert_rendered(diagnostic, (
            'MBPF309 (adapter.audit/error): input must not define '
            "globals: '@static_string_516c36dc19e44511 = internal "
            'constant [5 x i8] c"boom\\\\00", align 16\'; location: line 6; '
            'remedy: keep all state in entrypoint-local values'
        ), root)
    driver_neighbor_inline(
        DIAG_EXCEPT_NEIGHBOR, "diag_except_ok.mojo",
        xdp_manifest("diag_except_ok.mojo", "xdp_entry", "d309n"),
    )
    print("PASS MBPF309 exact + neighbor builds")


def test_driver_312_self_call():
    check_tools()
    diagnostic, root = driver_trigger_inline(
        DIAG_SELF_TRIGGER, "diag_self_call.mojo",
        xdp_manifest("diag_self_call.mojo", "xdp_entry", "d312"),
    )
    assert diagnostic.code == "MBPF312", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic
    assert_rendered(diagnostic, (
            'MBPF312 (adapter.audit/error): the entrypoint must not call '
            "itself: '%17 = call i32 @xdp_entry(ptr %0)'; location: "
            '<tmp>/proj/diag_self_call.mojo:14:     return '
            'xdp_entry(ctx) + Int32(1); remedy: keep the reachable graph '
            'free of recursion'
        ), root)
    driver_neighbor_inline(
        DIAG_SELF_NEIGHBOR, "diag_self_ok.mojo",
        xdp_manifest("diag_self_ok.mojo", "xdp_entry", "d312n"),
    )
    print("PASS MBPF312 exact + neighbor builds")


def test_driver_314_bad_operands():
    check_tools()
    diagnostic, root = driver_trigger_file(
        ESCAPE_SOURCE,
        xdp_manifest(
            "subset_escape_value.mojo", "xdp_entry", "d314",
            max_entries=1,
        ),
    )
    assert diagnostic.code == "MBPF314", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic
    assert_rendered(diagnostic, (
            'MBPF314 (adapter.audit/error): update value operand %4 must '
            'come from the prepared value slot, not from line 9: call at '
            'line 23; location: <tmp>/proj/subset_escape_value.mojo:19:  '
            '   _ = bpf_map_update(MapHandle.load().addr, key_slot(), '
            'leaked, Int64(BPF_ANY)); remedy: pass the prepared key and '
            'value slots to helper calls'
        ), root)
    driver_neighbor_inline(
        DIAG_SLOT_NEIGHBOR, "diag_slot_ok.mojo",
        xdp_manifest(
            "diag_slot_ok.mojo", "xdp_entry", "d314n",
            max_entries=1,
        ),
    )
    print("PASS MBPF314 exact + neighbor builds")


def test_driver_317_context_use():
    check_tools()
    diagnostic, root = driver_trigger_file(
        TRACEPOINT_CTX_SOURCE,
        tracepoint_manifest(
            "tracepoint_ctx_attempt.mojo", "d317", max_entries=2
        ),
    )
    assert diagnostic.code == "MBPF317", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic
    assert_rendered(diagnostic, (
            'MBPF317 (adapter.audit/error): tracepoint programs must not '
            'read context payload fields: entry parameter %0 is used at '
            'line 19; location: '
            '<tmp>/proj/tracepoint_ctx_attempt.mojo:30:     var probe = '
            'ctx[unsafe_offset=0]; remedy: filter on the current-PID/TID '
            'helper and map state; leave the context pointer unused'
        ), root)
    driver_neighbor_file(
        TRACEPOINT_SOURCE,
        tracepoint_manifest("counter.mojo", "d317n", max_entries=2),
    )
    print("PASS MBPF317 exact + neighbor builds")


def test_driver_317_uprobe_register():
    check_tools()
    diagnostic, root = driver_trigger_file(
        UPROBE_REG_SOURCE,
        uprobe_manifest(
            "uprobe_reg_attempt.mojo", "d317u", max_entries=2
        ),
    )
    assert diagnostic.code == "MBPF317", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic
    assert_rendered(diagnostic, (
            'MBPF317 (adapter.audit/error): uprobe programs must read '
            'exactly the pinned x86-64 first-argument register '
            '(context word 14, rdi at byte 112): found '
            "'%2 = getelementptr inbounds i64, ptr %0, i32 13'; "
            'location: <tmp>/proj/uprobe_reg_attempt.mojo:18:     var '
            'arg = Int64(words[unsafe_offset=13]); remedy: read the '
            "probed call's first argument through the SDK uprobe "
            'vocabulary (x86-64 context word 14 only); any other '
            'context access needs a reviewed route'
        ), root)
    driver_neighbor_file(
        UPROBE_SOURCE,
        uprobe_manifest("counter.mojo", "d317un", max_entries=2),
    )
    print("PASS MBPF317 uprobe exact + neighbor builds")


def test_diagnose_remaps_stale_cache_paths():
    # The frontend replays cached line tables for byte-identical
    # sources, so two staged copies of one trigger would resolve
    # to the first copy's path without the remap. Each build must
    # name its own staged file.
    check_tools()
    locations = []
    for tag in ("stale-a", "stale-b"):
        root, manifest_path, out_dir = copy_project(
            BAD_HELPER_SOURCE,
            xdp_manifest(
                "subset_bad_helper.mojo", "xdp_entry", tag
            ),
        )
        result = build(manifest_path, out_dir)
        assert_failure(result, out_dir)
        diagnostic = result.diagnostics[0]
        assert diagnostic.code == "MBPF306", diagnostic
        expected = os.path.join(
            root, "proj", "subset_bad_helper.mojo:18:     ]()"
        )
        assert diagnostic.location == expected, (
            "stale path not remapped: %r" % (diagnostic.location,)
        )
        locations.append(diagnostic.location)
    assert locations[0] != locations[1]
    print("PASS stale debuginfo paths remap to the built source")


# ---------------------------------------------------------------------------
# Enrichment fail-safes (synthetic line tables, no toolchain needed).
# ---------------------------------------------------------------------------

SEAM_SOURCE_LINES = [
    "# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception",
    "from mojobpf.packet import XDP_PASS",
    "",
    "",
    "@export",
    'def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") '
    "-> Int32:",
    "    var x = Float32(1.0)",
    "    return Int32(XDP_PASS)",
]

SEAM_RAW = [
    "; ModuleID = 'case.mojo'",
    'source_filename = "case.mojo"',
    'target datalayout = "e-m:e"',
    'target triple = "x86_64-unknown-linux-gnu"',
    "",
    "define dso_local i32 @xdp_entry(ptr noundef %0) #0 {",
    "  %1 = sitofp i64 1 to float",
    "  ret i32 2",
    "}",
    "",
    'attributes #0 = { "target-cpu"="v3" }',
    "",
    "!llvm.module.flags = !{!0}",
    "",
    '!0 = !{i32 2, !"Debug Info Version", i32 3}',
]

SEAM_G1_TEMPLATE = [
    "; ModuleID = 'case.mojo'",
    'source_filename = "case.mojo"',
    'target datalayout = "e-m:e"',
    'target triple = "x86_64-unknown-linux-gnu"',
    "",
    "define dso_local i32 @xdp_entry(ptr noundef %0) #0 !dbg !6 {",
    "  %1 = sitofp i64 1 to float, !dbg !10",
    "  ret i32 2, !dbg !11",
    "}",
    "",
    'attributes #0 = { "target-cpu"="v3" }',
    "",
    "!llvm.module.flags = !{!12}",
    "",
    '!0 = !DIFile(filename: "{path}", directory: "")',
    '!6 = distinct !DISubprogram(name: "xdp_entry", '
    'linkageName: "xdp_entry", scope: !0, file: !0, line: 6, '
    "type: !2, scopeLine: 6, unit: !3)",
    "!10 = !DILocation(line: 7, column: 9, scope: !6)",
    "!11 = !DILocation(line: 8, column: 5, scope: !6)",
    '!12 = !{i32 2, !"Debug Info Version", i32 3}',
]


def write_seam_files(root, source_lines=SEAM_SOURCE_LINES):
    source_abs = os.path.join(root, "case.mojo")
    with open(source_abs, "w", encoding="utf-8") as handle:
        handle.write("\n".join(source_lines) + "\n")
    raw_path = os.path.join(root, "case.raw.ll")
    with open(raw_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(SEAM_RAW) + "\n")
    return source_abs, raw_path


def seam_g1(path):
    return [
        line.format(path=path) if "{path}" in line else line
        for line in SEAM_G1_TEMPLATE
    ]


def test_enrich_seam_line_maps_and_falls_back():
    from mojobpf.build import _enrich_audit_diagnostics
    from mojobpf.diagnostics import Diagnostic

    root = tempfile.mkdtemp(prefix="diag-seam-")
    source_abs, raw_path = write_seam_files(root)
    commands = []
    diagnostics = [
        Diagnostic(
            code="MBPF305",
            stage="adapter.audit",
            severity="error",
            explanation="float op",
            location="line 7",
            remedy="integers only",
        ),
        Diagnostic(
            code="MBPF307",
            stage="adapter.audit",
            severity="error",
            explanation="shape counts",
            location=None,
            remedy="match a family",
        ),
    ]
    _enrich_audit_diagnostics(
        diagnostics,
        raw_path=raw_path,
        source_abs=source_abs,
        tool_paths={},
        workdir=root,
        entry="xdp_entry",
        sdk_needed=False,
        sdk_dir="",
        timeout_s=600,
        commands=commands,
        _debug_lines=seam_g1(source_abs),
    )
    assert commands == [], "the seam runs no subprocess"
    assert normalize(diagnostics[0].location, root) == (
        "<tmp>/case.mojo:7:     var x = Float32(1.0)"
    ), diagnostics[0].location
    assert normalize(diagnostics[1].location, root) == (
        "<tmp>/case.mojo:6: def xdp_entry(ctx: "
        'MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:'
    ), diagnostics[1].location
    print("PASS seam line map + definition fallback")


def test_enrich_seam_stale_path_remaps():
    from mojobpf.build import _enrich_audit_diagnostics
    from mojobpf.diagnostics import Diagnostic

    root = tempfile.mkdtemp(prefix="diag-seam-")
    source_abs, raw_path = write_seam_files(root)
    stale = os.path.join(root, "stale-copy.mojo")
    with open(stale, "w", encoding="utf-8") as handle:
        handle.write("\n".join(SEAM_SOURCE_LINES) + "\n")
    diagnostics = [
        Diagnostic(
            code="MBPF305",
            stage="adapter.audit",
            severity="error",
            explanation="float op",
            location="line 7",
            remedy="integers only",
        )
    ]
    _enrich_audit_diagnostics(
        diagnostics,
        raw_path=raw_path,
        source_abs=source_abs,
        tool_paths={},
        workdir=root,
        entry="xdp_entry",
        sdk_needed=False,
        sdk_dir="",
        timeout_s=600,
        commands=[],
        _debug_lines=seam_g1(stale),
    )
    assert normalize(diagnostics[0].location, root) == (
        "<tmp>/case.mojo:7:     var x = Float32(1.0)"
    ), diagnostics[0].location
    print("PASS seam stale path remaps to the built source")


def seam_g1_chained(source_abs, hops):
    chained = []
    for line in seam_g1(source_abs):
        if line.startswith("!10 = "):
            line = (
                "!10 = !DILocation(line: 7, column: 9, scope: !6, "
                "inlinedAt: !20)"
            )
        chained.append(line)
    chained += hops
    return chained


def test_enrich_seam_inline_chain_resolves_outermost():
    from mojobpf.build import _enrich_audit_diagnostics
    from mojobpf.diagnostics import Diagnostic

    root = tempfile.mkdtemp(prefix="diag-seam-")
    source_abs, raw_path = write_seam_files(root)
    diagnostics = [
        Diagnostic(
            code="MBPF305",
            stage="adapter.audit",
            severity="error",
            explanation="float op",
            location="line 7",
            remedy="integers only",
        )
    ]
    _enrich_audit_diagnostics(
        diagnostics,
        raw_path=raw_path,
        source_abs=source_abs,
        tool_paths={},
        workdir=root,
        entry="xdp_entry",
        sdk_needed=False,
        sdk_dir="",
        timeout_s=600,
        commands=[],
        _debug_lines=seam_g1_chained(source_abs, [
            "!20 = !DILocation(line: 8, column: 5, scope: !6, "
            "inlinedAt: !30)",
            "!30 = !DILocation(line: 6, column: 1, scope: !6)",
        ]),
    )
    # A two-hop inlinedAt chain resolves to the outermost call
    # site (line 6), not the middle frame (line 8).
    assert normalize(diagnostics[0].location, root) == (
        "<tmp>/case.mojo:6: def xdp_entry(ctx: "
        'MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:'
    ), diagnostics[0].location
    print("PASS seam inline chain resolves outermost")


def test_enrich_seam_inline_cycle_terminates():
    from mojobpf.build import _enrich_audit_diagnostics
    from mojobpf.diagnostics import Diagnostic

    root = tempfile.mkdtemp(prefix="diag-seam-")
    source_abs, raw_path = write_seam_files(root)
    diagnostics = [
        Diagnostic(
            code="MBPF305",
            stage="adapter.audit",
            severity="error",
            explanation="float op",
            location="line 7",
            remedy="integers only",
        )
    ]
    _enrich_audit_diagnostics(
        diagnostics,
        raw_path=raw_path,
        source_abs=source_abs,
        tool_paths={},
        workdir=root,
        entry="xdp_entry",
        sdk_needed=False,
        sdk_dir="",
        timeout_s=600,
        commands=[],
        _debug_lines=seam_g1_chained(source_abs, [
            "!20 = !DILocation(line: 8, column: 5, scope: !6, "
            "inlinedAt: !10)",
        ]),
    )
    # A cyclic chain terminates at the last unvisited hop rather
    # than looping or standing the mapping down.
    assert normalize(diagnostics[0].location, root) == (
        "<tmp>/case.mojo:8:     return Int32(XDP_PASS)"
    ), diagnostics[0].location
    print("PASS seam inline cycle terminates")


def test_enrich_seam_foreign_bytes_untouched():
    from mojobpf.build import _enrich_audit_diagnostics
    from mojobpf.diagnostics import Diagnostic

    root = tempfile.mkdtemp(prefix="diag-seam-")
    source_abs, raw_path = write_seam_files(root)
    sdk_dir = os.path.join(root, "sdk")
    os.makedirs(sdk_dir)
    foreign = os.path.join(root, "earlier", "prog.mojo")
    os.makedirs(os.path.dirname(foreign))
    with open(foreign, "w", encoding="utf-8") as handle:
        handle.write("entirely different content\n" * 9)
    diagnostics = [
        Diagnostic(
            code="MBPF305",
            stage="adapter.audit",
            severity="error",
            explanation="float op",
            location="line 7",
            remedy="integers only",
        )
    ]
    _enrich_audit_diagnostics(
        diagnostics,
        raw_path=raw_path,
        source_abs=source_abs,
        tool_paths={},
        workdir=root,
        entry="xdp_entry",
        sdk_needed=False,
        sdk_dir=sdk_dir,
        timeout_s=600,
        commands=[],
        _debug_lines=seam_g1(foreign),
    )
    # A readable but byte-different file outside the SDK is not
    # trustworthy: the original diagnostic stands.
    assert diagnostics[0].location == "line 7", diagnostics[0].location
    print("PASS seam foreign bytes keep the original")


def test_enrich_seam_deleted_path_untouched():
    from mojobpf.build import _enrich_audit_diagnostics
    from mojobpf.diagnostics import Diagnostic

    root = tempfile.mkdtemp(prefix="diag-seam-")
    source_abs, raw_path = write_seam_files(root)
    sdk_dir = os.path.join(root, "sdk")
    os.makedirs(sdk_dir)
    gone = os.path.join(root, "earlier", "prog.mojo")
    diagnostics = [
        Diagnostic(
            code="MBPF305",
            stage="adapter.audit",
            severity="error",
            explanation="float op",
            location="line 7",
            remedy="integers only",
        )
    ]
    _enrich_audit_diagnostics(
        diagnostics,
        raw_path=raw_path,
        source_abs=source_abs,
        tool_paths={},
        workdir=root,
        entry="xdp_entry",
        sdk_needed=False,
        sdk_dir=sdk_dir,
        timeout_s=600,
        commands=[],
        _debug_lines=seam_g1(gone),
    )
    assert diagnostics[0].location == "line 7", diagnostics[0].location
    print("PASS seam deleted path keeps the original")


def test_enrich_seam_sdk_path_reported():
    from mojobpf.build import _enrich_audit_diagnostics
    from mojobpf.diagnostics import Diagnostic

    root = tempfile.mkdtemp(prefix="diag-seam-")
    source_abs, raw_path = write_seam_files(root)
    sdk_dir = os.path.join(root, "sdk")
    os.makedirs(os.path.join(sdk_dir, "mojobpf"))
    sdk_file = os.path.join(sdk_dir, "mojobpf", "helper.mojo")
    sdk_lines = ["sdk helper line %d" % number for number in range(1, 10)]
    with open(sdk_file, "w", encoding="utf-8") as handle:
        handle.write("\n".join(sdk_lines) + "\n")
    diagnostics = [
        Diagnostic(
            code="MBPF305",
            stage="adapter.audit",
            severity="error",
            explanation="float op",
            location="line 7",
            remedy="integers only",
        )
    ]
    _enrich_audit_diagnostics(
        diagnostics,
        raw_path=raw_path,
        source_abs=source_abs,
        tool_paths={},
        workdir=root,
        entry="xdp_entry",
        sdk_needed=True,
        sdk_dir=sdk_dir,
        timeout_s=600,
        commands=[],
        _debug_lines=seam_g1(sdk_file),
    )
    # Absolute paths under the SDK directory are this build's own
    # toolchain inputs, so they report as resolved.
    assert normalize(diagnostics[0].location, root) == (
        "<tmp>/sdk/mojobpf/helper.mojo:7: sdk helper line 7"
    ), diagnostics[0].location
    print("PASS seam SDK path reports as resolved")


def test_remap_relative_ignores_cwd():
    from mojobpf.build import _remap_source_location

    workdir = tempfile.mkdtemp(prefix="diag-remap-work-")
    srcdir = tempfile.mkdtemp(prefix="diag-remap-src-")
    source_abs = os.path.join(srcdir, "case.mojo")
    with open(source_abs, "w", encoding="utf-8") as handle:
        handle.write("\n".join(SEAM_SOURCE_LINES) + "\n")
    decoy_dir = tempfile.mkdtemp(prefix="diag-remap-cwd-")
    with open(os.path.join(decoy_dir, "case.mojo"), "w") as handle:
        handle.write("\n".join(SEAM_SOURCE_LINES) + "\n")
    old_cwd = os.getcwd()
    os.chdir(decoy_dir)
    try:
        got = _remap_source_location(
            "case.mojo",
            8,
            source_abs=source_abs,
            workdir=workdir,
            sdk_dir="",
        )
    finally:
        os.chdir(old_cwd)
    # The process CWD holds a byte-identical decoy, but relative
    # paths resolve against the workdir only: nothing verifiable.
    assert got is None, got
    print("PASS remap ignores CWD decoys")


def test_remap_relative_workdir_copy_maps():
    from mojobpf.build import _remap_source_location

    workdir = tempfile.mkdtemp(prefix="diag-remap-work-")
    srcdir = tempfile.mkdtemp(prefix="diag-remap-src-")
    source_abs = os.path.join(srcdir, "case.mojo")
    with open(source_abs, "w", encoding="utf-8") as handle:
        handle.write("\n".join(SEAM_SOURCE_LINES) + "\n")
    with open(os.path.join(workdir, "case.mojo"), "w") as handle:
        handle.write("\n".join(SEAM_SOURCE_LINES) + "\n")
    got = _remap_source_location(
        "case.mojo",
        8,
        source_abs=source_abs,
        workdir=workdir,
        sdk_dir="",
    )
    assert got == "%s:8: %s" % (source_abs, SEAM_SOURCE_LINES[7]), got
    print("PASS remap maps workdir copies")


def test_remap_relative_escape_refused():
    from mojobpf.build import _remap_source_location

    workdir = tempfile.mkdtemp(prefix="diag-remap-work-")
    srcdir = tempfile.mkdtemp(prefix="diag-remap-src-")
    source_abs = os.path.join(srcdir, "case.mojo")
    with open(source_abs, "w", encoding="utf-8") as handle:
        handle.write("\n".join(SEAM_SOURCE_LINES) + "\n")
    escape = os.path.join(os.path.dirname(workdir), "escape.mojo")
    with open(escape, "w", encoding="utf-8") as handle:
        handle.write("\n".join(SEAM_SOURCE_LINES) + "\n")
    got = _remap_source_location(
        "../escape.mojo",
        8,
        source_abs=source_abs,
        workdir=workdir,
        sdk_dir="",
    )
    # Byte-identical but outside the workdir: unreportable.
    assert got is None, got
    print("PASS remap refuses workdir escapes")


def test_enrich_seam_fail_safes_keep_originals():
    from mojobpf.build import _enrich_audit_diagnostics
    from mojobpf.diagnostics import Diagnostic

    root = tempfile.mkdtemp(prefix="diag-seam-")
    source_abs, raw_path = write_seam_files(root)

    def run(cases, g1_lines):
        diags = [
            Diagnostic(
                code=code,
                stage="adapter.audit",
                severity="error",
                explanation="case",
                location=location,
                remedy="remedy",
            )
            for code, location in cases
        ]
        before = [d.location for d in diags]
        _enrich_audit_diagnostics(
            diags,
            raw_path=raw_path,
            source_abs=source_abs,
            tool_paths={},
            workdir=root,
            entry="xdp_entry",
            sdk_needed=False,
            sdk_dir="",
            timeout_s=600,
            commands=[],
            _debug_lines=g1_lines,
        )
        return [d.location for d in diags], before

    # Misaligned re-emit: nothing is rewritten.
    shifted = seam_g1(source_abs)
    shifted[6] = "  %1 = sitofp i64 2 to float, !dbg !10"
    after, before = run([("MBPF305", "line 7")], shifted)
    assert after == before == ["line 7"], after
    # No debug locations anywhere: nothing is rewritten.
    bare = [
        re.sub(r",? !dbg !\d+", "", line)
        for line in seam_g1(source_abs)
    ]
    after, before = run(
        [("MBPF305", "line 7"), ("MBPF307", None)], bare
    )
    assert after == before == ["line 7", None], after
    # MBPF301 and non-audit codes are never candidates.
    after, before = run(
        [("MBPF301", None), ("MBPF106", "some/path")],
        seam_g1(source_abs),
    )
    assert after == before == [None, "some/path"], after
    print("PASS seam fail-safes keep originals")


def test_first_error_line_direct():
    from mojobpf.build import _first_error_line

    assert _first_error_line("") is None
    assert _first_error_line("mojo: note: nothing\n") is None
    assert _first_error_line(
        "x.mojo:7:12: error: expected argument name\n"
        "def broken(:\n"
    ) == "x.mojo:7:12: error: expected argument name"
    assert _first_error_line(
        "error: <unknown>:0:0: in function xdp_entry: boom\n"
    ) == "error: <unknown>:0:0: in function xdp_entry: boom"
    assert _first_error_line("LLVM ERROR: out of memory\n") == (
        "LLVM ERROR: out of memory"
    )
    assert _first_error_line(
        "x.mojo:7: error: terse shape\n"
    ) == "x.mojo:7: error: terse shape"
    assert _first_error_line(
        "note: the error: marker is documented\n"
        "x.mojo:7:12: error: expected argument name\n"
    ) == "x.mojo:7:12: error: expected argument name"
    assert _first_error_line("warning: ignoring error: state\n") is None
    print("PASS first error line extraction")


# ---------------------------------------------------------------------------
# Object codes (MBPF401-MBPF407) plus the object license gate (MBPF705).
# ---------------------------------------------------------------------------

PROFILE_ID = "linux-bpfel-v3"


def inspect_bytes(contract, content):
    path = contract._write_temp_image(content)
    try:
        return inspect_module.inspect_object(path, PROFILE_ID), path
    finally:
        os.remove(path)


def verify_bytes(contract, content, source=APACHE, kernel=APACHE):
    path = contract._write_temp_image(content)
    try:
        return (
            inspect_module.verify_object(path, PROFILE_ID, source, kernel),
            path,
        )
    finally:
        os.remove(path)


def test_object_401_garbage_bytes():
    contract = _load_contract()
    report, path = inspect_bytes(
        contract, b"not an elf object at all...................."
    )
    assert report.ok is False
    assert [d.code for d in report.structural] == ["MBPF401"]
    assert_rendered(report.structural[0], (
            'MBPF401 (inspect.object/error): not an ELF object file; '
            'location: <tmp>; remedy: rebuild the object with the pinned '
            'toolchain'
        ), path)
    missing = os.path.join(
        tempfile.gettempdir(), "mojobpf-no-such-object.bpf.o"
    )
    if os.path.exists(missing):
        os.remove(missing)
    try:
        inspect_module.inspect_object(missing, PROFILE_ID)
    except inspect_module.InspectionError as exc:
        assert exc.diagnostic.code == "MBPF401", exc.diagnostic
        assert_rendered(
            exc.diagnostic, (
            'MBPF401 (inspect.object/error): cannot read object file '
            "'<tmp>/mojobpf-no-such-object.bpf.o': [Errno 2] No such "
            "file or directory: '<tmp>/mojobpf-no-such-object.bpf.o'; "
            'location: <tmp>/mojobpf-no-such-object.bpf.o; remedy: check '
            'the object path and permissions'
        ), tempfile.gettempdir()
        )
    else:
        raise AssertionError("expected MBPF401 for a missing file")
    neighbor, _ = inspect_bytes(
        contract, contract._clean_builder().build()
    )
    assert neighbor.ok is True, neighbor.to_dict()
    assert (
        neighbor.structural == ()
        and neighbor.unsupported == ()
        and neighbor.license == ()
    )
    print("PASS MBPF401 exact + neighbor inspects clean")


def test_object_402_bad_headers():
    contract = _load_contract()
    bad = bytearray(contract._clean_builder().build())
    bad[60:62] = struct.pack("<H", 60)
    report, path = inspect_bytes(contract, bytes(bad))
    assert [d.code for d in report.structural] == ["MBPF402"]
    assert_rendered(report.structural[0], (
            'MBPF402 (inspect.object/error): section table runs past '
            'end; location: <tmp>; remedy: rebuild the object with the '
            'pinned toolchain'
        ), path)
    neighbor, _ = inspect_bytes(
        contract, contract._clean_builder().build()
    )
    assert neighbor.ok is True
    print("PASS MBPF402 exact + neighbor inspects clean")


def test_object_403_missing_license():
    contract = _load_contract()
    builder = contract.ElfBuilder()
    builder.add_section(
        "xdp",
        contract.SHT_PROGBITS,
        contract.SHF_EXECINSTR,
        contract._exit_code(),
        align=8,
    )
    report, path = inspect_bytes(contract, builder.build())
    assert [d.code for d in report.structural] == ["MBPF403"]
    assert_rendered(report.structural[0], (
            'MBPF403 (inspect.object/error): missing license section; '
            'location: <tmp>; remedy: rebuild so the object carries '
            'exactly one license payload'
        ), path)
    neighbor, _ = inspect_bytes(
        contract, contract._clean_builder().build()
    )
    assert neighbor.ok is True
    print("PASS MBPF403 exact + neighbor inspects clean")


def test_object_404_unknown_symbols():
    contract = _load_contract()
    builder = contract._clean_builder()
    builder.add_symbol("helper_x", 0, contract.SHN_UNDEF)
    builder.add_symbol("another_ext", 0, contract.SHN_UNDEF)
    report, path = inspect_bytes(contract, builder.build())
    assert [d.code for d in report.structural] == ["MBPF404"]
    assert_rendered(report.structural[0], (
            'MBPF404 (inspect.object/error): unknown external symbols: '
            'another_ext, helper_x; location: <tmp>; remedy: resolve '
            'every external symbol before publication'
        ), path)
    neighbor, _ = inspect_bytes(
        contract, contract._clean_builder().build()
    )
    assert neighbor.ok is True
    print("PASS MBPF404 exact + neighbor inspects clean")


def test_object_405_inconsistent_metadata():
    contract = _load_contract()
    builder = contract._clean_builder()
    builder.add_section(
        ".maps", contract.SHT_PROGBITS, 0, b"\x00" * 32, align=8
    )
    report, path = inspect_bytes(contract, builder.build())
    assert [d.code for d in report.structural] == ["MBPF405"]
    assert_rendered(report.structural[0], (
            'MBPF405 (inspect.object/error): inconsistent map metadata: '
            '.maps present: True, .BTF present: False; location: <tmp>; '
            'remedy: rebuild so map definitions and map BTF agree'
        ), path)
    neighbor, _ = inspect_bytes(
        contract, contract._clean_builder().build()
    )
    assert neighbor.ok is True
    print("PASS MBPF405 exact + neighbor inspects clean")


def test_object_406_outside_profile():
    contract = _load_contract()
    builder = contract.ElfBuilder()
    builder.add_section(
        "tracepoint/x",
        contract.SHT_PROGBITS,
        contract.SHF_EXECINSTR,
        contract._exit_code(),
        align=8,
    )
    builder.add_section(
        "license", contract.SHT_PROGBITS, 0, contract.APACHE_BYTES,
        align=1,
    )
    report, path = inspect_bytes(contract, builder.build())
    assert [d.code for d in report.unsupported] == ["MBPF406"]
    assert_rendered(report.unsupported[0], (
            'MBPF406 (inspect.object/error): executable section '
            "'tracepoint/x' is outside profile 'linux-bpfel-v3' "
            '(supported: tracepoint/syscalls/sys_enter_getpid, xdp); '
            'location: section:tracepoint/x; remedy: use only program '
            'sections of the named profile'
        ), path)
    neighbor, _ = inspect_bytes(
        contract, contract._clean_builder().build()
    )
    assert neighbor.ok is True
    print("PASS MBPF406 exact + neighbor inspects clean")


def test_object_407_unsupported_feature():
    contract = _load_contract()
    code = contract._call_code(7) + contract._exit_code()
    report, path = inspect_bytes(
        contract, contract._clean_builder(code=code).build()
    )
    assert [d.code for d in report.unsupported] == ["MBPF407"]
    assert_rendered(report.unsupported[0], (
            'MBPF407 (inspect.object/error): call to helper ID 7 in '
            "section 'xdp' is outside profile 'linux-bpfel-v3' "
            '(supported IDs: 1, 2, 3, 5, 8, 14, 130); location: '
            'section:xdp+0x0; remedy: use only helpers of the named profile'
        ), path)
    good = contract._call_code(1) + contract._call_code(2)
    good += contract._exit_code()
    neighbor, _ = inspect_bytes(
        contract, contract._clean_builder(code=good).build()
    )
    assert contract._codes(neighbor) == ([], [], [])
    print("PASS MBPF407 exact + neighbor inspects clean")


def test_object_705_license_value_mismatch():
    contract = _load_contract()
    image = contract._clean_builder(b"MIT\x00").build()
    verified, path = verify_bytes(contract, image)
    assert [d.code for d in verified.license] == ["MBPF705"]
    assert_rendered(verified.license[0], (
            "MBPF705 (inspect.license/error): object '<tmp>' declares "
            "license b'MIT\\x00', validated declaration is b'Apache-2.0 "
            "WITH LLVM-exception\\x00'; location: section:license; "
            'remedy: rebuild with the validated declaration'
        ), path)
    neighbor, _ = verify_bytes(
        contract, contract._clean_builder().build()
    )
    assert neighbor.ok is True, neighbor.to_dict()
    assert neighbor.license == ()
    print("PASS MBPF705 exact + neighbor verifies")


# ---------------------------------------------------------------------------
# License and provenance codes (MBPF701-MBPF704, MBPF706-MBPF709).
# ---------------------------------------------------------------------------

APACHE_HDR = "# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception\n"
MIT_HDR = "# SPDX-License-Identifier: MIT\n"
NO_HDR = "# no license tag here\n"


def write_grant_file(parent, name, content):
    path = os.path.join(parent, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


def test_license_701_bad_spdx():
    try:
        inspect_module.parse_spdx_expression("MIT OR")
    except inspect_module.InspectionError as exc:
        assert exc.diagnostic.code == "MBPF701", exc.diagnostic
        assert_rendered(exc.diagnostic, (
            'MBPF701 (inspect.license/error): malformed SPDX expression '
            "'MIT OR': unexpected end; remedy: use '<license>' or "
            "'<license> WITH <exception>', joined with AND/OR"
        ))
    else:
        raise AssertionError("expected MBPF701 for 'MIT OR'")
    parsed = inspect_module.parse_spdx_expression(APACHE)
    assert parsed.text == APACHE
    print("PASS MBPF701 exact + neighbor parses")


def test_license_702_grant_mismatch():
    parent = tempfile.mkdtemp(prefix="grant-catalog-")
    path = write_grant_file(parent, "prog.mojo", MIT_HDR)
    try:
        inspect_module.validate_source_grants(
            APACHE, [path], project_dir=parent
        )
    except inspect_module.InspectionError as exc:
        assert exc.diagnostic.code == "MBPF702", exc.diagnostic
        assert_rendered(exc.diagnostic, (
            'MBPF702 (inspect.license/error): program source '
            "'<tmp>/prog.mojo' grants 'MIT', declared source grant is "
            "'Apache-2.0 WITH LLVM-exception'; location: "
            '<tmp>/prog.mojo; remedy: align the header with the declared '
            'source grant'
        ), parent)
    else:
        raise AssertionError("expected MBPF702 for an MIT header")
    good = write_grant_file(parent, "good.mojo", APACHE_HDR)
    record = inspect_module.validate_source_grants(
        APACHE, [good], project_dir=parent
    )
    assert record.source_license == APACHE
    print("PASS MBPF702 exact + neighbor validates")


def test_license_703_mixed_grants():
    parent = tempfile.mkdtemp(prefix="grant-catalog-")
    prog = write_grant_file(parent, "prog.mojo", APACHE_HDR)
    sdk = write_grant_file(parent, "sdk.mojo", MIT_HDR)
    try:
        inspect_module.validate_source_grants(
            APACHE, [prog], sdk_sources=[sdk], project_dir=parent
        )
    except inspect_module.InspectionError as exc:
        assert exc.diagnostic.code == "MBPF703", exc.diagnostic
        assert_rendered(exc.diagnostic, (
            'MBPF703 (inspect.license/error): unsupported mixed-license '
            "arrangement: SDK file '<tmp>/sdk.mojo' grants 'MIT', "
            "program sources grant 'Apache-2.0 WITH LLVM-exception'; "
            'location: <tmp>/sdk.mojo; remedy: use SDK files under the '
            'declared source grant'
        ), parent)
    else:
        raise AssertionError("expected MBPF703 for mixed grants")
    record = inspect_module.validate_source_grants(
        APACHE, [prog], sdk_sources=[prog], project_dir=parent
    )
    assert record.source_license == APACHE
    print("PASS MBPF703 exact + neighbor validates")


def test_license_704_unmapped_pair():
    try:
        inspect_module.validate_declaration_pair(APACHE, "GPL")
    except inspect_module.InspectionError as exc:
        assert exc.diagnostic.code == "MBPF704", exc.diagnostic
        assert_rendered(exc.diagnostic, (
            'MBPF704 (inspect.license/error): declaration pair '
            "('Apache-2.0 WITH LLVM-exception', 'GPL') is not in license "
            "mapping version 1; only [('Apache-2.0 WITH LLVM-exception', "
            "'Apache-2.0 WITH LLVM-exception')] is qualified; remedy: "
            'use the qualified pair or seek a reviewed mapping'
        ))
    else:
        raise AssertionError("expected MBPF704 for the GPL pair")
    validated = inspect_module.validate_declaration_pair(
        APACHE, APACHE
    )
    assert validated.kernel_license == APACHE
    print("PASS MBPF704 exact + neighbor validates")


def test_license_706_restricted_helper():
    try:
        inspect_module.requires_gpl((7,), ("xdp",), (), PROFILE_ID)
    except inspect_module.InspectionError as exc:
        assert exc.diagnostic.code == "MBPF706", exc.diagnostic
        assert_rendered(exc.diagnostic, (
            'MBPF706 (inspect.license/error): cannot establish licensing '
            'requirements: helper ID 7 is outside profile '
            "'linux-bpfel-v3' (supported IDs: 1, 2, 3, 5, 8, 14, 130); "
            'remedy: use only helpers of the named profile'
        ))
    else:
        raise AssertionError("expected MBPF706 for helper 7")
    assert inspect_module.requires_gpl(
        (1, 2, 14), ("tracepoint",), (), PROFILE_ID
    ) is False
    print("PASS MBPF706 exact + neighbor answers")


def test_license_707_missing_header():
    parent = tempfile.mkdtemp(prefix="grant-catalog-")
    path = write_grant_file(parent, "prog.mojo", NO_HDR)
    try:
        inspect_module.validate_source_grants(
            APACHE, [path], project_dir=parent
        )
    except inspect_module.InspectionError as exc:
        assert exc.diagnostic.code == "MBPF707", exc.diagnostic
        assert_rendered(exc.diagnostic, (
            'MBPF707 (inspect.license/error): program source '
            "'<tmp>/prog.mojo' carries no SPDX header; location: "
            "<tmp>/prog.mojo; remedy: add an 'SPDX-License-Identifier: "
            "...' header line"
        ), parent)
    else:
        raise AssertionError("expected MBPF707 for a missing header")
    good = write_grant_file(parent, "good.mojo", APACHE_HDR)
    record = inspect_module.validate_source_grants(
        APACHE, [good], project_dir=parent
    )
    assert record.source_license == APACHE
    print("PASS MBPF707 exact + neighbor validates")


def test_license_708_unreadable_provenance_input():
    missing = os.path.join(
        tempfile.mkdtemp(prefix="grant-catalog-"), "no-such.mojo"
    )
    try:
        evidence_module.hash_file(missing)
    except evidence_module.EvidenceError as exc:
        assert exc.diagnostic.code == "MBPF708", exc.diagnostic
        assert_rendered(
            exc.diagnostic, (
            'MBPF708 (evidence.capture/error): cannot read provenance '
            "input '<tmp>/no-such.mojo': [Errno 2] No such file or "
            "directory: '<tmp>/no-such.mojo'; location: "
            '<tmp>/no-such.mojo; remedy: check the input path and permissions'
        ), os.path.dirname(missing)
        )
    else:
        raise AssertionError("expected MBPF708 for a missing file")
    parent = tempfile.mkdtemp(prefix="grant-catalog-")
    path = write_grant_file(parent, "prog.mojo", APACHE_HDR)
    hashed = evidence_module.hash_file(path, parent)
    assert hashed.path == "prog.mojo"
    print("PASS MBPF708 exact + neighbor hashes")


def test_license_709_gpl_only_helper():
    try:
        inspect_module.preflight_helper_licenses(
            (35,), APACHE, PROFILE_ID
        )
    except inspect_module.InspectionError as exc:
        assert exc.diagnostic.code == "MBPF709", exc.diagnostic
        assert exc.diagnostic.stage == "inspect.license"
        assert_rendered(exc.diagnostic, (
            'MBPF709 (inspect.license/error): helper 35 '
            '(bpf_get_current_task) is GPL-only but kernel license '
            "'Apache-2.0 WITH LLVM-exception' is not a kernel-recognized "
            "GPL-compatible declaration under profile 'linux-bpfel-v3'; "
            'remedy: restrict the program to non-GPL facilities'
        ))
    else:
        raise AssertionError("expected MBPF709 for helper 35")
    inspect_module.preflight_helper_licenses(
        [1, 2, 3, 5, 8, 14, 130], APACHE, PROFILE_ID
    )
    print("PASS MBPF709 exact + neighbor passes")


# ---------------------------------------------------------------------------
# Build-step codes (MBPF106 frontend/backend, MBPF107, MBPF216, MBPF218).
# ---------------------------------------------------------------------------


def test_build_106_frontend_error():
    check_tools()
    root, manifest_path, out_dir = copy_project(
        BAD_SOURCE, xdp_manifest("probe_bad.mojo", "xdp_entry", "b106")
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF106", diagnostic
    assert diagnostic.stage == "build.frontend", diagnostic
    assert_rendered(diagnostic, (
            'MBPF106 (build.frontend/error): frontend step exited 1: '
            '<mojo> build --emit llvm --target-cpu znver4 --target-features +adx,+aes,+avx,+avx2,+avx512bf16,+avx512bitalg,+avx512bw,+avx512cd,+avx512dq,+avx512f,+avx512ifma,+avx512vbmi,+avx512vbmi2,+avx512vl,+avx512vnni,+avx512vpopcntdq,+bmi,+bmi2,+clflushopt,+clwb,+clzero,+crc32,+cx16,+cx8,+f16c,+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,+mmx,+movbe,+mwaitx,+pclmul,+pku,+popcnt,+prfchw,+rdpid,+rdpru,+rdrnd,+rdseed,+sahf,+sha,+shstk,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+sse4a,+ssse3,+vaes,+vpclmulqdq,+wbnoinvd,+x87,+xsave,+xsavec,+xsaveopt,+xsaves -o /tmp/<work>/xdp_entry.raw.ll '
            '<tmp>/proj/probe_bad.mojo; location: '
            '<tmp>/proj/probe_bad.mojo:7:12: error: expected argument '
            'name; remedy: fix the reported error; the log excerpt names it'
        ), root, extra=tool_extra())
    _root, good_manifest, good_out = copy_project(
        CLASSIFIER_SOURCE,
        xdp_manifest("xdp_pass.mojo", "xdp_entry", "b106n"),
    )
    good = build(good_manifest, good_out)
    assert good.success is True, good.diagnostics
    assert_no_diagnose_record(good)
    print("PASS MBPF106/frontend exact + neighbor builds")


def test_build_106_backend_error():
    check_tools()
    root, manifest_path, out_dir = copy_project(
        DEEP_STACK_SOURCE,
        xdp_manifest(
            "subset_deep_stack.mojo", "xdp_entry", "b106b"
        ),
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF106", diagnostic
    assert diagnostic.stage == "build.backend", diagnostic
    assert "BPF stack limit" in diagnostic.explanation or (
        "BPF stack limit" in (diagnostic.location or "")
    ), diagnostic
    assert_rendered(diagnostic, (
            'MBPF106 (build.backend/error): backend step exited 1: <llc> '
            '-mtriple=bpfel -mcpu=v3 -filetype=obj '
            '/tmp/<work>/xdp_entry.adapter/adapted.ll -o '
            '/tmp/<work>/xdp_entry.bpf.o; location: error: '
            '<unknown>:0:0: in function xdp_entry i32 (ptr): Looks like '
            'the BPF stack limit is exceeded. Please move large on stack '
            'variables into BPF per-cpu array map. For non-kernel uses, '
            'the stack can be increased using -mllvm -bpf-stack-size.; '
            'remedy: fix the reported error; the log excerpt names it'
        ), root, extra=tool_extra())
    _root, good_manifest, good_out = copy_project(
        CLASSIFIER_SOURCE,
        xdp_manifest("xdp_pass.mojo", "xdp_entry", "b106bn"),
    )
    good = build(good_manifest, good_out)
    assert good.success is True, good.diagnostics
    assert_no_diagnose_record(good)
    print("PASS MBPF106/backend exact + neighbor builds")


def test_build_107_spill_gate():
    check_tools()
    root, manifest_path, out_dir = copy_project(
        MUTATED_SOURCE,
        xdp_manifest(
            "map_roundtrip_mutated.mojo", "xdp_entry", "b107",
            max_entries=1,
        ),
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF107", diagnostic
    assert diagnostic.stage == "build.backend", diagnostic
    assert_rendered(diagnostic, (
            'MBPF107 (build.backend/error): built map object leaves the '
            'qualified shape: xdp add-immediate set [-16, -4, -4, 2], '
            'expected [-16, -4, -4, 1]; location: '
            '/tmp/<work>/xdp_entry.bpf.o; remedy: keep the map program '
            'within the qualified shape; only the proven object layout '
            'is published'
        ), root)
    _root, good_manifest, good_out = copy_project(
        MAP_SOURCE,
        xdp_manifest(
            "map_roundtrip.mojo", "xdp_entry", "b107n",
            max_entries=1,
        ),
    )
    good = build(good_manifest, good_out)
    assert good.success is True, good.diagnostics
    assert_no_diagnose_record(good)
    print("PASS MBPF107 exact + neighbor builds")


def test_build_216_entry_reconciliation():
    check_tools()
    root, manifest_path, out_dir = copy_project(
        COMBINED_SOURCE,
        xdp_manifest(
            "packet_counter.mojo", "xdp_entry", "b216",
            max_entries=1,
        ),
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF216", diagnostic
    assert diagnostic.stage == "build.backend", diagnostic
    assert_rendered(diagnostic, (
            'MBPF216 (build.backend/error): built combined object '
            "'/tmp/<work>/xdp_entry.bpf.o' emits a 2-entry map but "
            'manifest.maps declares max_entries = 1; location: '
            '/tmp/<work>/xdp_entry.bpf.o; remedy: declare max_entries = '
            '2 for this program shape; wider shapes need a reviewed route'
        ), root)
    _root, good_manifest, good_out = copy_project(
        MAP_SOURCE,
        xdp_manifest(
            "map_roundtrip.mojo", "xdp_entry", "b216n",
            max_entries=1,
        ),
    )
    good = build(good_manifest, good_out)
    assert good.success is True, good.diagnostics
    assert_no_diagnose_record(good)
    print("PASS MBPF216 exact + neighbor builds")


def test_build_104_partial_pins_refuse_default():
    check_tools()
    root, manifest_path, out_dir = copy_project(
        CLASSIFIER_SOURCE,
        xdp_manifest("xdp_pass.mojo", "xdp_entry", "b218"),
    )
    lock_path = os.path.join(root, "unpinned-lock.json")
    with open(LOCKFILE, encoding="utf-8") as handle:
        document = json.load(handle)
    # A lockfile with sibling pins but no service pin refuses the
    # packaged default: the executed service bytes are unvetted,
    # and warnings never substitute for refusal. The distribution
    # closure (bound to a file beside the release lock) is
    # dropped, as in test and legacy locks.
    document["adapter"].pop("service_sha256", None)
    document.pop("distribution", None)
    with open(lock_path, "w", encoding="utf-8") as handle:
        json.dump(document, handle)
    result = build_project(
        BuildRequest(
            manifest_path=manifest_path,
            out_dir=out_dir,
            adapter_path=default_adapter_path(),
            lockfile_path=lock_path,
        )
    )
    assert result.success is False, result.diagnostics
    assert len(result.diagnostics) == 1, result.diagnostics
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF104", diagnostic
    assert diagnostic.stage == "build.setup", diagnostic
    assert diagnostic.severity == "error", diagnostic
    assert "adapter record" in diagnostic.explanation, diagnostic
    assert_no_diagnose_record(result)
    _root, good_manifest, good_out = copy_project(
        CLASSIFIER_SOURCE,
        xdp_manifest("xdp_pass.mojo", "xdp_entry", "b218n"),
    )
    good = build_project(
        BuildRequest(
            manifest_path=good_manifest,
            out_dir=good_out,
            adapter_path=default_adapter_path(),
            lockfile_path=LOCKFILE,
        )
    )
    assert good.success is True, good.diagnostics
    assert good.diagnostics == (), good.diagnostics
    assert_no_diagnose_record(good)
    print("PASS MBPF104 partial refusal + neighbor builds")


def test_rendering_formats_agree():
    from mojobpf.diagnostics import Diagnostic

    diagnostic = Diagnostic(
        code="MBPF302",
        stage="adapter.audit",
        severity="error",
        explanation="entry shape",
        location="prog.mojo:6: def xdp_entry():",
        remedy="fix the entry",
    )
    assert MojobpfError(diagnostic).__str__() == rendered(diagnostic)
    assert_shape(diagnostic)
    print("PASS exception and CLI renderings agree")


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
    print("diagnostic catalog: %d cases green" % len(names))
    return 0


if __name__ == "__main__":
    sys.exit(main())
