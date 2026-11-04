# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for manifest parsing and the target-profile registry.

Every malformed input must fail with one deterministic diagnostic code;
each test below asserts the exact code. Uses only the standard library.

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3 tests/unit/test_manifest.py``).
"""

import json
import os
import sys
import tempfile

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

from mojobpf.diagnostics import MojobpfError  # noqa: E402
from mojobpf.manifest import (  # noqa: E402
    SUPPORTED_PROFILE_IDS,
    ManifestError,
    ProfileError,
    lookup_profile,
    parse_manifest,
)

SCHEMA_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "..",
    "schemas",
    "manifest.schema.json",
)

VALID_MANIFEST = """\
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


def write_project(manifest_text, sources=("src/xdp.mojo",)):
    """Create a temp project dir; return (manifest_path, tmpdir)."""
    tmpdir = tempfile.mkdtemp(prefix="manifest-test-")
    manifest_path = os.path.join(tmpdir, "mojobpf.toml")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(manifest_text)
    for source in sources:
        full = os.path.join(tmpdir, source)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as handle:
            handle.write("# fixture source\n")
    return manifest_path, tmpdir


def expect_code(manifest_text, code, sources=("src/xdp.mojo",)):
    """Parse a manifest and assert it fails with exactly ``code``."""
    manifest_path, _tmpdir = write_project(manifest_text, sources)
    try:
        parse_manifest(manifest_path)
    except MojobpfError as exc:
        assert exc.diagnostic.code == code, (
            "expected %s, got %s (%s)"
            % (code, exc.diagnostic.code, exc.diagnostic.explanation)
        )
        assert exc.diagnostic.severity == "error"
        assert exc.diagnostic.stage in (
            "manifest.parse",
            "profile.resolve",
        )
        assert exc.diagnostic.explanation
        assert exc.diagnostic.remedy
        return exc.diagnostic
    raise AssertionError("expected failure %s, manifest parsed" % code)


def mutate(section_anchor, replacement):
    """Return VALID_MANIFEST with one line replaced (exact match)."""
    lines = VALID_MANIFEST.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.strip() == section_anchor.strip():
            lines[index] = replacement
            return "".join(lines)
    raise AssertionError("anchor not found: %r" % section_anchor)


def mutate_in(text, anchor, replacement):
    """Return text with one line replaced (exact match)."""
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.strip() == anchor.strip():
            lines[index] = replacement
            return "".join(lines)
    raise AssertionError("anchor not found: %r" % anchor)


def test_valid_manifest_parses_to_versioned_model():
    manifest_path, _tmpdir = write_project(VALID_MANIFEST)
    manifest = parse_manifest(manifest_path)
    assert manifest.schema_version == 1
    assert manifest.project.name == "packet-counter"
    assert manifest.target.profile == "linux-bpfel-v3"
    assert manifest.target.core is False
    assert manifest.artifact.name == "packet_counter"
    assert manifest.artifact.kernel_license == (
        "Apache-2.0 WITH LLVM-exception"
    )
    assert len(manifest.programs) == 1
    program = manifest.programs[0]
    assert program.source == "src/xdp.mojo"
    assert program.entry == "xdp_entry"
    assert program.program_type == "xdp"
    assert program.section == "xdp"
    assert len(manifest.maps) == 1
    mapping = manifest.maps[0]
    assert mapping.name == "mojobpf_map0"
    assert mapping.map_type == "array"
    assert mapping.key_type == "u32"
    assert mapping.value_type == "u64"
    assert mapping.max_entries == 1
    assert manifest.manifest_path == manifest_path


def test_manifest_without_maps_parses():
    text = VALID_MANIFEST.split("[[maps]]")[0]
    manifest_path, _tmpdir = write_project(text)
    manifest = parse_manifest(manifest_path)
    assert manifest.maps == ()


def test_profile_registry_holds_supported_profiles():
    assert SUPPORTED_PROFILE_IDS == (
        "linux-bpfel-v3",
        "linux-bpfel-v3-core",
        "linux-bpfel-v3-hash",
        "linux-bpfel-v3-reserve",
        "linux-bpfel-v3-subprog",
        "linux-bpfel-v3-uprobe",
    )
    profile = lookup_profile("linux-bpfel-v3")
    assert profile.byte_order == "little"
    assert profile.cpu == "v3"
    assert profile.allowed_pairs == (
        ("xdp", "xdp"),
        ("tracepoint", "tracepoint/syscalls/sys_enter_getpid"),
    )
    assert profile.allowed_map_types == ("array", "percpu_array", "ringbuf")
    assert profile.allowed_key_types == ("u32",)
    assert profile.allowed_value_types == ("u64",)
    assert profile.allowed_max_entries == (1, 2, 3, 4)
    assert profile.allowed_ringbuf_sizes == (4096, 131072)
    assert profile.helper_ids == (1, 2, 3, 5, 8, 14, 130)
    assert profile.btf_scope == "map-only"
    assert profile.entry_return == "i32"
    assert profile.entry_parameters == ("ptr",)
    assert profile.core_supported is False
    assert profile.subprog_supported is False


def test_core_profile_extends_base_with_core_vocabulary():
    profile = lookup_profile("linux-bpfel-v3-core")
    base = lookup_profile("linux-bpfel-v3")
    assert profile.byte_order == base.byte_order
    assert profile.cpu == base.cpu
    assert profile.allowed_pairs == base.allowed_pairs
    assert profile.allowed_map_types == base.allowed_map_types
    assert profile.allowed_key_types == base.allowed_key_types
    assert profile.allowed_value_types == ("u64", "bytes4096")
    assert profile.allowed_max_entries == base.allowed_max_entries
    assert profile.allowed_ringbuf_sizes == base.allowed_ringbuf_sizes
    assert profile.helper_ids == base.helper_ids
    assert profile.btf_scope == "map-and-core"
    assert profile.entry_return == base.entry_return
    assert profile.entry_parameters == base.entry_parameters
    assert profile.core_supported is True
    assert profile.subprog_supported is False


def test_hash_profile_extends_base_with_hash_vocabulary():
    profile = lookup_profile("linux-bpfel-v3-hash")
    base = lookup_profile("linux-bpfel-v3")
    assert profile.byte_order == base.byte_order
    assert profile.cpu == base.cpu
    assert profile.allowed_pairs == base.allowed_pairs
    assert profile.allowed_map_types == (
        "array", "percpu_array", "ringbuf", "hash",
    )
    assert profile.allowed_key_types == base.allowed_key_types
    assert profile.allowed_value_types == base.allowed_value_types
    assert profile.allowed_max_entries == base.allowed_max_entries
    assert profile.allowed_ringbuf_sizes == base.allowed_ringbuf_sizes
    assert profile.helper_ids == base.helper_ids
    assert profile.btf_scope == base.btf_scope
    assert profile.entry_return == base.entry_return
    assert profile.entry_parameters == base.entry_parameters
    assert profile.core_supported is False
    assert profile.subprog_supported is False


def test_reserve_profile_extends_base_with_reserve_helpers():
    profile = lookup_profile("linux-bpfel-v3-reserve")
    base = lookup_profile("linux-bpfel-v3")
    assert profile.byte_order == base.byte_order
    assert profile.cpu == base.cpu
    assert profile.allowed_pairs == base.allowed_pairs
    assert profile.allowed_map_types == base.allowed_map_types
    assert profile.allowed_key_types == base.allowed_key_types
    assert profile.allowed_value_types == base.allowed_value_types
    assert profile.allowed_max_entries == base.allowed_max_entries
    assert profile.allowed_ringbuf_sizes == base.allowed_ringbuf_sizes
    assert profile.helper_ids == (
        1, 2, 3, 5, 8, 14, 130, 131, 132, 133,
    )
    assert profile.helper_ids[:7] == base.helper_ids
    assert profile.btf_scope == base.btf_scope
    assert profile.entry_return == base.entry_return
    assert profile.entry_parameters == base.entry_parameters
    assert profile.core_supported is False
    assert profile.subprog_supported is False


def test_subprog_profile_extends_base_with_subprog_flag():
    profile = lookup_profile("linux-bpfel-v3-subprog")
    base = lookup_profile("linux-bpfel-v3")
    assert profile.byte_order == base.byte_order
    assert profile.cpu == base.cpu
    assert profile.allowed_pairs == base.allowed_pairs
    assert profile.allowed_map_types == base.allowed_map_types
    assert profile.allowed_key_types == base.allowed_key_types
    assert profile.allowed_value_types == base.allowed_value_types
    assert profile.allowed_max_entries == base.allowed_max_entries
    assert profile.allowed_ringbuf_sizes == base.allowed_ringbuf_sizes
    assert profile.helper_ids == base.helper_ids
    assert profile.btf_scope == base.btf_scope
    assert profile.entry_return == base.entry_return
    assert profile.entry_parameters == base.entry_parameters
    assert profile.core_supported is False
    assert profile.subprog_supported is True
    assert base.subprog_supported is False


def test_uprobe_profile_extends_base_with_uprobe_pair():
    profile = lookup_profile("linux-bpfel-v3-uprobe")
    base = lookup_profile("linux-bpfel-v3")
    assert profile.byte_order == base.byte_order
    assert profile.cpu == base.cpu
    assert profile.allowed_pairs == (
        base.allowed_pairs + (("uprobe", "uprobe"),)
    )
    assert profile.allowed_map_types == base.allowed_map_types
    assert profile.allowed_key_types == base.allowed_key_types
    assert profile.allowed_value_types == base.allowed_value_types
    assert profile.allowed_max_entries == base.allowed_max_entries
    assert profile.allowed_ringbuf_sizes == base.allowed_ringbuf_sizes
    assert profile.helper_ids == base.helper_ids
    assert profile.btf_scope == base.btf_scope
    assert profile.entry_return == base.entry_return
    assert profile.entry_parameters == base.entry_parameters
    assert profile.core_supported is False
    assert profile.subprog_supported is False


def test_uprobe_pair_parses_under_uprobe_profile():
    text = mutate(
        'profile = "linux-bpfel-v3"',
        'profile = "linux-bpfel-v3-uprobe"\n',
    )
    text = mutate_in(text, 'entry = "xdp_entry"', 'entry = "uprobe_entry"\n')
    text = mutate_in(text, 'program_type = "xdp"', 'program_type = "uprobe"\n')
    text = mutate_in(text, 'section = "xdp"', 'section = "uprobe"\n')
    text = mutate_in(text, "max_entries = 1", "max_entries = 2\n")
    manifest_path, _tmpdir = write_project(text)
    manifest = parse_manifest(manifest_path)
    assert manifest.target.profile == "linux-bpfel-v3-uprobe"
    assert len(manifest.programs) == 1
    program = manifest.programs[0]
    assert program.entry == "uprobe_entry"
    assert program.program_type == "uprobe"
    assert program.section == "uprobe"


def test_uprobe_pair_refused_under_base_profile():
    text = mutate_in(VALID_MANIFEST, 'entry = "xdp_entry"', 'entry = "uprobe_entry"\n')
    text = mutate_in(text, 'program_type = "xdp"', 'program_type = "uprobe"\n')
    text = mutate_in(text, 'section = "xdp"', 'section = "uprobe"\n')
    diagnostic = expect_code(text, "MBPF206")
    assert "'uprobe'" in diagnostic.explanation


def test_uprobe_wrong_section_refused():
    text = mutate(
        'profile = "linux-bpfel-v3"',
        'profile = "linux-bpfel-v3-uprobe"\n',
    )
    text = mutate_in(text, 'program_type = "xdp"', 'program_type = "uprobe"\n')
    diagnostic = expect_code(text, "MBPF206")
    assert "'uprobe'" in diagnostic.explanation
    assert "'xdp'" in diagnostic.explanation


def test_two_uprobe_programs_refused():
    text = mutate(
        'profile = "linux-bpfel-v3"',
        'profile = "linux-bpfel-v3-uprobe"\n',
    )
    text = mutate_in(text, 'entry = "xdp_entry"', 'entry = "uprobe_entry"\n')
    text = mutate_in(text, 'program_type = "xdp"', 'program_type = "uprobe"\n')
    text = mutate_in(text, 'section = "xdp"', 'section = "uprobe"\n')
    extra = (
        '\n[[programs]]\nsource = "src/other.mojo"\n'
        'entry = "uprobe_entry_two"\nprogram_type = "uprobe"\n'
        'section = "uprobe"\n'
    )
    text = text.split("[[maps]]")[0] + extra
    diagnostic = expect_code(
        text, "MBPF211", sources=("src/xdp.mojo", "src/other.mojo")
    )
    assert "at most one uprobe program" in diagnostic.explanation


def test_uprobe_plus_xdp_program_refused():
    text = mutate(
        'profile = "linux-bpfel-v3"',
        'profile = "linux-bpfel-v3-uprobe"\n',
    )
    text = mutate_in(text, 'entry = "xdp_entry"', 'entry = "uprobe_entry"\n')
    text = mutate_in(text, 'program_type = "xdp"', 'program_type = "uprobe"\n')
    text = mutate_in(text, 'section = "xdp"', 'section = "uprobe"\n')
    extra = (
        '\n[[programs]]\nsource = "src/other.mojo"\n'
        'entry = "xdp_entry"\nprogram_type = "xdp"\nsection = "xdp"\n'
    )
    text = text.split("[[maps]]")[0] + extra
    diagnostic = expect_code(
        text, "MBPF211", sources=("src/xdp.mojo", "src/other.mojo")
    )
    assert "single uprobe program" in diagnostic.explanation


def test_hash_manifest_parses_under_hash_profile():
    text = mutate(
        'profile = "linux-bpfel-v3"',
        'profile = "linux-bpfel-v3-hash"\n',
    )
    text = mutate_in(text, 'map_type = "array"', 'map_type = "hash"\n')
    manifest_path, _tmpdir = write_project(text)
    manifest = parse_manifest(manifest_path)
    assert manifest.target.profile == "linux-bpfel-v3-hash"
    assert len(manifest.maps) == 1
    mapping = manifest.maps[0]
    assert mapping.map_type == "hash"
    assert mapping.key_type == "u32"
    assert mapping.value_type == "u64"
    assert mapping.max_entries == 1


def _hash_text():
    text = mutate(
        'profile = "linux-bpfel-v3"',
        'profile = "linux-bpfel-v3-hash"\n',
    )
    return mutate_in(text, 'map_type = "array"', 'map_type = "hash"\n')


def test_hash_profile_refuses_non_hash_kinds():
    for refused in ("lru_hash", "array_of_maps", "prog_array"):
        text = mutate_in(
            _hash_text(), 'map_type = "hash"',
            'map_type = "%s"\n' % refused,
        )
        diagnostic = expect_code(text, "MBPF205")
        assert refused in diagnostic.explanation


def test_hash_profile_refuses_bad_key_value_sizes():
    text = mutate_in(
        _hash_text(), 'key_type = "u32"', 'key_type = "u16"\n'
    )
    diagnostic = expect_code(text, "MBPF205")
    assert "u16" in diagnostic.explanation
    text = mutate_in(
        _hash_text(), 'value_type = "u64"', 'value_type = "u32"\n'
    )
    diagnostic = expect_code(text, "MBPF205")
    assert "u32" in diagnostic.explanation
    text = mutate_in(_hash_text(), "max_entries = 1", "max_entries = 5\n")
    diagnostic = expect_code(text, "MBPF205")
    assert "5" in diagnostic.explanation


def test_unknown_schema_version_fails():
    text = mutate("schema_version = 1", "schema_version = 99\n")
    expect_code(text, "MBPF201")


def test_unknown_top_level_field_fails():
    text = VALID_MANIFEST + '\n[extra]\nkey = "value"\n'
    expect_code(text, "MBPF202")


def test_unknown_nested_field_fails():
    text = mutate(
        'name = "packet-counter"', 'name = "packet-counter"\nextra = 1\n'
    )
    expect_code(text, "MBPF202")


def test_duplicate_program_entry_fails():
    extra = (
        "\n[[programs]]\nsource = \"src/other.mojo\"\n"
        'entry = "xdp_entry"\nprogram_type = "xdp"\nsection = "xdp"\n'
    )
    text = VALID_MANIFEST.split("[[maps]]")[0] + extra
    expect_code(
        text, "MBPF203", sources=("src/xdp.mojo", "src/other.mojo")
    )


def test_duplicate_map_name_fails():
    extra = (
        '\n[[maps]]\nname = "mojobpf_map0"\nmap_type = "array"\n'
        'key_type = "u32"\nvalue_type = "u64"\nmax_entries = 1\n'
    )
    expect_code(VALID_MANIFEST + extra, "MBPF204")


def test_zero_max_entries_fails():
    text = mutate("max_entries = 1", "max_entries = 0\n")
    diagnostic = expect_code(text, "MBPF205")
    assert "max_entries" in diagnostic.explanation


def test_oversize_max_entries_fails():
    text = mutate("max_entries = 1", "max_entries = 4294967296\n")
    expect_code(text, "MBPF205")


def test_two_entry_count_parses():
    text = mutate("max_entries = 1", "max_entries = 2\n")
    manifest_path, _tmpdir = write_project(text)
    manifest = parse_manifest(manifest_path)
    assert manifest.maps[0].max_entries == 2


def test_supported_entry_counts_parse():
    for count in (1, 2, 3, 4):
        text = mutate(
            "max_entries = 1", "max_entries = %d\n" % count
        )
        manifest_path, _tmpdir = write_project(text)
        manifest = parse_manifest(manifest_path)
        assert manifest.maps[0].max_entries == count, count


def test_unsupported_entry_count_fails():
    text = mutate("max_entries = 1", "max_entries = 5\n")
    diagnostic = expect_code(text, "MBPF205")
    assert "max_entries" in diagnostic.explanation


def test_bad_key_width_fails():
    text = mutate('key_type = "u32"', 'key_type = "u16"\n')
    expect_code(text, "MBPF205")


def test_bad_value_width_fails():
    text = mutate('value_type = "u64"', 'value_type = "u32"\n')
    expect_code(text, "MBPF205")


def test_supported_map_types_parse():
    for kind in ("array", "percpu_array"):
        text = mutate(
            'map_type = "array"', 'map_type = "%s"\n' % kind
        )
        manifest_path, _tmpdir = write_project(text)
        manifest = parse_manifest(manifest_path)
        assert manifest.maps[0].map_type == kind, kind


def test_hash_map_type_refused():
    text = mutate('map_type = "array"', 'map_type = "hash"\n')
    diagnostic = expect_code(text, "MBPF205")
    assert "hash" in diagnostic.explanation


def test_lru_map_type_refused():
    text = mutate('map_type = "array"', 'map_type = "lru_hash"\n')
    diagnostic = expect_code(text, "MBPF205")
    assert "lru_hash" in diagnostic.explanation


def test_map_in_map_type_refused():
    text = mutate('map_type = "array"', 'map_type = "array_of_maps"\n')
    diagnostic = expect_code(text, "MBPF205")
    assert "array_of_maps" in diagnostic.explanation


def test_prog_array_map_type_refused():
    text = mutate('map_type = "array"', 'map_type = "prog_array"\n')
    diagnostic = expect_code(text, "MBPF205")
    assert "prog_array" in diagnostic.explanation


def _ringbuf_text(size, key_type="none", value_type="none"):
    text = mutate('map_type = "array"', 'map_type = "ringbuf"\n')
    text = mutate_in(text, 'key_type = "u32"', 'key_type = "%s"\n' % key_type)
    text = mutate_in(
        text, 'value_type = "u64"', 'value_type = "%s"\n' % value_type
    )
    return mutate_in(text, "max_entries = 1", "max_entries = %d\n" % size)


def test_ringbuf_qualified_sizes_parse():
    for size in (4096, 131072):
        manifest_path, _tmpdir = write_project(_ringbuf_text(size))
        manifest = parse_manifest(manifest_path)
        assert len(manifest.maps) == 1
        entry = manifest.maps[0]
        assert entry.map_type == "ringbuf"
        assert entry.key_type == "none"
        assert entry.value_type == "none"
        assert entry.max_entries == size


def test_ringbuf_unqualified_size_refused():
    diagnostic = expect_code(_ringbuf_text(8192), "MBPF205")
    assert "8192" in diagnostic.explanation


def test_ringbuf_key_vocabulary_refused():
    diagnostic = expect_code(_ringbuf_text(4096, key_type="u32"), "MBPF205")
    assert "key/value vocabulary" in diagnostic.explanation


def test_ringbuf_value_vocabulary_refused():
    diagnostic = expect_code(
        _ringbuf_text(131072, value_type="u64"), "MBPF205"
    )
    assert "key/value vocabulary" in diagnostic.explanation


def test_conflicting_section_and_program_type_fails():
    text = mutate('section = "xdp"', 'section = "kprobe"\n')
    diagnostic = expect_code(text, "MBPF206")
    assert "kprobe" in diagnostic.explanation


def test_unknown_program_type_fails():
    text = mutate('program_type = "xdp"', 'program_type = "tracepoint"\n')
    text = mutate_in(text, 'section = "xdp"', 'section = "tracepoint"\n')
    expect_code(text, "MBPF206")


def test_tracepoint_pair_parses():
    text = mutate('program_type = "xdp"', 'program_type = "tracepoint"\n')
    text = mutate_in(
        text,
        'section = "xdp"',
        'section = "tracepoint/syscalls/sys_enter_getpid"\n',
    )
    manifest_path, _tmpdir = write_project(text)
    manifest = parse_manifest(manifest_path)
    assert manifest.programs[0].program_type == "tracepoint"
    assert (
        manifest.programs[0].section
        == "tracepoint/syscalls/sys_enter_getpid"
    )


def test_tracepoint_wrong_event_fails():
    text = mutate('program_type = "xdp"', 'program_type = "tracepoint"\n')
    text = mutate_in(
        text,
        'section = "xdp"',
        'section = "tracepoint/syscalls/sys_enter_gettid"\n',
    )
    diagnostic = expect_code(text, "MBPF206")
    assert "sys_enter_gettid" in diagnostic.explanation


def test_tracepoint_short_section_fails():
    text = mutate('program_type = "xdp"', 'program_type = "tracepoint"\n')
    text = mutate_in(
        text, 'section = "xdp"', 'section = "syscalls:sys_enter_getpid"\n'
    )
    diagnostic = expect_code(text, "MBPF206")
    assert "syscalls:sys_enter_getpid" in diagnostic.explanation


def test_xdp_type_with_tracepoint_section_fails():
    text = mutate_in(
        VALID_MANIFEST,
        'section = "xdp"',
        'section = "tracepoint/syscalls/sys_enter_getpid"\n',
    )
    diagnostic = expect_code(text, "MBPF206")
    assert "tracepoint/syscalls/sys_enter_getpid" in (
        diagnostic.explanation
    )


def test_parent_escape_source_fails():
    text = mutate('source = "src/xdp.mojo"', 'source = "../evil.mojo"\n')
    expect_code(text, "MBPF207")


def test_absolute_source_fails():
    text = mutate(
        'source = "src/xdp.mojo"', 'source = "/tmp/evil.mojo"\n'
    )
    expect_code(text, "MBPF207")


def test_missing_source_fails():
    manifest_path, _tmpdir = write_project(VALID_MANIFEST, sources=())
    try:
        parse_manifest(manifest_path)
    except ManifestError as exc:
        assert exc.diagnostic.code == "MBPF208"
    else:
        raise AssertionError("expected MBPF208 for missing source")


def test_unsupported_profile_fails():
    text = mutate(
        'profile = "linux-bpfel-v3"', 'profile = "linux-bpfeb-v9"\n'
    )
    manifest_path, _tmpdir = write_project(text)
    try:
        parse_manifest(manifest_path)
    except ProfileError as exc:
        assert exc.diagnostic.code == "MBPF101"
        assert exc.diagnostic.stage == "profile.resolve"
    else:
        raise AssertionError("expected MBPF101 for unknown profile")


def test_core_request_outside_profile_fails():
    text = mutate("core = false", "core = true\n")
    expect_code(text, "MBPF211")


def test_malformed_toml_fails():
    expect_code("schema_version = [unclosed\n", "MBPF209")


def test_missing_required_table_fails():
    text = "\n".join(
        line
        for line in VALID_MANIFEST.splitlines(keepends=True)
        if not line.startswith("[artifact]")
        and 'name = "packet_counter"' not in line
        and "source_license" not in line
        and "kernel_license" not in line
    )
    expect_code(text, "MBPF209")


def test_wrong_value_type_fails():
    text = mutate("max_entries = 1", 'max_entries = "one"\n')
    expect_code(text, "MBPF209")


def test_invalid_entry_name_fails():
    text = mutate('entry = "xdp_entry"', 'entry = "9bad-name!"\n')
    expect_code(text, "MBPF210")


def test_invalid_map_name_fails():
    text = mutate('name = "mojobpf_map0"', 'name = "has space"\n')
    expect_code(text, "MBPF210")


def test_missing_manifest_file_fails():
    try:
        parse_manifest("/nonexistent-dir-xyz/mojobpf.toml")
    except ManifestError as exc:
        assert exc.diagnostic.code == "MBPF209"
    else:
        raise AssertionError("expected MBPF209 for missing manifest")


def test_schema_file_is_well_formed_contract():
    with open(SCHEMA_PATH, encoding="utf-8") as handle:
        schema = json.load(handle)
    assert schema["title"] == "MojoBPF project manifest"
    for key in ("schema_version", "project", "target", "artifact",
                "programs"):
        assert key in schema["required"]
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == 1
    programs = schema["properties"]["programs"]
    assert programs["minItems"] == 1
    max_entries = schema["properties"]["maps"]["items"]["properties"][
        "max_entries"
    ]
    assert max_entries["minimum"] == 1
    assert max_entries["maximum"] == 4294967295


ROUTE_MANIFEST = """\
schema_version = 1

[project]
name = "route-proj"

[target]
profile = "linux-bpfel-v3"
core = false

[artifact]
name = "route_obj"
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

RINGBUF_COMPANION = """\
[[maps]]
name = "mojobpf_map1"
map_type = "ringbuf"
key_type = "none"
value_type = "none"
max_entries = 4096
"""


def test_parse_rejects_unsupported_map_name():
    text = mutate_in(
        ROUTE_MANIFEST,
        'name = "mojobpf_map0"',
        'name = "packet_counts"\n',
    )
    expect_code(text, "MBPF214")


def test_parse_rejects_extra_non_pair_map():
    text = ROUTE_MANIFEST + (
        "[[maps]]\n"
        'name = "mojobpf_map1"\n'
        'map_type = "array"\n'
        'key_type = "u32"\n'
        'value_type = "u64"\n'
        "max_entries = 1\n"
    )
    expect_code(text, "MBPF215")


def test_parse_rejects_three_maps():
    # The count gate precedes the name gate, so any third map
    # trips MBPF215 even with a name the route never emits.
    text = ROUTE_MANIFEST + RINGBUF_COMPANION + (
        "[[maps]]\n"
        'name = "mojobpf_map2"\n'
        'map_type = "array"\n'
        'key_type = "u32"\n'
        'value_type = "u64"\n'
        "max_entries = 1\n"
    )
    expect_code(text, "MBPF215")


def test_parse_accepts_event_pair():
    manifest_path, _tmpdir = write_project(
        ROUTE_MANIFEST + RINGBUF_COMPANION
    )
    manifest = parse_manifest(manifest_path)
    assert [entry.name for entry in manifest.maps] == [
        "mojobpf_map0",
        "mojobpf_map1",
    ]


def test_parse_rejects_empty_license():
    text = mutate_in(
        ROUTE_MANIFEST,
        'source_license = "Apache-2.0 WITH LLVM-exception"',
        'source_license = ""\n',
    )
    expect_code(text, "MBPF209")


def test_parse_rejects_control_char_license():
    text = mutate_in(
        ROUTE_MANIFEST,
        'kernel_license = "Apache-2.0 WITH LLVM-exception"',
        'kernel_license = "Apache-2.0\\u0007 WITH LLVM-exception"\n',
    )
    expect_code(text, "MBPF209")


def _direct_run():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    names = sorted(
        name
        for name in globals()
        if name.startswith("test_") and callable(globals()[name])
    )
    for name in names:
        try:
            globals()[name]()
        except Exception:
            failures += 1
            print("FAIL %s" % name)
            import traceback

            traceback.print_exc()
        else:
            print("ok %s" % name)
    print("%d tests, %d failures" % (len(names), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_direct_run())
