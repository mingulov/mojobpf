# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Pipeline tests: the reusable build interface reproduces the pins.

Builds the two canonical programs (the packet classifier and the map
round trip) through ``build_project`` and through the ``mojobpf build``
CLI, and asserts every intermediate hash matches the pinned genuine
pipeline outputs: raw frontend IR, adapted IR (via the versioned
adapter service), and the final object. An SDK-importing classifier
with no maps declared builds end to end as well, proving the
scan-gated ``-I``. The combined packet workload builds end to end
with a two-entry manifest; its byte-sum mutant is refused by the
spill gate, and entry-count mismatches in either direction fail map
reconciliation. A final test feeds invalid source through the
same interface and asserts the frontend failure is reported with
its stage and exit, leaving no object behind.

Requires the working Mojo compiler and LLVM ``llc`` on PATH (for
example the project pixi environment plus system LLVM). A missing tool
is reported as an environment failure; a hash mismatch or a build
failure is a proof failure. Neither ever passes.

Runnable directly (``python3 tests/compile/test_build_pipeline.py``)
or under any ``test_``-style runner. Standard library only.
"""

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)
sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..",
        "compiler",
    ),
)

import audit  # noqa: E402
from mojobpf.build import (  # noqa: E402
    BuildRequest,
    LOWERED_CALLEE_MARKERS,
    QUALIFIED_COMBINED_ADD_IMMS,
    QUALIFIED_CORE_ADD_IMMS,
    QUALIFIED_EVENT_ADD_IMMS,
    QUALIFIED_MAP_ADD_IMMS,
    QUALIFIED_RESERVE_ADD_IMMS,
    QUALIFIED_SHAPE_IMMS,
    QUALIFIED_TRACEPOINT_ADD_IMMS,
    QUALIFIED_UPROBE_ADD_IMMS,
    _verify_gate_outcome,
    build_project,
)
from mojobpf.inspect import object_map_value_sizes  # noqa: E402
from mojobpf.manifest import parse_manifest  # noqa: E402

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
CLASSIFIER_SOURCE = os.path.join(
    REPO_ROOT, "examples", "xdp_pass", "xdp_pass.mojo"
)
MAP_SOURCE = os.path.join(REPO_ROOT, "tests", "compile",
                          "map_roundtrip.mojo")
SDK_CLASSIFIER_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "subset", "subset_loop_sum.mojo"
)
MUTATED_SOURCE = os.path.join(REPO_ROOT, "tests", "compile",
                             "map_roundtrip_mutated.mojo")
COMBINED_SOURCE = os.path.join(
    REPO_ROOT, "examples", "packet_counter", "packet_counter.mojo"
)
COMBINED_MUTATED_SOURCE = os.path.join(
    REPO_ROOT, "examples", "packet_counter",
    "packet_counter_bytesum_mutated.mojo",
)
BAD_SOURCE = os.path.join(REPO_ROOT, "tests", "compile", "probe_bad.mojo")
SUBPROG_SOURCE = os.path.join(
    REPO_ROOT, "examples", "subprog_call", "decision.mojo"
)
SUBPROG_ENTRY_FIRST_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "subprog_entry_first.mojo"
)
SUBPROG_RECURSION_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "subprog_recursion_attempt.mojo"
)
UPROBE_SOURCE = os.path.join(
    REPO_ROOT, "examples", "uprobe_counter", "counter.mojo"
)
UPROBE_MUTANT_SOURCE = os.path.join(
    REPO_ROOT,
    "examples",
    "uprobe_counter",
    "counter_inverted_mutated.mojo",
)
UPROBE_REG_ATTEMPT = os.path.join(
    REPO_ROOT, "tests", "compile", "uprobe_reg_attempt.mojo"
)
UPROBE_MANIFEST = os.path.join(
    REPO_ROOT, "examples", "uprobe_counter", "mojobpf.toml"
)
SERVICE = os.path.join(REPO_ROOT, "compiler", "adapter_service.py")
SRC_DIR = os.path.join(REPO_ROOT, "src")
LOCKFILE = os.path.join(REPO_ROOT, "toolchains.lock.json")

# Pinned SHA-256 of the genuine pipeline outputs (see
# tests/probes/run_feasibility.py): the reusable interface must
# reproduce them byte-identically.
EXPECTED_PINS = {
    "classifier": {
        "raw_ir":
            "aea81a0f56b2ecbaecd3b84c04cc3c3c373c7759ccacdcb30380ab2d2b32a39a",
        "adapted_ir":
            "42cc47109656b8649ce89fe84fb9586df1e5830e3b56e7db255b5c8eabdf2413",
        "object":
            "17570ee79a16b64ccc4f723d00d26ae316a286cffdd3382ba3a6e6b4be95097c",
    },
    "map": {
        "raw_ir":
            "699d4a9797fc4f318064adb7f93e33df5c11e52c316d20c59c005b436241ab49",
        "adapted_ir":
            "b111c0d3b4fba1c32391fd3d01747ccac1381d8ffe77a5c57ece46913f50045a",
        "object":
            "18f7490634c6462360aafcb1ece85406b2374b4b74a2ca4501f90b5781e8a540",
    },
    "tracepoint": {
        "raw_ir":
            "0a7cbc6a1bae8aaf2c14792e1659700b3102040d1ed81c6f941c1adeeddfe9c7",
        "adapted_ir":
            "689cd2079b109b9448f9e9ea543c6c077abe32b3f1185c2e69999573dadad4fe",
        "object":
            "b687af78c3056e2299929cd635044875f8369f9ca6e27f626c4f55c4def8b67a",
    },
    "uprobe": {
        "raw_ir":
            "e95d4c1279e63227db1ce4eca7e10735d5a5b8b3fb2eb4f1cf9445617fc21ba2",
        "adapted_ir":
            "8da47023932a28d3824c857723044646e3baea02d5ab0907e5c3979384a3185e",
        "object":
            "efdc0af7f50f27d45494135bbb2715200701c337f3686f2381c11b71c0e6b7aa",
    },
    "reserve": {
        "object":
            "d454155a728b1e23b71df0f15346fe17b668d1a164ced9b877472181cecc6731",
    },
}

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
{maps}
"""

HASH_MANIFEST_TEMPLATE = """\
schema_version = 1

[project]
name = "{project}"

[target]
profile = "linux-bpfel-v3-hash"
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
{maps}
"""

SUBPROG_MANIFEST_TEMPLATE = """\
schema_version = 1

[project]
name = "{project}"

[target]
profile = "linux-bpfel-v3-subprog"
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
{maps}
"""

MAPS_BLOCK = """\
[[maps]]
name = "mojobpf_map0"
map_type = "array"
key_type = "u32"
value_type = "u64"
max_entries = 1
"""

MAPS_BLOCK_TWO = """\
[[maps]]
name = "mojobpf_map0"
map_type = "array"
key_type = "u32"
value_type = "u64"
max_entries = 2
"""

MAPS_BLOCK_TEMPLATE = """\
[[maps]]
name = "mojobpf_map0"
map_type = "{map_type}"
key_type = "u32"
value_type = "u64"
max_entries = {max_entries}
"""

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
{maps}
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
{maps}
"""

CORE_MANIFEST_TEMPLATE = """\
schema_version = 1

[project]
name = "{project}"

[target]
profile = "linux-bpfel-v3-core"
core = true

[artifact]
name = "{artifact}"
source_license = "Apache-2.0 WITH LLVM-exception"
kernel_license = "Apache-2.0 WITH LLVM-exception"

[[programs]]
source = "{source}"
entry = "xdp_entry"
program_type = "xdp"
section = "xdp"
{maps}
"""

CORE_MAPS_BLOCK = """\
[[maps]]
name = "mojobpf_map0"
map_type = "array"
key_type = "u32"
value_type = "bytes4096"
max_entries = 1
"""

RMW_SOURCES = {
    2: os.path.join(REPO_ROOT, "tests", "compile", "maps_rmw2.mojo"),
    3: os.path.join(REPO_ROOT, "tests", "compile", "maps_rmw3.mojo"),
    4: os.path.join(REPO_ROOT, "tests", "compile", "maps_rmw4.mojo"),
}
DELETE_SOURCES = {
    count: os.path.join(
        REPO_ROOT, "tests", "compile", "maps_delete%d.mojo" % count
    )
    for count in (1, 2, 3, 4)
}
PERCPU_RMW_SOURCES = {
    count: os.path.join(
        REPO_ROOT, "tests", "compile", "percpu_rmw%d.mojo" % count
    )
    for count in (1, 2, 3, 4)
}
PERCPU_DELETE_SOURCES = {
    count: os.path.join(
        REPO_ROOT, "tests", "compile", "percpu_delete%d.mojo" % count
    )
    for count in (1, 2, 3, 4)
}
PERCPU_COMBINED_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "percpu_combined.mojo"
)
HASH_RMW_SOURCES = {
    count: os.path.join(
        REPO_ROOT, "tests", "compile", "hash_rmw%d.mojo" % count
    )
    for count in (1, 2, 3, 4)
}
HASH_DELETE_SOURCES = {
    count: os.path.join(
        REPO_ROOT, "tests", "compile", "hash_delete%d.mojo" % count
    )
    for count in (1, 2, 3, 4)
}
HASH_MIXED_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "maps_hash_mixed.mojo"
)
GETNEXT_ATTEMPT_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "maps_getnext_attempt.mojo"
)
OOB_KEY_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "maps_oob_key.mojo"
)
MIXED_KIND_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "maps_mixed_kind.mojo"
)
RMW5_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "maps_rmw5_attempt.mojo"
)
TRACEPOINT_SOURCE = os.path.join(
    REPO_ROOT, "examples", "tracepoint_counter", "counter.mojo"
)
TRACEPOINT_MANIFEST = os.path.join(
    REPO_ROOT, "examples", "tracepoint_counter", "mojobpf.toml"
)
RESERVE_MANIFEST = os.path.join(
    REPO_ROOT, "examples", "ringbuf_reserve", "mojobpf.toml"
)
TRACEPOINT_COUNT_TWO_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "tracepoint_count_two_attempt.mojo"
)
TRACEPOINT_CTX_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "tracepoint_ctx_attempt.mojo"
)
CORE_SOURCE = os.path.join(
    REPO_ROOT, "tests", "core", "core_read.mojo"
)


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def check_tools():
    for tool in ("mojo", "llc"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (
        CLASSIFIER_SOURCE, MAP_SOURCE, SDK_CLASSIFIER_SOURCE,
        COMBINED_SOURCE, COMBINED_MUTATED_SOURCE, BAD_SOURCE,
        TRACEPOINT_SOURCE, TRACEPOINT_MANIFEST,
        TRACEPOINT_COUNT_TWO_SOURCE, TRACEPOINT_CTX_SOURCE,
        CORE_SOURCE, SUBPROG_SOURCE, SUBPROG_ENTRY_FIRST_SOURCE,
        SUBPROG_RECURSION_SOURCE, SERVICE, LOCKFILE,
    ):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_project(source, entry, artifact, with_maps, dirname="proj",
                  max_entries=1, map_type="array", template=None):
    """Copy a canonical source into a fresh project; return paths."""
    parent = tempfile.mkdtemp(prefix="build-pipeline-")
    root = os.path.join(parent, dirname)
    os.makedirs(root)
    filename = os.path.basename(source)
    staged = os.path.join(root, filename)
    shutil.copyfile(source, staged)
    if with_maps:
        if max_entries == 2 and map_type == "array":
            maps = MAPS_BLOCK_TWO
        elif max_entries == 1 and map_type == "array":
            maps = MAPS_BLOCK
        else:
            maps = MAPS_BLOCK_TEMPLATE.format(
                map_type=map_type, max_entries=max_entries
            )
    else:
        maps = ""
    manifest_path = os.path.join(root, "mojobpf.toml")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(
            (template or MANIFEST_TEMPLATE).format(
                project="%s-proj" % entry,
                artifact=artifact,
                source=filename,
                entry=entry,
                maps=maps,
            )
        )
    return manifest_path, os.path.join(root, "out")


def build(manifest_path, out_dir, save_temps=False):
    return build_project(
        BuildRequest(
            manifest_path=manifest_path,
            out_dir=out_dir,
            adapter_path=SERVICE,
            save_temps=save_temps,
            lockfile_path=LOCKFILE,
        )
    )


def write_tracepoint_project(source, artifact, max_entries=2,
                             entry="trace_entry"):
    """Stage a tracepoint source with its manifest; return paths."""
    parent = tempfile.mkdtemp(prefix="build-tracepoint-")
    root = os.path.join(parent, "proj")
    os.makedirs(root)
    filename = os.path.basename(source)
    staged = os.path.join(root, filename)
    shutil.copyfile(source, staged)
    if max_entries == 2:
        maps = MAPS_BLOCK_TWO
    else:
        maps = MAPS_BLOCK_TEMPLATE.format(
            map_type="array", max_entries=max_entries
        )
    manifest_text = TRACEPOINT_MANIFEST_TEMPLATE.format(
        project="tracepoint-proj",
        artifact=artifact,
        source=filename,
        maps=maps,
    )
    if entry != "trace_entry":
        manifest_text = manifest_text.replace(
            'entry = "trace_entry"', 'entry = "%s"' % entry
        )
    manifest_path = os.path.join(root, "mojobpf.toml")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(manifest_text)
    return manifest_path, os.path.join(root, "out")


def write_uprobe_project(source, artifact, max_entries=2,
                         pair=("uprobe", "uprobe")):
    """Stage a uprobe source with its manifest; return paths."""
    parent = tempfile.mkdtemp(prefix="build-uprobe-")
    root = os.path.join(parent, "proj")
    os.makedirs(root)
    filename = os.path.basename(source)
    staged = os.path.join(root, filename)
    shutil.copyfile(source, staged)
    if max_entries == 2:
        maps = MAPS_BLOCK_TWO
    else:
        maps = MAPS_BLOCK_TEMPLATE.format(
            map_type="array", max_entries=max_entries
        )
    manifest_text = UPROBE_MANIFEST_TEMPLATE.format(
        project="uprobe-proj",
        artifact=artifact,
        source=filename,
        maps=maps,
    )
    if pair != ("uprobe", "uprobe"):
        manifest_text = manifest_text.replace(
            'program_type = "uprobe"',
            'program_type = "%s"' % pair[0],
        ).replace(
            'section = "uprobe"', 'section = "%s"' % pair[1]
        )
    manifest_path = os.path.join(root, "mojobpf.toml")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(manifest_text)
    return manifest_path, os.path.join(root, "out")


def assert_failure(result, out_dir):
    assert result.success is False, "failing build reported success"
    assert result.artifacts == (), "failing build reported artifacts"
    assert result.diagnostics, "failing build carried no diagnostics"
    assert not os.path.exists(out_dir) or (
        [name for name in os.listdir(out_dir) if name.endswith(".bpf.o")]
        == []
    ), "failing build left an object behind"


def write_core_project(artifact):
    """Stage the relocation probe with its manifest; return paths."""
    parent = tempfile.mkdtemp(prefix="build-core-")
    root = os.path.join(parent, "proj")
    os.makedirs(root)
    filename = os.path.basename(CORE_SOURCE)
    shutil.copyfile(CORE_SOURCE, os.path.join(root, filename))
    manifest_path = os.path.join(root, "mojobpf.toml")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(
            CORE_MANIFEST_TEMPLATE.format(
                project="core-probe",
                artifact=artifact,
                source=filename,
                maps=CORE_MAPS_BLOCK,
            )
        )
    return manifest_path, os.path.join(root, "out")


def _section_file_range(data, want):
    shoff = struct.unpack_from("<Q", data, 40)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
    headers = []
    for index in range(shnum):
        base = shoff + index * shentsize
        headers.append(struct.unpack_from("<IIQQQQIIQQ", data, base))
    strtab = headers[shstrndx]
    for fields in headers:
        end = data.index(b"\0", strtab[4] + fields[0])
        name = data[strtab[4] + fields[0] : end].decode("ascii")
        if name == want:
            return fields[4], fields[5]
    raise AssertionError("object has no %s section" % want)


def _value_size_bound_offset(data):
    """Return the file offset of the value_size ARRAY bound.

    Walks DATASEC ``.maps`` -> VAR -> STRUCT member
    ``value_size`` -> pointer target ARRAY, asserting every hop,
    so BTF drift fails loudly instead of patching dead bytes.
    """
    boff, blen = _section_file_range(data, ".BTF")
    blob = data[boff : boff + blen]
    (magic, version, _flags, hdr_len) = struct.unpack_from(
        "<HBBI", blob, 0
    )
    assert (magic, version, hdr_len) == (0xEB9F, 1, 24)
    (type_off, type_len, str_off, _str_len) = struct.unpack_from(
        "<IIII", blob, 8
    )
    assert (type_off, str_off) == (0, type_len)
    strings = blob[24 + type_len :]

    def _string(off):
        assert 0 <= off < len(strings), off
        end = strings.index(b"\0", off)
        return strings[off:end].decode("ascii")

    records = []
    pos, end = 24, 24 + type_len
    while pos < end:
        start = pos
        (name_off, info, size_or_type) = struct.unpack_from(
            "<III", blob, pos
        )
        kind = (info >> 24) & 0xF
        vlen = info & 0xFFFF
        pos += 12
        name = _string(name_off)
        if kind == 1:
            pos += 4
            payload = None
        elif kind in (2, 12):
            payload = size_or_type
        elif kind == 13:
            pos += 8 * vlen
            payload = size_or_type
        elif kind == 3:
            (_elem, _index, nelems) = struct.unpack_from(
                "<III", blob, pos
            )
            pos += 12
            payload = nelems
        elif kind in (4, 5):
            members = []
            for _ in range(vlen):
                (m_name, m_type, m_off) = struct.unpack_from(
                    "<III", blob, pos
                )
                pos += 12
                members.append((_string(m_name), m_type, m_off))
            payload = members
        elif kind == 14:
            pos += 4
            payload = size_or_type
        elif kind == 15:
            entries = []
            for _ in range(vlen):
                entries.append(struct.unpack_from("<III", blob, pos))
                pos += 12
            payload = entries
        else:
            raise AssertionError("unexpected BTF kind %d" % kind)
        records.append((name, kind, payload, boff + start))
    assert pos == end, (pos, end)

    def _record(type_id):
        assert 1 <= type_id <= len(records), type_id
        return records[type_id - 1]

    for name, kind, payload, _ in records:
        if kind != 15 or name != ".maps":
            continue
        (var_id, _off, _size) = payload[0]
        (_vname, vkind, target, _voff) = _record(var_id)
        assert vkind == 14, vkind
        (_sname, skind, members, _soff) = _record(target)
        assert skind == 4, skind
        for m_name, m_type, _ in members:
            if m_name != "value_size":
                continue
            (_pname, pkind, ptarget, _poff) = _record(m_type)
            assert pkind == 2, pkind
            (_aname, akind, nelems, aoff) = _record(ptarget)
            assert akind == 3, akind
            return aoff + 12 + 8, nelems
    raise AssertionError("value_size bound not found")


def _mutate_value_size(staged_obj, workdir, tag, new_size):
    """Copy a built object with a patched BTF value size."""
    with open(staged_obj, "rb") as handle:
        image = bytearray(handle.read())
    at, old = _value_size_bound_offset(bytes(image))
    assert old != new_size, (old, new_size)
    struct.pack_into("<I", image, at, new_size)
    mutated = os.path.join(workdir, "%s.bpf.o" % tag)
    with open(mutated, "wb") as handle:
        handle.write(bytes(image))
    sizes = object_map_value_sizes(mutated)
    assert sizes.get("mojobpf_map0") == new_size, sizes
    return mutated


def test_classifier_matches_pins():
    check_tools()
    manifest_path, out_dir = write_project(
        CLASSIFIER_SOURCE, "xdp_entry", "classifier_obj", False
    )
    result = build(manifest_path, out_dir, save_temps=True)
    try:
        assert result.success is True, result.diagnostics
        assert [item.role for item in result.artifacts] == [
            "object", "evidence",
        ]
        pins = EXPECTED_PINS["classifier"]
        observed = result.artifacts[0].sha256
        assert observed == pins["object"], (
            "object mismatch: observed %s expected %s"
            % (observed, pins["object"])
        )
        workdir = result.work_dir
        assert workdir is not None
        for key, relpath in (
            ("raw_ir", "xdp_entry.raw.ll"),
            ("adapted_ir", os.path.join("xdp_entry.adapter",
                                        "adapted.ll")),
        ):
            observed = sha256_file(os.path.join(workdir, relpath))
            assert observed == pins[key], (
                "%s mismatch: observed %s expected %s"
                % (key, observed, pins[key])
            )
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_map_roundtrip_matches_pins():
    check_tools()
    manifest_path, out_dir = write_project(
        MAP_SOURCE, "xdp_entry", "roundtrip_obj", True
    )
    result = build(manifest_path, out_dir, save_temps=True)
    try:
        assert result.success is True, result.diagnostics
        assert [item.role for item in result.artifacts] == [
            "object", "evidence",
        ]
        pins = EXPECTED_PINS["map"]
        observed = result.artifacts[0].sha256
        assert observed == pins["object"], (
            "object mismatch: observed %s expected %s"
            % (observed, pins["object"])
        )
        workdir = result.work_dir
        assert workdir is not None
        for key, relpath in (
            ("raw_ir", "xdp_entry.raw.ll"),
            ("adapted_ir", os.path.join("xdp_entry.adapter",
                                        "adapted.ll")),
        ):
            observed = sha256_file(os.path.join(workdir, relpath))
            assert observed == pins[key], (
                "%s mismatch: observed %s expected %s"
                % (key, observed, pins[key])
            )
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_cli_build_matches_pin():
    check_tools()
    manifest_path, out_dir = write_project(
        CLASSIFIER_SOURCE, "xdp_entry", "cli_obj", False
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC_DIR + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [
            sys.executable, "-m", "mojobpf.cli", "build",
            "--manifest", manifest_path,
            "--out-dir", out_dir,
            "--adapter", SERVICE,
            "--lockfile", LOCKFILE,
        ],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=900,
    )
    assert proc.returncode == 0, (
        "cli build exited %d:\n%s\n%s"
        % (proc.returncode, proc.stdout, proc.stderr)
    )
    assert "built " in proc.stdout
    object_path = os.path.join(out_dir, "cli_obj.bpf.o")
    assert os.path.isfile(object_path)
    observed = sha256_file(object_path)
    expected = EXPECTED_PINS["classifier"]["object"]
    assert observed == expected, (
        "cli object mismatch: observed %s expected %s"
        % (observed, expected)
    )


def test_spaces_path_matches_pin():
    check_tools()
    manifest_path, out_dir = write_project(
        CLASSIFIER_SOURCE, "xdp_entry", "spaced_obj", False,
        dirname="pr ojéct dir",
    )
    result = build(manifest_path, out_dir)
    assert result.success is True, result.diagnostics
    observed = result.artifacts[0].sha256
    expected = EXPECTED_PINS["classifier"]["object"]
    assert observed == expected, (
        "spaced-path object mismatch: observed %s expected %s"
        % (observed, expected)
    )


def test_map_object_beyond_qualified_shape_rejected():
    # The plus-two mutation is audit-clean map IR whose object
    # carries [-16, -4, -4, 2]: the spill gate must refuse to
    # publish it with MBPF107 after a successful backend step.
    check_tools()
    if not os.path.isfile(MUTATED_SOURCE):
        raise EnvironmentFailure("missing repo file: %s" % MUTATED_SOURCE)
    manifest_path, out_dir = write_project(
        MUTATED_SOURCE, "xdp_entry", "mutated_obj", True
    )
    result = build(manifest_path, out_dir, save_temps=True)
    try:
        assert_failure(result, out_dir)
        diagnostic = result.diagnostics[0]
        assert diagnostic.code == "MBPF107", diagnostic
        assert diagnostic.stage == "build.backend", diagnostic
        assert "[-16, -4, -4, 2]" in diagnostic.explanation, diagnostic
        assert "[-16, -4, -4, 1]" in diagnostic.explanation, diagnostic
        backend = [
            record for record in result.commands
            if record.stage == "build.backend"
        ]
        assert len(backend) == 2
        assert all(record.status == "ok" for record in backend), backend
        assert result.work_dir is not None
        with open(
            os.path.join(result.work_dir, "xdp_entry.raw.ll"),
            "r", encoding="utf-8",
        ) as handle:
            assert audit.validate(handle.read()) == "map"
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_five_pair_program_refused_at_build_time():
    # Five read-modify-write pairs over dense keys 0..4 are
    # audit-clean (the N-pair rule is unbounded) and adapt to a
    # five-entry map, but no manifest can declare 5 entries and
    # the ("map", 5) shape has no qualified multiset: the spill
    # gate must refuse to publish it with MBPF107 after a
    # successful backend step, before the MIR conjunct runs.
    check_tools()
    if not os.path.isfile(RMW5_SOURCE):
        raise EnvironmentFailure("missing repo file: %s" % RMW5_SOURCE)
    manifest_path, out_dir = write_project(
        RMW5_SOURCE, "xdp_entry", "rmw5_obj", True, max_entries=4
    )
    result = build(manifest_path, out_dir, save_temps=True)
    try:
        assert_failure(result, out_dir)
        diagnostic = result.diagnostics[0]
        assert diagnostic.code == "MBPF107", diagnostic
        assert diagnostic.stage == "build.backend", diagnostic
        assert "map shape over 5 entries" in diagnostic.explanation, (
            diagnostic
        )
        assert "no qualified add-immediate" in diagnostic.explanation, (
            diagnostic
        )
        backend = [
            record for record in result.commands
            if record.stage == "build.backend"
        ]
        assert len(backend) == 1
        assert all(record.status == "ok" for record in backend), backend
        assert result.work_dir is not None
        with open(
            os.path.join(result.work_dir, "xdp_entry.raw.ll"),
            "r", encoding="utf-8",
        ) as handle:
            assert audit.validate(handle.read()) == "map"
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_spill_gate_contract_matches_audit():
    # The gate detects map families with the audit's own lowered
    # callee spellings and enforces the lowering suites' pinned
    # add-immediate multisets; either side drifting breaks this.
    assert tuple(LOWERED_CALLEE_MARKERS) == (
        audit.LOWERED_CALLEE["lookup"],
        audit.LOWERED_CALLEE["update"],
        audit.LOWERED_CALLEE["delete"],
        audit.LOWERED_CALLEE["pid"],
        audit.LOWERED_CALLEE["ktime"],
        audit.LOWERED_CALLEE["cpu"],
        audit.LOWERED_CALLEE["output"],
        audit.LOWERED_CALLEE["reserve"],
        audit.LOWERED_CALLEE["submit"],
        audit.LOWERED_CALLEE["discard"],
    )
    assert list(QUALIFIED_MAP_ADD_IMMS) == [-16, -4, -4, 1]
    assert list(QUALIFIED_COMBINED_ADD_IMMS) == [
        -16, -16, -4, -4, -4, -4, 1, 15,
    ]
    assert list(QUALIFIED_TRACEPOINT_ADD_IMMS) == [-16, -4, -4, -4, 1]
    assert list(QUALIFIED_EVENT_ADD_IMMS) == [
        -64, -64, -62, -60, -56, -52, -48, -40,
        -16, -16, -16,
        -4, -4, -4, -4, -4, -4, -4,
        1, 1, 1,
    ]
    assert list(QUALIFIED_RESERVE_ADD_IMMS) == [
        -16, -16, -16,
        -4, -4, -4, -4, -4, -4, -4,
        1, 1, 1,
    ]
    assert list(QUALIFIED_CORE_ADD_IMMS) == [-4]
    assert list(QUALIFIED_UPROBE_ADD_IMMS) == [-16, -4, -4, -4, 1]
    assert QUALIFIED_SHAPE_IMMS[("map", 1)] == QUALIFIED_MAP_ADD_IMMS
    assert (
        QUALIFIED_SHAPE_IMMS[("combined", 2)]
        == QUALIFIED_COMBINED_ADD_IMMS
    )
    assert (
        QUALIFIED_SHAPE_IMMS[("tracepoint", 2)]
        == QUALIFIED_TRACEPOINT_ADD_IMMS
    )
    assert (
        QUALIFIED_SHAPE_IMMS[("event", 4)]
        == QUALIFIED_EVENT_ADD_IMMS
    )
    assert (
        QUALIFIED_SHAPE_IMMS[("core", 1)]
        == QUALIFIED_CORE_ADD_IMMS
    )
    assert (
        QUALIFIED_SHAPE_IMMS[("reserve", 4)]
        == QUALIFIED_RESERVE_ADD_IMMS
    )
    assert (
        QUALIFIED_SHAPE_IMMS[("uprobe", 2)]
        == QUALIFIED_UPROBE_ADD_IMMS
    )
    assert sorted(QUALIFIED_SHAPE_IMMS) == [
        ("combined", 2),
        ("core", 1),
        ("delete", 1),
        ("delete", 2),
        ("delete", 3),
        ("delete", 4),
        ("event", 4),
        ("map", 1),
        ("map", 2),
        ("map", 3),
        ("map", 4),
        ("reserve", 4),
        ("tracepoint", 2),
        ("uprobe", 2),
    ]


def test_combined_builds_through_driver():
    # The combined packet workload builds end to end through
    # build_project with a two-entry manifest: audit, adapter,
    # spill gate, inspection, and entry-count reconciliation all
    # pass and the object is published.
    check_tools()
    manifest_path, out_dir = write_project(
        COMBINED_SOURCE, "xdp_entry", "combined_obj", True,
        max_entries=2,
    )
    result = build(manifest_path, out_dir, save_temps=True)
    try:
        assert result.success is True, result.diagnostics
        assert [item.role for item in result.artifacts] == [
            "object", "evidence",
        ]
        assert result.work_dir is not None
        with open(
            os.path.join(result.work_dir, "xdp_entry.raw.ll"),
            "r", encoding="utf-8",
        ) as handle:
            assert audit.validate(handle.read()) == "combined"
        object_path = os.path.join(out_dir, "combined_obj.bpf.o")
        assert os.path.isfile(object_path)
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_combined_object_beyond_qualified_shape_rejected():
    # The byte-sum mutation is audit-clean combined IR whose object
    # carries [-16, -16, -4, -4, -4, -4, 1, 1, 15]: the spill gate
    # must refuse to publish it with MBPF107 after a successful
    # backend step.
    check_tools()
    manifest_path, out_dir = write_project(
        COMBINED_MUTATED_SOURCE, "xdp_entry", "combined_mut_obj",
        True, max_entries=2,
    )
    result = build(manifest_path, out_dir, save_temps=True)
    try:
        assert_failure(result, out_dir)
        diagnostic = result.diagnostics[0]
        assert diagnostic.code == "MBPF107", diagnostic
        assert diagnostic.stage == "build.backend", diagnostic
        assert "combined object" in diagnostic.explanation, diagnostic
        assert "[-16, -16, -4, -4, -4, -4, 1, 1, 15]" in (
            diagnostic.explanation
        ), diagnostic
        assert "[-16, -16, -4, -4, -4, -4, 1, 15]" in (
            diagnostic.explanation
        ), diagnostic
        backend = [
            record for record in result.commands
            if record.stage == "build.backend"
        ]
        assert len(backend) == 2
        assert all(record.status == "ok" for record in backend), backend
        assert result.work_dir is not None
        with open(
            os.path.join(result.work_dir, "xdp_entry.raw.ll"),
            "r", encoding="utf-8",
        ) as handle:
            assert audit.validate(handle.read()) == "combined"
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_combined_entries_mismatch_rejected():
    # A combined program paired with a one-entry manifest passes
    # the audit, adapter, backend, and spill gate, then fails map
    # reconciliation with MBPF216: the emitted two-entry map
    # disagrees with the declared count. Nothing is published.
    check_tools()
    manifest_path, out_dir = write_project(
        COMBINED_SOURCE, "xdp_entry", "combined_mismatch_obj", True,
        max_entries=1,
    )
    result = build(manifest_path, out_dir, save_temps=True)
    try:
        assert_failure(result, out_dir)
        diagnostic = result.diagnostics[0]
        assert diagnostic.code == "MBPF216", diagnostic
        assert diagnostic.stage == "build.backend", diagnostic
        assert "2-entry map" in diagnostic.explanation, diagnostic
        assert "max_entries = 1" in diagnostic.explanation, diagnostic
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_map_entries_mismatch_rejected():
    # The mirror case: a one-entry map program paired with a
    # two-entry manifest fails the same reconciliation with
    # MBPF216 instead of publishing a miscounted artifact.
    check_tools()
    manifest_path, out_dir = write_project(
        MAP_SOURCE, "xdp_entry", "map_mismatch_obj", True,
        max_entries=2,
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF216", diagnostic
    assert diagnostic.stage == "build.backend", diagnostic
    assert "1-entry map" in diagnostic.explanation, diagnostic
    assert "max_entries = 2" in diagnostic.explanation, diagnostic


def _check_shape_builds(source, entries, map_type, artifact):
    manifest_path, out_dir = write_project(
        source, "xdp_entry", artifact, True,
        max_entries=entries, map_type=map_type,
    )
    result = build(manifest_path, out_dir, save_temps=True)
    try:
        assert result.success is True, result.diagnostics
        assert [item.role for item in result.artifacts] == [
            "object", "evidence",
        ]
        object_path = os.path.join(out_dir, artifact + ".bpf.o")
        assert os.path.isfile(object_path)
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_rmw_shapes_build_through_driver():
    # Each multi-pair map-only shape builds end to end with its
    # matching array manifest: audit, adapter, spill gate,
    # inspection, and kind/count reconciliation all pass.
    check_tools()
    for entries, source in sorted(RMW_SOURCES.items()):
        _check_shape_builds(
            source, entries, "array", "rmw%d_obj" % entries
        )


def test_delete_shapes_build_through_driver():
    # Each delete probe builds end to end with its matching
    # array manifest.
    check_tools()
    for entries, source in sorted(DELETE_SOURCES.items()):
        _check_shape_builds(
            source, entries, "array", "delete%d_obj" % entries
        )


def test_percpu_shapes_build_through_driver():
    # A per-CPU pair shape, a delete probe, and the combined
    # workload each build end to end with matching per-CPU
    # manifests; the remaining per-CPU shapes are covered by the
    # structure and kernel suites.
    check_tools()
    _check_shape_builds(
        PERCPU_RMW_SOURCES[4], 4, "percpu_array", "pcpu_rmw4_obj"
    )
    _check_shape_builds(
        PERCPU_DELETE_SOURCES[1], 1, "percpu_array", "pcpu_del1_obj"
    )
    _check_shape_builds(
        PERCPU_COMBINED_SOURCE, 2, "percpu_array", "pcpu_comb_obj"
    )


def test_map_kind_mismatch_rejected():
    # A per-CPU pair program paired with an array manifest fails
    # kind reconciliation with MBPF216 instead of publishing an
    # artifact that disagrees with its manifest.
    check_tools()
    manifest_path, out_dir = write_project(
        PERCPU_RMW_SOURCES[4], "xdp_entry", "kind_mismatch_obj", True,
        max_entries=4, map_type="array",
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF216", diagnostic
    assert diagnostic.stage == "build.backend", diagnostic
    assert "percpu_array map" in diagnostic.explanation, diagnostic
    assert 'map_type = \'array\'' in diagnostic.explanation, diagnostic


def _check_hash_shape_builds(source, entries, artifact):
    manifest_path, out_dir = write_project(
        source, "xdp_entry", artifact, True,
        max_entries=entries, map_type="hash",
        template=HASH_MANIFEST_TEMPLATE,
    )
    result = build(manifest_path, out_dir, save_temps=True)
    try:
        assert result.success is True, result.diagnostics
        assert [item.role for item in result.artifacts] == [
            "object", "evidence",
        ]
        object_path = os.path.join(out_dir, artifact + ".bpf.o")
        assert os.path.isfile(object_path)
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_hash_shapes_build_through_driver():
    # Every hash pair shape and every hash delete probe builds end
    # to end with its matching hash manifest: audit, adapter,
    # spill gate, inspection, and kind/count reconciliation all
    # pass under the hash capability profile.
    check_tools()
    for entries, source in sorted(HASH_RMW_SOURCES.items()):
        _check_hash_shape_builds(
            source, entries, "hash_rmw%d_obj" % entries
        )
    for entries, source in sorted(HASH_DELETE_SOURCES.items()):
        _check_hash_shape_builds(
            source, entries, "hash_del%d_obj" % entries
        )


def test_hash_kind_mismatch_rejected():
    # A hash pair program paired with an array manifest fails kind
    # reconciliation with MBPF216 instead of publishing an
    # artifact that disagrees with its manifest.
    check_tools()
    manifest_path, out_dir = write_project(
        HASH_RMW_SOURCES[4], "xdp_entry", "hash_kind_mismatch_obj",
        True, max_entries=4, map_type="array",
        template=HASH_MANIFEST_TEMPLATE,
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF216", diagnostic
    assert diagnostic.stage == "build.backend", diagnostic
    assert "hash map" in diagnostic.explanation, diagnostic
    assert 'map_type = \'array\'' in diagnostic.explanation, diagnostic


def test_array_program_hash_manifest_rejected():
    # An array pair program paired with a hash manifest fails kind
    # reconciliation with MBPF216 in the other direction.
    check_tools()
    manifest_path, out_dir = write_project(
        RMW_SOURCES[4], "xdp_entry", "array_hash_mismatch_obj", True,
        max_entries=4, map_type="hash",
        template=HASH_MANIFEST_TEMPLATE,
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF216", diagnostic
    assert diagnostic.stage == "build.backend", diagnostic
    assert "array map" in diagnostic.explanation, diagnostic
    assert 'map_type = \'hash\'' in diagnostic.explanation, diagnostic


def test_multientry_count_mismatch_rejected():
    # A four-pair program paired with a two-entry manifest fails
    # count reconciliation with MBPF216.
    check_tools()
    manifest_path, out_dir = write_project(
        RMW_SOURCES[4], "xdp_entry", "count_mismatch_obj", True,
        max_entries=2,
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF216", diagnostic
    assert diagnostic.stage == "build.backend", diagnostic
    assert "4-entry map" in diagnostic.explanation, diagnostic
    assert "max_entries = 2" in diagnostic.explanation, diagnostic


def test_noncore_value_size_keeps_base_behavior():
    # Value-size reconciliation is core-family only: a non-core
    # object whose BTF value size disagrees with the manifest
    # passes the gate exactly as before the core slice (kind and
    # entry count only), while a core object with a disagreeing
    # value size still fails closed with MBPF216. The gate runs
    # directly because the mutation applies post-build.
    check_tools()
    manifest_path, out_dir = write_project(
        MAP_SOURCE, "xdp_entry", "noncore_value_obj", True,
        max_entries=1,
    )
    result = build(manifest_path, out_dir, save_temps=True)
    try:
        assert result.success is True, result.diagnostics
        assert result.work_dir is not None
        staged = os.path.join(result.work_dir, "xdp_entry.bpf.o")
        adapted = os.path.join(
            result.work_dir, "xdp_entry.adapter", "adapted.ll"
        )
        assert os.path.isfile(staged), staged
        assert os.path.isfile(adapted), adapted
        manifest = parse_manifest(manifest_path)
        assert not manifest.target.core
        assert _verify_gate_outcome(manifest, staged, adapted) == []
        mutated = _mutate_value_size(
            staged, result.work_dir, "noncore_mut16", 16
        )
        outcome = _verify_gate_outcome(manifest, mutated, adapted)
        assert outcome == [], (
            "non-core value mismatch must keep base behavior: %s"
            % (outcome,)
        )
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)
    core_manifest_path, core_out = write_core_project("core_value_obj")
    core_result = build(core_manifest_path, core_out, save_temps=True)
    try:
        assert core_result.success is True, core_result.diagnostics
        assert core_result.work_dir is not None
        staged = os.path.join(core_result.work_dir, "xdp_entry.bpf.o")
        adapted = os.path.join(
            core_result.work_dir, "xdp_entry.adapter", "adapted.ll"
        )
        assert os.path.isfile(staged), staged
        assert os.path.isfile(adapted), adapted
        manifest = parse_manifest(core_manifest_path)
        assert manifest.target.core
        assert _verify_gate_outcome(manifest, staged, adapted) == []
        mutated = _mutate_value_size(
            staged, core_result.work_dir, "core_mut8", 8
        )
        outcome = _verify_gate_outcome(manifest, mutated, adapted)
        assert [item.code for item in outcome] == ["MBPF216"], outcome
        assert "map value" in outcome[0].explanation, outcome[0]
    finally:
        if core_result.work_dir is not None:
            shutil.rmtree(core_result.work_dir, ignore_errors=True)


def test_oob_key_rejected_through_driver():
    # A key literal outside every supported map is refused at the
    # adapter audit with MBPF307 before any object exists.
    check_tools()
    manifest_path, out_dir = write_project(
        OOB_KEY_SOURCE, "xdp_entry", "oob_key_obj", True,
        max_entries=1,
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF307", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic


def test_mixed_kind_rejected_through_driver():
    # Array and per-CPU handle loads in one program match no map
    # count family: MBPF307 at the adapter audit.
    check_tools()
    manifest_path, out_dir = write_project(
        MIXED_KIND_SOURCE, "xdp_entry", "mixed_kind_obj", True,
        max_entries=1,
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF307", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic


def test_hash_mixed_kind_rejected_through_driver():
    # Array and hash handle loads in one program match no map
    # count family: MBPF307 at the adapter audit.
    check_tools()
    manifest_path, out_dir = write_project(
        HASH_MIXED_SOURCE, "xdp_entry", "hash_mixed_kind_obj", True,
        max_entries=1, map_type="hash",
        template=HASH_MANIFEST_TEMPLATE,
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF307", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic


def test_getnext_attempt_rejected_through_driver():
    # The kernel offers no from-program map-iteration helper, so
    # the long-spelled attempt is refused at the adapter audit
    # with MBPF303 before any object exists.
    check_tools()
    manifest_path, out_dir = write_project(
        GETNEXT_ATTEMPT_SOURCE, "xdp_entry", "getnext_obj", True,
        max_entries=1,
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF303", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic


def test_sdk_importing_classifier_builds():
    # No maps declared, but the source imports SDK modules: the
    # driver passes -I on the import scan, seals the SDK inputs,
    # and records coherent flags. Without the scan gate the
    # frontend fails for the missing SDK import path.
    check_tools()
    manifest_path, out_dir = write_project(
        SDK_CLASSIFIER_SOURCE, "xdp_entry", "sdk_classifier_obj", False
    )
    result = build(manifest_path, out_dir)
    assert result.success is True, result.diagnostics
    assert [item.role for item in result.artifacts] == [
        "object", "evidence",
    ]
    frontend = [
        record for record in result.commands
        if record.stage == "build.frontend"
    ]
    assert len(frontend) == 1
    argv = list(frontend[0].argv)
    assert argv[1:4] == ["build", "--emit", "llvm"], argv
    assert "-I" in argv, (
        "SDK-importing build must pass -I: %r" % (argv,)
    )
    with open(
        os.path.join(out_dir, "sdk_classifier_obj.evidence.json"),
        encoding="utf-8",
    ) as handle:
        doc = json.load(handle)
    assert "-I" in doc["inputs"]["flags"], doc["inputs"]["flags"]
    assert doc["inputs"]["sdk"], (
        "SDK inputs must be sealed when -I is passed"
    )
    object_path = os.path.join(out_dir, "sdk_classifier_obj.bpf.o")
    assert os.path.isfile(object_path)


def test_invalid_source_fails_with_frontend_diagnostic():
    check_tools()
    manifest_path, out_dir = write_project(
        BAD_SOURCE, "xdp_entry", "bad_obj", False
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF106", diagnostic
    assert diagnostic.stage == "build.frontend", diagnostic
    frontend = [
        record for record in result.commands
        if record.stage == "build.frontend"
    ]
    assert len(frontend) == 1
    assert frontend[0].exit_code != 0


def test_tracepoint_matches_pins():
    check_tools()
    manifest_path, out_dir = write_tracepoint_project(
        TRACEPOINT_SOURCE, "tracepoint_obj"
    )
    result = build(manifest_path, out_dir, save_temps=True)
    try:
        assert result.success is True, result.diagnostics
        assert [item.role for item in result.artifacts] == [
            "object", "evidence",
        ]
        pins = EXPECTED_PINS["tracepoint"]
        observed = result.artifacts[0].sha256
        assert observed == pins["object"], (
            "object mismatch: observed %s expected %s"
            % (observed, pins["object"])
        )
        workdir = result.work_dir
        assert workdir is not None
        for key, relpath in (
            ("raw_ir", "trace_entry.raw.ll"),
            ("adapted_ir", os.path.join("trace_entry.adapter",
                                        "adapted.ll")),
        ):
            observed = sha256_file(os.path.join(workdir, relpath))
            assert observed == pins[key], (
                "%s mismatch: observed %s expected %s"
                % (key, observed, pins[key])
            )
        with open(
            os.path.join(workdir, "trace_entry.raw.ll"),
            "r", encoding="utf-8",
        ) as handle:
            assert audit.validate(handle.read()) == "tracepoint"
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_tracepoint_example_manifest_builds():
    # The committed example manifest builds as-is through
    # build_project and reproduces the pinned object, so the
    # example cannot drift from the qualified route.
    check_tools()
    out_dir = tempfile.mkdtemp(prefix="build-tracepoint-example-")
    result = build(TRACEPOINT_MANIFEST, out_dir)
    assert result.success is True, result.diagnostics
    object_path = os.path.join(out_dir, "tracepoint_counter.bpf.o")
    assert os.path.isfile(object_path)
    observed = sha256_file(object_path)
    expected = EXPECTED_PINS["tracepoint"]["object"]
    assert observed == expected, (
        "example object mismatch: observed %s expected %s"
        % (observed, expected)
    )


def test_reserve_example_manifest_builds():
    # The committed reservation example manifest builds as-is
    # through build_project and reproduces the pinned object, so
    # the example cannot drift from the qualified route (audit,
    # adapter, reservation profile, spill gate, inspection, and
    # pair reconciliation all run on the driver path).
    check_tools()
    out_dir = tempfile.mkdtemp(prefix="build-reserve-example-")
    result = build(RESERVE_MANIFEST, out_dir)
    assert result.success is True, result.diagnostics
    object_path = os.path.join(out_dir, "ringbuf_reserve.bpf.o")
    assert os.path.isfile(object_path)
    observed = sha256_file(object_path)
    expected = EXPECTED_PINS["reserve"]["object"]
    assert observed == expected, (
        "example object mismatch: observed %s expected %s"
        % (observed, expected)
    )


def test_tracepoint_count_two_rejected():
    # The plus-two tracepoint program is audit-clean IR whose
    # object carries [-16, -4, -4, -4, 2]: the spill gate must
    # refuse to publish it with MBPF107 after a successful
    # backend step.
    check_tools()
    manifest_path, out_dir = write_tracepoint_project(
        TRACEPOINT_COUNT_TWO_SOURCE, "tracepoint_two_obj"
    )
    result = build(manifest_path, out_dir, save_temps=True)
    try:
        assert_failure(result, out_dir)
        diagnostic = result.diagnostics[0]
        assert diagnostic.code == "MBPF107", diagnostic
        assert diagnostic.stage == "build.backend", diagnostic
        assert "tracepoint object" in diagnostic.explanation, diagnostic
        assert "[-16, -4, -4, -4, 2]" in diagnostic.explanation, diagnostic
        assert "[-16, -4, -4, -4, 1]" in diagnostic.explanation, diagnostic
        backend = [
            record for record in result.commands
            if record.stage == "build.backend"
        ]
        assert len(backend) == 2
        assert all(record.status == "ok" for record in backend), backend
        assert result.work_dir is not None
        with open(
            os.path.join(result.work_dir, "trace_entry.raw.ll"),
            "r", encoding="utf-8",
        ) as handle:
            assert audit.validate(handle.read()) == "tracepoint"
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_tracepoint_entries_mismatch_rejected():
    # A tracepoint program paired with a one-entry manifest passes
    # the audit, adapter, backend, and spill gate, then fails map
    # reconciliation with MBPF216: the emitted two-entry map
    # disagrees with the declared count. Nothing is published.
    check_tools()
    manifest_path, out_dir = write_tracepoint_project(
        TRACEPOINT_SOURCE, "tracepoint_mismatch_obj", max_entries=1
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF216", diagnostic
    assert diagnostic.stage == "build.backend", diagnostic
    assert "2-entry map" in diagnostic.explanation, diagnostic
    assert "max_entries = 1" in diagnostic.explanation, diagnostic


def test_tracepoint_ctx_attempt_rejected_through_driver():
    # The context-reading tracepoint program matches the count
    # vector but uses its entry parameter: MBPF317 at the adapter
    # audit before any object exists.
    check_tools()
    manifest_path, out_dir = write_tracepoint_project(
        TRACEPOINT_CTX_SOURCE, "tracepoint_ctx_obj"
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF317", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic


def test_tracepoint_entry_pair_mismatch_rejected():
    # A tracepoint pair under the XDP entry root fails entry/pair
    # reconciliation with MBPF217 before anything compiles.
    check_tools()
    manifest_path, out_dir = write_tracepoint_project(
        TRACEPOINT_SOURCE, "tracepoint_pair_obj", entry="xdp_entry"
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF217", diagnostic
    assert diagnostic.stage == "build.setup", diagnostic
    assert "xdp_entry" in diagnostic.explanation, diagnostic
    assert result.commands == ()
    assert result.artifacts == ()


def _check_subprog_shape_builds(source, artifact):
    manifest_path, out_dir = write_project(
        source, "xdp_entry", artifact, False,
        template=SUBPROG_MANIFEST_TEMPLATE,
    )
    result = build(manifest_path, out_dir, save_temps=True)
    try:
        assert result.success is True, result.diagnostics
        assert [item.role for item in result.artifacts] == [
            "object", "evidence",
        ]
        object_path = os.path.join(out_dir, artifact + ".bpf.o")
        assert os.path.isfile(object_path)
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_subprog_shapes_build_through_driver():
    # Both definition orders build end to end under the
    # subprogram capability profile: audit, adapter, spill gate
    # (classifier path), inspection, and reconciliation all pass.
    check_tools()
    _check_subprog_shape_builds(SUBPROG_SOURCE, "subprog_decision_obj")
    _check_subprog_shape_builds(
        SUBPROG_ENTRY_FIRST_SOURCE, "subprog_entry_first_obj"
    )


def test_subprog_base_profile_refused():
    # The decision program under the base profile fails the
    # pre-publication inspection gate: its static call is
    # outside the base profile, so no object is published.
    check_tools()
    manifest_path, out_dir = write_project(
        SUBPROG_SOURCE, "xdp_entry", "subprog_base_obj", False,
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    codes = [item.code for item in result.diagnostics]
    assert "MBPF407" in codes, result.diagnostics
    assert "MBPF406" in codes, result.diagnostics


def test_uprobe_matches_pins():
    check_tools()
    manifest_path, out_dir = write_uprobe_project(
        UPROBE_SOURCE, "uprobe_obj"
    )
    result = build(manifest_path, out_dir, save_temps=True)
    try:
        assert result.success is True, result.diagnostics
        assert [item.role for item in result.artifacts] == [
            "object", "evidence",
        ]
        pins = EXPECTED_PINS["uprobe"]
        observed = result.artifacts[0].sha256
        assert observed == pins["object"], (
            "object mismatch: observed %s expected %s"
            % (observed, pins["object"])
        )
        workdir = result.work_dir
        assert workdir is not None
        for key, relpath in (
            ("raw_ir", "uprobe_entry.raw.ll"),
            ("adapted_ir", os.path.join("uprobe_entry.adapter",
                                        "adapted.ll")),
        ):
            observed = sha256_file(os.path.join(workdir, relpath))
            assert observed == pins[key], (
                "%s mismatch: observed %s expected %s"
                % (key, observed, pins[key])
            )
        with open(
            os.path.join(workdir, "uprobe_entry.raw.ll"),
            "r", encoding="utf-8",
        ) as handle:
            assert audit.validate(handle.read()) == "uprobe"
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_uprobe_example_manifest_builds():
    # The committed uprobe example manifest builds as-is through
    # build_project and reproduces the pinned object, so the
    # example cannot drift from the qualified route (audit,
    # adapter, uprobe profile, spill gate, inspection, and pair
    # reconciliation all run on the driver path).
    check_tools()
    out_dir = tempfile.mkdtemp(prefix="build-uprobe-example-")
    result = build(UPROBE_MANIFEST, out_dir)
    assert result.success is True, result.diagnostics
    object_path = os.path.join(out_dir, "uprobe_counter.bpf.o")
    assert os.path.isfile(object_path)
    observed = sha256_file(object_path)
    expected = EXPECTED_PINS["uprobe"]["object"]
    assert observed == expected, (
        "example object mismatch: observed %s expected %s"
        % (observed, expected)
    )


def test_uprobe_mutant_builds_through_driver():
    # The inverted mutant builds end to end under the uprobe
    # capability profile with distinct object bytes.
    check_tools()
    manifest_path, out_dir = write_uprobe_project(
        UPROBE_MUTANT_SOURCE, "uprobe_mutant_obj"
    )
    result = build(manifest_path, out_dir)
    try:
        assert result.success is True, result.diagnostics
        assert [item.role for item in result.artifacts] == [
            "object", "evidence",
        ]
        object_path = os.path.join(out_dir, "uprobe_mutant_obj.bpf.o")
        assert os.path.isfile(object_path)
        observed = sha256_file(object_path)
        assert observed != EXPECTED_PINS["uprobe"]["object"]
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_uprobe_wrong_pair_refused_through_driver():
    # The uprobe counter under the XDP pair fails build setup:
    # uprobe_entry pins ("uprobe", "uprobe"), so no build runs.
    check_tools()
    manifest_path, out_dir = write_uprobe_project(
        UPROBE_SOURCE, "uprobe_pair_obj", pair=("xdp", "xdp")
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF217", diagnostic
    assert diagnostic.stage == "build.setup", diagnostic
    assert "uprobe_entry" in diagnostic.explanation, diagnostic
    assert result.commands == ()
    assert result.artifacts == ()


def test_uprobe_reg_attempt_refused_through_driver():
    # The non-pinned register attempt is refused at the adapter
    # audit with MBPF317 before any object exists, carrying the
    # offending source line.
    check_tools()
    manifest_path, out_dir = write_uprobe_project(
        UPROBE_REG_ATTEMPT, "uprobe_reg_obj"
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF317", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic
    assert diagnostic.location is not None, diagnostic
    assert "uprobe_reg_attempt.mojo" in diagnostic.location, (
        diagnostic
    )


def test_subprog_recursion_refused_through_driver():
    # The recursive attempt is refused at the adapter audit with
    # MBPF312 before any object exists, carrying the offending
    # source line.
    check_tools()
    manifest_path, out_dir = write_project(
        SUBPROG_RECURSION_SOURCE, "xdp_entry", "subprog_rec_obj",
        False, template=SUBPROG_MANIFEST_TEMPLATE,
    )
    result = build(manifest_path, out_dir)
    assert_failure(result, out_dir)
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF312", diagnostic
    assert diagnostic.stage == "adapter.audit", diagnostic
    assert diagnostic.location is not None, diagnostic
    assert "subprog_recursion_attempt.mojo" in diagnostic.location, (
        diagnostic
    )


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    for name, func in sorted(
        [(k, v) for k, v in globals().items() if k.startswith("test_")]
    ):
        try:
            func()
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
    print("build pipeline: both pinned objects reproduced")
    return 0


if __name__ == "__main__":
    sys.exit(main())
