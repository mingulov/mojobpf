# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Fixture-driven tests for the upstream capability inventory.

Covers the frozen ``capabilities/registry.json`` revision (schema shape,
completeness, package mapping, family resolution, registration rule and
public standalone form) and the inventory tool's behavior on synthetic
fixtures (unknown atoms abort, drift aborts, aliases/sentinels classify
once, flags and context-only values survive, diffs are deterministic).

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3 tests/unit/test_capability_inventory.py``).
Uses only the standard library.
"""

import hashlib
import importlib.util
import json
import os
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
TOOL_PATH = os.path.join(ROOT, "tools", "update_capabilities.py")
SCHEMA_PATH = os.path.join(ROOT, "schemas", "capability.schema.json")
REGISTRY_PATH = os.path.join(ROOT, "capabilities", "registry.json")
LOCK_PATH = os.path.join(ROOT, "capabilities", "upstream.lock.json")

_spec = importlib.util.spec_from_file_location(
    "update_capabilities", TOOL_PATH
)
uc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uc)

EXPECTED_PACKAGES = [
    "A-ARM-PHYSICAL", "A-ARM-VM", "A-BE", "A-KERNELS", "A-OTHER", "A-X86",
    "C-BASELINE", "C-OPTIMIZE", "D-DEMO", "D-PACKAGE", "D-SUPPORT",
    "F-BTF", "F-CALLS", "F-CORE", "F-ENDIAN", "F-ISA", "M-CHANNELS",
    "M-DISPATCH", "M-KEYED", "M-SPECIAL", "M-STORAGE", "N-AFXDP",
    "N-CGROUPS", "N-HARDWARE", "N-REMAINDER", "N-ROUTING", "N-SOCKETS",
    "N-TCX", "N-XDP", "O-CONSUMERS", "O-SCX", "O-STRUCT", "P0-AUDIT",
    "P0-COST", "P0-HARNESS", "P0-INVENTORY", "P0-TARGETS", "Q-ENDIAN",
    "Q-FUZZ", "Q-HARNESS", "Q-INTERACTIONS", "Q-KERNELS", "Q-NATIVE",
    "R-EXISTING-GATE", "R-FULL", "S-LSM", "S-LSM-VARIANTS", "T-FREPLACE",
    "T-KPROBES", "T-TRACEPOINTS", "T-TRAMPOLINES", "T-UP-MULTI",
    "T-UP-SINGLE", "T-UP-VARIANTS", "T-USDT", "U-ABI", "U-ATTACH",
    "U-CONTROL", "U-EVENTS", "U-MAPS", "U-OBJECT", "X-HELPERS",
    "X-ITERATORS", "X-KFUNCS", "X-MEMORY",
]

EXPECTED_FAMILIES = [
    "btf", "calls", "core-relocations", "endian", "helpers", "isa",
    "iterators", "kfuncs", "maps-channels", "maps-dispatch", "maps-keyed",
    "maps-special", "maps-storage", "memory", "net-afxdp", "net-cgroups",
    "net-hardware", "net-remainder", "net-routing", "net-sockets", "net-tcx",
    "net-xdp", "object-elf", "sched-ext", "security-lsm",
    "security-lsm-variants", "structops-consumers", "structops-core",
    "tracing-freplace", "tracing-kprobes", "tracing-perf",
    "tracing-tracepoints", "tracing-trampolines", "tracing-uprobe-multi",
    "tracing-uprobe-single", "tracing-uprobe-variants", "tracing-usdt",
    "userspace-abi", "userspace-attach", "userspace-control",
    "userspace-events", "userspace-maps", "userspace-object",
]

_registry_cache = None
_schema_cache = None
_lock_cache = None


def load_registry():
    global _registry_cache
    if _registry_cache is None:
        with open(REGISTRY_PATH, "r", encoding="utf-8") as handle:
            _registry_cache = json.load(handle)
    return _registry_cache


def load_schema():
    global _schema_cache
    if _schema_cache is None:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as handle:
            _schema_cache = json.load(handle)
    return _schema_cache


def load_lock():
    global _lock_cache
    if _lock_cache is None:
        with open(LOCK_PATH, "r", encoding="utf-8") as handle:
            _lock_cache = json.load(handle)
    return _lock_cache


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Frozen revision checks
# ---------------------------------------------------------------------------

def test_registry_matches_schema():
    errors = uc.validate_schema(load_registry(), load_schema())
    assert errors == [], errors[:5]


def test_registry_is_complete():
    errors = uc.check_completeness(load_registry())
    assert errors == [], errors[:5]


def test_packages_are_exactly_the_required_set():
    registry = load_registry()
    found = sorted(entry["id"] for entry in registry["packages"])
    assert found == EXPECTED_PACKAGES
    assert len(found) == 65


def test_every_record_has_a_required_package_owner():
    registry = load_registry()
    allowed = set(EXPECTED_PACKAGES)
    for entry in registry["records"]:
        assert entry["owner_task"] in allowed, entry["id"]
        tests = (entry["positive_tests"] + entry["negative_tests"]
                 + entry["interaction_tests"] + entry["cost_cases"])
        assert tests, entry["id"]
        assert entry["upstream_source_refs"], entry["id"]


def test_every_named_family_resolves():
    registry = load_registry()
    found = sorted(entry["id"] for entry in registry["families"])
    assert found == EXPECTED_FAMILIES
    with_records = set(entry["family"] for entry in registry["records"])
    blocked = set(entry["family"] for entry in registry["blockers"]
                  if entry["family"])
    for family in EXPECTED_FAMILIES:
        assert family in with_records or family in blocked, family
    for entry in registry["blockers"]:
        assert entry["source_refs"], entry["id"]
        assert entry["next_action"], entry["id"]


def test_revision_is_frozen_and_bound_to_lock():
    registry = load_registry()
    assert registry["registry_version"] == "capability-registry-v1"
    assert registry["schema_version"] == 1
    assert registry["revision"] == 1
    assert registry["frozen"] is True
    assert registry["generated_by"]["lock_digest"] == sha256_file(LOCK_PATH)


def test_no_callable_without_kernel_registration():
    for entry in load_registry()["records"]:
        for helper in entry["helpers_or_kfuncs"]:
            if helper["callable"]:
                assert entry["kernel_registration_refs"], entry["id"]


def test_aliases_and_sentinels_classified_once():
    members = load_registry()["enum_members"]
    seen = set()
    by_key = {}
    for item in members:
        key = (item["container"], item["name"])
        assert key not in seen, key
        seen.add(key)
        by_key[key] = item
    for item in members:
        if item["classification"] == "alias":
            target = by_key.get((item["container"], item["canonical"]))
            assert target is not None, item["name"]
            assert target["classification"] in (
                "capability", "context-only", "limit"), item["name"]
        if item["classification"] == "sentinel":
            assert item["record_id"] is None, item["name"]


def test_flags_and_context_only_values_not_lost():
    registry = load_registry()
    record_ids = set(entry["id"] for entry in registry["records"])
    flags = 0
    contexts = 0
    for item in registry["enum_members"]:
        if item["classification"] == "capability" and item["record_id"] \
                and item["record_id"].startswith("flag:"):
            flags += 1
            assert item["record_id"] in record_ids
        if item["classification"] == "context-only":
            contexts += 1
            assert item["record_refs"], item["name"]
            for ref in item["record_refs"]:
                assert ref in record_ids, (item["name"], ref)
    assert flags > 0 and contexts > 0


def test_public_files_stand_alone():
    # Forbidden tokens are built from fragments so this very file does
    # not contain them literally.
    sep = os.sep
    forbidden = [
        sep + "w" + "ork" + sep,
        "mojobpf" + "-" + "ws",
        "memv" + "eil",
        "doc" + sep + "plans",
        "doc" + sep + "validation",
        "in" + sep + "2026",
        "stage" + "-" + "state",
        "exec" + sep + "f01",
        ".work" + "trees",
    ]
    paths = [TOOL_PATH, SCHEMA_PATH, REGISTRY_PATH, LOCK_PATH, __file__]
    for path in paths:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
        for token in forbidden:
            assert token not in text, (path, token)
    import re
    stage_ids = re.compile(r"\bF0[0-5]\b")
    for path in paths:
        with open(path, "r", encoding="utf-8") as handle:
            assert not stage_ids.search(handle.read()), path


def test_lock_pins_are_well_formed():
    lock = load_lock()
    assert lock["lock_version"] == 1
    assert lock["uapi_versions"] == ["6.6.158", "6.12.112", "7.2.9"]
    assert lock["libbpf_version"] == "1.7.0"
    assert lock["selftests_tag"] == "v7.2.9"
    import re
    digest = re.compile(r"^[0-9a-f]{64}$")
    assert lock["expected"], "lock pins no staged files"
    for relpath, value in lock["expected"].items():
        assert digest.match(value), relpath
    for doc in lock["docs"]:
        assert digest.match(doc["sha256"]), doc["id"]
    assert lock["cohorts"]["selected_union"] == ["7.2.9", "6.12.112", "6.6.158"]
    assert lock["cohorts"]["extracted"]["stable"]["version"] == "7.2.9"


# ---------------------------------------------------------------------------
# Fixture harness: synthetic pinned sources in a temporary directory
# ---------------------------------------------------------------------------

FIXTURE_BPF_H = """\
enum bpf_prog_type {
\tBPF_PROG_TYPE_UNSPEC,
\tBPF_PROG_TYPE_SOCKET_FILTER,
\tBPF_PROG_TYPE_XDP,
\t__MAX_BPF_PROG_TYPE,
};

enum {
\tBPF_F_ALLOW_OVERRIDE = (1U << 0),
};

enum {
\tXDP_DROP = 1,
\tXDP_PASS = 2,
};
"""

FIXTURE_BTF_H = """\
enum {
\tBTF_KIND_UNKN = 0,
\tBTF_KIND_INT = 1,
\tNR_BTF_KINDS,
\tBTF_KIND_MAX = NR_BTF_KINDS - 1,
};
"""

FIXTURE_COMMON_H = """\
#ifndef _UAPI__LINUX_BPF_COMMON_H__
#define _UAPI__LINUX_BPF_COMMON_H__
#define BPF_LD 0x00
#endif
"""

FIXTURE_PERF_H = """\
#ifndef _UAPI__LINUX_BPF_PERF_EVENT_H__
#define _UAPI__LINUX_BPF_PERF_EVENT_H__
struct bpf_perf_event_data {
\t__u64 addr;
};
#endif
"""

FIXTURE_MAP = """\
LIBBPF_9.9 {
\tglobal:
\t\tbpf_object__open;
\t\tbpf_map_lookup_elem;
} LIBBPF_9.8;
"""

FIXTURE_LIBBPF_H = """\
int bpf_object__open(const char *path);
int bpf_map_lookup_elem(int fd, const void *key, void *value);
"""

FIXTURE_LIBBPF_C = """\
static const struct bpf_sec_def section_defs[] = {
\tSEC_DEF("socket", SOCKET_FILTER, 0, SEC_NONE),
\tSEC_DEF("xdp", XDP, 0, SEC_ATTACHABLE_OPT),
};
"""

FIXTURE_FACTS = {
    "version": "21.1.8",
    "bpf_cpus": ["v3"],
    "bpf_features": ["alu32"],
    "bpf_targets": ["bpfel"],
}

FIXTURE_SELFTESTS = {
    "prog_tests.paths": "test_struct_ops_module.c\nxsk.c\n",
    "progs.paths": "struct_ops_autocreate.c\n",
    "verifier.paths": "",
}

FIXTURE_DOCS = [
    {"id": "kfuncs-doc", "url": "https://example.invalid/kfuncs",
     "sha256": "0" * 64},
    {"id": "sched-ext-doc", "url": "https://example.invalid/sched-ext",
     "sha256": "1" * 64},
]


class Fixture:
    """A synthetic staging directory plus its matching lock file."""

    def __init__(self, tmp, uapi_versions=("v1",), bpf_h=FIXTURE_BPF_H,
                 extra_files=None):
        self.tmp = tmp
        self.sources = os.path.join(tmp, "sources")
        self.uapi_versions = list(uapi_versions)
        for version in self.uapi_versions:
            staged = os.path.join(self.sources, "uapi", version)
            os.makedirs(staged)
            for name, text in (("bpf.h", bpf_h),
                               ("btf.h", FIXTURE_BTF_H),
                               ("bpf_common.h", FIXTURE_COMMON_H),
                               ("bpf_perf_event.h", FIXTURE_PERF_H)):
                with open(os.path.join(staged, name), "w",
                          encoding="utf-8") as handle:
                    handle.write(text)
        libdir = os.path.join(self.sources, "libbpf-9.9", "src")
        os.makedirs(libdir)
        for name, text in (("libbpf.h", FIXTURE_LIBBPF_H),
                           ("libbpf.map", FIXTURE_MAP),
                           ("libbpf.c", FIXTURE_LIBBPF_C),
                           ("bpf.h", FIXTURE_LIBBPF_H),
                           ("btf.h", ""),
                           ("libbpf_legacy.h", "")):
            with open(os.path.join(libdir, name), "w",
                      encoding="utf-8") as handle:
                handle.write(text)
        llvm_dir = os.path.join(self.sources, "llvm")
        os.makedirs(llvm_dir)
        with open(os.path.join(llvm_dir, "facts.json"), "w",
                  encoding="utf-8") as handle:
            json.dump(FIXTURE_FACTS, handle, indent=2, sort_keys=True)
            handle.write("\n")
        selftest_dir = os.path.join(self.sources, "selftests", "v9")
        os.makedirs(selftest_dir)
        for name, text in FIXTURE_SELFTESTS.items():
            with open(os.path.join(selftest_dir, name), "w",
                      encoding="utf-8") as handle:
                handle.write(text)
        if extra_files:
            for relpath, text in extra_files.items():
                path = os.path.join(self.sources, relpath)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(text)
        self.lock_path = os.path.join(tmp, "lock.json")
        self.registry_path = os.path.join(tmp, "registry.json")
        self.repin()

    def repin(self):
        expected = {}
        for root, _, files in os.walk(self.sources):
            for name in files:
                path = os.path.join(root, name)
                relpath = os.path.relpath(path, self.sources)
                if relpath.startswith("libbpf-9.9" + os.sep) and relpath not in (
                        os.path.join("libbpf-9.9", "src", "libbpf.h"),
                        os.path.join("libbpf-9.9", "src", "libbpf.map"),
                        os.path.join("libbpf-9.9", "src", "libbpf.c"),
                        os.path.join("libbpf-9.9", "src", "bpf.h"),
                        os.path.join("libbpf-9.9", "src", "btf.h"),
                        os.path.join("libbpf-9.9", "src", "libbpf_legacy.h")):
                    continue
                expected[relpath.replace(os.sep, "/")] = sha256_file(path)
        lock = {
            "lock_version": 1,
            "uapi_versions": self.uapi_versions,
            "libbpf_version": "9.9",
            "selftests_tag": "v9",
            "llvm": {"facts": dict(FIXTURE_FACTS)},
            "selftests": {"lists": {
                name: [line for line in text.splitlines() if line]
                for name, text in FIXTURE_SELFTESTS.items()
            }},
            "docs": [dict(entry) for entry in FIXTURE_DOCS],
            "expected": expected,
        }
        with open(self.lock_path, "w", encoding="utf-8") as handle:
            json.dump(lock, handle, indent=2, sort_keys=True)
            handle.write("\n")
        return lock

    def refresh(self, **kwargs):
        import argparse
        args = argparse.Namespace(
            sources=self.sources,
            lock=self.lock_path,
            registry=self.registry_path,
            rebase_lock=kwargs.get("rebase_lock", False),
            root=self.tmp,
        )
        return uc.cmd_refresh(args)

    def registry(self):
        with open(self.registry_path, "r", encoding="utf-8") as handle:
            return json.load(handle)


def test_fixture_refresh_succeeds():
    # Fixtures exercise mechanisms on a partial universe; full family
    # completeness is asserted on the frozen registry above.
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        assert fixture.refresh() == 0
        registry = fixture.registry()
        assert uc.validate_schema(registry, load_schema()) == []
        # The fixture's program type, flag and context value survive.
        record_ids = set(entry["id"] for entry in registry["records"])
        assert "prog:XDP" in record_ids
        assert "flag:BPF_F_ALLOW_OVERRIDE" in record_ids
        members = {item["name"]: item for item in registry["enum_members"]}
        assert members["XDP_DROP"]["classification"] == "context-only"
        assert members["XDP_DROP"]["record_refs"] == ["prog:XDP"]
        assert members["BPF_PROG_TYPE_UNSPEC"]["classification"] == "sentinel"


def test_unknown_atom_fails_refresh_until_owned():
    bad = FIXTURE_BPF_H.replace(
        "BPF_PROG_TYPE_XDP,",
        "BPF_PROG_TYPE_XDP,\n\tBPF_PROG_TYPE_FROBNICATOR,",
    )
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp, bpf_h=bad)
        assert fixture.refresh() == uc.EXIT_UNKNOWN
        assert not os.path.exists(fixture.registry_path)


def test_hash_drift_fails_refresh():
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        staged = os.path.join(fixture.sources, "uapi", "v1", "bpf.h")
        with open(staged, "a", encoding="utf-8") as handle:
            handle.write("/* tampered */\n")
        assert fixture.refresh() == uc.EXIT_INTEGRITY
        assert not os.path.exists(fixture.registry_path)


def test_value_conflict_across_versions_fails():
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp, uapi_versions=("v1", "v2"))
        staged = os.path.join(fixture.sources, "uapi", "v2", "bpf.h")
        with open(staged, "r", encoding="utf-8") as handle:
            text = handle.read()
        text = text.replace("(1U << 0)", "(1U << 7)")
        with open(staged, "w", encoding="utf-8") as handle:
            handle.write(text)
        fixture.repin()
        assert fixture.refresh() == uc.EXIT_UNKNOWN


def test_alias_and_sentinel_fixture_classifies_once():
    header = FIXTURE_BPF_H + """\
enum bpf_cmd {
\tBPF_MAP_CREATE,
\tBPF_MAP_CREATE_ALIAS = BPF_MAP_CREATE,
\t__MAX_BPF_CMD,
};
"""
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp, bpf_h=header)
        assert fixture.refresh() == 0
        registry = fixture.registry()
        members = {(item["container"], item["name"]): item
                   for item in registry["enum_members"]}
        alias = members[("uapi:bpf.h#bpf_cmd", "BPF_MAP_CREATE_ALIAS")]
        assert alias["classification"] == "alias"
        assert alias["canonical"] == "BPF_MAP_CREATE"
        sentinel = members[("uapi:bpf.h#bpf_cmd", "__MAX_BPF_CMD")]
        assert sentinel["classification"] == "sentinel"
        assert sentinel["record_id"] is None
        assert len(members) == len(registry["enum_members"])


def test_rebase_lock_accepts_and_reports_drift():
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        staged = os.path.join(fixture.sources, "uapi", "v1", "bpf.h")
        with open(staged, "a", encoding="utf-8") as handle:
            handle.write("/* rebased comment */\n")
        assert fixture.refresh(rebase_lock=True) == 0
        assert os.path.exists(fixture.registry_path)
        with open(fixture.lock_path, "r", encoding="utf-8") as handle:
            lock = json.load(handle)
        assert lock["expected"]["uapi/v1/bpf.h"] == sha256_file(staged)
        # A second refresh without rebase now passes: the pin moved.
        assert fixture.refresh() == 0


def test_refresh_output_is_byte_deterministic():
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        assert fixture.refresh() == 0
        with open(fixture.registry_path, "rb") as handle:
            first = handle.read()
        assert fixture.refresh() == 0
        with open(fixture.registry_path, "rb") as handle:
            assert handle.read() == first


# ---------------------------------------------------------------------------
# Completeness-rule tests by mutation
# ---------------------------------------------------------------------------

def mutated_registry():
    return json.loads(json.dumps(load_registry()))


def test_unowned_record_fails_completeness():
    registry = mutated_registry()
    registry["records"][0]["owner_task"] = "NO-SUCH-PACKAGE"
    errors = uc.check_completeness(registry)
    assert any("not a known package" in line for line in errors), errors


def test_untested_record_fails_completeness():
    registry = mutated_registry()
    target = registry["records"][0]
    target["positive_tests"] = []
    target["negative_tests"] = []
    target["interaction_tests"] = []
    target["cost_cases"] = []
    errors = uc.check_completeness(registry)
    assert any("no owner tests assigned" in line for line in errors), errors


def test_callable_without_registration_fails_completeness():
    registry = mutated_registry()
    target = next(entry for entry in registry["records"]
                  if entry["helpers_or_kfuncs"])
    target["helpers_or_kfuncs"][0]["callable"] = True
    assert target["kernel_registration_refs"] == []
    errors = uc.check_completeness(registry)
    assert any("needs kernel registration refs" in line
               for line in errors), errors


def test_callable_with_registration_passes():
    registry = mutated_registry()
    target = next(entry for entry in registry["records"]
                  if entry["helpers_or_kfuncs"])
    target["helpers_or_kfuncs"][0]["callable"] = True
    target["kernel_registration_refs"] = ["kernel:func_proto@test"]
    errors = uc.check_completeness(registry)
    assert not any("needs kernel registration refs" in line
                   for line in errors), errors


def test_lost_context_value_fails_completeness():
    registry = mutated_registry()
    target = next(entry for entry in registry["enum_members"]
                  if entry["classification"] == "context-only")
    target["record_refs"] = []
    errors = uc.check_completeness(registry)
    assert any("is lost" in line for line in errors), errors


def test_duplicate_member_fails_completeness():
    registry = mutated_registry()
    registry["enum_members"].append(dict(registry["enum_members"][0]))
    errors = uc.check_completeness(registry)
    assert any("classified twice" in line for line in errors), errors


# ---------------------------------------------------------------------------
# Diff tests
# ---------------------------------------------------------------------------

def test_diff_of_identical_registries_is_empty():
    registry = load_registry()
    diff = uc.diff_documents(registry, json.loads(json.dumps(registry)))
    assert diff["added"] == []
    assert diff["removed"] == []
    assert diff["changed"] == []
    assert diff["members_added"] == []
    assert diff["members_removed"] == []
    assert diff["members_changed"] == []
    assert uc.format_diff(diff) == ""


def test_diff_reports_sorted_stable_changes():
    old = load_registry()
    new = mutated_registry()
    new["records"] = [entry for entry in new["records"]
                      if entry["id"] != "prog:XDP"]
    target = next(entry for entry in new["records"]
                  if entry["id"] == "prog:SOCKET_FILTER")
    target["next_action"] = "changed for the diff test"
    changed_id = target["id"]
    diff = uc.diff_documents(old, new)
    first = uc.format_diff(diff)
    second = uc.format_diff(uc.diff_documents(old, new))
    assert first == second
    assert "record removed: prog:XDP\n" in first
    assert "record changed: %s (next_action)\n" % changed_id in first
    assert diff["added"] == sorted(diff["added"])
    assert diff["removed"] == sorted(diff["removed"])
    assert [entry["id"] for entry in diff["changed"]] == sorted(
        entry["id"] for entry in diff["changed"])
    assert diff["members_added"] == sorted(diff["members_added"])
    assert diff["members_removed"] == sorted(diff["members_removed"])


# ---------------------------------------------------------------------------
# Schema-subset contract and validator behavior
# ---------------------------------------------------------------------------

SUPPORTED_KEYWORDS = frozenset({
    "type", "required", "properties", "additionalProperties", "items",
    "enum", "const", "pattern", "minItems",
})
IGNORED_KEYWORDS = frozenset({
    "$schema", "$comment", "license", "title", "description",
})


def test_schema_uses_only_the_supported_subset():
    def walk(node, path):
        assert isinstance(node, dict), path
        for key, value in node.items():
            assert key in SUPPORTED_KEYWORDS or key in IGNORED_KEYWORDS, (
                path, key)
            if key == "properties":
                for name, sub in value.items():
                    walk(sub, "%s.%s" % (path, name))
            if key == "items":
                walk(value, path + "[]")
    walk(load_schema(), "schema")


def test_validator_catches_each_supported_keyword():
    schema = {
        "type": "object",
        "required": ["name", "tags"],
        "additionalProperties": False,
        "properties": {
            "name": {"type": "string", "pattern": "^[a-z]+$"},
            "kind": {"const": "fixed"},
            "mode": {"enum": ["a", "b"]},
            "tags": {"type": "array", "minItems": 1,
                     "items": {"type": "integer"}},
            "maybe": {"type": ["string", "null"]},
        },
    }
    good = {"name": "ok", "kind": "fixed", "mode": "a",
            "tags": [1], "maybe": None}
    assert uc.validate_schema(good, schema) == []
    bad_type = dict(good, tags="nope")
    assert uc.validate_schema(bad_type, schema) != []
    missing = dict(good)
    del missing["tags"]
    assert any("missing required" in line
               for line in uc.validate_schema(missing, schema))
    extra = dict(good, surprise=1)
    assert any("unknown field" in line
               for line in uc.validate_schema(extra, schema))
    assert uc.validate_schema(dict(good, name="NOPE"), schema) != []
    assert uc.validate_schema(dict(good, kind="other"), schema) != []
    assert uc.validate_schema(dict(good, mode="zzz"), schema) != []
    assert uc.validate_schema(dict(good, tags=[]), schema) != []
    # Booleans are not integers.
    assert uc.validate_schema(dict(good, tags=[True]), schema) != []


def test_export_writes_pinned_bundle():
    with tempfile.TemporaryDirectory() as tmp:
        import argparse
        out = os.path.join(tmp, "bundle")
        args = argparse.Namespace(registry=REGISTRY_PATH,
                                  schema=SCHEMA_PATH, out=out, root=ROOT)
        assert uc.cmd_export(args) == 0
        with open(os.path.join(out, "DIGESTS.json"), "r",
                  encoding="utf-8") as handle:
            bundle = json.load(handle)
        assert bundle["bundle"] == "capability-registry-v1"
        assert bundle["revision"] == 1
        for name, digest in bundle["files"].items():
            assert digest == sha256_file(os.path.join(out, name)), name


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
