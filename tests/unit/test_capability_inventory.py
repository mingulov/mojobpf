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
    lock = load_lock()
    assert registry["registry_version"] == "capability-registry-v1"
    assert registry["schema_version"] == 1
    assert registry["revision"] == 1
    assert registry["frozen"] is True
    assert registry["generated_by"]["lock_digest"] == \
        uc.lock_digest_of(lock)
    assert registry["revision"] == lock["registry_revision"]
    assert lock["published"]["registry_digest"] == \
        sha256_file(REGISTRY_PATH)
    assert lock["published"]["records"] == len(registry["records"])
    assert lock["published"]["members"] == len(registry["enum_members"])
    assert lock["published"]["revision"] == registry["revision"]
    assert uc.check_binding(registry, lock,
                            sha256_file(REGISTRY_PATH)) == []


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
    # Coordination identifiers: gates, spec stages/phases and plan
    # leaves. The patterns name no literal ID, so they are safe here.
    id_patterns = [
        re.compile(r"\bG[0-9]+\b"),
        re.compile(r"\bS[0-9]{2}\b"),
        re.compile(r"\bP[0-5]\.[0-9]+\b"),
        re.compile(r"\b[FAUTR][0-9]{2}\b"),
    ]
    for path in paths:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
        for pattern in id_patterns:
            assert not pattern.search(text), (path, pattern.pattern)
    # Positive controls, built from fragments like the tokens above.
    assert id_patterns[0].search("the original " + "G" + "5 gate")
    assert id_patterns[1].search("stage " + "S" + "01")
    assert id_patterns[2].search("phase " + "P" + "0.1")
    assert id_patterns[3].search("leaf " + "F" + "01")
    assert id_patterns[3].search("leaf " + "A" + "11")
    assert id_patterns[3].search("leaf " + "U" + "05")
    assert id_patterns[3].search("leaf " + "T" + "02")
    assert id_patterns[3].search("leaf " + "R" + "00")


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
\tBPF_PROG_TYPE_STRUCT_OPS,
\t__MAX_BPF_PROG_TYPE,
};

enum {
\tBPF_F_ALLOW_OVERRIDE = (1U << 0),
};

enum {
\tXDP_DROP = 1,
\tXDP_PASS = 2,
};

#define ___BPF_FUNC_MAPPER(FN, ctx...) \
\tFN(unspec, 0, ##ctx) \
\tFN(map_lookup_elem, 1, ##ctx) \
\tFN(ktime_get_ns, 5, ##ctx) \
\tFN(redirect, 33, ##ctx)
/* end of mapper */
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

FIXTURE_BPF_TYPES_H = """\
BPF_PROG_TYPE(BPF_PROG_TYPE_SOCKET_FILTER, sk_filter, void *, void *)
BPF_PROG_TYPE(BPF_PROG_TYPE_XDP, xdp, void *, void *)
BPF_PROG_TYPE(BPF_PROG_TYPE_STRUCT_OPS, bpf_struct_ops, void *, void *)
"""

FIXTURE_KERNEL_PROTOS = """\
/* Synthetic kernel registration fixture. */
const struct bpf_func_proto *
sk_filter_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_proto;
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

const struct bpf_func_proto *
xdp_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_redirect:
		return &bpf_redirect_proto;
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

const struct bpf_func_proto *
bpf_base_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_proto;
	case BPF_FUNC_ktime_get_ns:
		return &bpf_ktime_get_ns_proto;
	default:
		return NULL;
	}
}

const struct bpf_verifier_ops sk_filter_verifier_ops = {
	.get_func_proto		= sk_filter_func_proto,
};

const struct bpf_verifier_ops xdp_verifier_ops = {
	.get_func_proto		= xdp_func_proto,
};

const struct bpf_verifier_ops bpf_struct_ops_verifier_ops = {
};

BTF_KFUNCS_START(fixture_kfunc_ids)
BTF_ID(func, bpf_fixture_acquire, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_fixture_release, KF_RELEASE)
BTF_KFUNCS_END(fixture_kfunc_ids)

static const struct btf_kfunc_id_set fixture_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &fixture_kfunc_ids,
};

static int __init fixture_kfunc_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &fixture_kfunc_set);
}
"""

FIXTURE_BTF_C = """\
/* Synthetic btf.c fixture: hook switch plus COMMON-first matching. */
static int bpf_prog_type_to_kfunc_hook(enum bpf_prog_type prog_type)
{
	switch (prog_type) {
	case BPF_PROG_TYPE_UNSPEC:
		return BTF_KFUNC_HOOK_COMMON;
	case BPF_PROG_TYPE_XDP:
		return BTF_KFUNC_HOOK_XDP;
	case BPF_PROG_TYPE_SOCKET_FILTER:
		return BTF_KFUNC_HOOK_SOCKET_FILTER;
	default:
		return BTF_KFUNC_HOOK_MAX;
	}
}

bool btf_kfunc_is_allowed(const struct btf *btf,
			  u32 kfunc_btf_id,
			  const struct bpf_prog *prog)
{
	enum bpf_prog_type prog_type = resolve_prog_type(prog);
	u32 *kfunc_flags;

	kfunc_flags = __btf_kfunc_id_set_contains(btf, BTF_KFUNC_HOOK_COMMON, kfunc_btf_id, prog);
	if (kfunc_flags)
		return kfunc_flags;

	hook = bpf_prog_type_to_kfunc_hook(prog_type);
	return __btf_kfunc_id_set_contains(btf, hook, kfunc_btf_id, prog);
}
"""

FIXTURE_KERNEL_FILES = {
    "include/linux/bpf_types.h": FIXTURE_BPF_TYPES_H,
    "kernel/bpf/btf.c": FIXTURE_BTF_C,
    "kernel/bpf/test_proto.c": FIXTURE_KERNEL_PROTOS,
}


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
        for version in self.uapi_versions:
            for relpath, text in FIXTURE_KERNEL_FILES.items():
                path = os.path.join(self.sources, "linux", version, relpath)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as handle:
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
            "registry_revision": 1,
            "kernel_files": {
                version: sorted(FIXTURE_KERNEL_FILES)
                for version in self.uapi_versions
            },
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
            schema=SCHEMA_PATH,
            rebase_lock=kwargs.get("rebase_lock", False),
            root=self.tmp,
        )
        return uc.cmd_refresh(args)

    def extract(self):
        """Run verify/load/inventory without publishing (partial fixtures)."""
        lock = uc.load_json(self.lock_path)
        uc.verify_staging(self.sources, lock)
        staging = uc.load_staging(self.sources, lock)
        return staging, lock, uc.inventory(staging, lock)

    def registry(self):
        with open(self.registry_path, "r", encoding="utf-8") as handle:
            return json.load(handle)


def test_fixture_refresh_refuses_partial_universe():
    # Refresh validates before publishing, so the partial fixture
    # universe must fail the gate and publish nothing. Mechanism
    # coverage stays at the extraction layer (see below).
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        assert fixture.refresh() == uc.EXIT_INVALID
        assert not os.path.exists(fixture.registry_path)


def expect_inventory_error(func, status):
    try:
        func()
    except uc.InventoryError as exc:
        assert exc.status == status, exc
    else:
        raise AssertionError("expected InventoryError")


def test_fixture_extraction_covers_mechanisms():
    # Fixtures exercise mechanisms on a partial universe; full family
    # completeness is asserted on the frozen registry above.
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        _, _, registry = fixture.extract()
        assert uc.validate_schema(registry, load_schema()) == []
        # The fixture's program type, flag and context value survive.
        record_ids = set(entry["id"] for entry in registry["records"])
        assert "prog:XDP" in record_ids
        assert "flag:BPF_F_ALLOW_OVERRIDE" in record_ids
        members = {item["name"]: item for item in registry["enum_members"]}
        assert members["XDP_DROP"]["classification"] == "context-only"
        assert members["XDP_DROP"]["record_refs"] == ["prog:XDP"]
        assert members["BPF_PROG_TYPE_UNSPEC"]["classification"] == "sentinel"
        # Helper registration resolves through the fixture protos and
        # the fixture kfunc set yields callable kfunc records.
        helper = next(entry for entry in registry["records"]
                      if entry["id"] == "helper:map_lookup_elem")
        assert helper["helpers_or_kfuncs"][0]["callable"] is True
        assert helper["kernel_registration_refs"]
        kfunc = next(entry for entry in registry["records"]
                     if entry["id"] == "kfunc:bpf_fixture_acquire")
        assert kfunc["helpers_or_kfuncs"][0]["callable"] is True
        assert kfunc["kernel_registration_refs"] == [
            "linux:kernel/bpf/test_proto.c@v1#fixture_kfunc_ids"]
        assert members["bpf_fixture_acquire"]["classification"] == \
            "capability"
        prog = next(entry for entry in registry["records"]
                    if entry["id"] == "prog:XDP")
        assert prog["kernel_registration_refs"] == [
            "linux:kernel/bpf/test_proto.c@v1#xdp_verifier_ops"]


def test_unknown_atom_fails_refresh_until_owned():
    bad = FIXTURE_BPF_H.replace(
        "BPF_PROG_TYPE_XDP,",
        "BPF_PROG_TYPE_XDP,\n\tBPF_PROG_TYPE_FROBNICATOR,",
    )
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp, bpf_h=bad)
        expect_inventory_error(fixture.extract, uc.EXIT_UNKNOWN)


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
        expect_inventory_error(fixture.extract, uc.EXIT_UNKNOWN)


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
        _, _, registry = fixture.extract()
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
        # The pin moves, but the partial fixture still fails the
        # publish gate: refresh reports the rebase, then refuses.
        assert fixture.refresh(rebase_lock=True) == uc.EXIT_INVALID
        assert not os.path.exists(fixture.registry_path)
        with open(fixture.lock_path, "r", encoding="utf-8") as handle:
            lock = json.load(handle)
        assert lock["expected"]["uapi/v1/bpf.h"] == sha256_file(staged)
        # The moved pin is coherent: verify passes without rebase now.
        assert uc.verify_staging(fixture.sources, lock) == []


def test_rebase_lock_updates_sources_mirrors():
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        with open(fixture.lock_path, "r", encoding="utf-8") as handle:
            lock = json.load(handle)
        lock["sources"] = [{
            "id": "linux-uapi",
            "versions": [{
                "version": "v1",
                "files": [{
                    "url": "https://example.invalid/bpf.h?h=vv1",
                    "sha256": lock["expected"]["uapi/v1/bpf.h"],
                }],
            }],
        }]
        with open(fixture.lock_path, "w", encoding="utf-8") as handle:
            json.dump(lock, handle, indent=2, sort_keys=True)
        staged = os.path.join(fixture.sources, "uapi", "v1", "bpf.h")
        with open(staged, "a", encoding="utf-8") as handle:
            handle.write("/* mirror drift */\n")
        with open(fixture.lock_path, "r", encoding="utf-8") as handle:
            lock = json.load(handle)
        delta = uc.verify_staging(fixture.sources, lock, rebase=True)
        assert any(line.startswith("MIRROR") for line in delta), delta
        mirror = lock["sources"][0]["versions"][0]["files"][0]["sha256"]
        assert mirror == lock["expected"]["uapi/v1/bpf.h"]


def test_rebase_lock_updates_copies():
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        facts_path = os.path.join(fixture.sources, "llvm", "facts.json")
        with open(facts_path, "r", encoding="utf-8") as handle:
            facts = json.load(handle)
        facts["bpf_cpus"] = ["v3", "v4"]
        with open(facts_path, "w", encoding="utf-8") as handle:
            json.dump(facts, handle, indent=2, sort_keys=True)
            handle.write("\n")
        with open(fixture.lock_path, "r", encoding="utf-8") as handle:
            lock = json.load(handle)
        delta = uc.verify_staging(fixture.sources, lock, rebase=True)
        assert any("llvm facts" in line for line in delta), delta
        assert lock["llvm"]["facts"]["bpf_cpus"] == ["v3", "v4"]
        assert lock["expected"]["llvm/facts.json"] == \
            sha256_file(facts_path)


def test_consumed_file_without_pin_fails_verify():
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        with open(fixture.lock_path, "r", encoding="utf-8") as handle:
            lock = json.load(handle)
        del lock["expected"]["uapi/v1/bpf.h"]
        try:
            uc.verify_staging(fixture.sources, lock)
        except uc.InventoryError as exc:
            assert exc.status == uc.EXIT_INTEGRITY
            assert "without pin" in str(exc), exc
        else:
            raise AssertionError("expected InventoryError")


def test_stale_pin_fails_verify():
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        with open(fixture.lock_path, "r", encoding="utf-8") as handle:
            lock = json.load(handle)
        lock["expected"]["uapi/v1/never-consumed.h"] = "0" * 64
        try:
            uc.verify_staging(fixture.sources, lock)
        except uc.InventoryError as exc:
            assert exc.status == uc.EXIT_INTEGRITY
            assert "stale pin" in str(exc), exc
        else:
            raise AssertionError("expected InventoryError")


def test_refresh_output_is_byte_deterministic():
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        _, _, first = fixture.extract()
        _, _, second = fixture.extract()
        assert uc.dump_canonical(first) == uc.dump_canonical(second)


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
    target["kernel_registration_refs"] = []
    target["callable_context_predicates"] = []
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
    assert diff["blockers_added"] == []
    assert diff["blockers_removed"] == []
    assert diff["blockers_changed"] == []
    assert diff["families_added"] == []
    assert diff["families_removed"] == []
    assert diff["families_changed"] == []
    assert diff["packages_added"] == []
    assert diff["packages_removed"] == []
    assert diff["packages_changed"] == []
    assert diff["metadata_changed"] == []
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
                                  schema=SCHEMA_PATH, out=out, root=ROOT,
                                  lock=LOCK_PATH)
        assert uc.cmd_export(args) == 0
        with open(os.path.join(out, "DIGESTS.json"), "r",
                  encoding="utf-8") as handle:
            bundle = json.load(handle)
        assert bundle["bundle"] == "capability-registry-v1"
        assert bundle["revision"] == 1
        for name, digest in bundle["files"].items():
            assert digest == sha256_file(os.path.join(out, name)), name


def test_export_rejects_revision_mismatch():
    with tempfile.TemporaryDirectory() as tmp:
        import argparse
        # Supported registry revision that disagrees with the lock.
        lock = json.loads(json.dumps(load_lock()))
        lock["registry_revision"] = 2
        lock_path = os.path.join(tmp, "lock.json")
        with open(lock_path, "w", encoding="utf-8") as handle:
            json.dump(lock, handle, indent=2, sort_keys=True)
        args = argparse.Namespace(registry=REGISTRY_PATH,
                                  schema=SCHEMA_PATH,
                                  out=os.path.join(tmp, "bundle"),
                                  root=ROOT, lock=lock_path)
        assert uc.cmd_export(args) == uc.EXIT_INVALID
        # Unsupported registry revision is rejected outright.
        registry = mutated_registry()
        registry["revision"] = 2
        registry_path = os.path.join(tmp, "registry.json")
        with open(registry_path, "w", encoding="utf-8") as handle:
            json.dump(registry, handle, indent=2, sort_keys=True)
        args = argparse.Namespace(registry=registry_path,
                                  schema=SCHEMA_PATH,
                                  out=os.path.join(tmp, "bundle2"),
                                  root=ROOT, lock=LOCK_PATH)
        assert uc.cmd_export(args) == uc.EXIT_INVALID


def test_unsupported_lock_revision_fails_extraction():
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        with open(fixture.lock_path, "r", encoding="utf-8") as handle:
            lock = json.load(handle)
        lock["registry_revision"] = 2
        with open(fixture.lock_path, "w", encoding="utf-8") as handle:
            json.dump(lock, handle, indent=2, sort_keys=True)
        expect_inventory_error(fixture.extract, uc.EXIT_UNKNOWN)


# ---------------------------------------------------------------------------
# Registration, flags, binding and mapping tests for the landed pins
# ---------------------------------------------------------------------------

def test_xdp_flags_follow_pinned_libbpf():
    records = {entry["id"]: entry for entry in load_registry()["records"]}
    # Optional load variants are never universal program requirements.
    assert records["prog:XDP"]["required_flags"] == []
    # Pinned libbpf sets HAS_FRAGS exactly for SEC_XDP_FRAGS sections.
    for rec_id in ("section:xdp.frags", "section:xdp.frags/devmap",
                   "section:xdp.frags/cpumap"):
        assert records[rec_id]["required_flags"] == \
            ["BPF_F_XDP_HAS_FRAGS"], rec_id
    assert records["section:xdp"]["required_flags"] == []


def _validate_copy(registry, lock):
    import argparse
    tmp = tempfile.mkdtemp()
    registry_path = os.path.join(tmp, "registry.json")
    lock_path = os.path.join(tmp, "lock.json")
    with open(registry_path, "w", encoding="utf-8") as handle:
        handle.write(uc.dump_canonical(registry))
    with open(lock_path, "w", encoding="utf-8") as handle:
        handle.write(uc.dump_canonical(lock))
    args = argparse.Namespace(schema=SCHEMA_PATH, registry=registry_path,
                              lock=lock_path, sources=None, root=ROOT)
    try:
        return uc.cmd_validate(args)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_validate_accepts_frozen_registry():
    assert _validate_copy(load_registry(), load_lock()) == uc.EXIT_OK


def test_validate_defeats_deleted_api_and_member():
    registry = mutated_registry()
    registry["records"] = [entry for entry in registry["records"]
                           if entry["id"] != "api:bpf_object__open"]
    registry["enum_members"] = [
        item for item in registry["enum_members"]
        if not (item["container"] == "libbpf:libbpf.map"
                and item["name"] == "bpf_object__open")]
    assert _validate_copy(registry, load_lock()) == uc.EXIT_INVALID


def test_validate_defeats_rewritten_member_value():
    registry = mutated_registry()
    for item in registry["enum_members"]:
        if item["name"] == "BPF_PROG_TYPE_XDP":
            item["value"] = 999
    assert _validate_copy(registry, load_lock()) == uc.EXIT_INVALID


def test_validate_defeats_swapped_lock_digest():
    registry = mutated_registry()
    registry["generated_by"]["lock_digest"] = "0" * 64
    assert _validate_copy(registry, load_lock()) == uc.EXIT_INVALID


def test_validate_defeats_tampered_published_pin():
    lock = json.loads(json.dumps(load_lock()))
    lock["published"]["records"] += 1
    assert _validate_copy(load_registry(), lock) == uc.EXIT_INVALID


def test_dangling_alias_fails_completeness():
    registry = mutated_registry()
    registry["enum_members"].append({
        "name": "BOGUS_ALIAS", "container": "uapi:bpf.h#bpf_cmd",
        "value": 1, "value_text": "1", "present_in": ["7.2.9"],
        "classification": "alias", "record_id": None,
        "canonical": "NO_SUCH_TARGET", "record_refs": [], "note": "",
    })
    errors = uc.check_completeness(registry)
    assert any("alias target" in line for line in errors), errors
    assert _validate_copy(registry, load_lock()) == uc.EXIT_INVALID


def test_diff_covers_blockers_families_packages_metadata():
    old = load_registry()
    new = mutated_registry()
    new["blockers"] = []
    new["revision"] = 99
    target = next(entry for entry in new["families"]
                  if entry["id"] == "helpers")
    target["owner"] = "X-KFUNCS"
    package = next(entry for entry in new["packages"]
                   if entry["id"] == "X-HELPERS")
    package["title"] = "changed title"
    diff = uc.diff_documents(old, new)
    text = uc.format_diff(diff)
    assert "metadata changed: revision" in text
    assert "blocker removed: " in text
    assert "family changed: helpers (owner)" in text
    assert "package changed: X-HELPERS (title)" in text


def test_helpers_are_registered_and_callable():
    registry = load_registry()
    members = {(item["container"], item["name"]): item
               for item in registry["enum_members"]}
    helpers = [entry for entry in registry["records"]
               if entry["id"].startswith("helper:")]
    assert len(helpers) == 211
    for entry in helpers:
        assert entry["implementation_state"] == "PLANNED", entry["id"]
        assert entry["blocker"] is None, entry["id"]
        assert entry["helpers_or_kfuncs"][0]["callable"] is True, \
            entry["id"]
        assert entry["kernel_registration_refs"], entry["id"]
        assert entry["callable_context_predicates"], entry["id"]
        # Every UAPI version carrying the helper has a registration.
        short = entry["id"][len("helper:"):]
        present = members[("uapi:bpf.h#helper-mapper",
                           "BPF_FUNC_" + short)]["present_in"]
        ref_versions = set(
            ref.split("@")[1].split("#")[0]
            for ref in entry["kernel_registration_refs"])
        assert set(present) <= ref_versions, entry["id"]
        for ref in entry["kernel_registration_refs"]:
            assert ref.startswith("linux:"), ref


def test_kfuncs_are_enumerated_with_registration():
    registry = load_registry()
    kfuncs = [entry for entry in registry["records"]
              if entry["id"].startswith("kfunc:")]
    assert len(kfuncs) > 100, len(kfuncs)
    members = {(item["container"], item["name"]): item
               for item in registry["enum_members"]}
    for entry in kfuncs:
        assert entry["family"] == "kfuncs", entry["id"]
        assert entry["kernel_registration_refs"], entry["id"]
        assert any(line.startswith("kfunc flags")
                   for line in entry["callable_context_predicates"]), \
            entry["id"]
        member = members[("linux:kfunc-sets",
                          entry["id"][len("kfunc:"):])]
        assert member["classification"] == "capability"
        assert member["record_id"] == entry["id"]
    # Fmodret attach targets stay traceable but claim no call.
    fmodret = [item for item in registry["enum_members"]
               if item["container"] == "linux:fmodret-ids"]
    assert fmodret, "expected fmodret attach-target members"
    record_ids = set(entry["id"] for entry in registry["records"])
    for item in fmodret:
        assert item["classification"] == "context-only"
        assert item["record_refs"] == ["attach:MODIFY_RETURN"]
        assert "attach:MODIFY_RETURN" in record_ids


def test_selftest_ids_all_mapped():
    registry = load_registry()
    lock = load_lock()
    tag = lock["selftests_tag"]
    indexed = set()
    for name, entries in lock["selftests"]["lists"].items():
        subdir = name[: -len(".paths")]
        for entry in entries:
            indexed.add("%s/%s" % (subdir, entry))
    assert len(indexed) > 1000
    cited = set()
    for entry in registry["records"]:
        for ref in entry["upstream_source_refs"]:
            marker = "selftests:%s#" % tag
            if ref.startswith(marker):
                cited.add(ref[len(marker):])
    for entry in registry["blockers"]:
        for ref in entry.get("source_refs", []):
            marker = "selftests:%s#" % tag
            # Index-level refs (no subdir) cite the whole index, not an ID.
            if ref.startswith(marker) and "/" in ref[len(marker):]:
                cited.add(ref[len(marker):])
    assert cited - indexed == set(), cited - indexed
    assert indexed - cited == set(), sorted(indexed - cited)[:10]


def test_lock_pins_kernel_sources():
    lock = load_lock()
    assert sorted(lock["kernel_files"]) == sorted(lock["uapi_versions"])
    for version, files in lock["kernel_files"].items():
        assert "include/linux/bpf_types.h" in files
        assert "kernel/bpf/btf.c" in files
        for relpath in files:
            staged = "linux/%s/%s" % (version, relpath)
            assert staged in lock["expected"], staged
    kernel = next(entry for entry in lock["sources"]
                  if entry["id"] == "linux-kernel")
    import re
    digest = re.compile(r"^[0-9a-f]{64}$")
    for version in kernel["versions"]:
        for item in version["files"]:
            assert digest.match(item["sha256"]), item["name"]
            assert item["url"].endswith("?h=v%s" % version["version"])
    assert "registration" in lock["extraction_rules"]
    assert "selftests" in lock["extraction_rules"]


def test_kernel_proto_parser_keeps_subdispatchers():
    text = (
        "static const struct bpf_func_proto *\n"
        "weird_name(enum bpf_func_id func_id, const struct bpf_prog *prog)\n"
        "{\n"
        "\tswitch (func_id) {\n"
        "\tcase BPF_FUNC_map_lookup_elem:\n"
        "\t\treturn &proto;\n"
        "\tdefault:\n"
        "\t\treturn bpf_base_func_proto(func_id, prog);\n"
        "\t}\n"
        "}\n"
    )
    protos = uc.parse_func_protos(text)
    assert set(protos) == {"weird_name"}
    assert protos["weird_name"][0] == {"BPF_FUNC_map_lookup_elem"}
    assert protos["weird_name"][1] == {"bpf_base_func_proto"}


def test_kernel_proto_parser_skips_indirect_and_keywords():
    text = (
        "const struct bpf_func_proto *\n"
        "bpf_iter_get_func_proto(enum bpf_func_id func_id, "
        "const struct bpf_prog *prog)\n"
        "{\n"
        "\tif (reg_info->get_func_proto)\n"
        "\t\tfn = reg_info->get_func_proto(func_id, prog);\n"
        "\treturn fn;\n"
        "}\n"
    )
    protos = uc.parse_func_protos(text)
    assert protos["bpf_iter_get_func_proto"] == (set(), set())


def test_kfunc_block_parses_all_three_forms():
    text = (
        "BTF_KFUNCS_START(first_ids)\n"
        "BTF_ID(func, one)\n"
        "BTF_KFUNCS_END(first_ids)\n"
        "BTF_SET8_START(second_ids)\n"
        "BTF_ID_FLAGS(func, two, KF_ACQUIRE)\n"
        "BTF_SET8_END(second_ids)\n"
        "BTF_SET_START(third_ids)\n"
        "BTF_ID(func, three)\n"
        "BTF_SET_END(third_ids)\n"
    )
    blocks = uc.parse_kfunc_blocks(text)
    assert blocks["first_ids"] == [("one", None)]
    assert blocks["second_ids"] == [("two", "KF_ACQUIRE")]
    assert blocks["third_ids"] == [("three", None)]


def test_hook_switch_and_common_first():
    tables = uc.parse_kfunc_hook_switch(FIXTURE_BTF_C)
    assert tables["BPF_PROG_TYPE_UNSPEC"] == "BTF_KFUNC_HOOK_COMMON"
    assert tables["BPF_PROG_TYPE_XDP"] == "BTF_KFUNC_HOOK_XDP"
    assert uc.check_kfunc_common_first(FIXTURE_BTF_C) is True
    legacy = FIXTURE_BTF_C.replace("btf_kfunc_is_allowed",
                                   "btf_kfunc_id_set_contains")
    assert uc.check_kfunc_common_first(legacy) is True


def test_fixture_structops_consumer_and_ext_roots():
    protos_c = FIXTURE_KERNEL_PROTOS + """\
const struct bpf_verifier_ops bpf_dummy_verifier_ops = {
\t.get_func_proto\t\t= bpf_base_func_proto,
};

struct bpf_struct_ops bpf_bpf_dummy_ops = {
\t.verifier_ops\t\t= &bpf_dummy_verifier_ops,
};
"""
    bpf_types_h = FIXTURE_BPF_TYPES_H + (
        "BPF_PROG_TYPE(BPF_PROG_TYPE_STRUCT_OPS, bpf_struct_ops, "
        "void *, void *)\n"
        "BPF_PROG_TYPE(BPF_PROG_TYPE_EXT, bpf_extension, void *, void *)\n"
    )
    struct_ops_c = """\
const struct bpf_verifier_ops bpf_struct_ops_verifier_ops = {
};

const struct bpf_verifier_ops bpf_extension_verifier_ops = {
};
"""
    files = {
        "include/linux/bpf_types.h": bpf_types_h,
        "kernel/bpf/btf.c": FIXTURE_BTF_C,
        "kernel/bpf/test_proto.c": protos_c,
        "kernel/bpf/extra_ops.c": struct_ops_c,
    }
    staging = {"kernel_versions": ["v1"], "kernel": {"v1": files}}
    registration = uc.collect_kernel_registration(staging)
    roots = uc.registration_roots(
        registration["v1"], "v1",
        ["BPF_PROG_TYPE_SOCKET_FILTER", "BPF_PROG_TYPE_XDP",
         "BPF_PROG_TYPE_STRUCT_OPS", "BPF_PROG_TYPE_EXT"])
    assert roots["BPF_PROG_TYPE_EXT"] == {
        "roots": [],
        "vops": [("bpf_extension_verifier_ops", "kernel/bpf/extra_ops.c")],
        "note": "target-inherited",
    }
    struct_ops = roots["BPF_PROG_TYPE_STRUCT_OPS"]
    assert ("bpf_base_func_proto", "bpf_dummy_verifier_ops",
            "kernel/bpf/test_proto.c") in struct_ops["roots"]
    defs = registration["v1"]["struct_ops"]
    assert defs["bpf_bpf_dummy_ops"]["vops"] == "bpf_dummy_verifier_ops"
    assert defs["bpf_bpf_dummy_ops"]["file"] == "kernel/bpf/test_proto.c"


def test_unknown_structops_consumer_fails_collection():
    protos_c = FIXTURE_KERNEL_PROTOS + """\
struct bpf_struct_ops bpf_widget_ops = {
\t.verifier_ops\t\t= &bpf_widget_verifier_ops,
};
"""
    files = {
        "include/linux/bpf_types.h": FIXTURE_BPF_TYPES_H,
        "kernel/bpf/btf.c": FIXTURE_BTF_C,
        "kernel/bpf/test_proto.c": protos_c,
    }
    staging = {"kernel_versions": ["v1"], "kernel": {"v1": files}}
    try:
        uc.collect_kernel_registration(staging)
    except uc.InventoryError as exc:
        assert "unknown struct_ops consumer bpf_widget_ops" in str(exc)
    else:
        raise AssertionError("expected InventoryError")


# ---------------------------------------------------------------------------
# Mirror coherence, export gates, kfunc filters, scheduler enumeration
# ---------------------------------------------------------------------------

def _export_copy(registry, lock):
    import argparse
    import shutil
    tmp = tempfile.mkdtemp()
    registry_path = os.path.join(tmp, "registry.json")
    lock_path = os.path.join(tmp, "lock.json")
    out = os.path.join(tmp, "bundle")
    with open(registry_path, "w", encoding="utf-8") as handle:
        handle.write(uc.dump_canonical(registry))
    with open(lock_path, "w", encoding="utf-8") as handle:
        handle.write(uc.dump_canonical(lock))
    args = argparse.Namespace(registry=registry_path, schema=SCHEMA_PATH,
                              out=out, root=ROOT, lock=lock_path)
    try:
        return uc.cmd_export(args), out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _fixture_lock_with_toolchain_mirror(fixture):
    with open(fixture.lock_path, "r", encoding="utf-8") as handle:
        lock = json.load(handle)
    lock["sources"] = [{
        "id": "llvm-toolchain",
        "version": FIXTURE_FACTS["version"],
        "facts": dict(FIXTURE_FACTS),
    }]
    with open(fixture.lock_path, "w", encoding="utf-8") as handle:
        json.dump(lock, handle, indent=2, sort_keys=True)
    return lock


def test_rebase_lock_updates_llvm_toolchain_mirror():
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        _fixture_lock_with_toolchain_mirror(fixture)
        facts_path = os.path.join(fixture.sources, "llvm", "facts.json")
        with open(facts_path, "r", encoding="utf-8") as handle:
            facts = json.load(handle)
        # Mirror the probe-removal counterexample: a CPU vanishes from
        # the staged facts and the rebase must move both lock copies.
        facts["bpf_cpus"] = ["v4"]
        facts["version"] = "21.1.9"
        with open(facts_path, "w", encoding="utf-8") as handle:
            json.dump(facts, handle, indent=2, sort_keys=True)
            handle.write("\n")
        with open(fixture.lock_path, "r", encoding="utf-8") as handle:
            lock = json.load(handle)
        delta = uc.verify_staging(fixture.sources, lock, rebase=True)
        assert any("llvm facts" in line for line in delta), delta
        assert any("sources/llvm-toolchain facts" in line
                   for line in delta), delta
        assert any("sources/llvm-toolchain version" in line
                   for line in delta), delta
        assert lock["llvm"]["facts"]["bpf_cpus"] == ["v4"]
        mirror = lock["sources"][0]
        assert mirror["facts"]["bpf_cpus"] == ["v4"]
        assert mirror["facts"] == lock["llvm"]["facts"]
        assert mirror["version"] == "21.1.9"
        assert uc.verify_staging(fixture.sources, lock) == []


def test_llvm_mirror_incoherence_fails_verify():
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        _fixture_lock_with_toolchain_mirror(fixture)
        with open(fixture.lock_path, "r", encoding="utf-8") as handle:
            lock = json.load(handle)
        lock["sources"][0]["facts"]["bpf_cpus"] = ["v3", "probe"]
        try:
            uc.verify_staging(fixture.sources, lock)
        except uc.InventoryError as exc:
            assert exc.status == uc.EXIT_INTEGRITY
            assert "incoherent" in str(exc), exc
        else:
            raise AssertionError("expected InventoryError")
        with open(fixture.lock_path, "r", encoding="utf-8") as handle:
            lock = json.load(handle)
        lock["sources"][0]["version"] = "0.0.0"
        try:
            uc.verify_staging(fixture.sources, lock)
        except uc.InventoryError as exc:
            assert exc.status == uc.EXIT_INTEGRITY
        else:
            raise AssertionError("expected InventoryError")


def test_llvm_mirror_incoherence_fails_extraction():
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        with open(fixture.lock_path, "r", encoding="utf-8") as handle:
            lock = json.load(handle)
        lock["sources"] = [{
            "id": "llvm-toolchain",
            "version": FIXTURE_FACTS["version"],
            "facts": dict(FIXTURE_FACTS, bpf_cpus=["v9"]),
        }]
        with open(fixture.lock_path, "w", encoding="utf-8") as handle:
            json.dump(lock, handle, indent=2, sort_keys=True)
        expect_inventory_error(fixture.extract, uc.EXIT_INTEGRITY)


def test_export_rejects_invalid_registry():
    registry = mutated_registry()
    for item in registry["enum_members"]:
        if item["name"] == "BPF_PROG_TYPE_XDP":
            item["value"] = 999
    status, _ = _export_copy(registry, load_lock())
    assert status == uc.EXIT_INVALID


def test_export_rejects_binding_mismatch():
    lock = json.loads(json.dumps(load_lock()))
    lock["published"]["records"] += 1
    status, _ = _export_copy(load_registry(), lock)
    assert status == uc.EXIT_INVALID


def test_export_writes_nothing_on_failure():
    import argparse
    with tempfile.TemporaryDirectory() as tmp:
        registry = mutated_registry()
        registry["records"] = []
        registry_path = os.path.join(tmp, "registry.json")
        with open(registry_path, "w", encoding="utf-8") as handle:
            handle.write(uc.dump_canonical(registry))
        out = os.path.join(tmp, "bundle")
        args = argparse.Namespace(registry=registry_path,
                                  schema=SCHEMA_PATH, out=out,
                                  root=ROOT, lock=LOCK_PATH)
        assert uc.cmd_export(args) == uc.EXIT_INVALID
        assert not os.path.exists(out)


def test_kfunc_id_set_parser_captures_filters():
    text = (
        "static const struct btf_kfunc_id_set plain_set = {\n"
        "\t.owner = THIS_MODULE,\n"
        "\t.set = &plain_ids,\n"
        "};\n"
        "static const struct btf_kfunc_id_set guarded_set = {\n"
        "\t.owner = THIS_MODULE,\n"
        "\t.set = &guarded_ids,\n"
        "\t.filter = guard_filter,\n"
        "};\n"
    )
    assert uc.parse_kfunc_id_sets(text) == [
        ("plain_set", "plain_ids", None),
        ("guarded_set", "guarded_ids", "guard_filter"),
    ]


def test_kfunc_filters_narrow_callability():
    registry = load_registry()
    records = {entry["id"]: entry for entry in registry["records"]}
    sock = records["kfunc:bpf_sock_destroy"]
    assert sock["attach_types"] == ["BPF_TRACE_ITER"]
    assert sock["helpers_or_kfuncs"][0]["callable"] is True
    iters = [line for line in sock["callable_context_predicates"]
             if "BPF_TRACE_ITER" in line]
    assert len(iters) == 3, iters
    assert any(line.endswith("#tracing_iter_filter")
               for line in sock["kernel_registration_refs"])
    cookie = records["kfunc:bpf_session_cookie"]
    assert cookie["attach_types"] == [
        "BPF_TRACE_FSESSION", "BPF_TRACE_FSESSION_MULTI",
        "BPF_TRACE_KPROBE_SESSION", "BPF_TRACE_UPROBE_SESSION"]
    exe = records["kfunc:bpf_get_task_exe_file"]
    assert exe["attach_types"] == []
    for line in exe["callable_context_predicates"]:
        if line.startswith("callable from"):
            assert line.startswith(
                "callable from BPF_PROG_TYPE_LSM "), line
    bstats = records["kfunc:bpf_qdisc_bstats_update"]
    assert any("bpf_Qdisc_ops" in line
               for line in bstats["callable_context_predicates"])
    assert any("DEQUEUE" in line
               for line in bstats["callable_context_predicates"])
    hidden = records["kfunc:bpf_qdisc_init_prologue"]
    assert hidden["helpers_or_kfuncs"][0]["callable"] is False
    assert "its filter denies all contexts" in \
        hidden["applicability_predicate"]
    # Filtered kfuncs keep their registration refs, including filters.
    for rid in ("kfunc:bpf_sock_destroy", "kfunc:bpf_session_cookie",
                "kfunc:bpf_get_task_exe_file",
                "kfunc:bpf_qdisc_bstats_update"):
        refs = records[rid]["kernel_registration_refs"]
        assert any("#" in ref for ref in refs), rid


def test_fixture_deny_all_filter_yields_uncallable():
    extra = """\
BTF_KFUNCS_START(denied_kfunc_ids)
BTF_ID(func, bpf_fixture_denied)
BTF_KFUNCS_END(denied_kfunc_ids)

static int deny_all_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
\treturn -EACCES;
}

static const struct btf_kfunc_id_set denied_kfunc_set = {
\t.owner = THIS_MODULE,
\t.set = &denied_kfunc_ids,
\t.filter = deny_all_filter,
};

static int __init denied_kfunc_init(void)
{
\treturn register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &denied_kfunc_set);
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        staged = os.path.join(fixture.sources, "linux", "v1",
                              "kernel", "bpf", "test_proto.c")
        with open(staged, "a", encoding="utf-8") as handle:
            handle.write(extra)
        fixture.repin()
        _, _, registry = fixture.extract()
        denied = next(entry for entry in registry["records"]
                      if entry["id"] == "kfunc:bpf_fixture_denied")
        assert denied["helpers_or_kfuncs"][0]["callable"] is False
        assert ("registration filter denies all contexts (v1)"
                in denied["callable_context_predicates"])
        assert "its filter denies all contexts" in \
            denied["applicability_predicate"]


def test_fixture_dangling_filter_fails():
    extra = """\
BTF_KFUNCS_START(dangling_kfunc_ids)
BTF_ID(func, bpf_fixture_dangling)
BTF_KFUNCS_END(dangling_kfunc_ids)

static const struct btf_kfunc_id_set dangling_kfunc_set = {
\t.owner = THIS_MODULE,
\t.set = &dangling_kfunc_ids,
\t.filter = no_such_filter,
};

static int __init dangling_kfunc_init(void)
{
\treturn register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
\t\t\t\t\t &dangling_kfunc_set);
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        staged = os.path.join(fixture.sources, "linux", "v1",
                              "kernel", "bpf", "test_proto.c")
        with open(staged, "a", encoding="utf-8") as handle:
            handle.write(extra)
        fixture.repin()
        expect_inventory_error(fixture.extract, uc.EXIT_UNKNOWN)


def test_fixture_opaque_denying_filter_denies_and_flags():
    # Default-deny: a filter outside the understood grammar yields no
    # permission and flags its records for owner review instead of
    # aborting the inventory. The flagged record fails completeness
    # until an owner extends the grammar and tests.
    extra = """\
BTF_KFUNCS_START(mystery_kfunc_ids)
BTF_ID(func, bpf_fixture_mystery)
BTF_KFUNCS_END(mystery_kfunc_ids)

static int mystery_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
\tif (mystery_check(prog))
\t\treturn -EACCES;
\treturn 0;
}

static const struct btf_kfunc_id_set mystery_kfunc_set = {
\t.owner = THIS_MODULE,
\t.set = &mystery_kfunc_ids,
\t.filter = mystery_filter,
};

static int __init mystery_kfunc_init(void)
{
\treturn register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &mystery_kfunc_set);
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        staged = os.path.join(fixture.sources, "linux", "v1",
                              "kernel", "bpf", "test_proto.c")
        with open(staged, "a", encoding="utf-8") as handle:
            handle.write(extra)
        fixture.repin()
        _, _, registry = fixture.extract()
        mystery = next(entry for entry in registry["records"]
                       if entry["id"] == "kfunc:bpf_fixture_mystery")
        assert mystery["helpers_or_kfuncs"][0]["callable"] is False
        assert mystery["needs_owner_review"] == [
            "filter mystery_filter (v1): kfunc filter "
            "mystery_filter@v1 denies on an unrecognized condition "
            "'mystery_check ( prog )'; cannot scope the denial"]
        assert any(line.startswith("NEEDS-OWNER: filter mystery_filter")
                   for line in mystery["callable_context_predicates"])
        assert "default-deny" in mystery["applicability_predicate"]
        assert any("linux:kernel/bpf/test_proto.c@v1#mystery_filter" in ref
                   for ref in mystery["kernel_registration_refs"])
        errors = uc.check_completeness(registry)
        assert any("kfunc:bpf_fixture_mystery: needs owner review" in line
                   for line in errors), errors


def test_kfunc_filter_simulator_shapes():
    texts = {"kernel/bpf/shapes.c": uc.strip_comments(
        "static int type_guard(const struct bpf_prog *prog, u32 id)\n"
        "{\n"
        "\tif (prog->type == BPF_PROG_TYPE_XDP) {\n"
        "\t\treturn 0;\n"
        "\t}\n"
        "\treturn -EACCES;\n"
        "}\n"
        "static int deny_all(const struct bpf_prog *prog, u32 id)\n"
        "{\n"
        "\treturn -EACCES;\n"
        "}\n"
    )}
    membersets = {"shape_ids": {"bpf_shape_fn"}}
    verdict = uc.simulate_kfunc_filter(
        "type_guard", texts, "v9", ["bpf_shape_fn"], membersets,
        ["BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_LSM"])
    assert verdict["bpf_shape_fn"]["types"] == {"BPF_PROG_TYPE_XDP"}
    verdict = uc.simulate_kfunc_filter(
        "deny_all", texts, "v9", ["bpf_shape_fn"], membersets,
        ["BPF_PROG_TYPE_XDP"])
    assert verdict["bpf_shape_fn"]["types"] == set()
    wider = {"kernel/bpf/wider.c": uc.strip_comments(
        "static int multi(const struct bpf_prog *prog, u32 id)\n"
        "{\n"
        "\tif (prog->expected_attach_type == BPF_TRACE_FSESSION)\n"
        "\t\treturn 0;\n"
        "\tif (prog->expected_attach_type == BPF_TRACE_KPROBE_SESSION)\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n"
        "}\n"
        "static int contra(const struct bpf_prog *prog, u32 id)\n"
        "{\n"
        "\tif (prog->expected_attach_type != BPF_TRACE_FSESSION)\n"
        "\t\treturn -EACCES;\n"
        "\tif (prog->expected_attach_type != BPF_TRACE_KPROBE_SESSION)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n"
        "}\n"
        "static int tern(const struct bpf_prog *prog, u32 id)\n"
        "{\n"
        "\treturn (prog->type == BPF_PROG_TYPE_XDP) ? 0 : -EACCES;\n"
        "}\n"
    )}
    verdict = uc.simulate_kfunc_filter(
        "multi", wider, "v9", ["bpf_shape_fn"], membersets,
        ["BPF_PROG_TYPE_TRACING"])
    assert verdict["bpf_shape_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["bpf_shape_fn"]["attach"] == {
        "BPF_TRACE_FSESSION", "BPF_TRACE_KPROBE_SESSION"}
    verdict = uc.simulate_kfunc_filter(
        "contra", wider, "v9", ["bpf_shape_fn"], membersets,
        ["BPF_PROG_TYPE_TRACING"])
    assert verdict["bpf_shape_fn"]["types"] == set()
    verdict = uc.simulate_kfunc_filter(
        "tern", wider, "v9", ["bpf_shape_fn"], membersets,
        ["BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_LSM"])
    assert verdict["bpf_shape_fn"]["types"] == {"BPF_PROG_TYPE_XDP"}


def test_kfunc_filter_nested_block_deny_is_not_skipped():
    texts = {"kernel/bpf/nested.c": uc.strip_comments(
        "static int nested_deny(const struct bpf_prog *prog, u32 id)\n"
        "{\n"
        "\t{ return -EACCES; }\n"
        "\treturn 0;\n"
        "}\n"
        "static int decl_block(const struct bpf_prog *prog, u32 id)\n"
        "{\n"
        "\t{ u32 aux = 1; (void)aux; }\n"
        "\treturn 0;\n"
        "}\n"
        "static int guarded_block(const struct bpf_prog *prog, u32 id)\n"
        "{\n"
        "\t{\n"
        "\t\tif (prog->type == BPF_PROG_TYPE_XDP)\n"
        "\t\t\treturn 0;\n"
        "\t\treturn -EACCES;\n"
        "\t}\n"
        "}\n"
    )}
    membersets = {"nested_ids": {"bpf_nested_fn"}}
    verdict = uc.simulate_kfunc_filter(
        "nested_deny", texts, "v9", ["bpf_nested_fn"], membersets,
        ["BPF_PROG_TYPE_XDP"])
    assert verdict["bpf_nested_fn"]["types"] == set()
    assert verdict["bpf_nested_fn"]["alternatives"] == []
    verdict = uc.simulate_kfunc_filter(
        "decl_block", texts, "v9", ["bpf_nested_fn"], membersets,
        ["BPF_PROG_TYPE_XDP"])
    assert verdict["bpf_nested_fn"]["types"] == {"BPF_PROG_TYPE_XDP"}
    verdict = uc.simulate_kfunc_filter(
        "guarded_block", texts, "v9", ["bpf_nested_fn"], membersets,
        ["BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_LSM"])
    assert verdict["bpf_nested_fn"]["types"] == {"BPF_PROG_TYPE_XDP"}


def test_kfunc_filter_or_alternatives_stay_distinct():
    texts = {"kernel/bpf/alt.c": uc.strip_comments(
        "static int either_iter(const struct bpf_prog *prog, u32 id)\n"
        "{\n"
        "\tif (prog->expected_attach_type == BPF_TRACE_ITER ||\n"
        "\t    prog->expected_attach_type == BPF_TRACE_FENTRY)\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n"
        "}\n"
        "static int multi(const struct bpf_prog *prog, u32 id)\n"
        "{\n"
        "\tif (prog->expected_attach_type == BPF_TRACE_FSESSION)\n"
        "\t\treturn 0;\n"
        "\tif (prog->expected_attach_type == BPF_TRACE_KPROBE_SESSION)\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n"
        "}\n"
    )}
    membersets = {"alt_ids": {"bpf_alt_fn"}}
    verdict = uc.simulate_kfunc_filter(
        "either_iter", texts, "v9", ["bpf_alt_fn"], membersets,
        ["BPF_PROG_TYPE_TRACING"])
    assert verdict["bpf_alt_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["bpf_alt_fn"]["attach"] == {
        "BPF_TRACE_ITER", "BPF_TRACE_FENTRY"}
    assert verdict["bpf_alt_fn"]["alternatives"] == [
        {"callers": ["BPF_PROG_TYPE_TRACING"],
         "attach": ["BPF_TRACE_FENTRY"], "stops": [],
         "notes": ["requires expected_attach_type BPF_TRACE_FENTRY"]},
        {"callers": ["BPF_PROG_TYPE_TRACING"],
         "attach": ["BPF_TRACE_ITER"], "stops": [],
         "notes": ["requires expected_attach_type BPF_TRACE_ITER"]},
    ]
    verdict = uc.simulate_kfunc_filter(
        "multi", texts, "v9", ["bpf_alt_fn"], membersets,
        ["BPF_PROG_TYPE_TRACING"])
    assert verdict["bpf_alt_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert len(verdict["bpf_alt_fn"]["alternatives"]) == 2


def test_kfunc_filter_caller_scope_stays_distinct():
    texts = {"kernel/bpf/scoped.c": uc.strip_comments(
        "static int scoped(const struct bpf_prog *prog, u32 id)\n"
        "{\n"
        "\tif (prog->type == BPF_PROG_TYPE_SYSCALL)\n"
        "\t\treturn 0;\n"
        "\tif (prog->type != BPF_PROG_TYPE_STRUCT_OPS)\n"
        "\t\treturn -EACCES;\n"
        "\tif (prog->expected_attach_type == BPF_TRACE_ITER)\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n"
        "}\n"
    )}
    membersets = {"scoped_ids": {"bpf_scoped_fn"}}
    verdict = uc.simulate_kfunc_filter(
        "scoped", texts, "v9", ["bpf_scoped_fn"], membersets,
        ["BPF_PROG_TYPE_SYSCALL", "BPF_PROG_TYPE_STRUCT_OPS",
         "BPF_PROG_TYPE_XDP"])
    assert verdict["bpf_scoped_fn"]["types"] == {
        "BPF_PROG_TYPE_SYSCALL", "BPF_PROG_TYPE_STRUCT_OPS"}
    assert verdict["bpf_scoped_fn"]["alternatives"] == [
        {"callers": ["BPF_PROG_TYPE_STRUCT_OPS"],
         "attach": ["BPF_TRACE_ITER"], "stops": [],
         "notes": ["requires expected_attach_type BPF_TRACE_ITER"]},
        {"callers": ["BPF_PROG_TYPE_SYSCALL"],
         "attach": [], "stops": [], "notes": []},
    ]


def test_fixture_hook_deny_filter_denies_unfiltered_set():
    extra = """\
BTF_KFUNCS_START(open_kfunc_ids)
BTF_ID(func, bpf_fixture_open)
BTF_KFUNCS_END(open_kfunc_ids)

static const struct btf_kfunc_id_set open_kfunc_set = {
\t.owner = THIS_MODULE,
\t.set = &open_kfunc_ids,
};

BTF_KFUNCS_START(shut_kfunc_ids)
BTF_ID(func, bpf_fixture_shut)
BTF_KFUNCS_END(shut_kfunc_ids)

static int shut_all_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
\treturn -EACCES;
}

static const struct btf_kfunc_id_set shut_kfunc_set = {
\t.owner = THIS_MODULE,
\t.set = &shut_kfunc_ids,
\t.filter = shut_all_filter,
};

static int __init hook_deny_init(void)
{
\tint ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
\t\t\t\t\t    &open_kfunc_set);
\treturn ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
\t\t\t\t\t\t&shut_kfunc_set);
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        staged = os.path.join(fixture.sources, "linux", "v1",
                              "kernel", "bpf", "test_proto.c")
        with open(staged, "a", encoding="utf-8") as handle:
            handle.write(extra)
        fixture.repin()
        _, _, registry = fixture.extract()
        records = {entry["id"]: entry for entry in registry["records"]}
        for rid in ("kfunc:bpf_fixture_open", "kfunc:bpf_fixture_shut"):
            assert records[rid]["helpers_or_kfuncs"][0]["callable"] \
                is False, rid
            assert ("registration filter denies all contexts (v1)"
                    in records[rid]["callable_context_predicates"]), rid


def test_fixture_hook_filters_conjoin_per_caller():
    extra = """\
BTF_KFUNCS_START(first_kfunc_ids)
BTF_ID(func, bpf_fixture_first)
BTF_ID(func, bpf_fixture_both)
BTF_KFUNCS_END(first_kfunc_ids)

static int first_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
\tif (!btf_id_set8_contains(&first_kfunc_ids, kfunc_id))
\t\treturn 0;
\tif (prog->expected_attach_type != BPF_TRACE_FENTRY)
\t\treturn -EACCES;
\treturn 0;
}

static const struct btf_kfunc_id_set first_kfunc_set = {
\t.owner = THIS_MODULE,
\t.set = &first_kfunc_ids,
\t.filter = first_filter,
};

BTF_KFUNCS_START(second_kfunc_ids)
BTF_ID(func, bpf_fixture_second)
BTF_ID(func, bpf_fixture_both)
BTF_KFUNCS_END(second_kfunc_ids)

static int second_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
\tif (!btf_id_set8_contains(&second_kfunc_ids, kfunc_id))
\t\treturn 0;
\tif (prog->expected_attach_type != BPF_TRACE_ITER)
\t\treturn -EACCES;
\treturn 0;
}

static const struct btf_kfunc_id_set second_kfunc_set = {
\t.owner = THIS_MODULE,
\t.set = &second_kfunc_ids,
\t.filter = second_filter,
};

static int __init hook_conjoin_init(void)
{
\tint ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
\t\t\t\t\t    &first_kfunc_set);
\treturn ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
\t\t\t\t\t\t&second_kfunc_set);
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        staged = os.path.join(fixture.sources, "linux", "v1",
                              "kernel", "bpf", "test_proto.c")
        with open(staged, "a", encoding="utf-8") as handle:
            handle.write(extra)
        fixture.repin()
        _, _, registry = fixture.extract()
        records = {entry["id"]: entry for entry in registry["records"]}
        first = records["kfunc:bpf_fixture_first"]
        assert first["helpers_or_kfuncs"][0]["callable"] is True
        assert first["attach_types"] == ["BPF_TRACE_FENTRY"]
        second = records["kfunc:bpf_fixture_second"]
        assert second["helpers_or_kfuncs"][0]["callable"] is True
        assert second["attach_types"] == ["BPF_TRACE_ITER"]
        both = records["kfunc:bpf_fixture_both"]
        assert both["helpers_or_kfuncs"][0]["callable"] is False
        assert ("registration filter denies all contexts (v1)"
                in both["callable_context_predicates"])


def _simulate_source(fn_name, body, members, membersets, callers):
    texts = {"kernel/bpf/probe.c": uc.strip_comments(
        "static int %s(const struct bpf_prog *prog, u32 kfunc_id)\n"
        "{\n%s\n}\n" % (fn_name, body))}
    return uc.simulate_kfunc_filter(
        fn_name, texts, "v9", list(members), membersets,
        list(callers))


def _expect_unrecognized(fn_name, body, fragment):
    try:
        _simulate_source(fn_name, body, ("probe_fn",),
                         {"probe_ids": {"probe_fn"}},
                         ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert fn_name in str(exc), exc
        assert fragment in str(exc), exc
    else:
        raise AssertionError(
            "expected FilterNotUnderstood for %s" % fn_name)


def _simulate_params(fn_name, params, body, members, membersets, callers):
    texts = {"kernel/bpf/probe.c": uc.strip_comments(
        "static int %s(%s)\n{\n%s\n}\n" % (fn_name, params, body))}
    return uc.simulate_kfunc_filter(
        fn_name, texts, "v9", list(members), membersets,
        list(callers))


def _expect_unrecognized_params(fn_name, params, body, members,
                                membersets, fragment):
    try:
        _simulate_params(fn_name, params, body, members, membersets,
                         ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert fn_name in str(exc), exc
        assert fragment in str(exc), exc
    else:
        raise AssertionError(
            "expected FilterNotUnderstood for %s" % fn_name)


def _simulate_header(fn_name, header, body, members, membersets, callers):
    texts = {"kernel/bpf/probe.c": uc.strip_comments(
        "%s\nstatic int %s(const struct bpf_prog *prog, u32 kfunc_id)\n"
        "{\n%s\n}\n" % (header, fn_name, body))}
    return uc.simulate_kfunc_filter(
        fn_name, texts, "v9", list(members), membersets,
        list(callers))


def _simulate_typed(fn_name, rettype, params, body, members, membersets,
                    callers):
    texts = {"kernel/bpf/probe.c": uc.strip_comments(
        "static %s %s(%s)\n{\n%s\n}\n"
        % (rettype, fn_name, params, body))}
    return uc.simulate_kfunc_filter(
        fn_name, texts, "v9", list(members), membersets,
        list(callers))


def _simulate_values(fn_name, body, members, membersets, callers, values):
    texts = {"kernel/bpf/probe.c": uc.strip_comments(
        "static int %s(const struct bpf_prog *prog, u32 kfunc_id)\n"
        "{\n%s\n}\n" % (fn_name, body))}
    return uc.simulate_kfunc_filter(
        fn_name, texts, "v9", list(members), membersets,
        list(callers), const_values=dict(values))


def _simulate_files(fn_name, files, members, membersets, callers):
    texts = {relpath: uc.strip_comments(text)
             for relpath, text in files.items()}
    return uc.simulate_kfunc_filter(
        fn_name, texts, "v9", list(members), membersets,
        list(callers))


def test_filter_grammar_is_documented():
    grammar = uc.FILTER_BODY_GRAMMAR
    assert "simulate_kfunc_filter" in grammar
    for token in ("Statements", "Returns", "Conditions",
                  "Evaluation", "outside the grammar",
                  "opaque", "exclusion", "default-deny",
                  "needs-owner", "NEEDS-OWNER"):
        assert token in grammar, token


def test_kfunc_filter_final_allow_keeps_earlier_grants():
    verdict = _simulate_source(
        "keep_grants",
        "\tif (prog->expected_attach_type == BPF_TRACE_ITER)\n"
        "\t\treturn 0;\n"
        "\tif (prog->expected_attach_type != BPF_TRACE_FENTRY)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["attach"] == {
        "BPF_TRACE_ITER", "BPF_TRACE_FENTRY"}
    assert verdict["probe_fn"]["alternatives"] == [
        {"callers": ["BPF_PROG_TYPE_TRACING"],
         "attach": ["BPF_TRACE_FENTRY"], "stops": [],
         "notes": ["requires expected_attach_type BPF_TRACE_FENTRY"]},
        {"callers": ["BPF_PROG_TYPE_TRACING"],
         "attach": ["BPF_TRACE_ITER"], "stops": [],
         "notes": ["requires expected_attach_type BPF_TRACE_ITER"]},
    ]


def test_kfunc_filter_unbraced_nesting_is_flagged():
    _expect_unrecognized(
        "nested_unbraced",
        "\tif (prog->type == BPF_PROG_TYPE_TRACING)\n"
        "\t\tif (prog->expected_attach_type != BPF_TRACE_ITER)\n"
        "\t\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        "non-return branch")
    _expect_unrecognized(
        "nested_braced",
        "\tif (prog->type == BPF_PROG_TYPE_TRACING) {\n"
        "\t\tif (prog->expected_attach_type != BPF_TRACE_ITER)\n"
        "\t\t\treturn -EACCES;\n"
        "\t}\n"
        "\treturn 0;\n",
        "complex branch")
    _expect_unrecognized(
        "guarded_call",
        "\tif (prog->type == BPF_PROG_TYPE_TRACING)\n"
        "\t\ttrace_probe(prog);\n"
        "\treturn 0;\n",
        "non-return branch")


def test_kfunc_filter_correlated_deny_alternatives_stay_distinct():
    verdict = _simulate_source(
        "either_context",
        "\tif (prog->expected_attach_type != BPF_TRACE_ITER &&\n"
        "\t    prog->aux->st_ops != &bpf_sched_ext_ops)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["alternatives"] == [
        {"callers": ["BPF_PROG_TYPE_TRACING"],
         "attach": [], "stops": ["bpf_sched_ext_ops"],
         "notes": ["requires struct_ops attachment to "
                   "bpf_sched_ext_ops"]},
        {"callers": ["BPF_PROG_TYPE_TRACING"],
         "attach": ["BPF_TRACE_ITER"], "stops": [],
         "notes": ["requires expected_attach_type BPF_TRACE_ITER"]},
    ]


def test_kfunc_filter_contradictions_deny():
    verdict = _simulate_source(
        "self_denying",
        "\tif (prog->expected_attach_type == BPF_TRACE_ITER)\n"
        "\t\treturn -EACCES;\n"
        "\tif (prog->expected_attach_type == BPF_TRACE_ITER)\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # A requirement set that merely overlaps the exclusions stays
    # satisfiable: it means the remaining values.
    verdict = _simulate_source(
        "narrowed_ops",
        "\tif (prog->aux->st_ops != &first_ops &&\n"
        "\t    prog->aux->st_ops != &second_ops)\n"
        "\t\treturn -EACCES;\n"
        "\tif (prog->aux->st_ops == &second_ops)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_alias_mutation_is_flagged():
    _expect_unrecognized(
        "alias_reassign",
        "\tbool in_probe = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tin_probe = false;\n"
        "\tif (!in_probe)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        "reassigns membership alias")
    _expect_unrecognized(
        "alias_shadow",
        "\tbool in_probe = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\t{ bool in_probe = false; (void)in_probe; }\n"
        "\tif (!in_probe)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        "redeclares membership alias")
    _expect_unrecognized(
        "alias_compound",
        "\tbool in_probe = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tin_probe &= false;\n"
        "\tif (!in_probe)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        "mutates membership alias")
    _expect_unrecognized(
        "alias_address",
        "\tbool in_probe = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tcheck_probe(&in_probe);\n"
        "\tif (!in_probe)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        "address of membership alias")
    _expect_unrecognized(
        "param_reassign",
        "\tkfunc_id = 0;\n"
        "\tif (!btf_id_set8_contains(&probe_ids, kfunc_id))\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        "reassigns parameter")


def test_kfunc_filter_numeric_constants_fold():
    verdict = _simulate_source(
        "zero_grant",
        "\tif (0)\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_source(
        "one_deny",
        "\tif (1)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_source(
        "zero_deny",
        "\tif (0)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "negated_zero_deny",
        "\tif (!0)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_source(
        "suffixed_zero_deny",
        "\tif (0UL)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "hex_nonzero_grant",
        "\tif (0x1)\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_id_param_name_is_general():
    texts = {"kernel/bpf/names.c": uc.strip_comments(
        "static int renamed(const struct bpf_prog *p, u32 id)\n"
        "{\n"
        "\tbool in_probe = btf_id_set8_contains(&probe_ids, id);\n"
        "\tif (!in_probe)\n"
        "\t\treturn 0;\n"
        "\tif (p->expected_attach_type != BPF_TRACE_ITER)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n"
        "}\n"
        "static int wrong_arg(const struct bpf_prog *p, u32 id)\n"
        "{\n"
        "\tif (!btf_id_set8_contains(&probe_ids, other))\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n"
        "}\n"
    )}
    membersets = {"probe_ids": {"probe_fn"}}
    verdict = uc.simulate_kfunc_filter(
        "renamed", texts, "v9", ["probe_fn"], membersets,
        ["BPF_PROG_TYPE_TRACING"])
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["attach"] == {"BPF_TRACE_ITER"}
    try:
        uc.simulate_kfunc_filter(
            "wrong_arg", texts, "v9", ["probe_fn"], membersets,
            ["BPF_PROG_TYPE_TRACING"])
    except uc.FilterNotUnderstood:
        pass
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_opaque_negation_polarity():
    verdict = _simulate_source(
        "flag_clear",
        "\tif (!(flags & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    btf_id_set8_contains(&probe_ids, kfunc_id))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    notes = verdict["probe_fn"]["alternatives"][0]["notes"]
    assert notes == ["excludes SCX_KF_ALLOW_DISPATCH attach context "
                     "(via flag_clear)"]
    verdict = _simulate_source(
        "flag_set",
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    btf_id_set8_contains(&probe_ids, kfunc_id))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    notes = verdict["probe_fn"]["alternatives"][0]["notes"]
    assert notes == ["requires SCX_KF_ALLOW_DISPATCH attach context "
                     "(via flag_set)"]


def test_kfunc_filter_parenthesized_alias_mutation_is_flagged():
    # Round 5, item 1 (exact counterexample): a parenthesized
    # mutation target bypassed the alias-immutability check, granting
    # members a permission C always denies.
    _expect_unrecognized_params(
        "paren_mutate", "const struct bpf_prog *prog, u32 id",
        "\tbool mine = btf_id_set8_contains(&set_ids, id);\n"
        "\t(mine) = false;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        ("member_fn",), {"set_ids": {"member_fn"}},
        "reassigns membership alias")
    _expect_unrecognized_params(
        "paren_mutate_nested", "const struct bpf_prog *prog, u32 id",
        "\tbool mine = btf_id_set8_contains(&set_ids, id);\n"
        "\t((mine)) = false;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        ("member_fn",), {"set_ids": {"member_fn"}},
        "reassigns membership alias")
    _expect_unrecognized_params(
        "paren_mutate_spaced", "const struct bpf_prog *prog, u32 id",
        "\tbool mine = btf_id_set8_contains(&set_ids, id);\n"
        "\t( mine ) = false;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        ("member_fn",), {"set_ids": {"member_fn"}},
        "reassigns membership alias")
    _expect_unrecognized_params(
        "paren_mutate_compound", "const struct bpf_prog *prog, u32 id",
        "\tbool mine = btf_id_set8_contains(&set_ids, id);\n"
        "\t(mine) &= false;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        ("member_fn",), {"set_ids": {"member_fn"}},
        "mutates membership alias")
    _expect_unrecognized(
        "paren_param_reassign",
        "\t(kfunc_id) = 0;\n"
        "\tif (!btf_id_set8_contains(&probe_ids, kfunc_id))\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        "reassigns parameter")
    _expect_unrecognized(
        "paren_alias_address",
        "\tbool in_probe = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tcheck_probe(&(in_probe));\n"
        "\tif (!in_probe)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        "address of membership alias")
    # A cast-shaped wrapper around the assignment is still the same
    # mutation of the same target.
    _expect_unrecognized(
        "paren_mutate_cast_void",
        "\tbool in_probe = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\t(void)(in_probe = false);\n"
        "\tif (in_probe)\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        "reassigns membership alias")


def test_kfunc_filter_compound_alias_initializer_is_flagged():
    # Round 5, item 2 (exact counterexample): an initializer prefix
    # was accepted as an ordinary membership alias, granting members
    # a permission C always denies.
    _expect_unrecognized_params(
        "compound_init", "const struct bpf_prog *prog, u32 id",
        "\tbool mine = btf_id_set8_contains(&set_ids, id) && false;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        ("member_fn",), {"set_ids": {"member_fn"}},
        "compound membership initializer")
    _expect_unrecognized(
        "compound_init_or",
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id)"
        " || true;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "compound membership initializer")
    _expect_unrecognized(
        "compound_init_cmp",
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id)"
        " == true;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "compound membership initializer")
    _expect_unrecognized(
        "compound_init_wrapped",
        "\tbool mine = (btf_id_set8_contains(&probe_ids, kfunc_id));\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "compound membership initializer")
    _expect_unrecognized(
        "compound_init_negated",
        "\tbool mine = !btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "compound membership initializer")
    # A bare membership call stays an ordinary alias when it shares
    # its declaration with other declarators (round 6, item 2: full
    # declarator-list support with per-declarator anchoring).
    verdict = _simulate_source(
        "compound_init_multi",
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id),"
        " other = true;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["alternatives"] == [
        {"callers": ["BPF_PROG_TYPE_TRACING"],
         "attach": [], "stops": [], "notes": []},
    ]


def test_kfunc_filter_opaque_flag_contradictions_deny():
    # Round 5, item 3 (exact counterexample): a flag required and
    # excluded in one conjunction stayed callable.
    verdict = _simulate_source(
        "flag_contra",
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    !(flags & SCX_KF_ALLOW_DISPATCH))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    verdict = _simulate_source(
        "flag_contra_reversed",
        "\tif (!(flags & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    (flags & SCX_KF_ALLOW_DISPATCH))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # Same flag with mirrored operand order is the same constraint.
    verdict = _simulate_source(
        "flag_contra_mirrored",
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    !(SCX_KF_ALLOW_DISPATCH & flags))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # A multi-const bit test contradicting its own negation.
    verdict = _simulate_source(
        "flag_contra_masked",
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH & SCX_KF_ALLOW_UNLOCKED)"
        " &&\n"
        "\t    !(flags & SCX_KF_ALLOW_DISPATCH &"
        " SCX_KF_ALLOW_UNLOCKED))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # Guards: satisfiable flag combinations must still grant.
    verdict = _simulate_source(
        "flag_tautology",
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH) ||\n"
        "\t    !(flags & SCX_KF_ALLOW_DISPATCH))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "flag_distinct",
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    (flags & SCX_KF_ALLOW_UNLOCKED))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "flag_repeated",
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    (flags & SCX_KF_ALLOW_DISPATCH))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_mixed_constant_bit_groups_fold():
    # Round 5, item 4 (exact counterexample): bit-test protection
    # swallowed a constant-false logical condition.
    verdict = _simulate_source(
        "const_false_bit",
        "\tif ((0 && flags & SCX_KF_ALLOW_DISPATCH)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    verdict = _simulate_source(
        "const_true_bit_deny",
        "\tif ((1 || flags & SCX_KF_ALLOW_DISPATCH))\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    verdict = _simulate_source(
        "const_false_bit_right",
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH && 0))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # A mixed group keeps its understood atom scoped per caller.
    verdict = _simulate_source(
        "mixed_bit_typed",
        "\tif ((prog->type == BPF_PROG_TYPE_TRACING &&\n"
        "\t     flags & SCX_KF_ALLOW_DISPATCH))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "mixed_bit_or_typed",
        "\tif ((0 && flags & SCX_KF_ALLOW_DISPATCH) ||\n"
        "\t    prog->type == BPF_PROG_TYPE_TRACING)\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # A lone & absorbing a literal zero always denies, however
    # symbolic the other side is.
    for tag, group in (("absorb_left", "(0 & flags)"),
                       ("absorb_right", "(flags & 0)"),
                       ("absorb_suffixed", "(flags & 0U)")):
        verdict = _simulate_source(
            "const_%s" % tag,
            "\tif (%s) return 0;\n"
            "\treturn -EACCES;\n" % group,
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
        assert verdict["probe_fn"]["types"] == set(), tag
        assert verdict["probe_fn"]["alternatives"] == [], tag
    # Pure integer-literal groups fold by value.
    verdict = _simulate_source(
        "const_lit_and",
        "\tif ((1 & 2)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_source(
        "const_lit_arith",
        "\tif ((4 / 2 & 1)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_source(
        "const_lit_nonzero",
        "\tif ((3 & 5)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING",
                                            "BPF_PROG_TYPE_XDP"}
    verdict = _simulate_source(
        "const_lit_negated",
        "\tif (!((3 & 5))) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # Absorption also applies per segment of a mixed group.
    verdict = _simulate_source(
        "mixed_bit_absorb",
        "\tif ((prog->type == BPF_PROG_TYPE_TRACING || flags & 0))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Guards: wraparound-sized values never fold, and a comma
    # defeats absorption (the group stays opaque, granting under
    # the pre-existing opaque-allow semantics).
    verdict = _simulate_source(
        "const_lit_wide",
        "\tif ((4294967295 & 4294967294)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "const_comma_stays",
        "\tif ((0 & flags, prog->type == BPF_PROG_TYPE_TRACING))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING",
                                            "BPF_PROG_TYPE_XDP"}


def test_kfunc_filter_mirrored_comparisons_permit():
    # Round 5, item 5 (exact counterexample): a documented mirrored
    # comparison was denied through the opaque path.
    verdict = _simulate_source(
        "mirror_attach_deny",
        "\tif (BPF_TRACE_ITER != prog->expected_attach_type)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["attach"] == {"BPF_TRACE_ITER"}
    assert verdict["probe_fn"]["alternatives"] == [
        {"callers": ["BPF_PROG_TYPE_TRACING"],
         "attach": ["BPF_TRACE_ITER"], "stops": [],
         "notes": ["requires expected_attach_type BPF_TRACE_ITER"]},
    ]
    verdict = _simulate_source(
        "mirror_attach_grant",
        "\tif (BPF_TRACE_ITER == prog->expected_attach_type)\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["attach"] == {"BPF_TRACE_ITER"}
    verdict = _simulate_source(
        "mirror_type_deny",
        "\tif (BPF_PROG_TYPE_TRACING != prog->type)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "mirror_attach_exclude",
        "\tif (BPF_TRACE_ITER == prog->expected_attach_type)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["attach"] == set()
    assert verdict["probe_fn"]["alternatives"] == [
        {"callers": ["BPF_PROG_TYPE_TRACING"],
         "attach": [], "stops": [],
         "notes": ["excludes expected_attach_type BPF_TRACE_ITER"]},
    ]
    # A mirrored struct_ops comparison is genuinely unsupported and
    # keeps its owner-review flag.
    _expect_unrecognized(
        "mirror_stops_deny",
        "\tif (&bpf_sched_ext_ops != prog->aux->st_ops)\n"
        "\t\treturn -EACCES;\n"
        "\treturn 0;\n",
        "unrecognized condition")
    # A mirrored comparison against a number stays an opaque atom.
    verdict = _simulate_source(
        "mirror_number_grant",
        "\tif (0 == prog->type)\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    notes = verdict["probe_fn"]["alternatives"][0]["notes"]
    assert notes and notes[0].startswith("additionally restricted"), \
        notes


def test_kfunc_filter_ternary_arms_classify_by_value():
    # Round 5, item 6 (exact counterexample): a zero-valued arm with
    # a suffix was misclassified as denying.
    verdict = _simulate_source(
        "ternary_zero_u",
        "\treturn (false) ? 0 : 0U;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["alternatives"] == [
        {"callers": ["BPF_PROG_TYPE_TRACING"],
         "attach": [], "stops": [], "notes": []},
    ]
    verdict = _simulate_source(
        "ternary_both_deny",
        "\treturn (prog->type == BPF_PROG_TYPE_TRACING) ? -EACCES : 1;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    verdict = _simulate_source(
        "ternary_zero_u_arm",
        "\treturn (prog->type == BPF_PROG_TYPE_TRACING) ? 0U : -EPERM;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "ternary_both_zero",
        "\treturn (prog->type == BPF_PROG_TYPE_XDP) ? 0 : 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "ternary_allow_second",
        "\treturn (prog->expected_attach_type == BPF_TRACE_ITER)"
        " ? -EACCES : 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["attach"] == set()
    assert verdict["probe_fn"]["alternatives"] == [
        {"callers": ["BPF_PROG_TYPE_TRACING"],
         "attach": [], "stops": [],
         "notes": ["excludes expected_attach_type BPF_TRACE_ITER"]},
    ]
    # Non-constant arms are explicitly rejected, never silently
    # classified.
    _expect_unrecognized(
        "ternary_call_arm",
        "\treturn (prog->type == BPF_PROG_TYPE_TRACING)"
        " ? 0 : pick_default();\n",
        "non-constant arm")
    _expect_unrecognized(
        "ternary_ident_arm",
        "\treturn (false) ? status : -EACCES;\n",
        "non-constant arm")


def test_kfunc_filter_typedef_named_alias_mutation_is_flagged():
    # Round 6, item 1 (exact counterexamples): a parenthesized name
    # bound as a local alias is never a cast, even when it spells a
    # typedef. Compiled C always denies members in both cases.
    _expect_unrecognized_params(
        "typedef_alias_mutate", "const struct bpf_prog *prog, u32 id",
        "\tbool u64 = btf_id_set8_contains(&set_ids, id);\n"
        "\t(u64) = false;\n"
        "\tif (u64) return 0;\n"
        "\treturn -EACCES;\n",
        ("member_fn",), {"set_ids": {"member_fn"}},
        "reassigns membership alias")
    _expect_unrecognized_params(
        "typedef_alias_compound", "const struct bpf_prog *prog, u32 id",
        "\tbool size_t = btf_id_set8_contains(&set_ids, id);\n"
        "\t((size_t)) &= false;\n"
        "\tif (size_t) return 0;\n"
        "\treturn -EACCES;\n",
        ("member_fn",), {"set_ids": {"member_fn"}},
        "mutates membership alias")
    _expect_unrecognized_params(
        "typedef_alias_or", "const struct bpf_prog *prog, u32 id",
        "\tbool u32 = btf_id_set8_contains(&set_ids, id);\n"
        "\t(u32) |= true;\n"
        "\tif (u32) return 0;\n"
        "\treturn -EACCES;\n",
        ("member_fn",), {"set_ids": {"member_fn"}},
        "mutates membership alias")
    _expect_unrecognized_params(
        "typedef_alias_addr", "const struct bpf_prog *prog, u32 id",
        "\tbool u64 = btf_id_set8_contains(&set_ids, id);\n"
        "\tcheck_probe(&(u64));\n"
        "\tif (u64) return 0;\n"
        "\treturn -EACCES;\n",
        ("member_fn",), {"set_ids": {"member_fn"}},
        "address of membership alias")
    _expect_unrecognized_params(
        "typedef_alias_incr", "const struct bpf_prog *prog, u32 id",
        "\tbool u64 = btf_id_set8_contains(&set_ids, id);\n"
        "\t++(u64);\n"
        "\tif (u64) return 0;\n"
        "\treturn -EACCES;\n",
        ("member_fn",), {"set_ids": {"member_fn"}},
        "mutates membership alias")
    _expect_unrecognized_params(
        "typedef_param_reassign", "const struct bpf_prog *prog, u32 u64",
        "\tbool mine = btf_id_set8_contains(&set_ids, u64);\n"
        "\t(u64) = 0;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        ("member_fn",), {"set_ids": {"member_fn"}},
        "reassigns parameter")
    # A genuine cast of an unrelated operand still strips: the alias
    # mutation underneath is flagged, not hidden.
    _expect_unrecognized(
        "typedef_alias_cast_value",
        "\tbool in_probe = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tin_probe = (u64)0;\n"
        "\tif (in_probe)\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        "reassigns membership alias")
    _expect_unrecognized(
        "paren_alias_postfix",
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\t(mine)++;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "mutates membership alias")
    # A cast in read position is not a mutation.
    verdict = _simulate_source(
        "typedef_alias_cast_read",
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tu32 rank = (u32)mine;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_declarator_list_initializers_are_checked():
    # Round 6, item 2 (exact counterexamples): compound membership
    # initializers hide in comma declarators and behind attributes.
    # Compiled C always denies members in both cases.
    _expect_unrecognized_params(
        "comma_compound_init", "const struct bpf_prog *prog, u32 id",
        "\tbool unused, mine = btf_id_set8_contains(&set_ids, id)"
        " && false;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        ("member_fn",), {"set_ids": {"member_fn"}},
        "compound membership initializer")
    _expect_unrecognized_params(
        "attr_compound_init", "const struct bpf_prog *prog, u32 id",
        "\tbool mine __attribute__((unused)) = "
        "btf_id_set8_contains(&set_ids, id) && false;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        ("member_fn",), {"set_ids": {"member_fn"}},
        "compound membership initializer")
    _expect_unrecognized(
        "comma_negated_init",
        "\tbool seen = true, mine ="
        " !btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "compound membership initializer")
    _expect_unrecognized(
        "attr_prefix_compound_init",
        "\tbool __attribute__((unused)) mine ="
        " btf_id_set8_contains(&probe_ids, kfunc_id) || true;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "compound membership initializer")
    _expect_unrecognized(
        "paren_comma_compound_init",
        "\tbool (mine) = btf_id_set8_contains(&probe_ids, kfunc_id)"
        " && false, other = true;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "compound membership initializer")
    # Bare calls in the same shapes stay ordinary aliases.
    verdict = _simulate_params(
        "comma_bare_alias", "const struct bpf_prog *prog, u32 id",
        "\tbool unused, mine = btf_id_set8_contains(&set_ids, id);\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        ("member_fn",), {"set_ids": {"member_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["member_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_params(
        "attr_bare_alias", "const struct bpf_prog *prog, u32 id",
        "\tbool mine __attribute__((unused)) ="
        " btf_id_set8_contains(&set_ids, id);\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        ("member_fn",), {"set_ids": {"member_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["member_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Non-identifier declarators without membership calls are
    # ignored, and string literals never declare aliases.
    verdict = _simulate_source(
        "comma_mixed_shapes",
        "\tbool *held = &flag, mine ="
        " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tnote(\"bool other = btf_id_set8_contains(&probe_ids,"
        " kfunc_id)\");\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_flag_constraints_keep_operand_identity():
    # Round 6, item 3 (exact counterexamples): independent operands
    # never contradict. Both conditions are satisfiable in C (for
    # example flags=F with other_flags=0), so both grant.
    verdict = _simulate_source(
        "flag_distinct_operands",
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    !(other_flags & SCX_KF_ALLOW_DISPATCH))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "flag_shifted_operand",
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    !(flags >> 1 & SCX_KF_ALLOW_DISPATCH))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Further satisfiable combinations keep granting.
    verdict = _simulate_source(
        "flag_two_operands_same_polarity",
        "\tif ((ready & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    (flags & SCX_KF_ALLOW_DISPATCH))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "flag_masked_negation",
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    !(flags & SCX_KF_ALLOW_DISPATCH &"
        " SCX_KF_ALLOW_UNLOCKED))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Genuine same-operand contradictions still deny, however the
    # operand is spelled or spaced.
    verdict = _simulate_source(
        "flag_contra_spacing",
        "\tif ((flags&SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    !(flags & SCX_KF_ALLOW_DISPATCH))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    verdict = _simulate_source(
        "flag_contra_shifted",
        "\tif ((flags >> 1 & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    !(flags >> 1 & SCX_KF_ALLOW_DISPATCH))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []


def test_kfunc_filter_zero_absorption_requires_complete_and_chain():
    # Round 6, item 4 (exact counterexample): (0 & flags | F) folds
    # to F in C, so a deny on it is unprovable and fails closed.
    _expect_unrecognized(
        "absorb_prefix_or_deny",
        "\tif ((0 & flags | SCX_KF_ALLOW_DISPATCH)) return -EACCES;\n"
        "\treturn 0;\n",
        "unrecognized condition")
    # The XOR twin, as an allowing condition, grants in C (F is
    # nonzero) and must grant here rather than fold to false.
    verdict = _simulate_source(
        "absorb_prefix_xor_allow",
        "\tif ((0 & flags ^ SCX_KF_ALLOW_DISPATCH)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    notes = verdict["probe_fn"]["alternatives"][0]["notes"]
    assert notes == ["requires SCX_KF_ALLOW_DISPATCH attach context "
                     "(via absorb_prefix_xor_allow)"]
    # The OR twin, as an allowing condition, grants as well.
    verdict = _simulate_source(
        "absorb_prefix_or_allow",
        "\tif ((0 & flags | SCX_KF_ALLOW_DISPATCH)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Trailing-zero prefixes are equally unprovable.
    verdict = _simulate_source(
        "absorb_suffix_or_allow",
        "\tif ((flags & 0 | SCX_KF_ALLOW_DISPATCH)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Complete &-chains with a zero operand still fold: C proves
    # both of these are exactly zero.
    verdict = _simulate_source(
        "absorb_grouped_zero",
        "\tif ((0 & (flags | SCX_KF_ALLOW_DISPATCH))) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    verdict = _simulate_source(
        "absorb_compared_zero",
        "\tif ((0 & flags == 0)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # A zero in any operand position absorbs; a non-literal mask
    # such as ~0 never does.
    verdict = _simulate_source(
        "absorb_middle_zero",
        "\tif ((ready & 0 & flags)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    verdict = _simulate_source(
        "absorb_invert_no_fold",
        "\tif ((~0 & flags)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Bit tests over | and ^ are opaque atoms in their own right: a
    # folded zero feeding an OR grants existentially.
    verdict = _simulate_source(
        "bitor_folded_zero",
        "\tif (((0 & flags) | SCX_KF_ALLOW_DISPATCH)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "bitor_plain",
        "\tif ((flags | SCX_KF_ALLOW_DISPATCH)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "bitxor_plain",
        "\tif ((flags ^ SCX_KF_ALLOW_DISPATCH)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Same-spelling contradictions deny for | forms as for & forms.
    verdict = _simulate_source(
        "bitor_contra",
        "\tif ((ready | flags) && !(ready | flags)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []


def test_kfunc_filter_const_expr_uses_c_precedence():
    # Round 6, item 5 (exact counterexample): C parses
    # 1 & (2 == 0), which is 0, so the grant never fires.
    verdict = _simulate_source(
        "c_prec_exact",
        "\tif ((1 & 2 == 0)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # Each further case differs between C and Python precedence and
    # follows the compiled C value (see the round-6 C oracle).
    verdict = _simulate_source(
        "c_prec_or_eq",
        "\tif ((2 | 1 == 1)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "c_prec_zero_and_eq",
        "\tif ((0 & 5 == 0)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    verdict = _simulate_source(
        "c_prec_and_rel",
        "\tif ((3 & 5 < 4)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    verdict = _simulate_source(
        "c_prec_xor_eq",
        "\tif ((3 ^ 2 == 0)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "c_prec_and_ne",
        "\tif ((1 & 2 != 0)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_const_expr_wraps_unsigned_widths():
    # Round 6, item 6 (exact counterexample): 4294967295U + 1U wraps
    # to 0U in C, making the deny condition true for every caller.
    verdict = _simulate_source(
        "c_wrap_exact",
        "\tif ((4294967295U + 1U == 0U & 1U)) return -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # A wrapped zero never grants.
    verdict = _simulate_source(
        "c_wrap_zero_grant",
        "\tif ((4294967295U + 1U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # Unsigned subtraction compares wrapped, not unbounded.
    verdict = _simulate_source(
        "c_wrap_sub_cmp",
        "\tif ((0U - 1U == 4294967295U & 4294967295U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Unsigned multiplication wraps before the comparison.
    verdict = _simulate_source(
        "c_wrap_mul_cmp",
        "\tif ((65536U * 65536U == 0U & 1U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # UL keeps 64-bit width: no wraparound, the condition is false.
    verdict = _simulate_source(
        "c_wrap_ul_wide",
        "\tif ((4294967295UL + 1UL == 0UL & 1UL)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # ULL wraps at 64 bits.
    verdict = _simulate_source(
        "c_wrap_ull",
        "\tif ((18446744073709551615ULL + 1ULL == 0ULL & 1ULL))"
        " return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # The usual arithmetic conversions: a 64-bit signed type wins
    # over unsigned int (found by differential fuzzing vs gcc).
    verdict = _simulate_source(
        "c_wrap_usual",
        "\tif ((2U - 4294967296 < 0U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "c_wrap_usual_and",
        "\tif ((1L - 2U < 0 & 1)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_negated_arms_classify_by_pinned_value():
    # Round 6, item 7 (exact counterexample): BPF_PROG_TYPE_UNSPEC
    # is pinned to 0, so both arms return zero and every caller is
    # allowed. Classification is by value, never by textual shape.
    header = ("enum bpf_prog_type {\n"
              "\tBPF_PROG_TYPE_UNSPEC = 0,\n"
              "\tBPF_PROG_TYPE_SOCKET_FILTER = 1,\n"
              "\tBPF_PROG_TYPE_XDP = 6,\n"
              "};\n")
    verdict = _simulate_header(
        "neg_zero_enum",
        header,
        "\treturn (false) ? 0 : -BPF_PROG_TYPE_UNSPEC;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["alternatives"] == [
        {"callers": ["BPF_PROG_TYPE_TRACING"],
         "attach": [], "stops": [], "notes": []},
    ]
    # A pinned nonzero value still denies.
    verdict = _simulate_header(
        "neg_nonzero_enum",
        header,
        "\treturn (false) ? 0 : -BPF_PROG_TYPE_XDP;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # An unknown non-errno identifier cannot be classified by value
    # and fails closed instead of silently denying.
    _expect_unrecognized(
        "neg_unknown_ident",
        "\treturn (false) ? 0 : -SOME_FUTURE_FLAG;\n",
        "non-constant arm")
    # Positive identifiers resolve by value as well.
    verdict = _simulate_header(
        "pos_zero_enum",
        header,
        "\treturn (false) ? BPF_PROG_TYPE_UNSPEC : 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # A file-local object-like macro resolves by its value.
    verdict = _simulate_header(
        "neg_local_define",
        "#define ZERO_FLAG 0\n",
        "\treturn (false) ? 0 : -ZERO_FLAG;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Values threaded from the pipeline take the same path.
    verdict = _simulate_values(
        "neg_pinned_kwarg",
        "\treturn (false) ? 0 : -BPF_PROG_TYPE_UNSPEC;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",),
        {"BPF_PROG_TYPE_UNSPEC": 0})
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Kernel errno macros keep their documented deny meaning: the
    # pinned SCX filter returns -EACCES from ternary arms.
    verdict = _simulate_source(
        "neg_errno_still_denies",
        "\treturn (false) ? 0 : -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # Direct returns resolve by value the same way.
    verdict = _simulate_header(
        "neg_zero_direct",
        header,
        "\treturn -BPF_PROG_TYPE_UNSPEC;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # A local binding shadows every constant: dynamic values fail
    # closed instead of classifying as the shadowed macro.
    _expect_unrecognized(
        "neg_shadowed_errno",
        "\tu32 EACCES = 1;\n"
        "\treturn (false) ? 0 : -EACCES;\n",
        "non-constant arm")
    _expect_unrecognized(
        "neg_shadowed_pinned",
        "\tbool BPF_PROG_TYPE_XDP ="
        " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\treturn (prog->type == BPF_PROG_TYPE_TRACING) ? 0 :"
        " -BPF_PROG_TYPE_XDP;\n",
        "non-constant arm")
    # A positive unknown identifier is not provably anything.
    _expect_unrecognized(
        "pos_unknown_ident",
        "\treturn (false) ? EACCES : 0;\n",
        "non-constant arm")
    # A file-local name with two different values across files is
    # ambiguous and fails closed rather than guessing.
    try:
        _simulate_files(
            "neg_ambiguous",
            {"kernel/bpf/a.c": "#define AMBIG_FLAG 0\n",
             "kernel/bpf/b.c": "#define AMBIG_FLAG 5\n"
             "static int neg_ambiguous(const struct bpf_prog *prog,"
             " u32 kfunc_id)\n{\n"
             "\treturn (false) ? 0 : -AMBIG_FLAG;\n}\n"},
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "non-constant arm" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_arms_convert_to_return_type():
    # Round 6, item 8 (exact counterexample): 4294967296ULL converts
    # to 0 on the 32-bit int ABI, so every caller is allowed.
    verdict = _simulate_source(
        "conv_ull_zero",
        "\treturn (false) ? 0 : 4294967296ULL;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["alternatives"] == [
        {"callers": ["BPF_PROG_TYPE_TRACING"],
         "attach": [], "stops": [], "notes": []},
    ]
    # Neighboring values and direct returns convert the same way.
    verdict = _simulate_source(
        "conv_ull_one",
        "\treturn (false) ? 0 : 4294967297ULL;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    verdict = _simulate_source(
        "conv_direct_wrap",
        "\treturn 4294967296;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "conv_direct_neg_zero",
        "\treturn -0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "conv_neg_wrap_zero",
        "\treturn (false) ? 0 : -4294967296L;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "conv_hex_wrap_zero",
        "\treturn (false) ? 0 : 0x100000000ULL;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # The conversion follows the filter's actual return type: a long
    # filter keeps the value and denies.
    verdict = _simulate_typed(
        "conv_long_keeps",
        "long", "const struct bpf_prog *prog, u32 kfunc_id",
        "\treturn (false) ? 0 : 4294967296ULL;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # Parenthesized and boolean direct returns classify by value.
    verdict = _simulate_source(
        "conv_direct_paren",
        "\treturn (0);\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "conv_direct_bool",
        "\treturn false;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "conv_direct_true",
        "\treturn true;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # Non-integer return types are outside the grammar.
    try:
        _simulate_typed(
            "conv_ptr_rejected",
            "int *", "const struct bpf_prog *prog, u32 kfunc_id",
            "\treturn 0;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "non-integer return type" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_fixture_contradictory_hook_filters_deny():
    extra = """\
BTF_KFUNCS_START(require_kfunc_ids)
BTF_ID(func, bpf_fixture_clash)
BTF_KFUNCS_END(require_kfunc_ids)

static int require_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
\tif (!btf_id_set8_contains(&require_kfunc_ids, kfunc_id))
\t\treturn 0;
\tif (prog->expected_attach_type != BPF_TRACE_FENTRY)
\t\treturn -EACCES;
\treturn 0;
}

static const struct btf_kfunc_id_set require_kfunc_set = {
\t.owner = THIS_MODULE,
\t.set = &require_kfunc_ids,
\t.filter = require_filter,
};

BTF_KFUNCS_START(exclude_kfunc_ids)
BTF_ID(func, bpf_fixture_clash)
BTF_KFUNCS_END(exclude_kfunc_ids)

static int exclude_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
\tif (!btf_id_set8_contains(&exclude_kfunc_ids, kfunc_id))
\t\treturn 0;
\tif (prog->expected_attach_type == BPF_TRACE_FENTRY)
\t\treturn -EACCES;
\treturn 0;
}

static const struct btf_kfunc_id_set exclude_kfunc_set = {
\t.owner = THIS_MODULE,
\t.set = &exclude_kfunc_ids,
\t.filter = exclude_filter,
};

static int __init clash_init(void)
{
\tint ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
\t\t\t\t\t    &require_kfunc_set);
\treturn ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
\t\t\t\t\t\t&exclude_kfunc_set);
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        staged = os.path.join(fixture.sources, "linux", "v1",
                              "kernel", "bpf", "test_proto.c")
        with open(staged, "a", encoding="utf-8") as handle:
            handle.write(extra)
        fixture.repin()
        _, _, registry = fixture.extract()
        records = {entry["id"]: entry for entry in registry["records"]}
        clash = records["kfunc:bpf_fixture_clash"]
        assert clash["helpers_or_kfuncs"][0]["callable"] is False
        assert "needs_owner_review" not in clash
        assert ("registration filter denies all contexts (v1)"
                in clash["callable_context_predicates"])


def test_fixture_contradictory_flag_filters_deny():
    # Round 5, item 3 across one hook: one filter requires the flag
    # while the other excludes it, so no context can satisfy both.
    extra = """\
BTF_KFUNCS_START(freq_kfunc_ids)
BTF_ID(func, bpf_fixture_fclash)
BTF_KFUNCS_END(freq_kfunc_ids)

static int freq_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
\tif (!btf_id_set8_contains(&freq_kfunc_ids, kfunc_id))
\t\treturn 0;
\tif ((flags & SCX_KF_ALLOW_DISPATCH))
\t\treturn 0;
\treturn -EACCES;
}

static const struct btf_kfunc_id_set freq_kfunc_set = {
\t.owner = THIS_MODULE,
\t.set = &freq_kfunc_ids,
\t.filter = freq_filter,
};

BTF_KFUNCS_START(fexc_kfunc_ids)
BTF_ID(func, bpf_fixture_fclash)
BTF_KFUNCS_END(fexc_kfunc_ids)

static int fexc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
\tif (!btf_id_set8_contains(&fexc_kfunc_ids, kfunc_id))
\t\treturn 0;
\tif (!(flags & SCX_KF_ALLOW_DISPATCH))
\t\treturn 0;
\treturn -EACCES;
}

static const struct btf_kfunc_id_set fexc_kfunc_set = {
\t.owner = THIS_MODULE,
\t.set = &fexc_kfunc_ids,
\t.filter = fexc_filter,
};

static int __init fclash_init(void)
{
\tint ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
\t\t\t\t\t    &freq_kfunc_set);
\treturn ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
\t\t\t\t\t\t&fexc_kfunc_set);
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        staged = os.path.join(fixture.sources, "linux", "v1",
                              "kernel", "bpf", "test_proto.c")
        with open(staged, "a", encoding="utf-8") as handle:
            handle.write(extra)
        fixture.repin()
        _, _, registry = fixture.extract()
        records = {entry["id"]: entry for entry in registry["records"]}
        clash = records["kfunc:bpf_fixture_fclash"]
        assert clash["helpers_or_kfuncs"][0]["callable"] is False
        assert "needs_owner_review" not in clash
        assert ("registration filter denies all contexts (v1)"
                in clash["callable_context_predicates"])


def _fixture_with_filter(tmp, tag, member, block, body):
    extra = """\
BTF_KFUNCS_START(%(block)s)
BTF_ID(func, %(member)s)
BTF_KFUNCS_END(%(block)s)

static int %(tag)s_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
%(body)s
}

static const struct btf_kfunc_id_set %(tag)s_kfunc_set = {
\t.owner = THIS_MODULE,
\t.set = &%(block)s,
\t.filter = %(tag)s_filter,
};

static int __init %(tag)s_kfunc_init(void)
{
\treturn register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
\t\t\t\t\t &%(tag)s_kfunc_set);
}
""" % {"tag": tag, "member": member, "block": block, "body": body}
    fixture = Fixture(tmp)
    staged = os.path.join(fixture.sources, "linux", "v1",
                          "kernel", "bpf", "test_proto.c")
    with open(staged, "a", encoding="utf-8") as handle:
        handle.write(extra)
    fixture.repin()
    return fixture


def test_fixture_unrecognized_filters_deny_and_flag():
    bodies = {
        "nest": ("\tbpf_fixture_nest",
                 "\tif (prog->type == BPF_PROG_TYPE_XDP)\n"
                 "\t\tif (prog->expected_attach_type != BPF_TRACE_ITER)\n"
                 "\t\t\treturn -EACCES;\n"
                 "\treturn 0;\n"),
        "mutate": ("\tbpf_fixture_mutate",
                   "\tbool in_mut = btf_id_set8_contains(\n"
                   "\t\t&mutate_kfunc_ids, kfunc_id);\n"
                   "\tin_mut = false;\n"
                   "\tif (!in_mut)\n"
                   "\t\treturn -EACCES;\n"
                   "\treturn 0;\n"),
    }
    for tag, (member, body) in sorted(bodies.items()):
        with tempfile.TemporaryDirectory() as tmp:
            member = member.strip()
            fixture = _fixture_with_filter(
                tmp, tag, member, "%s_kfunc_ids" % tag, body)
            _, _, registry = fixture.extract()
            records = {entry["id"]: entry
                       for entry in registry["records"]}
            entry = records["kfunc:" + member]
            assert entry["helpers_or_kfuncs"][0]["callable"] is False
            assert len(entry["needs_owner_review"]) == 1
            assert entry["needs_owner_review"][0].startswith(
                "filter %s_filter (v1): " % tag)
            assert any(line.startswith("NEEDS-OWNER: ")
                       for line in entry["callable_context_predicates"])
            errors = uc.check_completeness(registry)
            assert any("kfunc:%s: needs owner review" % member in line
                       for line in errors), errors


def test_fixture_unrecognized_filter_denies_despite_other_grant():
    # Strict default-deny: the member is registered without a filter
    # on the COMMON hook (which grants) and with an unrecognized
    # filter on the XDP hook. The unrecognized filter still yields
    # callable:false with a needs-owner flag.
    extra = """\
BTF_KFUNCS_START(strict_kfunc_ids)
BTF_ID(func, bpf_fixture_strict)
BTF_KFUNCS_END(strict_kfunc_ids)

static int strict_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
\tif (mystery_check(prog))
\t\treturn -EACCES;
\treturn 0;
}

static const struct btf_kfunc_id_set strict_kfunc_set = {
\t.owner = THIS_MODULE,
\t.set = &strict_kfunc_ids,
};

static const struct btf_kfunc_id_set strict_filtered_set = {
\t.owner = THIS_MODULE,
\t.set = &strict_kfunc_ids,
\t.filter = strict_filter,
};

static int __init strict_kfunc_init(void)
{
\tint ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
\t\t\t\t\t    &strict_kfunc_set);
\treturn ret ?: register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
\t\t\t\t\t\t&strict_filtered_set);
}
"""
    with tempfile.TemporaryDirectory() as tmp:
        fixture = Fixture(tmp)
        staged = os.path.join(fixture.sources, "linux", "v1",
                              "kernel", "bpf", "test_proto.c")
        with open(staged, "a", encoding="utf-8") as handle:
            handle.write(extra)
        fixture.repin()
        _, _, registry = fixture.extract()
        records = {entry["id"]: entry for entry in registry["records"]}
        entry = records["kfunc:bpf_fixture_strict"]
        assert entry["helpers_or_kfuncs"][0]["callable"] is False
        assert len(entry["needs_owner_review"]) == 1


def test_frozen_registry_has_zero_unrecognized_filters():
    # Totality over the pinned corpus: generation flags every filter
    # outside the understood grammar, so a frozen registry with no
    # flags proves every pinned filter parsed fully.
    registry = load_registry()
    flagged = [entry["id"] for entry in registry["records"]
               if entry.get("needs_owner_review")]
    assert flagged == []
    for entry in registry["records"]:
        for line in entry.get("callable_context_predicates", []):
            assert not line.startswith("NEEDS-OWNER: "), entry["id"]


# Synthetic filter corpus for the totality proof: every body must
# either evaluate to its expected verdict or raise
# FilterNotUnderstood with the expected reason. Verdict entries are
# (tag, body, types, attach, stops) over a single TRACING caller;
# flagged entries are (tag, body, reason_fragment).
FILTER_CORPUS_VERDICTS = [
    ("grant_attach",
     "\tif (prog->expected_attach_type == BPF_TRACE_ITER)\n"
     "\t\treturn 0;\n"
     "\treturn -EACCES;\n",
     ("BPF_PROG_TYPE_TRACING",), ("BPF_TRACE_ITER",), ()),
    ("deny_all",
     "\treturn -EACCES;\n",
     (), (), ()),
    ("allow_all",
     "\treturn 0;\n",
     ("BPF_PROG_TYPE_TRACING",), (), ()),
    ("contra_seq",
     "\tif (prog->expected_attach_type != BPF_TRACE_FSESSION)\n"
     "\t\treturn -EACCES;\n"
     "\tif (prog->expected_attach_type != BPF_TRACE_KPROBE_SESSION)\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     (), (), ()),
    ("member_shortcircuit",
     "\tif (!btf_id_set8_contains(&corpus_ids, kfunc_id))\n"
     "\t\treturn 0;\n"
     "\tif (prog->expected_attach_type != BPF_TRACE_FENTRY)\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     ("BPF_PROG_TYPE_TRACING",), ("BPF_TRACE_FENTRY",), ()),
    ("final_allow_keeps",
     "\tif (prog->expected_attach_type == BPF_TRACE_ITER)\n"
     "\t\treturn 0;\n"
     "\tif (prog->expected_attach_type != BPF_TRACE_FENTRY)\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     ("BPF_PROG_TYPE_TRACING",),
     ("BPF_TRACE_FENTRY", "BPF_TRACE_ITER"), ()),
    ("correlated",
     "\tif (prog->expected_attach_type != BPF_TRACE_ITER &&\n"
     "\t    prog->aux->st_ops != &corpus_ops)\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     ("BPF_PROG_TYPE_TRACING",), ("BPF_TRACE_ITER",),
     ("corpus_ops",)),
    ("self_contra",
     "\tif (prog->expected_attach_type == BPF_TRACE_ITER)\n"
     "\t\treturn -EACCES;\n"
     "\tif (prog->expected_attach_type == BPF_TRACE_ITER)\n"
     "\t\treturn 0;\n"
     "\treturn -EACCES;\n",
     (), (), ()),
    ("partial_overlap",
     "\tif (prog->aux->st_ops != &first_ops &&\n"
     "\t    prog->aux->st_ops != &second_ops)\n"
     "\t\treturn -EACCES;\n"
     "\tif (prog->aux->st_ops == &second_ops)\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     ("BPF_PROG_TYPE_TRACING",), (),
     ("first_ops", "second_ops")),
    ("zero_grant",
     "\tif (0)\n"
     "\t\treturn 0;\n"
     "\treturn -EACCES;\n",
     (), (), ()),
    ("one_deny",
     "\tif (1)\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     (), (), ()),
    ("zero_deny",
     "\tif (0)\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     ("BPF_PROG_TYPE_TRACING",), (), ()),
    ("opaque_allow",
     "\tif ((flags & SCX_KF_ALLOW_DISPATCH) &&\n"
     "\t    btf_id_set8_contains(&corpus_ids, kfunc_id))\n"
     "\t\treturn 0;\n"
     "\treturn -EACCES;\n",
     ("BPF_PROG_TYPE_TRACING",), (), ()),
    ("neg_opaque_allow",
     "\tif (!(flags & SCX_KF_ALLOW_DISPATCH) &&\n"
     "\t    btf_id_set8_contains(&corpus_ids, kfunc_id))\n"
     "\t\treturn 0;\n"
     "\treturn -EACCES;\n",
     ("BPF_PROG_TYPE_TRACING",), (), ()),
    ("stops_null_allow",
     "\tif (!prog->aux->st_ops)\n"
     "\t\treturn 0;\n"
     "\treturn -EACCES;\n",
     (), (), ()),
    ("alias_allow",
     "\tbool in_corpus = btf_id_set8_contains(&corpus_ids, kfunc_id);\n"
     "\tif (!in_corpus)\n"
     "\t\treturn 0;\n"
     "\tif (prog->expected_attach_type != BPF_TRACE_ITER)\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     ("BPF_PROG_TYPE_TRACING",), ("BPF_TRACE_ITER",), ()),
    ("ternary_allow",
     "\treturn (prog->expected_attach_type == BPF_TRACE_ITER)\n"
     "\t\t? 0 : -EACCES;\n",
     ("BPF_PROG_TYPE_TRACING",), ("BPF_TRACE_ITER",), ()),
    ("nested_block_deny",
     "\t{ return -EACCES; }\n"
     "\treturn 0;\n",
     (), (), ()),
    ("opaque_flag_contra",
     "\tif ((flags & SCX_KF_ALLOW_DISPATCH) &&\n"
     "\t    !(flags & SCX_KF_ALLOW_DISPATCH))\n"
     "\t\treturn 0;\n"
     "\treturn -EACCES;\n",
     (), (), ()),
    ("const_false_bit_group",
     "\tif ((0 && flags & SCX_KF_ALLOW_DISPATCH)) return 0;\n"
     "\treturn -EACCES;\n",
     (), (), ()),
    ("mirrored_attach_deny",
     "\tif (BPF_TRACE_ITER != prog->expected_attach_type)\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     ("BPF_PROG_TYPE_TRACING",), ("BPF_TRACE_ITER",), ()),
    ("ternary_zero_arms",
     "\treturn (false) ? 0 : 0U;\n",
     ("BPF_PROG_TYPE_TRACING",), (), ()),
]

FILTER_CORPUS_FLAGGED = [
    ("nested_if",
     "\tif (prog->type == BPF_PROG_TYPE_TRACING)\n"
     "\t\tif (prog->expected_attach_type != BPF_TRACE_ITER)\n"
     "\t\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     "non-return branch"),
    ("complex_branch",
     "\tif (prog->type == BPF_PROG_TYPE_TRACING) {\n"
     "\t\tif (prog->expected_attach_type != BPF_TRACE_ITER)\n"
     "\t\t\treturn -EACCES;\n"
     "\t}\n"
     "\treturn 0;\n",
     "complex branch"),
    ("guarded_call",
     "\tif (prog->type == BPF_PROG_TYPE_TRACING)\n"
     "\t\ttrace_probe(prog);\n"
     "\treturn 0;\n",
     "non-return branch"),
    ("else_branch",
     "\tif (prog->expected_attach_type == BPF_TRACE_ITER)\n"
     "\t\treturn 0;\n"
     "\telse\n"
     "\t\treturn -EACCES;\n",
     "else branch"),
    ("alias_reassign",
     "\tbool in_corpus = btf_id_set8_contains(&corpus_ids, kfunc_id);\n"
     "\tin_corpus = false;\n"
     "\tif (!in_corpus)\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     "reassigns membership alias"),
    ("alias_shadow",
     "\tbool in_corpus = btf_id_set8_contains(&corpus_ids, kfunc_id);\n"
     "\t{ bool in_corpus = false; (void)in_corpus; }\n"
     "\tif (!in_corpus)\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     "redeclares membership alias"),
    ("alias_compound",
     "\tbool in_corpus = btf_id_set8_contains(&corpus_ids, kfunc_id);\n"
     "\tin_corpus &= false;\n"
     "\tif (!in_corpus)\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     "mutates membership alias"),
    ("alias_address",
     "\tbool in_corpus = btf_id_set8_contains(&corpus_ids, kfunc_id);\n"
     "\tcheck_probe(&in_corpus);\n"
     "\tif (!in_corpus)\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     "address of membership alias"),
    ("param_reassign",
     "\tkfunc_id = 0;\n"
     "\tif (!btf_id_set8_contains(&corpus_ids, kfunc_id))\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     "reassigns parameter"),
    ("opaque_deny",
     "\tif (mystery_check(prog))\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     "unrecognized condition"),
    ("wrong_id_membership",
     "\tif (!btf_id_set8_contains(&corpus_ids, 42))\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     "cannot parse filter condition"),
    ("stops_null_deny",
     "\tif (!prog->aux->st_ops)\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     "st_ops-null"),
    ("falls_off_end",
     "\tif (prog->expected_attach_type == BPF_TRACE_ITER)\n"
     "\t\treturn -EACCES;\n",
     "falls off the end"),
    ("partial_ternary",
     "\tif (prog->expected_attach_type == BPF_TRACE_ITER)\n"
     "\t\treturn (prog->expected_attach_type == BPF_TRACE_FENTRY)\n"
     "\t\t\t? 0 : -EACCES;\n"
     "\treturn -EACCES;\n",
     "partial condition"),
    ("paren_alias_reassign",
     "\tbool in_corpus = btf_id_set8_contains(&corpus_ids, kfunc_id);\n"
     "\t(in_corpus) = false;\n"
     "\tif (!in_corpus)\n"
     "\t\treturn -EACCES;\n"
     "\treturn 0;\n",
     "reassigns membership alias"),
    ("compound_alias_init",
     "\tbool in_corpus = btf_id_set8_contains(&corpus_ids, kfunc_id)"
     " && false;\n"
     "\tif (in_corpus)\n"
     "\t\treturn 0;\n"
     "\treturn -EACCES;\n",
     "compound membership initializer"),
]


def test_filter_corpus_is_totally_classified():
    # Every corpus body either evaluates to its expected verdict or
    # raises FilterNotUnderstood with the expected reason: the
    # understood/unrecognized partition is total, and nothing
    # unrecognized is allowed.
    for tag, body, types, attach, stops in FILTER_CORPUS_VERDICTS:
        verdict = _simulate_source(
            "corpus_%s" % tag, body, ("corpus_fn",),
            {"corpus_ids": {"corpus_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
        assert verdict["corpus_fn"]["types"] == set(types), tag
        assert verdict["corpus_fn"]["attach"] == set(attach), tag
        assert verdict["corpus_fn"]["stops"] == set(stops), tag
    for tag, body, fragment in FILTER_CORPUS_FLAGGED:
        try:
            verdict = _simulate_source(
                "corpus_%s" % tag, body, ("corpus_fn",),
                {"corpus_ids": {"corpus_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert fragment in str(exc), (tag, exc)
        else:
            raise AssertionError(
                "corpus body %s was allowed but must be flagged: %s"
                % (tag, verdict["corpus_fn"]["types"]))
    assert FILTER_CORPUS_VERDICTS and FILTER_CORPUS_FLAGGED


def test_filter_corpus_inventory_agrees_with_simulation():
    # End-to-end totality: at inventory level every flagged corpus
    # body denies its member with a needs-owner flag (zero
    # unrecognized-but-allowed), and verdict bodies agree with the
    # direct simulation (callable exactly when types are granted).
    for tag, body, _ in FILTER_CORPUS_FLAGGED:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = _fixture_with_filter(
                tmp, "flg_%s" % tag, "bpf_fixture_flg_%s" % tag,
                "flg_%s_kfunc_ids" % tag,
                body.replace("corpus_ids",
                             "flg_%s_kfunc_ids" % tag))
            _, _, registry = fixture.extract()
            records = {entry["id"]: entry
                       for entry in registry["records"]}
            entry = records["kfunc:bpf_fixture_flg_%s" % tag]
            assert entry["helpers_or_kfuncs"][0]["callable"] is False, \
                tag
            assert len(entry["needs_owner_review"]) == 1, tag
    for tag, body, types, attach, _ in FILTER_CORPUS_VERDICTS:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = _fixture_with_filter(
                tmp, "ver_%s" % tag, "bpf_fixture_ver_%s" % tag,
                "ver_%s_kfunc_ids" % tag,
                body.replace("corpus_ids",
                             "ver_%s_kfunc_ids" % tag))
            _, _, registry = fixture.extract()
            records = {entry["id"]: entry
                       for entry in registry["records"]}
            entry = records["kfunc:bpf_fixture_ver_%s" % tag]
            assert entry["helpers_or_kfuncs"][0]["callable"] == \
                bool(types), tag
            assert "needs_owner_review" not in entry, tag
            if types:
                assert entry["attach_types"] == sorted(attach), tag


def test_scx_dsq_move_alternatives_stay_distinct():
    registry = load_registry()
    records = {entry["id"]: entry for entry in registry["records"]}
    move = records["kfunc:scx_bpf_dsq_move"]
    assert move["helpers_or_kfuncs"][0]["callable"] is True
    lines = move["callable_context_predicates"]
    assert "callable from BPF_PROG_TYPE_SYSCALL (7.2.9)" in lines
    dispatch = [line for line in lines if "SCX_KF_ALLOW_DISPATCH" in line]
    unlocked = [line for line in lines if "SCX_KF_ALLOW_UNLOCKED" in line]
    assert len(dispatch) == 1, lines
    assert len(unlocked) == 1, lines
    assert dispatch[0] != unlocked[0]
    for line in dispatch + unlocked:
        assert line.startswith(
            "callable from BPF_PROG_TYPE_STRUCT_OPS when "), line
        assert "struct_ops attachment to one of: " in line, line
    assert not [line for line in lines
                if "SYSCALL" in line and "when" in line], lines
    sched = records["kfunc:bpf_qdisc_watchdog_schedule"]
    when_lines = [line for line in
                  sched["callable_context_predicates"]
                  if " when " in line]
    assert len(when_lines) == 2, when_lines
    assert any("QDISC_OPS_KF_ENQUEUE" in line for line in when_lines)
    assert any("QDISC_OPS_KF_DEQUEUE" in line for line in when_lines)


def test_struct_ops_parser_skips_declarations():
    text = (
        "extern struct bpf_struct_ops bpf_fwd_ops;\n"
        "struct bpf_struct_ops bpf_fwd_ops;\n"
        "static struct bpf_struct_ops bpf_real_ops = {\n"
        "\t.verifier_ops = &real_verifier_ops,\n"
        "\t.name = \"real\",\n"
        "};\n"
    )
    assert uc.parse_struct_ops_defs(text) == {
        "bpf_real_ops": {"vops": "real_verifier_ops",
                         "map_name": "real"},
    }


def test_scx_ops_table_parser_lists_callbacks():
    text = (
        "struct sched_ext_ops {\n"
        "\tu64 flags;\n"
        "\ts32 (*select_cpu)(struct task_struct *p);\n"
        "\tvoid (*enqueue)(struct task_struct *p, u64 flags);\n"
        "};\n"
    )
    assert uc.parse_scx_ops_tables(text) == {
        "sched_ext_ops": [
            ("select_cpu", "s32", "struct task_struct *p"),
            ("enqueue", "void", "struct task_struct *p, u64 flags"),
        ],
    }
    try:
        uc.parse_scx_ops_tables("struct sched_ext_ops {\n\tu64 f;\n};\n")
    except uc.InventoryError as exc:
        assert "no callbacks" in str(exc)
    else:
        raise AssertionError("expected InventoryError")


def test_structops_consumers_enumerated():
    registry = load_registry()
    records = {entry["id"]: entry for entry in registry["records"]
               if entry["family"] == "structops-consumers"}
    assert sorted(records) == [
        "structops:dummy", "structops:hid-bpf", "structops:qdisc",
        "structops:smc-hs", "structops:tcp-congestion"]
    want_present = {
        "structops:dummy": ["6.12.112", "6.6.158", "7.2.9"],
        "structops:hid-bpf": ["6.12.112", "7.2.9"],
        "structops:qdisc": ["7.2.9"],
        "structops:smc-hs": ["7.2.9"],
        "structops:tcp-congestion": ["6.12.112", "6.6.158", "7.2.9"],
    }
    members = {(item["container"], item["name"]): item
               for item in registry["enum_members"]}
    want_symbols = {
        "structops:dummy": "bpf_bpf_dummy_ops",
        "structops:hid-bpf": "bpf_hid_bpf_ops",
        "structops:qdisc": "bpf_Qdisc_ops",
        "structops:smc-hs": "bpf_smc_hs_ctrl_ops",
        "structops:tcp-congestion": "bpf_tcp_congestion_ops",
    }
    for rid, entry in records.items():
        assert entry["owner_task"] == "O-CONSUMERS", rid
        assert entry["program_types"] == ["BPF_PROG_TYPE_STRUCT_OPS"], rid
        assert entry["kernel_registration_refs"], rid
        assert entry["callable_context_predicates"], rid
        present = want_present[rid]
        for version in present:
            assert any(version in ref
                       for ref in entry["upstream_source_refs"]), rid
        member = members[("linux:struct-ops", want_symbols[rid])]
        assert member["classification"] == "capability"
        assert member["record_id"] == rid
        assert sorted(member["present_in"]) == present
    hid = records["structops:hid-bpf"]
    assert any("absent from 6.6.158" in line
               for line in hid["callable_context_predicates"])


def test_sched_ext_interface_enumerated():
    registry = load_registry()
    records = {entry["id"]: entry for entry in registry["records"]
               if entry["family"] == "sched-ext"}
    assert "scx:sched-ext" in records
    assert len(records) == 43, len(records)
    sched = records["scx:sched-ext"]
    assert sched["owner_task"] == "O-SCX"
    assert any("docs.kernel.org/scheduler/sched-ext.html" in ref
               for ref in sched["upstream_source_refs"])
    assert any("no stability guarantees" in line
               for line in sched["callable_context_predicates"])
    assert any("absent from 6.6.158" in line
               for line in sched["callable_context_predicates"])
    assert any(line.endswith("#bpf_sched_ext_ops")
               for line in sched["kernel_registration_refs"])
    callbacks = {rid: entry for rid, entry in records.items()
                 if rid != "scx:sched-ext"}
    assert len(callbacks) == 42
    for rid, entry in callbacks.items():
        assert entry["owner_task"] == "O-SCX", rid
        assert entry["program_types"] == ["BPF_PROG_TYPE_STRUCT_OPS"], rid
        assert entry["kernel_registration_refs"], rid
        assert any(line.startswith("callback signature")
                   for line in entry["callable_context_predicates"]), rid
    select_cpu = callbacks["scx:select_cpu"]
    assert any("cpu-form (6.12.112, 7.2.9)" in line
               for line in select_cpu["callable_context_predicates"])
    select_cid = callbacks["scx:select_cid"]
    assert any("cid-form (7.2.9)" in line
               for line in select_cid["callable_context_predicates"])
    enqueue = callbacks["scx:enqueue"]
    assert any("cpu-form (6.12.112, 7.2.9)" in line
               for line in enqueue["callable_context_predicates"])
    assert any("cid-form (7.2.9)" in line
               for line in enqueue["callable_context_predicates"])
    members = {(item["container"], item["name"]): item
               for item in registry["enum_members"]}
    for rid in callbacks:
        name = rid[len("scx:"):]
        member = members[("linux:scx-ops", name)]
        assert member["classification"] == "capability"
        assert member["record_id"] == rid


def test_no_upstream_blockers_remain_except_afxdp():
    registry = load_registry()
    assert [(entry["id"], entry["status"])
            for entry in registry["blockers"]] == [
                ("net-afxdp-userspace", "BLOCKED_UPSTREAM")]


def test_lock_pins_scheduler_and_consumer_sources():
    lock = load_lock()
    files = lock["kernel_files"]
    assert "kernel/sched/ext.c" in files["6.12.112"]
    assert "include/linux/sched/ext.h" in files["6.12.112"]
    assert "drivers/hid/bpf/hid_bpf_struct_ops.c" in files["6.12.112"]
    assert "net/bpf/bpf_dummy_struct_ops.c" in files["6.12.112"]
    for relpath in ("kernel/sched/ext/internal.h",
                    "kernel/sched/ext/ext.c", "kernel/sched/ext/idle.c",
                    "kernel/sched/ext/cid.c",
                    "include/linux/sched/ext.h",
                    "drivers/hid/bpf/hid_bpf_struct_ops.c",
                    "net/bpf/bpf_dummy_struct_ops.c",
                    "net/smc/smc_hs_bpf.c"):
        assert relpath in files["7.2.9"], relpath
    assert files["6.6.158"].count(
        "net/bpf/bpf_dummy_struct_ops.c") == 1
    assert not [relpath for relpath in files["6.6.158"]
                if relpath.startswith("kernel/sched/")]
    assert "drivers/hid/bpf/hid_bpf_struct_ops.c" not in files["6.6.158"]
    kernel = next(entry for entry in lock["sources"]
                  if entry["id"] == "linux-kernel")
    pinned = {(version["version"], item["name"]): item
              for version in kernel["versions"]
              for item in version["files"]}
    import re
    digest = re.compile(r"^[0-9a-f]{64}$")
    for version, relpaths in files.items():
        for relpath in relpaths:
            item = pinned[(version, relpath)]
            assert digest.match(item["sha256"])
            assert item["url"].endswith("?h=v%s" % version)


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
