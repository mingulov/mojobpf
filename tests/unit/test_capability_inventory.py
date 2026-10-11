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


def _simulate_header_params(fn_name, header, params, body, members,
                            membersets, callers):
    texts = {"kernel/bpf/probe.c": uc.strip_comments(
        "%s\nstatic int %s(%s)\n{\n%s\n}\n"
        % (header, fn_name, params, body))}
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
    # defeats absorption. Round 11 overrides the old comma pin:
    # the group granted XDP where C denies, so a comma inside a
    # bit test rejects as an unproven operand instead of staying
    # symbolic.
    verdict = _simulate_source(
        "const_lit_wide",
        "\tif ((4294967295 & 4294967294)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    _expect_unrecognized(
        "const_comma_stays",
        "\tif ((0 & flags, prog->type == BPF_PROG_TYPE_TRACING))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        "bit-testable")


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
    # A mirrored comparison against a number stays an opaque atom,
    # and round 9, item 1 rejects non-bit opaque atoms in allow
    # position (only bit tests keep existential grants).
    _expect_unrecognized(
        "mirror_number_grant",
        "\tif (0 == prog->type)\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        "only bit tests")


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


def test_kfunc_filter_nested_const_folds_keep_values():
    # Round 7, item 1 (exact counterexamples): nested constant groups
    # fold to their actual numeric value, never to Boolean 1, so
    # enclosing comparisons and bit tests see real values.
    verdict = _simulate_source(
        "nested_eq_deny",
        "\tif (((1 + 1) == 2)) return -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    verdict = _simulate_source(
        "nested_and_allow",
        "\tif (((2) & 2)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "nested_gt_deny",
        "\tif ((2 > (1 + 1))) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # Further variants, each verified against compiled C (see the
    # round-7 oracle): arithmetic feeds comparisons, bit results feed
    # truth tests, and negative intermediates fold inside-out.
    verdict = _simulate_source(
        "nested_mul_eq",
        "\tif (((3 - 1) * 2 == 4)) return -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_source(
        "nested_or_allow",
        "\tif (((10) | 1)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "nested_xor_allow",
        "\tif (((2) ^ 3)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "nested_shr_eq",
        "\tif (((8 >> 2) == 2)) return -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_source(
        "nested_neg_inner",
        "\tif (((0 - 5) + 5 == 0)) return -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # A group whose folded value is negative has no spelling the
    # condition grammar parses, so it fails closed instead of
    # guessing a Boolean.
    try:
        _simulate_source(
            "nested_neg_fold",
            "\tif (((1 - 5))) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "cannot parse filter condition" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_shadowed_consts_bind_local_values():
    # Round 7, item 2 (exact counterexample): a local declaration
    # shadows the enum constant, so the comparison binds the local
    # value (TRACING) rather than the shadowed spelling (XDP).
    header = ("enum bpf_prog_type {\n"
              "\tBPF_PROG_TYPE_UNSPEC = 0,\n"
              "\tBPF_PROG_TYPE_XDP = 6,\n"
              "\tBPF_PROG_TYPE_TRACING = 26,\n"
              "};\n"
              "enum bpf_attach_type {\n"
              "\tBPF_TRACE_FENTRY = 10,\n"
              "\tBPF_TRACE_ITER = 14,\n"
              "};\n")
    callers = ("BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_TRACING")
    verdict = _simulate_header(
        "shadow_type",
        header,
        "\tu32 BPF_PROG_TYPE_XDP = BPF_PROG_TYPE_TRACING;\n"
        "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        callers)
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Mirrored operand order resolves the same way.
    verdict = _simulate_header(
        "shadow_type_mirrored",
        header,
        "\tu32 BPF_PROG_TYPE_XDP = BPF_PROG_TYPE_TRACING;\n"
        "\tif (BPF_PROG_TYPE_XDP == prog->type) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        callers)
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Attach-type comparisons resolve through shadowing too.
    verdict = _simulate_header(
        "shadow_attach",
        header,
        "\tu32 BPF_TRACE_FENTRY = BPF_TRACE_ITER;\n"
        "\tif (prog->expected_attach_type == BPF_TRACE_FENTRY)"
        " return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["attach"] == {"BPF_TRACE_ITER"}
    # A shadow holding the same value binds transparently.
    verdict = _simulate_header(
        "shadow_same_value",
        header,
        "\tu32 BPF_PROG_TYPE_XDP = 6;\n"
        "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        callers)
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_XDP"}
    # A shadowed constant without a provable value cannot bind.
    try:
        _simulate_header(
            "shadow_unknown",
            header,
            "\tu32 BPF_PROG_TYPE_XDP = kfunc_id;\n"
            "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            callers)
    except uc.FilterNotUnderstood as exc:
        assert "shadow_unknown" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A shadow holding a value no caller carries cannot bind either.
    try:
        _simulate_header(
            "shadow_impossible",
            header,
            "\tu32 BPF_PROG_TYPE_XDP = 9999;\n"
            "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            callers)
    except uc.FilterNotUnderstood as exc:
        assert "shadow_impossible" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A nested-block shadow is out of scope at the comparison, so the
    # filter-level binding is unprovable and fails closed.
    try:
        _simulate_header(
            "shadow_nested_scope",
            header,
            "\t{ u32 BPF_PROG_TYPE_XDP = BPF_PROG_TYPE_TRACING; }\n"
            "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            callers)
    except uc.FilterNotUnderstood as exc:
        assert "shadow_nested_scope" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # Shadowed boolean spellings in conditions resolve by value.
    verdict = _simulate_source(
        "shadow_bool_zero",
        "\tu32 TRUE = 0;\n"
        "\tif (TRUE) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_source(
        "shadow_bool_nonzero",
        "\tu32 FALSE = 2;\n"
        "\tif (FALSE) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_alias_shadows_cover_all_declarators():
    # Round 7, item 3 (exact counterexample): a function-pointer
    # declarator shadows the membership alias, which is outside the
    # grammar.
    _expect_unrecognized(
        "fnptr_shadow",
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\t{ int (*mine)(void) = 0; if (mine) return 0; }\n"
        "\treturn -EACCES;\n",
        "shadowing is outside the grammar")
    # Further declarator spellings shadow the same way.
    _expect_unrecognized(
        "fnptr_shadow_args",
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\t{ void *(*mine)(int, char) = 0; if (mine) return 0; }\n"
        "\treturn -EACCES;\n",
        "shadowing is outside the grammar")
    _expect_unrecognized(
        "fnptr_shadow_comma",
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tint helper = 0, (*mine)(void) = 0;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "shadowing is outside the grammar")
    _expect_unrecognized(
        "paren_shadow",
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tu32 (mine) = 1;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "shadowing is outside the grammar")
    _expect_unrecognized(
        "typedef_shadow",
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\ttypedef int mine;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "shadowing is outside the grammar")
    _expect_unrecognized(
        "enum_shadow",
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tenum { mine = 1 };\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "shadowing is outside the grammar")
    _expect_unrecognized(
        "struct_suffix_shadow",
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tstruct holder { int slot; } mine;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "shadowing is outside the grammar")
    # Storage-class and multi-word type prefixes do not hide the
    # declarator either.
    _expect_unrecognized(
        "static_shadow",
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tstatic u32 mine;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "shadowing is outside the grammar")
    _expect_unrecognized(
        "extern_shadow",
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\textern int mine;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "shadowing is outside the grammar")
    _expect_unrecognized(
        "unsigned_long_shadow",
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tunsigned long mine = 0;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "shadowing is outside the grammar")
    # Filter parameters shadow the same way: a redeclaration hides
    # the parameter the membership test consults.
    _expect_unrecognized(
        "param_shadow",
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tu32 kfunc_id = 5;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "shadowing is outside the grammar")
    _expect_unrecognized(
        "prog_shadow",
        "\tstruct bpf_prog *prog = 0;\n"
        "\tif (prog->type == BPF_PROG_TYPE_TRACING) return 0;\n"
        "\treturn -EACCES;\n",
        "shadowing is outside the grammar")
    # An unrelated local keeps the alias binding intact.
    verdict = _simulate_source(
        "unrelated_local",
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tu32 other = 1;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_return_arms_reject_every_local_form():
    # Round 7, item 4: a parenthesized declarator binds a local that
    # shadows the constant, so the arm is dynamic, never zero.
    header = ("enum bpf_prog_type {\n"
              "\tBPF_PROG_TYPE_UNSPEC = 0,\n"
              "};\n")
    try:
        _simulate_header(
            "paren_decl_arm",
            header,
            "\tu32 (BPF_PROG_TYPE_UNSPEC) = 1;\n"
            "\treturn (false) ? 0 : -BPF_PROG_TYPE_UNSPEC;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "non-constant arm" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A typedef-derived declaration binds the spelling as an object:
    # the arm is dynamic (C returns -1 here), never the enum zero.
    try:
        _simulate_header(
            "typedef_arm",
            header,
            "\ttypedef u32 review_t;\n"
            "\treview_t BPF_PROG_TYPE_UNSPEC = 1;\n"
            "\treturn (false) ? 0 : -BPF_PROG_TYPE_UNSPEC;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "non-constant arm" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # Boolean spellings consult local bindings before their shape.
    _expect_unrecognized(
        "bool_false_arm",
        "\tbool FALSE = true;\n"
        "\treturn (false) ? 0 : FALSE;\n",
        "non-constant arm")
    _expect_unrecognized(
        "bool_true_arm",
        "\tu32 TRUE = 0;\n"
        "\treturn TRUE;\n",
        "cannot parse filter")
    # Further local forms shadow constant spellings in arms.
    _expect_unrecognized(
        "enum_arm",
        "\tenum { EREVIEW_LOCAL = 0 };\n"
        "\treturn (false) ? 0 : -EREVIEW_LOCAL;\n",
        "non-constant arm")
    try:
        _simulate_header(
            "fndecl_arm",
            header,
            "\tint BPF_PROG_TYPE_UNSPEC(void);\n"
            "\treturn (false) ? 0 : -BPF_PROG_TYPE_UNSPEC;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "non-constant arm" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    try:
        _simulate_header(
            "comma_paren_arm",
            header,
            "\tu32 helper = 1, (BPF_PROG_TYPE_UNSPEC) = 2;\n"
            "\treturn (false) ? 0 : -BPF_PROG_TYPE_UNSPEC;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "non-constant arm" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    _expect_unrecognized(
        "fnptr_arm",
        "\tint (*ELOCAL_PTR)(void) = 0;\n"
        "\treturn (false) ? 0 : -ELOCAL_PTR;\n",
        "non-constant arm")


def test_kfunc_filter_bit_contradictions_use_canonical_operands():
    # Round 7, item 5 (exact counterexamples): redundant parentheses
    # do not change operand identity, and ^-mixed expressions
    # evaluate against pinned flag values.
    header = ("enum scx_kf_allow_flags {\n"
              "\tSCX_KF_ALLOW_DISPATCH = 1 << 3,\n"
              "\tSCX_KF_ALLOW_ENQUEUE = 1 << 4,\n"
              "};\n")
    verdict = _simulate_header(
        "paren_contra",
        header,
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    !((flags) & SCX_KF_ALLOW_DISPATCH)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    verdict = _simulate_header(
        "xor_contra",
        header,
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    !(flags ^ 1 & SCX_KF_ALLOW_DISPATCH)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # Further variants: parentheses on either side, ^-with-zero
    # folding back to the same test, and doubly-nested operands.
    verdict = _simulate_header(
        "paren_both_contra",
        header,
        "\tif (((flags) & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    !(flags & (SCX_KF_ALLOW_DISPATCH))) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_header(
        "xor_zero_contra",
        header,
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    !(flags & SCX_KF_ALLOW_DISPATCH ^ 0)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_header(
        "nested_paren_contra",
        header,
        "\tif ((((flags)) & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    !(flags & SCX_KF_ALLOW_DISPATCH)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # Independent operands and disjoint flags stay satisfiable.
    verdict = _simulate_header(
        "disjoint_flags_ok",
        header,
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    !(flags & SCX_KF_ALLOW_ENQUEUE)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_header(
        "other_operand_ok",
        header,
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    !(other & SCX_KF_ALLOW_DISPATCH)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_impossible_bit_groups_deny():
    # Round 7, item 6 (exact counterexample): a provably-false bit
    # expression grants nothing instead of minting permission.
    verdict = _simulate_source(
        "zero_xor_deny",
        "\tif ((0 & flags ^ 0)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # Further provably-false shapes deny the same way.
    verdict = _simulate_source(
        "and_zero_deny",
        "\tif ((1 & 0 & flags)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_source(
        "or_zero_deny",
        "\tif ((0 | 0 & flags)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_source(
        "self_xor_deny",
        "\tif ((flags ^ flags)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # A provably-false deny guard is vacuous: execution falls
    # through, so the filter still grants.
    verdict = _simulate_source(
        "zero_xor_deny_guard",
        "\tif ((0 & flags ^ 0)) return -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # A satisfiable bit test still grants with its restriction note.
    verdict = _simulate_source(
        "plain_bit_ok",
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_named_consts_keep_unsigned_types():
    # Round 7, item 7 (exact counterexample): the suffixed macro
    # wraps to zero, so the comparison is 1 and the arm denies.
    header = ("#define REVIEW_MAX7 4294967295U\n"
              "#define REVIEW_WRAPPED7"
              " (REVIEW_MAX7 + 1U == 0U)\n")
    verdict = _simulate_header(
        "wrapped_macro",
        header,
        "\treturn (false) ? 0 : -REVIEW_WRAPPED7;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # Further unsigned chains keep their width end to end.
    verdict = _simulate_header(
        "wrapped_neg_value",
        "#define REVIEW_MAX7 4294967295U\n",
        "\treturn (false) ? 0 : -REVIEW_MAX7;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    header2 = ("#define HALF7 2147483648U\n"
               "#define TWICE7 (HALF7 + HALF7 == 0U)\n")
    verdict = _simulate_header(
        "wrapped_half",
        header2,
        "\treturn (false) ? 0 : -TWICE7;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    header3 = ("enum review {\n"
               "\tEU7 = 4294967295U,\n"
               "};\n"
               "#define D7 (EU7 + 1U == 0U)\n")
    verdict = _simulate_header(
        "wrapped_enum",
        header3,
        "\treturn (false) ? 0 : -D7;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # A 64-bit unsigned chain wraps at 64 bits, not 32.
    header4 = ("#define BIG7 18446744073709551615ULL\n"
               "#define BIGWRAP7 (BIG7 + 1ULL == 0ULL)\n")
    verdict = _simulate_header(
        "wrapped_ull",
        header4,
        "\treturn (false) ? 0 : -BIGWRAP7;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()


def test_kfunc_filter_return_arms_resolve_values_not_spellings():
    # Round 7, item 8 (exact counterexample): a const-initialized
    # object resolving to zero allows, whatever its spelling.
    verdict = _simulate_header(
        "static_const_zero",
        "static const int EREVIEW_ZERO7 = 0;\n",
        "\treturn (false) ? 0 : -EREVIEW_ZERO7;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Further const objects resolve by their evaluated value.
    verdict = _simulate_header(
        "static_const_nonzero",
        "static const int ENONZERO8 = 5;\n",
        "\treturn (false) ? 0 : -ENONZERO8;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_header(
        "static_const_shift",
        "const u32 ELOCAL9 = 1u << 3;\n",
        "\treturn (false) ? 0 : -ELOCAL9;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # Initializers may reference macros, even when the object
    # follows a semicolon-less preprocessor line.
    verdict = _simulate_header(
        "static_const_macro_init",
        "#define KREVIEW8 20\n"
        "static const int CKREVIEW8 = KREVIEW8 + 2;\n",
        "\treturn (false) ? 0 : -CKREVIEW8;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # A declaration spelled inside a macro body is not an object.
    try:
        _simulate_header(
            "macro_body_decl",
            "#define MKREVIEW8 static const int CKREVIEW8B = 4;\n",
            "\treturn (false) ? 0 : -CKREVIEW8B;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "non-constant arm" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A file-local object shadows the errno table: this EACCES is
    # zero, so the arm allows.
    verdict = _simulate_header(
        "static_const_errno_shadow",
        "static const int EACCES = 0;\n",
        "\treturn (false) ? 0 : -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # A mutable global is not a constant even when initialized.
    try:
        _simulate_header(
            "mutable_global_arm",
            "int EGLOBALPLAIN = 0;\n",
            "\treturn (false) ? 0 : -EGLOBALPLAIN;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "non-constant arm" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # Unknown E-prefixed names are rejected, never guessed.
    _expect_unrecognized(
        "unknown_errno_arm",
        "\treturn (false) ? 0 : -ESOME_FUTURE_NAME;\n",
        "non-constant arm")
    # Genuine errno macros keep their deny meaning by tabled value.
    verdict = _simulate_source(
        "errno_table_deny",
        "\treturn (false) ? 0 : -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_source(
        "errno_table_deny_direct",
        "\treturn -EPERM;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # A braced array initializer is not a constant expression and
    # never misparses as one (SCX keeps such a table next to its
    # filter).
    verdict = _simulate_header(
        "array_table_ignored",
        "static const u32 scx_flags[] = {\n"
        "\t[0] = 1,\n"
        "\t[1] = 8,\n"
        "};\n",
        "\treturn (false) ? 0 : -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()


def test_kfunc_filter_typedef_decls_bind_like_direct_decls():
    # Round 8, item 1 (exact counterexamples): typedef-derived
    # declarations bind their names like direct declarations. A
    # stdint-spelled shadow is provable and rejects the arm; a
    # custom-typedef shadow is bound but unprovable, so any
    # verdict-relevant use fails closed instead of granting.
    header = ("enum bpf_prog_type {\n"
              "\tBPF_PROG_TYPE_UNSPEC = 0,\n"
              "\tBPF_PROG_TYPE_XDP = 6,\n"
              "\tBPF_PROG_TYPE_TRACING = 26,\n"
              "};\n")
    try:
        _simulate_header(
            "uint32_arm",
            header,
            "\tuint32_t BPF_PROG_TYPE_UNSPEC = 1;\n"
            "\treturn (false) ? 0 : -BPF_PROG_TYPE_UNSPEC;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "non-constant arm" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A stdint shadow with a provable value still resolves in
    # comparisons when it precedes the use (C semantics).
    verdict = _simulate_header(
        "uint32_cmp",
        header,
        "\tuint32_t BPF_PROG_TYPE_XDP = BPF_PROG_TYPE_TRACING;\n"
        "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_TRACING"))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # A custom-typedef shadow is unprovable: the comparison fails
    # closed rather than resolving through the shadowed spelling.
    try:
        _simulate_header(
            "typedef_cmp",
            "typedef u32 review_t;\n" + header,
            "\treview_t BPF_PROG_TYPE_XDP = BPF_PROG_TYPE_TRACING;\n"
            "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_TRACING"))
    except uc.FilterNotUnderstood as exc:
        assert "typedef_cmp" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A typedef-derived function-pointer declarator shadows the
    # membership alias instead of resolving as the outer binding.
    _expect_unrecognized(
        "typedef_fnptr_shadow",
        "typedef int (*fn_t)(void);\n"
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\t{ fn_t (*mine)(void) = 0; if (mine) return 0; }\n"
        "\treturn -EACCES;\n",
        "shadowing is outside the grammar")
    # A plain typedef-derived shadow of the alias fails closed too.
    _expect_unrecognized(
        "typedef_plain_shadow",
        "typedef u32 review_t;\n"
        "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\treview_t mine = 1;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "shadowing is outside the grammar")
    # A typedef that binds no verdict-relevant name is not an
    # over-rejection: the filter still evaluates.
    verdict = _simulate_header(
        "typedef_unused_ok",
        "typedef u32 review_t;\n" + header,
        "\treview_t helper = 1;\n"
        "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_TRACING"))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_XDP"}


def test_kfunc_filter_nested_typed_folds_keep_grouping():
    # Round 8, item 2 (exact counterexamples, verified against
    # compiled C): intermediate typed folds keep their grouping, so
    # (A+B)*2 folds to 4 and (9-1)/2 folds to 4, contradicting the
    # held (flags & 4) in both denying conditions.
    header = "#define A8 1\n#define B8 1\n"
    verdict = _simulate_header(
        "nested_fold_contra",
        header,
        "\tif ((flags & 4) && !(flags & ((A8 + B8) * 2))) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    verdict = _simulate_source(
        "nested_div_contra",
        "\tif ((flags & 4) && !(flags & ((9 - 1) / 2))) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # The folded mask is genuinely 4: the positive test grants.
    verdict = _simulate_header(
        "nested_fold_mask4",
        header,
        "\tif ((flags & ((A8 + B8) * 2))) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # A nested subtraction feeding a shift keeps its grouping too:
    # (8-2)>>1 is 3, contradicting the held (flags & 3) exclusion.
    verdict = _simulate_source(
        "nested_shift_contra",
        "\tif ((flags & 3) && !(flags & ((8 - 2) >> 1))) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # Pinned pipeline constants fold the same way through values.
    verdict = _simulate_values(
        "nested_pinned_contra",
        "\tif ((flags & 4) && !(flags & ((PA8 + PB8) * 2))) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",), {"PA8": 1, "PB8": 1})
    assert verdict["probe_fn"]["types"] == set()


def test_kfunc_filter_bindings_respect_position_and_writes():
    # Round 8, item 3 (exact counterexamples, verified against
    # compiled C): a use before any declaration sees the outer
    # meaning, and a reassigned shadow no longer carries its
    # initializer. Both shapes are outside the proven set and fail
    # closed instead of resolving through the wrong binding.
    header = ("enum bpf_prog_type {\n"
              "\tBPF_PROG_TYPE_UNSPEC = 0,\n"
              "\tBPF_PROG_TYPE_XDP = 6,\n"
              "\tBPF_PROG_TYPE_TRACING = 26,\n"
              "};\n")
    callers = ("BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_TRACING")
    try:
        _simulate_header(
            "use_before_decl",
            header,
            "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
            "\tu32 BPF_PROG_TYPE_XDP = BPF_PROG_TYPE_TRACING;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            callers)
    except uc.FilterNotUnderstood as exc:
        assert "before" in str(exc) and "declar" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    try:
        _simulate_header(
            "shadow_reassigned",
            header,
            "\tu32 BPF_PROG_TYPE_XDP = BPF_PROG_TYPE_TRACING;\n"
            "\tBPF_PROG_TYPE_XDP = 0;\n"
            "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            callers)
    except uc.FilterNotUnderstood as exc:
        assert "shadow_reassigned" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A compound write poisons the initializer the same way.
    try:
        _simulate_header(
            "shadow_compound_write",
            header,
            "\tu32 BPF_PROG_TYPE_XDP = BPF_PROG_TYPE_TRACING;\n"
            "\tBPF_PROG_TYPE_XDP |= 0;\n"
            "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            callers)
    except uc.FilterNotUnderstood as exc:
        assert "shadow_compound_write" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A bare-ident use before its declaration fails closed too.
    try:
        _simulate_source(
            "ident_use_before_decl",
            "\tif (helper) return 0;\n"
            "\tu32 helper = 1;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "before" in str(exc) and "declar" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A membership alias used before its declaration fails closed.
    try:
        _simulate_source(
            "alias_use_before_decl",
            "\tif (mine) return 0;\n"
            "\tbool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "before" in str(exc) and "declar" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A reassigned local that no condition consults is not an
    # over-rejection: the filter still evaluates.
    verdict = _simulate_source(
        "reassigned_unused_ok",
        "\tu32 tmp = 1;\n"
        "\ttmp = 2;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # In-order shadowing still resolves (no over-rejection).
    verdict = _simulate_header(
        "shadow_in_order_ok",
        header,
        "\tu32 BPF_PROG_TYPE_XDP = BPF_PROG_TYPE_TRACING;\n"
        "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        callers)
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_unprovable_local_idents_reject():
    # Round 8, item 4 (exact counterexample, verified against
    # compiled C): a local initialized from a non-constant
    # expression is not a constant. A bare use fails closed instead
    # of substituting false by spelling (which denied XDP).
    try:
        _simulate_source(
            "bool_expr_ident",
            "\tbool FALSE = prog->type == BPF_PROG_TYPE_XDP;\n"
            "\tif (FALSE) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_TRACING"))
    except uc.FilterNotUnderstood as exc:
        assert "bool_expr_ident" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # Negation does not make the spelling constant either.
    try:
        _simulate_source(
            "bool_expr_negated",
            "\tbool TRUE = prog->type == BPF_PROG_TYPE_XDP;\n"
            "\tif (!TRUE) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_TRACING"))
    except uc.FilterNotUnderstood as exc:
        assert "bool_expr_negated" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A parameter-fed local is unprovable the same way.
    try:
        _simulate_source(
            "param_fed_ident",
            "\tu32 flag = kfunc_id;\n"
            "\tif (flag) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "param_fed_ident" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # An uninitialized local used bare fails closed too.
    try:
        _simulate_source(
            "uninit_ident",
            "\tu32 helper;\n"
            "\tif (helper) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "uninit_ident" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: provable locals still fold and plain
    # spellings still classify.
    verdict = _simulate_source(
        "provable_ident_ok",
        "\tu32 FALSE = 2;\n"
        "\tif (FALSE) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Round 9, item 1 narrows the grammar: an unbound name in allow
    # position rejects (only bit tests keep existential grants).
    try:
        _simulate_source(
            "unbound_ident_ok",
            "\tif (flags) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "unbound_ident_ok" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    verdict = _simulate_source(
        "plain_false_ok",
        "\tif (FALSE) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()


def test_fixture_unprovable_bool_ident_denies_and_flags():
    # Round 8, item 4 at inventory level: the XDP-registered
    # source-backed filter denies with an owner-review flag instead
    # of silently denying XDP without one.
    body = ("\tbool FALSE = prog->type == BPF_PROG_TYPE_XDP;\n"
            "\tif (FALSE)\n"
            "\t\treturn 0;\n"
            "\treturn -EACCES;\n")
    with tempfile.TemporaryDirectory() as tmp:
        fixture = _fixture_with_filter(
            tmp, "boolexpr", "bpf_fixture_boolexpr",
            "boolexpr_kfunc_ids", body)
        _, _, registry = fixture.extract()
        records = {entry["id"]: entry for entry in registry["records"]}
        entry = records["kfunc:bpf_fixture_boolexpr"]
        assert entry["helpers_or_kfuncs"][0]["callable"] is False
        assert len(entry["needs_owner_review"]) == 1
        assert any(line.startswith("NEEDS-OWNER: ")
                   for line in entry["callable_context_predicates"])
        errors = uc.check_completeness(registry)
        assert any("kfunc:bpf_fixture_boolexpr: needs owner review" in line
                   for line in errors), errors


def test_kfunc_filter_bool_conversion_ignores_qualifier_order():
    # Round 8, item 5 (exact counterexample, verified against
    # compiled C): a bool-qualified local converts its initializer
    # (nonzero becomes 1) wherever the qualifier sits, so the
    # comparison binds type 1 rather than the TRACING value.
    header = ("enum bpf_prog_type {\n"
              "\tBPF_PROG_TYPE_UNSPEC = 0,\n"
              "\tBPF_PROG_TYPE_SOCKET_FILTER = 1,\n"
              "\tBPF_PROG_TYPE_XDP = 6,\n"
              "\tBPF_PROG_TYPE_TRACING = 26,\n"
              "};\n")
    callers = ("BPF_PROG_TYPE_SOCKET_FILTER", "BPF_PROG_TYPE_XDP",
               "BPF_PROG_TYPE_TRACING")
    for tag, decl in (
            ("post", "bool const BPF_PROG_TYPE_XDP"),
            ("pre", "const bool BPF_PROG_TYPE_XDP"),
            ("static_post", "static bool const BPF_PROG_TYPE_XDP"),
            ("volatile_post", "bool volatile BPF_PROG_TYPE_XDP"),
            ("under_post", "_Bool const BPF_PROG_TYPE_XDP")):
        verdict = _simulate_header(
            "qualbool_%s" % tag,
            header,
            "\t%s = BPF_PROG_TYPE_TRACING;\n"
            "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
            "\treturn -EACCES;\n" % decl,
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            callers)
        assert verdict["probe_fn"]["types"] == \
            {"BPF_PROG_TYPE_SOCKET_FILTER"}, tag
    # A zero initializer still converts to zero.
    verdict = _simulate_header(
        "qualbool_zero",
        header,
        "\tbool const BPF_PROG_TYPE_XDP = BPF_PROG_TYPE_UNSPEC;\n"
        "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        callers)
    assert verdict["probe_fn"]["types"] == set()
    # A comma declarator under a qualified bool converts too.
    verdict = _simulate_header(
        "qualbool_comma",
        header,
        "\tbool const helper = 0, BPF_PROG_TYPE_XDP = 26;\n"
        "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        callers)
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_SOCKET_FILTER"}


def test_kfunc_filter_bool_decl_scanner_covers_all_spellings():
    # Round 8, item 6 (exact counterexample, verified against
    # compiled C): _Bool declares exactly like bool, so a compound
    # membership initializer is rejected rather than granted.
    _expect_unrecognized(
        "underbool_compound",
        "\t_Bool mine = btf_id_set8_contains(&probe_ids, kfunc_id)"
        " && false;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "compound membership initializer")
    # A bare _Bool membership call is an ordinary alias.
    verdict = _simulate_source(
        "underbool_alias",
        "\t_Bool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # _Bool alias mutations fail closed like bool ones.
    _expect_unrecognized(
        "underbool_reassign",
        "\t_Bool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tmine = false;\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "reassigns membership alias")
    _expect_unrecognized(
        "underbool_shadow",
        "\t_Bool mine = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\t{ _Bool mine = false; (void)mine; }\n"
        "\tif (mine) return 0;\n"
        "\treturn -EACCES;\n",
        "redeclares membership alias")
    # A parenthesized _Bool declarator binds the same way.
    _expect_unrecognized(
        "underbool_paren_arm",
        "\t_Bool (ELOCAL_UNDER) = 1;\n"
        "\treturn (false) ? 0 : -ELOCAL_UNDER;\n",
        "non-constant arm")


def test_kfunc_filter_mask_equivalence_contradicts():
    # Round 8, item 7 (exact counterexamples, verified against
    # compiled C): mask literals canonicalize across
    # signedness/width/spelling before contradiction detection, and
    # subset masks contradict their supersets.
    verdict = _simulate_source(
        "mask_sign_contra",
        "\tif ((flags & 8) && !(flags & 8U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    verdict = _simulate_source(
        "mask_subset_contra",
        "\tif ((flags & 8U) && !(flags & 24U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # A pinned named mask contradicts the same literal mask.
    verdict = _simulate_values(
        "mask_named_contra",
        "\tif ((flags & F8) && !(flags & 8U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",), {"F8": 8})
    assert verdict["probe_fn"]["types"] == set()
    # Reversed order and wider spellings contradict the same way.
    verdict = _simulate_source(
        "mask_subset_reversed",
        "\tif (!(flags & 24U) && (flags & 8U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_source(
        "mask_width_contra",
        "\tif ((flags & 8L) && !(flags & 8UL)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # Hex and octal spellings of the same mask contradict too.
    verdict = _simulate_source(
        "mask_base_contra",
        "\tif ((flags & 0x8) && !(flags & 010)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # The other subset direction stays satisfiable (flags = 16).
    verdict = _simulate_source(
        "mask_superset_ok",
        "\tif ((flags & 24U) && !(flags & 8U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Disjoint masks and distinct operands stay satisfiable.
    verdict = _simulate_source(
        "mask_disjoint_ok",
        "\tif ((flags & 8) && !(flags & 16)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "mask_operand_ok",
        "\tif ((flags & 8) && !(other & 8U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_impossible_compound_groups_deny():
    # Round 8, item 8 (exact counterexamples, verified against
    # compiled C): bit algebra proves the compound groups
    # impossible, so the branches grant nothing.
    for tag, cond in (
            ("nested_and", "((flags & 1) & 2)"),
            ("nested_and_swapped", "((flags & 2) & 1)"),
            ("self_andnot", "(flags & ~flags)"),
            ("self_andnot_swapped", "(~flags & flags)"),
            ("xor_zero_and", "(flags & (flags ^ flags))")):
        verdict = _simulate_source(
            "impossible_%s" % tag,
            "\tif (%s) return 0;\n"
            "\treturn -EACCES;\n" % cond,
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
        assert verdict["probe_fn"]["types"] == set(), tag
        assert verdict["probe_fn"]["alternatives"] == [], tag
    # An impossible deny guard is vacuous and still falls through.
    verdict = _simulate_source(
        "impossible_deny_guard",
        "\tif (((flags & 1) & 2)) return -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Satisfiable compounds still grant (no over-rejection).
    verdict = _simulate_source(
        "compound_or_ok",
        "\tif (((flags & 1) | 2)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "compound_and_ok",
        "\tif (((flags & 3) & 2)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_macros_expand_textually():
    # Round 8, item 9 (exact counterexample, verified against
    # compiled C): SUM expands textually, so TEST is (1+1*2==3),
    # which is true, and the arm denies.
    header = ("#define SUM9 1 + 1\n"
              "#define TEST9 (SUM9 * 2 == 3)\n")
    verdict = _simulate_header(
        "textual_macro",
        header,
        "\treturn (false) ? 0 : -TEST9;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # A shift body in a tighter arithmetic context diverges the
    # same way: textually 8>>1*2==8 parses as 8>>2==8, which is
    # false, so the arm allows.
    header2 = ("#define D9 8 >> 1\n"
               "#define E9 (D9 * 2 == 8)\n")
    verdict = _simulate_header(
        "textual_shift_macro",
        header2,
        "\treturn (false) ? 0 : -E9;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # A single-identifier alias over an expression body inherits
    # the textual meaning, not the folded value.
    header3 = ("#define N9 1 + 1\n"
               "#define M9 N9\n"
               "#define T9 (M9 * 2 == 3)\n")
    verdict = _simulate_header(
        "textual_alias_macro",
        header3,
        "\treturn (false) ? 0 : -T9;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # An expression macro in a bit test expands textually too:
    # (flags & 0&flags) absorbs zero, so the branch never fires.
    header4 = "#define M9B 0 & flags\n"
    verdict = _simulate_header(
        "textual_bit_macro",
        header4,
        "\tif ((flags & M9B)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # Textual expansion also repairs the other direction: the
    # folded value 0 would deny, but (flags & 1^1) is satisfiable.
    verdict = _simulate_header(
        "textual_xor_body",
        "#define Z9 1 ^ 1\n",
        "\tif ((flags & Z9)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # No over-rejection: single-token and parenthesized macros
    # evaluate exactly as before.
    verdict = _simulate_header(
        "atomic_macro_ok",
        "#define K9 8\n",
        "\tif ((flags & K9)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_header(
        "paren_macro_ok",
        "#define P9 (1 + 1)\n"
        "#define Q9 (P9 * 2 == 4)\n",
        "\treturn (false) ? 0 : -Q9;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()


def test_kfunc_filter_enum_consts_use_value_types():
    # Round 8, item 10 (exact counterexample, verified against
    # compiled C): the enumerator has type int (its value fits), so
    # -ONE < 0 is true and the arm denies.
    header = ("enum { ONE10 = 1U };\n"
              "#define TEST10 (-ONE10 < 0)\n")
    verdict = _simulate_header(
        "enum_value_type",
        header,
        "\treturn (false) ? 0 : -TEST10;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["alternatives"] == []
    # A local enumerator types by value the same way: -LL < 0 is
    # true, so the guard grants.
    verdict = _simulate_source(
        "enum_local_value_type",
        "\tenum { LL10 = 1U };\n"
        "\tu32 guard = (-LL10 < 0);\n"
        "\tif (guard) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # A zero-valued unsigned enumerator is int zero.
    verdict = _simulate_header(
        "enum_zero_unsigned",
        "enum { ZED10 = 0U };\n"
        "#define ZT10 (-ZED10 < 0)\n",
        "\treturn (false) ? 0 : -ZT10;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # A value needing unsigned int keeps unsigned type: -EU10 < 0
    # is false, so the arm allows.
    verdict = _simulate_header(
        "enum_wide_unsigned",
        "enum { EU10 = 2147483648U };\n"
        "#define EUT10 (-EU10 < 0)\n",
        "\treturn (false) ? 0 : -EUT10;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_narrow_inits_convert_before_use():
    # Round 8, item 11 (exact counterexamples, verified against
    # compiled C): initializers convert to the declared narrow type
    # (modulo wraparound) before any promotion or use.
    verdict = _simulate_header(
        "narrow_short_wrap",
        "static const unsigned short ESHORT11 = 65536U;\n",
        "\treturn -ESHORT11;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_header(
        "narrow_char_wrap",
        "static const unsigned char ECHAR11 = 256U;\n"
        "#define TEST11 (ECHAR11 == 0)\n",
        "\treturn (false) ? 0 : -TEST11;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # A body-local narrow initializer wraps the same way.
    verdict = _simulate_source(
        "narrow_local_wrap",
        "\tunsigned short guard = 65536U;\n"
        "\tif (guard) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # A signed narrow wraps modulo its width: 65536 becomes 0.
    verdict = _simulate_header(
        "narrow_signed_wrap",
        "static const short SNARROW11 = 65536;\n",
        "\treturn -SNARROW11;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # A bool object converts nonzero to 1.
    verdict = _simulate_header(
        "narrow_bool_conv",
        "static const bool BCONV11 = 2;\n"
        "#define BT11 (BCONV11 == 1)\n",
        "\treturn (false) ? 0 : -BT11;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # In-range narrow values are unaffected (no over-rejection).
    verdict = _simulate_header(
        "narrow_in_range_ok",
        "static const unsigned short SMALL11 = 5;\n",
        "\treturn -SMALL11;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()


def test_kfunc_filter_errno_undef_and_file_bindings_reject():
    # Round 8, item 12 (exact counterexamples, verified against
    # compiled C): #undef and file-scope bindings defeat the errno
    # table. Unsupported bindings reject instead of substituting
    # the tabled value.
    try:
        _simulate_header(
            "errno_undef_bound",
            "#undef EPERM\n"
            "static int EPERM = 0;\n",
            "\treturn (false) ? 0 : -EPERM;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "non-constant arm" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A const object through an unresolvable typedef is an
    # unsupported binding: it rejects rather than reading the
    # table.
    try:
        _simulate_header(
            "errno_typedef_const",
            "typedef int myint12;\n"
            "static const myint12 EIO = 0;\n",
            "\treturn (false) ? 0 : -EIO;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "non-constant arm" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A mutable file binding defeats the table even without #undef.
    try:
        _simulate_header(
            "errno_mutable_file",
            "static int EPERM = 0;\n",
            "\treturn (false) ? 0 : -EPERM;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "non-constant arm" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # An #undef with no replacement binding is unresolvable too.
    try:
        _simulate_header(
            "errno_undef_only",
            "#undef EPERM\n",
            "\treturn (false) ? 0 : -EPERM;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "non-constant arm" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: genuine errno macros, file const objects
    # shadowing the table, and unrelated #undefs behave as before.
    verdict = _simulate_source(
        "errno_table_ok",
        "\treturn (false) ? 0 : -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_header(
        "errno_const_obj_ok",
        "static const int EACCES = 0;\n",
        "\treturn (false) ? 0 : -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_header(
        "errno_other_undef_ok",
        "#undef SOME_OTHER_MACRO\n",
        "\treturn (false) ? 0 : -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()


def test_kfunc_filter_wide_inits_convert_before_use():
    # Round 9, item 2 (exact counterexamples, verified against
    # compiled C at -O0 and -O2): a wide initializer converts to the
    # declared 32-bit type (modulo 2**32) before any use, so
    # 4294967296ULL becomes 0 and denies ...
    verdict = _simulate_source(
        "u32_wrap_deny",
        "\tu32 FALSE = 4294967296ULL;\n"
        "\tif (FALSE) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # ... and the reversed guard allows through the dead deny.
    verdict = _simulate_source(
        "u32_wrap_allow",
        "\tu32 TRUE = 4294967296ULL;\n"
        "\tif (TRUE) return -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Further probes: an unsigned negative wraps to nonzero and
    # grants, exactly as C does.
    verdict = _simulate_source(
        "u32_negative_wraps",
        "\tu32 neg = -1;\n"
        "\tif (neg) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # A signed out-of-range initializer is implementation-defined,
    # so the local stays unproven and its bare use rejects.
    try:
        _simulate_source(
            "int_over_unproven",
            "\tint over = 4294967296;\n"
            "\tif (over) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "int_over_unproven" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: in-range values, signed negatives and
    # 64-bit locals behave exactly as before.
    verdict = _simulate_source(
        "u32_in_range_ok",
        "\tu32 small = 5;\n"
        "\tif (small) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "int_negative_ok",
        "\tint neg = -5;\n"
        "\tif (neg) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "long_wide_ok",
        "\tlong big = 4294967296;\n"
        "\tif (big) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_parenthesized_writes_discard_values():
    # Round 9, item 3 (exact counterexample, verified against
    # compiled C at -O0 and -O2): C honors the parenthesized write,
    # so the stale zero must not decide. The write discards the
    # provable value and the bare use rejects instead of denying.
    try:
        _simulate_source(
            "paren_write_stale",
            "\tu32 FALSE = 0;\n"
            "\t(FALSE) = 1;\n"
            "\tif (FALSE) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "paren_write_stale" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # Further probes: nested parens, compound assignment and
    # address-takes through parens discard the same way.
    for tag, stmt in (
            ("nested", "\t((FALSE)) = 1;\n"),
            ("compound", "\t(FALSE) |= 1;\n"),
            ("addr", "\tuse_probe(&(FALSE));\n")):
        try:
            _simulate_source(
                "paren_write_%s" % tag,
                "\tu32 FALSE = 0;\n"
                "%s"
                "\tif (FALSE) return 0;\n"
                "\treturn -EACCES;\n" % stmt,
                ("probe_fn",), {"probe_ids": {"probe_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert ("paren_write_%s" % tag) in str(exc), exc
        else:
            raise AssertionError(
                "expected FilterNotUnderstood for %s" % tag)
    # No over-rejection: a parenthesized write to an unused local,
    # and a parenthesized declarator with no later write, behave as
    # their plain forms.
    verdict = _simulate_source(
        "paren_write_unused_ok",
        "\tu32 tmp = 0;\n"
        "\t(tmp) = 1;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "paren_declarator_ok",
        "\tu32 (ready) = 1;\n"
        "\tif (ready) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_chained_inits_resolve_through_bindings():
    # Round 9, item 4 (exact counterexample, verified against
    # compiled C at -O0 and -O2): a chained initializer resolves
    # through the binding table -- ready takes FALSE's value 1 and
    # permits -- instead of guessing false by spelling.
    verdict = _simulate_source(
        "chain_bool_permit",
        "\tbool FALSE = true;\n"
        "\tbool ready = FALSE;\n"
        "\tif (ready) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # The mirrored shadow chain denies exactly as C does.
    verdict = _simulate_source(
        "chain_shadow_deny",
        "\tu32 TRUE = 0;\n"
        "\tbool ready = TRUE;\n"
        "\tif (ready) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # A chain through an unproven binding rejects rather than
    # substituting false by spelling.
    try:
        _simulate_source(
            "chain_unproven_reject",
            "\tbool FALSE = prog->type == BPF_PROG_TYPE_XDP;\n"
            "\tbool ready = FALSE;\n"
            "\tif (ready) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "chain_unproven_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A forward reference stays unproven: C sees no binding there.
    try:
        _simulate_source(
            "chain_forward_reject",
            "\tbool ready = FALSE;\n"
            "\tbool FALSE = true;\n"
            "\tif (ready) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "chain_forward_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: plain u32 chains and unbound spellings
    # behave exactly as before.
    verdict = _simulate_source(
        "chain_u32_ok",
        "\tu32 one = 1;\n"
        "\tu32 two = one;\n"
        "\tif (two) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "chain_unbound_spelling_ok",
        "\tbool ready = TRUE;\n"
        "\tif (ready) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_compared_member_writes_reject():
    # Round 9, item 6 (exact counterexample, verified against
    # compiled C at -O0 and -O2): the skipped write decides the
    # later comparison in C, so the filter rejects instead of
    # granting under the stale restriction.
    try:
        _simulate_source(
            "stops_write_stale",
            "\tprog->aux->st_ops = &other_ops;\n"
            "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "stops_write_stale" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # Further probes: writes to compared type/attach members,
    # compound writes, parenthesized targets, writes through
    # another pointer (which may alias), writes to an intermediate
    # path, address-takes and calls that may mutate compared
    # state all reject.
    probes = (
        ("type_write",
         "\tprog->type = BPF_PROG_TYPE_TRACING;\n"
         "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
         "\treturn -EACCES;\n"),
        ("attach_compound",
         "\tprog->expected_attach_type |= 1;\n"
         "\tif (prog->expected_attach_type == BPF_TRACE_ITER)\n"
         "\t\treturn 0;\n"
         "\treturn -EACCES;\n"),
        ("paren_target",
         "\t(prog->aux->st_ops) = &other_ops;\n"
         "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
         "\treturn -EACCES;\n"),
        ("alias_ptr",
         "\tq->st_ops = &other_ops;\n"
         "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
         "\treturn -EACCES;\n"),
        ("intermediate",
         "\tprog->aux = other_aux;\n"
         "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
         "\treturn -EACCES;\n"),
        ("addr_take",
         "\tsave_ops(&prog->aux->st_ops);\n"
         "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
         "\treturn -EACCES;\n"),
        ("mutating_call",
         "\tset_st_ops(prog);\n"
         "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
         "\treturn -EACCES;\n"),
    )
    for tag, body in probes:
        try:
            _simulate_source(
                "compared_write_%s" % tag, body,
                ("probe_fn",), {"probe_ids": {"probe_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert ("compared_write_%s" % tag) in str(exc), exc
        else:
            raise AssertionError(
                "expected FilterNotUnderstood for %s" % tag)
    # No over-rejection: writes to uncompared members, reads of
    # compared members, and value calls still evaluate exactly.
    verdict = _simulate_source(
        "uncompared_write_ok",
        "\tprog->uncompared = 1;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "compared_read_ok",
        "\tu32 moff = prog->aux->attach_st_ops_member_off;\n"
        "\t(void)moff;\n"
        "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "value_call_ok",
        "\tuse_probe(kfunc_id);\n"
        "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_wide_masks_fold_or_reject():
    # Round 9, item 5 (exact counterexample, verified against
    # compiled C at -O0 and -O2): bit 32 of a u32 operand is
    # provably zero, so the allow alternative drops and the filter
    # denies exactly -- with no invented attach-context note.
    verdict = _simulate_source(
        "wide_mask_deny",
        "\tu32 flags = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((flags & 4294967296ULL)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["notes"] == []
    # The negated guard denies exactly too: !(0) is 1, so the deny
    # fires for every caller.
    verdict = _simulate_source(
        "wide_mask_neg_deny",
        "\tu32 flags = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((!(flags & 4294967296ULL))) return -EACCES;\n"
        "\treturn 0;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # An unknown-width operand with a wide mask rejects: the
    # outcome depends on the unproven width.
    try:
        _simulate_source(
            "wide_mask_unknown_reject",
            "\tif ((flags & 4294967296ULL)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "wide_mask_unknown_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # Further probes: narrow widths fold small-but-wide masks.
    verdict = _simulate_source(
        "narrow_mask_deny",
        "\tu8 tiny = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((tiny & 256U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["notes"] == []
    # Signed and 64-bit operands stay symbolic (both outcomes are
    # possible), but notes never invent requirements from literal
    # suffixes.
    for tag, decl in (("signed", "\ts32 sval"),
                      ("wide64", "\tu64 big")):
        verdict = _simulate_source(
            "wide_mask_%s_symbolic" % tag,
            "%s = prog->aux->attach_st_ops_member_off;\n"
            "\tif ((%s & 4294967296ULL)) return 0;\n"
            "\treturn -EACCES;\n"
            % (decl, "sval" if tag == "signed" else "big"),
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
        assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
        assert all("ULL attach context" not in note
                   for note in verdict["probe_fn"]["notes"]), \
            verdict["probe_fn"]["notes"]
    # No over-rejection: in-width masks on known widths behave as
    # before.
    verdict = _simulate_source(
        "in_width_mask_ok",
        "\tu32 flags = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((flags & 1U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "mixed_wide_mask_ok",
        "\tu32 flags = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((flags & 4294967297ULL)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_nonbit_opaque_allow_rejects():
    # Round 9, item 1 (exact counterexample, verified against
    # compiled C at -O0 and -O2): sizeof(ready) == 0 always denies
    # in C. The inventory rejects instead of emitting callable
    # permission under an impossible restriction: only bit tests
    # keep existential grants.
    try:
        _simulate_source(
            "sizeof_allow_reject",
            "\tu32 ready = 1;\n"
            "\tif (sizeof(ready) == 0) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "sizeof_allow_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # Further probes: unknown calls, bare unbound idents, foreign
    # members and number comparisons in allow position all reject.
    probes = (
        ("call",
         "\tif (mystery_check(prog)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("ident",
         "\tif (flags) return 0;\n"
         "\treturn -EACCES;\n"),
        ("foreign",
         "\tif (prog->other_field) return 0;\n"
         "\treturn -EACCES;\n"),
        ("number_cmp",
         "\tif (prog->type == 6) return 0;\n"
         "\treturn -EACCES;\n"),
    )
    for tag, body in probes:
        try:
            _simulate_source(
                "opaque_allow_%s" % tag, body,
                ("probe_fn",), {"probe_ids": {"probe_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert ("opaque_allow_%s" % tag) in str(exc), exc
        else:
            raise AssertionError(
                "expected FilterNotUnderstood for %s" % tag)
    # No over-rejection: bit-test allows still grant existentially.
    verdict = _simulate_source(
        "opaque_bit_allow_ok",
        "\tif ((flags & SCX_KF_ALLOW_DISPATCH) &&\n"
        "\t    btf_id_set8_contains(&probe_ids, kfunc_id))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_conditional_inclusion_is_evaluated():
    # Round 9, item 7a (exact counterexample, verified against
    # compiled C at -O0 and -O2): only the active branch defines
    # the macro, so the filter returns -1 and denies exactly.
    verdict = _simulate_header(
        "pp_active_branch",
        "#if 1\n"
        "#define TEST7A 1\n"
        "#else\n"
        "#define TEST7A 0\n"
        "#endif\n",
        "\treturn (false) ? 0 : -TEST7A;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # The mirrored shape evaluates the else branch: -0 allows.
    verdict = _simulate_header(
        "pp_else_branch",
        "#if 0\n"
        "#define TEST7B 1\n"
        "#else\n"
        "#define TEST7B 0\n"
        "#endif\n",
        "\treturn (false) ? 0 : -TEST7B;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # elif chains evaluate in order.
    verdict = _simulate_header(
        "pp_elif_chain",
        "#if 0\n"
        "#define TEST7C 1\n"
        "#elif 1\n"
        "#define TEST7C 2\n"
        "#else\n"
        "#define TEST7C 3\n"
        "#endif\n",
        "\treturn (false) ? 0 : -TEST7C;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # An inactive outer branch skips its unknown inner branch.
    verdict = _simulate_header(
        "pp_nested_skip",
        "#if 0\n"
        "#ifdef CONFIG_PROBE7\n"
        "#define TEST7D 1\n"
        "#endif\n"
        "#else\n"
        "#define TEST7D 0\n"
        "#endif\n",
        "\treturn (false) ? 0 : -TEST7D;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # A non-constant condition over a consulted define rejects.
    try:
        _simulate_header(
            "pp_unknown_reject",
            "#ifdef CONFIG_PROBE7\n"
            "#define TEST7E 1\n"
            "#else\n"
            "#define TEST7E 0\n"
            "#endif\n",
            "\treturn (false) ? 0 : -TEST7E;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "pp_unknown_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # So does a non-constant #elif over a consulted name.
    try:
        _simulate_header(
            "pp_elif_unknown_reject",
            "#if 0\n"
            "#define TEST7F 1\n"
            "#elif CONFIG_PROBE7\n"
            "#define TEST7F 2\n"
            "#else\n"
            "#define TEST7F 3\n"
            "#endif\n",
            "\treturn (false) ? 0 : -TEST7F;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "pp_elif_unknown_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: unknown-region defines of names the
    # filter never consults are ignored.
    verdict = _simulate_header(
        "pp_unconsulted_ok",
        "#ifdef CONFIG_PROBE7\n"
        "#define UNRELATED7 1\n"
        "#else\n"
        "#define UNRELATED7 0\n"
        "#endif\n",
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()


def test_kfunc_filter_load_bearing_redefines_reject():
    # Round 9, item 7b (exact counterexample, verified against
    # compiled C at -O0 and -O2): redefining the load-bearing
    # BPF_PROG_TYPE_XDP as TRACING rejects instead of permitting
    # the wrong caller.
    header = ("enum bpf_prog_type {\n"
              "\tBPF_PROG_TYPE_UNSPEC = 0,\n"
              "\tBPF_PROG_TYPE_XDP = 6,\n"
              "\tBPF_PROG_TYPE_TRACING = 26,\n"
              "};\n"
              "#define BPF_PROG_TYPE_XDP BPF_PROG_TYPE_TRACING\n")
    try:
        _simulate_header(
            "pp_redefine_reject", header,
            "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_TRACING"))
    except uc.FilterNotUnderstood as exc:
        assert "pp_redefine_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # The pipeline-pinned form rejects the same way.
    texts = {"kernel/bpf/probe.c": uc.strip_comments(
        "#define BPF_PROG_TYPE_XDP 26\n"
        "static int pp_redefine_pipe(const struct bpf_prog *prog,"
        " u32 kfunc_id)\n{\n"
        "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
        "\treturn -EACCES;\n}\n")}
    try:
        uc.simulate_kfunc_filter(
            "pp_redefine_pipe", texts, "v9", ["probe_fn"],
            {"probe_ids": {"probe_fn"}},
            ["BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_TRACING"],
            const_values={"BPF_PROG_TYPE_XDP": 6,
                          "BPF_PROG_TYPE_TRACING": 26})
    except uc.FilterNotUnderstood as exc:
        assert "pp_redefine_pipe" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # An active #undef of a consulted pipeline name rejects too:
    # uses past it are undeclared in C.
    texts = {"kernel/bpf/probe.c": uc.strip_comments(
        "#undef BPF_PROG_TYPE_XDP\n"
        "static int pp_undef_pipe(const struct bpf_prog *prog,"
        " u32 kfunc_id)\n{\n"
        "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
        "\treturn -EACCES;\n}\n")}
    try:
        uc.simulate_kfunc_filter(
            "pp_undef_pipe", texts, "v9", ["probe_fn"],
            {"probe_ids": {"probe_fn"}},
            ["BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_TRACING"],
            const_values={"BPF_PROG_TYPE_XDP": 6,
                          "BPF_PROG_TYPE_TRACING": 26})
    except uc.FilterNotUnderstood as exc:
        assert "pp_undef_pipe" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: a benign same-value restatement and an
    # unconsulted redefine evaluate as before.
    header_ok = ("enum bpf_prog_type {\n"
                 "\tBPF_PROG_TYPE_UNSPEC = 0,\n"
                 "\tBPF_PROG_TYPE_XDP = 6,\n"
                 "\tBPF_PROG_TYPE_TRACING = 26,\n"
                 "};\n"
                 "#define BPF_PROG_TYPE_XDP 6\n")
    verdict = _simulate_header(
        "pp_benign_ok", header_ok,
        "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_TRACING"))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_XDP"}
    header_other = ("enum bpf_prog_type {\n"
                    "\tBPF_PROG_TYPE_UNSPEC = 0,\n"
                    "\tBPF_PROG_TYPE_XDP = 6,\n"
                    "\tBPF_PROG_TYPE_TRACING = 26,\n"
                    "};\n"
                    "#define BPF_PROG_TYPE_TRACING 99\n")
    verdict = _simulate_header(
        "pp_unconsulted_redefine_ok", header_other,
        "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_XDP", "BPF_PROG_TYPE_TRACING"))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_XDP"}


def test_kfunc_filter_excluded_filters_and_body_directives_reject():
    # A filter C never sees (provably excluded) yields no
    # permission instead of evaluating dead text.
    texts = {"kernel/bpf/probe.c": uc.strip_comments(
        "#if 0\n"
        "static int pp_excluded_reject(const struct bpf_prog *prog,"
        " u32 kfunc_id)\n{\n\treturn 0;\n}\n"
        "#endif\n")}
    try:
        uc.simulate_kfunc_filter(
            "pp_excluded_reject", texts, "v9", ["probe_fn"],
            {"probe_ids": {"probe_fn"}},
            ["BPF_PROG_TYPE_TRACING", ])
    except uc.FilterNotUnderstood as exc:
        assert "pp_excluded_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A filter under a non-constant conditional rejects too.
    texts = {"kernel/bpf/probe.c": uc.strip_comments(
        "#ifdef CONFIG_PROBE7\n"
        "static int pp_guarded_reject(const struct bpf_prog *prog,"
        " u32 kfunc_id)\n{\n\treturn 0;\n}\n"
        "#endif\n")}
    try:
        uc.simulate_kfunc_filter(
            "pp_guarded_reject", texts, "v9", ["probe_fn"],
            {"probe_ids": {"probe_fn"}},
            ["BPF_PROG_TYPE_TRACING", ])
    except uc.FilterNotUnderstood as exc:
        assert "pp_guarded_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # Directives inside the body are outside the grammar --
    # including a conditionally-excluded grant, which must never
    # evaluate.
    for tag, body in (
            ("if", "\t#if 1\n\treturn 0;\n"),
            ("define", "\t#define INNER7 1\n\treturn 0;\n"),
            ("hidden",
             "\t#if 0\n"
             "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
             "\t#endif\n"
             "\treturn -EACCES;\n")):
        try:
            _simulate_source(
                "pp_body_%s_reject" % tag, body,
                ("probe_fn",), {"probe_ids": {"probe_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert ("pp_body_%s_reject" % tag) in str(exc), exc
            assert "outside the grammar" in str(exc), exc
        else:
            raise AssertionError(
                "expected FilterNotUnderstood for %s" % tag)


def test_kfunc_filter_bitplace_operands_reject():
    # Round 10, item 1 (exact counterexample, verified against
    # compiled C at -O0 and -O2): sizeof(ready) is 4 for a u32,
    # so (4 & 8) is 0 and C always denies. The inventory rejects
    # instead of granting an impossible restriction: sizeof is
    # not a bit-testable operand.
    _expect_unrecognized(
        "bitop_sizeof_reject",
        "\tu32 ready = 1;\n"
        "\tif ((sizeof(ready) & 8U)) return 0;\n"
        "\treturn -EACCES;\n",
        "bit-test")
    # Further probes, each verified against compiled C (always
    # deny at -O0 and -O2): masked unknown calls, ternaries and
    # zero-initialized array reads in bit positions reject too.
    probes = (
        ("call",
         "\tif ((mystery10() & 1)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("ternary",
         "\tint c = 0, a = 0, b = 0;\n"
         "\tif (((c ? a : b) & 1)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("array",
         "\tint arr[4] = {0, 0, 0, 0};\n"
         "\tif ((arr[0] & 1)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("shifted_call",
         "\tif (((mystery10() >> 1) & 1)) return 0;\n"
         "\treturn -EACCES;\n"),
    )
    for tag, body in probes:
        _expect_unrecognized(
            "bitop_%s_reject" % tag, body, "bit-test")
    # No over-rejection: plain flag tests over known widths keep
    # their existential grants. (Round 11 overrides the old comma
    # pin: the comma group granted XDP where C denies, so it
    # rejects as an unproven operand now.)
    verdict = _simulate_source(
        "bitop_plain_ok",
        "\tu32 flags = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((flags & 1U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    _expect_unrecognized(
        "bitop_comma_ok",
        "\tif ((0 & flags, prog->type == BPF_PROG_TYPE_TRACING))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        "bit-testable")


def test_kfunc_filter_composed_widths_fold_or_reject():
    # Round 10, item 2 (exact counterexample, verified against
    # compiled C at -O0 and -O2): (flags ^ 1U) is a u32, so bit
    # 32 is provably zero and C always denies. The literal's type
    # is canonicalized away, so the composed width is unproven
    # and the inventory rejects instead of granting.
    _expect_unrecognized(
        "xor_wide_reject",
        "\tu32 flags = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((flags ^ 1U) & 4294967296ULL)) return 0;\n"
        "\treturn -EACCES;\n",
        "width")
    # An unknown-width leaf poisons the composed width the same
    # way: the wide mask rejects instead of granting.
    _expect_unrecognized(
        "xor_unknown_leaf_reject",
        "\tu32 flags = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((flags ^ mystery_global10) & 4294967296ULL))\n"
        "\t\treturn 0;\n"
        "\treturn -EACCES;\n",
        "width")
    # Further probes, each verified against compiled C (always
    # deny at -O0 and -O2): shifted operands, explicit narrowing
    # casts and variable-only XOR carry proven widths, so the
    # provably-zero tests deny exactly.
    verdict = _simulate_source(
        "shift_wide_deny",
        "\tu32 flags = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((flags << 1) & 4294967296ULL)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["notes"] == []
    verdict = _simulate_source(
        "cast_wide_deny",
        "\tu64 big = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((((u32)big) & 4294967296ULL)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["notes"] == []
    verdict = _simulate_source(
        "varxor_wide_deny",
        "\tu32 first = prog->aux->attach_st_ops_member_off;\n"
        "\tu32 second = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((first ^ second) & 4294967296ULL)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    assert verdict["probe_fn"]["notes"] == []
    # No over-rejection: a signed composed operand stays
    # symbolic (sign extension may set high bits).
    verdict = _simulate_source(
        "shift_signed_symbolic",
        "\ts32 sval = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((sval << 1) & 4294967296ULL)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_aliased_calls_invalidate():
    # Round 10, item 3 (exact counterexample, verified against
    # compiled C at -O0 and -O2): the call mutates through the
    # local copy, so the later comparison always denies. The
    # inventory rejects instead of granting under stale state.
    _expect_unrecognized(
        "alias_call_reject",
        "\tstruct bpf_prog_aux *q = prog->aux;\n"
        "\tmutate_aux10(q);\n"
        "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
        "\treturn -EACCES;\n",
        "compared member state")
    # Further probes: transitive copies, whole-prog copies and
    # post-declaration bindings all invalidate compared state.
    probes = (
        ("transitive",
         "\tstruct bpf_prog_aux *q = prog->aux;\n"
         "\tstruct bpf_prog_aux *r = q;\n"
         "\tmutate_aux10(r);\n"
         "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
         "\treturn -EACCES;\n"),
        ("whole_prog",
         "\tconst struct bpf_prog *held = prog;\n"
         "\tmutate_prog10(held);\n"
         "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
         "\treturn -EACCES;\n"),
        ("late_bind",
         "\tstruct bpf_prog_aux *q;\n"
         "\tq = prog->aux;\n"
         "\tmutate_aux10(q);\n"
         "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
         "\treturn -EACCES;\n"),
    )
    for tag, body in probes:
        _expect_unrecognized(
            "alias_call_%s_reject" % tag, body,
            "compared member state")
    # No over-rejection: value calls still evaluate exactly.
    verdict = _simulate_source(
        "alias_value_ok",
        "\tuse_probe10(kfunc_id);\n"
        "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Corpus shape (7.2.9 scx/qdisc filters): integer locals
    # declared without an initializer and assigned later are
    # still proven value types, whether plain-declared or the
    # last declarator of a multi-declarator; passing them by
    # value to a call invalidates no compared member state.
    for tag, decl, target in (
            ("plain_uninit", "\tu32 moff;\n", "moff"),
            ("comma_last", "\tu32 moff, flags;\n", "flags")):
        verdict = _simulate_source(
            "alias_value_local_%s_ok" % tag,
            "%s"
            "\t%s = prog->aux->attach_st_ops_member_off;\n"
            "\tuse_probe10(%s);\n"
            "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
            "\treturn -EACCES;\n" % (decl, target, target),
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
        assert verdict["probe_fn"]["types"] == \
            {"BPF_PROG_TYPE_TRACING"}, tag


def test_kfunc_filter_writes_flow_through_copies():
    # Round 10, item 4 (exact counterexample, verified against
    # compiled C at -O0 and -O2): the copy reads the post-write
    # value 0, so C denies. The inventory rejects the stale copy
    # instead of granting.
    _expect_unrecognized(
        "chain_stale_reject",
        "\tu32 TRUE = 1;\n"
        "\t(TRUE) = 0;\n"
        "\tbool ready = TRUE;\n"
        "\tif (ready) return 0;\n"
        "\treturn -EACCES;\n",
        "outside the grammar")
    # The reversed shape (C permits at -O0 and -O2) rejects
    # instead of denying on the stale value.
    _expect_unrecognized(
        "chain_stale_rev_reject",
        "\tu32 TRUE = 0;\n"
        "\t(TRUE) = 1;\n"
        "\tbool ready = TRUE;\n"
        "\tif (ready) return 0;\n"
        "\treturn -EACCES;\n",
        "outside the grammar")
    # A copy made before the write keeps the proven value (C
    # permits; verified against compiled C at -O0 and -O2).
    verdict = _simulate_source(
        "chain_before_write_ok",
        "\tu32 TRUE = 1;\n"
        "\tbool ready = TRUE;\n"
        "\t(TRUE) = 0;\n"
        "\tif (ready) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # A second copy after the write rejects even when an earlier
    # copy was proven.
    _expect_unrecognized(
        "chain_second_copy_reject",
        "\tu32 TRUE = 1;\n"
        "\tbool early = TRUE;\n"
        "\t(TRUE) = 0;\n"
        "\tbool late = TRUE;\n"
        "\tif (late) return 0;\n"
        "\treturn -EACCES;\n",
        "outside the grammar")


def test_kfunc_filter_file_bindings_resolve_by_value():
    # Round 10, item 5 (exact counterexamples, verified against
    # compiled C at -O0 and -O2): file-scope bindings resolve by
    # value -- even mutable ones -- never by spelling.
    verdict = _simulate_header(
        "file_false_permits",
        "static bool FALSE = true;\n",
        "\tbool ready = FALSE;\n"
        "\tif (ready) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_header(
        "file_true_denies",
        "static bool TRUE = false;\n",
        "\tbool ready = TRUE;\n"
        "\tif (ready) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # Direct conditions resolve by value too (C permits).
    verdict = _simulate_header(
        "file_direct_ok",
        "static bool FALSE = true;\n",
        "\tif (FALSE) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # Return arms classify only immutable constants: a mutable
    # binding never decides an arm (round-7/8 pins), so the arm
    # rejects instead of substituting by spelling or value.
    try:
        _simulate_header(
            "file_return_reject",
            "static bool FALSE = true;\n",
            "\tif (prog->type == BPF_PROG_TYPE_TRACING)"
            " return FALSE;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "file_return_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # Parameters stay unproven in every position: their runtime
    # value is invisible (verified against compiled C, which
    # permits for 1 and denies for 0 at -O0 and -O2).
    _expect_unrecognized_params(
        "file_param_init_reject",
        "const struct bpf_prog *prog, u32 TRUE",
        "\tbool ready = TRUE;\n"
        "\tif (ready) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        "outside the grammar")
    _expect_unrecognized_params(
        "file_param_direct_reject",
        "const struct bpf_prog *prog, u32 FALSE",
        "\tif (FALSE) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        "unrecognized")
    # Unresolvable names reject instead of guessing: tentative
    # definitions, undeclared spellings in returns, and mutable
    # bindings with a body write or call are all outside the
    # grammar. (Completely unbound spellings in inits and
    # conditions keep their pinned round-9 legacy guesses.)
    for tag, header, body in (
            ("tentative",
             "static bool FLAG10;\n",
             "\tbool ready = FLAG10;\n"
             "\tif (ready) return 0;\n"
             "\treturn -EACCES;\n"),
            ("undeclared_return",
             "",
             "\treturn TRUE;\n"),
            ("written",
             "static bool FALSE = true;\n",
             "\tbool ready = FALSE;\n"
             "\tFALSE = false;\n"
             "\tif (ready) return 0;\n"
             "\treturn -EACCES;\n"),
            ("called",
             "static bool FALSE = true;\n",
             "\tbool ready = FALSE;\n"
             "\tmutate10();\n"
             "\tif (ready) return 0;\n"
             "\treturn -EACCES;\n")):
        try:
            _simulate_header(
                "file_%s_reject" % tag, header, body,
                ("probe_fn",), {"probe_ids": {"probe_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert ("file_%s_reject" % tag) in str(exc), exc
        else:
            raise AssertionError(
                "expected FilterNotUnderstood for %s" % tag)
    # No over-rejection: lowercase keywords still classify.
    verdict = _simulate_source(
        "file_lower_ok",
        "\tbool ready = true;\n"
        "\tif (ready) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_predicates_use_active_definitions():
    # Round 10, item 6 (exact counterexample, verified against
    # compiled C at -O0 and -O2): the excluded definition never
    # compiles, so C always denies. The inventory inlines only
    # the active definition; here nothing provable inlines, so
    # the filter rejects instead of granting.
    try:
        _simulate_header(
            "pp_pred_excluded_reject",
            "#if 0\n"
            "static bool gate10(const struct bpf_prog *prog)"
            " { return true; }\n"
            "#endif\n"
            "static bool gate10(const struct bpf_prog *prog)\n"
            "{\n"
            "(void)prog;\n"
            "return false;\n"
            "}\n",
            "\tif (gate10(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "pp_pred_excluded_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # Unknown conditional inclusion rejects: the compiled
    # definition depends on flags the inventory cannot see
    # (verified: -DCONFIG_X10 flips the oracle verdict).
    try:
        _simulate_header(
            "pp_pred_unknown_reject",
            "#ifdef CONFIG_X10\n"
            "static bool ugate10(const struct bpf_prog *prog)"
            " { return true; }\n"
            "#else\n"
            "static bool ugate10(const struct bpf_prog *prog)"
            " { return false; }\n"
            "#endif\n",
            "\tif (ugate10(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "pp_pred_unknown_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A helper input redefined 0 -> 1 rejects through the
    # consulted-name check: helper dependencies and their macro
    # inputs count as consulted.
    try:
        _simulate_header(
            "pp_pred_mask_redefine_reject",
            "#define MASK10 0\n"
            "static bool mgate10(const struct bpf_prog *prog)\n"
            "{ return prog->expected_attach_type & MASK10; }\n"
            "#define MASK10 1\n",
            "\tif (mgate10(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "pp_pred_mask_redefine_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: an active single-definition helper still
    # inlines exactly, and an uncalled unknown-region helper is
    # ignored.
    verdict = _simulate_header(
        "pp_pred_active_ok",
        "static bool okgate10(const struct bpf_prog *prog)\n"
        "{ return prog->type == BPF_PROG_TYPE_TRACING; }\n",
        "\tif (okgate10(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    # A provably-included definition inlines too: directive lines
    # never pollute the helper's parsed return type.
    verdict = _simulate_header(
        "pp_pred_if1_ok",
        "#if 1\n"
        "static bool ifgate10(const struct bpf_prog *prog)\n"
        "{ return prog->type == BPF_PROG_TYPE_TRACING; }\n"
        "#endif\n",
        "\tif (ifgate10(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_header(
        "pp_pred_unconsulted_ok",
        "#ifdef CONFIG_X10\n"
        "static bool unused10(const struct bpf_prog *prog)"
        " { return true; }\n"
        "#endif\n",
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()


def test_kfunc_filter_predicates_convert_returns():
    # Round 10, item 7 (exact counterexample, verified against
    # compiled C at -O0 and -O2): the helper converts 256U to
    # (unsigned char)0, so C denies. The inventory converts the
    # inlined constant to the declared return type and denies.
    verdict = _simulate_header(
        "conv_uchar_deny",
        "static unsigned char cgate10(const struct bpf_prog *prog)\n"
        "{ return 256U; }\n",
        "\tif (cgate10(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # A wide constant into a signed int return is
    # implementation-defined, so the helper rejects instead of
    # granting (C denies under gcc at -O0 and -O2, -Woverflow).
    try:
        _simulate_header(
            "conv_wide_int_reject",
            "static int wgate10(const struct bpf_prog *prog)\n"
            "{ return 4294967296ULL; }\n",
            "\tif (wgate10(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "conv_wide_int_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # Converted constants keep bit semantics too: (bool)2 is 1,
    # so bit 1 is clear and C denies (verified at -O0 and -O2).
    verdict = _simulate_header(
        "conv_bool_bit_deny",
        "static bool bgate10(const struct bpf_prog *prog)\n"
        "{ return 2; }\n",
        "\tif ((bgate10(prog) & 2)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    # A symbolic narrowing return keeps its conversion in every
    # position: the wrapped test grants only with its
    # restriction (input-dependent in C at -O0 and -O2).
    verdict = _simulate_header(
        "conv_uchar_sym_ok",
        "static unsigned char sgate10(const struct bpf_prog *prog)\n"
        "{ return prog->type; }\n",
        "\tif (sgate10(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert len(verdict["probe_fn"]["notes"]) == 1
    assert "additionally restricted by conv_uchar_sym_ok" in \
        verdict["probe_fn"]["notes"][0]
    # A symbolic bool helper in a bit test rejects: truth and
    # value differ there and the conversion is unproven.
    try:
        _simulate_header(
            "conv_bool_bitctx_reject",
            "static bool tgate10(const struct bpf_prog *prog)\n"
            "{ return prog->type; }\n",
            "\tif ((tgate10(prog) & 1)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "conv_bool_bitctx_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A signed helper with a symbolic body rejects: its return
    # conversion cannot be proven.
    try:
        _simulate_header(
            "conv_signed_sym_reject",
            "static int igate10(const struct bpf_prog *prog)\n"
            "{ return prog->type; }\n",
            "\tif (igate10(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "conv_signed_sym_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_folded_predicates_keep_dependencies():
    # Round 11, item 1 (exact counterexample, verified against
    # compiled C at -O0 and -O2): the helper body folds to a
    # literal, but C expands MASK11 to 0 at the helper's
    # definition point and denies. The inventory must reject on
    # the redefined dependency, not grant on the folded value.
    try:
        _simulate_header(
            "fold_mask_redefine_reject",
            "#define MASK11 0\n"
            "static bool mgate11(const struct bpf_prog *prog)\n"
            "{ return MASK11 & 1U; }\n"
            "#undef MASK11\n"
            "#define MASK11 1\n",
            "\tif (mgate11(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "fold_mask_redefine_reject" in str(exc), exc
        assert "unproven preprocessor state" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # Exact mutable-binding shape (C denies at -O0 and -O2): the
    # folded literal hides the FALSE11 dependency while a call
    # disturbs it. Rejection names the consulted binding.
    try:
        _simulate_header(
            "fold_mutable_call_reject",
            "static bool FALSE11 = true;\n"
            "static bool fgate11(const struct bpf_prog *prog)\n"
            "{ return FALSE11; }\n",
            "\tuse_probe11();\n"
            "\tif (fgate11(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "fold_mutable_call_reject" in str(exc), exc
        assert "consulting mutable file binding FALSE11" in str(exc), \
            exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # Further probe: a direct body write to the folded
    # dependency rejects the same way (C denies: the gate reads
    # the post-write value).
    try:
        _simulate_header(
            "fold_mutable_write_reject",
            "static bool FALSE11 = true;\n"
            "static bool wgate11(const struct bpf_prog *prog)\n"
            "{ return FALSE11; }\n",
            "\tFALSE11 = false;\n"
            "\tif (wgate11(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "fold_mutable_write_reject" in str(exc), exc
        assert "writes consulted mutable file binding FALSE11" in \
            str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # Further probes: a helper input killed by #undef (C
    # denies: the body expanded the pre-undef value 0) and one
    # defined only after the helper (C fails to compile) both
    # reject instead of inlining an unprovable value.
    try:
        _simulate_header(
            "fold_undef_killed_reject",
            "#define KILL11 0\n"
            "static bool kgate11(const struct bpf_prog *prog)\n"
            "{ return KILL11 & 1U; }\n"
            "#undef KILL11\n",
            "\tif (kgate11(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "fold_undef_killed_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    try:
        _simulate_header(
            "fold_late_define_reject",
            "static bool lgate11(const struct bpf_prog *prog)\n"
            "{ return LATE11 & 1U; }\n"
            "#define LATE11 1\n",
            "\tif (lgate11(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "fold_late_define_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: a helper folding over a stable macro
    # still inlines exactly (C permits: 1 & 1).
    verdict = _simulate_header(
        "fold_stable_macro_ok",
        "#define STABLE11 1\n"
        "static bool sgate11(const struct bpf_prog *prog)\n"
        "{ return STABLE11 & 1U; }\n",
        "\tif (sgate11(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_unparsed_bit_operands_reject():
    # Round 11, item 2 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): an assignment
    # inside a bit operand is outside the proven set and must
    # reject instead of granting an impossible restriction.
    bodies = (
        ("bit_assign_reject",
         "\tu32 f = 1;\n"
         "\tif (((f = 0) & 1U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("bit_incr_reject",
         "\tu32 f = 0;\n"
         "\tif (((f++) & 2U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("bit_comma_reject",
         "\tu32 f = 1;\n"
         "\tu32 g = 2;\n"
         "\tif (((f, g) & 1U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("bit_deref_reject",
         "\tu32 f = 1;\n"
         "\tu32 *p = &f;\n"
         "\tif (((*p) & 1U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("bit_charlit_reject",
         "\tu32 f = 1;\n"
         "\tif (((f) & 'a')) return 0;\n"
         "\treturn -EACCES;\n"),
        ("bit_floatcast_reject",
         "\tu32 f = 1;\n"
         "\tif ((((int)1.5) & 1U)) return 0;\n"
         "\treturn -EACCES;\n"),
    )
    for fn_name, body in bodies:
        _expect_unrecognized(fn_name, body, "bit-testable")
    # A direct member masked with 2**32 rejects through the width
    # gate instead (C denies for every u32 value, swept): member
    # fields carry no proven width, so the wide mask decides
    # nothing the inventory may claim.
    _expect_unrecognized(
        "bit_member_wide_reject",
        "\tif ((prog->aux->attach_st_ops_member_off & "
        "4294967296ULL)) return 0;\n"
        "\treturn -EACCES;\n",
        "unproven width")
    # Unsigned helper returns holding comma or assignment
    # expressions bypass the same way (both input-dependent in
    # C at -O0 and -O2: deny at type 0, permit at type 3).
    try:
        _simulate_header(
            "bit_helper_comma_reject",
            "static unsigned int cgate11(const struct bpf_prog *prog)\n"
            "{ return (1, prog->type); }\n",
            "\tif (cgate11(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "bit_helper_comma_reject" in str(exc), exc
        assert "bit-testable" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    try:
        _simulate_header(
            "bit_helper_assign_reject",
            "static u32 x11h = 0;\n"
            "static unsigned int agate11(const struct bpf_prog *prog)\n"
            "{ return (prog->type & (x11h = 1U)); }\n",
            "\tif (agate11(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "bit_helper_assign_reject" in str(exc), exc
        assert "bit-testable" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: a plain lvalue masked with a constant
    # still keeps its existential restriction.
    verdict = _simulate_source(
        "bit_plain_ok",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((f & 1U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert len(verdict["probe_fn"]["notes"]) == 1


def test_kfunc_filter_parenthesized_callees_invalidate():
    # Round 11, item 3 (exact counterexamples, verified against
    # compiled C at -O0 and -O2, which denies in each form): a
    # call through parentheses or a dereference still mutates
    # through the alias, so the later comparison must reject
    # instead of granting under stale state.
    bodies = (
        ("alias_paren_reject",
         "\tstruct bpf_prog_aux *q = prog->aux;\n"
         "\t(mutate_aux11)(q);\n"
         "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
         "\treturn -EACCES;\n"),
        ("alias_deref_reject",
         "\tstruct bpf_prog_aux *q = prog->aux;\n"
         "\t(*mutate_aux11)(q);\n"
         "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
         "\treturn -EACCES;\n"),
        ("alias_fp_paren_reject",
         "\tstruct bpf_prog_aux *q = prog->aux;\n"
         "\t(fp11)(q);\n"
         "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
         "\treturn -EACCES;\n"),
        ("alias_fp_deref_reject",
         "\tstruct bpf_prog_aux *q = prog->aux;\n"
         "\t(*fp11)(q);\n"
         "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
         "\treturn -EACCES;\n"),
        ("alias_nested_paren_reject",
         "\tstruct bpf_prog_aux *q = prog->aux;\n"
         "\t((mutate_aux11))(q);\n"
         "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
         "\treturn -EACCES;\n"),
        ("alias_subscript_reject",
         "\tstruct bpf_prog_aux *q = prog->aux;\n"
         "\ttable11[0](q);\n"
         "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
         "\treturn -EACCES;\n"),
        ("alias_call_result_reject",
         "\tstruct bpf_prog_aux *q = prog->aux;\n"
         "\t(getter11())(q);\n"
         "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
         "\treturn -EACCES;\n"),
    )
    for fn_name, body in bodies:
        _expect_unrecognized(fn_name, body, "compared member state")
    # A function-pointer declaration in the body declares nothing
    # to invalidate, but the later parenthesized call through it
    # still does.
    _expect_unrecognized(
        "alias_fp_decl_reject",
        "\tvoid (*fp)(struct bpf_prog_aux *);\n"
        "\tstruct bpf_prog_aux *q = prog->aux;\n"
        "\tfp = mutate_aux11;\n"
        "\t(fp)(q);\n"
        "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
        "\treturn -EACCES;\n",
        "compared member state")
    # No over-rejection: a parenthesized call to a pure
    # single-return predicate disturbs nothing and still
    # evaluates (C permits on XDP callers only).
    verdict = _simulate_header(
        "alias_paren_pure_ok",
        "static bool pgate11(const struct bpf_prog *prog)\n"
        "{ return prog->type == BPF_PROG_TYPE_TRACING; }\n",
        "\t(pgate11)(prog);\n"
        "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_XDP"}
    # A cast of a parenthesized alias expression is a cast, never
    # a call, so it invalidates nothing (C permits: the st_ops
    # comparison still sees the undisturbed wanted_ops).
    verdict = _simulate_source(
        "alias_paren_cast_ok",
        "\tstruct bpf_prog_aux *q = prog->aux;\n"
        "\tu32 v = (u32)(q->attach_st_ops_member_off);\n"
        "\t(void)v;\n"
        "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_params_shadow_file_bindings():
    # Round 11, item 4 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which permits for TRUE11=1):
    # the parameter shadows the file binding, whose value the
    # inventory must not substitute. The shadowed initializer
    # stays unproven and its later use rejects.
    try:
        _simulate_header_params(
            "shadow_param_true_reject",
            "static bool TRUE11 = false;\n",
            "const struct bpf_prog *prog, u32 TRUE11",
            "\tbool ready = TRUE11;\n"
            "\tif (ready) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "shadow_param_true_reject" in str(exc), exc
        assert "without a provable value" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # Mirrored FALSE and const-object bindings, the reviewer's
    # literal TRUE spelling, plus a compound initializer over
    # the shadowing parameter: each rejects instead of
    # substituting the shadowed file value.
    mirrors = (
        ("shadow_param_exact_true_reject",
         "static bool TRUE = false;\n",
         "const struct bpf_prog *prog, u32 TRUE",
         "\tbool ready = TRUE;\n"
         "\tif (ready) return 0;\n"
         "\treturn -EACCES;\n"),
        ("shadow_param_false_reject",
         "static bool FALSE12 = true;\n",
         "const struct bpf_prog *prog, u32 FALSE12",
         "\tbool ready = FALSE12;\n"
         "\tif (ready) return 0;\n"
         "\treturn -EACCES;\n"),
        ("shadow_param_const_reject",
         "static const u32 LIMIT11 = 0;\n",
         "const struct bpf_prog *prog, u32 LIMIT11",
         "\tbool ready = LIMIT11;\n"
         "\tif (ready) return 0;\n"
         "\treturn -EACCES;\n"),
        ("shadow_param_expr_reject",
         "static bool TRUE13 = false;\n",
         "const struct bpf_prog *prog, u32 TRUE13",
         "\tbool ready = TRUE13 & 1U;\n"
         "\tif (ready) return 0;\n"
         "\treturn -EACCES;\n"),
    )
    for fn_name, header, params, body in mirrors:
        try:
            _simulate_header_params(
                fn_name, header, params, body,
                ("probe_fn",), {"probe_ids": {"probe_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert fn_name in str(exc), exc
            assert "without a provable value" in str(exc), exc
        else:
            raise AssertionError(
                "expected FilterNotUnderstood for %s" % fn_name)
    # No over-rejection: a file binding with no shadowing
    # parameter still resolves by value (C permits).
    verdict = _simulate_header_params(
        "shadow_unshadowed_ok",
        "static bool FLAG11 = true;\n",
        "const struct bpf_prog *prog, u32 kfunc_id",
        "\tbool ready = FLAG11;\n"
        "\tif (ready) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_composed_bit_shapes_reject():
    # Round 11, item 5 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies for every input):
    # !f holds only 0 or 1, so bit 1 can never be set. The
    # inventory must reject the composed shape instead of
    # granting an impossible permission.
    bodies = (
        ("comp_not_reject",
         "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
         "\tif ((!f & 2U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("comp_eq_reject",
         "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
         "\tif (((f == 0) & 2U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("comp_and_reject",
         "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
         "\tif (((f && f) & 2U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("comp_shl_reject",
         "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
         "\tif (((f << 1) & 1U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("comp_or_reject",
         "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
         "\tif (((f || f) & 2U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("comp_rel_reject",
         "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
         "\tif (((f < 3) & 2U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("comp_shr_reject",
         "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
         "\tif (((f >> 31) & 2U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("comp_shift_mask_reject",
         "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
         "\tif (((f << 8) & 255U)) return 0;\n"
         "\treturn -EACCES;\n"),
    )
    for fn_name, body in bodies:
        _expect_unrecognized(fn_name, body, "composed bit operand")
    # A shift narrowed through an unsigned-char helper return is
    # the same class (C denies for every program type at -O0
    # and -O2: the low 8 bits of (type << 8) are always zero).
    try:
        _simulate_header(
            "comp_uchar_shift_reject",
            "static unsigned char shgate11(const struct bpf_prog *prog)\n"
            "{ return prog->type << 8; }\n",
            "\tif (shgate11(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "comp_uchar_shift_reject" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: a root negation over a plain bit test
    # keeps its polarity-carrying restriction.
    verdict = _simulate_source(
        "comp_rootneg_ok",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((!(f & 2U))) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert len(verdict["probe_fn"]["notes"]) == 1


def test_kfunc_filter_guarded_branches_are_return_only():
    # Round 11, item 6 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which permits): grammar rule S3
    # requires a return-only branch, so statements ahead of the
    # return reject even though the verdict matches C here.
    _expect_unrecognized(
        "branch_pre_stmts_reject",
        "\tif (true) {\n"
        "\t\tu32 unused = 1;\n"
        "\t\t(void)unused;\n"
        "\t\treturn 0;\n"
        "\t}\n"
        "\treturn -EACCES;\n",
        "guarded branch")
    # Further probes: preceding statements in a deny branch, and
    # a label carried into the branch, reject the same way.
    _expect_unrecognized(
        "branch_deny_pre_reject",
        "\tif (prog->type == BPF_PROG_TYPE_XDP) {\n"
        "\t\tu32 x = 1;\n"
        "\t\t(void)x;\n"
        "\t\treturn -EACCES;\n"
        "\t}\n"
        "\treturn 0;\n",
        "guarded branch")
    _expect_unrecognized(
        "branch_label_reject",
        "\tif (true) { done: return 0; }\n"
        "\treturn -EACCES;\n",
        "guarded branch")
    # Statements after the return already reject; a clean
    # braced return still permits.
    _expect_unrecognized(
        "branch_trailing_reject",
        "\tif (true) { return 0; (void)1; }\n"
        "\treturn -EACCES;\n",
        "cannot parse filter branch_trailing_reject")
    verdict = _simulate_source(
        "branch_clean_ok",
        "\tif (true) { return 0; }\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_shadowed_folded_dependencies_reject():
    # Round 12, item 1 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): the helper reads
    # the global FLAG, which clobber() clears, but the caller
    # shadows FLAG with a local. The folded literal must not
    # hide the helper-scope dependency: the disturbing call
    # rejects instead of granting.
    try:
        _simulate_header(
            "shadow_folded_local_reject",
            "static bool FLAG = true;\n"
            "static bool gate12(const struct bpf_prog *prog)\n"
            "{ return FLAG; }\n"
            "static void clobber12(void) { FLAG = false; }\n",
            "\tbool FLAG = false;\n"
            "\tclobber12();\n"
            "\tif (gate12(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "shadow_folded_local_reject" in str(exc), exc
        assert "consulting mutable file binding FLAG" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A parameter shadowing the same dependency bypasses the
    # check the same way (C denies at -O0 and -O2).
    try:
        _simulate_header_params(
            "shadow_folded_param_reject",
            "static bool FLAG = true;\n"
            "static bool pgate12(const struct bpf_prog *prog)\n"
            "{ return FLAG; }\n"
            "static void pclobber12(void) { FLAG = false; }\n",
            "const struct bpf_prog *prog, u32 FLAG",
            "\tpclobber12();\n"
            "\tif (pgate12(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "shadow_folded_param_reject" in str(exc), exc
        assert "consulting mutable file binding FLAG" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A write ahead of the shadowing declaration still hits the
    # file binding in C (denies at -O0 and -O2), as does a write
    # outside a nested shadowing block; both reject.
    try:
        _simulate_header(
            "shadow_folded_predecl_reject",
            "static bool FLAG = true;\n"
            "static bool wgate12(const struct bpf_prog *prog)\n"
            "{ return FLAG; }\n",
            "\tFLAG = false;\n"
            "\tbool FLAG = true;\n"
            "\tif (wgate12(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "shadow_folded_predecl_reject" in str(exc), exc
        assert "writes consulted mutable file binding FLAG" in \
            str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    try:
        _simulate_header(
            "shadow_folded_nested_reject",
            "static bool FLAG = true;\n"
            "static bool ngate12(const struct bpf_prog *prog)\n"
            "{ return FLAG; }\n",
            "\t{ bool FLAG = true; }\n"
            "\tFLAG = false;\n"
            "\tif (ngate12(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "shadow_folded_nested_reject" in str(exc), exc
        assert "writes consulted mutable file binding FLAG" in \
            str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: without any disturbance the folded
    # value is exact (C permits at -O0 and -O2), and a write
    # after the declaration touches only the local.
    verdict = _simulate_header(
        "shadow_folded_quiet_ok",
        "static bool FLAG = true;\n"
        "static bool qgate12(const struct bpf_prog *prog)\n"
        "{ return FLAG; }\n",
        "\tbool FLAG = false;\n"
        "\tif (qgate12(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_header(
        "shadow_folded_local_write_ok",
        "static bool FLAG = true;\n"
        "static bool lgate12(const struct bpf_prog *prog)\n"
        "{ return FLAG; }\n",
        "\tbool FLAG = false;\n"
        "\tFLAG = true;\n"
        "\tif (lgate12(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_folded_side_effects_reject():
    # Round 12, item 2 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which executes the assignment
    # and denies): zero-absorption must not erase the nested
    # assignment and its side effect on the later read.
    _expect_unrecognized(
        "zero_nested_assign_reject",
        "\tu32 f = 1;\n"
        "\tif ((0U & (f = 0)) || (f & 1U)) return 0;\n"
        "\treturn -EACCES;\n",
        "bit-testable")
    # Deeper nesting (behind an already-abstracted group), a
    # hidden call, an increment and a dereference erase the
    # same way; each rejects instead of folding to "0".
    bodies = (
        ("zero_deep_nest_reject",
         "\tu32 f = 1;\n"
         "\tif ((0U & (1 | (f = 0))) || (f & 1U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("zero_hidden_call_reject",
         "\tu32 f = 1;\n"
         "\tif ((0U & frob12(f)) || (f & 1U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("zero_hidden_incr_reject",
         "\tu32 f = 1;\n"
         "\tif ((0U & (f++)) || (f & 1U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("zero_hidden_deref_reject",
         "\tu32 f = 1;\n"
         "\tu32 *p = &f;\n"
         "\tif ((0U & (*p)) || (f & 1U)) return 0;\n"
         "\treturn -EACCES;\n"),
    )
    for fn_name, body in bodies:
        _expect_unrecognized(fn_name, body, "bit-testable")
    # Short-circuited effectful branches reject too: C grants
    # the true-|| shape (the branch never runs) and denies the
    # false-&& shape at -O0 and -O2 alike, but the erased
    # assignment is outside the grammar in either position.
    _expect_unrecognized(
        "sc_true_or_effect_reject",
        "\tu32 f = 1;\n"
        "\tif (true || ((f = 0) & 1U)) return 0;\n"
        "\treturn -EACCES;\n",
        "bit-testable")
    _expect_unrecognized(
        "sc_false_and_effect_reject",
        "\tu32 f = 1;\n"
        "\tif (false && ((f = 0) & 1U)) return 0;\n"
        "\treturn -EACCES;\n",
        "bit-testable")
    # A short-circuited call of unproven purity rejects (C
    # grants at -O0 and -O2 without calling it).
    _expect_unrecognized(
        "sc_dropped_call_reject",
        "\tu32 f = 1;\n"
        "\tif (true || unknown_fn12(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        "short-circuits past a call")
    # No over-rejection: a pure zero-fold still denies
    # silently, pure short-circuits drop exactly as C does, and
    # a caller-specific drop of a pure bit test keeps granting.
    verdict = _simulate_source(
        "zero_pure_deny_ok",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((0U & f)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_source(
        "sc_pure_or_ok",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (true || (f & 1U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_source(
        "sc_pure_and_ok",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (false && (f & 1U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()
    verdict = _simulate_source(
        "sc_caller_drop_ok",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (prog->type == BPF_PROG_TYPE_XDP || (f & 1U)) "
        "return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == {
        "BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"}


def test_kfunc_filter_mutating_predicates_invalidate():
    # Round 12, item 3 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): a parenthesized
    # call to a mutating predicate disturbs the later st_ops
    # comparison and must invalidate instead of exempting.
    for fn_name, stmt in (
            ("pred_paren_mutate_reject", "\t(mutate12)(prog);\n"),
            ("pred_plain_mutate_reject", "\tmutate12(prog);\n")):
        try:
            _simulate_header(
                fn_name,
                "static int wanted_ops12;\n"
                "static int other_ops12;\n"
                "static bool mutate12(const struct bpf_prog *prog)\n"
                "{\n"
                "    return (prog->aux->st_ops = &other_ops12)"
                " != 0;\n"
                "}\n",
                stmt +
                "\tif (prog->aux->st_ops == &wanted_ops12) "
                "return 0;\n"
                "\treturn -EACCES;\n",
                ("probe_fn",), {"probe_ids": {"probe_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert fn_name in str(exc), exc
            assert "compared member state" in str(exc), exc
        else:
            raise AssertionError(
                "expected FilterNotUnderstood for %s" % fn_name)
    # Comma-bearing helpers invalidate the same way, whether the
    # comma arm mutates or not (C denies both at -O0 and -O2).
    try:
        _simulate_header(
            "pred_comma_effect_reject",
            "static u32 xh12 = 0;\n"
            "static unsigned int cme12(const struct bpf_prog *prog)\n"
            "{ return (xh12 = 1U, prog->type); }\n",
            "\tcme12(prog);\n"
            "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "pred_comma_effect_reject" in str(exc), exc
        assert "compared member state" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    try:
        _simulate_header(
            "pred_comma_pure_reject",
            "static unsigned int cmp12(const struct bpf_prog *prog)\n"
            "{ return (1, prog->type); }\n",
            "\tcmp12(prog);\n"
            "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "pred_comma_pure_reject" in str(exc), exc
        assert "compared member state" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A mutating predicate also invalidates a consulted mutable
    # file binding (C denies at -O0 and -O2).
    try:
        _simulate_header(
            "pred_file_mutate_reject",
            "static bool FLAG = true;\n"
            "static bool fgate12(const struct bpf_prog *prog)\n"
            "{ return FLAG; }\n"
            "static bool setflag12(const struct bpf_prog *prog)\n"
            "{ return (FLAG = false); }\n",
            "\tsetflag12(prog);\n"
            "\tif (fgate12(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "pred_file_mutate_reject" in str(exc), exc
        assert "consulting mutable file binding FLAG" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: a pure predicate statement-call still
    # disturbs nothing (C permits on XDP callers only).
    verdict = _simulate_header(
        "pred_plain_pure_ok",
        "static bool ppgate12(const struct bpf_prog *prog)\n"
        "{ return prog->type == BPF_PROG_TYPE_TRACING; }\n",
        "\tppgate12(prog);\n"
        "\tif (prog->type == BPF_PROG_TYPE_XDP) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_XDP"}


def test_kfunc_filter_arithmetic_wrapped_operands_reject():
    # Round 12, item 4 (exact counterexample, verified against
    # compiled C at -O0 and -O2 over a swept offset range, which
    # always denies): !f + 1U holds only 1 or 2, so bit 2 can
    # never be set. Arithmetic around a Boolean result must hit
    # composed-operand rejection, not grant an impossible
    # restriction.
    bodies = (
        ("wrap_add_reject",
         "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
         "\tif (((!f + 1U) & 4U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("wrap_xor_reject",
         "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
         "\tif ((((f == 0) ^ 1U) & 2U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("wrap_mul_reject",
         "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
         "\tif ((((f == 0) * 2U) & 1U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("wrap_nested_reject",
         "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
         "\tif (((((f == 0) + 1U) + 1U) & 4U)) return 0;\n"
         "\treturn -EACCES;\n"),
    )
    for fn_name, body in bodies:
        _expect_unrecognized(fn_name, body, "composed bit operand")
    # No over-rejection: satisfiable wrappers keep their
    # existential restrictions (C permits), as do wrappers the
    # inventory cannot prove (a negative subtraction, a
    # variable mixture), which stay symbolic.
    for fn_name, body in (
            ("wrap_add_sat_ok",
             "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
             "\tif (((!f + 1U) & 3U)) return 0;\n"
             "\treturn -EACCES;\n"),
            ("wrap_xor_sat_ok",
             "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
             "\tif ((((f == 0) ^ 1U) & 1U)) return 0;\n"
             "\treturn -EACCES;\n"),
            ("wrap_mul_sat_ok",
             "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
             "\tif ((((f == 0) * 2U) & 3U)) return 0;\n"
             "\treturn -EACCES;\n"),
            ("wrap_sub_neg_ok",
             "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
             "\tif ((((f == 0) - 1U) & 4U)) return 0;\n"
             "\treturn -EACCES;\n"),
            ("wrap_var_mix_ok",
             "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
             "\tif ((((f == 0) + f) & 4U)) return 0;\n"
             "\treturn -EACCES;\n")):
        verdict = _simulate_source(
            fn_name, body, ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
        assert verdict["probe_fn"]["types"] == \
            {"BPF_PROG_TYPE_TRACING"}, fn_name
        assert len(verdict["probe_fn"]["notes"]) == 1, fn_name


def test_kfunc_filter_macro_aliased_shadowed_dependencies_reject():
    # Round 13, item 1 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): the helper reads
    # the global FLAG through a macro alias while the caller
    # shadows FLAG with a local. Alias expansion must surface
    # the true global dependency before the shadowing check, so
    # the disturbing call rejects like the unaliased round-12
    # shape instead of granting.
    try:
        _simulate_header(
            "alias_shadow_local_reject",
            "static bool FLAG = true;\n"
            "#define ALIAS_FLAG FLAG\n"
            "static bool gate13a(const struct bpf_prog *prog)\n"
            "{ return ALIAS_FLAG; }\n"
            "static void clobber13a(void) { FLAG = false; }\n",
            "\tbool FLAG = false;\n"
            "\tclobber13a();\n"
            "\tif (gate13a(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "alias_shadow_local_reject" in str(exc), exc
        assert "consulting mutable file binding FLAG" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A two-macro chain conceals the same dependency (C denies
    # at -O0 and -O2); expansion follows the whole chain.
    try:
        _simulate_header(
            "alias_shadow_chain_reject",
            "static bool FLAG = true;\n"
            "#define ALIAS_FLAG FLAG\n"
            "#define ALIAS13B ALIAS_FLAG\n"
            "static bool gate13b(const struct bpf_prog *prog)\n"
            "{ return ALIAS13B; }\n"
            "static void clobber13b(void) { FLAG = false; }\n",
            "\tbool FLAG = false;\n"
            "\tclobber13b();\n"
            "\tif (gate13b(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "alias_shadow_chain_reject" in str(exc), exc
        assert "consulting mutable file binding FLAG" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A parameter shadowing the aliased dependency bypasses the
    # check the same way (C denies at -O0 and -O2).
    try:
        _simulate_header_params(
            "alias_shadow_param_reject",
            "static bool FLAG = true;\n"
            "#define ALIAS_FLAG FLAG\n"
            "static bool gate13c(const struct bpf_prog *prog)\n"
            "{ return ALIAS_FLAG; }\n"
            "static void clobber13c(void) { FLAG = false; }\n",
            "const struct bpf_prog *prog, u32 FLAG",
            "\tclobber13c();\n"
            "\tif (gate13c(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "alias_shadow_param_reject" in str(exc), exc
        assert "consulting mutable file binding FLAG" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: without any disturbance the aliased
    # value is exact (C permits at -O0 and -O2).
    verdict = _simulate_header(
        "alias_shadow_quiet_ok",
        "static bool FLAG = true;\n"
        "#define ALIAS_FLAG FLAG\n"
        "static bool gate13d(const struct bpf_prog *prog)\n"
        "{ return ALIAS_FLAG; }\n",
        "\tbool FLAG = false;\n"
        "\tif (gate13d(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_zero_fold_unsupported_literals_reject():
    # Round 13, item 2 (verified against compiled C at -O0 and
    # -O2, which denies both): a character literal and a float
    # literal under zero absorption must reject loudly. The
    # Boolean outcome matching C does not bless a silent deny
    # of shapes the bit-test path rejects when kept.
    _expect_unrecognized(
        "zero_char_literal_reject",
        "\tif ((0U & 'x')) return 0;\n"
        "\treturn -EACCES;\n",
        "unproven bit operand")
    _expect_unrecognized(
        "zero_float_literal_reject",
        "\tif ((0U & (u32)1e2)) return 0;\n"
        "\treturn -EACCES;\n",
        "unproven bit expression")
    # No over-rejection: pure folds over valid integer
    # spellings (hex literals, digit-led local names) still
    # deny silently, exactly as C does.
    for fn_name, body in (
            ("zero_hex_ok",
             "\tif ((0U & 0x1U)) return 0;\n"
             "\treturn -EACCES;\n"),
            ("zero_digitname_ok",
             "\tu32 f2 = prog->aux->attach_st_ops_member_off;\n"
             "\tif ((0U & f2)) return 0;\n"
             "\treturn -EACCES;\n")):
        verdict = _simulate_source(
            fn_name, body, ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
        assert verdict["probe_fn"]["types"] == set(), fn_name


def test_kfunc_filter_shortcircuited_opaque_operands_reject():
    # Round 13, item 3 (verified against compiled C at -O0 and
    # -O2: the true-|| shapes permit, the false-&& shape
    # denies): short-circuited foreign reads and numeric
    # comparisons must reject exactly as they do when kept.
    # Matching C does not satisfy the rejection boundary.
    _expect_unrecognized(
        "sc_foreign_or_reject",
        "\tif (true || prog->aux->attach_st_ops_member_off) "
        "return 0;\n"
        "\treturn -EACCES;\n",
        "short-circuits past an unrecognized condition")
    _expect_unrecognized(
        "sc_foreign_and_reject",
        "\tif (false && prog->aux->attach_st_ops_member_off) "
        "return 0;\n"
        "\treturn -EACCES;\n",
        "short-circuits past an unrecognized condition")
    _expect_unrecognized(
        "sc_numcmp_or_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (true || (f == 0)) return 0;\n"
        "\treturn -EACCES;\n",
        "short-circuits past an unrecognized condition")
    # No over-rejection: proven leaves (type comparisons,
    # membership tests) are plain reads C skips without
    # effect and still drop silently.
    for fn_name, body in (
            ("sc_type_drop_ok",
             "\tif (prog->type == BPF_PROG_TYPE_XDP || true) "
             "return 0;\n"
             "\treturn -EACCES;\n"),
            ("sc_member_drop_ok",
             "\tbool in_set = "
             "btf_id_set_contains(&probe_ids, kfunc_id);\n"
             "\tif (in_set || true) return 0;\n"
             "\treturn -EACCES;\n")):
        verdict = _simulate_source(
            fn_name, body, ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
        assert verdict["probe_fn"]["types"] == \
            {"BPF_PROG_TYPE_TRACING"}, fn_name


def test_kfunc_filter_macro_hidden_mutation_reject():
    # Round 13, item 4 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): purity is
    # proven on the macro-expanded predicate body, so a member
    # write hidden behind an alias never earns the predicate
    # exemption for a parenthesized call.
    try:
        _simulate_header(
            "mac_mutation_reject",
            "static int wanted_ops, other_ops;\n"
            "#define MUTATION13 "
            "(prog->aux->st_ops = &other_ops)\n"
            "static bool mutate13(const struct bpf_prog *prog)\n"
            "{ return MUTATION13 != 0; }\n",
            "\t(mutate13)(prog);\n"
            "\tif (prog->aux->st_ops == &wanted_ops) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "mac_mutation_reject" in str(exc), exc
        assert "compared member state" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A comma expression hidden behind a macro invalidates the
    # same way for a direct call (C denies at -O0 and -O2).
    try:
        _simulate_header(
            "mac_comma_reject",
            "static int wanted13c, other13c;\n"
            "#define COMMA13 "
            "(prog->aux->st_ops = &other13c, 1)\n"
            "static bool comma13(const struct bpf_prog *prog)\n"
            "{ return COMMA13; }\n",
            "\tcomma13(prog);\n"
            "\tif (prog->aux->st_ops == &wanted13c) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "mac_comma_reject" in str(exc), exc
        assert "compared member state" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # A consulted-global write hidden behind a macro never
    # earns the file-binding exemption either (C denies at -O0
    # and -O2).
    try:
        _simulate_header(
            "mac_global_reject",
            "static bool FLAG4 = true;\n"
            "#define SETF13 (FLAG4 = false)\n"
            "static bool sethelp13(const struct bpf_prog *prog)\n"
            "{ return SETF13; }\n"
            "static bool gate13e(const struct bpf_prog *prog)\n"
            "{ return FLAG4; }\n",
            "\tsethelp13(prog);\n"
            "\tif (gate13e(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "mac_global_reject" in str(exc), exc
        assert "consulting mutable file binding FLAG4" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: pure macro bodies still exempt, for
    # consulted file bindings and compared members alike (C
    # permits both at -O0 and -O2).
    verdict = _simulate_header(
        "mac_pure_file_ok",
        "static bool FLAG4 = true;\n"
        "#define PURE13F (FLAG4)\n"
        "static bool purehelp13(const struct bpf_prog *prog)\n"
        "{ return PURE13F; }\n"
        "static bool gate13f(const struct bpf_prog *prog)\n"
        "{ return FLAG4; }\n",
        "\tpurehelp13(prog);\n"
        "\tif (gate13f(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == \
        {"BPF_PROG_TYPE_TRACING"}
    verdict = _simulate_header(
        "mac_pure_member_ok",
        "static int wanted13m;\n"
        "#define PASSM13 (prog->aux->st_ops != 0)\n"
        "static bool passhelp13(const struct bpf_prog *prog)\n"
        "{ return PASSM13; }\n",
        "\tpasshelp13(prog);\n"
        "\tif (prog->aux->st_ops == &wanted13m) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == \
        {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_shift_complement_wrapped_operands_reject():
    # Round 13, item 5 (exact counterexample, verified against
    # compiled C at -O0 and -O2 over a swept offset range, which
    # always denies): (!f + 1U) << 1 holds only 2 or 4, so bit
    # 3 can never be set. Shift wrappers around Boolean
    # results must hit composed-operand rejection instead of
    # granting an impossible restriction.
    bodies = (
        ("wrap_shl_reject",
         "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
         "\tif ((((!f + 1U) << 1) & 8U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("wrap_shr_reject",
         "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
         "\tif ((((!f + 1U) >> 1) & 8U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("wrap_bitnot_reject",
         "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
         "\tif (((~((!f + 1U) | 8U)) & 8U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("wrap_big_mul_reject",
         "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
         "\tif ((((u32)!f * 0x80000000U) & 8U)) return 0;\n"
         "\treturn -EACCES;\n"),
        ("wrap_big_add_reject",
         "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
         "\tif ((((u64)!f + 0x100000000ULL) & 8U)) return 0;\n"
         "\treturn -EACCES;\n"),
    )
    for fn_name, body in bodies:
        _expect_unrecognized(fn_name, body, "composed bit operand")
    # No over-rejection: satisfiable shift, complement and
    # large-constant wrappers keep their existential
    # restrictions (C permits each when f == 0 at -O0 and -O2).
    for fn_name, body in (
            ("wrap_shl_sat_ok",
             "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
             "\tif ((((!f + 1U) << 1) & 6U)) return 0;\n"
             "\treturn -EACCES;\n"),
            ("wrap_bitnot_sat_ok",
             "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
             "\tif (((~((!f + 1U) | 8U)) & 1U)) return 0;\n"
             "\treturn -EACCES;\n"),
            ("wrap_big_mul_sat_ok",
             "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
             "\tif ((((u32)!f * 0x80000000U) & 0x80000000U)) "
             "return 0;\n"
             "\treturn -EACCES;\n"),
            ("wrap_big_add_sat_ok",
             "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
             "\tif ((((u64)!f + 0x100000000ULL) & 3U)) return 0;\n"
             "\treturn -EACCES;\n")):
        verdict = _simulate_source(
            fn_name, body, ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
        assert verdict["probe_fn"]["types"] == \
            {"BPF_PROG_TYPE_TRACING"}, fn_name
        assert len(verdict["probe_fn"]["notes"]) == 1, fn_name


def test_kfunc_filter_macro_only_statements_invalidate():
    # Round 14, item 1 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): DISTURB is a
    # macro-only statement hiding a clobber() call, while the
    # helper reads the global FLAG through a two-macro chain and
    # the caller shadows FLAG locally. The straight-line call
    # scan must expand macros before matching callees, so the
    # disturbing call rejects like a direct call.
    try:
        _simulate_header(
            "disturb_shadow_reject",
            "static bool FLAG = true;\n"
            "#define A FLAG\n"
            "#define B A\n"
            "static bool gate14a(const struct bpf_prog *prog)\n"
            "{ return B; }\n"
            "static void clobber14a(void) { FLAG = false; }\n"
            "#define DISTURB (clobber14a())\n",
            "\tbool FLAG = true;\n"
            "\tDISTURB;\n"
            "\tif (gate14a(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "disturb_shadow_reject" in str(exc), exc
        assert "consulting mutable file binding FLAG" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: a benign macro-only statement still
    # disturbs nothing (C permits on every caller).
    verdict = _simulate_header(
        "disturb_noop_ok",
        "static bool FLAG = true;\n"
        "#define NOOP14 (1)\n"
        "static bool gate14b(const struct bpf_prog *prog)\n"
        "{ return FLAG; }\n",
        "\tNOOP14;\n"
        "\tif (gate14b(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == \
        {"BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"}


def test_kfunc_filter_zero_fold_expands_atomic_macros():
    # Round 14, item 2 (exact counterexamples, verified against
    # compiled C at -O0 and -O2, which denies each): zero-fold
    # purity must audit the expanded macro body, never the raw
    # macro identifier. A character literal, a float and a hidden
    # assignment behind an alias must all fail closed instead of
    # folding to 0.
    for fn_name, header, body, fragment in (
            ("zero_char_reject",
             "#define LIT14A ('x')\n",
             "\tif (0U & LIT14A) return 0;\n"
             "\treturn -EACCES;\n",
             "cannot parse filter"),
            ("zero_float_reject",
             "#define LIT14B ((u32)1e2)\n",
             "\tif (0U & LIT14B) return 0;\n"
             "\treturn -EACCES;\n",
             "cannot parse filter"),
            ("zero_char_paren_reject",
             "#define LIT14A ('x')\n",
             "\tif ((0U & LIT14A)) return 0;\n"
             "\treturn -EACCES;\n",
             "unproven bit operand"),
            ("zero_float_paren_reject",
             "#define LIT14B ((u32)1e2)\n",
             "\tif ((0U & LIT14B)) return 0;\n"
             "\treturn -EACCES;\n",
             "unproven bit expression"),
            ("zero_assign_reject",
             "#define EFFECT14 (f = 0)\n",
             "\tu32 f = 1;\n"
             "\tif ((0U & EFFECT14) || (f & 1U)) return 0;\n"
             "\treturn -EACCES;\n",
             "unproven bit operand")):
        try:
            _simulate_header(
                fn_name, header, body, ("probe_fn",),
                {"probe_ids": {"probe_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert fragment in str(exc), exc
            if fragment != "cannot parse filter":
                assert fn_name in str(exc), exc
        else:
            raise AssertionError(
                "expected FilterNotUnderstood for %s" % fn_name)


def test_kfunc_filter_identical_ternary_arms_audit_condition():
    # Round 14, item 3 (exact counterexamples, verified against
    # compiled C at -O0 and -O2 over a swept member range): the
    # allow shape always allows and the deny shape always denies,
    # but matching C is not enough -- identical arms must not
    # discard the condition before auditing it. A short-circuited
    # foreign read or comparison rejects like a kept one.
    _expect_unrecognized(
        "const_tern_allow_reject",
        "\treturn (true || prog->aux->attach_st_ops_member_off)"
        " ? 0 : 0;\n",
        "short-circuits past an unrecognized condition")
    _expect_unrecognized(
        "const_tern_deny_reject",
        "\treturn (false && (prog->aux->attach_st_ops_member_off"
        " == 0)) ? -EACCES : -EACCES;\n",
        "short-circuits past an unrecognized condition")
    _expect_unrecognized(
        "const_tern_branch_reject",
        "\tif (prog->type == BPF_PROG_TYPE_TRACING)\n"
        "\t\treturn (true || prog->aux->attach_st_ops_member_off)"
        " ? 0 : 0;\n"
        "\treturn -EACCES;\n",
        "short-circuits past an unrecognized condition")
    # No over-rejection: identical arms over a proven condition
    # keep their constant verdict (existing terminal tests cover
    # the terminal shape; the branch shape grants its callers).
    verdict = _simulate_source(
        "const_tern_branch_ok",
        "\tif (prog->type == BPF_PROG_TYPE_TRACING)\n"
        "\t\treturn (false) ? 0 : 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}


def test_kfunc_filter_parenthesized_macro_callees_invalidate():
    # Round 14, item 4 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): EFFECT hides a
    # parenthesized callee, (clobber)(prog), behind a macro, and
    # mutate's single-return body earns no purity exemption for
    # it. A direct macro-only statement hiding clobber(prog)
    # invalidates the same way.
    try:
        _simulate_header(
            "paren_macro_call_reject",
            "static int wanted14, other14;\n"
            "static bool clobber14d(const struct bpf_prog *prog) {\n"
            "    prog->aux->st_ops = &other14;\n"
            "    return true;\n"
            "}\n"
            "#define EFFECT14D (clobber14d)(prog)\n"
            "static bool mutate14(const struct bpf_prog *prog)\n"
            "{ return EFFECT14D; }\n",
            "\tmutate14(prog);\n"
            "\tif (prog->aux->st_ops == &wanted14) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "paren_macro_call_reject" in str(exc), exc
        assert "in call mutate14" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    try:
        _simulate_header(
            "direct_macro_call_reject",
            "static int wanted14b, other14b;\n"
            "static bool clobber14e(const struct bpf_prog *prog) {\n"
            "    prog->aux->st_ops = &other14b;\n"
            "    return true;\n"
            "}\n"
            "#define EFFECT14E clobber14e(prog)\n",
            "\tEFFECT14E;\n"
            "\tif (prog->aux->st_ops == &wanted14b) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "direct_macro_call_reject" in str(exc), exc
        assert "in call clobber14e" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: a cast group ahead of a paren group is
    # grouping, never a call, so a cast-wrapped predicate body
    # keeps its purity exemption (C permits on every caller).
    verdict = _simulate_header(
        "cast_paren_pure_ok",
        "static bool FLAG = true;\n"
        "#define C14 ((u32)1)\n"
        "static bool gate14e(const struct bpf_prog *prog)\n"
        "{ return FLAG; }\n"
        "static bool pass14e(const struct bpf_prog *prog)\n"
        "{ return (u32)(C14 == 1); }\n",
        "\tpass14e(prog);\n"
        "\tif (gate14e(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == \
        {"BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"}


def test_kfunc_filter_composed_arithmetic_preserves_widths():
    # Round 14, item 5 (exact counterexamples, verified against
    # compiled C at -O0 and -O2 over a swept offset range, which
    # always denies): (!f + 0xffffffffU) wraps at 32 bits, so the
    # shifted (or halved) value is 0 or 0x7fffffff -- never
    # 0x80000000 -- and ~(u64)!f complements at 64 bits, so the
    # xor chain is always zero. Width-sensitive compositions
    # reject instead of granting on unbounded values.
    _expect_unrecognized(
        "wrap_wrap_shr_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((((!f + 0xffffffffU) >> 1) & 0x80000000U))"
        " return 0;\n"
        "\treturn -EACCES;\n",
        "width-sensitive")
    _expect_unrecognized(
        "wrap_wrap_div_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((((!f + 0xffffffffU) / 2U) & 0x80000000U))"
        " return 0;\n"
        "\treturn -EACCES;\n",
        "width-sensitive")
    _expect_unrecognized(
        "wrap_c64_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((((~(u64)!f) >> 32) ^ 0xffffffffULL) & 8ULL))"
        " return 0;\n"
        "\treturn -EACCES;\n",
        "composed bit operand")


def test_kfunc_filter_negated_boolean_operands_reject():
    # Round 14, item 6 (exact counterexample, verified against
    # compiled C at -O0 and -O2 over a swept offset range, which
    # always denies): (u32)-(f == 0) * 2U holds only 0 or
    # 0xfffffffe, so bit 0 can never be set. Unmodeled unary
    # negation fails closed instead of retaining a symbolic
    # restriction -- even when the composition is satisfiable.
    _expect_unrecognized(
        "wrap_neg_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((((u32)-(f == 0) * 2U) & 1U)) return 0;\n"
        "\treturn -EACCES;\n",
        "with unary negation")
    _expect_unrecognized(
        "wrap_neg_sat_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((-(f == 0)) & 1U)) return 0;\n"
        "\treturn -EACCES;\n",
        "with unary negation")
    # No over-rejection: negation without a Boolean leaf stays
    # symbolic (C allows exactly the odd offsets).
    verdict = _simulate_source(
        "wrap_neg_var_ok",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((-f) & 1U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert len(verdict["probe_fn"]["notes"]) == 1


def test_kfunc_filter_indexed_macro_calls_invalidate():
    # Round 15, item 1 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): TOUCH15h hides
    # an indexed function-pointer call, dispatch15h[0](), behind
    # a macro, and the call clears the global FLAG15h the helper
    # gate15h reads through an alias, while the caller shadows
    # the name locally. The invalidation scan must see through
    # the subscript as well as the macro. A direct indexed call
    # invalidates the same way.
    for fn_name, header, body in (
            ("indexed_macro_call_reject",
             "static bool FLAG15h = true;\n"
             "#define READ15h FLAG15h\n"
             "static bool gate15h(const struct bpf_prog *prog)\n"
             "{ return READ15h; }\n"
             "static void clear15h(void) { FLAG15h = false; }\n"
             "static void (*dispatch15h[1])(void) = {clear15h};\n"
             "#define TOUCH15h (dispatch15h[0]())\n",
             "\tbool FLAG15h = true;\n"
             "\tTOUCH15h;\n"
             "\tif (gate15h(prog)) return 0;\n"
             "\treturn -EACCES;\n"),
            ("indexed_direct_call_reject",
             "static bool FLAG15h = true;\n"
             "static bool gate15h(const struct bpf_prog *prog)\n"
             "{ return FLAG15h; }\n"
             "static void clear15h(void) { FLAG15h = false; }\n"
             "static void (*dispatch15h[1])(void) = {clear15h};\n",
             "\tdispatch15h[0]();\n"
             "\tif (gate15h(prog)) return 0;\n"
             "\treturn -EACCES;\n")):
        try:
            _simulate_header(
                fn_name, header, body, ("probe_fn",),
                {"probe_ids": {"probe_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert fn_name in str(exc), exc
            assert "calls through a subscript" in str(exc), exc
        else:
            raise AssertionError(
                "expected FilterNotUnderstood for %s" % fn_name)
    # No over-rejection: a subscript read is not a call, so a
    # consulting filter that only reads through a subscript
    # keeps granting (C permits on every caller).
    verdict = _simulate_header(
        "indexed_read_ok",
        "static int table15j[2] = {1, 2};\n"
        "static bool FLAG15j = true;\n"
        "static bool gate15j(const struct bpf_prog *prog)\n"
        "{ return FLAG15j; }\n",
        "\tbool FLAG15j = true;\n"
        "\tu32 x = table15j[1];\n"
        "\t(void)x;\n"
        "\tif (gate15j(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == \
        {"BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"}


def test_kfunc_filter_macro_only_assignments_invalidate():
    # Round 15, item 2 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): CLEAR15i is a
    # macro-only assignment clearing the consulted global
    # FLAG15i. The write scan must examine the expanded
    # statements, not the raw macro identifier, for
    # initializer invalidation.
    try:
        _simulate_header(
            "macro_global_assign_reject",
            "static bool FLAG15i = true;\n"
            "#define CLEAR15i ((FLAG15i) = false)\n"
            "static bool gate15i(const struct bpf_prog *prog)\n"
            "{ return FLAG15i; }\n",
            "\tCLEAR15i;\n"
            "\tif (gate15i(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "macro_global_assign_reject" in str(exc), exc
        assert "writes consulted mutable" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: the same macro spelling under caller
    # shadowing writes the caller's local, not the file
    # binding, so the helper's initializer value still decides
    # (C permits on every caller).
    verdict = _simulate_header(
        "macro_shadowed_assign_ok",
        "static bool FLAG15 = true;\n"
        "#define AL FLAG15\n"
        "#define CLR ((FLAG15) = false)\n"
        "static bool gate15a(const struct bpf_prog *prog)\n"
        "{ return AL; }\n",
        "\tbool FLAG15 = true;\n"
        "\tCLR;\n"
        "\tif (gate15a(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == \
        {"BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"}


def test_kfunc_filter_zero_fold_parenthesized_callees_reject():
    # Round 15, item 3 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): EFFECT15c hides
    # a parenthesized callee, (clear15c)(prog), behind a macro
    # under a zero bit-mask. The call clears FLAG15c before the
    # later gate15c predicate reads it, so the fold must
    # account for the expanded callee effect and decline,
    # letting the bit-test path reject the call-shaped operand.
    try:
        _simulate_header(
            "zero_paren_call_reject",
            "static bool FLAG15c = true;\n"
            "static bool gate15c(const struct bpf_prog *prog)\n"
            "{ return FLAG15c; }\n"
            "static u32 clear15c(const struct bpf_prog *prog)\n"
            "{ FLAG15c = false; return 1; }\n"
            "#define EFFECT15c ((clear15c)(prog))\n",
            "\tif ((0U & EFFECT15c) || gate15c(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "zero_paren_call_reject" in str(exc), exc
        assert "outside the proven integer types" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: a genuine cast group is grouping,
    # never a call, so a pure cast under zero absorption still
    # denies silently, exactly as C does.
    verdict = _simulate_source(
        "zero_cast_fold_ok",
        "\tif ((0U & (u32)(1))) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()


def test_kfunc_filter_dead_guard_ternaries_audit_condition():
    # Round 15, item 4 (exact counterexamples, verified against
    # compiled C at -O0 and -O2, which denies each): a
    # constant-false outer guard must not skip auditing the
    # ternary condition it guards. A foreign read inside an
    # identical-arm or general ternary rejects even though the
    # branch is dead -- the matching denial still violates the
    # required rejection behavior.
    _expect_unrecognized(
        "ternary_outer_false_reject",
        "\tif (false) return (true || prog->aux->attach_st_ops_member_off)"
        " ? 0 : 0;\n"
        "\treturn -EACCES;\n",
        "short-circuits past an unrecognized condition")
    _expect_unrecognized(
        "ternary_outer_false_branch_reject",
        "\tif (false) return (prog->aux->attach_st_ops_member_off)"
        " ? 0 : -EACCES;\n"
        "\treturn -EACCES;\n",
        "short-circuits past an unrecognized condition")
    # No over-rejection: a dead guard over a proven condition
    # still denies silently, exactly as C does.
    verdict = _simulate_source(
        "ternary_outer_false_clean_ok",
        "\tif (false) return (prog->type == BPF_PROG_TYPE_TRACING)"
        " ? 0 : -EACCES;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == set()


def test_kfunc_filter_shadowed_typedef_callees_invalidate():
    # Round 15, item 5 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): TOUCH15f invokes
    # a parenthesized local function pointer, (u64)(prog),
    # whose name shadows the integer typedef u64. Cast
    # recognition must respect the shadowing binding and treat
    # the group as a call, catching the callee's mutation of
    # compared attachment state.
    try:
        _simulate_header(
            "local_callee_typename_reject",
            "static int wanted15f, other15f;\n"
            "static bool clear15f(const struct bpf_prog *prog)\n"
            "{ prog->aux->st_ops = &other15f; return true; }\n"
            "#define TOUCH15f (u64)(prog)\n",
            "\tbool (*u64)(const struct bpf_prog *) = clear15f;\n"
            "\tTOUCH15f;\n"
            "\tif (prog->aux->st_ops == &wanted15f) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "local_callee_typename_reject" in str(exc), exc
        assert "in call u64" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    # No over-rejection: a genuinely unbound type spelling is
    # still a cast, so a cast group ahead of a compared member
    # test keeps granting (C permits exactly the wanted
    # attachment).
    verdict = _simulate_header(
        "cast_touch_ok",
        "static int wanted15k, other15k;\n",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\t(u32)(f);\n"
        "\tif (prog->aux->st_ops == &wanted15k) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == \
        {"BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"}
    assert len(verdict["probe_fn"]["notes"]) == 1


def test_kfunc_filter_wrapped_64bit_compositions_reject():
    # Round 15, item 6 (exact counterexamples, verified against
    # compiled C at -O0 and -O2 over a swept offset range, which
    # always denies): !f + 0xffffffffffffffffULL wraps at 64
    # bits, so halving it can never set the top bit, and
    # shifting the half down 63 can never set bit 0 either.
    # Enumeration abandoning the addition at wraparound must
    # still run width validation instead of skipping it.
    _expect_unrecognized(
        "width_64_cast_divide_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((((u64)((!f + 0xffffffffffffffffULL) / 2ULL))"
        " & 0x8000000000000000ULL)) return 0;\n"
        "\treturn -EACCES;\n",
        "composed bit operand")
    _expect_unrecognized(
        "width_64_small_mask_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((((!f + 0xffffffffffffffffULL) / 2ULL) >> 63) & 1U))"
        " return 0;\n"
        "\treturn -EACCES;\n",
        "composed bit operand")
    # No over-rejection: a wrapped composition the width
    # verdict proves satisfiable at every width keeps its
    # symbolic restriction (C permits exactly the nonzero
    # offsets).
    verdict = _simulate_source(
        "width_modulo_ok",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((((!f + 0xffffffffU) % 2U) & 1U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert len(verdict["probe_fn"]["notes"]) == 1


def test_kfunc_filter_disjunct_negations_reject():
    # Round 15, item 7 (exact counterexample, verified against
    # compiled C at -O0 and -O2 over a swept offset range, which
    # always denies): (u32)-(f == 0) * 2U and (u32)-(f != 0) *
    # 2U are both even, so each low-bit test is zero. An outer
    # bitwise disjunction (or exclusive disjunction) must not
    # prevent the unary-negation check from visiting every
    # disjunct.
    _expect_unrecognized(
        "negation_or_even_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((((u32)-(f == 0) * 2U) & 1U) |"
        " (((u32)-(f != 0) * 2U) & 1U))) return 0;\n"
        "\treturn -EACCES;\n",
        "with unary negation")
    _expect_unrecognized(
        "negation_xor_even_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((((u32)-(f == 0) * 2U) & 1U) ^"
        " (((u32)-(f != 0) * 2U) & 1U))) return 0;\n"
        "\treturn -EACCES;\n",
        "with unary negation")
    # No over-rejection: one satisfiable disjunct keeps the
    # whole test symbolic (C permits some offsets and denies
    # others for each).
    for fn_name, body in (
            ("negation_or_outer_ok",
             "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
             "\tif (((((u32)-(f == 0)) * 2U) | (f & 2U))) return 0;\n"
             "\treturn -EACCES;\n"),
            ("negation_xor_outer_ok",
             "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
             "\tif (((((u32)-(f == 0)) * 2U) ^ (f & 2U))) return 0;\n"
             "\treturn -EACCES;\n")):
        verdict = _simulate_source(
            fn_name, body, ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
        assert verdict["probe_fn"]["types"] == \
            {"BPF_PROG_TYPE_TRACING"}, fn_name
        assert len(verdict["probe_fn"]["notes"]) == 1, fn_name


def test_kfunc_filter_spliced_indexed_call_invalidates():
    # Round 16, item 1 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): a
    # backslash-newline between the indexed callee
    # dispatch16b[0] and its argument list is one token stream
    # in C, so the call clears the consulted global FLAG16b.
    # The call scan must see past the line splice.
    try:
        _simulate_header(
            "spliced_indexed_call_reject",
            "static bool FLAG16b = true;\n"
            "static bool gate16b(const struct bpf_prog *prog)\n"
            "{ return FLAG16b; }\n"
            "static void clear16b(void) { FLAG16b = false; }\n"
            "static void (*dispatch16b[1])(void) = {clear16b};\n",
            "\tdispatch16b[0] \\\n ();\n"
            "\tif (gate16b(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "spliced_indexed_call_reject" in str(exc), exc
        assert "calls through a subscript" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_macro_remainder_assignment_invalidates():
    # Round 16, item 2 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): CLEAR16c hides
    # a remainder assignment, ((FLAG16c) %= 1), behind a macro,
    # clearing the consulted global FLAG16c. The write scan
    # must cover every compound assignment operator.
    try:
        _simulate_header(
            "macro_remainder_assign_reject",
            "static bool FLAG16c = true;\n"
            "static bool gate16c(const struct bpf_prog *prog)\n"
            "{ return FLAG16c; }\n"
            "#define CLEAR16c ((FLAG16c) %= 1)\n",
            "\tCLEAR16c;\n"
            "\tif (gate16c(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "macro_remainder_assign_reject" in str(exc), exc
        assert "writes consulted mutable" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_shadow_bool_typedef_callee_rejects():
    # Round 16, item 3 (exact counterexamples, verified against
    # compiled C at -O0 and -O2, which denies each): ``bool``
    # is a typedef, so a parenthesized local function pointer
    # bearing that name is a call, never a cast -- both in a
    # macro-only statement and beneath a zero mask. Each call
    # redirects compared attachment state before the later
    # comparison reads it.
    try:
        _simulate_header(
            "shadow_bool_call_reject",
            "static int wanted16g, other16g;\n"
            "static bool clear16g(const struct bpf_prog *prog)\n"
            "{ prog->aux->st_ops = &other16g; return true; }\n"
            "#define TOUCH16g (bool)(prog)\n",
            "\tbool (*bool)(const struct bpf_prog *) = clear16g;\n"
            "\tTOUCH16g;\n"
            "\tif (prog->aux->st_ops == &wanted16g) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "shadow_bool_call_reject" in str(exc), exc
        assert "in call bool" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    try:
        _simulate_header(
            "zero_shadow_bool_call_reject",
            "static int wanted16m, other16m;\n"
            "static bool clear16m(const struct bpf_prog *prog)\n"
            "{ prog->aux->st_ops = &other16m; return true; }\n"
            "#define EFFECT16m (bool)(prog)\n",
            "\tbool (*bool)(const struct bpf_prog *) = clear16m;\n"
            "\tif ((0U & EFFECT16m) ||"
            " prog->aux->st_ops == &wanted16m) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "zero_shadow_bool_call_reject" in str(exc), exc
        assert "in a bit test" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_outer_cast_width_audit_rejects():
    # Round 16, item 4 (exact counterexample, verified against
    # compiled C at -O0 and -O2 over a swept offset range,
    # which always denies): casting the completed high-bit
    # test of a divided, wrapped u64 addition -- then
    # combining it with zero -- leaves an outer cast around
    # the impossible composition. The width audit must look
    # through the cast instead of stopping at it.
    _expect_unrecognized(
        "wrap_outer_cast_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((u64)(((!f + 0xffffffffffffffffULL) / 2ULL)"
        " & 0x8000000000000000ULL) | 0ULL)) return 0;\n"
        "\treturn -EACCES;\n",
        "composed bit operand")


def test_kfunc_filter_wrapped_disjuncts_audit_all():
    # Round 16, item 5 (exact counterexamples, verified against
    # compiled C at -O0 and -O2 over a swept offset range):
    # casts and shifts around doubled-negation low-bit tests
    # must not stop the disjunct audit, and a satisfiable
    # first disjunct must not suppress auditing of a later
    # unsupported negated subtest (C permits some offsets
    # there, but the required rejection rule still applies).
    # Each fixture always denies except the last, which mixes
    # 0 and -13 across offsets.
    _expect_unrecognized(
        "neg_disjunct_casts_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((u32)(((u32)-(f == 0) * 2U) & 1U)"
        " | (u32)(((u32)-(f != 0) * 2U) & 1U))) return 0;\n"
        "\treturn -EACCES;\n",
        "with unary negation")
    _expect_unrecognized(
        "neg_disjunct_shift_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((((u32)-(f == 0) * 2U) & 1U)"
        " | ((((u32)-(f != 0) * 2U) & 1U) << 1))) return 0;\n"
        "\treturn -EACCES;\n",
        "with unary negation")
    _expect_unrecognized(
        "neg_disjunct_live_first_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((f & 2U) | (((u32)-(f == 0) * 2U) & 1U)))"
        " return 0;\n"
        "\treturn -EACCES;\n",
        "with unary negation")


def test_kfunc_filter_cast_statement_global_grants():
    # Round 16, item 6 (positive control, verified against
    # compiled C at -O0 and -O2, which permits on every
    # caller): a harmless integer cast statement ahead of a
    # pure predicate reading an unchanged global is grouping,
    # never an indirect call, so the filter keeps granting.
    # (The over-rejection predates round 16; this test pins
    # the acceptance.)
    verdict = _simulate_header(
        "cast_stmt_global_ok",
        "static bool FLAG16j = true;\n"
        "static bool gate16j(const struct bpf_prog *prog)\n"
        "{ return FLAG16j; }\n",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\t(u32)(f);\n"
        "\tif (gate16j(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == \
        {"BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"}
    assert verdict["probe_fn"]["notes"] == []


def test_kfunc_filter_spliced_helper_call_invalidates():
    # Round 17, item 1 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): the
    # single-return helper invoke17q calls the indexed callee
    # dispatch_global17q[0] across a backslash-newline, which
    # is one token stream in C, clearing the consulted global
    # FLAG17q. The purity scan must see past the line splice,
    # like the straight-line call scan already does.
    try:
        _simulate_header(
            "spliced_pure_helper_reject",
            "static bool FLAG17q = true;\n"
            "static bool gate17q(const struct bpf_prog *prog)\n"
            "{ return FLAG17q; }\n"
            "static bool clear_global17q(void)\n"
            "{ FLAG17q = false; return true; }\n"
            "static bool (*dispatch_global17q[1])(void) =\n"
            "    {clear_global17q};\n"
            "static bool invoke17q(const struct bpf_prog *prog)\n"
            "{ return dispatch_global17q[0] \\\n (); }\n",
            "\tinvoke17q(prog);\n"
            "\tif (gate17q(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "spliced_pure_helper_reject" in str(exc), exc
        assert "while consulting mutable file binding" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_macro_alias_modulo_invalidates():
    # Round 17, item 2 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): MOD17q hides a
    # modulo-one assignment, ((in17q) %= 1), behind an object
    # macro, clearing the immutable membership alias in17q
    # before its allow guard. The assignment scan must
    # examine the expanded statements.
    try:
        _simulate_header(
            "macro_alias_modulo_reject",
            "#define MOD17q ((in17q) %= 1)\n",
            "\tbool in17q ="
            " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
            "\tMOD17q;\n"
            "\tif (in17q) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "macro_alias_modulo_reject" in str(exc), exc
        assert "mutates membership alias" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_macro_shadow_bool_typedef_rejects():
    # Round 17, item 3 (exact counterexamples, verified against
    # compiled C at -O0 and -O2, which denies each): one macro
    # declares a local function pointer shadowing the Boolean
    # typedef while another invokes it -- both as a statement
    # and beneath a zero mask -- before an attachment
    # comparison. Each call redirects compared attachment
    # state, so binding discovery must see macro-introduced
    # declarations exactly like literal ones.
    try:
        _simulate_header(
            "macro_shadow_bool_reject",
            "static int wanted17q, other17q;\n"
            "static bool clear17q(const struct bpf_prog *prog)\n"
            "{ prog->aux->st_ops = &other17q; return true; }\n"
            "#define DECL17q bool (*bool)(const struct bpf_prog *)"
            " = clear17q\n"
            "#define TOUCH17q (bool)(prog)\n",
            "\tDECL17q;\n"
            "\tTOUCH17q;\n"
            "\tif (prog->aux->st_ops == &wanted17q) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "macro_shadow_bool_reject" in str(exc), exc
        assert "in call bool" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    try:
        _simulate_header(
            "macro_zero_shadow_bool_reject",
            "static int wanted17q, other17q;\n"
            "static bool clear17q(const struct bpf_prog *prog)\n"
            "{ prog->aux->st_ops = &other17q; return true; }\n"
            "#define DECL17q bool (*bool)(const struct bpf_prog *)"
            " = clear17q\n"
            "#define TOUCH17q (bool)(prog)\n",
            "\tDECL17q;\n"
            "\tif ((0U & TOUCH17q) ||"
            " prog->aux->st_ops == &wanted17q) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "macro_zero_shadow_bool_reject" in str(exc), exc
        assert "in a bit test" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_shifted_cast_width_audit_rejects():
    # Round 17, item 4 (exact counterexample, verified against
    # compiled C at -O0 and -O2 over a swept offset range,
    # which always denies): a cast around the completed
    # high-bit test of a divided, wrapped u64 addition is
    # followed by a right shift inside a bit disjunction. The
    # width audit must look through the trailing shift instead
    # of stopping at it.
    _expect_unrecognized(
        "cast_shift_bit_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((((u64)(((!f + 0xffffffffffffffffULL) / 2ULL)"
        " & 0x8000000000000000ULL) >> 1) | 0ULL)) return 0;\n"
        "\treturn -EACCES;\n",
        "composed bit operand")


def test_kfunc_filter_nested_negated_disjuncts_reject():
    # Round 17, item 5 (exact counterexamples, verified against
    # compiled C at -O0 and -O2 over a swept offset range): a
    # satisfiable first disjunct precedes unsupported Boolean
    # compositions inside a nested disjunction under a cast, or
    # inside a negated sibling. The visitor must audit every
    # nested and negated subtree: the nested form mixes 0 and
    # -13 while the negated sibling always permits, but
    # matching Boolean outcomes still fail the required
    # rejection contract.
    _expect_unrecognized(
        "nested_disjunct_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((f & 2U) | ((u32)((((u32)-(f == 0) * 2U) & 1U)"
        " | (((u32)-(f != 0) * 2U) & 1U))))) return 0;\n"
        "\treturn -EACCES;\n",
        "with unary negation")
    _expect_unrecognized(
        "negated_sibling_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((f & 2U) | !(((u32)-(f == 0) * 2U) & 1U)))"
        " return 0;\n"
        "\treturn -EACCES;\n",
        "with unary negation")


def test_kfunc_filter_qualified_cast_statement_grants():
    # Round 17, item 6 (positive control, verified against
    # compiled C at -O0 and -O2, which permits on every
    # caller): a harmless cast to a qualified 32-bit integer
    # ahead of a pure predicate reading an unchanged global is
    # grouping, never an indirect call. Declaration discovery
    # must not bind the qualified type name.
    verdict = _simulate_header(
        "qualified_cast_global_ok",
        "static bool FLAG17q = true;\n"
        "static bool gate17q(const struct bpf_prog *prog)\n"
        "{ return FLAG17q; }\n",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\t(const u32)(f);\n"
        "\tif (gate17q(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"))
    assert verdict["probe_fn"]["types"] == \
        {"BPF_PROG_TYPE_TRACING", "BPF_PROG_TYPE_XDP"}
    assert verdict["probe_fn"]["notes"] == []


def test_kfunc_filter_spliced_macro_purity_rejects():
    # Round 18, item 1 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): the
    # single-return helper invoke18r references the
    # global-clearing object macro CLEAR18r through a name
    # split by a backslash-newline. C joins the splice in
    # phase 2, before macro expansion, so purity inspection
    # must see the joined name and the assignment it hides.
    try:
        _simulate_header(
            "spliced_macro_purity_reject",
            "static bool FLAG18r = true;\n"
            "static bool gate18r(const struct bpf_prog *prog)\n"
            "{ return FLAG18r; }\n"
            "#define CLEAR18r (FLAG18r = false)\n"
            "static bool invoke18r(const struct bpf_prog *prog)\n"
            "{ return CLE\\\nAR18r; }\n",
            "\tinvoke18r(prog);\n"
            "\tif (gate18r(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "spliced_macro_purity_reject" in str(exc), exc
        assert "while consulting mutable file binding" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_spliced_macro_alias_rejects():
    # Round 18, item 2 (exact counterexamples, verified against
    # compiled C at -O0 and -O2, which denies each): MOD18r
    # hides a modulo-one assignment behind an object macro,
    # and a backslash-newline splits either the invocation
    # name in the body or the alias name in the replacement
    # text. C joins each splice before expansion and token
    # recognition, so the mutation scan must see the joined
    # alias and its remainder assignment either way.
    try:
        _simulate_header(
            "spliced_macro_invocation_reject",
            "#define MOD18r ((in18r) %= 1)\n",
            "\tbool in18r ="
            " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
            "\tMO\\\nD18r;\n"
            "\tif (in18r) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "spliced_macro_invocation_reject" in str(exc), exc
        assert "mutates membership alias" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    try:
        _simulate_header(
            "spliced_macro_replacement_reject",
            "#define MOD18r ((in\\\n18r) %= 1)\n",
            "\tbool in18r ="
            " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
            "\tMOD18r;\n"
            "\tif (in18r) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "spliced_macro_replacement_reject" in str(exc), exc
        assert "mutates membership alias" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_spliced_decl_macro_rejects():
    # Round 18, item 3 (exact counterexamples, verified against
    # compiled C at -O0 and -O2, which denies each): one macro
    # declares a local function pointer shadowing the Boolean
    # typedef while another invokes it -- both as a statement
    # and beneath a zero mask -- but the declaration macro's
    # invocation name is split by a backslash-newline. Binding
    # discovery must join the splice before matching
    # declarations, exactly as C does.
    try:
        _simulate_header(
            "spliced_decl_macro_reject",
            "static int wanted18r, other18r;\n"
            "static bool clear18r(const struct bpf_prog *prog)\n"
            "{ prog->aux->st_ops = &other18r; return true; }\n"
            "#define DECL18r bool (*bool)(const struct bpf_prog *)"
            " = clear18r\n"
            "#define TOUCH18r (bool)(prog)\n",
            "\tDE\\\nCL18r;\n"
            "\tTOUCH18r;\n"
            "\tif (prog->aux->st_ops == &wanted18r) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "spliced_decl_macro_reject" in str(exc), exc
        assert "in call bool" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    try:
        _simulate_header(
            "spliced_zero_decl_macro_reject",
            "static int wanted18r, other18r;\n"
            "static bool clear18r(const struct bpf_prog *prog)\n"
            "{ prog->aux->st_ops = &other18r; return true; }\n"
            "#define DECL18r bool (*bool)(const struct bpf_prog *)"
            " = clear18r\n"
            "#define TOUCH18r (bool)(prog)\n",
            "\tDE\\\nCL18r;\n"
            "\tif ((0U & TOUCH18r) ||"
            " prog->aux->st_ops == &wanted18r) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "spliced_zero_decl_macro_reject" in str(exc), exc
        assert "in a bit test" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_shift_amount_audit_rejects():
    # Round 18, item 4 (exact counterexamples, verified against
    # compiled C at -O0 and -O2 over a swept offset range,
    # which mixes 0 and -13): a negated Boolean composition,
    # or the completed high-bit test of a divided, wrapped u64
    # addition, sits inside a shift amount beneath a bit
    # disjunction. The audit must visit the amount exactly
    # like the shifted value instead of discarding it.
    _expect_unrecognized(
        "shift_amount_neg_bit_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((((f & 2U) >> (u32)((((u32)-(f == 0) * 2U)"
        " & 1U))) | 0U)) return 0;\n"
        "\treturn -EACCES;\n",
        "with unary negation")
    _expect_unrecognized(
        "shift_amount_width_bit_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((((f & 2U) >> (u32)(((!f + 0xffffffffffffffffULL)"
        " / 2ULL) & 0x8000000000000000ULL)) | 0U)) return 0;\n"
        "\treturn -EACCES;\n",
        "composed bit operand")


def test_kfunc_filter_wrapped_disjuncts_reject():
    # Round 18, item 5 (exact counterexamples, verified against
    # compiled C at -O0 and -O2 over a swept offset range,
    # which always permits): unsupported Boolean compositions
    # sit beneath a bitwise complement, or beneath an addition
    # surrounding a nested disjunction under a cast. The
    # disjunct visitor must look through complements and
    # arithmetic wrappers: matching the reference return does
    # not excuse the missing rejection.
    _expect_unrecognized(
        "complement_disjunct_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((f & 4U) | ~(((u32)-(f == 0) * 2U) & 1U)))"
        " return 0;\n"
        "\treturn -EACCES;\n",
        "with unary negation")
    _expect_unrecognized(
        "nested_add_disjunct_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((f & 4U) | (u32)(((((u32)-(f == 0) * 2U) & 1U)"
        " | (((u32)-(f != 0) * 2U) & 1U)) + 1U))) return 0;\n"
        "\treturn -EACCES;\n",
        "with unary negation")


def test_kfunc_filter_qualified_cast_variants_grant():
    # Round 18, item 6 (positive controls, verified against
    # compiled C at -O0 and -O2, which permits on every
    # caller): harmless casts with reordered qualifiers ahead
    # of a pure predicate reading an unchanged global are
    # grouping, never indirect calls. The rejection fixes
    # must not disturb these acceptances.
    for tag, cast in (("trailing_const", "u32 const"),
                      ("unsigned_spelling", "const unsigned int")):
        verdict = _simulate_header(
            "qualified_cast_%s_ok" % tag,
            "static bool FLAG18r = true;\n"
            "static bool gate18r(const struct bpf_prog *prog)\n"
            "{ return FLAG18r; }\n",
            "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
            "\t(%s)(f);\n" % cast
            + "\tif (gate18r(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
        assert verdict["probe_fn"]["types"] == \
            {"BPF_PROG_TYPE_TRACING"}
        assert verdict["probe_fn"]["notes"] == []


def test_kfunc_filter_spliced_global_type_rejects():
    # Round 19, item 1 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): the mutable
    # global TRUE is declared with a Boolean type split by a
    # backslash-newline, and a helper clears it through a
    # spliced macro name. C joins the splice in phase 2, so
    # file-scope binding discovery must see the joined type
    # and treat the subsequent read as consulting a mutable
    # binding, never as a Boolean constant.
    try:
        _simulate_header(
            "spliced_global_type_reject",
            "static bo\\\nol TRUE = true;\n"
            "static bool gate19b(const struct bpf_prog *prog)\n"
            "{ return TRUE; }\n"
            "#define CLEAR19b (TRUE = false)\n"
            "static bool invoke19b(const struct bpf_prog *prog)\n"
            "{ return CLE\\\nAR19b; }\n",
            "\tinvoke19b(prog);\n"
            "\tif (gate19b(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "spliced_global_type_reject" in str(exc), exc
        assert "while consulting mutable file binding" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_zero_arg_function_macro_rejects():
    # Round 19, item 2 (exact counterexamples, verified against
    # compiled C at -O0 and -O2, which denies each): MOD19b
    # hides a modulo-one assignment behind a function-like
    # macro with no arguments, while DECL19b hides a function
    # pointer declaration shadowing the Boolean typedef; each
    # invocation name is split by a backslash-newline. A use
    # with empty parentheses splices the body textually
    # exactly like C preprocessing, so the mutation and the
    # shadowing declaration stay visible to the scans.
    try:
        _simulate_header(
            "zero_arg_macro_alias_reject",
            "#define MOD19b() ((in19b) %= 1)\n",
            "\tbool in19b ="
            " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
            "\tMO\\\nD19b();\n"
            "\tif (in19b) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "zero_arg_macro_alias_reject" in str(exc), exc
        assert "mutates membership alias" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    try:
        _simulate_header(
            "zero_arg_macro_decl_reject",
            "static int wanted19b, other19b;\n"
            "static bool clear19d(const struct bpf_prog *prog)\n"
            "{ prog->aux->st_ops = &other19b; return true; }\n"
            "#define DECL19b() bool (*bool)(const struct bpf_prog *)"
            " = clear19d\n"
            "#define TOUCH19b (bool)(prog)\n",
            "\tDE\\\nCL19b();\n"
            "\tTOUCH19b;\n"
            "\tif (prog->aux->st_ops == &wanted19b) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "zero_arg_macro_decl_reject" in str(exc), exc
        assert "in call bool" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_comparison_wrapped_compositions_reject():
    # Round 19, item 3 (exact counterexamples, verified against
    # compiled C at -O0 and -O2 over a swept offset range,
    # which mixes 0 and -13 for the shift pair and always
    # permits the disjunction pair): the completed high-bit
    # test of a divided, wrapped u64 addition sits inside a
    # shift amount beneath a comparison or a logical
    # conjunction, while unsupported Boolean compositions sit
    # beneath complements and arithmetic under a comparison.
    # The audit must look through comparison and logical
    # nodes instead of stopping at them: matching the
    # reference return does not excuse the missing rejection.
    _expect_unrecognized(
        "shift_amount_comparison_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((((f & 2U) >> (u32)((((!f + 0xffffffffffffffffULL)"
        " / 2ULL) & 0x8000000000000000ULL) != 0ULL)) | 0U))"
        " return 0;\n"
        "\treturn -EACCES;\n",
        "composed bit operand")
    _expect_unrecognized(
        "shift_amount_logical_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((((f & 2U) >> (u32)((((!f + 0xffffffffffffffffULL)"
        " / 2ULL) & 0x8000000000000000ULL) && (f == f)))"
        " | 0U)) return 0;\n"
        "\treturn -EACCES;\n",
        "composed bit operand")
    _expect_unrecognized(
        "complement_comparison_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((f & 4U) | (u32)(~(((u32)-(f == 0) * 2U) & 1U)"
        " != 0U))) return 0;\n"
        "\treturn -EACCES;\n",
        "with unary negation")
    _expect_unrecognized(
        "arithmetic_comparison_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tif (((f & 4U) | (u32)((((((u32)-(f == 0) * 2U) & 1U)"
        " | (((u32)-(f != 0) * 2U) & 1U)) + 1U) != 0U)))"
        " return 0;\n"
        "\treturn -EACCES;\n",
        "with unary negation")


def test_continued_macro_values_keep_recorded_bytes():
    # Round 19, item 4 (regression: scanning normalization
    # must never alter inventoried output; each recorded
    # value below is byte-identical to the frozen registry,
    # and each recorded macro was compiled at -O0 and -O2,
    # behaving exactly as specified). Continued macro
    # definitions record with the original joining while
    # analysis keeps the C-faithful splice (no added
    # space), so tokenization still matches the compiler.
    bpf_func_mapper_source = '#define ___BPF_FUNC_MAPPER(FN, ctx...)\t\t\t\\\n\tFN(unspec, 0, ##ctx)\t\t\t\t\\\n\tFN(map_lookup_elem, 1, ##ctx)\t\t\t\\\n\tFN(map_update_elem, 2, ##ctx)\t\t\t\\\n\tFN(map_delete_elem, 3, ##ctx)\t\t\t\\\n\tFN(probe_read, 4, ##ctx)\t\t\t\\\n\tFN(ktime_get_ns, 5, ##ctx)\t\t\t\\\n\tFN(trace_printk, 6, ##ctx)\t\t\t\\\n\tFN(get_prandom_u32, 7, ##ctx)\t\t\t\\\n\tFN(get_smp_processor_id, 8, ##ctx)\t\t\\\n\tFN(skb_store_bytes, 9, ##ctx)\t\t\t\\\n\tFN(l3_csum_replace, 10, ##ctx)\t\t\t\\\n\tFN(l4_csum_replace, 11, ##ctx)\t\t\t\\\n\tFN(tail_call, 12, ##ctx)\t\t\t\\\n\tFN(clone_redirect, 13, ##ctx)\t\t\t\\\n\tFN(get_current_pid_tgid, 14, ##ctx)\t\t\\\n\tFN(get_current_uid_gid, 15, ##ctx)\t\t\\\n\tFN(get_current_comm, 16, ##ctx)\t\t\t\\\n\tFN(get_cgroup_classid, 17, ##ctx)\t\t\\\n\tFN(skb_vlan_push, 18, ##ctx)\t\t\t\\\n\tFN(skb_vlan_pop, 19, ##ctx)\t\t\t\\\n\tFN(skb_get_tunnel_key, 20, ##ctx)\t\t\\\n\tFN(skb_set_tunnel_key, 21, ##ctx)\t\t\\\n\tFN(perf_event_read, 22, ##ctx)\t\t\t\\\n\tFN(redirect, 23, ##ctx)\t\t\t\t\\\n\tFN(get_route_realm, 24, ##ctx)\t\t\t\\\n\tFN(perf_event_output, 25, ##ctx)\t\t\\\n\tFN(skb_load_bytes, 26, ##ctx)\t\t\t\\\n\tFN(get_stackid, 27, ##ctx)\t\t\t\\\n\tFN(csum_diff, 28, ##ctx)\t\t\t\\\n\tFN(skb_get_tunnel_opt, 29, ##ctx)\t\t\\\n\tFN(skb_set_tunnel_opt, 30, ##ctx)\t\t\\\n\tFN(skb_change_proto, 31, ##ctx)\t\t\t\\\n\tFN(skb_change_type, 32, ##ctx)\t\t\t\\\n\tFN(skb_under_cgroup, 33, ##ctx)\t\t\t\\\n\tFN(get_hash_recalc, 34, ##ctx)\t\t\t\\\n\tFN(get_current_task, 35, ##ctx)\t\t\t\\\n\tFN(probe_write_user, 36, ##ctx)\t\t\t\\\n\tFN(current_task_under_cgroup, 37, ##ctx)\t\\\n\tFN(skb_change_tail, 38, ##ctx)\t\t\t\\\n\tFN(skb_pull_data, 39, ##ctx)\t\t\t\\\n\tFN(csum_update, 40, ##ctx)\t\t\t\\\n\tFN(set_hash_invalid, 41, ##ctx)\t\t\t\\\n\tFN(get_numa_node_id, 42, ##ctx)\t\t\t\\\n\tFN(skb_change_head, 43, ##ctx)\t\t\t\\\n\tFN(xdp_adjust_head, 44, ##ctx)\t\t\t\\\n\tFN(probe_read_str, 45, ##ctx)\t\t\t\\\n\tFN(get_socket_cookie, 46, ##ctx)\t\t\\\n\tFN(get_socket_uid, 47, ##ctx)\t\t\t\\\n\tFN(set_hash, 48, ##ctx)\t\t\t\t\\\n\tFN(setsockopt, 49, ##ctx)\t\t\t\\\n\tFN(skb_adjust_room, 50, ##ctx)\t\t\t\\\n\tFN(redirect_map, 51, ##ctx)\t\t\t\\\n\tFN(sk_redirect_map, 52, ##ctx)\t\t\t\\\n\tFN(sock_map_update, 53, ##ctx)\t\t\t\\\n\tFN(xdp_adjust_meta, 54, ##ctx)\t\t\t\\\n\tFN(perf_event_read_value, 55, ##ctx)\t\t\\\n\tFN(perf_prog_read_value, 56, ##ctx)\t\t\\\n\tFN(getsockopt, 57, ##ctx)\t\t\t\\\n\tFN(override_return, 58, ##ctx)\t\t\t\\\n\tFN(sock_ops_cb_flags_set, 59, ##ctx)\t\t\\\n\tFN(msg_redirect_map, 60, ##ctx)\t\t\t\\\n\tFN(msg_apply_bytes, 61, ##ctx)\t\t\t\\\n\tFN(msg_cork_bytes, 62, ##ctx)\t\t\t\\\n\tFN(msg_pull_data, 63, ##ctx)\t\t\t\\\n\tFN(bind, 64, ##ctx)\t\t\t\t\\\n\tFN(xdp_adjust_tail, 65, ##ctx)\t\t\t\\\n\tFN(skb_get_xfrm_state, 66, ##ctx)\t\t\\\n\tFN(get_stack, 67, ##ctx)\t\t\t\\\n\tFN(skb_load_bytes_relative, 68, ##ctx)\t\t\\\n\tFN(fib_lookup, 69, ##ctx)\t\t\t\\\n\tFN(sock_hash_update, 70, ##ctx)\t\t\t\\\n\tFN(msg_redirect_hash, 71, ##ctx)\t\t\\\n\tFN(sk_redirect_hash, 72, ##ctx)\t\t\t\\\n\tFN(lwt_push_encap, 73, ##ctx)\t\t\t\\\n\tFN(lwt_seg6_store_bytes, 74, ##ctx)\t\t\\\n\tFN(lwt_seg6_adjust_srh, 75, ##ctx)\t\t\\\n\tFN(lwt_seg6_action, 76, ##ctx)\t\t\t\\\n\tFN(rc_repeat, 77, ##ctx)\t\t\t\\\n\tFN(rc_keydown, 78, ##ctx)\t\t\t\\\n\tFN(skb_cgroup_id, 79, ##ctx)\t\t\t\\\n\tFN(get_current_cgroup_id, 80, ##ctx)\t\t\\\n\tFN(get_local_storage, 81, ##ctx)\t\t\\\n\tFN(sk_select_reuseport, 82, ##ctx)\t\t\\\n\tFN(skb_ancestor_cgroup_id, 83, ##ctx)\t\t\\\n\tFN(sk_lookup_tcp, 84, ##ctx)\t\t\t\\\n\tFN(sk_lookup_udp, 85, ##ctx)\t\t\t\\\n\tFN(sk_release, 86, ##ctx)\t\t\t\\\n\tFN(map_push_elem, 87, ##ctx)\t\t\t\\\n\tFN(map_pop_elem, 88, ##ctx)\t\t\t\\\n\tFN(map_peek_elem, 89, ##ctx)\t\t\t\\\n\tFN(msg_push_data, 90, ##ctx)\t\t\t\\\n\tFN(msg_pop_data, 91, ##ctx)\t\t\t\\\n\tFN(rc_pointer_rel, 92, ##ctx)\t\t\t\\\n\tFN(spin_lock, 93, ##ctx)\t\t\t\\\n\tFN(spin_unlock, 94, ##ctx)\t\t\t\\\n\tFN(sk_fullsock, 95, ##ctx)\t\t\t\\\n\tFN(tcp_sock, 96, ##ctx)\t\t\t\t\\\n\tFN(skb_ecn_set_ce, 97, ##ctx)\t\t\t\\\n\tFN(get_listener_sock, 98, ##ctx)\t\t\\\n\tFN(skc_lookup_tcp, 99, ##ctx)\t\t\t\\\n\tFN(tcp_check_syncookie, 100, ##ctx)\t\t\\\n\tFN(sysctl_get_name, 101, ##ctx)\t\t\t\\\n\tFN(sysctl_get_current_value, 102, ##ctx)\t\\\n\tFN(sysctl_get_new_value, 103, ##ctx)\t\t\\\n\tFN(sysctl_set_new_value, 104, ##ctx)\t\t\\\n\tFN(strtol, 105, ##ctx)\t\t\t\t\\\n\tFN(strtoul, 106, ##ctx)\t\t\t\t\\\n\tFN(sk_storage_get, 107, ##ctx)\t\t\t\\\n\tFN(sk_storage_delete, 108, ##ctx)\t\t\\\n\tFN(send_signal, 109, ##ctx)\t\t\t\\\n\tFN(tcp_gen_syncookie, 110, ##ctx)\t\t\\\n\tFN(skb_output, 111, ##ctx)\t\t\t\\\n\tFN(probe_read_user, 112, ##ctx)\t\t\t\\\n\tFN(probe_read_kernel, 113, ##ctx)\t\t\\\n\tFN(probe_read_user_str, 114, ##ctx)\t\t\\\n\tFN(probe_read_kernel_str, 115, ##ctx)\t\t\\\n\tFN(tcp_send_ack, 116, ##ctx)\t\t\t\\\n\tFN(send_signal_thread, 117, ##ctx)\t\t\\\n\tFN(jiffies64, 118, ##ctx)\t\t\t\\\n\tFN(read_branch_records, 119, ##ctx)\t\t\\\n\tFN(get_ns_current_pid_tgid, 120, ##ctx)\t\t\\\n\tFN(xdp_output, 121, ##ctx)\t\t\t\\\n\tFN(get_netns_cookie, 122, ##ctx)\t\t\\\n\tFN(get_current_ancestor_cgroup_id, 123, ##ctx)\t\\\n\tFN(sk_assign, 124, ##ctx)\t\t\t\\\n\tFN(ktime_get_boot_ns, 125, ##ctx)\t\t\\\n\tFN(seq_printf, 126, ##ctx)\t\t\t\\\n\tFN(seq_write, 127, ##ctx)\t\t\t\\\n\tFN(sk_cgroup_id, 128, ##ctx)\t\t\t\\\n\tFN(sk_ancestor_cgroup_id, 129, ##ctx)\t\t\\\n\tFN(ringbuf_output, 130, ##ctx)\t\t\t\\\n\tFN(ringbuf_reserve, 131, ##ctx)\t\t\t\\\n\tFN(ringbuf_submit, 132, ##ctx)\t\t\t\\\n\tFN(ringbuf_discard, 133, ##ctx)\t\t\t\\\n\tFN(ringbuf_query, 134, ##ctx)\t\t\t\\\n\tFN(csum_level, 135, ##ctx)\t\t\t\\\n\tFN(skc_to_tcp6_sock, 136, ##ctx)\t\t\\\n\tFN(skc_to_tcp_sock, 137, ##ctx)\t\t\t\\\n\tFN(skc_to_tcp_timewait_sock, 138, ##ctx)\t\\\n\tFN(skc_to_tcp_request_sock, 139, ##ctx)\t\t\\\n\tFN(skc_to_udp6_sock, 140, ##ctx)\t\t\\\n\tFN(get_task_stack, 141, ##ctx)\t\t\t\\\n\tFN(load_hdr_opt, 142, ##ctx)\t\t\t\\\n\tFN(store_hdr_opt, 143, ##ctx)\t\t\t\\\n\tFN(reserve_hdr_opt, 144, ##ctx)\t\t\t\\\n\tFN(inode_storage_get, 145, ##ctx)\t\t\\\n\tFN(inode_storage_delete, 146, ##ctx)\t\t\\\n\tFN(d_path, 147, ##ctx)\t\t\t\t\\\n\tFN(copy_from_user, 148, ##ctx)\t\t\t\\\n\tFN(snprintf_btf, 149, ##ctx)\t\t\t\\\n\tFN(seq_printf_btf, 150, ##ctx)\t\t\t\\\n\tFN(skb_cgroup_classid, 151, ##ctx)\t\t\\\n\tFN(redirect_neigh, 152, ##ctx)\t\t\t\\\n\tFN(per_cpu_ptr, 153, ##ctx)\t\t\t\\\n\tFN(this_cpu_ptr, 154, ##ctx)\t\t\t\\\n\tFN(redirect_peer, 155, ##ctx)\t\t\t\\\n\tFN(task_storage_get, 156, ##ctx)\t\t\\\n\tFN(task_storage_delete, 157, ##ctx)\t\t\\\n\tFN(get_current_task_btf, 158, ##ctx)\t\t\\\n\tFN(bprm_opts_set, 159, ##ctx)\t\t\t\\\n\tFN(ktime_get_coarse_ns, 160, ##ctx)\t\t\\\n\tFN(ima_inode_hash, 161, ##ctx)\t\t\t\\\n\tFN(sock_from_file, 162, ##ctx)\t\t\t\\\n\tFN(check_mtu, 163, ##ctx)\t\t\t\\\n\tFN(for_each_map_elem, 164, ##ctx)\t\t\\\n\tFN(snprintf, 165, ##ctx)\t\t\t\\\n\tFN(sys_bpf, 166, ##ctx)\t\t\t\t\\\n\tFN(btf_find_by_name_kind, 167, ##ctx)\t\t\\\n\tFN(sys_close, 168, ##ctx)\t\t\t\\\n\tFN(timer_init, 169, ##ctx)\t\t\t\\\n\tFN(timer_set_callback, 170, ##ctx)\t\t\\\n\tFN(timer_start, 171, ##ctx)\t\t\t\\\n\tFN(timer_cancel, 172, ##ctx)\t\t\t\\\n\tFN(get_func_ip, 173, ##ctx)\t\t\t\\\n\tFN(get_attach_cookie, 174, ##ctx)\t\t\\\n\tFN(task_pt_regs, 175, ##ctx)\t\t\t\\\n\tFN(get_branch_snapshot, 176, ##ctx)\t\t\\\n\tFN(trace_vprintk, 177, ##ctx)\t\t\t\\\n\tFN(skc_to_unix_sock, 178, ##ctx)\t\t\\\n\tFN(kallsyms_lookup_name, 179, ##ctx)\t\t\\\n\tFN(find_vma, 180, ##ctx)\t\t\t\\\n\tFN(loop, 181, ##ctx)\t\t\t\t\\\n\tFN(strncmp, 182, ##ctx)\t\t\t\t\\\n\tFN(get_func_arg, 183, ##ctx)\t\t\t\\\n\tFN(get_func_ret, 184, ##ctx)\t\t\t\\\n\tFN(get_func_arg_cnt, 185, ##ctx)\t\t\\\n\tFN(get_retval, 186, ##ctx)\t\t\t\\\n\tFN(set_retval, 187, ##ctx)\t\t\t\\\n\tFN(xdp_get_buff_len, 188, ##ctx)\t\t\\\n\tFN(xdp_load_bytes, 189, ##ctx)\t\t\t\\\n\tFN(xdp_store_bytes, 190, ##ctx)\t\t\t\\\n\tFN(copy_from_user_task, 191, ##ctx)\t\t\\\n\tFN(skb_set_tstamp, 192, ##ctx)\t\t\t\\\n\tFN(ima_file_hash, 193, ##ctx)\t\t\t\\\n\tFN(kptr_xchg, 194, ##ctx)\t\t\t\\\n\tFN(map_lookup_percpu_elem, 195, ##ctx)\t\t\\\n\tFN(skc_to_mptcp_sock, 196, ##ctx)\t\t\\\n\tFN(dynptr_from_mem, 197, ##ctx)\t\t\t\\\n\tFN(ringbuf_reserve_dynptr, 198, ##ctx)\t\t\\\n\tFN(ringbuf_submit_dynptr, 199, ##ctx)\t\t\\\n\tFN(ringbuf_discard_dynptr, 200, ##ctx)\t\t\\\n\tFN(dynptr_read, 201, ##ctx)\t\t\t\\\n\tFN(dynptr_write, 202, ##ctx)\t\t\t\\\n\tFN(dynptr_data, 203, ##ctx)\t\t\t\\\n\tFN(tcp_raw_gen_syncookie_ipv4, 204, ##ctx)\t\\\n\tFN(tcp_raw_gen_syncookie_ipv6, 205, ##ctx)\t\\\n\tFN(tcp_raw_check_syncookie_ipv4, 206, ##ctx)\t\\\n\tFN(tcp_raw_check_syncookie_ipv6, 207, ##ctx)\t\\\n\tFN(ktime_get_tai_ns, 208, ##ctx)\t\t\\\n\tFN(user_ringbuf_drain, 209, ##ctx)\t\t\\\n\tFN(cgrp_storage_get, 210, ##ctx)\t\t\\\n\tFN(cgrp_storage_delete, 211, ##ctx)\t\t\\\n\t/* This helper list is effectively frozen. If you are trying to\t\\\n\t * add a new helper, you should add a kfunc instead which has\t\\\n\t * less stability guarantees. See Documentation/bpf/kfuncs.rst\t\\\n\t */\n'
    bpf_func_mapper_recorded = 'FN, ctx...)\t\t\t \tFN(unspec, 0, ##ctx)\t\t\t\t \tFN(map_lookup_elem, 1, ##ctx)\t\t\t \tFN(map_update_elem, 2, ##ctx)\t\t\t \tFN(map_delete_elem, 3, ##ctx)\t\t\t \tFN(probe_read, 4, ##ctx)\t\t\t \tFN(ktime_get_ns, 5, ##ctx)\t\t\t \tFN(trace_printk, 6, ##ctx)\t\t\t \tFN(get_prandom_u32, 7, ##ctx)\t\t\t \tFN(get_smp_processor_id, 8, ##ctx)\t\t \tFN(skb_store_bytes, 9, ##ctx)\t\t\t \tFN(l3_csum_replace, 10, ##ctx)\t\t\t \tFN(l4_csum_replace, 11, ##ctx)\t\t\t \tFN(tail_call, 12, ##ctx)\t\t\t \tFN(clone_redirect, 13, ##ctx)\t\t\t \tFN(get_current_pid_tgid, 14, ##ctx)\t\t \tFN(get_current_uid_gid, 15, ##ctx)\t\t \tFN(get_current_comm, 16, ##ctx)\t\t\t \tFN(get_cgroup_classid, 17, ##ctx)\t\t \tFN(skb_vlan_push, 18, ##ctx)\t\t\t \tFN(skb_vlan_pop, 19, ##ctx)\t\t\t \tFN(skb_get_tunnel_key, 20, ##ctx)\t\t \tFN(skb_set_tunnel_key, 21, ##ctx)\t\t \tFN(perf_event_read, 22, ##ctx)\t\t\t \tFN(redirect, 23, ##ctx)\t\t\t\t \tFN(get_route_realm, 24, ##ctx)\t\t\t \tFN(perf_event_output, 25, ##ctx)\t\t \tFN(skb_load_bytes, 26, ##ctx)\t\t\t \tFN(get_stackid, 27, ##ctx)\t\t\t \tFN(csum_diff, 28, ##ctx)\t\t\t \tFN(skb_get_tunnel_opt, 29, ##ctx)\t\t \tFN(skb_set_tunnel_opt, 30, ##ctx)\t\t \tFN(skb_change_proto, 31, ##ctx)\t\t\t \tFN(skb_change_type, 32, ##ctx)\t\t\t \tFN(skb_under_cgroup, 33, ##ctx)\t\t\t \tFN(get_hash_recalc, 34, ##ctx)\t\t\t \tFN(get_current_task, 35, ##ctx)\t\t\t \tFN(probe_write_user, 36, ##ctx)\t\t\t \tFN(current_task_under_cgroup, 37, ##ctx)\t \tFN(skb_change_tail, 38, ##ctx)\t\t\t \tFN(skb_pull_data, 39, ##ctx)\t\t\t \tFN(csum_update, 40, ##ctx)\t\t\t \tFN(set_hash_invalid, 41, ##ctx)\t\t\t \tFN(get_numa_node_id, 42, ##ctx)\t\t\t \tFN(skb_change_head, 43, ##ctx)\t\t\t \tFN(xdp_adjust_head, 44, ##ctx)\t\t\t \tFN(probe_read_str, 45, ##ctx)\t\t\t \tFN(get_socket_cookie, 46, ##ctx)\t\t \tFN(get_socket_uid, 47, ##ctx)\t\t\t \tFN(set_hash, 48, ##ctx)\t\t\t\t \tFN(setsockopt, 49, ##ctx)\t\t\t \tFN(skb_adjust_room, 50, ##ctx)\t\t\t \tFN(redirect_map, 51, ##ctx)\t\t\t \tFN(sk_redirect_map, 52, ##ctx)\t\t\t \tFN(sock_map_update, 53, ##ctx)\t\t\t \tFN(xdp_adjust_meta, 54, ##ctx)\t\t\t \tFN(perf_event_read_value, 55, ##ctx)\t\t \tFN(perf_prog_read_value, 56, ##ctx)\t\t \tFN(getsockopt, 57, ##ctx)\t\t\t \tFN(override_return, 58, ##ctx)\t\t\t \tFN(sock_ops_cb_flags_set, 59, ##ctx)\t\t \tFN(msg_redirect_map, 60, ##ctx)\t\t\t \tFN(msg_apply_bytes, 61, ##ctx)\t\t\t \tFN(msg_cork_bytes, 62, ##ctx)\t\t\t \tFN(msg_pull_data, 63, ##ctx)\t\t\t \tFN(bind, 64, ##ctx)\t\t\t\t \tFN(xdp_adjust_tail, 65, ##ctx)\t\t\t \tFN(skb_get_xfrm_state, 66, ##ctx)\t\t \tFN(get_stack, 67, ##ctx)\t\t\t \tFN(skb_load_bytes_relative, 68, ##ctx)\t\t \tFN(fib_lookup, 69, ##ctx)\t\t\t \tFN(sock_hash_update, 70, ##ctx)\t\t\t \tFN(msg_redirect_hash, 71, ##ctx)\t\t \tFN(sk_redirect_hash, 72, ##ctx)\t\t\t \tFN(lwt_push_encap, 73, ##ctx)\t\t\t \tFN(lwt_seg6_store_bytes, 74, ##ctx)\t\t \tFN(lwt_seg6_adjust_srh, 75, ##ctx)\t\t \tFN(lwt_seg6_action, 76, ##ctx)\t\t\t \tFN(rc_repeat, 77, ##ctx)\t\t\t \tFN(rc_keydown, 78, ##ctx)\t\t\t \tFN(skb_cgroup_id, 79, ##ctx)\t\t\t \tFN(get_current_cgroup_id, 80, ##ctx)\t\t \tFN(get_local_storage, 81, ##ctx)\t\t \tFN(sk_select_reuseport, 82, ##ctx)\t\t \tFN(skb_ancestor_cgroup_id, 83, ##ctx)\t\t \tFN(sk_lookup_tcp, 84, ##ctx)\t\t\t \tFN(sk_lookup_udp, 85, ##ctx)\t\t\t \tFN(sk_release, 86, ##ctx)\t\t\t \tFN(map_push_elem, 87, ##ctx)\t\t\t \tFN(map_pop_elem, 88, ##ctx)\t\t\t \tFN(map_peek_elem, 89, ##ctx)\t\t\t \tFN(msg_push_data, 90, ##ctx)\t\t\t \tFN(msg_pop_data, 91, ##ctx)\t\t\t \tFN(rc_pointer_rel, 92, ##ctx)\t\t\t \tFN(spin_lock, 93, ##ctx)\t\t\t \tFN(spin_unlock, 94, ##ctx)\t\t\t \tFN(sk_fullsock, 95, ##ctx)\t\t\t \tFN(tcp_sock, 96, ##ctx)\t\t\t\t \tFN(skb_ecn_set_ce, 97, ##ctx)\t\t\t \tFN(get_listener_sock, 98, ##ctx)\t\t \tFN(skc_lookup_tcp, 99, ##ctx)\t\t\t \tFN(tcp_check_syncookie, 100, ##ctx)\t\t \tFN(sysctl_get_name, 101, ##ctx)\t\t\t \tFN(sysctl_get_current_value, 102, ##ctx)\t \tFN(sysctl_get_new_value, 103, ##ctx)\t\t \tFN(sysctl_set_new_value, 104, ##ctx)\t\t \tFN(strtol, 105, ##ctx)\t\t\t\t \tFN(strtoul, 106, ##ctx)\t\t\t\t \tFN(sk_storage_get, 107, ##ctx)\t\t\t \tFN(sk_storage_delete, 108, ##ctx)\t\t \tFN(send_signal, 109, ##ctx)\t\t\t \tFN(tcp_gen_syncookie, 110, ##ctx)\t\t \tFN(skb_output, 111, ##ctx)\t\t\t \tFN(probe_read_user, 112, ##ctx)\t\t\t \tFN(probe_read_kernel, 113, ##ctx)\t\t \tFN(probe_read_user_str, 114, ##ctx)\t\t \tFN(probe_read_kernel_str, 115, ##ctx)\t\t \tFN(tcp_send_ack, 116, ##ctx)\t\t\t \tFN(send_signal_thread, 117, ##ctx)\t\t \tFN(jiffies64, 118, ##ctx)\t\t\t \tFN(read_branch_records, 119, ##ctx)\t\t \tFN(get_ns_current_pid_tgid, 120, ##ctx)\t\t \tFN(xdp_output, 121, ##ctx)\t\t\t \tFN(get_netns_cookie, 122, ##ctx)\t\t \tFN(get_current_ancestor_cgroup_id, 123, ##ctx)\t \tFN(sk_assign, 124, ##ctx)\t\t\t \tFN(ktime_get_boot_ns, 125, ##ctx)\t\t \tFN(seq_printf, 126, ##ctx)\t\t\t \tFN(seq_write, 127, ##ctx)\t\t\t \tFN(sk_cgroup_id, 128, ##ctx)\t\t\t \tFN(sk_ancestor_cgroup_id, 129, ##ctx)\t\t \tFN(ringbuf_output, 130, ##ctx)\t\t\t \tFN(ringbuf_reserve, 131, ##ctx)\t\t\t \tFN(ringbuf_submit, 132, ##ctx)\t\t\t \tFN(ringbuf_discard, 133, ##ctx)\t\t\t \tFN(ringbuf_query, 134, ##ctx)\t\t\t \tFN(csum_level, 135, ##ctx)\t\t\t \tFN(skc_to_tcp6_sock, 136, ##ctx)\t\t \tFN(skc_to_tcp_sock, 137, ##ctx)\t\t\t \tFN(skc_to_tcp_timewait_sock, 138, ##ctx)\t \tFN(skc_to_tcp_request_sock, 139, ##ctx)\t\t \tFN(skc_to_udp6_sock, 140, ##ctx)\t\t \tFN(get_task_stack, 141, ##ctx)\t\t\t \tFN(load_hdr_opt, 142, ##ctx)\t\t\t \tFN(store_hdr_opt, 143, ##ctx)\t\t\t \tFN(reserve_hdr_opt, 144, ##ctx)\t\t\t \tFN(inode_storage_get, 145, ##ctx)\t\t \tFN(inode_storage_delete, 146, ##ctx)\t\t \tFN(d_path, 147, ##ctx)\t\t\t\t \tFN(copy_from_user, 148, ##ctx)\t\t\t \tFN(snprintf_btf, 149, ##ctx)\t\t\t \tFN(seq_printf_btf, 150, ##ctx)\t\t\t \tFN(skb_cgroup_classid, 151, ##ctx)\t\t \tFN(redirect_neigh, 152, ##ctx)\t\t\t \tFN(per_cpu_ptr, 153, ##ctx)\t\t\t \tFN(this_cpu_ptr, 154, ##ctx)\t\t\t \tFN(redirect_peer, 155, ##ctx)\t\t\t \tFN(task_storage_get, 156, ##ctx)\t\t \tFN(task_storage_delete, 157, ##ctx)\t\t \tFN(get_current_task_btf, 158, ##ctx)\t\t \tFN(bprm_opts_set, 159, ##ctx)\t\t\t \tFN(ktime_get_coarse_ns, 160, ##ctx)\t\t \tFN(ima_inode_hash, 161, ##ctx)\t\t\t \tFN(sock_from_file, 162, ##ctx)\t\t\t \tFN(check_mtu, 163, ##ctx)\t\t\t \tFN(for_each_map_elem, 164, ##ctx)\t\t \tFN(snprintf, 165, ##ctx)\t\t\t \tFN(sys_bpf, 166, ##ctx)\t\t\t\t \tFN(btf_find_by_name_kind, 167, ##ctx)\t\t \tFN(sys_close, 168, ##ctx)\t\t\t \tFN(timer_init, 169, ##ctx)\t\t\t \tFN(timer_set_callback, 170, ##ctx)\t\t \tFN(timer_start, 171, ##ctx)\t\t\t \tFN(timer_cancel, 172, ##ctx)\t\t\t \tFN(get_func_ip, 173, ##ctx)\t\t\t \tFN(get_attach_cookie, 174, ##ctx)\t\t \tFN(task_pt_regs, 175, ##ctx)\t\t\t \tFN(get_branch_snapshot, 176, ##ctx)\t\t \tFN(trace_vprintk, 177, ##ctx)\t\t\t \tFN(skc_to_unix_sock, 178, ##ctx)\t\t \tFN(kallsyms_lookup_name, 179, ##ctx)\t\t \tFN(find_vma, 180, ##ctx)\t\t\t \tFN(loop, 181, ##ctx)\t\t\t\t \tFN(strncmp, 182, ##ctx)\t\t\t\t \tFN(get_func_arg, 183, ##ctx)\t\t\t \tFN(get_func_ret, 184, ##ctx)\t\t\t \tFN(get_func_arg_cnt, 185, ##ctx)\t\t \tFN(get_retval, 186, ##ctx)\t\t\t \tFN(set_retval, 187, ##ctx)\t\t\t \tFN(xdp_get_buff_len, 188, ##ctx)\t\t \tFN(xdp_load_bytes, 189, ##ctx)\t\t\t \tFN(xdp_store_bytes, 190, ##ctx)\t\t\t \tFN(copy_from_user_task, 191, ##ctx)\t\t \tFN(skb_set_tstamp, 192, ##ctx)\t\t\t \tFN(ima_file_hash, 193, ##ctx)\t\t\t \tFN(kptr_xchg, 194, ##ctx)\t\t\t \tFN(map_lookup_percpu_elem, 195, ##ctx)\t\t \tFN(skc_to_mptcp_sock, 196, ##ctx)\t\t \tFN(dynptr_from_mem, 197, ##ctx)\t\t\t \tFN(ringbuf_reserve_dynptr, 198, ##ctx)\t\t \tFN(ringbuf_submit_dynptr, 199, ##ctx)\t\t \tFN(ringbuf_discard_dynptr, 200, ##ctx)\t\t \tFN(dynptr_read, 201, ##ctx)\t\t\t \tFN(dynptr_write, 202, ##ctx)\t\t\t \tFN(dynptr_data, 203, ##ctx)\t\t\t \tFN(tcp_raw_gen_syncookie_ipv4, 204, ##ctx)\t \tFN(tcp_raw_gen_syncookie_ipv6, 205, ##ctx)\t \tFN(tcp_raw_check_syncookie_ipv4, 206, ##ctx)\t \tFN(tcp_raw_check_syncookie_ipv6, 207, ##ctx)\t \tFN(ktime_get_tai_ns, 208, ##ctx)\t\t \tFN(user_ringbuf_drain, 209, ##ctx)\t\t \tFN(cgrp_storage_get, 210, ##ctx)\t\t \tFN(cgrp_storage_delete, 211, ##ctx)'
    bpf_f_adj_room_encap_l2_source = '#define BPF_F_ADJ_ROOM_ENCAP_L2(len)\t(((__u64)len & \\\n\t\t\t\t\t  BPF_ADJ_ROOM_ENCAP_L2_MASK) \\\n\t\t\t\t\t << BPF_ADJ_ROOM_ENCAP_L2_SHIFT)\n'
    bpf_f_adj_room_encap_l2_recorded = 'len)\t(((__u64)len &  \t\t\t\t\t  BPF_ADJ_ROOM_ENCAP_L2_MASK)  \t\t\t\t\t << BPF_ADJ_ROOM_ENCAP_L2_SHIFT)'
    bpf_md_ptr_source = '#define __bpf_md_ptr(type, name)\t\\\nunion {\t\t\t\t\t\\\n\ttype name;\t\t\t\\\n\t__u64 :64;\t\t\t\\\n} __attribute__((aligned(8)))\n'
    bpf_md_ptr_recorded = 'type, name)\t union {\t\t\t\t\t \ttype name;\t\t\t \t__u64 :64;\t\t\t } __attribute__((aligned(8)))'
    frozen = {entry["name"]: entry["value_text"]
              for entry in load_registry()["enum_members"]}
    cases = (
        ('___BPF_FUNC_MAPPER', bpf_func_mapper_source, bpf_func_mapper_recorded),
        ('BPF_F_ADJ_ROOM_ENCAP_L2', bpf_f_adj_room_encap_l2_source, bpf_f_adj_room_encap_l2_recorded),
        ('__bpf_md_ptr', bpf_md_ptr_source, bpf_md_ptr_recorded),
    )
    for name, source, pinned in cases:
        defines = uc.parse_defines(source, recorded=True)
        assert len(defines) == 1, name
        assert defines[0][0] == name, name
        assert defines[0][1] == pinned, name
        assert frozen[name] == pinned, name
    # Analysis joining stays C-faithful: a splice joins
    # with no added space, unlike recorded joining.
    joined = uc.parse_defines(
        "#define JOIN19r (ab\\\ncd)\n")[0][1]
    assert joined == "(abcd)", joined
    kept = uc.parse_defines(
        "#define JOIN19r (ab\\\ncd)\n", recorded=True)[0][1]
    assert kept == "(ab cd)", kept


def test_kfunc_filter_newline_global_init_rejects():
    # Round 20, item 1 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): the mutable
    # global TRUE is declared with a spliced Boolean type, a
    # newline between the name and the ``=``, and a parenthesized
    # initializer split across lines, while a helper clears it
    # through a spliced macro name. Binding discovery must
    # tolerate newlines between the joined type, the name and a
    # multiline initializer; otherwise the later predicate read
    # falls back to the ``TRUE`` keyword spelling and grants
    # while the reference denies.
    try:
        _simulate_header(
            "newline_global_init_reject",
            "static bo\\\nol TRUE\n"
            "=\n"
            "(true\n"
            ");\n"
            "static bool gate20(const struct bpf_prog *prog)\n"
            "{ return TRUE; }\n"
            "#define CLEAR20 (TRUE = false)\n"
            "static bool invoke20(const struct bpf_prog *prog)\n"
            "{ return CLE\\\nAR20; }\n",
            "\tinvoke20(prog);\n"
            "\tif (gate20(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "newline_global_init_reject" in str(exc), exc
        assert "while consulting mutable file binding" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_object_alias_zero_arg_macro_rejects():
    # Round 20, item 2 (exact counterexamples, verified against
    # compiled C at -O0 and -O2, which denies each): MOD20 hides
    # a modulo-one assignment behind a zero-argument
    # function-like macro, reached through an object-like alias
    # (directly, and through a two-link chain) whose invocation
    # is split by a backslash-newline. C rescanning expands the
    # alias-formed ``NAME()`` use, so the substitution must run
    # the zero-argument pass once more after object-like
    # replacement; otherwise the membership-alias remainder
    # mutation stays invisible.
    try:
        _simulate_header(
            "alias_zero_arg_macro_reject",
            "#define MOD20() ((in20) %= 1)\n"
            "#define ALIAS20 MOD20\n",
            "\tbool in20 ="
            " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
            "\tALI\\\nAS20();\n"
            "\tif (in20) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "alias_zero_arg_macro_reject" in str(exc), exc
        assert "mutates membership alias" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    try:
        _simulate_header(
            "alias_chain_zero_arg_macro_reject",
            "#define MOD20b() ((in20b) %= 1)\n"
            "#define MID20b MOD20b\n"
            "#define TOP20b MID20b\n",
            "\tbool in20b ="
            " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
            "\tTOP20b();\n"
            "\tif (in20b) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "alias_chain_zero_arg_macro_reject" in str(exc), exc
        assert "mutates membership alias" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_maskless_and_descendants_reject():
    # Round 20, item 3 (exact counterexample, verified against
    # compiled C at -O0 and -O2 over a swept offset range, which
    # always denies): an outer bitwise AND of two symbolic
    # values carries no literal mask, while the completed
    # high-bit test of a divided, wrapped u64 addition sits
    # beneath a comparison in another chain operand. The audit
    # must descend through maskless AND nodes and audit every
    # descendant instead of stopping: matching the reference
    # return does not excuse the missing rejection. A maskless
    # AND over plain lvalues still constrains nothing and keeps
    # its note-only verdict.
    _expect_unrecognized(
        "maskless_and_comparison_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tu32 g = kfunc_id;\n"
        "\tif ((((f & g) & (u32)((((!f + 0xffffffffffffffffULL)"
        " / 2ULL) & 0x8000000000000000ULL) != 0ULL)) | 0U))"
        " return 0;\n"
        "\treturn -EACCES;\n",
        "composed bit operand")
    verdict = _simulate_source(
        "maskless_and_plain_accept",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tu32 g = kfunc_id;\n"
        "\tif ((((f & g)) | 0U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["notes"] == [
        "additionally restricted by maskless_and_plain_accept"
        " ((( __bitop_1 ) | 0U))"]


def test_kfunc_filter_comma_global_init_rejects():
    # Round 21, item 1 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): the mutable
    # global TRUE is the second declarator in a comma list
    # whose head carries a spliced Boolean type, with the name,
    # the ``=`` and a parenthesized initializer split across
    # lines, while a helper clears it through a spliced macro
    # name. Binding discovery must replay comma-separated
    # declarators in any position with balanced, multiline,
    # parenthesized initializers; otherwise the later
    # predicate read falls back to the ``TRUE`` keyword
    # spelling and grants while the reference denies. Without
    # the clearing call the same declaration still grants,
    # since nothing invalidates the initializer. The head may
    # also follow a function definition, whose body leaves no
    # semicolon boundary.
    header = (
        "static bo\\\nol ignored = true,\n"
        "TRUE\n"
        "=\n"
        "(true\n"
        ");\n"
        "static bool gate21(const struct bpf_prog *prog)\n"
        "{ return TRUE; }\n"
        "#define CLEAR21 (TRUE = false)\n"
        "static bool invoke21(const struct bpf_prog *prog)\n"
        "{ return CLE\\\nAR21; }\n")
    try:
        _simulate_header(
            "comma_global_init_reject",
            header,
            "\tinvoke21(prog);\n"
            "\tif (gate21(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "comma_global_init_reject" in str(exc), exc
        assert "while consulting mutable file binding" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    try:
        _simulate_header(
            "comma_global_init_after_func",
            "static int dummy21(void)\n"
            "{ return 1; }\n" + header,
            "\tinvoke21(prog);\n"
            "\tif (gate21(prog)) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "comma_global_init_after_func" in str(exc), exc
        assert "while consulting mutable file binding" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    verdict = _simulate_header(
        "comma_global_init_nocall",
        header,
        "\tif (gate21(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["notes"] == []


def test_kfunc_filter_chained_zero_arg_macro_rejects():
    # Round 21, item 2 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies for both
    # membership polarities): MOD21 hides a modulo-one
    # assignment behind a zero-argument function-like macro,
    # STEP21() names bare MOD21, and the object-like alias
    # TOP21 is invoked with two successive empty argument
    # lists through a spliced name. C rescanning expands the
    # chain to a fixpoint (``TOP21()()`` -> ``STEP21()()`` ->
    # ``MOD21()`` -> the assignment), so substitution must do
    # the same; otherwise the membership-alias remainder
    # mutation stays invisible. A cyclic chain that never
    # stabilizes is outside the grammar and rejects too.
    try:
        _simulate_header(
            "chained_zero_arg_macro_reject",
            "#define MOD21() ((in21) %= 1)\n"
            "#define STEP21() MOD21\n"
            "#define TOP21 STEP21\n"
            "static int unused21;\n",
            "\tbool in21 ="
            " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
            "\tTO\\\nP21()();\n"
            "\tif (in21) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "chained_zero_arg_macro_reject" in str(exc), exc
        assert "mutates membership alias" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    try:
        _simulate_header(
            "cyclic_zero_arg_macro_reject",
            "#define CYC21() CYC21() CYC21()\n",
            "\tbool in21c ="
            " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
            "\tCYC21();\n"
            "\tif (in21c) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "does not terminate" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_add_wrapped_maskless_and_rejects():
    # Round 21, item 3 (exact counterexample, verified against
    # compiled C at -O0 and -O2 over a swept 144-pair offset
    # grid, which always denies): the maskless conjunction of
    # two symbolic values with the completed high-bit
    # comparison sits under an addition of one and a masked
    # selection of the second-lowest bit. The audit must look
    # through the arithmetic wrapper and audit the conjunction
    # inside instead of stopping at the addition. A maskless
    # AND over three plain lvalues still constrains nothing
    # and keeps its note-only verdict.
    _expect_unrecognized(
        "add_wrapped_maskless_and_reject",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tu32 g = kfunc_id;\n"
        "\tif (((((f & g) & (u32)((((!f + 0xffffffffffffffffULL)"
        " / 2ULL) & 0x8000000000000000ULL) != 0ULL)) + 1U) & 2U))"
        " return 0;\n"
        "\treturn -EACCES;\n",
        "composed bit operand")
    verdict = _simulate_source(
        "add_wrapped_maskless_and_plain",
        "\tu32 f = prog->aux->attach_st_ops_member_off;\n"
        "\tu32 g = kfunc_id;\n"
        "\tu32 h = prog->aux->attach_st_ops_member_off;\n"
        "\tif ((((f & g & h)) | 0U)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["notes"] == [
        "additionally restricted by add_wrapped_maskless_and_plain"
        " ((( __bitop_1 ) | 0U))"]


def test_kfunc_filter_paren_declarator_name_rejects():
    # Round 22, item 1 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies): parenthesizing
    # the second Boolean declarator's name leaves its mutable
    # global undiscovered unless declarator parsing strips
    # redundant parentheses around names before binding. The
    # stripping applies in every position (first, middle,
    # later and single declarators), nested and split across
    # lines alike, and comma heads keep replaying when the
    # first declarator spells a pointer or array form (whose
    # braced initializer blanks with every other body);
    # otherwise the later predicate read falls back to the
    # ``TRUE`` keyword spelling and grants while the reference
    # denies. Without the clearing call the same parenthesized
    # declaration still grants, since nothing invalidates the
    # initializer.
    header = (
        "static bo\\\nol ignored = true,\n"
        "(TRUE)\n"
        "=\n"
        "(true\n"
        ");\n"
        "static bool gate21(const struct bpf_prog *prog)\n"
        "{ return TRUE; }\n"
        "#define CLEAR21 (TRUE = false)\n"
        "static bool invoke21(const struct bpf_prog *prog)\n"
        "{ return CLE\\\nAR21; }\n")
    body = (
        "\tinvoke21(prog);\n"
        "\tif (gate21(prog)) return 0;\n"
        "\treturn -EACCES;\n")
    variants = {
        "paren_declarator_name_reject": header,
        "paren_declarator_nested_multiline": header.replace(
            "(TRUE)\n=\n", "((\nTRUE\n))\n=\n"),
        "paren_declarator_first": header.replace(
            "ignored = true,", "(ignored) = true,"),
        "paren_declarator_middle": header.replace(
            "ignored = true,", "ignored = true, (middle),"),
        "paren_declarator_pointer_head": header.replace(
            "bo\\\nol ignored = true", "bool *ignored = 0"),
        "paren_declarator_array_head": header.replace(
            "bo\\\nol ignored = true", "bool ignored[1] = {true}"),
        }
    for tag, variant in variants.items():
        try:
            _simulate_header(
                tag, variant, body,
                ("probe_fn",), {"probe_ids": {"probe_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert tag in str(exc), exc
            assert "while consulting mutable file binding" in str(
                exc), exc
        else:
            raise AssertionError("expected FilterNotUnderstood")
    try:
        _simulate_header(
            "paren_declarator_single_reject",
            "static bool (TRUE) = (true);\n"
            "static bool gate21(const struct bpf_prog *prog)\n"
            "{ return TRUE; }\n"
            "#define CLEAR21 (TRUE = false)\n"
            "static bool invoke21(const struct bpf_prog *prog)\n"
            "{ return CLEAR21; }\n",
            body,
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "paren_declarator_single_reject" in str(exc), exc
        assert "while consulting mutable file binding" in str(exc), \
            exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    verdict = _simulate_header(
        "paren_declarator_name_nocall",
        header,
        "\tif (gate21(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["notes"] == []


def test_kfunc_filter_parameterized_macro_endpoint_rejects():
    # Round 22, item 2 (exact counterexample, verified against
    # compiled C at -O0 and -O2, which denies for both
    # membership polarities): a spliced object alias traverses
    # successive zero-argument macros into the parameterized
    # macro MOD22, whose argument supplies the remainder
    # assignment clearing the membership Boolean. Chain
    # expansion must expand parameterized macros encountered
    # mid-chain with whole-token argument substitution and
    # then scan the expansion for mutations; otherwise the
    # remainder mutation stays invisible. A direct use and a
    # ``(void)`` spelling (one parameter named ``void``,
    # exactly as C preprocessing reads a macro parameter
    # list) expand the same way. A cyclic parameterized
    # chain never stabilizes and rejects, as does any use
    # whose substitution is unanalyzable (variadic,
    # stringizing or pasting bodies, arity mismatches). A
    # benign parameterized use in a skipped straight-line
    # statement still accepts, including behind a parameter
    # that shadows an object-like macro name.
    body_n21 = (
        "\tbool in21 ="
        " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "%s"
        "\tif (in21) return 0;\n"
        "\treturn -EACCES;\n")
    try:
        _simulate_header(
            "parameterized_macro_endpoint_reject",
            "#define MOD22(n) ((in21) %= (n))\n"
            "#define STEP22() MOD22\n"
            "#define TOP22 STEP22\n"
            "static int unused22;\n",
            body_n21 % "\tTO\\\nP22()(1);\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "parameterized_macro_endpoint_reject" in str(exc), exc
        assert "mutates membership alias" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    try:
        _simulate_header(
            "parameterized_macro_endpoint_three_hops",
            "#define MOD22(n) ((in21) %= (n))\n"
            "#define STEP22() MOD22\n"
            "#define MID22() STEP22\n"
            "#define TOP22 MID22\n"
            "static int unused22;\n",
            body_n21 % "\tTO\\\nP22()()(1);\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
    except uc.FilterNotUnderstood as exc:
        assert "parameterized_macro_endpoint_three_hops" in str(
            exc), exc
        assert "mutates membership alias" in str(exc), exc
    else:
        raise AssertionError("expected FilterNotUnderstood")
    body_n22 = (
        "\tbool in22 ="
        " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "%s"
        "\tif (in22) return 0;\n"
        "\treturn -EACCES;\n")
    mutating = {
        "parameterized_macro_direct_reject": (
            "#define M22(n) ((in22) %= (n))\n"
            "static int unused22;\n",
            body_n22 % "\tM22(1);\n",
            "mutates membership alias"),
        "parameterized_macro_void_reject": (
            "#define VM22(void) ((in22) %= 1)\n"
            "static int unused22;\n",
            body_n22 % "\tVM22();\n",
            "mutates membership alias"),
        "parameterized_macro_cycle_reject": (
            "#define C22(n) C22((n))\n"
            "static int unused22;\n",
            body_n22 % "\tC22(1);\n",
            "does not terminate"),
        "parameterized_macro_paste_reject": (
            "#define P22(n) x ## n\n"
            "static int unused22;\n",
            body_n22 % "\tP22(1);\n",
            "stringizes or pastes"),
        "parameterized_macro_variadic_reject": (
            "#define V22(n, ...) ((in22) %= (n))\n"
            "static int unused22;\n",
            body_n22 % "\tV22(1);\n",
            "variadic"),
        "parameterized_macro_arity_reject": (
            "#define N22(n, m) ((in22) %= (n))\n"
            "static int unused22;\n",
            body_n22 % "\tN22(1);\n",
            "takes 2 arguments"),
        }
    for tag, (variant, stmt_body, fragment) in mutating.items():
        try:
            _simulate_header(
                tag, variant, stmt_body,
                ("probe_fn",), {"probe_ids": {"probe_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert tag in str(exc) or fragment in str(exc), exc
            assert fragment in str(exc), exc
        else:
            raise AssertionError("expected FilterNotUnderstood")
    benign = {
        "parameterized_macro_benign": (
            "#define ID22(n) ((n) + 0)\n"
            "static int unused22;\n",
            body_n22 % "\tID22(1);\n"),
        "parameterized_macro_shadow": (
            "#define X22 5\n"
            "#define W22(X22) ((X22))\n"
            "static int unused22;\n",
            body_n22 % "\tW22(0);\n"),
        }
    for tag, (variant, stmt_body) in benign.items():
        verdict = _simulate_header(
            tag, variant, stmt_body,
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
        assert verdict["probe_fn"]["types"] == {
            "BPF_PROG_TYPE_TRACING"}, (tag, verdict["probe_fn"])
        assert verdict["probe_fn"]["notes"] == [], \
            (tag, verdict["probe_fn"])


def test_kfunc_filter_bitwise_wrapped_maskless_and_rejects():
    # Round 22, item 3 (exact counterexample, verified against
    # compiled C at -O0 and -O2 over a swept 144-pair offset
    # grid, which always denies): a bitwise OR or XOR with
    # four around the reported addition, before the masked
    # selection of the second-lowest bit, leaves the completed
    # high-bit comparison uninspected unless the audit
    # descends through every bitwise and arithmetic wrapper
    # (OR, XOR, AND past a cast, complement, addition and
    # shifts) around the conjunction to the comparison
    # inside. A complement wrapper matches the reference
    # return 0, which still violates the required rejection
    # rule. The same descent rejects a shifted conjunction
    # and a cast-wrapped conjunction. Plain lvalues under the
    # same wrappers keep their note-only verdicts.
    base = ("(f & g) & (u32)((((!f + 0xffffffffffffffffULL)"
            " / 2ULL) & 0x8000000000000000ULL) != 0ULL)")
    prefix = ("\tu32 f = prog->aux->attach_st_ops_member_off;\n"
              "\tu32 g = kfunc_id;\n")
    for tag, condition in (
            ("bitwise_wrapped_or_reject",
             "((((" + base + ") + 1U) | 4U) & 2U)"),
            ("bitwise_wrapped_xor_reject",
             "((((" + base + ") + 1U) ^ 4U) & 2U)"),
            ("bitwise_wrapped_not_reject",
             "((~((" + base + ") + 1U)) & 2U)"),
            ("bitwise_wrapped_shl_base_reject",
             "(((" + base + ") << 1U) & 2U)"),
            ("bitwise_wrapped_shr_base_reject",
             "(((" + base + ") >> 1U) & 2U)"),
            ("bitwise_wrapped_cast_and_reject",
             "(((u32)(" + base + ") & 2U))")):
        _expect_unrecognized(
            tag,
            prefix + "\tif (" + condition + ") return 0;\n"
            "\treturn -EACCES;\n",
            "composed bit operand")
    plains = {
        "bitwise_wrapped_or_plain": (
            "(((f | g)) & 2U)",
            "((( __bitop_1 ) & 2U))"),
        "bitwise_wrapped_not_plain": (
            "((~f) & 2U)",
            "(((~f) & 2U))"),
        "bitwise_wrapped_shl_plain": (
            "(((f & g) << 1U) & 2U)",
            "((( __bitop_1 << 1U) & 2U))"),
        "bitwise_wrapped_cast_and_plain": (
            "(((u32)(f & g) & 2U))",
            "(((u32) __bitop_1 & 2U))"),
        }
    for tag, (condition, core) in plains.items():
        verdict = _simulate_source(
            tag,
            prefix + "\tif (" + condition + ") return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
        assert verdict["probe_fn"]["types"] == {
            "BPF_PROG_TYPE_TRACING"}, (tag, verdict["probe_fn"])
        assert verdict["probe_fn"]["notes"] == [
            "additionally restricted by %s %s" % (tag, core)], \
            (tag, verdict["probe_fn"])


def test_kfunc_filter_no_gap_paren_declarator_rejects():
    # Round 23, item 1 (exact counterexamples, verified against
    # compiled C at -O0 and -O2, which denies with -13 for both
    # membership polarities): a parenthesized Boolean declarator
    # immediately adjoining its type with no whitespace
    # (``bool(TRUE)``) stays undiscovered unless declarator
    # binding tolerates zero-gap parens-type adjacency. The gap
    # tolerance applies in every type-adjoining position
    # (single declarators and comma heads alike), nested and
    # multiline alike, and comma heads keep replaying when the
    # first declarator spells a qualifier-carrying pointer
    # (``*const``), an attribute-annotated later declarator, or
    # a function-pointer form; otherwise the later predicate
    # read falls back to the ``TRUE`` keyword spelling and
    # grants while the reference denies. Without the clearing
    # call the no-gap single still grants, since nothing
    # invalidates the initializer.
    tail = (
        "static bool gate23(const struct bpf_prog *prog)\n"
        "{ return TRUE; }\n"
        "#define CLEAR23 (TRUE = false)\n"
        "static bool invoke23(const struct bpf_prog *prog)\n"
        "{ return CLEAR23; }\n")
    body = (
        "\tinvoke23(prog);\n"
        "\tif (gate23(prog)) return 0;\n"
        "\treturn -EACCES;\n")
    variants = {
        "no_gap_paren_single_reject":
            "static bool(TRUE) = true;\n",
        "no_gap_paren_head_reject":
            "static bool(ignored) = true, (TRUE) = true;\n",
        "no_gap_paren_ptr_qual_head_reject":
            "static bool *const ignored = 0, (TRUE) = true;\n",
        "no_gap_paren_attr_tail_reject":
            "static bool ignored = true,"
            " (TRUE) __attribute__((used)) = true;\n",
        "no_gap_paren_fn_pointer_head_reject":
            "static bool (*ignored)(void) = 0, (TRUE) = true;\n",
        }
    for tag, decl in variants.items():
        try:
            _simulate_header(
                tag, decl + tail, body,
                ("probe_fn",), {"probe_ids": {"probe_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert tag in str(exc), exc
            assert "while consulting mutable file binding" in str(
                exc), exc
        else:
            raise AssertionError("expected FilterNotUnderstood")
    verdict = _simulate_header(
        "no_gap_paren_single_nocall",
        "static bool(TRUE) = true;\n" + tail,
        "\tif (gate23(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["notes"] == []


def test_kfunc_filter_shadowed_param_alias_rejects():
    # Round 23, item 2 (exact counterexamples, verified against
    # compiled C at -O0 and -O2, which denies with -13 for both
    # membership polarities): a macro chain reaches a
    # parameterized endpoint whose parameter shares the
    # membership Boolean's name, while an object alias in its
    # body resolves to that Boolean. Expanding the alias
    # before argument substitution wrongly redirects the
    # remainder assignment to the unrelated argument variable;
    # correct C order substitutes arguments into parameters
    # first (with hygiene for shadowed names), then expands
    # object aliases, so the clearing of the true membership
    # Boolean stays visible. Two-object alias chains and
    # identity endpoints with trailing assignments reject the
    # same way.
    template = (
        "\tbool in23 ="
        " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "%s"
        "\tif (in23) return 0;\n"
        "\treturn -EACCES;\n")
    cases = {
        "shadowed_param_alias_reject": (
            "#define BIND23 in23\n"
            "#define MOD23(in23) ((BIND23) %= 1)\n"
            "#define STEP23() MOD23\n"
            "#define TOP23 STEP23\n"
            "static int spare23 = 1;\n",
            template % "\tTOP23()(spare23);\n"),
        "shadowed_param_identity_reject": (
            "#define BIND23 in23\n"
            "#define ID23(in23) BIND23\n"
            "#define STEP23() ID23\n"
            "#define TOP23 STEP23\n"
            "static int spare23 = 1;\n",
            template % "\tTOP23()(spare23) %= 1;\n"),
        "shadowed_param_two_objects_reject": (
            "#define NAME23 in23\n"
            "#define BIND23 NAME23\n"
            "#define MOD23(in23) ((BIND23) %= 1)\n"
            "#define STEP23() MOD23\n"
            "#define TOP23 STEP23\n"
            "static int spare23 = 1;\n",
            template % "\tTOP23()(spare23);\n"),
        }
    for tag, (header, stmt_body) in cases.items():
        try:
            _simulate_header(
                tag, header, stmt_body,
                ("probe_fn",), {"probe_ids": {"probe_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert tag in str(exc), exc
            assert "mutates membership alias" in str(exc), exc
        else:
            raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_inner_masked_comparison_rejects():
    # Round 23, item 3 (exact counterexamples, verified against
    # compiled C at -O0 and -O2 over a swept 144-pair offset
    # grid: the OR and XOR variants always deny with -13, the
    # complement variant always returns 0): a lowest-bit mask
    # around the inner comparison stops descendant inspection
    # before the unsupported high-bit computation unless the
    # audit descends through bit-selection masks around
    # comparisons and audits the masked operand fully. All
    # three wrappers (OR, XOR and complement around a
    # ``& 1U``/``& 3U`` inner mask) reject as composed bit
    # operands.
    base = ("(f & g) & (u32)((((!f + 0xffffffffffffffffULL)"
            " / 2ULL) & 0x8000000000000000ULL) != 0ULL)")
    prefix = ("\tu32 f = prog->aux->attach_st_ops_member_off;\n"
              "\tu32 g = kfunc_id;\n")
    for tag, condition in (
            ("inner_masked_or_reject",
             "(((((" + base + ") & 1U) + 1U) | 4U) & 2U)"),
            ("inner_masked_xor_reject",
             "(((((" + base + ") & 3U) + 1U) ^ 4U) & 2U)"),
            ("inner_masked_not_reject",
             "((~(((" + base + ") & 1U) + 1U)) & 2U)")):
        _expect_unrecognized(
            tag,
            prefix + "\tif (" + condition + ") return 0;\n"
            "\treturn -EACCES;\n",
            "composed bit operand")


def test_kfunc_filter_void_named_parameter_accepts():
    # Round 23, item 4 (over-regression positive control,
    # verified against compiled C at -O0 and -O2, which returns
    # 0 for membership present and -13 for membership absent):
    # a benign macro endpoint with one parameter named ``void``
    # spells a single parameterized argument, never the
    # ``(void)`` empty-parameter-list function spelling, so a
    # one-argument use expands with whole-token substitution
    # and the skipped statement stays pure. The parent commit
    # accepts this shape on both paths with types
    # {BPF_PROG_TYPE_TRACING} and no notes; this restores that
    # acceptance exactly.
    verdict = _simulate_header(
        "void_named_parameter_safe",
        "#define END23(void) ((void) + 1)\n"
        "#define STEP23() END23\n"
        "#define TOP23 STEP23\n"
        "static int unused23;\n",
        "\tbool in23 ="
        " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tTOP23()(4);\n"
        "\tif (in23) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {
        "BPF_PROG_TYPE_TRACING"}, verdict["probe_fn"]
    assert verdict["probe_fn"]["notes"] == [], verdict["probe_fn"]


def test_kfunc_filter_nested_identity_macros_accept():
    # Round 23, item 5 (over-regression positive control,
    # verified against compiled C at -O0 and -O2, which returns
    # 0 for membership present and -13 for membership absent):
    # four finite nested identity-macro invocations in a
    # skipped statement terminate after one pass per nesting
    # level; only genuinely cyclic or recursive chains are
    # outside the grammar. The parent commit accepts this
    # shape on both paths with types {BPF_PROG_TYPE_TRACING}
    # and no notes; this restores that acceptance exactly.
    verdict = _simulate_header(
        "nested_identity_macros_safe",
        "#define END23(n) (n)\n"
        "#define STEP23() END23\n"
        "#define TOP23 STEP23\n"
        "static int unused23;\n",
        "\tbool in23 ="
        " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tTOP23()(END23(END23(END23(1))));\n"
        "\tif (in23) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {
        "BPF_PROG_TYPE_TRACING"}, verdict["probe_fn"]
    assert verdict["probe_fn"]["notes"] == [], verdict["probe_fn"]


def test_kfunc_filter_comma_head_declarator_rejects():
    # Round 24, item 1 (exact shapes, verified against
    # compiled C at -O0 and -O2, which denies with -13 for
    # both membership polarities): the opening declarator of
    # a comma declaration binds exactly like a later one, so
    # a clearing write to it never stays invisible. The
    # parenthesized Boolean immediately adjoining its type
    # with no whitespace heads the list here, and the plain
    # and gapped-parenthesized heads share the same root
    # cause; otherwise the predicate read falls back to the
    # ``TRUE`` keyword spelling and grants while the
    # reference denies. Without the clearing call the head
    # still grants, since nothing invalidates the
    # initializer.
    tail = (
        "static bool gate24(const struct bpf_prog *prog)\n"
        "{ return TRUE; }\n"
        "#define CLEAR24 (TRUE = false)\n"
        "static bool invoke24(const struct bpf_prog *prog)\n"
        "{ return CLEAR24; }\n")
    body = (
        "\tinvoke24(prog);\n"
        "\tif (gate24(prog)) return 0;\n"
        "\treturn -EACCES;\n")
    variants = {
        "comma_head_paren_nogap_reject":
            "static bool(TRUE) = true, ignored = true;\n",
        "comma_head_plain_reject":
            "static bool TRUE = true, ignored = true;\n",
        "comma_head_paren_gap_reject":
            "static bool (TRUE) = true, ignored = true;\n",
        }
    for tag, decl in variants.items():
        try:
            _simulate_header(
                tag, decl + tail, body,
                ("probe_fn",), {"probe_ids": {"probe_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert tag in str(exc), exc
            assert "while consulting mutable file binding" in str(
                exc), exc
        else:
            raise AssertionError("expected FilterNotUnderstood")
    verdict = _simulate_header(
        "comma_head_paren_nogap_nocall",
        "static bool(TRUE) = true, ignored = true;\n" + tail,
        "\tif (gate24(prog)) return 0;\n"
        "\treturn -EACCES;\n",
        ("probe_fn",), {"probe_ids": {"probe_fn"}},
        ("BPF_PROG_TYPE_TRACING",))
    assert verdict["probe_fn"]["types"] == {"BPF_PROG_TYPE_TRACING"}
    assert verdict["probe_fn"]["notes"] == []


def test_kfunc_filter_redundant_paren_fn_pointer_head_rejects():
    # Round 24, item 2 (exact shapes, verified against
    # compiled C at -O0 and -O2, which denies with -13 for
    # both membership polarities): redundant parentheses
    # inside a function-pointer comma head -- around the
    # starred group, around its name, or nested -- still
    # open the declaration, so the later Boolean binds and
    # the clearing write stays visible. Otherwise the head
    # fails to replay, the later predicate read falls back
    # to the ``TRUE`` keyword spelling, and the filter
    # grants while the reference denies.
    tail = (
        "static bool gate24(const struct bpf_prog *prog)\n"
        "{ return TRUE; }\n"
        "#define CLEAR24 (TRUE = false)\n"
        "static bool invoke24(const struct bpf_prog *prog)\n"
        "{ return CLEAR24; }\n")
    body = (
        "\tinvoke24(prog);\n"
        "\tif (gate24(prog)) return 0;\n"
        "\treturn -EACCES;\n")
    variants = {
        "fn_ptr_redundant_group_reject":
            "static bool ((*ignored))(void) = 0,"
            " (TRUE) = true;\n",
        "fn_ptr_paren_name_reject":
            "static bool (*(ignored))(void) = 0,"
            " (TRUE) = true;\n",
        "fn_ptr_nested_parens_reject":
            "static bool ((*(ignored)))(void) = 0,"
            " (TRUE) = true;\n",
        }
    for tag, decl in variants.items():
        try:
            _simulate_header(
                tag, decl + tail, body,
                ("probe_fn",), {"probe_ids": {"probe_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert tag in str(exc), exc
            assert "while consulting mutable file binding" in str(
                exc), exc
        else:
            raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_comma_carrying_macro_argument_accepts():
    # Round 24, item 3 (over-rejection positive control,
    # verified against compiled C at -O0 and -O2, which
    # returns 0 for membership present and -13 for membership
    # absent): a parameterized invocation delimits its
    # arguments before object aliases expand, exactly as C
    # collects argument tokens first, so one argument
    # holding a comma-carrying alias stays a single argument
    # and the pure skipped statement stays accepted. Direct,
    # chained, alias-headed and nested invocations accept
    # alike with types {BPF_PROG_TYPE_TRACING} and no notes.
    template = (
        "\tbool in24 ="
        " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "%s"
        "\tif (in24) return 0;\n"
        "\treturn -EACCES;\n")
    cases = {
        "comma_arg_direct_safe": (
            "#define PAIR24 1, 2\n"
            "#define END24(n) ((n) + 0)\n"
            "static int unused24;\n",
            template % "\tEND24(PAIR24);\n"),
        "comma_arg_chained_safe": (
            "#define PAIR24 1, 2\n"
            "#define END24(n) ((n) + 0)\n"
            "#define STEP24() END24\n"
            "#define TOP24 STEP24\n"
            "static int unused24;\n",
            template % "\tTOP24()(PAIR24);\n"),
        "comma_arg_aliased_head_safe": (
            "#define PAIR24 1, 2\n"
            "#define END24(n) ((n) + 0)\n"
            "#define ALIAS24 END24\n"
            "static int unused24;\n",
            template % "\tALIAS24(PAIR24);\n"),
        "comma_arg_nested_safe": (
            "#define PAIR24 1, 2\n"
            "#define END24(n) ((n) + 0)\n"
            "#define OUTER24(m) ((m) + 0)\n"
            "#define STEP24() OUTER24\n"
            "#define TOP24 STEP24\n"
            "static int unused24;\n",
            template % "\tTOP24()(END24(PAIR24));\n"),
        }
    for tag, (header, stmt_body) in cases.items():
        verdict = _simulate_header(
            tag, header, stmt_body,
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
        assert verdict["probe_fn"]["types"] == {
            "BPF_PROG_TYPE_TRACING"}, verdict["probe_fn"]
        assert verdict["probe_fn"]["notes"] == [], (
            verdict["probe_fn"])


def test_kfunc_filter_deep_identity_macros_accept():
    # Round 24, item 4 (over-rejection positive control,
    # verified against compiled C at -O0 and -O2, which
    # returns 0 for membership present and -13 for membership
    # absent): finite identity-macro nesting 64 and 65
    # invocations deep in a skipped statement terminates and
    # stays accepted with types {BPF_PROG_TYPE_TRACING} and
    # no notes; only genuinely nonterminating chains are
    # outside the grammar.

    def nest(depth):
        text = "1"
        for _ in range(depth):
            text = "END24(%s)" % text
        return text

    header = (
        "#define END24(n) (n)\n"
        "#define STEP24() END24\n"
        "#define TOP24 STEP24\n"
        "static int unused24;\n")
    for depth in (64, 65):
        verdict = _simulate_header(
            "deep_identity_macros_%d_safe" % depth,
            header,
            "\tbool in24 ="
            " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
            "\tTOP24()(%s);\n" % nest(depth) +
            "\tif (in24) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
        assert verdict["probe_fn"]["types"] == {
            "BPF_PROG_TYPE_TRACING"}, verdict["probe_fn"]
        assert verdict["probe_fn"]["notes"] == [], (
            verdict["probe_fn"])


def test_kfunc_filter_comma_head_sibling_shapes_reject():
    # Round 25, item 1 (exact shapes, verified against
    # compiled C at -O0 and -O2, which denies with -13 for
    # both membership polarities): the opening declarator of
    # a comma declaration binds independently of its
    # siblings' shapes, so a clearing write to it never stays
    # invisible. The parenthesized Boolean heads the list
    # here with an uninitialized, pointer, array-braced or
    # function sibling; otherwise the head is missed, the
    # predicate read falls back to the keyword spelling and
    # grants while the reference denies.
    tail = (
        "static bool gate25(const struct bpf_prog *prog)\n"
        "{ return TRUE; }\n"
        "#define CLEAR25 (TRUE = false)\n"
        "static bool invoke25(const struct bpf_prog *prog)\n"
        "{ return CLEAR25; }\n")
    body = (
        "\tinvoke25(prog);\n"
        "\tbool in25 ="
        " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tif (in25 && gate25(prog)) return 0;\n"
        "\treturn -EACCES;\n")
    variants = {
        "comma_head_uninit_sibling_reject":
            "static bool (TRUE) = true, ignored25;\n",
        "comma_head_pointer_sibling_reject":
            "static bool (TRUE) = true, *ignored25 = 0;\n",
        "comma_head_array_sibling_reject":
            "static bool (TRUE) = true,"
            " ignored25[2] = {1, 2};\n",
        "comma_head_function_sibling_reject":
            "static bool (TRUE) = true, laterfunc25(void);\n",
        }
    for tag, decl in variants.items():
        try:
            _simulate_header(
                tag, decl + tail, body,
                ("probe_fn",), {"probe_ids": {"probe_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert tag in str(exc), exc
            assert "while consulting mutable file binding" in str(
                exc), exc
        else:
            raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_fn_pointer_spacing_rejects():
    # Round 25, item 2 (exact shapes, verified against
    # compiled C at -O0 and -O2, which denies with -13 for
    # both membership polarities): spacing, newlines and
    # comments between the star, the qualifiers and the name
    # inside a redundantly parenthesized function-pointer
    # comma head still open the declaration, so the later
    # Boolean binds and the clearing write stays visible.
    # Otherwise the head fails to replay and the filter
    # grants while the reference denies.
    assert uc._is_fn_pointer_declarator(
        "(* /*c*/ const ignored25)(void)") is True
    assert uc._is_fn_pointer_declarator(
        "((* const volatile ignored25))(void)") is True
    assert uc._unwrap_declarator_name(
        "* /*c*/ const p25") == "p25"
    tail = (
        "static bool gate25(const struct bpf_prog *prog)\n"
        "{ return TRUE; }\n"
        "#define CLEAR25 (TRUE = false)\n"
        "static bool invoke25(const struct bpf_prog *prog)\n"
        "{ return CLEAR25; }\n")
    body = (
        "\tinvoke25(prog);\n"
        "\tbool in25 ="
        " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "\tif (in25 && gate25(prog)) return 0;\n"
        "\treturn -EACCES;\n")
    variants = {
        "fn_ptr_space_before_const_reject":
            "static bool ((* const ignored25))(void) = 0,"
            " (TRUE) = true;\n",
        "fn_ptr_comment_before_const_reject":
            "static bool ((* /*c*/ const ignored25))(void) = 0,"
            " (TRUE) = true;\n",
        "fn_ptr_multi_qual_spacing_reject":
            "static bool ((* const volatile ignored25))(void)"
            " = 0, (TRUE) = true;\n",
        "fn_ptr_newline_before_const_reject":
            "static bool ((* \n const ignored25))(void) = 0,"
            " (TRUE) = true;\n",
        }
    for tag, decl in variants.items():
        try:
            _simulate_header(
                tag, decl + tail, body,
                ("probe_fn",), {"probe_ids": {"probe_fn"}},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert tag in str(exc), exc
            assert "while consulting mutable file binding" in str(
                exc), exc
        else:
            raise AssertionError("expected FilterNotUnderstood")


def test_kfunc_filter_zero_arg_comma_argument_accepts():
    # Round 25, item 3 (over-rejection positive control,
    # verified against compiled C at -O0 and -O2, which
    # returns 0 for membership present and -13 for membership
    # absent): a parameterized invocation delimits its
    # arguments before zero-argument invocations expand,
    # exactly as C collects argument tokens first, so one
    # argument supplied by a nullary macro expanding to
    # comma-separated constants stays a single argument and
    # the pure skipped statement stays accepted. Single,
    # two-argument and nested invocations accept alike with
    # types {BPF_PROG_TYPE_TRACING} and no notes.
    template = (
        "\tbool in25 ="
        " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
        "%s"
        "\tif (in25) return 0;\n"
        "\treturn -EACCES;\n")
    cases = {
        "comma_arg_zeroarg_single_safe": (
            "#define PAIR25() 1, 2\n"
            "#define END25(n) ((n) + 0)\n"
            "static int unused25;\n",
            template % "\tEND25(PAIR25());\n"),
        "comma_arg_zeroarg_twoarg_safe": (
            "#define PAIR25() 1, 2\n"
            "#define END225(a, b) (((a)) + ((b)))\n"
            "static int unused25;\n",
            template % "\tEND225(PAIR25(), 3);\n"),
        "comma_arg_zeroarg_nested_safe": (
            "#define PAIR25() 1, 2\n"
            "#define END25(n) ((n) + 0)\n"
            "#define OUTER25(m) ((m) + 0)\n"
            "static int unused25;\n",
            template % "\tOUTER25(END25(PAIR25()));\n"),
        }
    for tag, (header, stmt_body) in cases.items():
        verdict = _simulate_header(
            tag, header, stmt_body,
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
        assert verdict["probe_fn"]["types"] == {
            "BPF_PROG_TYPE_TRACING"}, verdict["probe_fn"]
        assert verdict["probe_fn"]["notes"] == [], (
            verdict["probe_fn"])


def test_kfunc_filter_very_deep_identity_macros_accept():
    # Round 25, item 4 (over-rejection positive control,
    # verified against compiled C at -O0 and -O2, which
    # returns 0 for membership present and -13 for membership
    # absent): finite identity-macro nesting 257, 512 and
    # 1000 invocations deep in a skipped statement terminates
    # and stays accepted with types {BPF_PROG_TYPE_TRACING}
    # and no notes; only genuinely nonterminating chains are
    # outside the grammar.

    def nest(depth):
        text = "1"
        for _ in range(depth):
            text = "END25(%s)" % text
        return text

    header = (
        "#define END25(n) (n)\n"
        "#define STEP25() END25\n"
        "#define TOP25 STEP25\n"
        "static int unused25;\n")
    for depth in (257, 512, 1000):
        verdict = _simulate_header(
            "very_deep_identity_macros_%d_safe" % depth,
            header,
            "\tbool in25 ="
            " btf_id_set8_contains(&probe_ids, kfunc_id);\n"
            "\tTOP25()(%s);\n" % nest(depth) +
            "\tif (in25) return 0;\n"
            "\treturn -EACCES;\n",
            ("probe_fn",), {"probe_ids": {"probe_fn"}},
            ("BPF_PROG_TYPE_TRACING",))
        assert verdict["probe_fn"]["types"] == {
            "BPF_PROG_TYPE_TRACING"}, verdict["probe_fn"]
        assert verdict["probe_fn"]["notes"] == [], (
            verdict["probe_fn"])


# Structural filter regressions. Every new counterexample below was checked
# with Ubuntu Clang 21.1.8 at -O0 and -O2 before being encoded. Return
# pairs in the comments are membership absent/present. The pinned base
# 0da1a6c silently accepts each rejection counterexample unless noted.
_F01_MEMBERSHIP = (
    "bool in_set = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
    "%s;\nif (in_set) return 0;\nreturn -EACCES;\n")
_F01_GLOBAL_TAIL = (
    "static bool gate(const struct bpf_prog *prog) { return TRUE; }\n"
    "static bool clear(const struct bpf_prog *prog) { return TRUE = false; }\n")
_F01_GLOBAL_BODY = (
    "clear(prog);\n"
    "bool in_set = btf_id_set8_contains(&probe_ids, kfunc_id);\n"
    "if (in_set && gate(prog)) return 0;\nreturn -EACCES;\n")


def _f01_expect(header, body, rejection):
    for present in (False, True):
        try:
            verdict = _simulate_header(
                "structural_filter", header, body, ("probe_fn",),
                {"probe_ids": {"probe_fn"} if present else set()},
                ("BPF_PROG_TYPE_TRACING",))
        except uc.FilterNotUnderstood as exc:
            assert rejection, str(exc)
            assert "outside the grammar" in str(exc) or "immutable" in str(exc), str(exc)
        else:
            assert not rejection, verdict
            assert verdict["probe_fn"]["types"] == (
                {"BPF_PROG_TYPE_TRACING"} if present else set()), verdict
            assert verdict["probe_fn"]["notes"] == [], verdict


def _f01_rejection_is_unpublished(header, body):
    """Exercise owner marker and exit 4 independently of simulator errors."""
    import argparse
    import contextlib
    import io
    from unittest.mock import patch

    with tempfile.TemporaryDirectory() as tmp:
        fixture = _fixture_with_filter(
            tmp, "structural", "bpf_fixture_structural", "probe_ids", body)
        staged = os.path.join(fixture.sources, "linux", "v1", "kernel", "bpf", "test_proto.c")
        with open(staged, encoding="utf-8") as handle:
            original = handle.read()
        with open(staged, "w", encoding="utf-8") as handle:
            handle.write(header + "\n" + original)
        fixture.repin()
        _, _, registry = fixture.extract()
        entry = next(record for record in registry["records"]
                     if record["id"] == "kfunc:bpf_fixture_structural")
        assert entry["helpers_or_kfuncs"][0]["callable"] is False
        assert len(entry["needs_owner_review"]) == 1
        assert any(note.startswith("NEEDS-OWNER: ")
                   for note in entry["callable_context_predicates"])
        assert any("kfunc:bpf_fixture_structural: needs owner review:" in error
                   for error in uc.check_completeness(registry))
        published = uc.dump_canonical(registry).encode("utf-8")
        with open(fixture.registry_path, "wb") as handle:
            handle.write(published)
        with open(fixture.lock_path, "rb") as handle:
            locked = handle.read()
        real_open = open

        def no_publication(path, mode="r", *args, **kwargs):
            if os.fspath(path) in (fixture.registry_path, fixture.lock_path):
                assert not any(flag in mode for flag in "wax+"), (path, mode)
            return real_open(path, mode, *args, **kwargs)

        args = argparse.Namespace(
            sources=fixture.sources, lock=fixture.lock_path,
            registry=fixture.registry_path, schema=SCHEMA_PATH, root=tmp)
        for command in (fixture.refresh, lambda: uc.cmd_validate(args)):
            diagnostic = io.StringIO()
            with patch("builtins.open", no_publication), contextlib.redirect_stderr(diagnostic):
                assert command() == 4
            # Refresh prints only the first twenty errors; this partial
            # fixture also lacks unrelated families. The complete error
            # list above proves the owner marker is a publication blocker.
            assert "error:" in diagnostic.getvalue()
        with open(fixture.registry_path, "rb") as handle:
            assert handle.read() == published
        with open(fixture.lock_path, "rb") as handle:
            assert handle.read() == locked


def _filter_acceptance_is_registered(header, body):
    """Prove accepted simulation survives source-backed registration."""
    with tempfile.TemporaryDirectory() as tmp:
        fixture = _fixture_with_filter(
            tmp, "structural", "bpf_fixture_structural", "probe_ids", body)
        staged = os.path.join(fixture.sources, "linux", "v1", "kernel", "bpf", "test_proto.c")
        with open(staged, encoding="utf-8") as handle:
            original = handle.read()
        with open(staged, "w", encoding="utf-8") as handle:
            handle.write(header + "\n" + original)
        fixture.repin()
        _, _, registry = fixture.extract()
        entry = next(record for record in registry["records"]
                     if record["id"] == "kfunc:bpf_fixture_structural")
        assert entry["helpers_or_kfuncs"][0]["callable"] is True
        assert not entry.get("needs_owner_review"), entry
        assert not any(note.startswith("NEEDS-OWNER: ")
                       for note in entry["callable_context_predicates"])


def test_f01_c1_declaration_heads_bind_independently():
    # C returns (-13, -13). Fresh long-initializer and comment-separated
    # heads grant on the base. Recombine each with all known sibling kinds.
    heads = ("static bool TRUE = " + "(" * 140 + "true" + ")" * 140,
             "static/**/bool TRUE = true")
    siblings = ("spare", "*spare = 0", "spare[2] = {1,2}",
                "spare(void)", "(*spare)(void) = 0")
    for head in heads:
        for sibling in siblings:
            header = head + ", " + sibling + ";\n" + _F01_GLOBAL_TAIL
            _f01_expect(header, _F01_GLOBAL_BODY, True)
    for head in heads:
        header = head + ", spare;\n" + _F01_GLOBAL_TAIL
        _f01_rejection_is_unpublished(header, _F01_GLOBAL_BODY)
        # No disturbance: the same binding remains usable, C (-13, 0).
        _f01_expect(header, _F01_GLOBAL_BODY.replace("clear(prog);\n", ""), False)


def test_f01_c1_unmodeled_initializer_cannot_be_a_keyword():
    # A braced scalar initializer is not in the value grammar. C denies
    # (-13, -13) after clear; the base misses the declaration and grants.
    header = "static bool TRUE = {true}, spare;\n" + _F01_GLOBAL_TAIL
    _f01_expect(header, _F01_GLOBAL_BODY, True)
    _f01_rejection_is_unpublished(header, _F01_GLOBAL_BODY)


def test_f01_c1_external_declaration_boundaries():
    # C (-13,-13) after clear and (-13,0) without it. A function
    # declarator's name is not part of the shared type; an external
    # macro invocation does not consume the next declaration. The base
    # silently grants the function-head mutation case.
    declarations = (
        "static bool spare(void), TRUE = true;\n",
        "#define DECLARE()\nDECLARE()\nstatic bool TRUE = true, spare;\n",
    )
    for declaration in declarations:
        header = declaration + _F01_GLOBAL_TAIL
        _f01_expect(header, _F01_GLOBAL_BODY, True)
        _f01_rejection_is_unpublished(header, _F01_GLOBAL_BODY)
        _f01_expect(header, _F01_GLOBAL_BODY.replace("clear(prog);\n", ""), False)


def test_f01_c2_recursive_declarators_open_once():
    # C (-13, -13). Parentheses around the complete declarator, a pointer
    # returning another function pointer, and an array of pointers all
    # hide TRUE on the base. Qualifiers/comments exercise token boundaries.
    declarators = (
        "((*ignored)(void)) = 0",
        "(* const (*ignored)(void))(void) = 0",
        "(*ignored[])(void) = {0}",
    )
    for declarator in declarators:
        header = "static bool " + declarator + ", TRUE = true;\n" + _F01_GLOBAL_TAIL
        _f01_expect(header, _F01_GLOBAL_BODY, True)
        _f01_rejection_is_unpublished(header, _F01_GLOBAL_BODY)
        _f01_expect(header, _F01_GLOBAL_BODY.replace("clear(prog);\n", ""), False)


def test_f01_c3_forwarded_comma_carriers_rescan_after_prescan():
    # C (-13, 0); base rejects with one argument at END. Prescan expands
    # PAIR within APPLY's single argument, then END sees two arguments.
    for carrier, use in (("#define PAIR 1, 2\n", "PAIR"),
                         ("#define PAIR() 1, 2\n", "PAIR()")):
        header = carrier + "#define APPLY(x) END(x)\n#define END(a,b) (0)\n"
        _f01_expect(header, _F01_MEMBERSHIP % ("APPLY(" + use + ")"), False)


def test_f01_c3_forwarded_comma_arity_errors_reject():
    # C compilation fails at both optimization levels; base grants.
    for carrier, use in (("#define PAIR 1, 2\n", "PAIR"),
                         ("#define PAIR() 1, 2\n", "PAIR()")):
        header = carrier + "#define APPLY(x) END(x)\n#define END(a) (0)\n"
        body = _F01_MEMBERSHIP % ("APPLY(" + use + ")")
        _f01_expect(header, body, True)
        _f01_rejection_is_unpublished(header, body)


def test_f01_c3_only_parentheses_protect_argument_commas():
    # The preprocessor discards both arguments, so the bracket/brace text
    # never becomes C syntax. C (-13, 0); base incorrectly collects one.
    for use in ("DROP({1,2})", "DROP(array[1,2])"):
        _f01_expect("#define DROP(a,b) (0)\n", _F01_MEMBERSHIP % use, False)


def test_filter_declarator_groups_have_no_text_length_boundary():
    # GCC 15.2.0 and Clang 21.1.8, -O0/-O2: (-13, -13).
    # The base's 256-character limit loses all three heads. Whitespace
    # changes spelling size without changing the declaration grammar.
    for depth, separator in ((129, ""), (193, " "), (257, "\n")):
        name = ("(" + separator) * depth + "TRUE" + (separator + ")") * depth
        header = "static bool " + name + " = true, spare;\n" + _F01_GLOBAL_TAIL
        _f01_expect(header, _F01_GLOBAL_BODY, True)
        _f01_rejection_is_unpublished(header, _F01_GLOBAL_BODY)


def test_filter_comments_separate_pointer_qualifiers():
    # GCC/Clang at both levels: (-13, -13). Comment deletion on the
    # base merges qualifiers into an identifier and hides the comma head.
    for qualifiers in ("const/**/volatile", "volatile/* sole separator */const",
                       "const/**/_Atomic/*\n*/volatile"):
        header = ("static bool (*" + qualifiers + " ignored)(void)=0, TRUE=true;\n"
                  + _F01_GLOBAL_TAIL)
        _f01_expect(header, _F01_GLOBAL_BODY, True)
        _f01_rejection_is_unpublished(header, _F01_GLOBAL_BODY)


def test_filter_zero_argument_carriers_forward_expanded_arguments():
    # GCC/Clang at both levels: (-13, 0). Each carrier supplies one raw
    # argument to APPLY and two expanded arguments to the downstream call.
    # The base reports the wrong arity for the direct and fresh carriers.
    for carrier, call, downstream in (
        ("#define PAIR() 1,2\n", "PAIR()", "END(x)"),
        ("#define PAIR() 1,2\n#define ALIAS PAIR\n", "ALIAS()", "END(x)"),
        ("#define PAIR() 1,2\n#define NEXT() PAIR()\n"
         "#define BRIDGE(a,b) END(a,b)\n", "NEXT()", "BRIDGE(x)"),
    ):
        header = carrier + "#define APPLY(x) " + downstream + "\n#define END(a,b) (0)\n"
        body = _F01_MEMBERSHIP % ("APPLY(" + call + ")")
        _f01_expect(header, body, False)
        _filter_acceptance_is_registered(header, body)


def test_f01_c4_reference_expression_boundary_is_not_argument_depth():
    # GCC 15.2 at -O0/-O2 accepts 2048, 2049 and 4097 expanded groups;
    # Clang 21.1.8 defaults to a 2048 parser limit, even with a large
    # stack. A reference's resource limit cannot reject finite grammar.
    for depth in (64, 65, 257, 2048, 2049, 4097):
        text = "ID(" * depth + "1" + ")" * depth
        _f01_expect("#define ID(n) (n)\n", _F01_MEMBERSHIP % text, False)


def test_f01_c4_observed_macro_stack_boundary():
    # GCC and Clang with a 128 MiB stack return (-13, 0) at all
    # three depths, -O0/-O2. Clang's crashes at the latter depths
    # with a 32 MiB stack are resource failures, not grammar limits.
    header = "#define ID(n) n\nstatic int unused;\n"
    before = sys.getrecursionlimit()
    for depth in (7820, 8000, 8192):
        text = "ID(" * depth + "1" + ")" * depth
        _f01_expect(header, _F01_MEMBERSHIP % text, False)
    assert sys.getrecursionlimit() == before


def test_filter_finite_macro_nesting_has_no_depth_boundary():
    # Both compilers at -O0/-O2 with a 128 MiB stack give (-13, 0).
    # GCC also accepts the bare calls at 8 MiB. Deeper calls and fresh
    # alias/nullary carriers prove that acceptance is structural, not
    # a larger cap. The extra forwarding level is covered below.
    before = sys.getrecursionlimit()
    cases = [("#define ID(n) n\n", "ID(", depth)
             for depth in (8192, 8193, 16385)]
    cases.extend((
        ("#define ID(n) n\n#define ALIAS ID\n", "ALIAS(", 8193),
        ("#define ID(n) n\n#define PICK() ID\n", "PICK()(", 10241),
    ))
    expanded = []
    for header, prefix, depth in cases:
        header += "static int unused;\n"
        text = prefix * depth + "1" + ")" * depth
        expansion = uc._prepare_macro_expansion(
            uc._live_file_defines(header), uc._live_zero_arg_defines(header),
            uc._live_parameterized_defines(header))
        assert uc._expand_all_macros(text, expansion).strip() == "1"
        expanded.append((header, text))
    # Check all preprocessing boundaries before whole-file discovery;
    # the latter is prohibitively slow on the old recursive parser.
    for header, text in expanded:
        body = _F01_MEMBERSHIP % text
        _f01_expect(header, body, False)
        _filter_acceptance_is_registered(header, body)
    assert sys.getrecursionlimit() == before


def test_filter_forwarded_identity_chain_crosses_former_depth_limit():
    # GCC/Clang -O0/-O2 at 128 MiB: (-13, 0) at both depths. The
    # base counts the forwarding call as another argument level: its
    # 8192 control accepts, and its 8193 counterexample rejects.
    header = ("#define ID(n) n\n#define STEP() ID\n#define TOP STEP\n"
              "static int unused;\n")
    expansion = uc._prepare_macro_expansion(
        uc._live_file_defines(header), uc._live_zero_arg_defines(header),
        uc._live_parameterized_defines(header))
    for depth in (8193, 8192):
        text = "TOP()(" + "ID(" * depth + "1" + ")" * depth + ")"
        assert uc._expand_all_macros(text, expansion).strip() == "1"
        body = _F01_MEMBERSHIP % text
        _f01_expect(header, body, False)
        _filter_acceptance_is_registered(header, body)


def test_filter_recursive_expansion_is_not_finite_nesting():
    # GCC/Clang -O0/-O2 diagnose each used recursive replacement,
    # including after 8193 finite calls. The base silently admits the
    # shallow self/object cycles. Cycle identity, not frame count,
    # controls rejection; every rejection must block both CLI paths.
    recursive = (
        ("#define LOOP(n) LOOP(n)\n", "LOOP(1)"),
        ("#define LEFT RIGHT\n#define RIGHT LEFT\n", "LEFT"),
        ("#define LOOP(n) BRIDGE(n)\n#define BRIDGE(n) LOOP(n)\n", "LOOP(1)"),
    )
    for macros, call in recursive:
        header = "#define ID(n) n\n" + macros + "static int unused;\n"
        for depth in (0, 8193):
            text = "ID(" * depth + call + ")" * depth
            body = _F01_MEMBERSHIP % text
            _f01_expect(header, body, True)
            _f01_rejection_is_unpublished(header, body)
    # GCC/Clang both return (-13, 0): an unused argument does not
    # expand, so its apparent cycle is never reached. A declaration
    # dependency graph alone must not reject this finite expansion.
    header = ("#define ID(n) n\n#define LOOP(n) LOOP(n)\n"
              "#define DROP(n) 0\nstatic int unused;\n")
    text = "DROP(" + "ID(" * 8193 + "LOOP(1)" + ")" * 8193 + ")"
    body = _F01_MEMBERSHIP % text
    _f01_expect(header, body, False)
    _filter_acceptance_is_registered(header, body)


def test_f01_c4_stable_text_is_not_termination():
    # Clang rejects both at -O0/-O2 (undeclared residual invocation/name).
    # Both stabilize textually and silently grant on the base. Mutual
    # function recursion is the previously caught control for this class.
    for header, call in (("#define LOOP(x) LOOP(x)\n", "LOOP(1)"),
                         ("#define LEFT RIGHT\n#define RIGHT LEFT\n", "LEFT")):
        body = _F01_MEMBERSHIP % call
        _f01_expect(header, body, True)
        _f01_rejection_is_unpublished(header, body)


def test_filter_cycle_commands_preserve_publication_sentinels():
    """A live cycle blocks both command entry points without publication."""
    import subprocess

    with tempfile.TemporaryDirectory() as tmp:
        fixture = _fixture_with_filter(
            tmp, "cycle", "bpf_fixture_cycle", "probe_ids",
            _F01_MEMBERSHIP % "LOOP(1)")
        staged = os.path.join(fixture.sources, "linux", "v1", "kernel", "bpf", "test_proto.c")
        with open(staged, encoding="utf-8") as handle:
            original = handle.read()
        with open(staged, "w", encoding="utf-8") as handle:
            handle.write("#define LOOP(n) LOOP(n)\n" + original)
        # Refresh prints only twenty gate errors. Cover enough unrelated
        # families to assert the cycle's diagnostic in the actual CLI.
        uapi = os.path.join(fixture.sources, "uapi", "v1", "bpf.h")
        with open(uapi, "a", encoding="utf-8") as handle:
            handle.write("""
enum bpf_map_type {
    BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_PROG_ARRAY, BPF_MAP_TYPE_SK_STORAGE,
    BPF_MAP_TYPE_RINGBUF, BPF_MAP_TYPE_ARENA,
};
enum bpf_attach_type {
    BPF_CGROUP_INET_INGRESS, BPF_FLOW_DISSECTOR, BPF_LIRC_MODE2,
    BPF_TRACE_RAW_TP, BPF_TRACE_FENTRY, BPF_TRACE_ITER,
    BPF_TRACE_KPROBE_MULTI, BPF_TRACE_UPROBE_MULTI,
    BPF_TRACE_UPROBE_SESSION, BPF_LSM_MAC, BPF_LSM_CGROUP, BPF_TCX_INGRESS,
};
""")
        fixture.repin()
        _, lock, registry = fixture.extract()
        published = uc.dump_canonical(registry).encode("utf-8")
        # Give validation a correctly bound JSON sentinel so neither
        # malformed input nor a stale publication pin can explain exit 4.
        lock["published"] = {
            "registry_digest": hashlib.sha256(published).hexdigest(),
            "records": len(registry["records"]),
            "members": len(registry["enum_members"]),
            "revision": registry["revision"],
        }
        locked = uc.dump_canonical(lock).encode("utf-8")
        with open(fixture.lock_path, "wb") as handle:
            handle.write(locked)
        assert uc.validate_schema(registry, load_schema()) == []
        assert uc.check_binding(registry, lock, hashlib.sha256(published).hexdigest()) == []

        for command, sentinel in (("refresh", b"publication sentinel\n"),
                                  ("validate", published)):
            with open(fixture.registry_path, "wb") as handle:
                handle.write(sentinel)
            before = os.stat(fixture.registry_path)
            result = subprocess.run(
                [sys.executable, "-B", TOOL_PATH, command,
                 "--sources", fixture.sources, "--lock", fixture.lock_path,
                 "--registry", fixture.registry_path, "--schema", SCHEMA_PATH],
                capture_output=True, text=True, timeout=30, check=False)
            with open(fixture.registry_path, "rb") as handle:
                assert handle.read() == sentinel, command
            with open(fixture.lock_path, "rb") as handle:
                assert handle.read() == locked, command
            after = os.stat(fixture.registry_path)
            assert (after.st_ino, after.st_mtime_ns, after.st_ctime_ns) == (
                before.st_ino, before.st_mtime_ns, before.st_ctime_ns), command
            assert result.returncode == 4, (command, result.stdout, result.stderr)
            assert result.stdout == "", (command, result.stdout)
            assert "kfunc:bpf_fixture_cycle: needs owner review: filter cycle_filter" in result.stderr
            assert "macro chain does not terminate: LOOP" in result.stderr
            if command == "refresh":
                assert "not publishing:" in result.stderr
            else:
                assert "registry bytes differ" not in result.stderr
                assert "does not match" not in result.stderr

        entry = next(record for record in registry["records"]
                     if record["id"] == "kfunc:bpf_fixture_cycle")
        assert entry["helpers_or_kfuncs"][0]["callable"] is False
        assert len(entry["needs_owner_review"]) == 1
        assert entry["needs_owner_review"][0].startswith("filter cycle_filter (v1): ")
        assert "outside the grammar" in entry["needs_owner_review"][0]
        assert any(note.startswith("NEEDS-OWNER: filter cycle_filter (v1): ")
                   for note in entry["callable_context_predicates"])


def _check_unmodeled_file_declarations(declarations):
    # GCC 15.2 and Clang 21.1 at -O0/-O2 deny both membership states.
    for declaration in declarations:
        header = declaration + "\n" + _F01_GLOBAL_TAIL
        _f01_expect(header, _F01_GLOBAL_BODY, True)
        _f01_rejection_is_unpublished(header, _F01_GLOBAL_BODY)
        # Unused opaque declarations and macro-generated function bodies
        # do not put their types, parameters or local reads in file scope.
        unused = declaration.replace("TRUE", "unrelated") + "\n"
        unused += ("#define BODY(name) static int name(void)\n"
                   "BODY(unused) { return -EACCES; }\n")
        _f01_expect(unused, _F01_MEMBERSHIP % "0", False)


def test_filter_atomic_type_declarations_cannot_disappear():
    _check_unmodeled_file_declarations((
        "static _Atomic(bool) TRUE = true;",
        "static _Atomic (_Bool) (TRUE) = true;",
    ))


def test_filter_inferred_type_declarations_cannot_disappear():
    _check_unmodeled_file_declarations((
        "static __auto_type TRUE = true;",
        "static __typeof__(true) TRUE = true;",
        "static typeof(_Bool) (TRUE) = true;",
        "__typeof__(true) TRUE = true;",
        'typeof(_Bool) TRUE asm("inferred_true") = true;',
        "__typeof__(true) TRUE;",
        '__typeof__(true) TRUE asm("inferred_uninitialized");',
    ))


def test_filter_assembler_labels_cannot_hide_bindings():
    _check_unmodeled_file_declarations((
        'static bool TRUE __asm__("renamed_true") = true;',
        'static bool (TRUE) asm("renamed_other") = true;',
    ))


def test_filter_gnu_pointer_qualifiers_cannot_hide_comma_siblings():
    _check_unmodeled_file_declarations((
        "static bool (* __const__ ignored)(void) = 0, TRUE = true;",
        "static bool (* __volatile__/**/__const ignored)(void) = 0, TRUE = true;",
    ))


def test_filter_alignment_specifiers_cannot_hide_bindings():
    _check_unmodeled_file_declarations(("static _Alignas(16) bool TRUE = true;",))


def _check_erased_conversions(types):
    # GCC/Clang -O0/-O2: the first three wrappers allow both states;
    # the arithmetic/comparison wrapper denies both. All must reject
    # because the conversion is outside the inventory's integer grammar.
    header = "typedef unsigned long word_alias; typedef int signed_alias;\n"
    for kind in types:
        operand = "(unsigned long)(" + kind + ")in_set"
        erased = "(" + operand + " & 0U)"
        for condition in ("!(" + erased + " & 1U)", "(" + erased + " | 1U)",
                          "(~" + erased + " & 2U)", "(" + erased + " + 1U) == 0U"):
            body = ("bool in_set = btf_id_set8_contains(&probe_ids,kfunc_id);\n"
                    "if (" + condition + ") return 0;\nreturn -EACCES;\n")
            _f01_expect(header, body, True)
            _f01_rejection_is_unpublished(header, body)


def test_filter_zero_masks_cannot_erase_floating_conversions():
    _check_erased_conversions(("double", "float", "long double"))


def test_filter_zero_masks_cannot_erase_pointer_conversions():
    _check_erased_conversions(("void *", "const int *"))


def test_filter_zero_masks_cannot_erase_unproven_typedef_conversions():
    _check_erased_conversions(("word_alias", "signed_alias"))


def _check_finite_condition_frames(replacement, depths):
    # GCC/Clang -O0/-O2 return (-13, 0). Clang used a 128 MiB
    # process stack and a 20000 bracket-depth setting for the deeper
    # cases; those compiler resource knobs are not grammar boundaries.
    before = sys.getrecursionlimit()
    header = "#define ID(n) " + replacement + "\n"
    for depth in depths:
        condition = "ID(" * depth + "in_set" + ")" * depth
        body = ("bool in_set = btf_id_set8_contains(&probe_ids,kfunc_id);\n"
                "if (" + condition + ") return 0;\nreturn -EACCES;\n")
        verdict = _simulate_header(
            "structural_filter", header, body, ("inside", "outside"),
            {"probe_ids": {"inside"}}, ("BPF_PROG_TYPE_TRACING",))
        assert verdict["inside"]["types"] == {"BPF_PROG_TYPE_TRACING"}
        assert verdict["outside"]["types"] == set()
        assert verdict["inside"]["notes"] == verdict["outside"]["notes"] == []
        _filter_acceptance_is_registered(header, body)
    assert sys.getrecursionlimit() == before


def test_filter_finite_parenthesized_guards_have_no_recursion_boundary():
    _check_finite_condition_frames("(n)", (1200, 2401, 6001))
    for macros, call in (("#define LOOP(n) LOOP(n)\n", "LOOP(in_set)"),
                         ("#define A(n) B(n)\n#define B(n) A(n)\n", "A(in_set)")):
        header = "#define ID(n) (n)\n" + macros
        body = ("bool in_set = btf_id_set8_contains(&probe_ids,kfunc_id);\n"
                "if (" + "ID(" * 1200 + call + ")" * 1200
                + ") return 0;\nreturn -EACCES;\n")
        _f01_expect(header, body, True)
        _f01_rejection_is_unpublished(header, body)


def test_filter_finite_negated_guards_have_no_recursion_boundary():
    _check_finite_condition_frames("!(!(n))", (1200,))


def test_filter_finite_mixed_guards_have_no_recursion_boundary():
    _check_finite_condition_frames("(((n) && 1) || 0)", (1200,))


def test_f01_c5_operators_audit_operands_before_erasing_them():
    # C returns (-13,-13) for the first three wrappers and (0,0) for the
    # last three, for both erasers and both cores. All 24 variants silently
    # match C on the base; all must instead reject the unsupported operand.
    cores = (
        "(((!in_set + 0xffffffffffffffffULL) / 2ULL) & 0x8000000000000000ULL)",
        "(((u32)-(in_set == 0) * 2U) & 1U)",
    )
    wrappers = ("((%s) & 1U)", "(((%s) + 1U) & 2U)",
                "(((%s) | 4U) & 2U)", "((~(%s)) & 2U)",
                "((%s) | 1U)", "(!(%s) & 1U)")
    for core in cores:
        for erased in ("(0U & (%s))" % core, "((%s) ^ (%s))" % (core, core)):
            for wrapper in wrappers:
                condition = wrapper % erased
                body = ("bool in_set = btf_id_set8_contains(&probe_ids,kfunc_id);\n"
                        "if (" + condition + ") return 0;\nreturn -EACCES;\n")
                _f01_expect("", body, True)
            _f01_rejection_is_unpublished("", body)


def test_f01_c5_helper_folds_retain_original_operands():
    # C (-13,-13); base silently denies after replacing the helper with 0.
    core = ("(((!prog->aux->attach_st_ops_member_off + 0xffffffffffffffffULL)"
            " / 2ULL) & 0x8000000000000000ULL)")
    for expr in ("0U & " + core, core + " ^ " + core):
        header = "static unsigned int gate(const struct bpf_prog *prog) { return " + expr + "; }\n"
        body = "if (gate(prog)) return 0;\nreturn -EACCES;\n"
        _f01_expect(header, body, True)
        _f01_rejection_is_unpublished(header, body)


def _membership_condition_body(condition):
    return ("bool in_set = btf_id_set8_contains(&probe_ids,kfunc_id);\n"
            "if (" + condition + ") return 0;\nreturn -EACCES;\n")


def test_filter_leading_alignment_stays_with_its_declaration():
    # GCC/Clang -O0/-O2: (-13, 0) for every placement and unused control.
    # Even matching Boolean results must reject unmodeled declarations.
    declarations = (
        "_Alignas(16) static bool TRUE = true;",
        "static _Alignas(16) bool TRUE = true;",
        "_Alignas(16) bool TRUE = true;",
        "_Alignas(_Bool) _Alignas(8) static bool (TRUE) = true;",
        "_Alignas(0) static bool TRUE = true;",
        "_Alignas(16) static _Alignas(8) bool TRUE = true;",
        "static bool _Alignas(16) TRUE = true;",
    )
    body = _membership_condition_body("in_set && TRUE")
    for declaration in declarations:
        _f01_expect(declaration, body, True)
        _f01_rejection_is_unpublished(declaration, body)
        unused = declaration.replace("TRUE", "unused")
        control = _membership_condition_body("in_set")
        _f01_expect(unused, control, False)
        _filter_acceptance_is_registered(unused, control)


_MACRO_SCOPE_HEADER = "#define ID(x) x\n#define NEXT(x) ID(x)\n"


def _check_completed_macro_scopes(header, conditions):
    # GCC/Clang -O0/-O2: (-13, 0), including calls spanning replacements
    # and source tokens. Disabling belongs to an invocation's scope.
    for condition in conditions:
        body = _membership_condition_body(condition)
        _f01_expect(header, body, False)
        _filter_acceptance_is_registered(header, body)


def test_filter_generated_calls_release_completed_macro_scopes():
    _check_completed_macro_scopes(_MACRO_SCOPE_HEADER, (
        "ID(NEXT)(in_set)",
        "ID(ID(NEXT))(in_set)",
        "ID(NEXT)(ID(ID(in_set)))",
        "ID(NEXT)(ID(NEXT)(in_set))",
        "ID(NEXT)(in_set) && ID(NEXT)(in_set)",
    ))
    _check_completed_macro_scopes(
        _MACRO_SCOPE_HEADER + "#define START ID(NEXT)\n", ("START(in_set)",))
    _check_completed_macro_scopes(
        _MACRO_SCOPE_HEADER + "#define NAME() NEXT\n", ("ID(NAME)()(in_set)",))


def test_filter_forwarded_pairs_release_completed_macro_scopes():
    header = (_MACRO_SCOPE_HEADER + "#define FORWARD(x) END(x)\n"
              "#define END(a,b) ID(a)\n")
    for carrier, condition in (
        ("#define PAIR in_set, 0\n", "ID(FORWARD)(PAIR)"),
        ("#define PAIR() in_set, 0\n", "ID(FORWARD)(PAIR())"),
        ("#define PAIR() in_set, 0\n#define ALIAS PAIR\n",
         "ID(ID(FORWARD))(ALIAS())"),
        ("#define PAIR() ID(NEXT)(in_set), 0\n", "ID(FORWARD)(PAIR())"),
    ):
        _check_completed_macro_scopes(header + carrier, (condition,))


def test_filter_completed_macro_scopes_keep_live_cycles_rejected():
    # The discarded argument is finite in C: it is never expanded.
    header = (_MACRO_SCOPE_HEADER + "#define DROP(x) 0\n"
              "#define LOOP(x) LOOP(x)\n")
    _check_completed_macro_scopes(
        header, ("ID(NEXT)(in_set) || DROP(ID(LOOP)(in_set))",))
    # GCC/Clang -O0/-O2 reject the remaining residual macro calls.
    # Completed scopes may expire; the current invocation must stay disabled.
    for macros, condition in (
        ("#define LOOP(x) LOOP(x)\n", "ID(LOOP)(in_set)"),
        ("#define LEFT(x) RIGHT(x)\n#define RIGHT(x) LEFT(x)\n",
         "ID(LEFT)(in_set)"),
        ("#define LOOP(x) ID(LOOP)(x)\n", "LOOP(in_set)"),
        ("", "ID(ID)(in_set)"),
        ("#define LOOP(x) LOOP(x)\n", "ID(NEXT)(in_set) || ID(LOOP)(in_set)"),
        ("#define LOOP(x) LOOP(x)\n", "ID(NEXT)(in_set) && ID(LOOP)(in_set)"),
    ):
        body = _membership_condition_body(condition)
        _f01_expect(_MACRO_SCOPE_HEADER + macros, body, True)
        _f01_rejection_is_unpublished(_MACRO_SCOPE_HEADER + macros, body)


def _fresh_unsupported_validation_has_owner_diagnostic(condition):
    """A complete, bound publication must not hide fresh inventory errors."""
    import subprocess

    body = _membership_condition_body(condition)
    _f01_expect("", body, True)
    with tempfile.TemporaryDirectory() as tmp:
        fixture = _fixture_with_filter(
            tmp, "fresh", "bpf_fixture_fresh", "probe_ids", body)
        _, lock, fresh = fixture.extract()
        entry = next(record for record in fresh["records"]
                     if record["id"] == "kfunc:bpf_fixture_fresh")
        assert entry["helpers_or_kfuncs"][0]["callable"] is False
        assert entry["needs_owner_review"]
        assert any(note.startswith("NEEDS-OWNER: filter fresh_filter")
                   for note in entry["callable_context_predicates"])
        # Retain valid published content while binding the temporary copy
        # to this source snapshot. Its own completeness/binding diagnostics
        # cannot supply the marker expected from the newly inventoried input.
        with open(REGISTRY_PATH, encoding="utf-8") as handle:
            previous = json.load(handle)
        previous["generated_by"]["lock_digest"] = uc.lock_digest_of(lock)
        published = uc.dump_canonical(previous).encode("utf-8")
        lock[uc.PUBLISHED_KEY] = {
            "registry_digest": hashlib.sha256(published).hexdigest(),
            "records": len(previous["records"]),
            "members": len(previous["enum_members"]),
            "revision": previous["revision"],
        }
        locked = uc.dump_canonical(lock).encode("utf-8")
        with open(fixture.registry_path, "wb") as handle:
            handle.write(published)
        with open(fixture.lock_path, "wb") as handle:
            handle.write(locked)
        assert uc.validate_schema(previous, load_schema()) == []
        assert uc.check_completeness(previous) == []
        assert uc.check_binding(previous, lock, hashlib.sha256(published).hexdigest()) == []
        command = [sys.executable, "-B", TOOL_PATH, "validate",
                   "--registry", fixture.registry_path, "--lock", fixture.lock_path,
                   "--schema", SCHEMA_PATH]
        control = subprocess.run(command, capture_output=True, text=True, timeout=30)
        assert control.returncode == 0, (control.stdout, control.stderr)
        assert control.stderr == ""
        before = [os.stat(path) for path in (fixture.registry_path, fixture.lock_path)]
        result = subprocess.run(command + ["--sources", fixture.sources],
                                capture_output=True, text=True, timeout=30)
        for path, expected, initial in zip(
                (fixture.registry_path, fixture.lock_path), (published, locked), before):
            with open(path, "rb") as handle:
                assert handle.read() == expected
            after = os.stat(path)
            assert (after.st_ino, after.st_mtime_ns, after.st_ctime_ns) == (
                initial.st_ino, initial.st_mtime_ns, initial.st_ctime_ns)
        assert result.returncode == 4, (result.stdout, result.stderr)
        assert result.stdout == ""
        assert "kfunc:bpf_fixture_fresh: needs owner review: filter fresh_filter" in result.stderr
        assert "outside the grammar" in result.stderr
        assert "registry bytes differ" in result.stderr
        assert "does not match" not in result.stderr


def test_validate_reports_fresh_unsupported_complemented_comparison():
    # GCC/Clang -O0/-O2 return (0, 0); the unsupported inner computation
    # must still supply the owner diagnostic when comparing a valid registry.
    for condition in (
        "!((((u32)~(in_set == 0) / 2U) & 0x80000000U) & 0U)",
        "!((~(in_set == 0) / 2U & 0x80000000U) & 0U)",
    ):
        _fresh_unsupported_validation_has_owner_diagnostic(condition)


def test_validate_reports_fresh_unsupported_masked_conversion():
    # GCC/Clang -O0/-O2: (0, 0).
    for kind in ("double", "void *"):
        _fresh_unsupported_validation_has_owner_diagnostic(
            "!((unsigned long)(" + kind + ")in_set & 0U)")


def test_validate_reports_fresh_unsupported_mutated_boolean():
    # GCC/Clang -O0/-O2: (0, 0).
    for condition in (
        "!((((u32)-(in_set == 0) * 2U) & 1U) & 0U)",
        "!((((!in_set + 0xffffffffU) / 2U) & 0x80000000U) & 0U)",
    ):
        _fresh_unsupported_validation_has_owner_diagnostic(condition)


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
