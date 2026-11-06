# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""SDK compatibility: the v1 surface only grows, and old code builds.

Four guards for the ``mojobpf`` Mojo package surface:

* the additive rule: while the SDK major version is 1, the
  current export list must still contain every v1.0 module and
  name with byte-identical signatures (the frozen baseline
  below); removals, renames, and signature changes require a
  major bump plus a reviewed re-baseline here;
* the frontend negatives: the genuine Mojo compiler rejects
  unknown modules, unknown names, wrong-module names, and
  deeper-than-module paths at the source layer, and accepts
  alias and parenthesized-list spellings, with a passing
  control proving the harness itself can succeed;
* the old-examples proof: the four committed examples build
  unchanged (byte-identical sources) through the genuine
  ``build_project`` pipeline against the current SDK resources
  (byte-pinned to the packaged copy by the wheel-contents
  suite; the true installed-wheel path is covered by the
  installed-build suite);
* the event-manifests proof: the committed tracepoint-event
  manifests (healthy and small rings) build through the same
  genuine pipeline to the exact qualified bytes (matching the
  structure and kernel suites' pins), proving the driver path
  agrees with the direct pipeline.

Requires the genuine ``mojo``/``llc`` tools on PATH for the
frontend and build proofs. A missing tool is an environment
failure, never a pass.

Runnable directly (``python3
tests/packaging/test_sdk_compat.py``) or under any ``test_``-style
runner. Standard library only.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)

sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf.build import BuildRequest, build_project  # noqa: E402
from mojobpf.inspect import inspect_object  # noqa: E402
from mojobpf import sdk as sdk_module  # noqa: E402

SDK_DIR = os.path.join(
    REPO_ROOT, "src", "mojobpf", "resources", "sdk"
)
ADAPTER = os.path.join(
    REPO_ROOT, "compiler", "adapter_service.py"
)
LOCKFILE = os.path.join(REPO_ROOT, "toolchains.lock.json")
PIXI_BIN = os.path.join(
    REPO_ROOT, ".pixi", "envs", "default", "bin"
)

# Frozen v1.0 export baseline: every module and top-level name the
# 1.0 surface promised, with the exact normalized signatures. This
# literal must never be regenerated from the tree: while the SDK
# major version stays 1, the current surface must still contain
# all of it unchanged. Update it only together with a major bump
# and a review of every removed, renamed, or re-signed entry.
V1_BASELINE_MAJOR = 1
V1_BASELINE_EXPORTS = {
    "checksum": (
        "cksum_add",
        "cksum_finalize",
        "cksum_fold",
    ),
    "helpers": (
        "BPF_FUNC_map_delete_elem",
        "BPF_FUNC_map_lookup_elem",
        "BPF_FUNC_map_update_elem",
        "LookupResult",
        "bpf_map_delete",
        "bpf_map_lookup",
        "bpf_map_update",
    ),
    "maps": (
        "BPF_ANY",
        "BPF_EXIST",
        "BPF_NOEXIST",
        "MAP_KEY_SIZE",
        "MAP_MAX_ENTRIES",
        "MAP_MAX_ENTRIES_COMBINED",
        "MAP_MAX_ENTRIES_N3",
        "MAP_MAX_ENTRIES_N4",
        "MAP_TYPE_ARRAY",
        "MAP_TYPE_PERCPU_ARRAY",
        "MAP_VALUE_SIZE",
        "MapHandle",
        "PercpuHandle",
        "key_slot",
        "key_slot1",
        "key_slot2",
        "key_slot3",
        "value_slot",
    ),
    "packet": (
        "Cursor",
        "GUARD_ACTION",
        "XDP_DROP",
        "XDP_PASS",
        "XdpCtx",
        "addr_short",
        "load_u16_le",
        "load_u32_le",
        "load_u8",
        "packet_addr",
        "packet_base",
        "packet_len",
        "packet_short",
    ),
    "parse": (
        "inner_ethertype",
        "is_vlan_tag",
        "load_u16_be",
        "outer_ethertype",
        "vlan_id",
        "vlan_tci",
    ),
}
V1_BASELINE_SIGNATURES = {
    "checksum": {
        "cksum_add": (
            "@inline(.always) "
            "def cksum_add(sum: UInt32, word: UInt16) -> UInt32:"
        ),
        "cksum_finalize": (
            "@inline(.always) "
            "def cksum_finalize(sum: UInt32) -> UInt16:"
        ),
        "cksum_fold": (
            "@inline(.always) "
            "def cksum_fold(sum: UInt32) -> UInt16:"
        ),
    },
    "helpers": {
        "BPF_FUNC_map_delete_elem": "BPF_FUNC_map_delete_elem = 3",
        "BPF_FUNC_map_lookup_elem": "BPF_FUNC_map_lookup_elem = 1",
        "BPF_FUNC_map_update_elem": "BPF_FUNC_map_update_elem = 2",
        "LookupResult": (
            "@fieldwise_init struct LookupResult(ImplicitlyCopyable):"
        ),
        "LookupResult.is_null": (
            "@inline(.always) def is_null(self) -> Bool:"
        ),
        "LookupResult.unsafe_value_ptr": (
            "@inline(.always) "
            "def unsafe_value_ptr(self) "
            "-> MutPointer[UInt64, MutAnyOrigin]:"
        ),
        "bpf_map_delete": (
            "@inline(.always) "
            "def bpf_map_delete( "
            "map_addr: Int64, "
            "key: MutPointer[UInt32, MutAnyOrigin] ) -> Int64:"
        ),
        "bpf_map_lookup": (
            "@inline(.always) "
            "def bpf_map_lookup( "
            "map_addr: Int64, "
            "key: MutPointer[UInt32, MutAnyOrigin] ) -> LookupResult:"
        ),
        "bpf_map_update": (
            "@inline(.always) "
            "def bpf_map_update( "
            "map_addr: Int64, "
            "key: MutPointer[UInt32, MutAnyOrigin], "
            "value: MutPointer[UInt64, MutAnyOrigin], "
            "flags: Int64, ) -> Int64:"
        ),
    },
    "maps": {
        "BPF_ANY": "BPF_ANY = 0",
        "BPF_EXIST": "BPF_EXIST = 2",
        "BPF_NOEXIST": "BPF_NOEXIST = 1",
        "MAP_KEY_SIZE": "MAP_KEY_SIZE = 4",
        "MAP_MAX_ENTRIES": "MAP_MAX_ENTRIES = 1",
        "MAP_MAX_ENTRIES_COMBINED": "MAP_MAX_ENTRIES_COMBINED = 2",
        "MAP_MAX_ENTRIES_N3": "MAP_MAX_ENTRIES_N3 = 3",
        "MAP_MAX_ENTRIES_N4": "MAP_MAX_ENTRIES_N4 = 4",
        "MAP_TYPE_ARRAY": "MAP_TYPE_ARRAY = 2",
        "MAP_TYPE_PERCPU_ARRAY": "MAP_TYPE_PERCPU_ARRAY = 6",
        "MAP_VALUE_SIZE": "MAP_VALUE_SIZE = 8",
        "MapHandle": (
            "@fieldwise_init struct MapHandle(ImplicitlyCopyable):"
        ),
        "MapHandle.load": (
            "@staticmethod @inline(.always) def load() -> Self:"
        ),
        "PercpuHandle": (
            "@fieldwise_init struct PercpuHandle(ImplicitlyCopyable):"
        ),
        "PercpuHandle.load": (
            "@staticmethod @inline(.always) def load() -> Self:"
        ),
        "key_slot": (
            "@inline(.always) "
            "def key_slot() -> MutPointer[UInt32, MutAnyOrigin]:"
        ),
        "key_slot1": (
            "@inline(.always) "
            "def key_slot1() -> MutPointer[UInt32, MutAnyOrigin]:"
        ),
        "key_slot2": (
            "@inline(.always) "
            "def key_slot2() -> MutPointer[UInt32, MutAnyOrigin]:"
        ),
        "key_slot3": (
            "@inline(.always) "
            "def key_slot3() -> MutPointer[UInt32, MutAnyOrigin]:"
        ),
        "value_slot": (
            "@inline(.always) "
            "def value_slot() -> MutPointer[UInt64, MutAnyOrigin]:"
        ),
    },
    "packet": {
        "GUARD_ACTION": "GUARD_ACTION = XDP_DROP",
        "XDP_DROP": "XDP_DROP = 1",
        "XDP_PASS": "XDP_PASS = 2",
        "Cursor": (
            "@fieldwise_init "
            "struct Cursor[O: MutOrigin, //](ImplicitlyCopyable):"
        ),
        "Cursor.advance": (
            "@inline(.always) def advance(self, step: Int) -> Self:"
        ),
        "Cursor.u8": "@inline(.always) def u8(self) -> UInt8:",
        "Cursor.u8_at": (
            "@inline(.always) def u8_at(self, k: Int) -> UInt8:"
        ),
        "XdpCtx": (
            "@fieldwise_init struct XdpCtx(ImplicitlyCopyable):"
        ),
        "XdpCtx.from_ctx": (
            "@staticmethod @inline(.always) "
            "def from_ctx(ctx: MutPointer[UInt8, MutAnyOrigin]) "
            "-> Self:"
        ),
        "addr_short": (
            "@inline(.always) "
            "def addr_short(addr: UInt64, ctx: XdpCtx, size: UInt64) "
            "-> Bool:"
        ),
        "load_u16_le": (
            "@inline(.always) "
            "def load_u16_le(base: MutPointer[UInt8, MutAnyOrigin], "
            "off: Int) -> UInt16:"
        ),
        "load_u32_le": (
            "@inline(.always) "
            "def load_u32_le(base: MutPointer[UInt8, MutAnyOrigin], "
            "off: Int) -> UInt32:"
        ),
        "load_u8": (
            "@inline(.always) "
            "def load_u8(base: MutPointer[UInt8, MutAnyOrigin], "
            "off: Int) -> UInt8:"
        ),
        "packet_addr": (
            "@inline(.always) "
            "def packet_addr(ctx: XdpCtx, off: UInt64) -> UInt64:"
        ),
        "packet_base": (
            "@inline(.always) "
            "def packet_base(addr: UInt64) "
            "-> MutPointer[UInt8, MutAnyOrigin]:"
        ),
        "packet_len": (
            "@inline(.always) "
            "def packet_len(ctx: XdpCtx) -> UInt64:"
        ),
        "packet_short": (
            "@inline(.always) "
            "def packet_short(ctx: XdpCtx, need: UInt64) -> Bool:"
        ),
    },
    "parse": {
        "inner_ethertype": (
            "@inline(.always) "
            "def inner_ethertype(base: MutPointer[UInt8, MutAnyOrigin]) "
            "-> UInt16:"
        ),
        "is_vlan_tag": (
            "@inline(.always) "
            "def is_vlan_tag(field12: UInt16) -> Bool:"
        ),
        "load_u16_be": (
            "@inline(.always) "
            "def load_u16_be(base: MutPointer[UInt8, MutAnyOrigin], "
            "off: Int) -> UInt16:"
        ),
        "outer_ethertype": (
            "@inline(.always) "
            "def outer_ethertype(base: MutPointer[UInt8, MutAnyOrigin]) "
            "-> UInt16:"
        ),
        "vlan_id": (
            "@inline(.always) def vlan_id(tci: UInt16) -> UInt16:"
        ),
        "vlan_tci": (
            "@inline(.always) "
            "def vlan_tci(base: MutPointer[UInt8, MutAnyOrigin]) "
            "-> UInt16:"
        ),
    },
}

# (example source, artifact name, map entries or None).
EXAMPLE_BUILDS = (
    ("examples/xdp_pass/xdp_pass.mojo", "xdp_pass_obj", None),
    (
        "examples/packet_classifier/classifier.mojo",
        "classifier_obj",
        None,
    ),
    ("examples/xdp_counter/counter.mojo", "counter_obj", 1),
    ("examples/packet_counter/packet_counter.mojo", "ppc_obj", 2),
)

# (committed manifest, artifact name, qualified object sha256).
# The driver path must produce byte-identical objects to the
# direct pipeline; these pins must match the structure suite
# (tests/elf/test_event_struct.py) and the kernel suite
# (tests/kernel/test_tracepoint_events.py).
EVENT_MANIFEST_BUILDS = (
    (
        "examples/tracepoint_events/mojobpf.toml",
        "tracepoint_events",
        "61ff0825a6e284e7bb88d35e1cef80adb5be580bf8bc15a8db6fb65ce94c7cbf",
    ),
    (
        "examples/tracepoint_events/mojobpf-small.toml",
        "tracepoint_events_small",
        "8f61138c79080273908ee0edfcb1d259183b9b66fe1097cd7f70f20d935055d7",
    ),
)

# Genuine-frontend import probes: (stem, source, must_fail,
# expected stderr marker or None).
IMPORT_PROBES = (
    (
        "compat_import_ok",
        "from mojobpf.packet import XDP_PASS\n"
        "def entry() -> Int32:\n"
        "    return Int32(XDP_PASS)\n",
        False,
        None,
    ),
    (
        "compat_import_bad_name",
        "from mojobpf.packet import _nope\n"
        "def entry() -> Int32:\n"
        "    return Int32(0)\n",
        True,
        "does not contain",
    ),
    (
        "compat_import_bad_module",
        "from mojobpf._impl import x\n"
        "def entry() -> Int32:\n"
        "    return Int32(0)\n",
        True,
        "unable to locate module",
    ),
    (
        "compat_import_deep_path",
        "from mojobpf.packet.sub import x\n"
        "def entry() -> Int32:\n"
        "    return Int32(0)\n",
        True,
        "not a package",
    ),
    (
        "compat_import_wrong_module",
        "from mojobpf.packet import BPF_ANY\n"
        "def entry() -> Int32:\n"
        "    return Int32(0)\n",
        True,
        "does not contain",
    ),
    (
        "compat_import_alias",
        "from mojobpf.packet import load_u8 as lu8\n"
        "def entry() -> Int32:\n"
        "    return Int32(0)\n",
        False,
        None,
    ),
    (
        "compat_import_paren_list",
        "from mojobpf.packet import (\n XDP_PASS,\n load_u8,\n)\n"
        "def entry() -> Int32:\n"
        "    return Int32(XDP_PASS)\n",
        False,
        None,
    ),
)


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def _check_tools():
    if shutil.which("mojo") is None:
        raise EnvironmentFailure("mojo not found on PATH")
    if shutil.which("llc") is None:
        raise EnvironmentFailure("llc not found on PATH")


def test_additive_only_within_major():
    assert sdk_module.SDK_SCHEMA_VERSION >= V1_BASELINE_MAJOR
    if sdk_module.SDK_SCHEMA_VERSION != V1_BASELINE_MAJOR:
        raise AssertionError(
            "SDK major moved to %d: re-baseline the v1 export "
            "list in this file after review"
            % sdk_module.SDK_SCHEMA_VERSION
        )
    for module, names in V1_BASELINE_EXPORTS.items():
        assert module in sdk_module.SDK_EXPORTS, module
        for name in names:
            assert name in sdk_module.SDK_EXPORTS[module], (
                module, name,
            )
    for module, signatures in V1_BASELINE_SIGNATURES.items():
        for key, pinned in signatures.items():
            assert sdk_module.SDK_SIGNATURES[module][key] == (
                pinned
            ), (module, key)


def test_frontend_import_negatives():
    _check_tools()
    parent = tempfile.mkdtemp(prefix="mojobpf-compat-imports-")
    try:
        for stem, source, must_fail, marker in IMPORT_PROBES:
            probe = os.path.join(parent, stem + ".mojo")
            with open(probe, "w", encoding="utf-8") as handle:
                handle.write(source)
            proc = subprocess.run(
                [
                    "mojo",
                    "build",
                    "--emit",
                    "llvm",
                    "-I",
                    SDK_DIR,
                    "-o",
                    os.path.join(parent, stem + ".ll"),
                    probe,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300,
            )
            if not must_fail:
                assert proc.returncode == 0, (
                    stem,
                    proc.stdout,
                    proc.stderr,
                )
                continue
            assert proc.returncode != 0, (stem, proc.stdout)
            assert "error:" in proc.stderr.lower(), (
                stem,
                proc.stderr,
            )
            assert marker in proc.stderr, (stem, proc.stderr)
            static = sdk_module.check_mojo_imports(source)
            assert len(static) >= 1, stem
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def _manifest_text(artifact, source, entries):
    maps = ""
    if entries is not None:
        maps = (
            "[[maps]]\n"
            'name = "mojobpf_map0"\n'
            'map_type = "array"\n'
            'key_type = "u32"\n'
            'value_type = "u64"\n'
            "max_entries = %d\n" % entries
        )
    return (
        "schema_version = 1\n"
        "\n"
        "[project]\n"
        'name = "compat-proof"\n'
        "\n"
        "[target]\n"
        'profile = "linux-bpfel-v3"\n'
        "core = false\n"
        "\n"
        "[artifact]\n"
        'name = "%s"\n'
        'source_license = "Apache-2.0 WITH LLVM-exception"\n'
        'kernel_license = "Apache-2.0 WITH LLVM-exception"\n'
        "\n"
        "[[programs]]\n"
        'source = "%s"\n'
        'entry = "xdp_entry"\n'
        'program_type = "xdp"\n'
        'section = "xdp"\n'
        "%s" % (artifact, source, maps)
    )


def _sha256_file(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def test_old_examples_build_unchanged():
    _check_tools()
    for relative, artifact, entries in EXAMPLE_BUILDS:
        parent = tempfile.mkdtemp(prefix="mojobpf-compat-build-")
        try:
            project = os.path.join(parent, "proj")
            os.makedirs(project)
            tree_source = os.path.join(REPO_ROOT, relative)
            staged = os.path.join(
                project, os.path.basename(relative)
            )
            shutil.copyfile(tree_source, staged)
            assert _sha256_file(staged) == _sha256_file(
                tree_source
            ), relative
            manifest_path = os.path.join(project, "mojobpf.toml")
            with open(manifest_path, "w", encoding="utf-8") as handle:
                handle.write(
                    _manifest_text(
                        artifact, os.path.basename(relative), entries
                    )
                )
            out_dir = os.path.join(parent, "out")
            result = build_project(
                BuildRequest(
                    manifest_path=manifest_path,
                    out_dir=out_dir,
                    adapter_path=ADAPTER,
                    search_paths=(PIXI_BIN,),
                    timeout_s=600,
                    lockfile_path=LOCKFILE,
                )
            )
            assert result.success is True, (
                relative,
                result.diagnostics,
            )
            assert result.provenance.sdk_version == (
                sdk_module.SDK_VERSION
            ), relative
            objects = sorted(
                entry
                for entry in os.listdir(out_dir)
                if entry.endswith(".bpf.o")
            )
            assert objects == ["%s.bpf.o" % artifact], (
                relative,
                objects,
            )
            report = inspect_object(
                os.path.join(out_dir, objects[0]), "linux-bpfel-v3"
            )
            assert report.ok is True, (relative, report.to_dict())
            with open(
                os.path.join(
                    out_dir, "%s.evidence.json" % artifact
                ),
                encoding="utf-8",
            ) as handle:
                doc = json.load(handle)
            assert doc["sdk_version"] == sdk_module.SDK_VERSION
            assert doc["inputs"]["sdk_version"] == (
                sdk_module.SDK_VERSION
            )
        finally:
            shutil.rmtree(parent, ignore_errors=True)


def test_event_manifests_build_qualified_bytes():
    _check_tools()
    for relative, artifact, want_hash in EVENT_MANIFEST_BUILDS:
        parent = tempfile.mkdtemp(prefix="mojobpf-compat-events-")
        try:
            out_dir = os.path.join(parent, "out")
            result = build_project(
                BuildRequest(
                    manifest_path=os.path.join(REPO_ROOT, relative),
                    out_dir=out_dir,
                    adapter_path=ADAPTER,
                    search_paths=(PIXI_BIN,),
                    timeout_s=600,
                    lockfile_path=LOCKFILE,
                )
            )
            assert result.success is True, (
                relative,
                result.diagnostics,
            )
            assert result.provenance.sdk_version == (
                sdk_module.SDK_VERSION
            ), relative
            objects = sorted(
                entry
                for entry in os.listdir(out_dir)
                if entry.endswith(".bpf.o")
            )
            assert objects == ["%s.bpf.o" % artifact], (
                relative,
                objects,
            )
            object_path = os.path.join(out_dir, objects[0])
            observed = _sha256_file(object_path)
            assert observed == want_hash, (relative, observed)
            report = inspect_object(object_path, "linux-bpfel-v3")
            assert report.ok is True, (relative, report.to_dict())
            with open(
                os.path.join(
                    out_dir, "%s.evidence.json" % artifact
                ),
                encoding="utf-8",
            ) as handle:
                doc = json.load(handle)
            assert doc["sdk_version"] == sdk_module.SDK_VERSION
            assert doc["inputs"]["sdk_version"] == (
                sdk_module.SDK_VERSION
            )
        finally:
            shutil.rmtree(parent, ignore_errors=True)


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
    print("sdk compat: additive surface and old builds passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
