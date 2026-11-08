# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""BTF FUNC/FUNC_PROTO: reader-positive plus emission split.

The CO-RE route emits exactly one FUNC_PROTO + one FUNC
'xdp_entry' pair; the map route emits no kind 12/13. The
inspector decodes both kinds per UAPI. This suite pins the
UAPI kind numbers, the decode rules on a synthetic blob
(FUNC payload is the proto type id; FUNC_PROTO skips vlen
params and its payload is the return type id; truncation
raises MBPF402), the core-route emission pair and the
map-route absence over the genuine pipeline
(mojo -> adapter -> llc), cross-checked with bpftool.

Requires a working Mojo compiler, LLVM ``llc`` and ``bpftool``
on PATH for the pipeline test. A missing tool is reported
as an environment failure; a failing build step is a proof
failure. Neither ever passes.

Runnable directly (``python3 tests/elf/test_func_btf.py``) or
under any ``test_``-style runner. Standard library only.
"""
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
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf.build import FRONTEND_TARGET_FLAGS  # noqa: E402
from mojobpf.elf_reader import (  # noqa: E402
    ElfError,
    parse_elf,
    section_bytes,
)
from mojobpf.inspect import _parse_btf_types  # noqa: E402

ROUNDTRIP_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "map_roundtrip.mojo"
)
CORE_SOURCE = os.path.join(
    REPO_ROOT, "tests", "core", "core_read.mojo"
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
PACKAGED_ADAPTER = os.path.join(
    REPO_ROOT, "src", "mojobpf", "resources", "adapter",
    "mojo_ir_adapter.py",
)
UAPI_HEADER = "/usr/include/linux/btf.h"

BTF_KIND_FUNC = 12
BTF_KIND_FUNC_PROTO = 13


class EnvironmentFailure(Exception):
    """The toolchain needed by this test is missing or broken."""


def run_step(argv, timeout=600):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def check_tools(*tools):
    for tool in tools:
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)


def build_object(source):
    """Run the genuine three-step build; return the image bytes."""
    check_tools("mojo", "llc")
    for path in (source, ADAPTER):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK directory: %s" % SDK_INCLUDE)
    workdir = tempfile.mkdtemp(prefix="mojo-func-elf-")
    stem = os.path.splitext(os.path.basename(source))[0]
    raw_path = os.path.join(workdir, stem + ".ll")
    adapted_path = os.path.join(workdir, stem + ".bpf.ll")
    object_path = os.path.join(workdir, stem + ".bpf.o")
    proc = run_step(
        [
            "mojo",
            "build",
            "--emit",
            "llvm",
            *FRONTEND_TARGET_FLAGS,
            "-I",
            SDK_INCLUDE,
            "-o",
            raw_path,
            source,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise AssertionError(
            "frontend failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    proc = run_step(
        [
            sys.executable,
            ADAPTER,
            "--input",
            raw_path,
            "--output",
            adapted_path,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(adapted_path):
        raise AssertionError(
            "adapter failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    proc = run_step(
        [
            "llc",
            "-mtriple=bpfel",
            "-mcpu=v3",
            "-filetype=obj",
            adapted_path,
            "-o",
            object_path,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "backend failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    with open(object_path, "rb") as handle:
        return handle.read()


def func_blob():
    """Synthetic .BTF: INT + FUNC_PROTO(1 param) + FUNC."""
    strings = b"\x00int\x00myfunc\x00"
    types = b"".join([
        struct.pack("<III", 1, (1 << 24) | 0, 4),
        struct.pack("<I", 0x20),
        struct.pack("<III", 0, (13 << 24) | 1, 1),
        struct.pack("<II", 1, 0),
        struct.pack("<III", 5, (12 << 24) | 0, 2),
    ])
    header = struct.pack(
        "<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(types),
        len(types), len(strings),
    )
    return header + types + strings


def test_func_uapi_kinds():
    with open(UAPI_HEADER, encoding="utf-8") as handle:
        text = handle.read()
    for name, want in (("BTF_KIND_FUNC", BTF_KIND_FUNC),
                       ("BTF_KIND_FUNC_PROTO", BTF_KIND_FUNC_PROTO)):
        match = re.search(
            r"%s\s*=\s*(\d+)" % name, text)
        assert match, "UAPI kind missing: %s" % name
        assert int(match.group(1)) == want, (name, match.group(1))


def test_func_decode():
    records, _strings = _parse_btf_types(func_blob(), "synthetic")
    assert records == [
        ("int", 1, 4),
        ("", 13, 1),
        ("myfunc", 12, 2),
    ], records


def test_func_proto_truncation_rejected():
    # Consistent header lengths with the FUNC_PROTO param cut
    # short, so the failure lands at the param guard (not the
    # generic size check): type section shrinks by 4 bytes.
    blob = bytearray(func_blob())
    header_len = 24
    type_len = struct.unpack_from("<I", blob, 12)[0]
    str_len = struct.unpack_from("<I", blob, 20)[0]
    param_end = header_len + 12 + 4 + 12 + 8
    del blob[param_end - 4:param_end]
    struct.pack_into("<I", blob, 12, type_len - 4)
    struct.pack_into("<I", blob, 16, type_len - 4)
    assert len(blob) == header_len + (type_len - 4) + str_len
    try:
        _parse_btf_types(bytes(blob), "synthetic")
    except ElfError as exc:
        assert exc.code == "MBPF402", exc.code
    else:
        raise AssertionError("truncated FUNC blob must raise MBPF402")


def test_map_route_emits_no_func_btf():
    check_tools("bpftool")
    records = _btf_kinds(build_object(ROUNDTRIP_SOURCE))
    kinds = sorted(kind for _name, kind, _payload in records)
    assert kinds, "built object must carry map BTF"
    assert BTF_KIND_FUNC not in kinds, kinds
    assert BTF_KIND_FUNC_PROTO not in kinds, kinds


def test_bpftool_cross_check_has_no_func():
    check_tools("bpftool")
    image = build_object(ROUNDTRIP_SOURCE)
    workdir = tempfile.mkdtemp(prefix="mojo-func-xcheck-")
    path = os.path.join(workdir, "probe.bpf.o")
    with open(path, "wb") as handle:
        handle.write(image)
    proc = run_step(["bpftool", "btf", "dump", "file", path])
    assert proc.returncode == 0, proc.stderr
    assert "FUNC" not in proc.stdout, proc.stdout


def _btf_kinds(image):
    elf = parse_elf(image, "built")
    sections = [s for s in elf.sections if s.name == ".BTF"]
    assert len(sections) == 1, [s.name for s in elf.sections]
    records, _strings = _parse_btf_types(
        section_bytes(elf, sections[0]), "built")
    return records


def test_core_route_emits_exact_func_pair():
    # The CO-RE route emits exactly one FUNC_PROTO + one
    # FUNC 'xdp_entry', linked: FUNC points at the PROTO,
    # PROTO returns INT.
    records = _btf_kinds(build_object(CORE_SOURCE))
    protos = [(index, name, payload)
              for index, (name, kind, payload) in enumerate(records, 1)
              if kind == BTF_KIND_FUNC_PROTO]
    funcs = [(index, name, payload)
             for index, (name, kind, payload) in enumerate(records, 1)
             if kind == BTF_KIND_FUNC]
    assert len(protos) == 1, protos
    assert len(funcs) == 1, funcs
    (proto_id, proto_name, proto_ret), = protos
    (func_id, func_name, func_proto), = funcs
    assert proto_name == "", protos
    assert func_name == "xdp_entry", funcs
    assert func_proto == proto_id, funcs
    by_id = {index: (name, kind, payload)
             for index, (name, kind, payload) in enumerate(records, 1)}
    assert by_id[proto_ret][1] == 1, by_id[proto_ret]


def test_adapter_debuginfo_lists_no_subprograms():
    # The adapter synthesizes exactly one DISubprogram (xdp_entry,
    # attached to the function definition) and the compile unit
    # lists no `subprograms:` field. That shape does NOT prevent
    # emission by itself (the core route emits the FUNC pair
    # despite it); pin it so drift fails loudly and forces
    # re-examination of the emission proofs above.
    for path in (ADAPTER, PACKAGED_ADAPTER):
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        assert text.count("DISubprogram(") == 1, path
        for line in text.splitlines():
            if "!DICompileUnit(" in line:
                assert "subprograms" not in line, line


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
    print("func BTF: reader, emission and debuginfo checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
