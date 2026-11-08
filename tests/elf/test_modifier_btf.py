# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""BTF modifiers/qualifiers: refusal on both sides.

Our toolchain neither emits BTF kinds 8/9/10/11
(TYPEDEF/VOLATILE/CONST/RESTRICT) nor decodes them:
the inspector rejects them with MBPF402
("unexpected BTF kind N"), which is correct
fail-closed behavior for a reader whose contract is
our own objects. This suite pins the UAPI kind
numbers, the per-kind rejection with exact messages,
and the emitter absence on the map + core routes over
the genuine pipeline (mojo -> adapter -> llc),
cross-checked with bpftool.

Requires a working Mojo compiler, LLVM ``llc`` and ``bpftool``
on PATH for the pipeline tests. A missing tool is reported
as an environment failure; a failing build step is a proof
failure. Neither ever passes.

Runnable directly (``python3 tests/elf/test_modifier_btf.py``) or
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
UAPI_HEADER = "/usr/include/linux/btf.h"

MODIFIER_KINDS = {
    "BTF_KIND_TYPEDEF": 8,
    "BTF_KIND_VOLATILE": 9,
    "BTF_KIND_CONST": 10,
    "BTF_KIND_RESTRICT": 11,
}


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
    workdir = tempfile.mkdtemp(prefix="mojo-mod-elf-")
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


def modifier_blob(kind):
    """Synthetic .BTF: INT + one KIND record pointing at it."""
    strings = b"\x00int\x00mod\x00"
    types = b"".join([
        struct.pack("<III", 1, (1 << 24) | 0, 4),
        struct.pack("<I", 0x20),
        struct.pack("<III", 5, (kind << 24) | 0, 1),
    ])
    header = struct.pack(
        "<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(types),
        len(types), len(strings),
    )
    return header + types + strings


def test_modifier_uapi_kinds():
    with open(UAPI_HEADER, encoding="utf-8") as handle:
        text = handle.read()
    for name, want in sorted(MODIFIER_KINDS.items()):
        match = re.search(r"%s\s*=\s*(\d+)" % name, text)
        assert match, "UAPI kind missing: %s" % name
        assert int(match.group(1)) == want, (name, match.group(1))


def _assert_rejected(kind):
    try:
        _parse_btf_types(modifier_blob(kind), "synthetic")
    except ElfError as exc:
        assert exc.code == "MBPF402", exc.code
        assert str(exc) == "unexpected BTF kind %d" % kind, str(exc)
    else:
        raise AssertionError(
            "kind-%d blob must raise MBPF402" % kind)


def test_typedef_rejected():
    _assert_rejected(8)


def test_volatile_rejected():
    _assert_rejected(9)


def test_const_rejected():
    _assert_rejected(10)


def test_restrict_rejected():
    _assert_rejected(11)


def _btf_kinds(image):
    elf = parse_elf(image, "built")
    sections = [s for s in elf.sections if s.name == ".BTF"]
    assert len(sections) == 1, [s.name for s in elf.sections]
    records, _strings = _parse_btf_types(
        section_bytes(elf, sections[0]), "built")
    return sorted(kind for _name, kind, _payload in records)


def test_routes_emit_no_modifiers():
    for source in (ROUNDTRIP_SOURCE, CORE_SOURCE):
        kinds = _btf_kinds(build_object(source))
        assert kinds, source
        for kind in sorted(MODIFIER_KINDS.values()):
            assert kind not in kinds, (source, kinds)


def test_bpftool_cross_check_has_no_modifiers():
    check_tools("bpftool")
    for source in (ROUNDTRIP_SOURCE, CORE_SOURCE):
        image = build_object(source)
        workdir = tempfile.mkdtemp(prefix="mojo-mod-xcheck-")
        path = os.path.join(workdir, "probe.bpf.o")
        with open(path, "wb") as handle:
            handle.write(image)
        proc = run_step(["bpftool", "btf", "dump", "file", path])
        assert proc.returncode == 0, proc.stderr
        for word in ("TYPEDEF", "VOLATILE", "CONST", "RESTRICT"):
            assert word not in proc.stdout, (source, proc.stdout)


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
    print("modifier BTF: rejection and absence checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
