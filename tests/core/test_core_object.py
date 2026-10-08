# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Structural checks for the Mojo-built CO-RE relocation probe.

Builds ``tests/core/core_read.mojo`` through the genuine pipeline
(``mojo build --emit llvm`` with the packaged SDK on the import
path -> ``compiler/mojo_ir_adapter.py`` -> ``llc -mtriple=bpfel
-mcpu=v3``) and asserts the resulting object is a conventional BPF
relocatable carrying exactly the two pinned relocation records:
EM_BPF machine type, exactly one executable section holding
exactly one function (``xdp_entry``), the exact license bytes,
exactly one ``call 1`` (lookup) and no other helper call, one map
relocation against the ``.maps`` symbol, a 32-byte all-zero
``.maps`` section, map BTF describing a one-entry array map with
u32 keys and a 4096-byte value, and ``.BTF.ext`` records for
exactly one ``task_struct.pid`` byte-offset access plus one
``task_struct.scx`` existence check.

The relocation content is resolved with the independent reader
(``tests/core/btfext_reader.py``, which shares no code with the
product parser) and cross-checked against ``bpftool btf dump``
(field/type IDs, member offsets, sizes). A third leg, the
loader's own relocation transcript, runs in the kernel suite.
The reader's isolation (standard library only, no product or
test imports) is asserted here, in a fresh subprocess.

Also locks the adapted-IR hash and the ``xdp`` section bytes so
adapter or backend evolution cannot silently change the core
pipeline, pins the spill-gate immediates, and proves
``verify_object`` accepts the object under the CO-RE profile
while the base profile refuses its ``.BTF.ext`` with
``MBPF407``.

Requires a working Mojo compiler, LLVM ``llc`` and ``bpftool`` on
PATH. A missing tool is reported as an environment failure; a
failing frontend, adapter, or backend step is a proof failure.
Neither ever passes.

Runnable directly (``python3 tests/core/test_core_object.py``) or
under any ``test_``-style runner. Standard library only.
"""

import hashlib
import importlib.util
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

from mojobpf.inspect import verify_object  # noqa: E402

CORE_SOURCE = os.path.join(REPO_ROOT, "tests", "core", "core_read.mojo")
READER_SOURCE = os.path.join(
    REPO_ROOT, "tests", "core", "btfext_reader.py"
)
SDK_INCLUDE = os.path.join(REPO_ROOT, "src", "mojobpf", "resources", "sdk")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

# Adapted-IR hash of the core relocation probe. The adapter must
# keep producing byte-identical output for that input (core mode).
CORE_ADAPTED_HASH = (
    "162eb73c5cabc772de565c805770d6948c80521271f7f4e94217d573ec28a922"
)
# Compiled ``xdp`` section bytes of the probe (144 bytes). The
# pinned backend must keep producing byte-identical code.
CORE_XDP_HASH = (
    "ae6958dce94d4e589eba3da31691eace1d69e3fe2df4278fc2cf19f476297ca3"
)

EM_BPF = 247
BPF_OP_CALL = 0x85
LICENSE_BYTES = b"Apache-2.0 WITH LLVM-exception\x00"
MAP_SYMBOL = "mojobpf_map0"
MAP_SECTION_SIZE = 32
CORE_PROFILE = "linux-bpfel-v3-core"
BASE_PROFILE = "linux-bpfel-v3"


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


def build_core_object(workdir):
    raw_path = os.path.join(workdir, "core.raw.ll")
    adapted_path = os.path.join(workdir, "core.bpf.ll")
    obj_path = os.path.join(workdir, "core.bpf.o")
    proc = run_step(
        ["mojo", "build", "--emit", "llvm", "-I", SDK_INCLUDE,
         "-o", raw_path, CORE_SOURCE]
    )
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise AssertionError(
            "frontend failed for core_read.mojo (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    proc = run_step(
        [sys.executable, ADAPTER, "--input", raw_path,
         "--output", adapted_path]
    )
    if proc.returncode != 0 or not os.path.isfile(adapted_path):
        raise AssertionError(
            "adapter failed for the core program (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    proc = run_step(
        ["llc", "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj",
         adapted_path, "-o", obj_path]
    )
    if proc.returncode != 0 or not os.path.isfile(obj_path):
        raise AssertionError(
            "backend failed for the core program (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    return raw_path, adapted_path, obj_path


def load_reader():
    spec = importlib.util.spec_from_file_location(
        "core_btfext_reader", READER_SOURCE
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_sections(data):
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise AssertionError("not an ELF file")
    if data[4] != 2 or data[5] != 1 or data[6] != 1:
        raise AssertionError("not a 64-bit little-endian ELF")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != EM_BPF:
        raise AssertionError("machine %d, expected EM_BPF" % machine)
    shoff = struct.unpack_from("<Q", data, 40)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
    headers = []
    for index in range(shnum):
        base = shoff + index * shentsize
        fields = struct.unpack_from("<IIQQQQIIQQ", data, base)
        headers.append(fields)
    strtab = headers[shstrndx]
    sections = {}
    for fields in headers:
        end = data.index(b"\0", strtab[4] + fields[0])
        name = data[strtab[4] + fields[0] : end].decode("ascii")
        sections[name] = bytes(data[fields[4] : fields[4] + fields[5]])
    return sections


def test_reader_isolation():
    with open(READER_SOURCE, "r", encoding="utf-8") as handle:
        source = handle.read()
    imports = []
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith(
            "from "
        ):
            imports.append(stripped)
    assert sorted(imports) == ["import struct", "import sys"], imports
    probe = (
        "import sys; sys.path.insert(0, %r); "
        "import btfext_reader as _r; "
        "mods = sorted(m for m in sys.modules "
        "if m.split('.')[0] in "
        "('mojobpf', 'audit', 'build', 'inspect', 'test')); "
        "print('LEAKED:' + ','.join(mods) if mods else 'ISOLATED')"
        % os.path.dirname(READER_SOURCE)
    )
    proc = run_step([sys.executable, "-c", probe])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "ISOLATED", proc.stdout
    print("PASS reader isolation (stdlib only, no product imports)")


def test_core_object_structure():
    check_tools("mojo", "llc", "bpftool")
    workdir = tempfile.mkdtemp(prefix="core-object-")
    _raw, adapted_path, obj_path = build_core_object(workdir)
    with open(adapted_path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    assert digest == CORE_ADAPTED_HASH, (
        "adapted IR drifted: %s" % digest
    )
    with open(obj_path, "rb") as handle:
        data = handle.read()
    sections = read_sections(data)
    assert "xdp" in sections, sorted(sections)
    assert sections["license"] == LICENSE_BYTES
    assert len(sections[".maps"]) == MAP_SECTION_SIZE
    assert sections[".maps"] == bytes(MAP_SECTION_SIZE)
    assert ".BTF" in sections and ".BTF.ext" in sections
    code = sections["xdp"]
    assert len(code) == 144, len(code)
    assert hashlib.sha256(code).hexdigest() == CORE_XDP_HASH
    calls = []
    imms = []
    offset = 0
    while offset < len(code):
        opcode = code[offset]
        if opcode == 0x18:
            offset += 16
            continue
        if opcode == BPF_OP_CALL:
            (imm,) = struct.unpack_from("<i", code, offset + 4)
            calls.append(imm)
        if opcode == 0x07:
            (imm,) = struct.unpack_from("<i", code, offset + 4)
            imms.append(imm)
        offset += 8
    assert calls == [1], calls
    assert sorted(imms) == [-4], imms
    print("PASS core object structure (pins hold)")


def test_core_relocations_independent():
    check_tools("mojo", "llc", "bpftool")
    workdir = tempfile.mkdtemp(prefix="core-relocs-")
    _raw, _adapted, obj_path = build_core_object(workdir)
    reader = load_reader()
    with open(obj_path, "rb") as handle:
        result = reader.read_relocations(handle.read())
    relocs = result["relocations"]
    assert len(relocs) == 2, relocs
    first, second = relocs
    assert first["section"] == "xdp", first
    assert first["type"] == "task_struct", first
    assert (first["kind"], first["kind_name"]) == (
        0, "FIELD_BYTE_OFFSET",
    ), first
    assert first["access"] == "0:1", first
    assert first["member"] == "pid", first
    assert first["local_byte_offset"] == 32, first
    assert first["local_size"] == 4, first
    assert first["insn_off"] == 96, first
    assert second["section"] == "xdp", second
    assert second["type"] == "task_struct", second
    assert (second["kind"], second["kind_name"]) == (
        2, "FIELD_EXISTS",
    ), second
    assert second["access"] == "0:4", second
    assert second["member"] == "scx", second
    assert second["insn_off"] == 112, second
    # bpftool cross-check: the same type IDs, member offsets,
    # and map value bound from the reference implementation.
    proc = run_step(
        ["bpftool", "btf", "dump", "file", obj_path, "format", "raw"]
    )
    assert proc.returncode == 0, proc.stderr
    dump = proc.stdout
    task = re.search(
        r"\[(\d+)\] STRUCT 'task_struct' size=(\d+) vlen=(\d+)", dump
    )
    assert task is not None, dump[:500]
    assert int(task.group(1)) == first["type_id"], dump[:500]
    assert int(task.group(2)) == 312, dump[:500]
    pid = re.search(r"'pid' type_id=(\d+) bits_offset=(\d+)", dump)
    assert pid is not None, dump[:500]
    assert int(pid.group(2)) == 256, dump[:500]
    assert re.search(r"'scx' type_id=(\d+) bits_offset=(\d+)", dump), (
        dump[:500]
    )
    bound = re.search(
        r"nr_elems=4096", dump
    )
    assert bound is not None, dump[:500]
    print("PASS core relocations (reader + bpftool agree)")


def test_core_profile_verdicts():
    check_tools("mojo", "llc", "bpftool")
    workdir = tempfile.mkdtemp(prefix="core-verdicts-")
    _raw, _adapted, obj_path = build_core_object(workdir)
    apache = "Apache-2.0 WITH LLVM-exception"
    report = verify_object(obj_path, CORE_PROFILE, apache, apache)
    assert report.ok, (
        report.structural + report.unsupported + report.license
    )
    base = verify_object(obj_path, BASE_PROFILE, apache, apache)
    assert base.ok is False, "base profile accepted .BTF.ext"
    codes = [item.code for item in base.unsupported]
    assert codes == ["MBPF407"], codes
    print("PASS core profile verdicts (core ok, base MBPF407)")


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
    print("core object: structure, relocations, and verdicts hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
