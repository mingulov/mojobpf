# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for build orchestration, the CLI and the adapter boundary.

Covers ``build_project`` (success, failure classification, bounded
logs, timeouts, failure safety), the versioned JSON adapter service
(request validation, rejection propagation, transform fidelity), and
the CLI (build/check/doctor/inspect exits, platform gate, packaged
adapter default). Deterministic on any host:
tool behavior comes from fixture scripts resolved through
``search_paths`` or an isolated ``PATH``; only the adapter service and
its sibling transform run for real (both need just Python).

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3
tests/unit/test_build_commands.py``).
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

import mojobpf  # noqa: E402
from mojobpf import build as build_module  # noqa: E402
from mojobpf import cli as cli_module  # noqa: E402
from mojobpf import evidence as evidence_module  # noqa: E402
from mojobpf import inputs as inputs_module  # noqa: E402
from mojobpf.sdk import SDK_VERSION  # noqa: E402
from mojobpf.build import (  # noqa: E402
    ADAPTER_REQUEST_VERSION,
    BuildRequest,
    BuildResult,
    build_project,
)
from mojobpf.diagnostics import (  # noqa: E402
    Diagnostic,
    SEVERITY_ERROR,
)
from mojobpf.manifest import SUPPORTED_PROFILE_IDS  # noqa: E402
from mojobpf import toolchain as toolchain_module  # noqa: E402
from test_native_adapter import real_bundle  # noqa: E402,F401
import pytest

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
SERVICE = os.path.join(REPO_ROOT, "compiler", "adapter_service.py")
SIBLING = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")


def _assemble_btf(directives):
    """Assemble fixed-block directives to section bytes (test only)."""
    blob = bytearray()
    for directive in directives:
        parts = directive.split(None, 1)
        op = parts[0]
        if op == ".section":
            continue
        arg = parts[1]
        if op == ".short":
            blob += struct.pack("<H", int(arg))
        elif op == ".byte":
            blob += struct.pack("<B", int(arg))
        elif op == ".long":
            if arg.lstrip("-").isdigit():
                blob += struct.pack("<i", int(arg))
            else:
                blob += b"\x00\x00\x00\x00"
        elif op == ".ascii":
            assert arg.startswith('"') and arg.endswith('"')
            blob += arg[1:-1].encode("ascii")
        else:
            raise AssertionError("unknown directive %r" % (directive,))
    return bytes(blob)


def _adapter_btf_hex():
    """Hex of the adapter's fixed one-entry array map-BTF block."""
    spec = importlib.util.spec_from_file_location(
        "fixture_adapter", SIBLING
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return _assemble_btf(module.BTF_ASM_LINES).hex()


# Map-mode fixture builds carry the adapter's real fixed map-BTF
# block (array, one entry) so the build's kind/count
# reconciliation reads honest attributes.
FIXTURE_MAP_BTF_HEX = _adapter_btf_hex()

MOJO_FIXTURE = """\
#!{python}
import os
import sys
import time


def main(argv):
    if argv[1:] == ["--version"]:
        print("Mojo 9.9.9 (fixture)")
        return 0
    mode = os.environ.get("MOJOBPF_FIXTURE_MOJO", "ok")
    if mode == "crash":
        sys.stderr.write("fixture frontend boom\\n")
        return 3
    if mode == "loud-crash":
        sys.stderr.write("E" * 100000 + "\\n")
        return 3
    if mode == "hang":
        time.sleep(30)
        return 0
    if mode == "flood":
        sys.stderr.write("F" * 3000000 + "\\n")
        sys.stderr.write("fixture frontend boom\\n")
        return 3
    out = argv[argv.index("-o") + 1]
    src = argv[-1]
    with open(out, "w", encoding="utf-8") as handle:
        handle.write("; fixture raw IR for %s\\n" % src)
        if mode == "mapmode":
            handle.write("; inttoptr (i64 1 to ptr)\\n")
            handle.write("; inttoptr (i64 2 to ptr)\\n")
    if mode == "stderr-error":
        sys.stderr.write("error: fixture latent error\\n")
    if mode == "buried-error":
        sys.stderr.write("error: buried marker\\n" + "x" * 100000 + "\\n")
    if mode == "late-error":
        sys.stderr.write("L" * 3000000 + "\\n")
        sys.stderr.write("error: fixture late error\\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
"""

LLC_FIXTURE = """\
#!{python}
import os
import struct
import sys
import time

LICENSE = b"Apache-2.0 WITH LLVM-exception\\x00"
WRONG_LICENSE = b"MIT\\x00"
XDP_CODE = (
    b"\\xb0\\x00\\x00\\x00\\x02\\x00\\x00\\x00"
    b"\\x95\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
)
MIR_EMPTY = (
    "---\\n"
    "name: xdp_entry\\n"
    "fixedStack:      []\\n"
    "stack:           []\\n"
    "body:            |\\n"
    "  $r0 = MOV_32_64 2\\n"
    "  RET implicit $r0\\n"
    "...\\n"
)
MIR_FRAMED = (
    "---\\n"
    "name: xdp_entry\\n"
    "fixedStack:      []\\n"
    "stack:\\n"
    "  - {{ id: 0, size: 8 }}\\n"
    "body:            |\\n"
    "  $r0 = MOV_32_64 2\\n"
    "  RET implicit $r0\\n"
    "...\\n"
)


def minimal_elf(code, license=LICENSE):
    shstr = b"\\x00xdp\\x00license\\x00.shstrtab\\x00"
    ehsize = 64
    shoff = ehsize
    shentsize, shnum, shstrndx = 64, 4, 3
    xdp_off = shoff + shentsize * shnum
    lic_off = xdp_off + len(code)
    str_off = lic_off + len(license)
    eh = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\\x7fELF\\x02\\x01\\x01" + b"\\x00" * 9,
        1, 247, 1, 0, 0, shoff, 0, ehsize, 0, 0,
        shentsize, shnum, shstrndx,
    )
    null = b"\\x00" * 64
    xdp = struct.pack(
        "<IIQQQQIIQQ", 1, 1, 6, 0, xdp_off, len(code),
        0, 0, 8, 0,
    )
    lic = struct.pack(
        "<IIQQQQIIQQ", 5, 1, 0, 0, lic_off, len(license),
        0, 0, 1, 0,
    )
    strsec = struct.pack(
        "<IIQQQQIIQQ", 13, 3, 0, 0, str_off, len(shstr),
        0, 0, 1, 0,
    )
    return eh + null + xdp + lic + strsec + code + license + shstr


MAP_BYTES = b"\\x00" * 32
BTF_BYTES = bytes.fromhex(os.environ.get("MOJOBPF_FIXTURE_BTF", "00" * 32))


def minimal_map_elf(code):
    shstr = (
        b"\\x00xdp\\x00license\\x00.maps\\x00.BTF\\x00"
        b".symtab\\x00.strtab\\x00.shstrtab\\x00"
    )
    ehsize = 64
    shoff = ehsize
    shentsize, shnum, shstrndx = 64, 8, 7
    xdp_off = shoff + shentsize * shnum
    lic_off = xdp_off + len(code)
    maps_off = lic_off + len(LICENSE)
    btf_off = maps_off + len(MAP_BYTES)
    sym_off = btf_off + len(BTF_BYTES)
    strtab = b"\\x00mojobpf_map0\\x00"
    str_off = sym_off + 48
    shstr_off = str_off + len(strtab)
    eh = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\\x7fELF\\x02\\x01\\x01" + b"\\x00" * 9,
        1, 247, 1, 0, 0, shoff, 0, ehsize, 0, 0,
        shentsize, shnum, shstrndx,
    )
    null = b"\\x00" * 64
    xdp = struct.pack(
        "<IIQQQQIIQQ", 1, 1, 6, 0, xdp_off, len(code),
        0, 0, 8, 0,
    )
    lic = struct.pack(
        "<IIQQQQIIQQ", 5, 1, 0, 0, lic_off, len(LICENSE),
        0, 0, 1, 0,
    )
    maps = struct.pack(
        "<IIQQQQIIQQ", 13, 1, 3, 0, maps_off, len(MAP_BYTES),
        0, 0, 8, 0,
    )
    btf = struct.pack(
        "<IIQQQQIIQQ", 19, 1, 0, 0, btf_off, len(BTF_BYTES),
        0, 0, 1, 0,
    )
    symtab = struct.pack(
        "<IIQQQQIIQQ", 24, 2, 0, 0, sym_off, 48,
        6, 1, 8, 24,
    )
    strsec = struct.pack(
        "<IIQQQQIIQQ", 32, 3, 0, 0, str_off, len(strtab),
        0, 0, 1, 0,
    )
    shstrsec = struct.pack(
        "<IIQQQQIIQQ", 40, 3, 0, 0, shstr_off, len(shstr),
        0, 0, 1, 0,
    )
    sym_null = b"\\x00" * 24
    sym_map = struct.pack("<IBBHQQ", 1, 0x11, 0, 3, 0, 32)
    return (
        eh + null + xdp + lic + maps + btf + symtab + strsec
        + shstrsec + code + LICENSE + MAP_BYTES + BTF_BYTES
        + sym_null + sym_map + strtab + shstr
    )


def mapshape_code():
    code = b"".join(
        struct.pack("<BBhi", 0x07, 0x11, 0, imm)
        for imm in (-16, -4, -4, 1)
    )
    return code + XDP_CODE


def main(argv):
    if argv[1:] == ["--version"]:
        print("llc fixture 0.0")
        return 0
    mode = os.environ.get("MOJOBPF_FIXTURE_LLC", "ok")
    if mode == "crash":
        sys.stderr.write("fixture backend boom\\n")
        return 4
    if mode == "hang":
        time.sleep(30)
        return 0
    out = argv[argv.index("-o") + 1]
    if "-stop-after=prologepilog" in argv:
        mir_mode = os.environ.get("MOJOBPF_FIXTURE_MIR", "empty")
        if mir_mode == "crash":
            sys.stderr.write("fixture MIR boom\\n")
            return 4
        text = MIR_FRAMED if mir_mode == "framed" else MIR_EMPTY
        with open(out, "w", encoding="utf-8") as handle:
            handle.write(text)
        return 0
    if mode == "garbage":
        with open(out, "wb") as handle:
            handle.write(b"not-an-elf-object")
        return 0
    if mode == "badlicense":
        payload = minimal_elf(XDP_CODE, WRONG_LICENSE)
    elif mode == "mapshape":
        payload = minimal_map_elf(mapshape_code())
    else:
        payload = minimal_elf(XDP_CODE)
    with open(out, "wb") as handle:
        handle.write(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
"""

FORKING_MOJO_FIXTURE = """\
#!{python}
import os
import subprocess
import sys
import time


def main(argv):
    if argv[1:] == ["--version"]:
        print("Mojo 9.9.9 (fixture)")
        return 0
    if os.path.basename(argv[-1]) == "dialect_probe.mojo":
        # Dialect-canary probe, not a program compile: succeed
        # quietly without forking (matches CANARY_SOURCE_FILENAME).
        return 0
    marker = os.environ["MOJOBPF_ORPHAN_MARKER"]
    subprocess.Popen(
        [sys.executable, "-c",
         "import time; time.sleep(60)  # " + marker],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(30)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
"""

ADAPTER_OK_FIXTURE = """\
#!{python}
import json
import os
import shutil
import sys


def main(argv):
    req = argv[argv.index("--request") + 1]
    resp = argv[argv.index("--response") + 1]
    with open(req, encoding="utf-8") as handle:
        request = json.load(handle)
    out_dir = request["output_dir"]
    os.makedirs(out_dir, exist_ok=True)
    adapted = os.path.join(out_dir, "adapted.ll")
    shutil.copyfile(request["input_ir"], adapted)
    with open(resp, "w", encoding="utf-8") as handle:
        json.dump(
            {{
                "schema_version": 1,
                "ok": True,
                "outputs": {{"adapted_ir": adapted}},
                "diagnostics": [],
            }},
            handle,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
"""

ADAPTER_SCRIPTED = """\
#!{python}
import sys


PAYLOAD = {payload}
EXIT = {exit_code}


def main(argv):
    if PAYLOAD is not None:
        resp = argv[argv.index("--response") + 1]
        with open(resp, "w", encoding="utf-8") as handle:
            handle.write(PAYLOAD)
    return EXIT


if __name__ == "__main__":
    sys.exit(main(sys.argv))
"""

VERSION_STUB = """\
#!{python}
import sys


def main(argv):
    print({version!r})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
"""

MANIFEST_TEMPLATE = """\
schema_version = 1

[project]
name = "fixture-proj"

[target]
profile = "linux-bpfel-v3"
core = false

[artifact]
name = "fixture_obj"
source_license = "Apache-2.0 WITH LLVM-exception"
kernel_license = "Apache-2.0 WITH LLVM-exception"

{programs}
{maps}
"""

PROGRAM_TEMPLATE = """\
[[programs]]
source = "{source}"
entry = "{entry}"
program_type = "xdp"
section = "xdp"
"""

MAPS_BLOCK = """\
[[maps]]
name = "mojobpf_map0"
map_type = "array"
key_type = "u32"
value_type = "u64"
max_entries = 1
"""

SOURCE_HEADER = "# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception\n"


def write_executable(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text.format(python=sys.executable))
    os.chmod(path, 0o755)


def write_tool_bindir(parent, extra=()):
    """Create fixture mojo+llc (+extra version stubs); return bindir."""
    bindir = tempfile.mkdtemp(prefix="fixture-bin-", dir=parent)
    write_executable(os.path.join(bindir, "mojo"), MOJO_FIXTURE)
    write_executable(os.path.join(bindir, "llc"), LLC_FIXTURE)
    for name, version in extra:
        write_executable(
            os.path.join(bindir, name),
            VERSION_STUB.format(python=sys.executable, version=version),
        )
    return bindir


def write_adapter(parent, payload, exit_code=0):
    path = os.path.join(
        parent, "adapter-%d.py" % len(os.listdir(parent))
    )
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            ADAPTER_SCRIPTED.format(
                python=sys.executable,
                payload=repr(payload),
                exit_code=exit_code,
            )
        )
    os.chmod(path, 0o755)
    return path


def write_project(parent, dirname="proj", programs=(("src/main.mojo",
                                                  "xdp_entry"),),
                with_maps=False):
    """Create a manifest project; return (manifest_path, out_dir)."""
    root = os.path.join(parent, dirname)
    os.makedirs(root)
    blocks = []
    for source, entry in programs:
        full = os.path.join(root, source)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as handle:
            handle.write(SOURCE_HEADER)
            handle.write("# fixture mojo source\n")
        blocks.append(
            PROGRAM_TEMPLATE.format(source=source, entry=entry)
        )
    text = MANIFEST_TEMPLATE.format(
        programs="\n".join(blocks),
        maps=MAPS_BLOCK if with_maps else "",
    )
    manifest_path = os.path.join(root, "mojobpf.toml")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return manifest_path, os.path.join(root, "out")


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


@contextlib.contextmanager
def fixture_env(**values):
    old = {}
    for key, value in values.items():
        old[key] = os.environ.get(key)
        os.environ[key] = value
    try:
        yield
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_service(request_doc, parent, raw=None):
    """Serve one request doc through the real service subprocess."""
    req_path = os.path.join(parent, "req.json")
    resp_path = os.path.join(parent, "resp.json")
    if os.path.exists(resp_path):
        os.remove(resp_path)
    with open(req_path, "w", encoding="utf-8") as handle:
        if raw is not None:
            handle.write(raw)
        else:
            json.dump(request_doc, handle)
    proc = subprocess.run(
        [sys.executable, SERVICE, "--request", req_path,
         "--response", resp_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    response = None
    if os.path.isfile(resp_path):
        with open(resp_path, encoding="utf-8") as handle:
            response = json.load(handle)
    return proc.returncode, response


def valid_service_request(parent, **overrides):
    """Write input IR + manifest stubs; return a valid request doc."""
    input_ir = os.path.join(parent, "input.ll")
    with open(input_ir, "w", encoding="utf-8") as handle:
        handle.write(overrides.pop("ir_text", "; stub\n"))
    manifest_stub = os.path.join(parent, "mojobpf.toml")
    with open(manifest_stub, "w", encoding="utf-8") as handle:
        handle.write("# stub\n")
    request = {
        "schema_version": 1,
        "input_ir": input_ir,
        "manifest_path": manifest_stub,
        "profile_id": "linux-bpfel-v3",
        "output_dir": os.path.join(parent, "adapter-out"),
        "diagnostic_mode": "text",
    }
    request.update(overrides)
    return request


def write_lockfile(parent, bindir, name="toolchains.lock.json",
                   pins=None, tools_pinned=("mojo", "llc")):
    """Pin the fixture tools; return the lockfile path.

    ``pins`` optionally overrides ``{tool: (version, sha256)}`` per
    tool (used by mismatch tests); otherwise pins are measured from
    the fixture binaries.
    """
    tools = {}
    for tool in tools_pinned:
        if pins is not None and tool in pins:
            version, digest = pins[tool]
        else:
            argv0 = "python3" if tool == "python" else tool
            path = os.path.join(bindir, argv0)
            proc = subprocess.run(
                [path, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
            text = proc.stdout if proc.stdout.strip() else proc.stderr
            version = text.strip().splitlines()[0].strip()
            with open(os.path.realpath(path), "rb") as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()
        tools[tool] = {"version": version, "sha256": digest}
    lock_path = os.path.join(parent, name)
    with open(lock_path, "w", encoding="utf-8") as handle:
        json.dump({"schema_version": 1, "tools": tools}, handle)
    return lock_path


def build_fixture(manifest_path, out_dir, parent, adapter=None,
                  lockfile=True, **kwargs):
    bindir = write_tool_bindir(parent)
    if adapter is None:
        adapter = os.path.join(parent, "adapter-ok.py")
        write_executable(adapter, ADAPTER_OK_FIXTURE)
    if lockfile is True:
        lockfile = write_lockfile(parent, bindir)
    elif lockfile is False:
        lockfile = None
    request = BuildRequest(
        manifest_path=manifest_path,
        out_dir=out_dir,
        adapter_path=adapter,
        search_paths=(bindir,),
        lockfile_path=lockfile,
        **kwargs
    )
    return build_project(request)


def test_native_manifest_capture_ownership(tmp_path):
    from mojobpf.manifest import parse_manifest
    from mojobpf.inputs import canonical_manifest_bytes

    manifest_path, _out = write_project(str(tmp_path))
    captured = canonical_manifest_bytes(parse_manifest(manifest_path))
    # Captured declarations remain authoritative after a live TOML edit.
    with open(manifest_path, "a", encoding="utf-8") as handle:
        handle.write("\n# changed after capture\n")
    assert hasattr(build_module, "materialize_native_manifest"), "native captured-manifest materialization is missing"
    owned = tmp_path / "captured.json"
    digest = build_module.materialize_native_manifest(captured, str(owned))
    assert owned.read_bytes() == captured
    assert digest == hashlib.sha256(captured).hexdigest()
    assert json.loads(captured)["programs"][0]["entry"] == "xdp_entry"
    assert b"schema_version = 1" in open(manifest_path, "rb").read()


def test_native_canonical_manifest_tamper(tmp_path):
    from mojobpf.native_adapter import NativeAdapterError
    assert hasattr(build_module, "materialize_native_manifest"), "native captured-manifest materialization is missing"
    captured = b'{"captured":true}\n'
    owned = tmp_path / "captured.json"
    digest = build_module.materialize_native_manifest(captured, str(owned))
    owned.write_bytes(b'{"captured":false}\n')
    try:
        build_module.readback_native_manifest(captured, str(owned), digest)
    except NativeAdapterError:
        pass
    else:
        raise AssertionError("a changed staged native manifest was trusted")


def test_native_response_rejects_unknown_success_field(tmp_path):
    output = tmp_path / "adapted.ll"
    output.write_text("; owned\n")
    response = {"schema_version": 1, "ok": True, "outputs": {"adapted_ir": str(output)},
                "diagnostics": [], "select_native": True}
    diagnostics = []
    assert "native" in __import__("inspect").signature(build_module._interpret_response).parameters, "native protocol gate is missing"
    assert build_module._interpret_response(response, "response.json", diagnostics,
        exit_code=0, adapter_dir=str(tmp_path), native=True) is None
    assert diagnostics[0].code == "MBPF212"


def test_generic_adapter_cannot_select_native_gate(tmp_path):
    # Extra service claims have no authority to change the caller's route.
    output = tmp_path / "adapted.ll"
    output.write_text("; owned generic output\n")
    response = {"schema_version": 1, "ok": True, "outputs": {"adapted_ir": str(output)},
                "diagnostics": [], "select_native": True}
    diagnostics = []
    assert build_module._interpret_response(response, "response.json", diagnostics,
        exit_code=0, adapter_dir=str(tmp_path)) == str(output)
    assert diagnostics == []


def native_fixture_request(tmp_path, bundle, entry="independent_entry"):
    from test_native_adapter import compiler_controls
    service, record = bundle
    parent = str(tmp_path)
    manifest_path, out_dir = write_project(parent, programs=(("src/main.mojo", entry),))
    bindir = write_tool_bindir(parent)
    raw_ir = compiler_controls().module(header="i32 @%s(ptr noundef %%ctx)" % entry)
    frontend = ("#!%s\nimport os,sys\n" % sys.executable +
        "if sys.argv[1:]==['--version']:\n"
        " marker=os.environ.get('MOJOBPF_PROBE_MARKER')\n"
        " if marker: open(marker,'w').write('probed')\n"
        " print('Mojo 9.9.9 (fixture)')\n"
        "else:\n"
        " open(sys.argv[sys.argv.index('-o')+1],'w').write(%r)\n" % raw_ir)
    frontend_path = os.path.join(bindir, "mojo")
    with open(frontend_path, "w", encoding="utf-8") as handle:
        handle.write(frontend)
    os.chmod(frontend_path, 0o755)
    lock = write_lockfile(parent, bindir, name="candidate-lock.json")
    with open(lock, encoding="utf-8") as handle:
        document = json.load(handle)
    document.update(schema_version=2, native_adapter=record)
    with open(lock, "w", encoding="utf-8") as handle:
        json.dump(document, handle)
    return BuildRequest(manifest_path=manifest_path, out_dir=out_dir,
        adapter_path=str(service), lockfile_path=lock, search_paths=(bindir,),
        save_temps=True, work_parent=parent), record


def test_native_build_stops_before_backend_preserving_publication(real_bundle, tmp_path):
    request, _record = native_fixture_request(tmp_path, real_bundle, entry="xdp_entry")
    previous = build_fixture(request.manifest_path, request.out_dir, str(tmp_path))
    assert previous.success, previous.diagnostics
    before = {artifact.path: open(artifact.path, "rb").read() for artifact in previous.artifacts}
    result = build_project(request)
    assert result.success is False and result.artifacts == ()
    assert [(item.code, item.stage) for item in result.diagnostics] == [("MBPF107", "build.backend")], result.diagnostics
    assert result.provenance.adapter_trust == "extension"
    assert all(command.stage != "build.backend" for command in result.commands)
    assert before == {path: open(path, "rb").read() for path in before}
    observed = json.load(open(os.path.join(result.work_dir, "native-input", "admitted-inputs.json")))
    assert observed["runtime_qualified"] is False
    assert observed["observed"]["native_report"]["runtime_qualified"] is False
    spec = json.load(open(os.path.join(result.work_dir, "xdp_entry.adapter", "native-spec.json")))
    assert spec["entry"] == "xdp_entry" and spec["map"] is None


def test_native_missing_sibling_refuses_before_any_tool_probe(real_bundle, tmp_path, monkeypatch):
    request, _record = native_fixture_request(tmp_path, real_bundle)
    probe = tmp_path / "probe-marker"
    monkeypatch.setenv("MOJOBPF_PROBE_MARKER", str(probe))
    os.unlink(os.path.join(os.path.dirname(request.adapter_path), "execution.py"))
    result = build_project(request)
    assert result.success is False and result.commands == ()
    assert result.diagnostics[0].code in ("MBPF102", "MBPF212")
    assert not probe.exists()


def test_native_transport_uses_captured_pins_after_ambient_change(real_bundle, tmp_path, monkeypatch):
    request, record = native_fixture_request(tmp_path, real_bundle)
    monkeypatch.setenv("MOJOBPF_NATIVE_ADMISSION", "ambient before capture")
    capture = build_module._capture_snapshot

    def after_capture(*args, **kwargs):
        snapshot = capture(*args, **kwargs)
        monkeypatch.setenv("MOJOBPF_NATIVE_ADMISSION", "ambient after capture")
        return snapshot

    monkeypatch.setattr(build_module, "_capture_snapshot", after_capture)
    result = build_project(request)
    assert [(item.code, item.stage) for item in result.diagnostics] == [("MBPF107", "build.backend")], result.diagnostics
    observed = json.load(open(os.path.join(result.work_dir, "native-input", "admitted-inputs.json")))
    from test_native_adapter import canonical
    assert observed["native_pins_sha256"] == hashlib.sha256(canonical(record)).hexdigest()


def test_native_live_toml_mutation_keeps_captured_declarations(real_bundle, tmp_path, monkeypatch):
    request, _record = native_fixture_request(tmp_path, real_bundle)
    capture = build_module._capture_snapshot

    def after_capture(*args, **kwargs):
        snapshot = capture(*args, **kwargs)
        text = open(request.manifest_path, encoding="utf-8").read()
        with open(request.manifest_path, "w", encoding="utf-8") as handle:
            handle.write(text.replace('entry = "independent_entry"', 'entry = "live_changed"'))
        return snapshot

    monkeypatch.setattr(build_module, "_capture_snapshot", after_capture)
    result = build_project(request)
    assert result.success is False and not result.artifacts
    assert result.diagnostics[0].code in ("MBPF106", "MBPF107"), result.diagnostics
    if result.diagnostics[0].code == "MBPF107":
        spec_path = os.path.join(result.work_dir, "independent_entry.adapter", "native-spec.json")
        assert json.load(open(spec_path))["entry"] == "independent_entry"
    assert all(command.stage != "build.backend" for command in result.commands)


def test_native_candidate_lock_mutation_after_capture_refuses(real_bundle, tmp_path, monkeypatch):
    request, _record = native_fixture_request(tmp_path, real_bundle)
    capture = build_module._capture_snapshot

    def after_capture(*args, **kwargs):
        snapshot = capture(*args, **kwargs)
        with open(request.lockfile_path, "a", encoding="utf-8") as handle:
            handle.write("\n")
        return snapshot

    monkeypatch.setattr(build_module, "_capture_snapshot", after_capture)
    result = build_project(request)
    assert result.success is False and result.commands == ()
    assert result.diagnostics[0].code == "MBPF102", result.diagnostics


def test_native_manifest_tamper_before_bridge_refuses(real_bundle, tmp_path, monkeypatch):
    request, _record = native_fixture_request(tmp_path, real_bundle)
    adapter = build_module._run_adapter

    def tamper(*args, **kwargs):
        path = kwargs["native_input"].manifest_path
        with open(path, "w", encoding="utf-8") as handle:
            handle.write('{"tampered":true}\n')
        return adapter(*args, **kwargs)

    monkeypatch.setattr(build_module, "_run_adapter", tamper)
    result = build_project(request)
    assert result.diagnostics[0].code == "MBPF106", result.diagnostics
    assert all(command.stage not in ("build.adapter", "build.backend") for command in result.commands)


def test_native_manifest_tamper_after_bridge_refuses(real_bundle, tmp_path, monkeypatch):
    request, _record = native_fixture_request(tmp_path, real_bundle)
    step = build_module._run_step

    def tamper(argv, stage, *args, **kwargs):
        result = step(argv, stage, *args, **kwargs)
        if stage == "build.adapter":
            req_path = argv[argv.index("--request") + 1]
            path = json.load(open(req_path))["manifest_path"]
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('{"tampered":true}\n')
        return result

    monkeypatch.setattr(build_module, "_run_step", tamper)
    result = build_project(request)
    assert result.diagnostics[0].code == "MBPF106", result.diagnostics
    assert all(command.stage != "build.backend" for command in result.commands)


@pytest.mark.parametrize("severity", [[], {}], ids=["array", "object"])
def test_native_malformed_diagnostic_returns_failed_build(real_bundle, tmp_path, monkeypatch, severity):
    # The bridge must really succeed before a malformed owned response is
    # consumed. Enum membership on an untyped severity used to escape here.
    from pathlib import Path
    request, _record = native_fixture_request(tmp_path, real_bundle, entry="xdp_entry")
    previous = build_fixture(request.manifest_path, request.out_dir, str(tmp_path))
    assert previous.success, previous.diagnostics
    before = {artifact.path: Path(artifact.path).read_bytes() for artifact in previous.artifacts}
    step = build_module._run_step

    def fault(argv, stage, *args, **kwargs):
        observed = step(argv, stage, *args, **kwargs)
        if stage == "build.adapter":
            assert observed[0].status == "ok"
            path = Path(argv[argv.index("--response") + 1])
            response = json.loads(path.read_bytes())
            assert response["ok"] is True and response["diagnostics"] == []
            path.with_name("response-before-fault.json").write_bytes(path.read_bytes())
            response["diagnostics"] = [{"code": "MBPF319", "stage": "adapter.target", "severity": severity,
                "explanation": "owned malformed severity control", "location": None, "remedy": "restore typed response"}]
            path.write_text(json.dumps(response))
        return observed

    monkeypatch.setattr(build_module, "_run_step", fault)
    result = build_project(request)
    assert result.success is False and result.artifacts == ()
    assert [(d.code, d.stage) for d in result.diagnostics] == [("MBPF212", "build.adapter")], result.diagnostics
    assert all(command.stage != "build.backend" for command in result.commands)
    assert before == {path: Path(path).read_bytes() for path in before}
    assert Path(result.work_dir, "xdp_entry.adapter-response.json").is_file()


def test_native_response_cannot_select_different_staging_output(real_bundle, tmp_path, monkeypatch):
    # A valid fixed adapted.ll/report cannot approve a distinct returned file.
    from pathlib import Path
    request, _record = native_fixture_request(tmp_path, real_bundle)
    step = build_module._run_step

    def fault(argv, stage, *args, **kwargs):
        observed = step(argv, stage, *args, **kwargs)
        if stage == "build.adapter":
            assert observed[0].status == "ok"
            path = Path(argv[argv.index("--response") + 1])
            response = json.loads(path.read_bytes())
            assert response["ok"] is True
            fixed = Path(response["outputs"]["adapted_ir"])
            report = json.loads(fixed.with_name("native-report.json").read_bytes())
            assert report["output_digest"] == hashlib.sha256(fixed.read_bytes()).hexdigest()
            different = fixed.with_name("different.ll")
            different.write_text("; distinct existing staging output\n")
            path.with_name("response-before-fault.json").write_bytes(path.read_bytes())
            response["outputs"]["adapted_ir"] = str(different)
            path.write_text(json.dumps(response))
        return observed

    monkeypatch.setattr(build_module, "_run_step", fault)
    result = build_project(request)
    assert result.success is False and result.artifacts == ()
    assert [(d.code, d.stage) for d in result.diagnostics] == [("MBPF212", "build.adapter")], result.diagnostics
    assert all(command.stage != "build.backend" for command in result.commands)
    assert not os.listdir(request.out_dir)


def test_native_later_readback_retains_selected_output(real_bundle, tmp_path):
    # Pure output-binding replay: these stand-ins supply no capture/runtime
    # proof. Both files exist and the real fixed output/report remain valid.
    from types import SimpleNamespace
    from pathlib import Path
    from test_native_adapter import serve_native
    service, record = real_bundle
    raw, request, response, _completed = serve_native(tmp_path, service, record)
    manifest = Path(request["manifest_path"])
    directory = Path(request["output_dir"])
    item = SimpleNamespace(manifest_path=str(manifest), manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
        spec_bytes=(directory / "native-spec.json").read_bytes(), raw_path=str(raw),
        input_ir_sha256=hashlib.sha256(raw.read_bytes()).hexdigest(), adapter_dir=str(directory),
        selected_output=response["outputs"]["adapted_ir"], outputs_bytes=None)
    snapshot = SimpleNamespace(verify=lambda: None, manifest_bytes=manifest.read_bytes(), profile_id="linux-bpfel-v3")
    bundle = SimpleNamespace(verify=lambda: None)
    checked = build_module._readback_native_inputs(snapshot, item, bundle)
    item.outputs_bytes = build_module.native_module.canonical_json(checked)
    different = directory / "different.ll"
    different.write_text("; distinct existing staging output\n")
    item.selected_output = str(different)
    with pytest.raises(build_module.native_module.NativeAdapterError, match="output"):
        build_module._readback_native_inputs(snapshot, item, bundle)


def test_legacy_adapter_retains_staged_toml(tmp_path, monkeypatch):
    manifest_path, out_dir = write_project(str(tmp_path))
    original = open(manifest_path, "rb").read()
    monkeypatch.setenv("MOJOBPF_NATIVE_ADMISSION", "ambient data cannot select a native route")
    result = build_fixture(manifest_path, out_dir, str(tmp_path), save_temps=True,
                           work_parent=str(tmp_path))
    assert result.success, result.diagnostics
    request_path = os.path.join(result.work_dir, "xdp_entry.adapter-request.json")
    request = json.load(open(request_path))
    assert request["manifest_path"].endswith("mojobpf.toml")
    from pathlib import Path
    staged = list((Path(result.work_dir) / "inputs-snapshot").rglob("mojobpf.toml"))
    assert len(staged) == 1 and staged[0].read_bytes() == original
    assert result.provenance.manifest_sha256 == hashlib.sha256(original).hexdigest()


def test_generic_route_cannot_inherit_native_pin_carrier(real_bundle, tmp_path, monkeypatch):
    from test_native_adapter import canonical
    service, pins = real_bundle
    manifest_path, out_dir = write_project(str(tmp_path))
    monkeypatch.setenv("MOJOBPF_NATIVE_ADMISSION", canonical(pins).decode("ascii"))
    result = build_fixture(manifest_path, out_dir, str(tmp_path), adapter=str(service),
                           save_temps=True, work_parent=str(tmp_path))
    assert result.success is False and result.artifacts == ()
    assert "missing caller-admitted native pin record" in result.diagnostics[0].explanation, result.diagnostics
    assert all(command.stage != "build.backend" for command in result.commands)


def test_native_publication_guard_rechecks_captured_json(real_bundle, tmp_path):
    from pathlib import Path
    from test_native_adapter import compiler_controls
    request, _record = native_fixture_request(tmp_path, real_bundle)
    manifest = build_module.parse_manifest(request.manifest_path)
    diagnostics, commands = [], []
    seal = build_module._setup_inputs(request, manifest, diagnostics)
    assert seal is not None, diagnostics
    work = tmp_path / "publication-guard"
    work.mkdir()
    try:
        captured = work / "captured.json"
        digest = build_module.materialize_native_manifest(seal.snapshot.manifest_bytes, str(captured))
        raw = work / "source.ll"
        raw.write_text(compiler_controls().module(header="i32 @independent_entry(ptr noundef %ctx)"))
        adapter_dir = str(work / "adapter")
        item = build_module._NativeInputSeal(str(captured), digest,
            build_module.native_module.derive_native_spec(seal.snapshot.manifest_bytes, "linux-bpfel-v3"),
            str(raw), hashlib.sha256(raw.read_bytes()).hexdigest(), adapter_dir)
        adapted = build_module._run_adapter(request, manifest, str(work), "independent_entry", str(raw),
            adapter_dir, diagnostics, commands, seal.adapter_execution,
            staged_manifest=str(captured), spawn_env=dict(seal.spawn_env), spawn_unset=seal.spawn_unset,
            snapshot=seal.snapshot, native_bundle=seal.native_bundle, native_input=item)
        assert adapted is not None, diagnostics
        item = build_module._dataclass_replace(item, selected_output=adapted)
        observed = build_module._readback_native_inputs(seal.snapshot, item, seal.native_bundle)
        item = build_module._dataclass_replace(item, outputs_bytes=build_module.native_module.canonical_json(observed))
        seal = build_module._dataclass_replace(seal, native_inputs=(item,))
        changed = json.loads(captured.read_bytes())
        changed["programs"][0]["entry"] = "publication_tamper"
        captured.write_bytes(build_module.native_module.canonical_json(changed))
        result = build_module._publish_generation(request, manifest, seal, str(work), [], None, diagnostics, commands)
        assert result.success is False and result.artifacts == ()
        assert result.diagnostics[-1].code == "MBPF106", result.diagnostics
        assert not Path(request.out_dir).exists()
    finally:
        seal.snapshot.dispose()


def orphan_marker():
    """Return a process-table marker unique to this test process."""
    return "mojobpf-orphan-%d-%d" % (os.getpid(),
                                     time.monotonic_ns())


def write_forking_bindir(parent):
    """Create bindir with a forking mojo plus the stock llc."""
    bindir = tempfile.mkdtemp(prefix="fixture-bin-", dir=parent)
    write_executable(
        os.path.join(bindir, "mojo"), FORKING_MOJO_FIXTURE
    )
    write_executable(os.path.join(bindir, "llc"), LLC_FIXTURE)
    return bindir


def scan_marker(marker):
    """List process-table lines still carrying ``marker``."""
    try:
        proc = subprocess.run(
            ["pgrep", "-af", marker],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        proc = subprocess.run(
            ["ps", "-eo", "pid=,args="],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15,
        )
    return [
        line.strip() for line in proc.stdout.splitlines()
        if marker in line
    ]


def kill_marker(marker):
    """Best-effort cleanup of marker-carrying sleepers."""
    try:
        subprocess.run(
            ["pkill", "-KILL", "-f", marker],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def await_no_marker(marker, deadline_s=10):
    """Poll for the SIGKILL to land; return any surviving lines."""
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        if not scan_marker(marker):
            return []
        time.sleep(0.1)
    return scan_marker(marker)

def test_successful_fixture_build_publishes_object():
    parent = tempfile.mkdtemp(prefix="build-ok-")
    manifest_path, out_dir = write_project(parent)
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is True, result.diagnostics
    assert result.schema_version == 1
    assert result.diagnostics == ()
    assert result.work_dir is None
    assert [item.role for item in result.artifacts] == [
        "object", "evidence",
    ]
    artifact = result.artifacts[0]
    assert artifact.path == os.path.join(out_dir, "fixture_obj.bpf.o")
    with open(artifact.path, "rb") as handle:
        content = handle.read()
    assert content[:4] == b"\x7fELF"
    assert b"Apache-2.0 WITH LLVM-exception\x00" in content
    assert artifact.size == len(content)
    assert artifact.sha256 == hashlib.sha256(content).hexdigest()
    sidecar = result.artifacts[1]
    assert sidecar.path == os.path.join(
        out_dir, "fixture_obj.evidence.json"
    )
    with open(sidecar.path, encoding="utf-8") as handle:
        evidence_doc = json.load(handle)
    assert evidence_doc["success"] is True
    assert evidence_doc["profile_id"] == "linux-bpfel-v3"
    assert result.provenance is not None
    assert result.provenance.profile_id == "linux-bpfel-v3"
    assert result.provenance.mojo_version == "Mojo 9.9.9 (fixture)"
    assert result.provenance.llc_version == "llc fixture 0.0"
    assert len(result.provenance.mojo_sha256) == 64
    assert len(result.provenance.llc_sha256) == 64
    assert len(result.provenance.source_files) == 1
    stages = [record.stage for record in result.commands]
    assert stages == [
        "build.frontend",
        "build.adapter",
        "build.backend",
    ]
    assert all(record.status == "ok" for record in result.commands)
    assert all(isinstance(record.argv, tuple) for record in result.commands)
    frontend = result.commands[0].argv
    assert frontend[1:4] == ("build", "--emit", "llvm")
    assert "-I" not in frontend
    backend = result.commands[2].argv
    assert backend[1:5] == (
        "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj", backend[4],
    )
    assert backend[-2:] == ("-o", backend[-1])


def test_spaces_and_nonnascii_paths_build():
    parent = tempfile.mkdtemp(prefix="build-uni-")
    manifest_path, out_dir = write_project(
        parent, dirname="pr ojéct ünïcode",
        programs=(("s rc/mödüle file.mojo", "xdp_entry"),),
    )
    assert os.path.isfile(manifest_path)
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is True, result.diagnostics
    assert [item.role for item in result.artifacts] == [
        "object", "evidence",
    ]
    assert os.path.isfile(result.artifacts[0].path)
    assert "pr ojéct ünïcode" in result.artifacts[0].path


def test_maps_manifest_passes_sdk_import_path():
    parent = tempfile.mkdtemp(prefix="build-maps-")
    manifest_path, out_dir = write_project(parent, with_maps=True)
    with fixture_env(
        MOJOBPF_FIXTURE_MOJO="mapmode", MOJOBPF_FIXTURE_LLC="mapshape",
        MOJOBPF_FIXTURE_BTF=FIXTURE_MAP_BTF_HEX,
    ):
        result = build_fixture(
            manifest_path, out_dir, parent, save_temps=True
        )
    try:
        assert result.success is True, result.diagnostics
        frontend = result.commands[0].argv
        flag = frontend.index("-I")
        sdk = frontend[flag + 1]
        # The recorded -I names the origin SDK tree, while the
        # frontend compiled from the snapshot's staged SDK copy,
        # kept under save_temps for inspection.
        assert sdk == os.path.abspath(
            build_module._sdk_dir()
        ), frontend
        for token in frontend:
            assert "mojobpf-inputs-" not in token, frontend
        kept = os.path.join(
            result.work_dir, "inputs-snapshot", "sdk"
        )
        assert os.path.isdir(kept)
        assert sorted(os.listdir(kept)) == ["mojobpf"]
        assert os.path.isfile(
            os.path.join(kept, "mojobpf", "maps.mojo")
        )
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_unsupported_entry_roots_rejected_before_compiling():
    parent = tempfile.mkdtemp(prefix="build-multi-")
    manifest_path, out_dir = write_project(
        parent,
        programs=(("src/a.mojo", "xdp_entry"), ("src/b.mojo", "xdp_b")),
    )
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF213"]
    assert result.diagnostics[0].stage == "build.setup"
    assert result.commands == ()
    assert result.artifacts == ()


def test_mismatched_entry_pair_rejected_before_compiling():
    parent = tempfile.mkdtemp(prefix="build-pair-")
    manifest_path, out_dir = write_project(
        parent,
        programs=(("src/main.mojo", "xdp_entry"),),
    )
    with open(manifest_path, encoding="utf-8") as handle:
        text = handle.read()
    text = text.replace('program_type = "xdp"', 'program_type = "tracepoint"')
    text = text.replace(
        'section = "xdp"', 'section = "tracepoint/syscalls/sys_enter_getpid"'
    )
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(text)
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF217"]
    assert result.diagnostics[0].stage == "build.setup"
    assert "xdp_entry" in result.diagnostics[0].explanation
    assert result.commands == ()
    assert result.artifacts == ()


def test_mismatched_trace_entry_pair_rejected_before_compiling():
    parent = tempfile.mkdtemp(prefix="build-tracepair-")
    manifest_path, out_dir = write_project(
        parent,
        programs=(("src/main.mojo", "trace_entry"),),
    )
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF217"]
    assert result.diagnostics[0].stage == "build.setup"
    assert "trace_entry" in result.diagnostics[0].explanation
    assert result.commands == ()
    assert result.artifacts == ()


def test_unsupported_map_names_rejected_before_compiling():
    parent = tempfile.mkdtemp(prefix="build-mapname-")
    manifest_path, out_dir = write_project(parent, with_maps=True)
    with open(manifest_path, encoding="utf-8") as handle:
        text = handle.read()
    text = text.replace('name = "mojobpf_map0"', 'name = "counts"')
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(text)
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF214"]
    assert result.diagnostics[0].stage == "build.setup"
    assert result.commands == ()
    assert result.artifacts == ()


def test_extra_maps_rejected_before_compiling():
    parent = tempfile.mkdtemp(prefix="build-mapcount-")
    manifest_path, out_dir = write_project(parent, with_maps=True)
    with open(manifest_path, "a", encoding="utf-8") as handle:
        handle.write(
            "[[maps]]\n"
            'name = "mojobpf_map1"\n'
            'map_type = "array"\n'
            'key_type = "u32"\n'
            'value_type = "u64"\n'
            "max_entries = 1\n"
        )
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF215"]
    assert result.diagnostics[0].stage == "build.setup"
    assert result.commands == ()
    assert result.artifacts == ()


def test_declared_map_missing_from_object_rejected():
    parent = tempfile.mkdtemp(prefix="build-nomap-")
    manifest_path, out_dir = write_project(parent, with_maps=True)
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF216"]
    assert result.diagnostics[0].stage == "build.backend"
    assert "manifest.maps" in result.diagnostics[0].explanation
    assert result.artifacts == ()


def test_undeclared_map_in_object_rejected():
    parent = tempfile.mkdtemp(prefix="build-extramap-")
    manifest_path, out_dir = write_project(parent)
    with fixture_env(MOJOBPF_FIXTURE_LLC="mapshape"):
        result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF216"]
    assert result.diagnostics[0].stage == "build.backend"
    assert "manifest.maps" in result.diagnostics[0].explanation
    assert result.artifacts == ()


def test_discover_imports_follows_transitively():
    parent = tempfile.mkdtemp(prefix="imports-")
    main = os.path.join(parent, "main.mojo")
    helper = os.path.join(parent, "helper.mojo")
    deep = os.path.join(parent, "deep.mojo")
    with open(main, "w", encoding="utf-8") as handle:
        handle.write("from helper import thing\n")
    with open(helper, "w", encoding="utf-8") as handle:
        handle.write("from deep import other\n")
    with open(deep, "w", encoding="utf-8") as handle:
        handle.write("from helper import back\n")
    found = build_module._discover_imports(
        (main,), parent, os.path.join(parent, "sdk")
    )
    # The transitive import is captured, and the helper<->deep
    # cycle terminates instead of looping.
    assert sorted(os.path.basename(path) for path in found) == [
        "deep.mojo", "helper.mojo",
    ]


def test_build_captures_transitive_imports_in_evidence():
    parent = tempfile.mkdtemp(prefix="build-trans-")
    manifest_path, out_dir = write_project(parent)
    root = os.path.dirname(manifest_path)
    helper = os.path.join(root, "helper.mojo")
    deep = os.path.join(root, "deep.mojo")
    with open(helper, "w", encoding="utf-8") as handle:
        handle.write(SOURCE_HEADER)
        handle.write("from deep import thing\n")
    with open(deep, "w", encoding="utf-8") as handle:
        handle.write(SOURCE_HEADER)
        handle.write("# leaf module\n")
    with open(
        os.path.join(root, "src", "main.mojo"), "a", encoding="utf-8"
    ) as handle:
        handle.write("from helper import thing\n")
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is True, result.diagnostics
    with open(
        os.path.join(out_dir, "fixture_obj.evidence.json"),
        encoding="utf-8",
    ) as handle:
        doc = json.load(handle)
    assert sorted(
        item["path"] for item in doc["inputs"]["imports"]
    ) == ["deep.mojo", "helper.mojo"]


def test_supported_roots_match_adapter_emission():
    from mojobpf.build import SUPPORTED_ENTRY_ROOTS, SUPPORTED_MAP_NAMES
    with open(SIBLING, encoding="utf-8") as handle:
        adapter_source = handle.read()
    assert tuple(SUPPORTED_ENTRY_ROOTS) == (
        "xdp_entry", "trace_entry", "uprobe_entry",
    )
    assert tuple(SUPPORTED_MAP_NAMES) == ("mojobpf_map0", "mojobpf_map1")
    for root in SUPPORTED_ENTRY_ROOTS:
        assert ("@%s" % root) in adapter_source, (
            "entry root the adapter never emits: %s" % root
        )
    for name in SUPPORTED_MAP_NAMES:
        assert ("@%s" % name) in adapter_source, (
            "map name the adapter never emits: %s" % name
        )


def test_supported_roots_pin_profile_pairs():
    from mojobpf.build import ENTRY_PROGRAM_SECTIONS
    from mojobpf.manifest import SUPPORTED_PROFILES
    registry = set(ENTRY_PROGRAM_SECTIONS.values())
    union = set()
    for profile in SUPPORTED_PROFILES.values():
        assert set(profile.allowed_pairs) <= registry, (
            "profile %s admits a pair no entry root pins"
            % profile.profile_id
        )
        union |= set(profile.allowed_pairs)
    assert union == registry, (
        "entry root pins a pair no profile admits: %r"
        % (registry - union,)
    )


def test_missing_tools_fail_without_fallback():
    parent = tempfile.mkdtemp(prefix="build-notools-")
    manifest_path, out_dir = write_project(parent)
    empty = tempfile.mkdtemp(prefix="empty-path-")
    lockfile = os.path.join(parent, "toolchains.lock.json")
    with open(lockfile, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "schema_version": 1,
                "tools": {
                    "mojo": {"version": "v", "sha256": "0" * 64},
                    "llc": {"version": "v", "sha256": "0" * 64},
                },
            },
            handle,
        )
    with isolated_path(empty):
        result = build_project(
            BuildRequest(
                manifest_path=manifest_path,
                out_dir=out_dir,
                adapter_path=SERVICE,
                lockfile_path=lockfile,
            )
        )
    assert result.success is False
    assert [item.code for item in result.diagnostics] == [
        "MBPF103", "MBPF103",
    ]
    assert all(
        item.stage == "toolchain.discovery" for item in result.diagnostics
    )
    assert result.provenance is None
    assert result.commands == ()
    assert result.artifacts == ()


def test_missing_lockfile_fails_closed():
    parent = tempfile.mkdtemp(prefix="build-nolock-")
    manifest_path, out_dir = write_project(parent)
    result = build_fixture(
        manifest_path, out_dir, parent, lockfile=False
    )
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF104"]
    assert result.diagnostics[0].stage == "toolchain.match"
    assert "no lockfile supplied" in result.diagnostics[0].explanation
    assert result.provenance is None
    assert result.commands == ()
    assert result.artifacts == ()


def test_pin_mismatch_fails_before_compiling():
    parent = tempfile.mkdtemp(prefix="build-mismatch-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(
        parent, bindir, pins={"mojo": ("Mojo 0.0.0 (wrong)", "0" * 64)}
    )
    result = build_project(
        BuildRequest(
            manifest_path=manifest_path,
            out_dir=out_dir,
            adapter_path=adapter,
            search_paths=(bindir,),
            lockfile_path=lockfile,
        )
    )
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF102"]
    assert result.diagnostics[0].stage == "toolchain.match"
    assert result.provenance is None
    assert result.commands == ()
    assert result.artifacts == ()


def test_broken_version_probe_fails():
    parent = tempfile.mkdtemp(prefix="build-broken-")
    manifest_path, out_dir = write_project(parent)
    bindir = tempfile.mkdtemp(prefix="fixture-bin-", dir=parent)
    broken = VERSION_STUB.replace('return 0', 'return 1').format(
        python=sys.executable, version="unused"
    )
    write_executable(os.path.join(bindir, "mojo"), broken)
    write_executable(os.path.join(bindir, "llc"), LLC_FIXTURE)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    proc = subprocess.run(
        [os.path.join(bindir, "llc"), "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    llc_version = proc.stdout.strip().splitlines()[0].strip()
    with open(os.path.join(bindir, "llc"), "rb") as handle:
        llc_sha = hashlib.sha256(handle.read()).hexdigest()
    lockfile = os.path.join(parent, "toolchains.lock.json")
    with open(lockfile, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "schema_version": 1,
                "tools": {
                    "mojo": {"version": "v", "sha256": "0" * 64},
                    "llc": {"version": llc_version, "sha256": llc_sha},
                },
            },
            handle,
        )
    empty = tempfile.mkdtemp(prefix="empty-path-")
    with isolated_path(empty):
        result = build_project(
            BuildRequest(
                manifest_path=manifest_path,
                out_dir=out_dir,
                adapter_path=adapter,
                search_paths=(bindir,),
                lockfile_path=lockfile,
            )
        )
    assert result.success is False
    # A01 admission-first: the bogus mojo pin is rejected with MBPF102
    # before any --version probe runs (previously the probe ran and
    # failed as MBPF103). The build still fails with no artifacts.
    assert [item.code for item in result.diagnostics] == ["MBPF102"]
    assert result.artifacts == ()

def test_compiler_crash_is_captured():
    parent = tempfile.mkdtemp(prefix="build-crash-")
    manifest_path, out_dir = write_project(parent)
    with fixture_env(MOJOBPF_FIXTURE_MOJO="crash"):
        result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert len(result.diagnostics) == 1
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF106"
    assert diagnostic.stage == "build.frontend"
    assert "exited 3" in diagnostic.explanation
    frontend = result.commands[0]
    assert frontend.stage == "build.frontend"
    assert frontend.status == "failed"
    assert frontend.exit_code == 3
    assert "fixture frontend boom" in frontend.log_excerpt
    assert result.artifacts == ()
    assert result.provenance is not None
    assert not os.path.exists(out_dir) or os.listdir(out_dir) == []


def test_backend_crash_is_captured():
    parent = tempfile.mkdtemp(prefix="build-be-")
    manifest_path, out_dir = write_project(parent)
    with fixture_env(MOJOBPF_FIXTURE_LLC="crash"):
        result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF106"]
    assert result.diagnostics[0].stage == "build.backend"
    backend = result.commands[-1]
    assert backend.exit_code == 4
    assert "fixture backend boom" in backend.log_excerpt
    assert result.artifacts == ()


def test_error_marker_on_stderr_fails_the_step():
    parent = tempfile.mkdtemp(prefix="build-errmark-")
    manifest_path, out_dir = write_project(parent)
    with fixture_env(MOJOBPF_FIXTURE_MOJO="stderr-error"):
        result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert result.diagnostics[0].code == "MBPF106"
    assert result.diagnostics[0].stage == "build.frontend"
    assert "reported errors" in result.diagnostics[0].explanation
    # The process exited 0; only the marker failed it.
    assert result.commands[0].exit_code == 0
    assert result.artifacts == ()


def test_buried_error_marker_before_long_tail_fails():
    parent = tempfile.mkdtemp(prefix="build-buried-")
    manifest_path, out_dir = write_project(parent)
    with fixture_env(MOJOBPF_FIXTURE_MOJO="buried-error"):
        result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert result.diagnostics[0].code == "MBPF106"
    assert result.diagnostics[0].stage == "build.frontend"
    assert "reported errors" in result.diagnostics[0].explanation
    # The marker sits before the excerpt window: the verdict must still
    # see it, while the excerpt itself stays bounded.
    assert "buried marker" not in result.commands[0].log_excerpt
    assert len(result.commands[0].log_excerpt) <= 4000
    assert result.artifacts == ()


def test_late_error_marker_past_cap_fails():
    parent = tempfile.mkdtemp(prefix="build-lateerr-")
    manifest_path, out_dir = write_project(parent)
    with fixture_env(MOJOBPF_FIXTURE_MOJO="late-error"):
        result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF106"]
    assert result.diagnostics[0].stage == "build.frontend"
    assert "reported errors" in result.diagnostics[0].explanation
    # The tool exits zero with its error past the retained head: the
    # verdict still sees it across the full drained stream, while the
    # excerpt itself never holds the marker.
    assert "error:" not in result.commands[0].log_excerpt
    assert result.artifacts == ()


def test_pump_scans_marker_across_chunk_boundaries():
    chunks, state = [], [0, 0, None, False]
    old = build_module._STREAM_CHUNK
    build_module._STREAM_CHUNK = 3
    try:
        stream = io.StringIO("xxERROR:yy")
        build_module._pump_stream(stream, chunks, state, "error:")
    finally:
        build_module._STREAM_CHUNK = old
    assert state[3] is True
    assert "".join(chunks) == "xxERROR:yy"
    # No marker, same chunking: nothing found.
    chunks, state = [], [0, 0, None, False]
    build_module._STREAM_CHUNK = 3
    try:
        stream = io.StringIO("xxERRO R:yy")
        build_module._pump_stream(stream, chunks, state, "error:")
    finally:
        build_module._STREAM_CHUNK = old
    assert state[3] is False


def test_pump_scans_marker_past_capture_cap():
    old_chunk = build_module._STREAM_CHUNK
    old_cap = build_module.STREAM_CAPTURE_LIMIT
    build_module._STREAM_CHUNK = 4
    build_module.STREAM_CAPTURE_LIMIT = 8
    try:
        stream = io.StringIO("12345678" + "error: late")
        chunks, state = [], [0, 0, None, False]
        build_module._pump_stream(stream, chunks, state, "error:")
    finally:
        build_module._STREAM_CHUNK = old_chunk
        build_module.STREAM_CAPTURE_LIMIT = old_cap
    assert state[3] is True
    assert state[1] > 0
    assert "error:" not in "".join(chunks)


def test_backend_timeout_is_recorded():
    parent = tempfile.mkdtemp(prefix="build-timeout-")
    manifest_path, out_dir = write_project(parent)
    start = time.monotonic()
    with fixture_env(MOJOBPF_FIXTURE_LLC="hang"):
        result = build_fixture(
            manifest_path, out_dir, parent, timeout_s=1
        )
    elapsed = time.monotonic() - start
    assert result.success is False
    assert result.diagnostics[0].code == "MBPF106"
    assert "timed out" in result.diagnostics[0].explanation
    backend = result.commands[-1]
    assert backend.status == "timeout"
    assert backend.exit_code is None
    assert result.artifacts == ()
    assert elapsed < 20, "hung child was not killed promptly"


def test_failed_build_never_reports_stale_success():
    parent = tempfile.mkdtemp(prefix="build-stale-")
    manifest_path, out_dir = write_project(parent)
    first = build_fixture(manifest_path, out_dir, parent)
    assert first.success is True
    stale_path = first.artifacts[0].path
    with open(stale_path, "rb") as handle:
        stale_bytes = handle.read()
    with fixture_env(MOJOBPF_FIXTURE_MOJO="crash"):
        result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert result.artifacts == ()
    # The previous output is untouched user data, never the new result.
    with open(stale_path, "rb") as handle:
        assert handle.read() == stale_bytes


def test_license_pair_gate_runs_before_compiling():
    parent = tempfile.mkdtemp(prefix="build-pair-")
    manifest_path, out_dir = write_project(parent)
    with open(manifest_path, encoding="utf-8") as handle:
        text = handle.read()
    text = text.replace(
        'kernel_license = "Apache-2.0 WITH LLVM-exception"',
        'kernel_license = "MIT"',
    )
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(text)
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF704"]
    assert result.diagnostics[0].stage == "inspect.license"
    assert result.commands == ()
    assert result.artifacts == ()


def test_source_grant_gate_runs_before_compiling():
    parent = tempfile.mkdtemp(prefix="build-grants-")
    manifest_path, out_dir = write_project(parent)
    source = os.path.join(
        os.path.dirname(manifest_path), "src", "main.mojo"
    )
    with open(source, "w", encoding="utf-8") as handle:
        handle.write("# no SPDX header here\n")
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF707"]
    assert result.diagnostics[0].stage == "inspect.license"
    assert result.commands == ()
    assert result.artifacts == ()


def test_verify_gate_rejects_garbage_object():
    parent = tempfile.mkdtemp(prefix="build-garbage-")
    manifest_path, out_dir = write_project(parent)
    with fixture_env(MOJOBPF_FIXTURE_LLC="garbage"):
        result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert result.diagnostics[0].code == "MBPF401"
    assert result.diagnostics[0].stage == "inspect.object"
    assert result.artifacts == ()
    assert not os.path.exists(out_dir) or os.listdir(out_dir) == []


def test_verify_gate_rejects_wrong_license():
    parent = tempfile.mkdtemp(prefix="build-badlic-")
    manifest_path, out_dir = write_project(parent)
    with fixture_env(MOJOBPF_FIXTURE_LLC="badlicense"):
        result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF705"]
    assert result.diagnostics[0].stage == "inspect.license"
    assert result.artifacts == ()


def test_map_mode_passes_frameless_gate():
    parent = tempfile.mkdtemp(prefix="build-mapgate-")
    manifest_path, out_dir = write_project(parent, with_maps=True)
    with fixture_env(
        MOJOBPF_FIXTURE_MOJO="mapmode", MOJOBPF_FIXTURE_LLC="mapshape",
        MOJOBPF_FIXTURE_BTF=FIXTURE_MAP_BTF_HEX,
    ):
        result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is True, result.diagnostics
    stages = [record.stage for record in result.commands]
    assert stages == [
        "build.frontend",
        "build.adapter",
        "build.backend",
        "build.backend",
    ]
    mir_argv = result.commands[3].argv
    assert "-stop-after=prologepilog" in mir_argv


def test_map_mode_framed_object_rejected():
    parent = tempfile.mkdtemp(prefix="build-framed-")
    manifest_path, out_dir = write_project(parent, with_maps=True)
    with fixture_env(
        MOJOBPF_FIXTURE_MOJO="mapmode",
        MOJOBPF_FIXTURE_LLC="mapshape",
        MOJOBPF_FIXTURE_BTF=FIXTURE_MAP_BTF_HEX,
        MOJOBPF_FIXTURE_MIR="framed",
    ):
        result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF107"]
    assert "stack frame" in result.diagnostics[0].explanation
    assert result.artifacts == ()


def test_map_mode_mir_dump_failure_rejected():
    parent = tempfile.mkdtemp(prefix="build-mirfail-")
    manifest_path, out_dir = write_project(parent, with_maps=True)
    with fixture_env(
        MOJOBPF_FIXTURE_MOJO="mapmode",
        MOJOBPF_FIXTURE_LLC="mapshape",
        MOJOBPF_FIXTURE_BTF=FIXTURE_MAP_BTF_HEX,
        MOJOBPF_FIXTURE_MIR="crash",
    ):
        result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF107"]
    assert "MIR frame dump" in result.diagnostics[0].explanation
    assert result.artifacts == ()


def test_map_mode_shape_drift_rejected():
    parent = tempfile.mkdtemp(prefix="build-shapedrift-")
    manifest_path, out_dir = write_project(parent, with_maps=True)
    with fixture_env(MOJOBPF_FIXTURE_MOJO="mapmode"):
        result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF107"]
    assert "add-immediate set" in result.diagnostics[0].explanation
    assert result.artifacts == ()


def test_flood_output_is_captured_bounded():
    parent = tempfile.mkdtemp(prefix="build-flood-")
    manifest_path, out_dir = write_project(parent)
    with fixture_env(MOJOBPF_FIXTURE_MOJO="flood"):
        result = build_fixture(
            manifest_path, out_dir, parent, save_temps=True
        )
    try:
        assert result.success is False
        assert result.diagnostics[0].code == "MBPF106"
        assert result.work_dir is not None
        log_path = os.path.join(
            result.work_dir, "xdp_entry.frontend.log"
        )
        with open(log_path, encoding="utf-8") as handle:
            full = handle.read()
        assert len(full) < 1200000, len(full)
        assert "capture truncated" in full
        assert len(result.commands[0].log_excerpt) <= 4000
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def _failing_stdout_popen(fail):
    real_popen = subprocess.Popen

    class FailingStdout:
        def __init__(self, wrapped):
            self._wrapped = wrapped

        def read(self, size=-1):
            raise OSError("fixture reader failure")

        def close(self):
            try:
                self._wrapped.close()
            except Exception:
                pass

    def popping(*args, **kwargs):
        proc = real_popen(*args, **kwargs)
        if fail(args[0]):
            proc.stdout = FailingStdout(proc.stdout)
        return proc

    return real_popen, popping


def test_run_step_reader_error_fails_verdict():
    real_popen, popping = _failing_stdout_popen(lambda argv: True)
    subprocess.Popen = popping
    try:
        parent = tempfile.mkdtemp(prefix="run-capture-")
        log = os.path.join(parent, "step.log")
        record, stdout, stderr, saw = build_module._run_step(
            [
                sys.executable, "-c",
                "import sys; sys.stderr.write('note\\n')",
            ],
            "build.frontend",
            30,
            log,
            parent,
        )
    finally:
        subprocess.Popen = real_popen
    assert record.status == "failed"
    assert record.exit_code == 0
    assert "capture error" in stdout
    assert "capture error" in record.log_excerpt
    failure = build_module._step_outcome(
        record, os.path.join(parent, "out.o"), "frontend", "error:",
        stderr, saw,
    )
    assert failure is not None
    assert failure.code == "MBPF106"
    assert "capture" in failure.explanation


def test_build_frontend_capture_error_fails_closed():
    parent = tempfile.mkdtemp(prefix="build-capture-")
    manifest_path, out_dir = write_project(parent)
    scratch = tempfile.mkdtemp(prefix="build-capture-work-", dir=parent)

    def fail_frontend(argv):
        return len(argv) > 1 and argv[1] == "build"

    real_popen, popping = _failing_stdout_popen(fail_frontend)
    subprocess.Popen = popping
    try:
        result = build_fixture(
            manifest_path, out_dir, parent, work_parent=scratch
        )
    finally:
        subprocess.Popen = real_popen
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF106"]
    assert "capture" in result.diagnostics[0].explanation
    assert result.artifacts == ()
    assert [
        name for name in os.listdir(out_dir)
        if name.endswith(".bpf.o")
    ] == []
    assert [
        name for name in os.listdir(scratch)
        if name.startswith("mojobpf-build-")
    ] == []


def test_run_step_drain_bounded_by_deadline():
    parent = tempfile.mkdtemp(prefix="run-drain-")
    pidfile = os.path.join(parent, "grandchild.pid")
    grandchild = (
        "import os, time; "
        "open(os.environ['MOJOBPF_DRAIN_PIDFILE'], 'w').write("
        "str(os.getpid())); time.sleep(25)"
    )
    script = (
        "import subprocess, sys; "
        "subprocess.Popen([sys.executable, '-c', %r], "
        "stdout=sys.stdout, stderr=sys.stderr); "
        "print('parent done')" % grandchild
    )
    with fixture_env(MOJOBPF_DRAIN_PIDFILE=pidfile):
        log = os.path.join(parent, "step.log")
        start = time.monotonic()
        record, _, _, _ = build_module._run_step(
            [sys.executable, "-c", script],
            "build.frontend",
            2,
            log,
            parent,
        )
        elapsed = time.monotonic() - start
    # The parent exits at once while its descendant holds the pipes:
    # the step times out at the shared deadline instead of hanging
    # 25s (one budget for both readers, not one per reader), and
    # the group kill reaps the descendant.
    assert record.status == "timeout", record
    assert "draining output pipes" in record.log_excerpt
    assert 1.0 <= elapsed < 3.0, elapsed
    with open(pidfile, encoding="utf-8") as handle:
        orphan = int(handle.read())
    deadline = time.monotonic() + 10
    while True:
        try:
            os.kill(orphan, 0)
        except OSError:
            break
        assert time.monotonic() < deadline, "pipe holder survived"
        time.sleep(0.05)


def test_malformed_manifest_maps_to_result():
    parent = tempfile.mkdtemp(prefix="build-badman-")
    manifest_path, out_dir = write_project(parent)
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write("schema_version = [unclosed\n")
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF209"]
    assert result.provenance is None
    assert result.commands == ()


def test_unknown_profile_maps_to_result():
    parent = tempfile.mkdtemp(prefix="build-badprof-")
    manifest_path, out_dir = write_project(parent)
    with open(manifest_path, encoding="utf-8") as handle:
        text = handle.read()
    text = text.replace("linux-bpfel-v3", "linux-bpfeb-v9")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(text)
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF101"]
    assert result.provenance is None


def test_log_excerpt_is_bounded_but_full_log_kept():
    parent = tempfile.mkdtemp(prefix="build-excerpt-")
    manifest_path, out_dir = write_project(parent)
    with fixture_env(MOJOBPF_FIXTURE_MOJO="loud-crash"):
        result = build_fixture(
            manifest_path, out_dir, parent, save_temps=True
        )
    try:
        assert result.success is False
        excerpt = result.commands[0].log_excerpt
        assert len(excerpt) <= 4000
        assert result.work_dir is not None
        log_path = os.path.join(result.work_dir, "xdp_entry.frontend.log")
        with open(log_path, encoding="utf-8") as handle:
            full = handle.read()
        assert len(full) > 100000
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_save_temps_keeps_workdir_on_success():
    parent = tempfile.mkdtemp(prefix="build-temps-")
    manifest_path, out_dir = write_project(parent)
    result = build_fixture(manifest_path, out_dir, parent, save_temps=True)
    try:
        assert result.success is True
        assert result.work_dir is not None
        assert os.path.isdir(result.work_dir)
        assert os.path.isfile(
            os.path.join(result.work_dir, "xdp_entry.raw.ll")
        )
        assert os.path.isfile(
            os.path.join(result.work_dir, "xdp_entry.frontend.log")
        )
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)

def test_malformed_adapter_responses_fail_closed():
    cases = {
        "garbage": ("not json{{{", 0, "no usable response"),
        "wrong-version": (
            json.dumps({
                "schema_version": 99, "ok": True,
                "outputs": {}, "diagnostics": [],
            }),
            0, "unsupported schema_version",
        ),
        "failure-without-diagnostics": (
            json.dumps({
                "schema_version": 1, "ok": False,
                "outputs": {}, "diagnostics": [],
            }),
            1, "without diagnostics",
        ),
        "success-without-output": (
            json.dumps({
                "schema_version": 1, "ok": True,
                "outputs": {}, "diagnostics": [],
            }),
            0, "without a usable adapted_ir",
        ),
        "bad-diagnostic-entry": (
            json.dumps({
                "schema_version": 1, "ok": False,
                "outputs": {}, "diagnostics": [{"code": "bogus"}],
            }),
            1, "invalid diagnostic entry",
        ),
        "crash-without-response": (None, 3, "trustworthy response"),
        "exit-zero-with-failure": (
            json.dumps({
                "schema_version": 1, "ok": False,
                "outputs": {},
                "diagnostics": [
                    {
                        "code": "MBPF302",
                        "stage": "adapter.audit",
                        "severity": "error",
                        "explanation": "fixture rejection",
                        "location": None,
                        "remedy": None,
                    }
                ],
            }),
            0, "contradictory adapter outcome",
        ),
        "exit-one-with-success": (
            json.dumps({
                "schema_version": 1, "ok": True,
                "outputs": {"adapted_ir": "/nonexistent.ll"},
                "diagnostics": [],
            }),
            1, "contradictory adapter outcome",
        ),
    }
    for name, (payload, exit_code, marker) in cases.items():
        parent = tempfile.mkdtemp(prefix="build-adapter-%s-" % name)
        manifest_path, out_dir = write_project(parent)
        adapter = write_adapter(parent, payload, exit_code)
        result = build_fixture(
            manifest_path, out_dir, parent, adapter=adapter
        )
        assert result.success is False, name
        assert len(result.diagnostics) == 1, name
        diagnostic = result.diagnostics[0]
        assert diagnostic.code == "MBPF212", name
        assert diagnostic.stage == "build.adapter", name
        assert marker in diagnostic.explanation, name
        assert result.artifacts == (), name
        assert result.provenance is not None, name


def test_adapter_rejection_propagates_through_build():
    parent = tempfile.mkdtemp(prefix="build-reject-")
    manifest_path, out_dir = write_project(parent)
    # The fixture frontend emits canned text the real adapter rejects.
    result = build_fixture(
        manifest_path, out_dir, parent, adapter=SERVICE
    )
    assert result.success is False
    assert len(result.diagnostics) == 1
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF302"
    assert diagnostic.stage == "adapter.audit"
    assert "@xdp_entry" in diagnostic.explanation
    assert result.artifacts == ()
    assert not os.path.exists(out_dir) or os.listdir(out_dir) == []


def test_contradictory_adapter_success_rejected():
    parent = tempfile.mkdtemp(prefix="build-contra-")
    manifest_path, out_dir = write_project(parent)
    foreign = os.path.join(parent, "foreign.ll")
    with open(foreign, "w", encoding="utf-8") as handle:
        handle.write("; foreign pre-existing IR\n")
    payload = json.dumps({
        "schema_version": 1, "ok": True,
        "outputs": {"adapted_ir": foreign},
        "diagnostics": [
            {
                "code": "MBPF302",
                "stage": "adapter.audit",
                "severity": "error",
                "explanation": "fixture error with success",
                "location": None,
                "remedy": None,
            }
        ],
    })
    adapter = write_adapter(parent, payload, 0)
    result = build_fixture(
        manifest_path, out_dir, parent, adapter=adapter
    )
    assert result.success is False
    assert len(result.diagnostics) == 1
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF212"
    assert diagnostic.stage == "build.adapter"
    assert "contradictory" in diagnostic.explanation
    assert result.artifacts == ()


def test_adapter_output_outside_staging_rejected():
    parent = tempfile.mkdtemp(prefix="build-outside-")
    manifest_path, out_dir = write_project(parent)
    foreign = os.path.join(parent, "foreign.ll")
    with open(foreign, "w", encoding="utf-8") as handle:
        handle.write("; foreign pre-existing IR\n")
    payload = json.dumps({
        "schema_version": 1, "ok": True,
        "outputs": {"adapted_ir": foreign},
        "diagnostics": [],
    })
    adapter = write_adapter(parent, payload, 0)
    result = build_fixture(
        manifest_path, out_dir, parent, adapter=adapter
    )
    assert result.success is False
    assert len(result.diagnostics) == 1
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF212"
    assert diagnostic.stage == "build.adapter"
    assert "staging directory" in diagnostic.explanation
    assert result.artifacts == ()


def test_build_path_is_unprivileged_only():
    parent = tempfile.mkdtemp(prefix="build-unpriv-")
    manifest_path, out_dir = write_project(parent)
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is True
    forbidden = {
        "bpftool", "load", "attach", "run", "verify", "--kernel",
        "tc", "ip", "vng", "mount", "sudo",
    }
    for record in result.commands:
        tokens = {item.lower() for item in record.argv}
        assert not tokens & forbidden, record.argv
        binary = os.path.basename(record.argv[0])
        assert binary in ("mojo", "llc", os.path.basename(sys.executable)), (
            record.argv
        )


def test_build_request_validation():
    parent = tempfile.mkdtemp(prefix="build-req-")
    manifest_path, out_dir = write_project(parent)
    for bad in (2, True, 1.0, "1"):
        try:
            BuildRequest(
                manifest_path, out_dir, SERVICE, schema_version=bad
            )
        except ValueError:
            pass
        else:
            raise AssertionError("schema_version %r accepted" % (bad,))
    for bad_timeout in (0, -5, True, "60"):
        try:
            BuildRequest(manifest_path, out_dir, SERVICE,
                         timeout_s=bad_timeout)
        except ValueError:
            pass
        else:
            raise AssertionError("timeout_s %r accepted" % (bad_timeout,))
    try:
        build_project("not-a-request")
    except ValueError:
        pass
    else:
        raise AssertionError("non-BuildRequest accepted")


def test_publish_leaves_no_temporary_files():
    parent = tempfile.mkdtemp(prefix="build-pub-")
    manifest_path, out_dir = write_project(parent)
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is True, result.diagnostics
    assert sorted(os.listdir(out_dir)) == [
        "fixture_obj.bpf.o", "fixture_obj.evidence.json",
    ]


def test_build_publish_rolls_back_failed_generation():
    parent = tempfile.mkdtemp(prefix="build-rollback-")
    manifest_path, out_dir = write_project(parent)
    os.makedirs(out_dir)
    # Block the evidence sidecar: the object must roll back with it.
    os.makedirs(os.path.join(out_dir, "fixture_obj.evidence.json"))
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF106"]
    assert result.artifacts == ()
    assert sorted(os.listdir(out_dir)) == ["fixture_obj.evidence.json"]
    assert os.path.isdir(os.path.join(out_dir, "fixture_obj.evidence.json"))


def test_publish_failure_leaves_no_tmp_files():
    if os.geteuid() == 0:
        raise AssertionError("refusing permission test as root")
    parent = tempfile.mkdtemp(prefix="build-pubfail-")
    manifest_path, out_dir = write_project(parent)
    os.makedirs(out_dir)
    os.chmod(out_dir, 0o555)
    try:
        result = build_fixture(manifest_path, out_dir, parent)
    finally:
        os.chmod(out_dir, 0o755)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF106"]
    assert result.diagnostics[0].stage == "evidence.publish"
    assert result.artifacts == ()
    assert os.listdir(out_dir) == []


def test_relative_request_paths_resolve_against_cwd():
    parent = tempfile.mkdtemp(prefix="build-rel-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(parent, bindir)
    old_cwd = os.getcwd()
    os.chdir(parent)
    try:
        result = build_project(
            BuildRequest(
                manifest_path=os.path.relpath(manifest_path),
                out_dir=os.path.relpath(out_dir),
                adapter_path=os.path.relpath(adapter),
                search_paths=(os.path.relpath(bindir),),
                lockfile_path=os.path.relpath(lockfile),
            )
        )
    finally:
        os.chdir(old_cwd)
    assert result.success is True, result.diagnostics
    assert os.path.isabs(result.artifacts[0].path)
    assert os.path.isabs(result.provenance.manifest_path)
    assert os.path.isabs(result.provenance.adapter_path)


def test_missing_adapter_script_fails_in_setup():
    parent = tempfile.mkdtemp(prefix="build-noadapter-")
    manifest_path, out_dir = write_project(parent)
    result = build_fixture(
        manifest_path, out_dir, parent,
        adapter=os.path.join(parent, "no-such-adapter.py"),
    )
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF106"]
    assert result.diagnostics[0].stage == "build.setup"

def test_service_rejects_malformed_requests():
    parent = tempfile.mkdtemp(prefix="service-req-")
    code, response = run_service(None, parent, raw="not json{{{")
    assert code == 1
    assert response["ok"] is False
    assert response["diagnostics"][0]["code"] == "MBPF212"
    variants = []
    base = valid_service_request(parent)
    unknown = dict(base)
    unknown["bogus"] = 1
    variants.append((unknown, "unknown adapter request field"))
    missing = dict(base)
    del missing["output_dir"]
    variants.append((missing, "lacks required field"))
    for bad_version in (99, True, "1", None):
        versioned = dict(base)
        versioned["schema_version"] = bad_version
        variants.append((versioned, "unsupported adapter request"))
    bad_profile = dict(base)
    bad_profile["profile_id"] = "linux-bpfeb-v9"
    variants.append((bad_profile, "unsupported target profile"))
    bad_mode = dict(base)
    bad_mode["diagnostic_mode"] = "yaml"
    variants.append((bad_mode, "unsupported diagnostic_mode"))
    bad_input = dict(base)
    bad_input["input_ir"] = os.path.join(parent, "no-such.ll")
    variants.append((bad_input, "input IR not found"))
    bad_manifest = dict(base)
    bad_manifest["manifest_path"] = os.path.join(parent, "no-such.toml")
    variants.append((bad_manifest, "manifest not found"))
    bad_empty = dict(base)
    bad_empty["output_dir"] = ""
    variants.append((bad_empty, "non-empty string"))
    for request_doc, marker in variants:
        code, response = run_service(request_doc, parent)
        assert code == 1, marker
        assert response["schema_version"] == 1, marker
        assert response["ok"] is False, marker
        assert response["outputs"] == {}, marker
        assert len(response["diagnostics"]) == 1, marker
        diagnostic = response["diagnostics"][0]
        assert diagnostic["code"] == "MBPF212", marker
        assert diagnostic["stage"] == "adapter.request", marker
        assert marker in diagnostic["explanation"], marker
        assert set(diagnostic) == {
            "code", "stage", "severity", "explanation",
            "location", "remedy",
        }, marker


def test_service_propagates_audit_diagnostic_unchanged():
    parent = tempfile.mkdtemp(prefix="service-ir-")
    request = valid_service_request(parent, ir_text="; nothing here\n")
    code, response = run_service(request, parent)
    assert code == 1
    assert response["ok"] is False
    assert len(response["diagnostics"]) == 1
    diagnostic = response["diagnostics"][0]
    assert diagnostic["code"] == "MBPF302"
    assert diagnostic["stage"] == "adapter.audit"
    assert diagnostic["severity"] == "error"
    assert "@xdp_entry" in diagnostic["explanation"]
    assert diagnostic["remedy"]


def test_service_reports_internal_failures_separately():
    service = load_module("adapter_service_internal", SERVICE)
    parent = tempfile.mkdtemp(prefix="service-internal-")
    input_ir = os.path.join(parent, "input.ll")
    with open(input_ir, "w", encoding="utf-8") as handle:
        handle.write("; stub\n")
    manifest_stub = os.path.join(parent, "mojobpf.toml")
    with open(manifest_stub, "w", encoding="utf-8") as handle:
        handle.write("# stub\n")
    request_path = os.path.join(parent, "req.json")
    response_path = os.path.join(parent, "resp.json")
    with open(request_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "schema_version": 1,
                "input_ir": input_ir,
                "manifest_path": manifest_stub,
                "profile_id": "linux-bpfel-v3",
                "output_dir": os.path.join(parent, "adapter-out"),
                "diagnostic_mode": "text",
            },
            handle,
        )

    class Exploding:
        AdapterError = type("AdapterError", (Exception,), {})

        def validate(self, text):
            raise RuntimeError("boom-" + "x" * 5000)

        def adapt(self, text):  # pragma: no cover
            raise AssertionError("unreachable")

    original_loader = service._load_adapter
    service._load_adapter = lambda: Exploding()
    try:
        exit_code = service.handle_request(request_path, response_path)
    finally:
        service._load_adapter = original_loader
    assert exit_code == 1
    with open(response_path, encoding="utf-8") as handle:
        response = json.load(handle)
    assert response["ok"] is False
    assert len(response["diagnostics"]) == 1
    diagnostic = response["diagnostics"][0]
    assert diagnostic["code"] == "MBPF212"
    assert diagnostic["stage"] == "adapter.transform"
    assert "failed internally" in diagnostic["explanation"]
    assert len(diagnostic["explanation"]) <= 2100
    assert "report this adapter failure" in diagnostic["remedy"]


def test_service_transform_matches_sibling_exactly(monkeypatch):
    sibling = load_module("mojo_ir_adapter_check", SIBLING)
    ir_text = (
        'source_filename = "fixture"\n'
        + sibling.HOST_DATALAYOUT + "\n"
        + sibling.HOST_TRIPLE + "\n"
        + sibling.ENTRY_DEFINE + "\n"
        + "  %x = load i64, ptr %0, align 8\n"
        + '  %r = call ptr asm "", "=r,0"(i64 %x)\n'
        + "  ret i32 2\n"
        + "}\n"
        + sibling.HOST_ATTRS + "\n"
    )
    sibling.validate(ir_text)
    expected = sibling.adapt(ir_text)
    parent = tempfile.mkdtemp(prefix="service-fidelity-")
    # The in-lane verifier accepts (stub exit 0): this test pins
    # service/sibling fidelity, not the verifier mapping, and the
    # guarded lane forbids real LLVM tools.
    monkeypatch.setenv("MOJOBPF_OPT", write_opt_stub(parent))
    request = valid_service_request(parent, ir_text=ir_text)
    code, response = run_service(request, parent)
    assert code == 0, response
    assert response["ok"] is True
    assert response["diagnostics"] == []
    adapted_path = response["outputs"]["adapted_ir"]
    with open(adapted_path, encoding="utf-8") as handle:
        assert handle.read() == expected


def write_opt_stub(parent, exit_code=0, stderr_text="", name="opt-stub"):
    """Write an owned stub verifier; return its path.

    The guarded unit lane forbids real LLVM tools, so service
    tests point MOJOBPF_OPT at this stub. It records its argv
    (minus argv[0]) to MOJOBPF_OPT_ARGV_LOG when set, prints the
    canned stderr, and exits with the canned code.
    """
    path = os.path.join(parent, name)
    body = (
        "#!%s\n" % os.path.realpath(sys.executable)
        + "import json\n"
        + "import os\n"
        + "import sys\n"
        + "log = os.environ.get('MOJOBPF_OPT_ARGV_LOG')\n"
        + "if log:\n"
        + "    open(log, 'w', encoding='utf-8').write(\n"
        + "        json.dumps(sys.argv[1:]))\n"
        + "sys.stderr.write(%r)\n" % stderr_text
        + "sys.exit(%d)\n" % exit_code
    )
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
    os.chmod(path, 0o755)
    return path


def _verify_fixture_ir(extra=""):
    sibling = load_module("mojo_ir_adapter_verify", SIBLING)
    ir_text = (
        'source_filename = "fixture"\n'
        + sibling.HOST_DATALAYOUT + "\n"
        + sibling.HOST_TRIPLE + "\n"
        + sibling.ENTRY_DEFINE + "\n"
        + "  %x = load i64, ptr %0, align 8\n"
        + '  %r = call ptr asm "", "=r,0"(i64 %x)\n'
        + "  ret i32 2\n"
    )
    if extra:
        ir_text += extra
    return ir_text + "}\n" + sibling.HOST_ATTRS + "\n"


def test_service_verify_accepts_valid_ir_with_stub_opt(
    monkeypatch, tmp_path
):
    parent = str(tmp_path)
    stub = write_opt_stub(parent)
    argv_log = os.path.join(parent, "argv.json")
    monkeypatch.setenv("MOJOBPF_OPT", stub)
    monkeypatch.setenv("MOJOBPF_OPT_ARGV_LOG", argv_log)
    request = valid_service_request(
        parent, ir_text=_verify_fixture_ir()
    )
    code, response = run_service(request, parent)
    assert code == 0, response
    assert response["ok"] is True
    with open(argv_log, encoding="utf-8") as handle:
        observed = json.load(handle)
    assert observed == [
        "-passes=verify",
        "-disable-output",
        request["input_ir"],
    ], observed


def test_service_verify_rejects_malformed_ir(monkeypatch, tmp_path):
    parent = str(tmp_path)
    marker = "use of undefined value '%nosuch'"
    stub = write_opt_stub(
        parent, exit_code=1, stderr_text="opt: input.ll:9: error: " + marker + "\n"
    )
    monkeypatch.setenv("MOJOBPF_OPT", stub)
    malformed = _verify_fixture_ir(extra="  br label %nosuch\n")
    sibling = load_module("mojo_ir_adapter_verify_probe", SIBLING)
    assert sibling.validate(malformed) == "classifier"
    request = valid_service_request(parent, ir_text=malformed)
    code, response = run_service(request, parent)
    assert code == 1, response
    assert response["ok"] is False
    assert len(response["diagnostics"]) == 1
    diagnostic = response["diagnostics"][0]
    assert diagnostic["code"] == "MBPF106"
    assert diagnostic["stage"] == "adapter.verify"
    assert diagnostic["severity"] == "error"
    assert marker in diagnostic["explanation"]
    assert diagnostic["location"] == request["input_ir"]
    assert diagnostic["remedy"]
    assert response["outputs"] == {}
    assert not os.path.exists(
        os.path.join(parent, "adapter-out", "adapted.ll")
    )


def test_service_verify_missing_tool_is_loud(monkeypatch, tmp_path):
    parent = str(tmp_path)
    empty = os.path.join(parent, "empty-path")
    os.mkdir(empty)
    monkeypatch.setenv("PATH", empty)
    monkeypatch.delenv("MOJOBPF_OPT", raising=False)
    monkeypatch.delenv("MOJOBPF_LLVM_CONFIG", raising=False)
    request = valid_service_request(
        parent, ir_text=_verify_fixture_ir()
    )
    code, response = run_service(request, parent)
    assert code == 1, response
    assert response["ok"] is False
    assert len(response["diagnostics"]) == 1
    diagnostic = response["diagnostics"][0]
    assert diagnostic["code"] == "MBPF103"
    assert "opt" in diagnostic["explanation"]
    assert diagnostic["location"] == "tool:opt"
    assert diagnostic["remedy"]


def test_producer_contract_matches_adapter_and_frontend():
    sibling = load_module("mojo_ir_adapter_contract_check", SIBLING)
    contract = toolchain_module.PRODUCER_CONTRACT
    assert contract["datalayout"] == sibling.HOST_DATALAYOUT
    assert contract["triple"] == sibling.HOST_TRIPLE
    assert contract["attrs"] == sibling.HOST_ATTRS
    assert tuple(contract["target_flags"]) == tuple(
        build_module.FRONTEND_TARGET_FLAGS
    )


def write_ir_mojo_local(bindir, body):
    """Mojo stub emitting fixed IR to -o (local copy: cross-test
    imports are collection-order fragile, so each suite owns its)."""
    script = (
        "#!" + sys.executable + "\n"
        "import sys\n"
        "if sys.argv[1:] == ['--version']:\n"
        "    print('Mojo 9.9.9 (fixture)')\n"
        "    sys.exit(0)\n"
        "out = sys.argv[sys.argv.index('-o') + 1]\n"
        "with open(out, 'w', encoding='utf-8') as handle:\n"
        "    handle.write(" + repr(body) + ")\n"
    )
    path = os.path.join(bindir, "mojo")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(script)
    os.chmod(path, 0o755)


def test_drifted_frontend_dialect_fails_build_as_environment():
    parent = tempfile.mkdtemp(prefix="dialect-drift-build-")
    bindir = write_tool_bindir(parent)
    sibling = load_module("mojo_ir_adapter_drift", SIBLING)
    drift = "\n".join(
        [
            'target datalayout = "e-m:e"',
            sibling.HOST_TRIPLE,
            "define dso_local i32 @xdp_entry(ptr noundef %0) #0 {",
            "  ret i32 2",
            "}",
            sibling.HOST_ATTRS,
        ]
    ) + "\n"
    write_ir_mojo_local(bindir, drift)
    lock = write_lockfile(parent, bindir)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    manifest_path, out_dir = write_project(parent)
    request = BuildRequest(
        manifest_path=manifest_path,
        out_dir=out_dir,
        adapter_path=adapter,
        search_paths=(bindir,),
        lockfile_path=lock,
    )
    result = build_project(request)
    assert result.success is False
    assert "MBPF102" in [item.code for item in result.diagnostics]
    assert cli_module._build_exit_code(result) == 3
    assert "build.frontend" not in [
        command.stage for command in result.commands
    ], "drifted frontend must fail the probe, not compile"


def _sha256_file_local(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def _adapter_ran_local(result):
    return any(
        command.stage == build_module.STAGE_BUILD_ADAPTER
        and command.status != build_module.STATUS_SPAWN_FAILED
        for command in result.commands
    )


def test_unpinned_default_adapter_marks_result_with_warning():
    parent = tempfile.mkdtemp(prefix="unpinned-warn-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    lock = write_lockfile(parent, bindir)
    request = BuildRequest(
        manifest_path=manifest_path,
        out_dir=out_dir,
        adapter_path=build_module.default_adapter_path(),
        search_paths=(bindir,),
        lockfile_path=lock,
    )
    result = build_project(request)
    assert _adapter_ran_local(result), (
        "the packaged adapter never ran; the warning test proves nothing"
    )
    assert result.diagnostics, "no diagnostics carried"
    assert result.diagnostics[0].code == "MBPF302", (
        "the fixture IR must reach the same audit rejection in both "
        "trust arms, so only the trust marker differs"
    )
    last = result.diagnostics[-1]
    assert (last.code, last.stage, last.severity) == (
        "MBPF218", build_module.STAGE_BUILD_SETUP, "warning",
    ), [(item.code, item.stage, item.severity)
        for item in result.diagnostics]


def test_pinned_default_adapter_carries_no_unpinned_warning():
    parent = tempfile.mkdtemp(prefix="pinned-silent-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    lock = write_lockfile(parent, bindir)
    with open(lock, encoding="utf-8") as handle:
        document = json.load(handle)
    default_service = build_module.default_adapter_path()
    service_dir = os.path.dirname(default_service)
    document["adapter"] = {
        "service_sha256": _sha256_file_local(default_service),
        "siblings": {
            name: _sha256_file_local(os.path.join(service_dir, name))
            for name in build_module.ADAPTER_SIBLING_FILES
        },
    }
    with open(lock, "w", encoding="utf-8") as handle:
        json.dump(document, handle)
    request = BuildRequest(
        manifest_path=manifest_path,
        out_dir=out_dir,
        adapter_path=default_service,
        search_paths=(bindir,),
        lockfile_path=lock,
    )
    result = build_project(request)
    assert _adapter_ran_local(result), (
        "the packaged adapter never ran; the silence test proves nothing"
    )
    assert result.diagnostics[0].code == "MBPF302", (
        "the pinned arm must execute identically to the unpinned arm"
    )
    assert "MBPF218" not in [
        item.code for item in result.diagnostics
    ], [(item.code, item.stage) for item in result.diagnostics]


def _warning_probe_result_local(status):
    # The no-lockfile path never reaches the adapter under fixture
    # tools (discovery refuses them), so the helper is probed
    # directly with a result shaped exactly like a pipeline one.
    return BuildResult(
        schema_version=build_module.BUILD_SCHEMA_VERSION,
        success=False,
        diagnostics=(),
        artifacts=(),
        provenance=None,
        commands=(
            build_module.CommandRecord(
                argv=("python3", SERVICE),
                stage=build_module.STAGE_BUILD_ADAPTER,
                status=status,
                exit_code=None,
                duration_s=0.1,
                log_excerpt="",
            ),
        ),
    )


def test_unpinned_warning_without_lockfile_names_the_gap():
    result = _warning_probe_result_local(build_module.STATUS_OK)
    marked = build_module._with_unpinned_warning(
        result, build_module.ADAPTER_TRUST_DEFAULT_UNPINNED, None
    )
    assert len(marked.diagnostics) == 1
    warning = marked.diagnostics[0]
    assert (warning.code, warning.stage, warning.severity) == (
        "MBPF218", build_module.STAGE_BUILD_SETUP, "warning",
    )
    assert "no lockfile was provided" in warning.explanation
    assert warning.location is None


def test_unpinned_warning_stays_silent_when_adapter_never_spawned():
    result = _warning_probe_result_local(
        build_module.STATUS_SPAWN_FAILED
    )
    assert build_module._with_unpinned_warning(
        result, build_module.ADAPTER_TRUST_DEFAULT_UNPINNED, "/tmp/x.json"
    ) is result


def test_adapter_and_driver_contracts_agree():
    service = load_module("adapter_service_check", SERVICE)
    assert service.ADAPTER_SCHEMA_VERSION == ADAPTER_REQUEST_VERSION == 1
    assert tuple(service.SUPPORTED_PROFILE_IDS) == tuple(
        SUPPORTED_PROFILE_IDS
    )
    assert tuple(service.SUPPORTED_DIAGNOSTIC_MODES) == ("text",)


def run_cli(argv, path=None):
    out, err = io.StringIO(), io.StringIO()
    context = (
        isolated_path(path) if path is not None
        else contextlib.nullcontext()
    )
    with context:
        with contextlib.redirect_stdout(out):
            with contextlib.redirect_stderr(err):
                try:
                    code = cli_module.main(argv)
                except SystemExit as exc:
                    code = exc.code
    return code, out.getvalue(), err.getvalue()


def test_cli_build_exits():
    parent = tempfile.mkdtemp(prefix="cli-build-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(parent, bindir)
    base = [
        "build", "--manifest", manifest_path, "--out-dir", out_dir,
        "--adapter", adapter, "--lockfile", lockfile,
    ]
    code, out, _ = run_cli(base, path=bindir)
    assert code == 0, out
    assert "built " in out
    assert "fixture_obj.bpf.o (" in out.strip().splitlines()[0]
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write("schema_version = [unclosed\n")
    code, _, err = run_cli(base, path=bindir)
    assert code == 2
    assert "MBPF209" in err
    manifest_path, out_dir = write_project(parent, dirname="proj2")
    base = [
        "build", "--manifest", manifest_path, "--out-dir", out_dir,
        "--adapter", adapter, "--lockfile", lockfile,
    ]
    empty = tempfile.mkdtemp(prefix="empty-path-")
    code, _, err = run_cli(base, path=empty)
    assert code == 3
    assert "MBPF103" in err
    with fixture_env(MOJOBPF_FIXTURE_MOJO="crash"):
        code, _, err = run_cli(base, path=bindir)
    assert code == 4
    assert "MBPF106" in err
    code, _, _ = run_cli(["build", "--manifest", manifest_path])
    assert code == 2
    # Without a lockfile the locked build fails closed (exit 3).
    code, _, err = run_cli(base[:-2], path=bindir)
    assert code == 3
    assert "MBPF104" in err


def failed_result(code):
    return BuildResult(
        schema_version=1,
        success=False,
        diagnostics=(
            Diagnostic(
                code=code,
                stage="build.adapter",
                severity=SEVERITY_ERROR,
                explanation="fixture failure",
                location=None,
                remedy=None,
            ),
        ),
        artifacts=(),
        provenance=None,
        commands=(),
        work_dir=None,
    )


def test_cli_build_exit_mapping_adapter_contract():
    manifest_codes = ["MBPF101"] + [
        "MBPF%03d" % number for number in range(201, 212)
    ] + ["MBPF%03d" % number for number in range(213, 217)]
    assert len(manifest_codes) == 16
    for code in manifest_codes:
        assert cli_module._build_exit_code(
            failed_result(code)) == 2, code
    for code in ("MBPF212", "MBPF106", "MBPF301"):
        assert cli_module._build_exit_code(
            failed_result(code)) == 4, code
    for code in ("MBPF102", "MBPF103", "MBPF104"):
        assert cli_module._build_exit_code(
            failed_result(code)) == 3, code
    # End to end: a malformed adapter response through the CLI.
    parent = tempfile.mkdtemp(prefix="cli-212-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = write_adapter(parent, "this is not json{", 0)
    lockfile = write_lockfile(parent, bindir)
    code, _, err = run_cli(
        [
            "build", "--manifest", manifest_path,
            "--out-dir", out_dir, "--adapter", adapter,
            "--lockfile", lockfile,
        ],
        path=bindir,
    )
    assert code == 4, err
    assert "MBPF212" in err


def test_cli_build_interrupt_reports_recovery():
    real_build = cli_module.build_project

    def raising(request):
        raise KeyboardInterrupt("fixture interrupt")

    cli_module.build_project = raising
    try:
        code, _, err = run_cli(
            [
                "build", "--manifest", "m", "--out-dir", "o",
                "--adapter", "a",
            ]
        )
    finally:
        cli_module.build_project = real_build
    assert code == 130
    assert "partial outputs removed" in err

    def raising_complete(request):
        exc = KeyboardInterrupt("fixture interrupt")
        setattr(
            exc,
            evidence_module.RECOVERY_ATTRIBUTE,
            evidence_module.PublicationRecovery(
                recovered=("out/a.bpf.o (uncertain rename)",),
                failures=(),
            ),
        )
        raise exc

    cli_module.build_project = raising_complete
    try:
        code, _, err = run_cli(
            [
                "build", "--manifest", "m", "--out-dir", "o",
                "--adapter", "a",
            ]
        )
    finally:
        cli_module.build_project = real_build
    assert code == 130
    assert "partial outputs removed" in err

    def raising_incomplete(request):
        exc = KeyboardInterrupt("fixture interrupt")
        setattr(
            exc,
            evidence_module.RECOVERY_ATTRIBUTE,
            evidence_module.PublicationRecovery(
                recovered=(),
                failures=(
                    "out/a.bpf.o (recovery backup retained at "
                    "out/.a.backup: boom)",
                ),
            ),
        )
        raise exc

    cli_module.build_project = raising_incomplete
    try:
        code, _, err = run_cli(
            [
                "build", "--manifest", "m", "--out-dir", "o",
                "--adapter", "a",
            ]
        )
    finally:
        cli_module.build_project = real_build
    assert code == 130
    assert "rollback incomplete" in err
    assert "not restored" in err
    assert "partial outputs removed" not in err


def test_cli_check_reports_manifest_and_toolchain():
    parent = tempfile.mkdtemp(prefix="cli-check-")
    manifest_path, _ = write_project(parent)
    bindir = write_tool_bindir(
        parent,
        extra=(
            ("bpftool", "bpftool v0.0-fixture"),
            ("python3", "Python 9.9.9-fixture"),
        ),
    )
    code, out, _ = run_cli(
        ["check", "--manifest", manifest_path], path=bindir
    )
    assert code == 0, out
    assert "manifest OK" in out
    assert "linux-bpfel-v3" in out
    code, out, _ = run_cli(
        ["check", "--manifest", manifest_path, "--json"], path=bindir
    )
    assert code == 0
    document = json.loads(out)
    assert document["manifest"]["manifest_path"] == manifest_path
    assert document["manifest"]["target"]["profile"] == "linux-bpfel-v3"
    assert "toolchain" in document
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write("schema_version = [unclosed\n")
    code, _, err = run_cli(["check", "--manifest", manifest_path])
    assert code == 2
    assert "MBPF209" in err
    manifest_path, _ = write_project(parent, dirname="proj2")
    empty = tempfile.mkdtemp(prefix="empty-path-")
    code, _, _ = run_cli(
        ["check", "--manifest", manifest_path], path=empty
    )
    assert code == 3


def test_cli_check_validates_lockfile_match():
    parent = tempfile.mkdtemp(prefix="cli-checklock-")
    manifest_path, _ = write_project(parent)
    bindir = write_tool_bindir(
        parent,
        extra=(
            ("bpftool", "bpftool v0.0-fixture"),
            ("python3", "Python 9.9.9-fixture"),
        ),
    )
    lockfile = write_lockfile(
        parent, bindir, tools_pinned=("mojo", "llc", "bpftool", "python")
    )
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    code, out, _ = run_cli(
        ["check", "--manifest", manifest_path,
         "--lockfile", lockfile, "--adapter", adapter],
        path=bindir,
    )
    assert code == 0, out
    bad_lock = write_lockfile(
        parent, bindir, name="bad.lock.json",
        pins={"llc": ("llc wrong", "0" * 64)},
        tools_pinned=("mojo", "llc", "bpftool", "python"),
    )
    code, _, err = run_cli(
        ["check", "--manifest", manifest_path,
         "--lockfile", bad_lock],
        path=bindir,
    )
    assert code == 3
    assert "MBPF102" in err


def test_cli_doctor_always_reports():
    parent = tempfile.mkdtemp(prefix="cli-doctor-")
    empty = tempfile.mkdtemp(prefix="empty-path-", dir=parent)
    code, out, _ = run_cli(["doctor"], path=empty)
    assert code == 0
    assert "tool mojo: missing" in out
    assert "linux-bpfel-v3" in out
    code, out, _ = run_cli(["doctor", "--json"], path=empty)
    assert code == 0
    document = json.loads(out)
    assert "toolchain" in document
    assert document["kernel_test_capable"] in (True, False)


def test_cli_doctor_reports_lockfile_match():
    parent = tempfile.mkdtemp(prefix="cli-doctorlock-")
    bindir = write_tool_bindir(
        parent,
        extra=(
            ("bpftool", "bpftool v0.0-fixture"),
            ("python3", "Python 9.9.9-fixture"),
        ),
    )
    lockfile = write_lockfile(
        parent, bindir, tools_pinned=("mojo", "llc", "bpftool", "python")
    )
    code, out, _ = run_cli(
        ["doctor", "--lockfile", lockfile], path=bindir
    )
    assert code == 0
    assert "lockfile %s: matched" % lockfile in out
    code, out, _ = run_cli(
        ["doctor", "--lockfile", os.path.join(parent, "missing.json")],
        path=bindir,
    )
    assert code == 0
    assert "unreadable" in out


def test_cli_refuses_unsupported_platform():
    before = sys.platform
    sys.platform = "darwin"
    try:
        code, _, err = run_cli(["doctor"])
    finally:
        sys.platform = before
    assert code == cli_module.EXIT_ENVIRONMENT
    assert "unsupported platform" in err
    assert "Linux is required" in err


def test_cli_help_bypasses_platform_gate():
    before = sys.platform
    sys.platform = "win32"
    try:
        code, out, _ = run_cli(["--help"])
    finally:
        sys.platform = before
    assert code == 0
    assert "mojobpf" in out


def test_cli_build_uses_packaged_adapter_default():
    parent = tempfile.mkdtemp(prefix="cli-default-adapter-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    lockfile = write_lockfile(parent, bindir)
    packaged = build_module.default_adapter_path()
    assert os.path.isfile(packaged)
    assert os.path.realpath(packaged).startswith(
        os.path.realpath(
            os.path.join(
                os.path.dirname(build_module.__file__), "resources"
            )
        )
    )
    code, _, err = run_cli(
        [
            "build",
            "--manifest", manifest_path,
            "--out-dir", out_dir,
            "--lockfile", lockfile,
        ],
        path=bindir,
    )
    # Exit 4 (not argparse's 2) proves --adapter defaulted and the
    # pipeline ran; the packaged real service rejects the fixture
    # frontend's trivial IR at the adapter stage.
    assert code == cli_module.EXIT_COMPILE
    assert "adapter" in err


def _fixture_built_object(parent):
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(parent, bindir)
    result = build_project(
        BuildRequest(
            manifest_path=manifest_path,
            out_dir=out_dir,
            adapter_path=adapter,
            search_paths=(bindir,),
            timeout_s=60,
            lockfile_path=lockfile,
        )
    )
    assert result.success is True, result.diagnostics
    assert len(result.artifacts) == 2
    return result


def test_build_stamps_tool_and_sdk_versions():
    parent = tempfile.mkdtemp(prefix="build-stamps-")
    result = _fixture_built_object(parent)
    assert result.provenance.tool_version == mojobpf.__version__
    assert result.provenance.sdk_version == SDK_VERSION
    sidecar = os.path.join(
        os.path.dirname(result.artifacts[0].path),
        "fixture_obj.evidence.json",
    )
    with open(sidecar, encoding="utf-8") as handle:
        doc = json.load(handle)
    assert doc["tool_version"] == mojobpf.__version__
    assert doc["sdk_version"] == SDK_VERSION
    assert doc["inputs"]["tool_version"] == mojobpf.__version__
    assert doc["inputs"]["sdk_version"] == SDK_VERSION


def test_cli_inspect_reports_and_verifies():
    parent = tempfile.mkdtemp(prefix="cli-inspect-")
    result = _fixture_built_object(parent)
    obj = result.artifacts[0].path
    code, out, _ = run_cli(["inspect", "--object", obj])
    assert code == 0
    assert "linux-bpfel-v3" in out
    assert "ok" in out
    code, out, _ = run_cli(
        [
            "inspect", "--object", obj,
            "--source-license", "Apache-2.0 WITH LLVM-exception",
            "--kernel-license", "Apache-2.0 WITH LLVM-exception",
        ]
    )
    assert code == 0
    assert "ok" in out
    code, out, _ = run_cli(["inspect", "--object", obj, "--json"])
    assert code == 0
    assert json.loads(out)["ok"] is True


def test_cli_inspect_rejects_bad_inputs():
    parent = tempfile.mkdtemp(prefix="cli-inspect-neg-")
    result = _fixture_built_object(parent)
    obj = result.artifacts[0].path
    code, _, err = run_cli(
        ["inspect", "--object", obj, "--profile", "nope-bad"]
    )
    assert code == cli_module.EXIT_USAGE
    assert "MBPF101" in err
    code, _, err = run_cli(
        ["inspect", "--object", os.path.join(parent, "missing.o")]
    )
    assert code == cli_module.EXIT_COMPILE
    assert "MBPF401" in err
    code, _, err = run_cli(
        [
            "inspect", "--object", obj,
            "--source-license", "Apache-2.0 WITH LLVM-exception",
        ]
    )
    assert code == cli_module.EXIT_USAGE
    assert "must be given together" in err
    code, out, _ = run_cli(
        [
            "inspect", "--object", obj,
            "--source-license", "MIT",
            "--kernel-license", "MIT",
        ]
    )
    assert code == cli_module.EXIT_COMPILE
    assert "MBPF704" in out


def test_interrupted_build_removes_workdir():
    parent = tempfile.mkdtemp(prefix="build-interrupt-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(parent, bindir)
    work_parent = os.path.join(parent, "work")
    os.mkdir(work_parent)
    driver = os.path.join(parent, "driver.py")
    with open(driver, "w", encoding="utf-8") as handle:
        handle.write(
            "import sys\n"
            "sys.path.insert(0, %r)\n"
            "from mojobpf.build import BuildRequest, build_project\n"
            "result = build_project(BuildRequest(\n"
            "    manifest_path=%r, out_dir=%r, adapter_path=%r,\n"
            "    search_paths=(%r,), work_parent=%r, "
            "lockfile_path=%r))\n"
            "print('UNREACHABLE: %%s' %% result.success)\n"
            % (
                os.path.join(REPO_ROOT, "src"),
                manifest_path, out_dir, adapter, bindir, work_parent,
                lockfile,
            )
        )
    env = dict(os.environ, MOJOBPF_FIXTURE_MOJO="hang")
    proc = subprocess.Popen(
        [sys.executable, driver],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        if os.listdir(work_parent):
            break
        time.sleep(0.05)
    assert os.listdir(work_parent), "build never started"
    assert proc.poll() is None, "driver exited before interrupt"
    proc.send_signal(signal.SIGINT)
    try:
        _, stderr = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise AssertionError("driver did not exit after SIGINT")
    assert proc.returncode != 0
    assert "KeyboardInterrupt" in stderr
    assert os.listdir(work_parent) == []
    if os.path.exists(out_dir):
        assert [
            name for name in os.listdir(out_dir)
            if name.endswith(".bpf.o")
        ] == []


def assert_fixture_forks(mojo_path, marker):
    """Prove the forking fixture really leaves a marked grandchild."""
    env = dict(os.environ, MOJOBPF_ORPHAN_MARKER=marker)
    proc = subprocess.Popen(
        [mojo_path, "build", "--emit", "llvm"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if scan_marker(marker):
                break
            time.sleep(0.05)
        assert scan_marker(marker), "fixture never forked grandchild"
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        kill_marker(marker)
    assert await_no_marker(marker) == []


def test_timeout_kills_forked_grandchildren():
    parent = tempfile.mkdtemp(prefix="build-orphan-timeout-")
    marker = orphan_marker()
    manifest_path, out_dir = write_project(parent)
    bindir = write_forking_bindir(parent)
    assert_fixture_forks(os.path.join(bindir, "mojo"), marker)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(parent, bindir)
    try:
        with fixture_env(MOJOBPF_ORPHAN_MARKER=marker):
            result = build_project(
                BuildRequest(
                    manifest_path=manifest_path,
                    out_dir=out_dir,
                    adapter_path=adapter,
                    search_paths=(bindir,),
                    timeout_s=2,
                    lockfile_path=lockfile,
                )
            )
        assert result.success is False
        assert result.commands[0].status == "timeout"
        survivors = await_no_marker(marker)
        assert survivors == [], survivors
    finally:
        kill_marker(marker)


def test_interrupted_publish_restores_overwritten_outputs():
    parent = tempfile.mkdtemp(prefix="build-pubint-")
    manifest_path, out_dir = write_project(parent)
    os.makedirs(out_dir)
    obj_pred = os.path.join(out_dir, "fixture_obj.bpf.o")
    ev_pred = os.path.join(out_dir, "fixture_obj.evidence.json")
    with open(obj_pred, "wb") as handle:
        handle.write(b"OLD-OBJECT")
    with open(ev_pred, "wb") as handle:
        handle.write(b"OLD-EVIDENCE")
    real_link = os.link
    calls = []

    def interrupting(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
        # Real install followed immediately by interruption: the
        # first publication install lands, then the build dies.
        # Directory-fd keywords are forwarded so descriptor-pinned
        # publication installs keep working under this shim.
        calls.append((src, dst))
        real_link(
            src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd
        )
        if len(calls) == 1:
            raise KeyboardInterrupt("fixture interrupt")
        return None

    os.link = interrupting
    caught = None
    try:
        build_fixture(manifest_path, out_dir, parent)
    except KeyboardInterrupt as exc:
        caught = exc
    else:
        raise AssertionError("expected KeyboardInterrupt")
    finally:
        os.link = real_link
    assert caught is not None
    assert calls, "publish boundary never exercised"
    with open(obj_pred, "rb") as handle:
        assert handle.read() == b"OLD-OBJECT"
    with open(ev_pred, "rb") as handle:
        assert handle.read() == b"OLD-EVIDENCE"
    leftovers = [
        name for name in os.listdir(out_dir) if name.startswith(".")
    ]
    assert leftovers == [], leftovers
    recovery = evidence_module.publication_recovery(caught)
    assert recovery is not None
    assert recovery.complete is True


def test_interrupt_kills_forked_grandchildren():
    parent = tempfile.mkdtemp(prefix="build-orphan-interrupt-")
    marker = orphan_marker()
    manifest_path, out_dir = write_project(parent)
    bindir = write_forking_bindir(parent)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(parent, bindir)
    work_parent = os.path.join(parent, "work")
    os.mkdir(work_parent)
    driver = os.path.join(parent, "driver.py")
    with open(driver, "w", encoding="utf-8") as handle:
        handle.write(
            "import sys\n"
            "sys.path.insert(0, %r)\n"
            "from mojobpf.build import BuildRequest, build_project\n"
            "result = build_project(BuildRequest(\n"
            "    manifest_path=%r, out_dir=%r, adapter_path=%r,\n"
            "    search_paths=(%r,), work_parent=%r, "
            "lockfile_path=%r))\n"
            "print('UNREACHABLE: %%s' %% result.success)\n"
            % (
                os.path.join(REPO_ROOT, "src"),
                manifest_path, out_dir, adapter, bindir, work_parent,
                lockfile,
            )
        )
    env = dict(os.environ, MOJOBPF_ORPHAN_MARKER=marker)
    proc = subprocess.Popen(
        [sys.executable, driver],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            if os.listdir(work_parent) and scan_marker(marker):
                break
            time.sleep(0.05)
        assert proc.poll() is None, "driver exited before interrupt"
        assert scan_marker(marker), "fixture never forked grandchild"
        proc.send_signal(signal.SIGINT)
        try:
            _, stderr = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise AssertionError("driver did not exit after SIGINT")
        assert proc.returncode != 0
        assert "KeyboardInterrupt" in stderr
        survivors = await_no_marker(marker)
        assert survivors == [], survivors
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()
        kill_marker(marker)


MOJO_SNAPSHOT_FIXTURE = """\
#!{python}
import hashlib
import os
import sys


def main(argv):
    if argv[1:] == ["--version"]:
        print("Mojo 9.9.9 (fixture)")
        return 0
    out = argv[argv.index("-o") + 1]
    src = argv[-1]
    if os.path.basename(src) == "dialect_probe.mojo":
        # Dialect-canary probe, not a program compile: emit plainly
        # with no plant/flap/tamper side effects (matches
        # CANARY_SOURCE_FILENAME).
        with open(out, "w", encoding="utf-8") as handle:
            handle.write("; fixture canary IR (no side effects)\\n")
        return 0
    plant = os.environ.get("MOJOBPF_SNAPSHOT_PLANT")
    if plant:
        with open(plant, "w", encoding="utf-8") as handle:
            handle.write(
                "# SPDX-License-Identifier: Apache-2.0 "
                "WITH LLVM-exception\\n# planted mid-build\\n"
            )
    flap = os.environ.get("MOJOBPF_SNAPSHOT_FLAP")
    clean_backup = None
    if flap:
        with open(flap, "rb") as handle:
            clean_backup = handle.read()
        with open(flap, "wb") as handle:
            handle.write(clean_backup + b"# evil\\n")
    try:
        with open(src, "rb") as handle:
            content = handle.read()
    finally:
        if flap:
            with open(flap, "wb") as handle:
                handle.write(clean_backup)
    digest = hashlib.sha256(content).hexdigest()
    pkgsub = os.environ.get("MOJOBPF_SNAPSHOT_PKGSUBDIR")
    pkg_members = None
    if pkgsub:
        pkgdir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(src))),
            pkgsub,
        )
        pkg_members = ",".join(sorted(
            name for name in os.listdir(pkgdir)
            if name.endswith(".mojo")
        ))
    if os.environ.get("MOJOBPF_SNAPSHOT_TAMPER") == "1":
        os.chmod(src, 0o644)
        with open(src, "ab") as handle:
            handle.write(b"# tampered\\n")
    with open(out, "w", encoding="utf-8") as handle:
        handle.write("; fixture raw IR for %s\\n" % src)
        handle.write("; src-sha256:%s\\n" % digest)
        handle.write(
            "; modular-home:%s\\n"
            % os.environ.get("MODULAR_HOME", "")
        )
        handle.write(
            "; env-seen:%s\\n"
            % ",".join(
                "%s=%s" % (name, os.environ[name])
                for name in sorted(os.environ)
                if name.startswith(("MOJO_", "MODULAR_", "LLVM_"))
            )
        )
        if pkg_members is not None:
            handle.write("; pkg-members:%s\\n" % pkg_members)
    fail = os.environ.get("MOJOBPF_SNAPSHOT_FAIL")
    if fail:
        sys.stderr.write("%s:1:1: error: %s\\n" % (src, fail))
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
"""


def write_snapshot_bindir(parent):
    """Create bindir with the snapshot-probing mojo + stock llc."""
    bindir = tempfile.mkdtemp(prefix="fixture-bin-", dir=parent)
    write_executable(
        os.path.join(bindir, "mojo"), MOJO_SNAPSHOT_FIXTURE
    )
    write_executable(os.path.join(bindir, "llc"), LLC_FIXTURE)
    return bindir


def build_snapshot_fixture(manifest_path, out_dir, parent, adapter=None,
                           **kwargs):
    bindir = write_snapshot_bindir(parent)
    if adapter is None:
        adapter = os.path.join(parent, "adapter-ok.py")
        write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(parent, bindir)
    request = BuildRequest(
        manifest_path=manifest_path,
        out_dir=out_dir,
        adapter_path=adapter,
        search_paths=(bindir,),
        lockfile_path=lockfile,
        **kwargs
    )
    return build_project(request)


def write_helper(root, relpath, body, header=SOURCE_HEADER):
    path = os.path.join(root, relpath)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(header)
        handle.write(body)
    return path


def _snapshot_modules(text):
    return inputs_module.parse_mojo_imports_text(text, "case.mojo")


def test_snapshot_grammar_comma_and_aliased_imports():
    assert _snapshot_modules("import helper_a, helper_b") == (
        "helper_a", "helper_b",
    )
    assert _snapshot_modules("import helper_a, helper_b,") == (
        "helper_a", "helper_b",
    )
    assert _snapshot_modules("import helper as h") == ("helper",)
    assert _snapshot_modules(
        "import a.b, c.d as e, f"
    ) == ("a.b", "c.d", "f")
    assert _snapshot_modules(
        "from helper import thing as t"
    ) == ("helper",)
    assert _snapshot_modules(
        "from a import b, c as d, e,"
    ) == ("a",)


def test_snapshot_grammar_from_forms():
    assert _snapshot_modules("from a import b") == ("a",)
    assert _snapshot_modules("from a import (b)") == ("a",)
    assert _snapshot_modules("from a import (b,)") == ("a",)
    assert _snapshot_modules(
        "from mojobpf.packet import (\n"
        "    XDP_DROP,\n"
        "    XDP_PASS,\n"
        ")\n"
    ) == ("mojobpf.packet",)
    assert _snapshot_modules("import a; import b") == ("a", "b")
    assert _snapshot_modules("if x: import a") == ("a",)
    assert _snapshot_modules("import a, \\\n    b") == ("a", "b")
    assert _snapshot_modules(
        "from a import b\nfrom a import c\n"
    ) == ("a",)


def test_snapshot_grammar_ignores_comments_and_strings():
    assert _snapshot_modules(
        "# from nope import x\n"
        "s = \"from nope import y\"\n"
        "t = 'import nope2'\n"
        "\"\"\"from nope import z\"\"\"\n"
        "import ok\n"
    ) == ("ok",)
    assert _snapshot_modules(
        "'''\nfrom nope import y\n'''\nfrom z import w\n"
    ) == ("z",)
    assert _snapshot_modules(
        "from pkg import nested  # trailing comment\n"
    ) == ("pkg",)
    assert _snapshot_modules(
        "def f(x: Int = 3):\n    return x\n"
        "y = d[1:2]\n"
    ) == ()


def test_snapshot_grammar_escaped_triple_quote_masks_nothing():
    # An escaped triple-quote is string content, not the string's
    # end: the wildcard after the real close must still reject
    # instead of being masked by a phantom string.
    text = (
        'comptime DOC = """hello \\"""\n'
        "still in string\n"
        '"""\n'
        "from std.sys import *\n"
    )
    try:
        found = _snapshot_modules(text)
    except inputs_module.InputError as exc:
        assert exc.diagnostic.code == "MBPF106", text
        assert exc.diagnostic.stage == "build.inputs", text
        assert "wildcard" in exc.diagnostic.explanation, text
    else:
        raise AssertionError("wildcard masked as %r" % (found,))


def test_snapshot_grammar_escaped_quotes_still_mask_strings():
    # Escaped quotes never end a string early: imports inside
    # stay masked while imports after the real close are found.
    assert _snapshot_modules(
        'x = "say \\"hi\\" from nope import x"\nimport ok\n'
    ) == ("ok",)
    assert _snapshot_modules(
        "x = '''it\\'s from nope import y'''\nimport ok\n"
    ) == ("ok",)
    assert _snapshot_modules(
        'd = """a \\""" b\nfrom nope import z\n"""\nimport ok\n'
    ) == ("ok",)
    assert _snapshot_modules(
        "d = '''a \\''' b\nfrom nope import z\n'''\nimport ok\n"
    ) == ("ok",)


def test_snapshot_grammar_rejects_unsupported():
    cases = [
        "from . import x",
        "from .a import b",
        "from a import *",
        "from a import (b) as c",
        "x = __import__('a')",
        "import importlib",
        "from importlib import import_module",
        "from a import",
        "import",
        "import a,, b",
        "import ,",
        "from a import b.c",
        "import .a",
        "from a import (b",
    ]
    for text in cases:
        try:
            found = _snapshot_modules(text)
        except inputs_module.InputError as exc:
            assert exc.diagnostic.code == "MBPF106", text
            assert exc.diagnostic.stage == "build.inputs", text
            assert exc.diagnostic.location == "case.mojo:1", (
                text, exc.diagnostic.location,
            )
        else:
            raise AssertionError(
                "accepted %r as %r" % (text, found)
            )


def test_snapshot_grammar_covers_in_tree_sources():
    # Every committed Mojo source parses under the bounded
    # grammar: the snapshot cannot reject a real build for its
    # import spelling.
    roots = [
        os.path.join(REPO_ROOT, "examples"),
        os.path.join(REPO_ROOT, "tests"),
        os.path.join(REPO_ROOT, "src"),
    ]
    count = 0
    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            for name in sorted(files):
                if not name.endswith(".mojo"):
                    continue
                path = os.path.join(dirpath, name)
                inputs_module.parse_mojo_imports(path)
                count += 1
    assert count > 100, count
    classifier = os.path.join(
        REPO_ROOT, "examples", "packet_classifier", "classifier.mojo"
    )
    assert inputs_module.parse_mojo_imports(classifier) == (
        "mojobpf.packet",
    )


def test_snapshot_discovery_comma_imports():
    parent = tempfile.mkdtemp(prefix="imports-comma-")
    main = os.path.join(parent, "main.mojo")
    for name in ("helper_a", "helper_b"):
        with open(
            os.path.join(parent, name + ".mojo"), "w", encoding="utf-8"
        ) as handle:
            handle.write("# %s\n" % name)
    with open(main, "w", encoding="utf-8") as handle:
        handle.write("import helper_a, helper_b\n")
    found = build_module._discover_imports(
        (main,), parent, os.path.join(parent, "sdk")
    )
    assert sorted(os.path.basename(path) for path in found) == [
        "helper_a.mojo", "helper_b.mojo",
    ]


def test_snapshot_discovery_rejects_unresolved():
    parent = tempfile.mkdtemp(prefix="imports-unresolved-")
    main = os.path.join(parent, "main.mojo")
    with open(main, "w", encoding="utf-8") as handle:
        handle.write("from nosuch_xyz import thing\n")
    try:
        build_module._discover_imports(
            (main,), parent, os.path.join(parent, "sdk")
        )
    except inputs_module.InputError as exc:
        assert exc.diagnostic.code == "MBPF106"
        assert exc.diagnostic.stage == "build.inputs"
        assert "nosuch_xyz" in exc.diagnostic.explanation
    else:
        raise AssertionError("unresolved import was silently skipped")


def test_snapshot_discovery_rejects_dynamic():
    parent = tempfile.mkdtemp(prefix="imports-dynamic-")
    main = os.path.join(parent, "main.mojo")
    with open(main, "w", encoding="utf-8") as handle:
        handle.write("x = __import__('helper')\n")
    try:
        build_module._discover_imports(
            (main,), parent, os.path.join(parent, "sdk")
        )
    except inputs_module.InputError as exc:
        assert exc.diagnostic.code == "MBPF106"
        assert exc.diagnostic.stage == "build.inputs"
    else:
        raise AssertionError("dynamic import was silently skipped")


def test_snapshot_build_seals_comma_imports():
    parent = tempfile.mkdtemp(prefix="build-comma-")
    manifest_path, out_dir = write_project(parent)
    root = os.path.dirname(manifest_path)
    for name in ("helper_a", "helper_b"):
        write_helper(root, name + ".mojo", "# %s module\n" % name)
    with open(
        os.path.join(root, "src", "main.mojo"), "a", encoding="utf-8"
    ) as handle:
        handle.write("import helper_a, helper_b\n")
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is True, result.diagnostics
    with open(
        os.path.join(out_dir, "fixture_obj.evidence.json"),
        encoding="utf-8",
    ) as handle:
        doc = json.load(handle)
    assert sorted(
        item["path"] for item in doc["inputs"]["imports"]
    ) == ["helper_a.mojo", "helper_b.mojo"]


def test_snapshot_build_symlinked_helper_both_names_staged():
    # Realpath deduplication must not drop a module name: with
    # helper_b.mojo symlinked to helper_a.mojo, both lexical
    # names stage so the frontend resolves both admitted
    # modules.
    from mojobpf.manifest import parse_manifest
    parent = tempfile.mkdtemp(prefix="build-symlink-")
    manifest_path, out_dir = write_project(parent)
    root = os.path.dirname(manifest_path)
    target = write_helper(root, "helper_a.mojo", "# shared module\n")
    os.symlink(target, os.path.join(root, "helper_b.mojo"))
    with open(
        os.path.join(root, "src", "main.mojo"), "a", encoding="utf-8"
    ) as handle:
        handle.write("import helper_a, helper_b\n")
    manifest = parse_manifest(manifest_path)
    toolchain = inputs_module.ToolchainInputs()
    sdk = inputs_module.SdkInputs(
        sdk_dir=build_module._sdk_dir(), version="9.9"
    )
    snapshot = inputs_module.capture_build_inputs(
        manifest, toolchain, sdk, work_parent=parent
    )
    try:
        assert sorted(
            item.logical for item in snapshot.imports
        ) == ["helper_a.mojo", "helper_b.mojo"]
        for item in snapshot.imports:
            assert os.path.isfile(item.staged), item
        snapshot.verify()
    finally:
        snapshot.dispose()
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is True, result.diagnostics


def test_snapshot_alias_flap_between_reads_rejected():
    # Two lexical aliases share one file; the shared file gains
    # ``from std.sys import *`` between the alias reads. Every
    # separately staged body is scanned, so capture rejects --
    # the way parsing the second body's bytes directly does.
    from mojobpf.manifest import parse_manifest
    parent = tempfile.mkdtemp(prefix="build-aliasflap-")
    manifest_path, _ = write_project(parent)
    root = os.path.dirname(manifest_path)
    shared = write_helper(root, "shared.mojo", "# shared helper\n")
    os.symlink(shared, os.path.join(root, "helper_a.mojo"))
    os.symlink(shared, os.path.join(root, "helper_b.mojo"))
    with open(
        os.path.join(root, "src", "main.mojo"), "a", encoding="utf-8"
    ) as handle:
        handle.write("import helper_a, helper_b\n")
    manifest = parse_manifest(manifest_path)
    toolchain = inputs_module.ToolchainInputs()
    sdk = inputs_module.SdkInputs(
        sdk_dir=build_module._sdk_dir(), version="9.9"
    )
    real_read_once = inputs_module._read_once
    shared_real = os.path.realpath(shared)
    reads = []

    def flapping_read(path):
        content = real_read_once(path)
        if os.path.realpath(path) == shared_real:
            reads.append(content)
            if len(reads) == 1:
                with open(shared, "ab") as handle:
                    handle.write(b"from std.sys import *\n")
        return content

    inputs_module._read_once = flapping_read
    try:
        try:
            snapshot = inputs_module.capture_build_inputs(
                manifest, toolchain, sdk, work_parent=parent
            )
        except inputs_module.InputError as exc:
            raised = exc
        else:
            snapshot.dispose()
            raised = None
    finally:
        inputs_module._read_once = real_read_once
    assert len(reads) == 2, reads
    try:
        inputs_module.parse_mojo_imports_text(
            reads[1].decode("utf-8"), "helper_b.mojo"
        )
    except inputs_module.InputError as exc:
        assert exc.diagnostic.code == "MBPF106"
    else:
        raise AssertionError("second alias body parsed clean")
    assert raised is not None, "capture accepted unscanned alias bytes"
    assert raised.diagnostic.code == "MBPF106"
    assert raised.diagnostic.stage == "build.inputs"


def test_snapshot_build_aliased_import_sealed():
    parent = tempfile.mkdtemp(prefix="build-alias-")
    manifest_path, out_dir = write_project(parent)
    root = os.path.dirname(manifest_path)
    write_helper(root, "helper.mojo", "from deep import thing\n")
    write_helper(root, "deep.mojo", "# leaf module\n")
    with open(
        os.path.join(root, "src", "main.mojo"), "a", encoding="utf-8"
    ) as handle:
        handle.write("import helper as h\n")
        handle.write("from deep import thing as t\n")
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is True, result.diagnostics
    with open(
        os.path.join(out_dir, "fixture_obj.evidence.json"),
        encoding="utf-8",
    ) as handle:
        doc = json.load(handle)
    assert sorted(
        item["path"] for item in doc["inputs"]["imports"]
    ) == ["deep.mojo", "helper.mojo"]


def test_snapshot_build_package_import_sealed():
    parent = tempfile.mkdtemp(prefix="build-pkg-")
    manifest_path, out_dir = write_project(parent)
    root = os.path.dirname(manifest_path)
    write_helper(root, "pkg/__init__.mojo", "# package init\n")
    write_helper(root, "pkg/child.mojo", "# child module\n")
    write_helper(root, "pkg/other.mojo", "# sibling module\n")
    with open(
        os.path.join(root, "src", "main.mojo"), "a", encoding="utf-8"
    ) as handle:
        handle.write("from pkg import child\n")
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is True, result.diagnostics
    with open(
        os.path.join(out_dir, "fixture_obj.evidence.json"),
        encoding="utf-8",
    ) as handle:
        doc = json.load(handle)
    assert sorted(
        item["path"] for item in doc["inputs"]["imports"]
    ) == [
        "pkg/__init__.mojo", "pkg/child.mojo", "pkg/other.mojo",
    ]


GPL_HEADER = "# SPDX-License-Identifier: GPL-2.0-only\n"


def test_snapshot_build_gpl_import_rejected():
    # An imported GPL helper under the old non-GPL grant pair
    # reaches the license gate as MBPF702. No new grant is
    # invented: the helper names an old GPL identifier and the
    # declaration pair is the untouched qualified Apache pair.
    parent = tempfile.mkdtemp(prefix="build-gplimp-")
    manifest_path, out_dir = write_project(parent)
    root = os.path.dirname(manifest_path)
    write_helper(
        root, "helper.mojo", "# helper module\n", header=GPL_HEADER
    )
    with open(
        os.path.join(root, "src", "main.mojo"), "a", encoding="utf-8"
    ) as handle:
        handle.write("from helper import thing\n")
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF702"]
    assert result.diagnostics[0].stage == "inspect.license"
    assert result.artifacts == ()
    assert result.commands == ()
    assert not os.path.exists(out_dir) or (
        os.listdir(out_dir) == []
    )


def test_snapshot_build_gpl_import_names_origin():
    # The MBPF702 diagnostic for an imported helper names the
    # origin path the user owns, never the staged copy that
    # cleanup removes.
    parent = tempfile.mkdtemp(prefix="build-gplloc-")
    manifest_path, out_dir = write_project(parent)
    root = os.path.dirname(manifest_path)
    helper = write_helper(
        root, "helper.mojo", "# helper module\n", header=GPL_HEADER
    )
    with open(
        os.path.join(root, "src", "main.mojo"), "a", encoding="utf-8"
    ) as handle:
        handle.write("from helper import thing\n")
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF702"]
    diagnostic = result.diagnostics[0]
    assert helper in (diagnostic.location or ""), diagnostic
    assert "mojobpf-inputs-" not in (diagnostic.location or "")
    assert helper in diagnostic.explanation, diagnostic
    assert "mojobpf-inputs-" not in diagnostic.explanation


def test_snapshot_build_changed_import_grant_rejected():
    parent = tempfile.mkdtemp(prefix="build-grantchg-")
    manifest_path, out_dir = write_project(parent)
    root = os.path.dirname(manifest_path)
    helper = write_helper(root, "helper.mojo", "# helper module\n")
    with open(
        os.path.join(root, "src", "main.mojo"), "a", encoding="utf-8"
    ) as handle:
        handle.write("from helper import thing\n")
    first = build_fixture(
        manifest_path, os.path.join(root, "out1"), parent
    )
    assert first.success is True, first.diagnostics
    with open(helper, "w", encoding="utf-8") as handle:
        handle.write(GPL_HEADER)
        handle.write("# helper module now GPL\n")
    second = build_fixture(
        manifest_path, os.path.join(root, "out2"), parent
    )
    assert second.success is False
    assert [item.code for item in second.diagnostics] == ["MBPF702"]


def test_snapshot_build_unresolved_import_rejected():
    parent = tempfile.mkdtemp(prefix="build-unres-")
    manifest_path, out_dir = write_project(parent)
    root = os.path.dirname(manifest_path)
    with open(
        os.path.join(root, "src", "main.mojo"), "a", encoding="utf-8"
    ) as handle:
        handle.write("from nosuch_xyz import thing\n")
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF106"]
    assert result.diagnostics[0].stage == "build.inputs"
    assert "nosuch_xyz" in result.diagnostics[0].explanation
    assert result.commands == ()
    assert result.artifacts == ()


def test_snapshot_build_missing_sdk_submodule_rejected():
    # Capture-layer rejection: `mojobpf.no_such_module` names no
    # file under the packaged SDK, so it rejects at capture
    # instead of deferring to the frontend.
    sdk_dir = build_module._sdk_dir()
    assert build_module._resolves_to_sdk(
        "mojobpf.packet", sdk_dir
    ) is True
    assert build_module._resolves_to_sdk(
        "mojobpf.no_such_module", sdk_dir
    ) is False
    parent = tempfile.mkdtemp(prefix="build-nosdk-")
    manifest_path, out_dir = write_project(parent)
    root = os.path.dirname(manifest_path)
    with open(
        os.path.join(root, "src", "main.mojo"), "a", encoding="utf-8"
    ) as handle:
        handle.write("from mojobpf.no_such_module import thing\n")
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF106"]
    assert result.diagnostics[0].stage == "build.inputs"
    assert "mojobpf.no_such_module" in (
        result.diagnostics[0].explanation
    )
    assert result.commands == ()
    assert result.artifacts == ()


def test_snapshot_build_dynamic_import_rejected():
    parent = tempfile.mkdtemp(prefix="build-dyn-")
    manifest_path, out_dir = write_project(parent)
    root = os.path.dirname(manifest_path)
    with open(
        os.path.join(root, "src", "main.mojo"), "a", encoding="utf-8"
    ) as handle:
        handle.write("x = __import__('helper')\n")
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF106"]
    assert result.diagnostics[0].stage == "build.inputs"
    assert result.commands == ()


def test_snapshot_build_unsupported_import_rejected():
    for tag, line in (
        ("relative", "from . import helper\n"),
        ("wildcard", "from helper import *\n"),
    ):
        parent = tempfile.mkdtemp(prefix="build-unsup-%s-" % tag)
        manifest_path, out_dir = write_project(parent)
        root = os.path.dirname(manifest_path)
        write_helper(root, "helper.mojo", "# helper module\n")
        with open(
            os.path.join(root, "src", "main.mojo"), "a", encoding="utf-8"
        ) as handle:
            handle.write(line)
        result = build_fixture(manifest_path, out_dir, parent)
        assert result.success is False, tag
        assert [item.code for item in result.diagnostics] == (
            ["MBPF106"]
        ), tag
        assert result.diagnostics[0].stage == "build.inputs", tag
        assert result.commands == (), tag


def test_snapshot_build_ignores_file_added_midbuild():
    # A package member planted in the origin tree while the
    # frontend runs is invisible to the build: the compiler
    # consumes the staged snapshot, so the package members it
    # records match the kept staged tree (clean only), and the
    # attested inputs match the clean build. The control phase
    # proves the consumption read sits inside the plant window:
    # pointed at origins, the same fixture records the plant.
    parent = tempfile.mkdtemp(prefix="build-plant-")
    ctrl = os.path.join(parent, "ctrl")
    os.makedirs(os.path.join(ctrl, "src"))
    os.makedirs(os.path.join(ctrl, "pkg"))
    ctrl_src = os.path.join(ctrl, "src", "main.mojo")
    with open(ctrl_src, "w", encoding="utf-8") as handle:
        handle.write("# control source\n")
    for name in ("__init__.mojo", "child.mojo"):
        with open(
            os.path.join(ctrl, "pkg", name), "w", encoding="utf-8"
        ) as handle:
            handle.write("# control member\n")
    bindir = write_snapshot_bindir(parent)
    ctrl_out = os.path.join(parent, "ctrl.ll")
    ctrl_plant = os.path.join(ctrl, "pkg", "planted.mojo")
    proc = subprocess.run(
        [os.path.join(bindir, "mojo"), "build", "-o", ctrl_out,
         ctrl_src],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=dict(
            os.environ,
            MOJOBPF_SNAPSHOT_PLANT=ctrl_plant,
            MOJOBPF_SNAPSHOT_PKGSUBDIR="pkg",
        ),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert os.path.isfile(ctrl_plant)
    with open(ctrl_out, encoding="utf-8") as handle:
        ctrl_raw = handle.read()
    assert "; pkg-members:" in ctrl_raw, ctrl_raw
    assert "planted.mojo" in ctrl_raw, ctrl_raw
    manifest_path, out_dir = write_project(parent)
    root = os.path.dirname(manifest_path)
    write_helper(root, "pkg/__init__.mojo", "# package init\n")
    write_helper(root, "pkg/child.mojo", "# child module\n")
    with open(
        os.path.join(root, "src", "main.mojo"), "a", encoding="utf-8"
    ) as handle:
        handle.write("from pkg import child\n")
    clean = build_snapshot_fixture(
        manifest_path, os.path.join(root, "out-clean"), parent
    )
    assert clean.success is True, clean.diagnostics
    with open(
        os.path.join(root, "out-clean", "fixture_obj.evidence.json"),
        encoding="utf-8",
    ) as handle:
        clean_doc = json.load(handle)
    assert sorted(
        item["path"] for item in clean_doc["inputs"]["imports"]
    ) == ["pkg/__init__.mojo", "pkg/child.mojo"]
    plant = os.path.join(root, "pkg", "planted.mojo")
    with fixture_env(
        MOJOBPF_SNAPSHOT_PLANT=plant, MOJOBPF_SNAPSHOT_PKGSUBDIR="pkg"
    ):
        result = build_snapshot_fixture(
            manifest_path, out_dir, parent, save_temps=True
        )
    try:
        assert result.success is True, result.diagnostics
        assert os.path.isfile(plant)
        with open(
            os.path.join(result.work_dir, "xdp_entry.raw.ll"),
            encoding="utf-8",
        ) as handle:
            raw = handle.read()
        members: list[str] = []
        for line in raw.splitlines():
            if line.startswith("; pkg-members:"):
                members = line[len("; pkg-members:"):].split(",")
        kept = os.path.join(
            result.work_dir, "inputs-snapshot", "project", "pkg"
        )
        assert sorted(os.listdir(kept)) == members == [
            "__init__.mojo", "child.mojo",
        ], (os.listdir(kept), members, raw)
        with open(
            os.path.join(out_dir, "fixture_obj.evidence.json"),
            encoding="utf-8",
        ) as handle:
            doc = json.load(handle)
        assert doc["inputs"] == clean_doc["inputs"]
        assert doc["outputs"] == clean_doc["outputs"]
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_snapshot_build_clean_changed_clean_consumes_snapshot():
    # The origin flaps clean->evil->clean while the frontend
    # runs; the compiled bytes and the attested hash stay clean
    # because the compiler read the staged snapshot.
    parent = tempfile.mkdtemp(prefix="build-flap-")
    manifest_path, out_dir = write_project(parent)
    root = os.path.dirname(manifest_path)
    origin = os.path.join(root, "src", "main.mojo")
    with open(origin, "rb") as handle:
        clean = handle.read()
    clean_sha = hashlib.sha256(clean).hexdigest()
    with fixture_env(MOJOBPF_SNAPSHOT_FLAP=origin):
        result = build_snapshot_fixture(
            manifest_path, out_dir, parent, save_temps=True
        )
    try:
        assert result.success is True, result.diagnostics
        with open(origin, "rb") as handle:
            assert handle.read() == clean
        with open(
            os.path.join(out_dir, "fixture_obj.evidence.json"),
            encoding="utf-8",
        ) as handle:
            doc = json.load(handle)
        assert doc["inputs"]["source"][0]["sha256"] == clean_sha
        raw_path = os.path.join(result.work_dir, "xdp_entry.raw.ll")
        with open(raw_path, encoding="utf-8") as handle:
            raw = handle.read()
        assert "; src-sha256:%s" % clean_sha in raw
        assert "mojobpf-inputs-" in raw
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_snapshot_spawn_environment_pins_raw_values():
    # The snapshot pins the raw compiler-material environment
    # for spawn: the sealed record hashes path values, but the
    # spawn binding keeps the verbatim bytes the compiler saw.
    from mojobpf.manifest import parse_manifest
    parent = tempfile.mkdtemp(prefix="build-spawnraw-")
    manifest_path, _ = write_project(parent)
    manifest = parse_manifest(manifest_path)
    toolchain = inputs_module.ToolchainInputs()
    sdk = inputs_module.SdkInputs(
        sdk_dir=build_module._sdk_dir(), version="9.9"
    )
    with fixture_env(MODULAR_HOME="/sealed/max", MOJO_X="1"):
        snapshot = inputs_module.capture_build_inputs(
            manifest, toolchain, sdk, work_parent=parent
        )
    try:
        pinned = dict(snapshot.spawn_environment)
        assert pinned["MODULAR_HOME"] == "/sealed/max", pinned
        assert pinned["MOJO_X"] == "1", pinned
        assert "PATH" in pinned, pinned
        sealed = dict(snapshot.environment)
        assert sealed["MODULAR_HOME"].startswith("sha256:"), sealed
    finally:
        snapshot.dispose()


def test_snapshot_spawn_uses_sealed_modular_home():
    # A post-capture MODULAR_HOME change must not silently
    # diverge spawn from evidence: the frontend observes the
    # sealed value, which is what the sidecar records.
    parent = tempfile.mkdtemp(prefix="build-spawnrace-")
    manifest_path, out_dir = write_project(parent)
    real_run_step = build_module._run_step

    def raced(argv, *args, **kwargs):
        os.environ["MODULAR_HOME"] = "/new/install"
        try:
            return real_run_step(argv, *args, **kwargs)
        finally:
            os.environ["MODULAR_HOME"] = "/old/install"

    build_module._run_step = raced
    try:
        with fixture_env(MODULAR_HOME="/old/install"):
            result = build_snapshot_fixture(
                manifest_path, out_dir, parent, save_temps=True
            )
    finally:
        build_module._run_step = real_run_step
    try:
        assert result.success is True, result.diagnostics
        raw_path = os.path.join(result.work_dir, "xdp_entry.raw.ll")
        with open(raw_path, encoding="utf-8") as handle:
            raw = handle.read()
        assert "; modular-home:/old/install\n" in raw, raw
        with open(
            os.path.join(out_dir, "fixture_obj.evidence.json"),
            encoding="utf-8",
        ) as handle:
            doc = json.load(handle)
        recorded = {
            entry["name"]: entry["value"]
            for entry in doc["environment"]
        }
        assert recorded["MODULAR_HOME"] == (
            "sha256:" + hashlib.sha256(b"/old/install").hexdigest()
        )
        assert (
            "env MODULAR_HOME=%s" % recorded["MODULAR_HOME"]
        ) in doc["inputs"]["compiler"]
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_snapshot_spawn_pins_absent_modular_home():
    # Absent-at-capture variables stay absent at spawn: a
    # MODULAR_HOME (or a brand-new MOJO_ variable) added after
    # capture must reach neither the compiler nor the evidence.
    # The reverse move (removed after capture) still spawns the
    # pinned value.
    parent = tempfile.mkdtemp(prefix="build-spawnabs-")
    manifest_path, out_dir = write_project(parent)
    real_run_step = build_module._run_step

    def raced_add(argv, *args, **kwargs):
        os.environ["MODULAR_HOME"] = "/sneaky/install"
        os.environ["MOJO_SNEAKY"] = "1"
        try:
            return real_run_step(argv, *args, **kwargs)
        finally:
            os.environ.pop("MODULAR_HOME", None)
            os.environ.pop("MOJO_SNEAKY", None)

    build_module._run_step = raced_add
    old_home = os.environ.pop("MODULAR_HOME", None)
    try:
        result = build_snapshot_fixture(
            manifest_path, out_dir, parent, save_temps=True
        )
    finally:
        build_module._run_step = real_run_step
        if old_home is not None:
            os.environ["MODULAR_HOME"] = old_home
        else:
            os.environ.pop("MODULAR_HOME", None)
    try:
        assert result.success is True, result.diagnostics
        with open(
            os.path.join(result.work_dir, "xdp_entry.raw.ll"),
            encoding="utf-8",
        ) as handle:
            raw = handle.read()
        assert "; modular-home:\n" in raw, raw
        assert "/sneaky/install" not in raw, raw
        assert "SNEAKY" not in raw, raw
        with open(
            os.path.join(out_dir, "fixture_obj.evidence.json"),
            encoding="utf-8",
        ) as handle:
            doc = json.load(handle)
        recorded = {
            entry["name"]: entry["value"]
            for entry in doc["environment"]
        }
        assert "MODULAR_HOME" not in recorded, recorded
        assert "MOJO_SNEAKY" not in recorded, recorded
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)

    def raced_pop(argv, *args, **kwargs):
        old = os.environ.pop("MODULAR_HOME", None)
        try:
            return real_run_step(argv, *args, **kwargs)
        finally:
            if old is not None:
                os.environ["MODULAR_HOME"] = old

    build_module._run_step = raced_pop
    try:
        with fixture_env(MODULAR_HOME="/keep/install"):
            removed = build_snapshot_fixture(
                manifest_path, os.path.join(parent, "out-b"),
                parent, save_temps=True,
            )
    finally:
        build_module._run_step = real_run_step
    try:
        assert removed.success is True, removed.diagnostics
        with open(
            os.path.join(removed.work_dir, "xdp_entry.raw.ll"),
            encoding="utf-8",
        ) as handle:
            raw = handle.read()
        assert "; modular-home:/keep/install\n" in raw, raw
    finally:
        if removed.work_dir is not None:
            shutil.rmtree(
                removed.work_dir, ignore_errors=True
            )


def test_snapshot_flap_window_is_hot_at_read_time():
    # Negative control for the clean->changed->clean test: when
    # the fixture reads the flapping path itself (as an
    # origin-reading driver would), it records the evil bytes,
    # proving the consumption read sits inside the evil window.
    parent = tempfile.mkdtemp(prefix="build-flapctl-")
    bindir = write_snapshot_bindir(parent)
    target = os.path.join(parent, "flap.mojo")
    with open(target, "wb") as handle:
        handle.write(b"# clean\n")
    out = os.path.join(parent, "out.ll")
    env = dict(os.environ, MOJOBPF_SNAPSHOT_FLAP=target)
    proc = subprocess.run(
        [os.path.join(bindir, "mojo"), "build", "-o", out, target],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    with open(target, "rb") as handle:
        assert handle.read() == b"# clean\n"
    with open(out, encoding="utf-8") as handle:
        raw = handle.read()
    evil = hashlib.sha256(b"# clean\n# evil\n").hexdigest()
    clean = hashlib.sha256(b"# clean\n").hexdigest()
    assert ("; src-sha256:%s" % evil) in raw, raw
    assert ("; src-sha256:%s" % clean) not in raw, raw


def test_snapshot_build_staged_tamper_rejected():
    # The staged input changes after capture: the build rejects
    # instead of attributing the clean hash to tampered bytes.
    parent = tempfile.mkdtemp(prefix="build-tamper-")
    manifest_path, out_dir = write_project(parent)
    with fixture_env(MOJOBPF_SNAPSHOT_TAMPER="1"):
        result = build_snapshot_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF106"]
    assert result.diagnostics[0].stage == "build.inputs"
    assert "changed after capture" in result.diagnostics[0].explanation
    assert result.artifacts == ()
    assert not os.path.exists(out_dir) or (
        os.listdir(out_dir) == []
    )


def test_snapshot_build_frontend_error_names_origin():
    parent = tempfile.mkdtemp(prefix="build-errloc-")
    manifest_path, out_dir = write_project(parent)
    root = os.path.dirname(manifest_path)
    origin = os.path.join(root, "src", "main.mojo")
    with fixture_env(MOJOBPF_SNAPSHOT_FAIL="fixture boom"):
        result = build_snapshot_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF106"
    assert diagnostic.stage == "build.frontend"
    assert diagnostic.location is not None
    assert origin in diagnostic.location, diagnostic.location
    assert "mojobpf-inputs-" not in diagnostic.location
    assert origin in diagnostic.explanation, diagnostic.explanation
    assert "mojobpf-inputs-" not in diagnostic.explanation


def test_snapshot_build_commands_name_origins():
    # BuildResult.commands argv names origin paths, never staged
    # capture copies: the staged root is gone by the time the
    # caller reads the result.
    parent = tempfile.mkdtemp(prefix="build-argvmap-")
    manifest_path, out_dir = write_project(parent, with_maps=True)
    root = os.path.dirname(manifest_path)
    origin = os.path.join(root, "src", "main.mojo")
    with fixture_env(
        MOJOBPF_FIXTURE_MOJO="mapmode", MOJOBPF_FIXTURE_LLC="mapshape",
        MOJOBPF_FIXTURE_BTF=FIXTURE_MAP_BTF_HEX,
    ):
        result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is True, result.diagnostics
    frontend = result.commands[0].argv
    assert frontend[-1] == origin, frontend
    flag = frontend.index("-I")
    assert frontend[flag + 1] == os.path.abspath(
        build_module._sdk_dir()
    ), frontend
    for record in result.commands:
        for token in record.argv:
            assert "mojobpf-inputs-" not in token, record.argv
        assert "mojobpf-inputs-" not in record.log_excerpt


def test_snapshot_build_failure_records_name_origins():
    # Step failures quote origin paths in the diagnostic, the
    # recorded argv and the log excerpt alike.
    parent = tempfile.mkdtemp(prefix="build-failloc-")
    manifest_path, out_dir = write_project(parent)
    root = os.path.dirname(manifest_path)
    origin = os.path.join(root, "src", "main.mojo")
    with fixture_env(MOJOBPF_SNAPSHOT_FAIL="fixture boom"):
        result = build_snapshot_fixture(manifest_path, out_dir, parent)
    assert result.success is False
    diagnostic = result.diagnostics[0]
    assert diagnostic.code == "MBPF106"
    assert origin in (diagnostic.location or ""), diagnostic
    record = result.commands[0]
    assert record.argv[-1] == origin, record.argv
    assert origin in record.log_excerpt, record.log_excerpt
    assert "mojobpf-inputs-" not in record.log_excerpt


def test_snapshot_two_roots_identical():
    # The same project built in two roots produces identical
    # evidence bytes and identical objects: stable metadata
    # carries no timestamps or temporary paths.
    parents = [
        tempfile.mkdtemp(prefix="build-root-a-"),
        tempfile.mkdtemp(prefix="build-root-b-"),
    ]
    docs = []
    objects = []
    for parent in parents:
        manifest_path, out_dir = write_project(parent)
        root = os.path.dirname(manifest_path)
        write_helper(root, "helper.mojo", "from deep import thing\n")
        write_helper(root, "deep.mojo", "# leaf module\n")
        with open(
            os.path.join(root, "src", "main.mojo"), "a", encoding="utf-8"
        ) as handle:
            handle.write("import helper, deep\n")
        result = build_fixture(manifest_path, out_dir, parent)
        assert result.success is True, result.diagnostics
        sidecar = os.path.join(out_dir, "fixture_obj.evidence.json")
        with open(sidecar, "rb") as handle:
            raw = handle.read()
        assert parent.encode() not in raw
        docs.append(raw)
        with open(
            os.path.join(out_dir, "fixture_obj.bpf.o"), "rb"
        ) as handle:
            objects.append(handle.read())
    assert docs[0] == docs[1]
    assert objects[0] == objects[1]


def test_snapshot_distribution_absolute_path_normalized():
    # Stable metadata records the distribution digest, never the
    # absolute distribution filename: identical bytes reached
    # through two absolute paths attest identically.
    parent = tempfile.mkdtemp(prefix="build-distabs-")
    manifest_path, _ = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    payload_bytes = b"distribution payload bytes\n"
    digest = hashlib.sha256(payload_bytes).hexdigest()

    def _build_through(filename, out_name):
        payload = os.path.join(parent, filename)
        with open(payload, "wb") as handle:
            handle.write(payload_bytes)
        lockfile = write_lockfile(parent, bindir)
        with open(lockfile, encoding="utf-8") as handle:
            document = json.load(handle)
        document["distribution"] = {
            "kind": "pixi-lock",
            "platform": "linux-64",
            "file": payload,
            "sha256": digest,
        }
        with open(lockfile, "w", encoding="utf-8") as handle:
            json.dump(document, handle)
        out_dir = os.path.join(parent, out_name)
        result = build_project(
            BuildRequest(
                manifest_path=manifest_path,
                out_dir=out_dir,
                adapter_path=adapter,
                search_paths=(bindir,),
                lockfile_path=lockfile,
            )
        )
        assert result.success is True, result.diagnostics
        with open(
            os.path.join(out_dir, "fixture_obj.evidence.json"), "rb"
        ) as handle:
            return payload, handle.read()

    payload_a, raw_a = _build_through("payload-a.bin", "out-a")
    payload_b, raw_b = _build_through("payload-b.bin", "out-b")
    # Neither absolute path leaks into either sidecar (the two
    # lockfile documents still hash differently, as they must:
    # they are different pin documents).
    assert payload_a.encode() not in raw_a
    assert payload_b.encode() not in raw_b
    expected = ["stdlib distribution pixi-lock linux-64 " + digest]
    for raw in (raw_a, raw_b):
        compiler = json.loads(
            raw.decode("utf-8")
        )["inputs"]["compiler"]
        dist = [
            entry for entry in compiler
            if entry.startswith("stdlib distribution ")
        ]
        assert dist == expected, compiler


def _sidecar_cache_key(doc):
    """Recompute the cache key from a sidecar's inputs mapping."""
    inputs = doc["inputs"]

    def _one(entry):
        return evidence_module.HashedFile(
            path=entry["path"], sha256=entry["sha256"],
            size=entry["size"],
        )

    return evidence_module.cache_key(
        evidence_module.CacheInputs(
            source=tuple(_one(e) for e in inputs["source"]),
            imports=tuple(_one(e) for e in inputs["imports"]),
            sdk=tuple(_one(e) for e in inputs["sdk"]),
            manifest=_one(inputs["manifest"]),
            compiler=tuple(inputs["compiler"]),
            flags=tuple(inputs["flags"]),
            profile_id=inputs["profile_id"],
            profile_sha256=inputs["profile_sha256"],
            adapter=tuple(inputs["adapter"]),
            tool_version=inputs["tool_version"],
            sdk_version=inputs["sdk_version"],
        )
    )


def test_snapshot_stdlib_payload_swap_changes_evidence_key():
    # Identical lockfile and identical binaries, swapped
    # installed stdlib bytes: the evidence compiler class and
    # the cache key must change (previously swap-invariant).
    parent = tempfile.mkdtemp(prefix="build-stdpay-")
    manifest_path, _ = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(parent, bindir)
    home = os.path.join(parent, "max")
    os.makedirs(os.path.join(parent, "lib", "mojo"))
    os.makedirs(home)
    std = os.path.join(parent, "lib", "mojo", "std.mojoc")
    cfg = os.path.join(home, "modular.cfg")
    with open(std, "wb") as handle:
        handle.write(b"stdlib-v1")
    with open(cfg, "wb") as handle:
        handle.write(b"cfg-v1")

    def _build(out_name):
        out_dir = os.path.join(parent, out_name)
        with fixture_env(MODULAR_HOME=home):
            result = build_project(
                BuildRequest(
                    manifest_path=manifest_path,
                    out_dir=out_dir,
                    adapter_path=adapter,
                    search_paths=(bindir,),
                    lockfile_path=lockfile,
                )
            )
        assert result.success is True, result.diagnostics
        with open(
            os.path.join(out_dir, "fixture_obj.evidence.json"),
            encoding="utf-8",
        ) as handle:
            return json.load(handle)

    doc_a = _build("out-a")
    with open(std, "wb") as handle:
        handle.write(b"stdlib-v2")
    doc_b = _build("out-b")
    with open(std, "wb") as handle:
        handle.write(b"stdlib-v1")
    with open(cfg, "wb") as handle:
        handle.write(b"cfg-v2")
    doc_c = _build("out-c")
    compiler_a = doc_a["inputs"]["compiler"]
    assert doc_b["inputs"]["compiler"] != compiler_a
    assert doc_c["inputs"]["compiler"] != compiler_a
    assert _sidecar_cache_key(doc_b) != _sidecar_cache_key(doc_a)
    assert _sidecar_cache_key(doc_c) != _sidecar_cache_key(doc_a)
    payload = [
        entry for entry in compiler_a
        if entry.startswith("stdlib payload ")
    ]
    assert len(payload) == 2, compiler_a
    for entry in payload:
        assert parent not in entry, entry


def test_snapshot_stdlib_midbuild_swap_rejected():
    # A stdlib payload swap after hashing rejects at the
    # snapshot-verification boundary: the recorded identity
    # still names the clean bytes, so the build fails closed
    # instead of attesting them for swapped bytes.
    parent = tempfile.mkdtemp(prefix="build-stdswap-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(parent, bindir)
    home = os.path.join(parent, "max")
    os.makedirs(home)
    cfg = os.path.join(home, "modular.cfg")
    with open(cfg, "wb") as handle:
        handle.write(b"cfg-v1")
    real_run_step = build_module._run_step
    swapped = []

    def raced(argv, *args, **kwargs):
        if not swapped:
            swapped.append(True)
            with open(cfg, "wb") as handle:
                handle.write(b"cfg-evil")
        return real_run_step(argv, *args, **kwargs)

    build_module._run_step = raced
    try:
        with fixture_env(MODULAR_HOME=home):
            result = build_project(
                BuildRequest(
                    manifest_path=manifest_path,
                    out_dir=out_dir,
                    adapter_path=adapter,
                    search_paths=(bindir,),
                    lockfile_path=lockfile,
                )
            )
    finally:
        build_module._run_step = real_run_step
        with open(cfg, "wb") as handle:
            handle.write(b"cfg-v1")
    assert swapped == [True]
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF106"]
    assert result.diagnostics[0].stage == "build.inputs"
    assert "modular.cfg" in result.diagnostics[0].explanation
    assert result.artifacts == ()
    assert not os.path.exists(out_dir) or (
        os.listdir(out_dir) == []
    )


def test_snapshot_capture_root_removed_on_success_and_failure():
    parent = tempfile.mkdtemp(prefix="build-cleanup-")
    manifest_path, _ = write_project(parent)
    result = build_fixture(
        manifest_path, os.path.join(parent, "out"), parent,
        work_parent=parent,
    )
    assert result.success is True, result.diagnostics
    assert [
        name for name in os.listdir(parent)
        if name.startswith("mojobpf-inputs-")
    ] == []
    bad_manifest, _ = write_project(parent, dirname="bad")
    bad_root = os.path.dirname(bad_manifest)
    with open(
        os.path.join(bad_root, "src", "main.mojo"), "a", encoding="utf-8"
    ) as handle:
        handle.write("from nosuch_xyz import thing\n")
    failed = build_fixture(
        bad_manifest, os.path.join(parent, "bad-out"), parent,
        work_parent=parent,
    )
    assert failed.success is False
    assert [
        name for name in os.listdir(parent)
        if name.startswith("mojobpf-inputs-")
    ] == []


def test_snapshot_capture_root_retired_on_keyboard_interrupt():
    # An interruption after a staged write still retires the
    # capture root: no staged residue survives a failed capture.
    from mojobpf.manifest import parse_manifest
    parent = tempfile.mkdtemp(prefix="build-kbint-")
    manifest_path, _ = write_project(parent)
    manifest = parse_manifest(manifest_path)
    toolchain = inputs_module.ToolchainInputs()
    sdk = inputs_module.SdkInputs(
        sdk_dir=build_module._sdk_dir(), version="9.9"
    )
    real_write = inputs_module._write_staged
    calls = []

    def flaky(path, content):
        calls.append(path)
        if len(calls) == 2:
            raise KeyboardInterrupt("injected")
        return real_write(path, content)

    inputs_module._write_staged = flaky
    try:
        try:
            inputs_module.capture_build_inputs(
                manifest, toolchain, sdk, work_parent=parent
            )
        except KeyboardInterrupt:
            pass
        else:
            raise AssertionError("injected interrupt was swallowed")
    finally:
        inputs_module._write_staged = real_write
    assert calls, "fault never injected"
    assert [
        name for name in os.listdir(parent)
        if name.startswith("mojobpf-inputs-")
    ] == []


def test_snapshot_capture_reread_oserror_retires_root():
    # An unexpected OSError from the staged reread still retires
    # the root; the fault itself reports as MBPF106 naming the
    # origin path, never the staged copy.
    import builtins
    from mojobpf.manifest import parse_manifest
    parent = tempfile.mkdtemp(prefix="build-reread-")
    manifest_path, _ = write_project(parent)
    manifest = parse_manifest(manifest_path)
    toolchain = inputs_module.ToolchainInputs()
    sdk = inputs_module.SdkInputs(
        sdk_dir=build_module._sdk_dir(), version="9.9"
    )
    real_open = builtins.open

    def guarded(file, *args, **kwargs):
        mode = args[0] if args else kwargs.get("mode", "r")
        if (
            isinstance(file, str)
            and "mojobpf-inputs-" in file
            and mode == "rb"
        ):
            raise OSError("injected reread fault")
        return real_open(file, *args, **kwargs)

    builtins.open = guarded
    try:
        try:
            inputs_module.capture_build_inputs(
                manifest, toolchain, sdk, work_parent=parent
            )
        except inputs_module.InputError as exc:
            assert exc.diagnostic.code == "MBPF106"
            assert exc.diagnostic.stage == "build.inputs"
            assert exc.diagnostic.location is not None
            assert "mojobpf-inputs-" not in exc.diagnostic.location
        else:
            raise AssertionError("reread fault was accepted")
    finally:
        builtins.open = real_open
    assert [
        name for name in os.listdir(parent)
        if name.startswith("mojobpf-inputs-")
    ] == []


def test_snapshot_manifest_drift_rejected():
    # The manifest file changes between the admission parse and
    # the capture read: capture rejects instead of compiling
    # under stale declarations.
    from mojobpf.manifest import parse_manifest
    parent = tempfile.mkdtemp(prefix="build-mdrift-")
    manifest_path, _ = write_project(parent)
    manifest = parse_manifest(manifest_path)
    with open(manifest_path, encoding="utf-8") as handle:
        text = handle.read()
    assert 'name = "fixture-proj"' in text
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(text.replace(
            'name = "fixture-proj"', 'name = "drifted-proj"'
        ))
    toolchain = inputs_module.ToolchainInputs()
    sdk = inputs_module.SdkInputs(
        sdk_dir=build_module._sdk_dir(), version="9.9"
    )
    try:
        inputs_module.capture_build_inputs(
            manifest, toolchain, sdk, work_parent=parent
        )
    except inputs_module.InputError as exc:
        assert exc.diagnostic.code == "MBPF106"
        assert exc.diagnostic.stage == "build.inputs"
        assert "changed between admission" in exc.diagnostic.explanation
    else:
        raise AssertionError("manifest drift was accepted")
    assert [
        name for name in os.listdir(parent)
        if name.startswith("mojobpf-inputs-")
    ] == []


def test_snapshot_escape_bypassing_parse_rejected():
    # Defense in depth: a manifest object whose source escapes
    # (unreachable through parse_manifest's MBPF207, reachable
    # through a hand-built object) is rejected by capture too.
    import dataclasses
    from mojobpf.manifest import ProgramEntry, parse_manifest
    parent = tempfile.mkdtemp(prefix="build-escape-")
    manifest_path, _ = write_project(parent)
    manifest = parse_manifest(manifest_path)
    evil = dataclasses.replace(
        manifest,
        programs=(
            dataclasses.replace(
                manifest.programs[0], source="../evil.mojo"
            ),
        ),
    )
    assert isinstance(evil.programs[0], ProgramEntry)
    toolchain = inputs_module.ToolchainInputs()
    sdk = inputs_module.SdkInputs(
        sdk_dir=build_module._sdk_dir(), version="9.9"
    )
    try:
        inputs_module.capture_build_inputs(evil, toolchain, sdk)
    except inputs_module.InputError as exc:
        assert exc.diagnostic.code == "MBPF106"
        assert exc.diagnostic.stage == "build.inputs"
        assert "escapes" in exc.diagnostic.explanation
    else:
        raise AssertionError("escaping source was accepted")


def test_snapshot_env_pin_read_once_before_payload_hash():
    # A MODULAR_HOME added after payload hashing (between the
    # driver's pin and capture's read) must reach neither spawn
    # nor evidence: the complete pin is captured once and passed
    # through, never re-read from the ambient environment.
    parent = tempfile.mkdtemp(prefix="build-pinonce-")
    manifest_path, out_dir = write_project(parent)
    real_capture = inputs_module.capture_pinned_environment
    calls = []

    def late_add(overrides=None):
        calls.append(True)
        os.environ["MODULAR_HOME"] = "/late/install"
        os.environ["MOJO_LATE"] = "1"
        return real_capture(overrides)

    inputs_module.capture_pinned_environment = late_add
    old_home = os.environ.pop("MODULAR_HOME", None)
    old_late = os.environ.pop("MOJO_LATE", None)
    try:
        result = build_snapshot_fixture(
            manifest_path, out_dir, parent, save_temps=True
        )
    finally:
        inputs_module.capture_pinned_environment = real_capture
        os.environ.pop("MODULAR_HOME", None)
        os.environ.pop("MOJO_LATE", None)
        if old_home is not None:
            os.environ["MODULAR_HOME"] = old_home
        if old_late is not None:
            os.environ["MOJO_LATE"] = old_late
    try:
        assert result.success is True, result.diagnostics
        # The capture path performs no second ambient read: the
        # driver's single pin passes through untouched.
        assert calls == [], calls
        with open(
            os.path.join(result.work_dir, "xdp_entry.raw.ll"),
            encoding="utf-8",
        ) as handle:
            raw = handle.read()
        assert "; modular-home:\n" in raw, raw
        assert "/late/install" not in raw, raw
        assert "MOJO_LATE" not in raw, raw
        with open(
            os.path.join(out_dir, "fixture_obj.evidence.json"),
            encoding="utf-8",
        ) as handle:
            doc = json.load(handle)
        recorded = {
            entry["name"]: entry["value"]
            for entry in doc["environment"]
        }
        assert "MODULAR_HOME" not in recorded, recorded
        assert "MOJO_LATE" not in recorded, recorded
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_snapshot_verify_added_vars_withheld_from_spawn():
    # Variables added inside admission verification -- after any
    # pre-spawn filtering -- must still be withheld from the
    # child: the spawn environment is filtered purely from the
    # snapshot pin, never inherited from post-filter ambient.
    import mojobpf.execution as execution_module
    parent = tempfile.mkdtemp(prefix="build-verifyadd-")
    manifest_path, out_dir = write_project(parent)
    real_verify = execution_module.verify_spawn
    seen = []

    armed = []

    def spying_verify(execution):
        seen.append(True)
        if armed:
            # Left set on purpose: the trace under test adds
            # variables inside verification that persist to
            # spawn. Dormant until the first build step so the
            # capture pin (taken during setup) stays clean.
            os.environ["MODULAR_HOME"] = "/verify-evil"
            os.environ["MOJO_VERIFY_EVIL"] = "1"
        return real_verify(execution)

    real_run_step = build_module._run_step

    def arming(argv, *args, **kwargs):
        armed.append(True)
        return real_run_step(argv, *args, **kwargs)

    execution_module.verify_spawn = spying_verify
    patched_build = hasattr(build_module, "verify_spawn")
    if patched_build:
        real_build_verify = build_module.verify_spawn
        build_module.verify_spawn = spying_verify
    build_module._run_step = arming
    old_home = os.environ.pop("MODULAR_HOME", None)
    old_evil = os.environ.pop("MOJO_VERIFY_EVIL", None)
    try:
        result = build_snapshot_fixture(
            manifest_path, out_dir, parent, save_temps=True
        )
    finally:
        execution_module.verify_spawn = real_verify
        if patched_build:
            build_module.verify_spawn = real_build_verify
        build_module._run_step = real_run_step
        os.environ.pop("MODULAR_HOME", None)
        os.environ.pop("MOJO_VERIFY_EVIL", None)
        if old_home is not None:
            os.environ["MODULAR_HOME"] = old_home
        if old_evil is not None:
            os.environ["MOJO_VERIFY_EVIL"] = old_evil
    try:
        assert seen != [], "verification spy never ran"
        assert result.success is True, result.diagnostics
        with open(
            os.path.join(result.work_dir, "xdp_entry.raw.ll"),
            encoding="utf-8",
        ) as handle:
            raw = handle.read()
        assert "; modular-home:\n" in raw, raw
        assert "/verify-evil" not in raw, raw
        assert "MOJO_VERIFY_EVIL" not in raw, raw
        with open(
            os.path.join(out_dir, "fixture_obj.evidence.json"),
            encoding="utf-8",
        ) as handle:
            doc = json.load(handle)
        recorded = {
            entry["name"]: entry["value"]
            for entry in doc["environment"]
        }
        assert "MODULAR_HOME" not in recorded, recorded
        assert "MOJO_VERIFY_EVIL" not in recorded, recorded
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_run_step_never_mutates_process_environment():
    # Spawning must not pop/restore os.environ: a concurrent
    # edit to a withheld name during the spawn must survive,
    # and the child must still observe the pinned environment.
    parent = tempfile.mkdtemp(prefix="build-nomut-")
    real_popen = subprocess.Popen
    child_envs = []

    def mutating_popen(argv, **kwargs):
        child_envs.append(kwargs.get("env"))
        # Simulate another thread editing a withheld name while
        # the child runs: the driver must not restore over it.
        os.environ["MODULAR_HOME"] = "/concurrent-edit"
        return real_popen(argv, **kwargs)

    subprocess.Popen = mutating_popen
    old_home = os.environ.get("MODULAR_HOME")
    os.environ["MODULAR_HOME"] = "/before-spawn"
    try:
        record, _out, _err, _saw = build_module._run_step(
            [sys.executable, "-c", "pass"],
            "build.clobber",
            30,
            os.path.join(parent, "step.log"),
            parent,
            execution=None,
            # A complete pin, as the product always passes:
            # every base name is pinned or listed absent.
            env_extra={"PATH": os.environ["PATH"]},
            env_unset=("MODULAR_HOME",),
        )
        observed = os.environ.get("MODULAR_HOME")
    finally:
        subprocess.Popen = real_popen
        if old_home is None:
            os.environ.pop("MODULAR_HOME", None)
        else:
            os.environ["MODULAR_HOME"] = old_home
    assert record.exit_code == 0, record
    assert observed == "/concurrent-edit", observed
    assert len(child_envs) == 1, child_envs
    assert child_envs[0] is not None, child_envs
    assert "MODULAR_HOME" not in child_envs[0], child_envs


MOJO_STDLIB_FIXTURE = """\
#!{python}
import hashlib
import os
import sys


def main(argv):
    if argv[1:] == ["--version"]:
        print("Mojo 9.9.9 (fixture)")
        return 0
    out = argv[argv.index("-o") + 1]
    src = argv[-1]
    with open(src, "rb") as handle:
        content = handle.read()
    digest = hashlib.sha256(content).hexdigest()
    stdlib_hex = "missing"
    cfg_hex = "missing"
    home = os.environ.get("MODULAR_HOME", "")
    if home:
        try:
            with open(
                os.path.join(home, "modular.cfg"), "rb"
            ) as handle:
                cfg_bytes = handle.read()
        except OSError:
            cfg_bytes = None
        if cfg_bytes is not None:
            cfg_hex = hashlib.sha256(cfg_bytes).hexdigest()
            import_path = None
            for line in cfg_bytes.decode(
                "utf-8", "replace"
            ).splitlines():
                key, sep, value = line.strip().partition("=")
                if sep and key.strip().lower() == "import_path":
                    import_path = value.strip() or None
            if import_path:
                try:
                    with open(
                        os.path.join(import_path, "std.mojoc"),
                        "rb",
                    ) as handle:
                        stdlib_hex = hashlib.sha256(
                            handle.read()
                        ).hexdigest()
                except OSError:
                    pass
    with open(out, "w", encoding="utf-8") as handle:
        handle.write("; fixture raw IR for %s\\n" % src)
        handle.write("; src-sha256:%s\\n" % digest)
        handle.write("; stdlib-sha256:%s\\n" % stdlib_hex)
        handle.write("; cfg-sha256:%s\\n" % cfg_hex)
        handle.write(
            "; modular-home:%s\\n"
            % os.environ.get("MODULAR_HOME", "")
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
"""


def test_snapshot_stdlib_transient_swap_consumes_staged_bytes():
    # Transient substitution between the two boundary checks:
    # verify(clean) -> swap -> frontend consumes -> restore ->
    # verify(clean). Both boundaries pass, yet the consumed bytes
    # must still equal the captured bytes: the frontend consumes
    # the staged payload, never the live install.
    parent = tempfile.mkdtemp(prefix="build-stdtrans-")
    manifest_path, out_dir = write_project(parent)
    bindir = tempfile.mkdtemp(prefix="fixture-bin-", dir=parent)
    write_executable(
        os.path.join(bindir, "mojo"), MOJO_STDLIB_FIXTURE
    )
    write_executable(os.path.join(bindir, "llc"), LLC_FIXTURE)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(parent, bindir)
    home = os.path.join(parent, "max")
    libdir = os.path.join(parent, "lib", "mojo")
    os.makedirs(libdir)
    os.makedirs(home)
    cfg_path = os.path.join(home, "modular.cfg")
    std_path = os.path.join(libdir, "std.mojoc")
    clean_cfg = (
        "[mojo-max]\nimport_path = %s\n" % libdir
    ).encode("utf-8")
    clean_std = b"stdlib-clean-payload"
    with open(cfg_path, "wb") as handle:
        handle.write(clean_cfg)
    with open(std_path, "wb") as handle:
        handle.write(clean_std)
    clean_std_hex = hashlib.sha256(clean_std).hexdigest()
    evil_cfg = (
        "[mojo-max]\nimport_path = %s\n# evil\n" % libdir
    ).encode("utf-8")
    evil_std = b"stdlib-EVIL-payload"
    evil_std_hex = hashlib.sha256(evil_std).hexdigest()
    evil_cfg_hex = hashlib.sha256(evil_cfg).hexdigest()
    real_run_step = build_module._run_step
    swapped = []

    def raced(argv, *args, **kwargs):
        if not swapped:
            swapped.append(True)
            with open(cfg_path, "wb") as handle:
                handle.write(evil_cfg)
            with open(std_path, "wb") as handle:
                handle.write(evil_std)
            try:
                return real_run_step(argv, *args, **kwargs)
            finally:
                with open(cfg_path, "wb") as handle:
                    handle.write(clean_cfg)
                with open(std_path, "wb") as handle:
                    handle.write(clean_std)
        return real_run_step(argv, *args, **kwargs)

    build_module._run_step = raced
    try:
        with fixture_env(MODULAR_HOME=home):
            result = build_project(
                BuildRequest(
                    manifest_path=manifest_path,
                    out_dir=out_dir,
                    adapter_path=adapter,
                    search_paths=(bindir,),
                    lockfile_path=lockfile,
                    save_temps=True,
                )
            )
    finally:
        build_module._run_step = real_run_step
    try:
        # Both boundaries saw clean bytes, so the build succeeds;
        # the transient swap is invisible to boundary checks.
        assert swapped == [True]
        assert result.success is True, result.diagnostics
        with open(
            os.path.join(result.work_dir, "xdp_entry.raw.ll"),
            encoding="utf-8",
        ) as handle:
            raw = handle.read()
        assert ("; stdlib-sha256:%s\n" % clean_std_hex) in raw, raw
        assert evil_std_hex not in raw, raw
        assert evil_cfg_hex not in raw, raw
        assert "; cfg-sha256:missing\n" not in raw, raw
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_snapshot_stdlib_configured_transient_swap_consumes_staged():
    # Configured-path variant of the transient-swap trace: the
    # binary-prefix payload is absent while modular.cfg selects
    # another existing directory. Capture must seal and stage the
    # configured bytes (never accept "missing" with live
    # consumption): verify(clean) -> swap -> consume -> restore ->
    # verify(clean) must still compile the captured bytes.
    parent = tempfile.mkdtemp(prefix="build-stdcfg-")
    manifest_path, out_dir = write_project(parent)
    bindir = tempfile.mkdtemp(prefix="fixture-bin-", dir=parent)
    write_executable(
        os.path.join(bindir, "mojo"), MOJO_STDLIB_FIXTURE
    )
    write_executable(os.path.join(bindir, "llc"), LLC_FIXTURE)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(parent, bindir)
    home = os.path.join(parent, "max")
    vendor = os.path.join(parent, "vendor", "lib")
    os.makedirs(vendor)
    os.makedirs(home)
    assert not os.path.exists(
        os.path.join(parent, "lib", "mojo", "std.mojoc")
    )
    cfg_path = os.path.join(home, "modular.cfg")
    std_path = os.path.join(vendor, "std.mojoc")
    clean_cfg = (
        "[mojo-max]\nimport_path = %s\n" % vendor
    ).encode("utf-8")
    clean_std = b"stdlib-configured-clean"
    with open(cfg_path, "wb") as handle:
        handle.write(clean_cfg)
    with open(std_path, "wb") as handle:
        handle.write(clean_std)
    clean_std_hex = hashlib.sha256(clean_std).hexdigest()
    evil_cfg = (
        "[mojo-max]\nimport_path = %s\n# evil\n" % vendor
    ).encode("utf-8")
    evil_std = b"stdlib-configured-EVIL"
    evil_std_hex = hashlib.sha256(evil_std).hexdigest()
    evil_cfg_hex = hashlib.sha256(evil_cfg).hexdigest()
    real_run_step = build_module._run_step
    swapped = []

    def raced(argv, *args, **kwargs):
        if not swapped:
            swapped.append(True)
            with open(cfg_path, "wb") as handle:
                handle.write(evil_cfg)
            with open(std_path, "wb") as handle:
                handle.write(evil_std)
            try:
                return real_run_step(argv, *args, **kwargs)
            finally:
                with open(cfg_path, "wb") as handle:
                    handle.write(clean_cfg)
                with open(std_path, "wb") as handle:
                    handle.write(clean_std)
        return real_run_step(argv, *args, **kwargs)

    build_module._run_step = raced
    try:
        with fixture_env(MODULAR_HOME=home):
            result = build_project(
                BuildRequest(
                    manifest_path=manifest_path,
                    out_dir=out_dir,
                    adapter_path=adapter,
                    search_paths=(bindir,),
                    lockfile_path=lockfile,
                    save_temps=True,
                )
            )
    finally:
        build_module._run_step = real_run_step
    try:
        assert swapped == [True]
        assert result.success is True, result.diagnostics
        with open(
            os.path.join(result.work_dir, "xdp_entry.raw.ll"),
            encoding="utf-8",
        ) as handle:
            raw = handle.read()
        assert ("; stdlib-sha256:%s\n" % clean_std_hex) in raw, raw
        assert evil_std_hex not in raw, raw
        assert evil_cfg_hex not in raw, raw
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_snapshot_stdlib_configured_selection_preserved():
    # When both the binary-prefix payload (library A) and the
    # modular.cfg-selected payload (library B) exist, staging
    # must preserve the configuration's selection: compilation
    # consumes B byte-for-byte, never redirected to A.
    parent = tempfile.mkdtemp(prefix="build-stdsel-")
    manifest_path, out_dir = write_project(parent)
    bindir = tempfile.mkdtemp(prefix="fixture-bin-", dir=parent)
    write_executable(
        os.path.join(bindir, "mojo"), MOJO_STDLIB_FIXTURE
    )
    write_executable(os.path.join(bindir, "llc"), LLC_FIXTURE)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(parent, bindir)
    home = os.path.join(parent, "max")
    prefix_lib = os.path.join(parent, "lib", "mojo")
    vendor = os.path.join(parent, "vendor", "lib")
    os.makedirs(prefix_lib)
    os.makedirs(vendor)
    os.makedirs(home)
    lib_a = b"stdlib-library-A"
    lib_b = b"stdlib-library-B"
    with open(os.path.join(prefix_lib, "std.mojoc"), "wb") as handle:
        handle.write(lib_a)
    with open(os.path.join(vendor, "std.mojoc"), "wb") as handle:
        handle.write(lib_b)
    with open(os.path.join(home, "modular.cfg"), "wb") as handle:
        handle.write(
            ("[mojo-max]\nimport_path = %s\n" % vendor).encode(
                "utf-8"
            )
        )
    hex_a = hashlib.sha256(lib_a).hexdigest()
    hex_b = hashlib.sha256(lib_b).hexdigest()
    with fixture_env(MODULAR_HOME=home):
        result = build_project(
            BuildRequest(
                manifest_path=manifest_path,
                out_dir=out_dir,
                adapter_path=adapter,
                search_paths=(bindir,),
                lockfile_path=lockfile,
                save_temps=True,
            )
        )
    try:
        assert result.success is True, result.diagnostics
        with open(
            os.path.join(result.work_dir, "xdp_entry.raw.ll"),
            encoding="utf-8",
        ) as handle:
            raw = handle.read()
        assert ("; stdlib-sha256:%s\n" % hex_b) in raw, raw
        assert hex_a not in raw, raw
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_snapshot_stdlib_configured_missing_payload_rejected():
    # A modular.cfg selecting a directory without the payload is
    # a configuration whose consumption cannot be bound: capture
    # rejects it (MBPF106) instead of accepting "missing" while
    # the frontend would still consume the live path.
    parent = tempfile.mkdtemp(prefix="build-stdcfgmiss-")
    manifest_path, out_dir = write_project(parent)
    bindir = tempfile.mkdtemp(prefix="fixture-bin-", dir=parent)
    write_executable(
        os.path.join(bindir, "mojo"), MOJO_STDLIB_FIXTURE
    )
    write_executable(os.path.join(bindir, "llc"), LLC_FIXTURE)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(parent, bindir)
    home = os.path.join(parent, "max")
    vendor = os.path.join(parent, "vendor", "lib")
    os.makedirs(vendor)
    os.makedirs(home)
    with open(os.path.join(home, "modular.cfg"), "wb") as handle:
        handle.write(
            ("[mojo-max]\nimport_path = %s\n" % vendor).encode(
                "utf-8"
            )
        )
    with fixture_env(MODULAR_HOME=home):
        result = build_project(
            BuildRequest(
                manifest_path=manifest_path,
                out_dir=out_dir,
                adapter_path=adapter,
                search_paths=(bindir,),
                lockfile_path=lockfile,
            )
        )
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF106"]
    assert "std.mojoc" in result.diagnostics[0].explanation


def test_spawn_env_builder_is_pure_and_checked():
    # The spawn environment is a pure function of one ambient
    # snapshot plus the snapshot pin: compiler-material names
    # come only from the pin, and the checker rejects any leak.
    ambient = {
        "PATH": "/ambient/bin",
        "MODULAR_HOME": "/ambient/max",
        "MOJO_SNEAKY": "1",
        "HOME": "/home/fixture",
    }
    pinned = {"PATH": "/pinned/bin"}
    child = inputs_module.build_spawn_env(
        ambient=ambient,
        admission_unset=("LD_PRELOAD",),
        admission_set=(("PYTHONSAFEPATH", "1"),),
        pinned=pinned,
        unset=("MODULAR_HOME",),
        redirect=None,
    )
    assert child["PATH"] == "/pinned/bin", child
    assert "MODULAR_HOME" not in child, child
    assert "MOJO_SNEAKY" not in child, child
    assert child["HOME"] == "/home/fixture", child
    assert child["PYTHONSAFEPATH"] == "1", child
    assert ambient == {
        "PATH": "/ambient/bin",
        "MODULAR_HOME": "/ambient/max",
        "MOJO_SNEAKY": "1",
        "HOME": "/home/fixture",
    }, ambient
    assert inputs_module.check_spawn_env(
        child, pinned=pinned, unset=("MODULAR_HOME",),
        redirect=None,
    ) is None
    assert inputs_module.check_spawn_env(
        dict(child, MOJO_SNEAKY="1"), pinned=pinned,
        unset=("MODULAR_HOME",), redirect=None,
    ) is not None
    assert inputs_module.check_spawn_env(
        dict(child, PATH="/ambient/bin"), pinned=pinned,
        unset=("MODULAR_HOME",), redirect=None,
    ) is not None
    redirected = inputs_module.build_spawn_env(
        ambient=ambient,
        admission_unset=(),
        admission_set=(),
        pinned=pinned,
        unset=("MODULAR_HOME",),
        redirect={"MODULAR_HOME": "/staged/home"},
    )
    assert redirected["MODULAR_HOME"] == "/staged/home"
    assert inputs_module.check_spawn_env(
        redirected, pinned=pinned, unset=("MODULAR_HOME",),
        redirect={"MODULAR_HOME": "/staged/home"},
    ) is None


def test_stdlib_cfg_repoint_targets_staged_payload():
    # The staged modular.cfg is the captured bytes with only the
    # import_path value re-pointed at the staged payload dir; a
    # config without the key stages verbatim (no binding).
    cfg = (
        b"[max]\npath = /live/env\n\n"
        b"[mojo-max]\nimport_path = /live/env/lib/mojo\n"
        b"driver_path = /live/env/bin/mojo\n"
    )
    rewritten = inputs_module.repoint_cfg_import_path(
        cfg, "/staged/stdlib"
    )
    assert rewritten == (
        b"[max]\npath = /live/env\n\n"
        b"[mojo-max]\nimport_path = /staged/stdlib\n"
        b"driver_path = /live/env/bin/mojo\n"
    ), rewritten
    assert inputs_module.repoint_cfg_import_path(
        b"[mojo-max]\nno_key_here = 1\n", "/staged/stdlib"
    ) is None
    # An empty selection stages verbatim like a missing key: the
    # frontend consumes nothing either way, so there is nothing
    # to re-point at the staged payload.
    assert inputs_module.repoint_cfg_import_path(
        b"[mojo-max]\nimport_path = \n", "/staged/stdlib"
    ) is None


def test_cfg_import_path_shared_parse_rewrite_rule():
    # One shared line-splitting + key-matching rule drives both the
    # parser and the rewriter: CR, LF and CRLF are all boundaries,
    # the key match is case-insensitive exact, and anything the
    # parser accepts the rewriter redirects -- the rewritten config
    # re-parses to exactly the staged directory.
    live = "/v/alternate/lib/mojo"
    staged = "/staged/payload"
    selecting = [
        # The reviewer's 9(c) trace, byte for byte.
        b"[mojo-max]\rimport_path = " + live.encode() + b"\r",
        b"[mojo-max]\r\nimport_path = " + live.encode() + b"\r\n",
        b"[mojo-max]\nimport_path = " + live.encode() + b"\n",
        b"[mojo-max]\n  Import_Path  =  " + live.encode() + b"  \n",
        b"[mojo-max]\nIMPORT_PATH=" + live.encode() + b"\n",
        b"[mojo-max]\nimport_path = " + live.encode(),
    ]
    for cfg in selecting:
        assert inputs_module.parse_cfg_import_path(cfg) == live, cfg
        rewritten = inputs_module.repoint_cfg_import_path(cfg, staged)
        assert rewritten is not None, cfg
        assert live.encode("utf-8") not in rewritten, rewritten
        assert inputs_module.parse_cfg_import_path(
            rewritten
        ) == staged, rewritten
    # CR-only input stays CR-only: rewriting changes values only.
    rewritten = inputs_module.repoint_cfg_import_path(
        selecting[0], staged
    )
    assert b"\n" not in rewritten, rewritten
    assert rewritten == (
        b"[mojo-max]\rimport_path = " + staged.encode() + b"\r"
    ), rewritten
    ignoring = [
        b"[mojo-max]\rimport_path_alias = " + live.encode() + b"\r",
        b"[mojo-max]\nimport_path_alias = " + live.encode() + b"\n",
        b"[mojo-max]\nimport_path = \n",
        b"[mojo-max]\nno_key_here = 1\n",
        b"[mojo-max]\nimport_path\n",
        b"",
    ]
    for cfg in ignoring:
        assert inputs_module.parse_cfg_import_path(cfg) is None, cfg
        assert inputs_module.repoint_cfg_import_path(
            cfg, staged
        ) is None, cfg


def test_cfg_import_path_alias_line_left_verbatim():
    # import_path_alias is inert on both sides of the shared rule
    # (the pinned frontend ignores it too): the parser skips it and
    # the rewriter preserves its line byte for byte while
    # redirecting the exact key.
    live = "/live/vendor/lib"
    staged = "/staged/payload"
    alias_line = b"import_path_alias = /live/aliased/lib\n"
    cfg = (
        b"[mojo-max]\n" + alias_line
        + b"import_path = " + live.encode() + b"\n"
    )
    assert inputs_module.parse_cfg_import_path(cfg) == live, cfg
    rewritten = inputs_module.repoint_cfg_import_path(cfg, staged)
    assert rewritten == (
        b"[mojo-max]\n" + alias_line
        + b"import_path = " + staged.encode() + b"\n"
    ), rewritten


def test_cfg_import_path_last_line_wins():
    # Duplicate keys: the pinned frontend resolves the LAST
    # import_path line (see the sibling frontend oracle test),
    # so the shared rule does the same -- including a trailing
    # empty line, which clears the selection. The rewriter still
    # redirects every non-empty occurrence, so all lines agree
    # post-rewrite.
    stale = "/stale/lib/mojo"
    fresh = "/fresh/lib/mojo"
    staged = "/staged/payload"
    cfg = (
        b"[mojo-max]\nimport_path = " + stale.encode()
        + b"\nimport_path = " + fresh.encode() + b"\n"
    )
    assert inputs_module.parse_cfg_import_path(cfg) == fresh, cfg
    rewritten = inputs_module.repoint_cfg_import_path(cfg, staged)
    assert stale.encode("utf-8") not in rewritten, rewritten
    assert fresh.encode("utf-8") not in rewritten, rewritten
    assert inputs_module.parse_cfg_import_path(
        rewritten
    ) == staged, rewritten
    cleared = (
        b"[mojo-max]\nimport_path = " + fresh.encode()
        + b"\nimport_path = \n"
    )
    assert inputs_module.parse_cfg_import_path(cleared) is None


def test_snapshot_trailing_empty_cfg_consumes_nothing():
    # Consumption half of the trailing-empty rule: a nonempty
    # key followed by an empty key selects nothing (production
    # parser resolves None), so the frontend must consume no
    # stdlib bytes -- the consumption fixture honors the same
    # last-key-wins/trailing-empty-clears rule instead of
    # reading std.mojoc through the first key.
    parent = tempfile.mkdtemp(prefix="build-stdclear-")
    manifest_path, out_dir = write_project(parent)
    bindir = tempfile.mkdtemp(prefix="fixture-bin-", dir=parent)
    write_executable(
        os.path.join(bindir, "mojo"), MOJO_STDLIB_FIXTURE
    )
    write_executable(os.path.join(bindir, "llc"), LLC_FIXTURE)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(parent, bindir)
    home = os.path.join(parent, "max")
    vendor = os.path.join(parent, "vendor", "lib")
    os.makedirs(vendor)
    os.makedirs(home)
    assert not os.path.exists(
        os.path.join(parent, "lib", "mojo", "std.mojoc")
    )
    std_path = os.path.join(vendor, "std.mojoc")
    clean_cfg = (
        "[mojo-max]\nimport_path = %s\nimport_path = \n" % vendor
    ).encode("utf-8")
    assert inputs_module.parse_cfg_import_path(clean_cfg) is None
    clean_std = b"stdlib-cleared-live-payload"
    with open(os.path.join(home, "modular.cfg"), "wb") as handle:
        handle.write(clean_cfg)
    with open(std_path, "wb") as handle:
        handle.write(clean_std)
    live_hex = hashlib.sha256(clean_std).hexdigest()
    with fixture_env(MODULAR_HOME=home):
        result = build_project(
            BuildRequest(
                manifest_path=manifest_path,
                out_dir=out_dir,
                adapter_path=adapter,
                search_paths=(bindir,),
                lockfile_path=lockfile,
                save_temps=True,
            )
        )
    try:
        assert result.success is True, result.diagnostics
        with open(
            os.path.join(result.work_dir, "xdp_entry.raw.ll"),
            encoding="utf-8",
        ) as handle:
            raw = handle.read()
        assert "; stdlib-sha256:missing\n" in raw, raw
        assert live_hex not in raw, raw
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_snapshot_cr_cfg_transient_swap_consumes_staged():
    # CR-only variant of the configured transient-swap trace: the
    # parser accepts the live directory, so the rewriter must
    # redirect it -- verify(clean) -> swap -> consume -> restore ->
    # verify(clean) must still compile the captured bytes, never
    # the swapped live payload.
    parent = tempfile.mkdtemp(prefix="build-stdcr-")
    manifest_path, out_dir = write_project(parent)
    bindir = tempfile.mkdtemp(prefix="fixture-bin-", dir=parent)
    write_executable(
        os.path.join(bindir, "mojo"), MOJO_STDLIB_FIXTURE
    )
    write_executable(os.path.join(bindir, "llc"), LLC_FIXTURE)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(parent, bindir)
    home = os.path.join(parent, "max")
    vendor = os.path.join(parent, "vendor", "lib")
    os.makedirs(vendor)
    os.makedirs(home)
    cfg_path = os.path.join(home, "modular.cfg")
    std_path = os.path.join(vendor, "std.mojoc")
    clean_cfg = (
        "[mojo-max]\rimport_path = %s\r" % vendor
    ).encode("utf-8")
    clean_std = b"stdlib-cr-clean"
    with open(cfg_path, "wb") as handle:
        handle.write(clean_cfg)
    with open(std_path, "wb") as handle:
        handle.write(clean_std)
    clean_std_hex = hashlib.sha256(clean_std).hexdigest()
    evil_cfg = (
        "[mojo-max]\rimport_path = %s\r# evil\r" % vendor
    ).encode("utf-8")
    evil_std = b"stdlib-cr-EVIL"
    evil_std_hex = hashlib.sha256(evil_std).hexdigest()
    evil_cfg_hex = hashlib.sha256(evil_cfg).hexdigest()
    real_run_step = build_module._run_step
    swapped = []

    def raced(argv, *args, **kwargs):
        if not swapped:
            swapped.append(True)
            with open(cfg_path, "wb") as handle:
                handle.write(evil_cfg)
            with open(std_path, "wb") as handle:
                handle.write(evil_std)
            try:
                return real_run_step(argv, *args, **kwargs)
            finally:
                with open(cfg_path, "wb") as handle:
                    handle.write(clean_cfg)
                with open(std_path, "wb") as handle:
                    handle.write(clean_std)
        return real_run_step(argv, *args, **kwargs)

    build_module._run_step = raced
    try:
        with fixture_env(MODULAR_HOME=home):
            result = build_project(
                BuildRequest(
                    manifest_path=manifest_path,
                    out_dir=out_dir,
                    adapter_path=adapter,
                    search_paths=(bindir,),
                    lockfile_path=lockfile,
                    save_temps=True,
                )
            )
    finally:
        build_module._run_step = real_run_step
    try:
        assert swapped == [True]
        assert result.success is True, result.diagnostics
        with open(
            os.path.join(result.work_dir, "xdp_entry.raw.ll"),
            encoding="utf-8",
        ) as handle:
            raw = handle.read()
        assert ("; stdlib-sha256:%s\n" % clean_std_hex) in raw, raw
        assert evil_std_hex not in raw, raw
        assert evil_cfg_hex not in raw, raw
    finally:
        if result.work_dir is not None:
            shutil.rmtree(result.work_dir, ignore_errors=True)


def test_snapshot_unredirected_staged_cfg_rejected():
    # Defense in depth: if the staged modular.cfg still selects a
    # live directory (here simulated by a rewriter that stages the
    # config unchanged), capture rejects (MBPF106) instead of
    # compiling against unbound live bytes.
    parent = tempfile.mkdtemp(prefix="build-stdcfgredir-")
    manifest_path, out_dir = write_project(parent)
    bindir = tempfile.mkdtemp(prefix="fixture-bin-", dir=parent)
    write_executable(
        os.path.join(bindir, "mojo"), MOJO_STDLIB_FIXTURE
    )
    write_executable(os.path.join(bindir, "llc"), LLC_FIXTURE)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(parent, bindir)
    home = os.path.join(parent, "max")
    vendor = os.path.join(parent, "vendor", "lib")
    os.makedirs(vendor)
    os.makedirs(home)
    with open(os.path.join(home, "modular.cfg"), "wb") as handle:
        handle.write(
            ("[mojo-max]\nimport_path = %s\n" % vendor).encode(
                "utf-8"
            )
        )
    with open(os.path.join(vendor, "std.mojoc"), "wb") as handle:
        handle.write(b"stdlib-redir-clean")
    real_repoint = inputs_module.repoint_cfg_import_path
    inputs_module.repoint_cfg_import_path = (
        lambda cfg, staged: cfg
    )
    try:
        with fixture_env(MODULAR_HOME=home):
            result = build_project(
                BuildRequest(
                    manifest_path=manifest_path,
                    out_dir=out_dir,
                    adapter_path=adapter,
                    search_paths=(bindir,),
                    lockfile_path=lockfile,
                )
            )
    finally:
        inputs_module.repoint_cfg_import_path = real_repoint
    assert result.success is False
    assert [item.code for item in result.diagnostics] == ["MBPF106"]
    assert "staged" in result.diagnostics[0].explanation


def test_snapshot_dropped_staged_cfg_selection_rejected():
    # Round-6 9(c): the staged-config re-resolution check must bind
    # to the ORIGINAL selection. When the captured config selected
    # the live payload but the staged bytes resolve to None (here a
    # fault-injected rewriter drops the import_path line or empties
    # its value), capture must reject (MBPF106) instead of staging
    # an unbound config -- pre-fix both faults passed capture and
    # verify while consumption reported stdlib-sha256:missing.
    def drop_line(cfg, _staged):
        kept = []
        for raw in cfg.split(b"\n"):
            key, sep, _value = (
                raw.decode("utf-8", "replace").strip().partition("=")
            )
            if sep and key.strip().lower() == "import_path":
                continue
            kept.append(raw)
        return b"\n".join(kept)

    def empty_value(cfg, _staged):
        out = []
        for raw in cfg.split(b"\n"):
            key, sep, _value = (
                raw.decode("utf-8", "replace").strip().partition("=")
            )
            if sep and key.strip().lower() == "import_path":
                prefix, _, _ = raw.partition(b"=")
                out.append(prefix + b"=")
            else:
                out.append(raw)
        return b"\n".join(out)

    for faulty in (drop_line, empty_value):
        parent = tempfile.mkdtemp(prefix="build-stdcfgdrop-")
        try:
            manifest_path, out_dir = write_project(parent)
            bindir = tempfile.mkdtemp(
                prefix="fixture-bin-", dir=parent
            )
            write_executable(
                os.path.join(bindir, "mojo"), MOJO_STDLIB_FIXTURE
            )
            write_executable(
                os.path.join(bindir, "llc"), LLC_FIXTURE
            )
            adapter = os.path.join(parent, "adapter-ok.py")
            write_executable(adapter, ADAPTER_OK_FIXTURE)
            lockfile = write_lockfile(parent, bindir)
            home = os.path.join(parent, "max")
            vendor = os.path.join(parent, "vendor", "lib")
            os.makedirs(vendor)
            os.makedirs(home)
            with open(
                os.path.join(home, "modular.cfg"), "wb"
            ) as handle:
                handle.write(
                    (
                        "[mojo-max]\nimport_path = %s\n" % vendor
                    ).encode("utf-8")
                )
            with open(
                os.path.join(vendor, "std.mojoc"), "wb"
            ) as handle:
                handle.write(b"stdlib-drop-clean")
            real_repoint = inputs_module.repoint_cfg_import_path
            inputs_module.repoint_cfg_import_path = faulty
            try:
                with fixture_env(MODULAR_HOME=home):
                    result = build_project(
                        BuildRequest(
                            manifest_path=manifest_path,
                            out_dir=out_dir,
                            adapter_path=adapter,
                            search_paths=(bindir,),
                            lockfile_path=lockfile,
                        )
                    )
            finally:
                inputs_module.repoint_cfg_import_path = real_repoint
            assert result.success is False, faulty.__name__
            assert [
                item.code for item in result.diagnostics
            ] == ["MBPF106"], faulty.__name__
        finally:
            shutil.rmtree(parent, ignore_errors=True)


def test_inspect_positional_object_parses():
    args = cli_module.build_parser().parse_args(["inspect", "build/x.o"])
    assert args.object is None
    assert args.object_pos == "build/x.o"


def test_verify_positional_object_parses():
    args = cli_module.build_parser().parse_args(
        ["verify", "build/x.o", "--kernel"]
    )
    assert args.object is None
    assert args.object_pos == "build/x.o"


def test_object_flag_and_positional_conflict_is_usage_error():
    assert (
        cli_module.main(["inspect", "--object", "a.o", "b.o"])
        == cli_module.EXIT_USAGE
    )
    assert (
        cli_module.main(["verify", "--object", "a.o", "b.o", "--kernel"])
        == cli_module.EXIT_USAGE
    )


def _write_garbage_object():
    import tempfile

    fd, path = tempfile.mkstemp(prefix="mojobpf-garbage-", suffix=".bpf.o")
    with os.fdopen(fd, "wb") as handle:
        handle.write(b"not an elf image, only findings follow....")
    return path


def test_inspect_findings_exit_nonzero():
    path = _write_garbage_object()
    try:
        assert (
            cli_module.main(["inspect", path])
            == cli_module.EXIT_COMPILE
        )
    finally:
        os.remove(path)


def test_inspect_report_only_exits_zero():
    path = _write_garbage_object()
    try:
        assert (
            cli_module.main(["inspect", path, "--report-only"])
            == cli_module.EXIT_OK
        )
    finally:
        os.remove(path)


def test_inspect_clean_exits_zero():
    parent = tempfile.mkdtemp(prefix="cli-inspect-clean-")
    obj = _fixture_built_object(parent).artifacts[0].path
    code, _, _ = run_cli(["inspect", obj])
    assert code == 0


def _write_check_project(parent):
    manifest_path, _ = write_project(parent)
    bindir = write_tool_bindir(
        parent,
        extra=(
            ("bpftool", "bpftool v0.0-fixture"),
            ("python3", "Python 9.9.9-fixture"),
        ),
    )
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    lockfile = write_lockfile(
        parent, bindir, tools_pinned=("mojo", "llc", "bpftool", "python")
    )
    return manifest_path, bindir, adapter, lockfile


def test_check_compiles_valid_manifest():
    parent = tempfile.mkdtemp(prefix="cli-check-compile-")
    manifest_path, bindir, adapter, lockfile = _write_check_project(parent)
    code, out, _ = run_cli(
        [
            "check", "--manifest", manifest_path,
            "--lockfile", lockfile, "--adapter", adapter,
        ],
        path=bindir,
    )
    assert code == 0, out
    assert "compile OK" in out


def test_check_rejects_uncompilable_source():
    parent = tempfile.mkdtemp(prefix="cli-check-uncompilable-")
    manifest_path, bindir, adapter, lockfile = _write_check_project(parent)
    with fixture_env(MOJOBPF_FIXTURE_MOJO="crash"):
        code, _, err = run_cli(
            [
                "check", "--manifest", manifest_path,
                "--lockfile", lockfile, "--adapter", adapter,
            ],
            path=bindir,
        )
    assert code == cli_module.EXIT_COMPILE
    assert "MBPF106" in err


def test_check_json_carries_compile_verdict():
    parent = tempfile.mkdtemp(prefix="cli-check-json-")
    manifest_path, bindir, adapter, lockfile = _write_check_project(parent)
    code, out, _ = run_cli(
        [
            "check", "--manifest", manifest_path,
            "--lockfile", lockfile, "--adapter", adapter, "--json",
        ],
        path=bindir,
    )
    assert code == 0, out
    document = json.loads(out)
    assert document["compile"]["success"] is True
    code, out, _ = run_cli(
        ["check", "--manifest", manifest_path, "--json"], path=bindir
    )
    assert code == 0, out
    assert json.loads(out)["compile"] is None


def _write_fixture_suite(root, name, passing=True):
    suitedir = os.path.join(root, name)
    os.makedirs(suitedir)
    body = (
        "def test_tiny_ok():\n    assert True\n"
        if passing
        else "def test_tiny_bad():\n    assert False\n"
    )
    with open(os.path.join(suitedir, "test_tiny.py"), "w") as handle:
        handle.write(body)
    return suitedir


def test_test_missing_suite_is_usage_error():
    code, _, err = run_cli(["test", "--suite", "no-such-suite"])
    assert code == cli_module.EXIT_USAGE
    assert "no-such-suite" in err
    code, _, err = run_cli(["test", "--suite", "../escape"])
    assert code == cli_module.EXIT_USAGE


def test_test_kernel_require_without_capability_is_environment_error():
    parent = tempfile.mkdtemp(prefix="cli-test-kernel-")
    root = os.path.join(parent, "tests")
    _write_fixture_suite(root, "kernel")
    empty = tempfile.mkdtemp(prefix="empty-path-", dir=parent)
    code, _, err = run_cli(
        ["test", "--suite", "kernel", "--require-kernel",
         "--suite-path", root],
        path=empty,
    )
    assert code == cli_module.EXIT_ENVIRONMENT
    assert "vng" in err


def test_test_compile_suite_runs():
    parent = tempfile.mkdtemp(prefix="cli-test-compile-")
    root = os.path.join(parent, "tests")
    _write_fixture_suite(root, "compile")
    code, out, _ = run_cli(
        ["test", "--suite", "compile", "--suite-path", root]
    )
    assert code == 0, out


def test_test_failing_suite_exits_test_failure():
    parent = tempfile.mkdtemp(prefix="cli-test-fail-")
    root = os.path.join(parent, "tests")
    _write_fixture_suite(root, "compile", passing=False)
    code, _, err = run_cli(
        ["test", "--suite", "compile", "--suite-path", root]
    )
    assert code == cli_module.EXIT_TEST
    assert "failed" in err


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

