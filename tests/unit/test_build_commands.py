# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for build orchestration, the CLI and the adapter boundary.

Covers ``build_project`` (success, failure classification, bounded
logs, timeouts, failure safety), the versioned JSON adapter service
(request validation, rejection propagation, transform fidelity), and
the minimal CLI (build/check/doctor exits). Deterministic on any host:
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

from mojobpf import build as build_module  # noqa: E402
from mojobpf import cli as cli_module  # noqa: E402
from mojobpf import evidence as evidence_module  # noqa: E402
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

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
SERVICE = os.path.join(REPO_ROOT, "compiler", "adapter_service.py")
SIBLING = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")

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
BTF_BYTES = b"\\x00" * 32


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
        MOJOBPF_FIXTURE_MOJO="mapmode", MOJOBPF_FIXTURE_LLC="mapshape"
    ):
        result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is True, result.diagnostics
    frontend = result.commands[0].argv
    flag = frontend.index("-I")
    sdk = frontend[flag + 1]
    assert os.path.isdir(sdk)
    assert sdk.replace(os.sep, "/").endswith("mojobpf/resources/sdk")


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
    assert len(SUPPORTED_ENTRY_ROOTS) == 1
    assert len(SUPPORTED_MAP_NAMES) == 1
    assert (
        "@%s" % SUPPORTED_ENTRY_ROOTS[0]
    ) in adapter_source, "entry root the adapter never emits"
    assert (
        "@%s" % SUPPORTED_MAP_NAMES[0]
    ) in adapter_source, "map name the adapter never emits"


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
    assert [item.code for item in result.diagnostics] == ["MBPF103"]
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
        MOJOBPF_FIXTURE_MOJO="mapmode", MOJOBPF_FIXTURE_LLC="mapshape"
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


def test_service_transform_matches_sibling_exactly():
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
    request = valid_service_request(parent, ir_text=ir_text)
    code, response = run_service(request, parent)
    assert code == 0, response
    assert response["ok"] is True
    assert response["diagnostics"] == []
    adapted_path = response["outputs"]["adapted_ir"]
    with open(adapted_path, encoding="utf-8") as handle:
        assert handle.read() == expected


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
    code, out, _ = run_cli(
        ["check", "--manifest", manifest_path,
         "--lockfile", lockfile],
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
    real_replace = os.replace
    calls = []

    def interrupting(src, dst):
        # Real rename followed immediately by interruption: the
        # first publication rename lands, then the build dies.
        calls.append((src, dst))
        real_replace(src, dst)
        if len(calls) == 1:
            raise KeyboardInterrupt("fixture interrupt")
        return None

    os.replace = interrupting
    caught = None
    try:
        build_fixture(manifest_path, out_dir, parent)
    except KeyboardInterrupt as exc:
        caught = exc
    else:
        raise AssertionError("expected KeyboardInterrupt")
    finally:
        os.replace = real_replace
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


def _direct_run():
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

