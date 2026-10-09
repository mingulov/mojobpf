# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for artifact publication, provenance and licensing.

Covers the license layer (SPDX parsing, source-grant validation,
declaration-pair mapping, GPL requirements), stable evidence and
cache keys, atomic publication (success, mid-publish rollback,
fail-after-success sequences), hardened publication (owned output
directories, injected symlink/directory swaps, concurrent
publishers, backup/replace-boundary failures), and sidecar
qualification (object/input/run-plan binding with fail-closed
schema and hash validation). Deterministic on any host: builds run
through fixture tools resolved via ``search_paths``; only the audit
and adapter siblings run for real (both need just Python). The
hardening tests need POSIX file locking and directory file
descriptors (the project's Linux host scope).

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3
tests/unit/test_artifact_publication.py``).
"""

import contextlib
import dataclasses
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

from mojobpf import __version__ as TOOL_VERSION  # noqa: E402
from mojobpf import evidence as evidence_module  # noqa: E402
from mojobpf import inputs as inputs_module  # noqa: E402
from mojobpf import inspect as inspect_module  # noqa: E402
from mojobpf.build import (  # noqa: E402
    BuildArtifact,
    BuildProvenance,
    BuildRequest,
    BuildResult,
    CommandRecord,
    _sdk_dir,
    build_project,
)
from mojobpf.diagnostics import Diagnostic  # noqa: E402
from mojobpf.manifest import (  # noqa: E402
    lookup_profile,
    parse_manifest,
    profile_digest,
)
from mojobpf.sdk import SDK_VERSION  # noqa: E402

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
AUDIT = os.path.join(REPO_ROOT, "compiler", "audit.py")
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
SCHEMA_DIR = os.path.join(REPO_ROOT, "schemas")

APACHE = "Apache-2.0 WITH LLVM-exception"
APACHE_BYTES = b"Apache-2.0 WITH LLVM-exception\x00"

MANIFEST_TOML = """\
schema_version = 1
[project]
name = "demo"
[target]
profile = "linux-bpfel-v3"
[artifact]
name = "demo"
source_license = "Apache-2.0 WITH LLVM-exception"
kernel_license = "Apache-2.0 WITH LLVM-exception"
[[programs]]
source = "prog.mojo"
entry = "xdp_entry"
program_type = "xdp"
section = "xdp"
"""

SOURCE_MOJO = (
    "# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception\n"
    "# fixture program source\n"
)

MOJO_FIXTURE = """\
#!{python}
import os
import sys


def main(argv):
    if argv[1:] == ["--version"]:
        print("Mojo 9.9.9 (fixture)")
        return 0
    if os.environ.get("MOJOBPF_PUB_MOJO") == "crash":
        sys.stderr.write("fixture frontend boom\\\\n")
        return 3
    out = argv[argv.index("-o") + 1]
    with open(out, "w", encoding="utf-8") as handle:
        handle.write("; fixture raw IR\\\\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
"""

LLC_FIXTURE = """\
#!{python}
import os
import struct
import sys

LICENSE = b"Apache-2.0 WITH LLVM-exception\\x00"
XDP_CODE = (
    b"\\xb0\\x00\\x00\\x00\\x02\\x00\\x00\\x00"
    b"\\x95\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
)


def minimal_elf(code):
    shstr = b"\\x00xdp\\x00license\\x00.shstrtab\\x00"
    ehsize = 64
    shoff = ehsize
    shentsize, shnum, shstrndx = 64, 4, 3
    xdp_off = shoff + shentsize * shnum
    lic_off = xdp_off + len(code)
    str_off = lic_off + len(LICENSE)
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
    strsec = struct.pack(
        "<IIQQQQIIQQ", 13, 3, 0, 0, str_off, len(shstr),
        0, 0, 1, 0,
    )
    return eh + null + xdp + lic + strsec + code + LICENSE + shstr


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


def main(argv):
    if argv[1:] == ["--version"]:
        print("llc 9.9.9 (fixture)")
        return 0
    out = argv[argv.index("-o") + 1]
    if os.environ.get("MOJOBPF_PUB_LLC") == "maps":
        payload = minimal_map_elf(XDP_CODE)
    else:
        payload = minimal_elf(XDP_CODE)
    with open(out, "wb") as handle:
        handle.write(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
"""

ADAPTER_FIXTURE = """\
#!{python}
import json
import os
import sys


def main(argv):
    req_path = argv[argv.index("--request") + 1]
    resp_path = argv[argv.index("--response") + 1]
    with open(req_path, encoding="utf-8") as handle:
        request = json.load(handle)
    if os.environ.get("MOJOBPF_PUB_ADAPTER") == "reject":
        response = {
            "schema_version": 1,
            "ok": False,
            "outputs": {},
            "diagnostics": [
                {
                    "code": "MBPF301",
                    "stage": "adapter.transform",
                    "severity": "error",
                    "explanation": "fixture rejection",
                    "location": None,
                    "remedy": None,
                }
            ],
        }
    else:
        adapted = os.path.join(request["output_dir"], "adapted.ll")
        with open(request["input_ir"], encoding="utf-8") as handle:
            text = handle.read()
        with open(adapted, "w", encoding="utf-8") as handle:
            handle.write(text + "; fixture lowered\\\\n")
        response = {
            "schema_version": 1,
            "ok": True,
            "outputs": {"adapted_ir": adapted},
            "diagnostics": [],
        }
    with open(resp_path, "w", encoding="utf-8") as handle:
        json.dump(response, handle)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
"""


@contextlib.contextmanager
def _scratch():
    parent = tempfile.mkdtemp(prefix="mojobpf-pub-")
    try:
        yield parent
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def _write(path, content):
    mode = "wb" if isinstance(content, bytes) else "w"
    with open(path, mode) as handle:
        handle.write(content)


def _expect_error(func, code, stage):
    try:
        func()
    except (
        inspect_module.InspectionError,
        evidence_module.EvidenceError,
    ) as exc:
        assert exc.diagnostic.code == code, exc.diagnostic
        assert exc.diagnostic.stage == stage, exc.diagnostic
        return exc
    raise AssertionError("expected %s/%s, call succeeded" % (code, stage))


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fixture_tools(parent):
    bindir = os.path.join(parent, "bin")
    os.makedirs(bindir)
    for name, template in (
        ("mojo", MOJO_FIXTURE),
        ("llc", LLC_FIXTURE),
    ):
        path = os.path.join(bindir, name)
        _write(path, template.replace("{python}", sys.executable))
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    adapter = os.path.join(parent, "adapter.py")
    _write(adapter, ADAPTER_FIXTURE.replace("{python}", sys.executable))
    return bindir, adapter


def _lockfile(parent, bindir):
    """Pin the fixture mojo/llc; return the lockfile path."""
    tools = {}
    for tool in ("mojo", "llc"):
        path = os.path.join(bindir, tool)
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
    lock_path = os.path.join(parent, "toolchains.lock.json")
    _write(
        lock_path,
        json.dumps({"schema_version": 1, "tools": tools}),
    )
    return lock_path


def _project(parent, name="proj", programs=1):
    project = os.path.join(parent, name)
    os.makedirs(project)
    if programs == 1:
        _write(os.path.join(project, "mojobpf.toml"), MANIFEST_TOML)
        _write(os.path.join(project, "prog.mojo"), SOURCE_MOJO)
    else:
        head = "".join(MANIFEST_TOML.splitlines(keepends=True)[:9])
        body = ""
        for index in range(programs):
            entry = "xdp_entry" if index == 0 else "xdp_%d" % index
            source = "prog%d.mojo" % index
            body += (
                "[[programs]]\n"
                'source = "%s"\nentry = "%s"\n'
                'program_type = "xdp"\nsection = "xdp"\n'
                % (source, entry)
            )
            _write(os.path.join(project, source), SOURCE_MOJO)
        _write(os.path.join(project, "mojobpf.toml"), head + body)
    return project


@contextlib.contextmanager
def _env(**overrides):
    old = {key: os.environ.get(key) for key in overrides}
    os.environ.update(overrides)
    try:
        yield
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_spdx_plain_identifier():
    parsed = inspect_module.parse_spdx_expression("MIT")
    assert parsed.text == "MIT"
    assert parsed.licenses == frozenset({"MIT"})
    assert parsed.exceptions == frozenset()
    assert parsed.compound is False


def test_spdx_with_exception():
    parsed = inspect_module.parse_spdx_expression(APACHE)
    assert parsed.text == APACHE
    assert parsed.licenses == frozenset({"Apache-2.0"})
    assert parsed.exceptions == frozenset({"LLVM-exception"})
    assert parsed.compound is False
    squashed = inspect_module.parse_spdx_expression(
        "  Apache-2.0   WITH   LLVM-exception  "
    )
    assert squashed.text == APACHE


def test_spdx_compound_or_and_parens():
    parsed = inspect_module.parse_spdx_expression("GPL-2.0-only OR MIT")
    assert parsed.compound is True
    assert parsed.licenses == frozenset({"GPL-2.0-only", "MIT"})
    nested = inspect_module.parse_spdx_expression(
        "(MIT OR Apache-2.0) AND BSD-2-Clause"
    )
    assert nested.compound is True
    assert nested.licenses == frozenset(
        {"MIT", "Apache-2.0", "BSD-2-Clause"}
    )


def test_spdx_malformed_rejected():
    bad = [
        "",
        "   ",
        "AND MIT",
        "MIT OR",
        "MIT AND",
        "(MIT",
        "MIT)",
        "()",
        "MIT WITH",
        "WITH MIT",
        "MIT WITH AND",
        "mit or",
        "MIT OR MIT OR",
        "Apache 2.0",
        "MIT!",
    ]
    for text in bad:
        _expect_error(
            lambda t=text: inspect_module.parse_spdx_expression(t),
            "MBPF701",
            "inspect.license",
        )
    for text in (None, 123, b"MIT"):
        _expect_error(
            lambda t=text: inspect_module.parse_spdx_expression(t),
            "MBPF701",
            "inspect.license",
        )


def test_source_grants_homogeneous_ok():
    validate = inspect_module.validate_source_grants
    extra_type = inspect_module.ExtraGrant
    with _scratch() as parent:
        first = os.path.join(parent, "first.mojo")
        second = os.path.join(parent, "second.mojo")
        sdk = os.path.join(parent, "sdk.mojo")
        notice = os.path.join(parent, "LICENSE")
        _write(first, SOURCE_MOJO)
        _write(second, SOURCE_MOJO + "# more\n")
        _write(sdk, SOURCE_MOJO)
        _write(notice, "Apache License full text fixture\n")
        record = validate(
            APACHE,
            [first, second],
            sdk_sources=[sdk],
            extra_grants=[
                extra_type("project license text", notice, APACHE),
                extra_type("vendored header", second, None),
            ],
            project_dir=parent,
        )
    assert record.source_license == APACHE
    assert [g.path for g in record.programs] == [
        "first.mojo",
        "second.mojo",
    ]
    assert [g.path for g in record.sdk] == ["sdk.mojo"]
    assert [g.path for g in record.extra] == ["LICENSE", "second.mojo"]
    for grant in record.programs + record.sdk + record.extra:
        assert grant.spdx == APACHE
        assert len(grant.sha256) == 64
    expected = hashlib.sha256(SOURCE_MOJO.encode()).hexdigest()
    assert record.programs[0].sha256 == expected
    assert record.programs[1].size == len(
        (SOURCE_MOJO + "# more\n").encode()
    )
    assert record.imports == ()
    assert record.to_dict()["imports"] == []
    assert set(record.to_dict()) == {
        "source_license",
        "programs",
        "imports",
        "sdk",
        "extra",
        "stdlib_note",
    }


def test_source_grants_header_mismatch():
    with _scratch() as parent:
        path = os.path.join(parent, "prog.mojo")
        _write(path, "# SPDX-License-Identifier: MIT\n")
        exc = _expect_error(
            lambda: inspect_module.validate_source_grants(
                APACHE, [path], project_dir=parent
            ),
            "MBPF702",
            "inspect.license",
        )
    assert "MIT" in exc.diagnostic.explanation


def test_source_grants_missing_header():
    with _scratch() as parent:
        path = os.path.join(parent, "prog.mojo")
        _write(path, "# no license tag here\n")
        _expect_error(
            lambda: inspect_module.validate_source_grants(
                APACHE, [path], project_dir=parent
            ),
            "MBPF707",
            "inspect.license",
        )


def test_source_grants_mixed_sdk():
    with _scratch() as parent:
        prog = os.path.join(parent, "prog.mojo")
        sdk = os.path.join(parent, "sdk.mojo")
        _write(prog, SOURCE_MOJO)
        _write(sdk, "# SPDX-License-Identifier: MIT\n")
        _expect_error(
            lambda: inspect_module.validate_source_grants(
                APACHE, [prog], sdk_sources=[sdk],
                project_dir=parent,
            ),
            "MBPF703",
            "inspect.license",
        )


def test_source_grants_mixed_extra_claimed():
    extra_type = inspect_module.ExtraGrant
    with _scratch() as parent:
        prog = os.path.join(parent, "prog.mojo")
        third = os.path.join(parent, "third.mojo")
        _write(prog, SOURCE_MOJO)
        _write(third, "# SPDX-License-Identifier: MIT\n")
        _expect_error(
            lambda: inspect_module.validate_source_grants(
                APACHE,
                [prog],
                extra_grants=[
                    extra_type("third-party file", third, "MIT"),
                ],
                project_dir=parent,
            ),
            "MBPF703",
            "inspect.license",
        )


def test_source_grants_bad_extra_type():
    with _scratch() as parent:
        prog = os.path.join(parent, "prog.mojo")
        _write(prog, SOURCE_MOJO)
        try:
            inspect_module.validate_source_grants(
                APACHE, [prog], extra_grants=[("name", prog, APACHE)],
                project_dir=parent,
            )
        except TypeError:
            pass
        else:
            raise AssertionError("expected TypeError for bad extra grant")


def test_source_grants_compound_declared():
    with _scratch() as parent:
        prog = os.path.join(parent, "prog.mojo")
        _write(prog, SOURCE_MOJO)
        _expect_error(
            lambda: inspect_module.validate_source_grants(
                "GPL-2.0-only OR MIT", [prog], project_dir=parent
            ),
            "MBPF703",
            "inspect.license",
        )


def test_source_grants_two_ids_one_file():
    with _scratch() as parent:
        prog = os.path.join(parent, "prog.mojo")
        _write(
            prog,
            "# SPDX-License-Identifier: MIT\n"
            "# SPDX-License-Identifier: Apache-2.0\n",
        )
        _expect_error(
            lambda: inspect_module.validate_source_grants(
                "MIT", [prog], project_dir=parent
            ),
            "MBPF703",
            "inspect.license",
        )


def test_source_grants_missing_file():
    with _scratch() as parent:
        missing = os.path.join(parent, "absent.mojo")
        _expect_error(
            lambda: inspect_module.validate_source_grants(
                APACHE, [missing], project_dir=parent
            ),
            "MBPF707",
            "inspect.license",
        )


def test_source_grants_empty_license_text():
    extra_type = inspect_module.ExtraGrant
    with _scratch() as parent:
        prog = os.path.join(parent, "prog.mojo")
        notice = os.path.join(parent, "LICENSE")
        _write(prog, SOURCE_MOJO)
        _write(notice, "")
        _expect_error(
            lambda: inspect_module.validate_source_grants(
                APACHE,
                [prog],
                extra_grants=[
                    extra_type("project license text", notice, APACHE),
                ],
                project_dir=parent,
            ),
            "MBPF707",
            "inspect.license",
        )


def test_source_grants_stdlib_note_unhashed():
    with _scratch() as parent:
        prog = os.path.join(parent, "prog.mojo")
        _write(prog, SOURCE_MOJO)
        record = inspect_module.validate_source_grants(
            APACHE, [prog], project_dir=parent
        )
    assert "toolchain" in record.stdlib_note
    assert "hash" in record.stdlib_note


def test_pair_qualified_apache_ok():
    validated = inspect_module.validate_declaration_pair(APACHE, APACHE)
    assert validated.source_license == APACHE
    assert validated.kernel_license == APACHE
    assert validated.mapping_version == 1
    assert inspect_module.LICENSE_MAPPING_VERSION == 1
    assert validated.expected_license_bytes == APACHE_BYTES


def test_pair_mapping_holds_exactly_one_pair():
    assert inspect_module.LICENSE_PAIRS == ((APACHE, APACHE),)


def test_pair_others_rejected():
    pairs = [
        ("MIT", "MIT"),
        ("GPL-2.0-only", "GPL v2"),
        ("GPL-2.0-only", "GPL"),
        ("MIT", APACHE),
        (APACHE, "GPL"),
        (APACHE, "GPL v2"),
        (APACHE, "Dual MIT/GPL"),
        (APACHE, "MIT"),
        ("BSD-2-Clause", "BSD-2-Clause"),
    ]
    for source, kernel in pairs:
        exc = _expect_error(
            lambda s=source, k=kernel: (
                inspect_module.validate_declaration_pair(s, k)
            ),
            "MBPF704",
            "inspect.license",
        )
        assert "mapping version 1" in exc.diagnostic.explanation


def test_pair_dual_source_rejected():
    dual = "GPL-2.0-only OR MIT"
    _expect_error(
        lambda: inspect_module.validate_declaration_pair(
            dual, "Dual MIT/GPL"
        ),
        "MBPF703",
        "inspect.license",
    )
    _expect_error(
        lambda: inspect_module.validate_declaration_pair(dual, dual),
        "MBPF703",
        "inspect.license",
    )


def test_pair_kernel_string_shape():
    for kernel in ("GPL\x00v2", "MIT\x00", "\x00"):
        exc = _expect_error(
            lambda k=kernel: inspect_module.validate_declaration_pair(
                APACHE, k
            ),
            "MBPF704",
            "inspect.license",
        )
        assert "NUL" in exc.diagnostic.explanation
    _expect_error(
        lambda: inspect_module.validate_declaration_pair(APACHE, ""),
        "MBPF704",
        "inspect.license",
    )
    _expect_error(
        lambda: inspect_module.validate_declaration_pair(
            APACHE, "Licence \u00e9"
        ),
        "MBPF704",
        "inspect.license",
    )
    try:
        inspect_module.validate_declaration_pair(APACHE, None)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError for non-string kernel")


def test_pair_requires_gpl_rejected():
    exc = _expect_error(
        lambda: inspect_module.validate_declaration_pair(
            APACHE, APACHE, requires_gpl=True
        ),
        "MBPF704",
        "inspect.license",
    )
    assert "GPL-compatible" in exc.diagnostic.explanation


def test_pair_malformed_source():
    _expect_error(
        lambda: inspect_module.validate_declaration_pair("MIT OR", "MIT"),
        "MBPF701",
        "inspect.license",
    )


def test_requires_gpl_supported_inputs():
    check = inspect_module.requires_gpl
    assert check((1, 2), ("xdp",), (), "linux-bpfel-v3") is False
    assert check((), ("xdp",), (), "linux-bpfel-v3") is False
    profile = lookup_profile("linux-bpfel-v3")
    assert check((1,), ("xdp",), (), profile) is False
    try:
        check((1,), ("xdp",), (), "no-such-profile")
    except Exception as exc:  # noqa: BLE001 - assert the carried code
        assert exc.diagnostic.code == "MBPF101", exc.diagnostic
    else:
        raise AssertionError("expected MBPF101 for unknown profile")
    try:
        check((1,), ("xdp",), (), 123)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError for bad profile")


def test_requires_gpl_unknown_inputs():
    check = inspect_module.requires_gpl
    _expect_error(
        lambda: check((7,), ("xdp",), (), "linux-bpfel-v3"),
        "MBPF706",
        "inspect.license",
    )
    _expect_error(
        lambda: check((1, 2, 99), ("xdp",), (), "linux-bpfel-v3"),
        "MBPF706",
        "inspect.license",
    )
    _expect_error(
        lambda: check((1,), ("kprobe",), (), "linux-bpfel-v3"),
        "MBPF706",
        "inspect.license",
    )
    _expect_error(
        lambda: check((1,), ("xdp",), ("bpf_x",), "linux-bpfel-v3"),
        "MBPF706",
        "inspect.license",
    )
    _expect_error(
        lambda: check(("1",), ("xdp",), (), "linux-bpfel-v3"),
        "MBPF706",
        "inspect.license",
    )


def test_requires_gpl_tracepoint_established_without_gpl():
    check = inspect_module.requires_gpl
    assert check((1, 2, 14), ("tracepoint",), (), "linux-bpfel-v3") is False
    assert check((14,), ("tracepoint",), (), "linux-bpfel-v3") is False


def test_requires_gpl_unrecorded_profile():
    check = inspect_module.requires_gpl
    future = dataclasses.replace(
        lookup_profile("linux-bpfel-v3"), profile_id="linux-bpfel-v9"
    )
    exc = _expect_error(
        lambda: check((), (), (), future),
        "MBPF706",
        "inspect.license",
    )
    assert "no GPL-restriction entry" in exc.diagnostic.explanation


def test_kernel_recognized_set():
    recognized = inspect_module.kernel_recognizes_as_gpl
    for declaration in (
        "GPL",
        "GPL v2",
        "GPL and additional rights",
        "Dual BSD/GPL",
        "Dual MIT/GPL",
        "Dual MPL/GPL",
    ):
        assert recognized(declaration) is True, declaration
    for declaration in (APACHE, "MIT", "", "gpl", "GPL-2.0-only"):
        assert recognized(declaration) is False, declaration


def test_license_layer_agrees_with_audit_on_unknown_helper():
    audit = _load_module("audit_unknown_helper_check", AUDIT)
    line = "  %2 = call i64 inttoptr (i64 7 to ptr)(i64 0, ptr %0)\n"
    try:
        audit.audit_post(line, "classifier")
    except audit.AuditError as exc:
        assert exc.code == "MBPF306", exc
        assert exc.stage == "adapter.audit", exc.stage
    else:
        raise AssertionError("expected the audit to reject helper 7")
    _expect_error(
        lambda: inspect_module.requires_gpl(
            (7,), ("xdp",), (), "linux-bpfel-v3"
        ),
        "MBPF706",
        "inspect.license",
    )


def _ir_payload(block):
    start = block.index('c"') + 2
    chars = []
    index = start
    while block[index] != '"':
        if block[index] == "\\":
            chars.append(
                chr(int(block[index + 1:index + 3], 16))
            )
            index += 3
        else:
            chars.append(block[index])
            index += 1
    return "".join(chars).encode("latin-1")


def test_emitter_bytes_equal_validated_declaration():
    adapter = _load_module("adapter_license_bytes_check", ADAPTER)
    validated = inspect_module.validate_declaration_pair(APACHE, APACHE)
    expected = validated.expected_license_bytes
    assert expected == APACHE_BYTES
    blocks = (
        adapter.LICENSE_BLOCK,
        adapter.MAP_LICENSE_BLOCK,
        adapter.TRACEPOINT_MAP_LICENSE_BLOCK,
    )
    for block in blocks:
        payload = _ir_payload(block)
        assert payload == expected, block[:60]
        head, _, _ = block.partition(" ")
        assert head.startswith("@_license"), head
    for block in blocks:
        found = re.search(r"\[(\d+) x i8\]", block)
        assert found is not None, block[:60]
        assert int(found.group(1)) == len(expected), block[:60]


def test_no_link_step_passes_on_build_commands():
    records = (
        CommandRecord(
            argv=("/bin/mojo", "--version"),
            stage="build.setup",
            status="ok",
            exit_code=0,
            duration_s=0.1,
            log_excerpt="",
        ),
        CommandRecord(
            argv=("/bin/mojo", "build", "--emit", "llvm"),
            stage="build.frontend",
            status="ok",
            exit_code=0,
            duration_s=0.2,
            log_excerpt="",
        ),
        CommandRecord(
            argv=("/bin/python", "adapter_service.py"),
            stage="build.adapter",
            status="ok",
            exit_code=0,
            duration_s=0.1,
            log_excerpt="",
        ),
        CommandRecord(
            argv=("/bin/llc", "-mtriple=bpfel"),
            stage="build.backend",
            status="ok",
            exit_code=0,
            duration_s=0.3,
            log_excerpt="",
        ),
    )
    assert inspect_module.assert_no_link_step(records) is None
    assert inspect_module.assert_no_link_step(()) is None


def test_no_link_step_rejects_linkers():
    def record(stage, argv):
        return CommandRecord(
            argv=tuple(argv),
            stage=stage,
            status="ok",
            exit_code=0,
            duration_s=0.1,
            log_excerpt="",
        )

    for stage, argv in (
        ("build.link", ("/bin/tool",)),
        ("adapter.link", ("/bin/tool",)),
        ("link", ("/bin/tool",)),
        ("build.backend", ("/usr/bin/ld", "a.o")),
        ("build.backend", ("bpf-linker", "a.o")),
        ("build.backend", ("/opt/x/llvm-link", "a.o")),
    ):
        try:
            inspect_module.assert_no_link_step([record(stage, argv)])
        except AssertionError as exc:
            assert "recheck" in str(exc), exc
        else:
            raise AssertionError(
                "expected AssertionError for %r/%r" % (stage, argv)
            )


def _load_schema(name):
    path = os.path.join(SCHEMA_DIR, name)
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _synthetic_result(project, out_dir, success=True):
    work = os.path.join(project, "work")
    source = os.path.join(project, "prog.mojo")
    raw = os.path.join(work, "xdp_entry.raw.ll")
    adapted = os.path.join(work, "xdp_entry.adapter", "adapted.ll")
    staged = os.path.join(work, "xdp_entry.bpf.o")
    commands = (
        CommandRecord(
            argv=("/opt/toolchain/bin/mojo", "--version"),
            stage="build.setup",
            status="ok",
            exit_code=0,
            duration_s=0.4,
            log_excerpt="Mojo 9.9.9",
        ),
        CommandRecord(
            argv=(
                "/opt/toolchain/bin/mojo",
                "build",
                "--emit",
                "llvm",
                "-o",
                raw,
                source,
            ),
            stage="build.frontend",
            status="ok",
            exit_code=0,
            duration_s=2.5,
            log_excerpt="",
        ),
        CommandRecord(
            argv=("/usr/bin/python3", "/opt/svc/adapter.py"),
            stage="build.adapter",
            status="ok" if success else "failed",
            exit_code=0 if success else 1,
            duration_s=0.2,
            log_excerpt="",
        ),
        CommandRecord(
            argv=(
                "/opt/toolchain/bin/llc",
                "-mtriple=bpfel",
                "-mcpu=v3",
                "-filetype=obj",
                adapted,
                "-o",
                staged,
            ),
            stage="build.backend",
            status="ok" if success else "timeout",
            exit_code=0 if success else None,
            duration_s=1.1,
            log_excerpt="",
        ),
    )
    provenance = BuildProvenance(
        manifest_path=os.path.join(project, "mojobpf.toml"),
        manifest_sha256="0" * 64,
        profile_id="linux-bpfel-v3",
        source_files=(source,),
        source_sha256=("1" * 64,),
        adapter_path="/opt/svc/adapter.py",
        adapter_sha256="2" * 64,
        mojo_version="Mojo 9.9.9 (fixture)",
        llc_version="llc 9.9.9 (fixture)",
        mojo_sha256="3" * 64,
        llc_sha256="4" * 64,
        tool_version=TOOL_VERSION,
        sdk_version=SDK_VERSION,
    )
    artifacts = ()
    if success:
        final = os.path.join(out_dir, "demo.bpf.o")
        _write(final, b"object-bytes")
        artifacts = (
            BuildArtifact(
                role="object",
                path=final,
                sha256=hashlib.sha256(b"object-bytes").hexdigest(),
                size=len(b"object-bytes"),
            ),
        )
    return BuildResult(
        schema_version=1,
        success=success,
        diagnostics=(),
        artifacts=artifacts,
        provenance=provenance,
        commands=commands,
        work_dir=None,
    )


def _synthetic_manifest(project):
    return parse_manifest(os.path.join(project, "mojobpf.toml"))


def test_schemas_valid_and_conform():
    for name in (
        "artifact.schema.json",
        "diagnostics.schema.json",
        "evidence.schema.json",
    ):
        schema = _load_schema(name)
        assert schema["$schema"].endswith("/draft/2020-12/schema"), name
        assert "SPDX-License-Identifier" in schema["$comment"], name
        assert schema["additionalProperties"] is False, name
    artifact_schema = _load_schema("artifact.schema.json")
    assert artifact_schema["properties"]["schema_version"]["const"] == (
        evidence_module.ARTIFACT_SCHEMA_VERSION
    )
    published = evidence_module.PublishedArtifact(
        schema_version=evidence_module.ARTIFACT_SCHEMA_VERSION,
        role="object",
        name="demo.bpf.o",
        sha256="a" * 64,
        size=12,
    )
    assert (
        sorted(published.to_dict()) == sorted(artifact_schema["required"])
    )
    assert published.to_dict()["schema_version"] == (
        artifact_schema["properties"]["schema_version"]["const"]
    )
    assert "evidence" in (
        artifact_schema["properties"]["role"]["enum"]
    )
    name_pattern = artifact_schema["properties"]["name"]["pattern"]
    assert re.match(name_pattern, "demo.bpf.o")
    assert re.match(name_pattern, "demo.xdp_entry.bpf.o")
    assert re.match(name_pattern, "demo.evidence.json")
    diagnostics_schema = _load_schema("diagnostics.schema.json")
    diagnostic = Diagnostic(
        code="MBPF704",
        stage="inspect.license",
        severity="error",
        explanation="fixture",
        location=None,
        remedy=None,
    )
    assert (
        sorted(diagnostic.to_dict())
        == sorted(diagnostics_schema["required"])
    )
    assert re.match(
        diagnostics_schema["properties"]["code"]["pattern"], "MBPF704"
    )
    evidence_schema = _load_schema("evidence.schema.json")
    with _scratch() as parent:
        project = _project(parent)
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        result = _synthetic_result(project, out_dir)
        manifest = _synthetic_manifest(project)
        evidence = evidence_module.evidence_from_build(
            result,
            manifest,
            project_dir=project,
            out_dir=out_dir,
            transforms=("frontend", "adapter", "backend"),
            flags=("llc:-mcpu=v3",),
            environment={"PATH": "/bin", "CUSTOM": "plain"},
            sealed=_seal_for(project, manifest),
        )
    doc = evidence.to_dict()
    assert sorted(doc) == sorted(evidence_schema["required"])
    assert doc["schema_version"] == (
        evidence_schema["properties"]["schema_version"]["const"]
    )
    assert doc["schema_version"] == (
        evidence_module.EVIDENCE_SCHEMA_VERSION
    )
    inputs_schema = evidence_schema["properties"]["inputs"]
    assert sorted(doc["inputs"]) == sorted(inputs_schema["required"])
    assert doc["tool_version"] == TOOL_VERSION
    assert doc["sdk_version"] == SDK_VERSION
    assert doc["inputs"]["tool_version"] == TOOL_VERSION
    assert doc["inputs"]["sdk_version"] == SDK_VERSION
    assert re.match(
        evidence_schema["properties"]["sdk_version"]["pattern"],
        doc["sdk_version"],
    )
    assert doc["inputs"]["profile_id"] == "linux-bpfel-v3"
    assert re.match(
        inputs_schema["properties"]["profile_sha256"]["pattern"],
        doc["inputs"]["profile_sha256"],
    )
    hashed_schema = evidence_schema["$defs"]["hashed_file"]
    assert (
        sorted(doc["inputs"]["manifest"])
        == sorted(hashed_schema["required"])
    )
    command_schema = evidence_schema["properties"]["commands"]["items"]
    for entry in doc["commands"]:
        assert sorted(entry) == sorted(command_schema["required"])
    env_schema = evidence_schema["properties"]["environment"]["items"]
    for entry in doc["environment"]:
        assert sorted(entry) == sorted(env_schema["required"])


def test_evidence_stable_across_directories():
    docs = []
    for tag in ("first", "second"):
        with _scratch() as parent:
            project = _project(parent)
            out_dir = os.path.join(parent, "out")
            os.makedirs(out_dir)
            result = _synthetic_result(project, out_dir)
            manifest = _synthetic_manifest(project)
            evidence = evidence_module.evidence_from_build(
                result,
                manifest,
                project_dir=project,
                out_dir=out_dir,
                transforms=("frontend", "adapter", "backend"),
                flags=("llc:-mcpu=v3",),
                environment={
                    "PATH": "/opt/toolchain/bin:/bin",
                    "MODULAR_HOME": "/opt/max",
                    "CUSTOM": "plain",
                },
                sealed=_seal_for(project, manifest),
            )
            raw = evidence_module.dumps_evidence(evidence)
            assert parent.encode() not in raw, tag
            docs.append(raw)
    assert docs[0] == docs[1]
    doc = json.loads(docs[0].decode("ascii"))
    assert doc["inputs"]["source"] == [
        {
            "path": "prog.mojo",
            "sha256": hashlib.sha256(SOURCE_MOJO.encode()).hexdigest(),
            "size": len(SOURCE_MOJO.encode()),
        }
    ]
    assert doc["inputs"]["manifest"]["path"] == "mojobpf.toml"
    assert doc["outputs"] == [
        {
            "path": "demo.bpf.o",
            "sha256": hashlib.sha256(b"object-bytes").hexdigest(),
            "size": len(b"object-bytes"),
        }
    ]
    frontend = [
        entry
        for entry in doc["commands"]
        if entry["stage"] == "build.frontend"
    ][0]
    assert "$SRC/prog.mojo" in frontend["argv"]
    assert any(
        token.startswith("$PATH/") for token in frontend["argv"]
    ), frontend["argv"]
    assert "duration_s" not in frontend
    assert "log_excerpt" not in frontend
    assert doc["license_mapping_version"] == 1
    env = {entry["name"]: entry["value"] for entry in doc["environment"]}
    assert env["PATH"].startswith("sha256:")
    assert env["MODULAR_HOME"].startswith("sha256:")
    assert env["CUSTOM"] == "plain"
    try:
        evidence_module.dumps_evidence({"not": "evidence"})
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError for bad dumps input")


def test_evidence_rejects_relative_manifest_path():
    with _scratch() as parent:
        project = _project(parent)
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        result = _synthetic_result(project, out_dir)
        manifest = _synthetic_manifest(project)
        relative = dataclasses.replace(
            manifest, manifest_path="proj/mojobpf.toml"
        )
        _expect_error(
            lambda: evidence_module.evidence_from_build(
                result,
                relative,
                project_dir=project,
                out_dir=out_dir,
                transforms=("frontend",),
                sealed=_seal_for(project, manifest),
            ),
            "MBPF708",
            "evidence.capture",
        )


def test_evidence_failed_build_records_inputs():
    with _scratch() as parent:
        project = _project(parent)
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        result = _synthetic_result(project, out_dir, success=False)
        manifest = _synthetic_manifest(project)
        evidence = evidence_module.evidence_from_build(
            result,
            manifest,
            project_dir=project,
            out_dir=out_dir,
            transforms=("frontend", "adapter"),
            environment={"CUSTOM": "plain"},
            sealed=_seal_for(project, manifest),
        )
    assert evidence.success is False
    assert evidence.outputs == ()
    assert len(evidence.inputs.source) == 1
    assert evidence.inputs.manifest.path == "mojobpf.toml"
    raw = evidence_module.dumps_evidence(evidence)
    assert b'"success":false' in raw


def _seal_for(project, manifest, sdk_files=(), imported=(), adapter=()):
    def sha(path):
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()

    def pairs(paths):
        return tuple(
            (os.path.realpath(path), sha(path)) for path in paths
        )

    return evidence_module.SealedInputs(
        manifest_sha256=sha(os.path.join(project, "mojobpf.toml")),
        source_sha256=tuple(
            sha(
                os.path.realpath(
                    os.path.join(project, program.source)
                )
            )
            for program in manifest.programs
        ),
        sdk=pairs(sdk_files),
        imports=pairs(imported),
        adapter=pairs(adapter),
        profile_sha256=profile_digest(
            lookup_profile(manifest.target.profile)
        ),
    )


def _capture_args(project, out_dir, result, manifest, sdk_files=(),
                  imported=(), adapter=(), *, sealed):
    return dict(
        result=result,
        manifest=manifest,
        project_dir=project,
        out_dir=out_dir,
        transforms=("frontend", "adapter", "backend"),
        sdk_files=sdk_files,
        imported_sources=imported,
        adapter_files=adapter,
        flags=("build",),
        sealed=sealed,
    )


def test_evidence_sealed_capture_accepts_unchanged():
    with _scratch() as parent:
        project = _project(parent)
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        helper = os.path.join(project, "helper.mojo")
        _write(helper, SOURCE_MOJO)
        sdk_copy = os.path.join(parent, "sdk-copy.mojo")
        _write(sdk_copy, SOURCE_MOJO)
        tool = os.path.join(parent, "tool.py")
        _write(tool, "# tool\n")
        result = _synthetic_result(project, out_dir)
        manifest = _synthetic_manifest(project)
        sealed = _seal_for(
            project, manifest, sdk_files=(sdk_copy,),
            imported=(helper,), adapter=(tool,),
        )
        evidence = evidence_module.evidence_from_build(
            **_capture_args(
                project, out_dir, result, manifest,
                sdk_files=(sdk_copy,), imported=(helper,),
                adapter=(tool,), sealed=sealed,
            )
        )
        assert len(evidence.inputs.sdk) == 1
        assert len(evidence.inputs.imports) == 1
        assert evidence.inputs.imports[0].path == "helper.mojo"
        assert evidence.inputs.adapter == (
            "tool.py %s" % sealed.adapter[0][1],
        )
        assert evidence.inputs.profile_id == "linux-bpfel-v3"
        assert evidence.inputs.profile_sha256 == sealed.profile_sha256
        tools = evidence.inputs.compiler[:2]
        assert tools == (
            "mojo Mojo 9.9.9 (fixture) %s" % ("3" * 64,),
            "llc llc 9.9.9 (fixture) %s" % ("4" * 64,),
        )
        assert evidence.inputs.compiler[2] == (
            evidence_module.STDLIB_UNBOUND
        )
        recorded = {
            entry.name: entry.value for entry in evidence.environment
        }
        assert evidence.inputs.compiler[3:] == tuple(
            "env %s=%s" % (name, recorded[name])
            for name in sorted(recorded)
        )


def test_evidence_sealed_capture_rejects_drift():
    with _scratch() as parent:
        project = _project(parent)
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        helper = os.path.join(project, "helper.mojo")
        _write(helper, SOURCE_MOJO)
        sdk_copy = os.path.join(parent, "sdk-copy.mojo")
        _write(sdk_copy, SOURCE_MOJO)
        tool = os.path.join(parent, "tool.py")
        _write(tool, "# tool\n")
        result = _synthetic_result(project, out_dir)
        manifest = _synthetic_manifest(project)
        sealed = _seal_for(
            project, manifest, sdk_files=(sdk_copy,),
            imported=(helper,), adapter=(tool,),
        )

        def capture():
            return evidence_module.evidence_from_build(
                **_capture_args(
                    project, out_dir, result, manifest,
                    sdk_files=(sdk_copy,), imported=(helper,),
                    adapter=(tool,), sealed=sealed,
                )
            )

        capture()
        mutations = {
            "manifest": os.path.join(project, "mojobpf.toml"),
            "source": os.path.join(project, "prog.mojo"),
            "sdk": sdk_copy,
            "import": helper,
            "adapter": tool,
        }
        for label, path in mutations.items():
            with open(path, "rb") as handle:
                original = handle.read()
            try:
                with open(path, "wb") as handle:
                    handle.write(original + b"# drift\n")
                exc = _expect_error(
                    capture, "MBPF708", "evidence.capture"
                )
                assert "recapture rejected" in (
                    exc.diagnostic.explanation
                ), label
            finally:
                with open(path, "wb") as handle:
                    handle.write(original)


def test_evidence_capture_requires_seal():
    with _scratch() as parent:
        project = _project(parent)
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        result = _synthetic_result(project, out_dir)
        manifest = _synthetic_manifest(project)
        try:
            evidence_module.evidence_from_build(
                result,
                manifest,
                project_dir=project,
                out_dir=out_dir,
                transforms=("frontend",),
            )
        except TypeError:
            pass
        else:
            raise AssertionError("expected TypeError without a seal")
        try:
            evidence_module.evidence_from_build(
                result,
                manifest,
                project_dir=project,
                out_dir=out_dir,
                transforms=("frontend",),
                sealed=None,
            )
        except TypeError:
            pass
        else:
            raise AssertionError("expected TypeError for a None seal")


def test_evidence_sealed_capture_rejects_profile_drift():
    with _scratch() as parent:
        project = _project(parent)
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        result = _synthetic_result(project, out_dir)
        manifest = _synthetic_manifest(project)
        sealed = _seal_for(project, manifest)
        drifted = dataclasses.replace(
            sealed, profile_sha256="0" * 64
        )
        exc = _expect_error(
            lambda: evidence_module.evidence_from_build(
                **_capture_args(
                    project, out_dir, result, manifest,
                    sealed=drifted,
                )
            ),
            "MBPF708",
            "evidence.capture",
        )
        assert "profile" in exc.diagnostic.explanation
        assert "recapture rejected" in exc.diagnostic.explanation


def _cache_inputs(**overrides):
    def hashed(path, marker):
        digest = hashlib.sha256(marker.encode()).hexdigest()
        return evidence_module.HashedFile(
            path=path, sha256=digest, size=len(marker)
        )

    fields = {
        "source": (hashed("prog.mojo", "source"),),
        "imports": (hashed("lib.mojo", "import"),),
        "sdk": (hashed("sdk/helpers.mojo", "sdk"),),
        "manifest": hashed("mojobpf.toml", "manifest"),
        "compiler": ("mojo Mojo 9.9.9 abc", "llc 9.9.9 def"),
        "flags": ("llc:-mcpu=v3",),
        "profile_id": "linux-bpfel-v3",
        "profile_sha256": profile_digest(
            lookup_profile("linux-bpfel-v3")
        ),
        "adapter": ("adapter_service.py abc", "audit.py def"),
        "tool_version": TOOL_VERSION,
        "sdk_version": SDK_VERSION,
    }
    fields.update(overrides)
    return evidence_module.CacheInputs(**fields)


def test_cache_key_stable_and_versioned():
    first = evidence_module.cache_key(_cache_inputs())
    second = evidence_module.cache_key(_cache_inputs())
    assert first == second
    assert first.startswith("v6:")
    assert len(first) == len("v6:") + 64
    try:
        evidence_module.cache_key({"not": "inputs"})
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError for bad cache input")


def _assert_invalidates(**overrides):
    base = evidence_module.cache_key(_cache_inputs())
    changed = evidence_module.cache_key(_cache_inputs(**overrides))
    assert changed != base, overrides


def test_cache_key_source_change_invalidates():
    def hashed(path, marker):
        return evidence_module.HashedFile(
            path=path,
            sha256=hashlib.sha256(marker.encode()).hexdigest(),
            size=len(marker),
        )

    _assert_invalidates(source=(hashed("prog.mojo", "edited"),))


def test_cache_key_import_change_invalidates():
    def hashed(path, marker):
        return evidence_module.HashedFile(
            path=path,
            sha256=hashlib.sha256(marker.encode()).hexdigest(),
            size=len(marker),
        )

    _assert_invalidates(imports=(hashed("lib.mojo", "edited-import"),))
    _assert_invalidates(imports=())


def test_cache_key_sdk_change_invalidates():
    def hashed(path, marker):
        return evidence_module.HashedFile(
            path=path,
            sha256=hashlib.sha256(marker.encode()).hexdigest(),
            size=len(marker),
        )

    _assert_invalidates(sdk=(hashed("sdk/helpers.mojo", "sdk-v2"),))


def test_cache_key_manifest_change_invalidates():
    changed = evidence_module.HashedFile(
        path="mojobpf.toml",
        sha256=hashlib.sha256(b"manifest-v2").hexdigest(),
        size=11,
    )
    _assert_invalidates(manifest=changed)


def test_cache_key_compiler_change_invalidates():
    _assert_invalidates(compiler=("mojo Mojo 9.9.10 abc", "llc 9.9.9 def"))
    _assert_invalidates(compiler=())


def test_cache_key_flags_change_invalidates():
    _assert_invalidates(flags=("llc:-mcpu=v4",))
    _assert_invalidates(flags=())


def test_cache_key_profile_change_invalidates():
    _assert_invalidates(profile_id="linux-bpfel-v4")


def test_cache_key_profile_impl_change_invalidates():
    _assert_invalidates(profile_sha256="0" * 64)


def test_cache_key_adapter_change_invalidates():
    _assert_invalidates(adapter=("adapter_service.py abc",))
    _assert_invalidates(adapter=())


def test_cache_key_tool_version_change_invalidates():
    _assert_invalidates(tool_version="0.0.0-test")
    _assert_invalidates(tool_version="")


def test_cache_key_sdk_version_change_invalidates():
    _assert_invalidates(sdk_version="9.9")
    _assert_invalidates(sdk_version="")


def test_environment_path_values_hashed():
    with _scratch() as parent:
        project = _project(parent)
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        result = _synthetic_result(project, out_dir)
        manifest = _synthetic_manifest(project)

        sealed = _seal_for(project, manifest)

        def capture(extra):
            return evidence_module.evidence_from_build(
                result,
                manifest,
                project_dir=project,
                out_dir=out_dir,
                transforms=("frontend",),
                environment=extra,
                sealed=sealed,
            )

        first = capture({"PATH": "/a/bin", "NOTE": "plain"})
        second = capture({"PATH": "/b/bin", "NOTE": "plain"})
        assert evidence_module.dumps_evidence(first) != (
            evidence_module.dumps_evidence(second)
        )
        env = {e.name: e.value for e in first.environment}
        assert env["PATH"].startswith("sha256:")
        assert env["NOTE"] == "plain"


def test_hash_file_paths_and_missing():
    with _scratch() as parent:
        inner = os.path.join(parent, "sub", "file.bin")
        os.makedirs(os.path.dirname(inner))
        _write(inner, b"data")
        hashed = evidence_module.hash_file(inner, parent)
        assert hashed.path == "sub/file.bin"
        assert hashed.sha256 == hashlib.sha256(b"data").hexdigest()
        assert hashed.size == 4
        assert evidence_module.hash_file(inner).path == "file.bin"
        outer = os.path.join(parent, "sub", "outer.bin")
        _write(outer, b"outer")
        assert (
            evidence_module.hash_file(
                outer, os.path.join(parent, "elsewhere")
            ).path
            == "outer.bin"
        )
        _expect_error(
            lambda: evidence_module.hash_file(
                os.path.join(parent, "absent.bin"), parent
            ),
            "MBPF708",
            "evidence.capture",
        )


def _staged(parent, name, content):
    path = os.path.join(parent, name + ".staged")
    _write(path, content)
    return path


def _snapshot(out_dir):
    digest = {}
    for name in sorted(os.listdir(out_dir)):
        path = os.path.join(out_dir, name)
        if os.path.isfile(path) and not os.path.islink(path):
            with open(path, "rb") as handle:
                digest[name] = handle.read()
        else:
            digest[name + "/"] = None
    return digest


def test_publish_success_exact_bytes():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        first = _staged(parent, "a.bpf.o", b"AAA")
        second = _staged(parent, "b.bpf.o", b"B" * 100)
        out_dir = os.path.join(parent, "out")
        published = publish(
            [("a.bpf.o", first), ("b.bpf.o", second)], out_dir
        )
    assert [item.name for item in published] == ["a.bpf.o", "b.bpf.o"]
    assert [item.role for item in published] == ["object", "object"]
    assert published[0].sha256 == hashlib.sha256(b"AAA").hexdigest()
    assert published[0].size == 3
    assert published[1].size == 100
    schema = _load_schema("artifact.schema.json")
    for item in published:
        assert sorted(item.to_dict()) == sorted(schema["required"])
        assert re.match(
            schema["properties"]["name"]["pattern"], item.name
        )
    with _scratch() as parent:
        out_dir = os.path.join(parent, "out")
        first = _staged(parent, "a.bpf.o", b"AAA")
        publish([("a.bpf.o", first)], out_dir)
        assert os.listdir(out_dir) == ["a.bpf.o"]


def test_publish_mid_failure_rolls_back():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        first = _staged(parent, "a.bpf.o", b"AAA")
        second = _staged(parent, "b.bpf.o", b"BBBB")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        blocker = os.path.join(out_dir, "b.bpf.o")
        os.makedirs(blocker)
        _write(os.path.join(blocker, "keep"), "keep")
        before = _snapshot(out_dir)
        exc = _expect_error(
            lambda: publish(
                [("a.bpf.o", first), ("b.bpf.o", second)], out_dir
            ),
            "MBPF106",
            "evidence.publish",
        )
        assert "b.bpf.o" in exc.diagnostic.explanation
        assert _snapshot(out_dir) == before
        assert sorted(os.listdir(out_dir)) == ["b.bpf.o"]
        assert os.listdir(blocker) == ["keep"]


def test_publish_rejects_symlink_predecessor():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = _staged(parent, "a.bpf.o", b"AAA")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        target = os.path.join(parent, "target.o")
        _write(target, b"target-bytes")
        link = os.path.join(out_dir, "a.bpf.o")
        os.symlink(target, link)
        exc = _expect_error(
            lambda: publish([("a.bpf.o", staged)], out_dir),
            "MBPF106",
            "evidence.publish",
        )
        assert "symlink" in exc.diagnostic.explanation
        assert os.path.islink(link)
        with open(link, "rb") as handle:
            assert handle.read() == b"target-bytes"


def test_publish_interrupted_at_rename_rolls_back():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        first = _staged(parent, "a.bpf.o", b"AAA")
        second = _staged(parent, "b.bpf.o", b"BBBB")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        predecessor = os.path.join(out_dir, "a.bpf.o")
        _write(predecessor, b"OLD")
        before = _snapshot(out_dir)
        real_replace = os.replace
        calls = []

        def interrupting(src, dst, *args, **kwargs):
            # The rename REALLY happens before the interruption:
            # the journal entry is pending with an uncertain
            # outcome, which rollback must recover (predecessor
            # restored, backup consumed -- never dropped).
            calls.append((src, dst))
            real_replace(src, dst, *args, **kwargs)
            if len(calls) == 1:
                raise KeyboardInterrupt("fixture interrupt")
            return None

        os.replace = interrupting
        caught = None
        try:
            publish(
                [("a.bpf.o", first), ("b.bpf.o", second)], out_dir
            )
        except KeyboardInterrupt as exc:
            caught = exc
        else:
            raise AssertionError("expected KeyboardInterrupt")
        finally:
            os.replace = real_replace
        assert calls, "rename boundary never exercised"
        assert _snapshot(out_dir) == before
        with open(predecessor, "rb") as handle:
            assert handle.read() == b"OLD"
        leftovers = [
            name for name in os.listdir(out_dir)
            if name.startswith(".")
        ]
        assert leftovers == [], leftovers
        recovery = evidence_module.publication_recovery(caught)
        assert recovery is not None
        assert recovery.complete is True
        assert recovery.failures == ()
        assert len(recovery.recovered) == 1
        assert "uncertain" in recovery.recovered[0]


def test_publish_interrupted_at_second_rename_rolls_back_both():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        first = _staged(parent, "a.bpf.o", b"AAA")
        second = _staged(parent, "b.bpf.o", b"BBBB")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        predecessor = os.path.join(out_dir, "a.bpf.o")
        _write(predecessor, b"OLD")
        before = _snapshot(out_dir)
        real_replace = os.replace
        calls = []

        def interrupting(src, dst, *args, **kwargs):
            calls.append((src, dst))
            real_replace(src, dst, *args, **kwargs)
            if len(calls) == 2:
                raise KeyboardInterrupt("fixture interrupt")
            return None

        os.replace = interrupting
        caught = None
        try:
            publish(
                [("a.bpf.o", first), ("b.bpf.o", second)], out_dir
            )
        except KeyboardInterrupt as exc:
            caught = exc
        else:
            raise AssertionError("expected KeyboardInterrupt")
        finally:
            os.replace = real_replace
        # The confirmed first rename and the uncertain second one
        # both roll back: the overwrite is restored, the new file
        # is removed. Three renames run: two publishes plus the
        # predecessor restore.
        assert len(calls) == 3, "rename boundary never exercised"
        assert _snapshot(out_dir) == before
        with open(predecessor, "rb") as handle:
            assert handle.read() == b"OLD"
        assert not os.path.lexists(os.path.join(out_dir, "b.bpf.o"))
        leftovers = [
            name for name in os.listdir(out_dir)
            if name.startswith(".")
        ]
        assert leftovers == [], leftovers
        recovery = evidence_module.publication_recovery(caught)
        assert recovery is not None
        assert recovery.complete is True
        assert recovery.failures == ()
        assert len(recovery.recovered) == 2


def test_publish_keyboard_interrupt_reports_incomplete_rollback():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        first = _staged(parent, "a.bpf.o", b"AAA")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        _write(os.path.join(out_dir, "a.bpf.o"), b"OLD")
        real_replace = os.replace
        calls = []

        def interrupting(src, dst, *args, **kwargs):
            calls.append((src, dst))
            if ".backup." in os.path.basename(src):
                raise OSError("fixture restore failure")
            real_replace(src, dst, *args, **kwargs)
            if len(calls) == 1:
                raise KeyboardInterrupt("fixture interrupt")
            return None

        os.replace = interrupting
        caught = None
        try:
            publish([("a.bpf.o", first)], out_dir)
        except KeyboardInterrupt as exc:
            caught = exc
        finally:
            os.replace = real_replace
        assert caught is not None, "expected KeyboardInterrupt"
        # The incomplete rollback is reported on the propagating
        # interruption -- never swallowed -- and the backup stays.
        recovery = evidence_module.publication_recovery(caught)
        assert recovery is not None
        assert recovery.complete is False
        assert len(recovery.failures) == 1
        assert "retained" in recovery.failures[0]
        backups = [
            name for name in os.listdir(out_dir)
            if ".backup." in name
        ]
        assert len(backups) == 1, os.listdir(out_dir)
        with open(
            os.path.join(out_dir, backups[0]), "rb"
        ) as handle:
            assert handle.read() == b"OLD"


def test_publish_incomplete_rollback_reports_backups():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        first = _staged(parent, "a.bpf.o", b"AAA")
        second = _staged(parent, "b.bpf.o", b"BBBB")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        _write(os.path.join(out_dir, "a.bpf.o"), b"OLD")
        blocker = os.path.join(out_dir, "b.bpf.o")
        os.makedirs(blocker)
        real_replace = os.replace

        def no_restore(src, dst, *args, **kwargs):
            if ".backup." in os.path.basename(src):
                raise OSError("fixture restore failure")
            return real_replace(src, dst, *args, **kwargs)

        os.replace = no_restore
        try:
            exc = _expect_error(
                lambda: publish(
                    [("a.bpf.o", first), ("b.bpf.o", second)],
                    out_dir,
                ),
                "MBPF106",
                "evidence.publish",
            )
        finally:
            os.replace = real_replace
        assert "incomplete" in exc.diagnostic.explanation
        assert "retained" in exc.diagnostic.explanation
        backups = [
            name for name in os.listdir(out_dir)
            if ".backup." in name
        ]
        assert len(backups) == 1, os.listdir(out_dir)
        with open(
            os.path.join(out_dir, backups[0]), "rb"
        ) as handle:
            assert handle.read() == b"OLD"


def test_publish_roles_and_rejections():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        obj = _staged(parent, "a.bpf.o", b"AAA")
        sidecar = _staged(parent, "a.evidence.json", b"{}")
        out_dir = os.path.join(parent, "out")
        published = publish(
            [("a.bpf.o", obj), ("a.evidence.json", sidecar, "evidence")],
            out_dir,
        )
        assert [item.role for item in published] == [
            "object", "evidence",
        ]
        assert all(
            item.schema_version
            == evidence_module.ARTIFACT_SCHEMA_VERSION
            for item in published
        )
        exc = _expect_error(
            lambda: publish([("a.bpf.o", obj, "sidecar")], out_dir),
            "MBPF106",
            "evidence.publish",
        )
        assert "role" in exc.diagnostic.explanation
        _expect_error(
            lambda: publish([("a.bpf.o",)], out_dir),
            "MBPF106",
            "evidence.publish",
        )


def test_publish_fail_after_success_disjoint():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        first = _staged(parent, "a.bpf.o", b"AAA")
        out_dir = os.path.join(parent, "out")
        published = publish([("a.bpf.o", first)], out_dir)
        assert [item.name for item in published] == ["a.bpf.o"]
        before = _snapshot(out_dir)
        second = _staged(parent, "b.bpf.o", b"BBBB")
        blocker = os.path.join(out_dir, "b.bpf.o")
        os.makedirs(blocker)
        _write(os.path.join(blocker, "keep"), "keep")
        before_blocked = _snapshot(out_dir)
        _expect_error(
            lambda: publish(
                [("c.bpf.o", first), ("b.bpf.o", second)], out_dir
            ),
            "MBPF106",
            "evidence.publish",
        )
        # The failed call claims nothing and leaves nothing new: the
        # earlier success is byte-identical, the blocker is intact.
        assert _snapshot(out_dir) == before_blocked
        with open(os.path.join(out_dir, "a.bpf.o"), "rb") as handle:
            assert handle.read() == before["a.bpf.o"]


def test_publish_failed_overwrite_restores_predecessor():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        old = _staged(parent, "old", b"OLD")
        new = _staged(parent, "new", b"NEW")
        other = _staged(parent, "other", b"OTHER")
        out_dir = os.path.join(parent, "out")
        publish([("a.bpf.o", old)], out_dir)
        blocker = os.path.join(out_dir, "b.bpf.o")
        os.makedirs(blocker)
        _write(os.path.join(blocker, "keep"), "keep")
        _expect_error(
            lambda: publish(
                [("a.bpf.o", new), ("b.bpf.o", other)], out_dir
            ),
            "MBPF106",
            "evidence.publish",
        )
        with open(os.path.join(out_dir, "a.bpf.o"), "rb") as handle:
            assert handle.read() == b"OLD"
        assert sorted(os.listdir(out_dir)) == ["a.bpf.o", "b.bpf.o"]


def test_publish_rejects_bad_inputs():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = _staged(parent, "a.bpf.o", b"AAA")
        out_dir = os.path.join(parent, "out")
        _expect_error(
            lambda: publish([], out_dir), "MBPF106", "evidence.publish"
        )
        _expect_error(
            lambda: publish(
                [("a.bpf.o", staged), ("a.bpf.o", staged)], out_dir
            ),
            "MBPF106",
            "evidence.publish",
        )
        for bad in ("a/b.bpf.o", "..", ".", ".hidden.bpf.o", ""):
            _expect_error(
                lambda name=bad: publish([(name, staged)], out_dir),
                "MBPF106",
                "evidence.publish",
            )
        _expect_error(
            lambda: publish(
                [("a.bpf.o", os.path.join(parent, "absent"))], out_dir
            ),
            "MBPF106",
            "evidence.publish",
        )
        _expect_error(
            lambda: publish([("lonely",)], out_dir),
            "MBPF106",
            "evidence.publish",
        )
        assert not os.path.exists(out_dir) or os.listdir(out_dir) == []


def test_publish_unrelated_files_untouched():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = _staged(parent, "a.bpf.o", b"AAA")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        _write(os.path.join(out_dir, "notes.txt"), "notes")
        publish([("a.bpf.o", staged)], out_dir)
        assert sorted(os.listdir(out_dir)) == ["a.bpf.o", "notes.txt"]
        with open(os.path.join(out_dir, "notes.txt")) as handle:
            assert handle.read() == "notes"


def test_layout_names():
    layout = evidence_module.layout_names
    assert layout("demo", ("xdp_entry",)) == ("demo.bpf.o",)
    assert layout("demo", ("xdp_entry", "xdp_1")) == (
        "demo.xdp_entry.bpf.o",
        "demo.xdp_1.bpf.o",
    )
    assert evidence_module.artifact_filename(
        "demo", "xdp_entry", False
    ) == "demo.bpf.o"


def test_build_fail_after_success_leaves_out_dir():
    with _scratch() as parent:
        bindir, adapter = _fixture_tools(parent)
        project = _project(parent)
        out_dir = os.path.join(parent, "out")
        request = BuildRequest(
            manifest_path=os.path.join(project, "mojobpf.toml"),
            out_dir=out_dir,
            adapter_path=adapter,
            search_paths=(bindir,),
            timeout_s=60,
            lockfile_path=_lockfile(parent, bindir),
        )
        first = build_project(request)
        assert first.success is True, first.diagnostics
        assert [item.path for item in first.artifacts] == [
            os.path.join(out_dir, "demo.bpf.o"),
            os.path.join(out_dir, "demo.evidence.json"),
        ]
        before = _snapshot(out_dir)
        with _env(MOJOBPF_PUB_MOJO="crash"):
            second = build_project(request)
        assert second.success is False
        assert second.artifacts == ()
        assert [d.code for d in second.diagnostics] == ["MBPF106"]
        # The failing rebuild publishes nothing: the earlier success
        # is byte-identical and unclaimed by the new result.
        assert _snapshot(out_dir) == before


def test_build_published_names_match_layout():
    with _scratch() as parent:
        bindir, adapter = _fixture_tools(parent)
        project = _project(parent)
        out_dir = os.path.join(parent, "out")
        result = build_project(
            BuildRequest(
                manifest_path=os.path.join(project, "mojobpf.toml"),
                out_dir=out_dir,
                adapter_path=adapter,
                search_paths=(bindir,),
                timeout_s=60,
                lockfile_path=_lockfile(parent, bindir),
            )
        )
        assert result.success is True, result.diagnostics
        assert sorted(os.listdir(out_dir)) == sorted(
            list(
                evidence_module.layout_names("demo", ("xdp_entry",))
            )
            + ["demo.evidence.json"]
        )


def test_build_second_entry_rejected_by_reconciliation():
    with _scratch() as parent:
        bindir, adapter = _fixture_tools(parent)
        project = _project(parent, programs=2)
        out_dir = os.path.join(parent, "out")
        result = build_project(
            BuildRequest(
                manifest_path=os.path.join(project, "mojobpf.toml"),
                out_dir=out_dir,
                adapter_path=adapter,
                search_paths=(bindir,),
                timeout_s=60,
                lockfile_path=_lockfile(parent, bindir),
            )
        )
        assert result.success is False
        assert [d.code for d in result.diagnostics] == ["MBPF213"]
        assert result.artifacts == ()
        assert not os.path.exists(out_dir) or (
            os.listdir(out_dir) == []
        )


MAPS_TOML = (
    '[[maps]]\n'
    'name = "mojobpf_map0"\n'
    'map_type = "array"\n'
    'key_type = "u32"\n'
    'value_type = "u64"\n'
    "max_entries = 1\n"
)


def _build_demo(parent, bindir, adapter, project, out_dir):
    return build_project(
        BuildRequest(
            manifest_path=os.path.join(project, "mojobpf.toml"),
            out_dir=out_dir,
            adapter_path=adapter,
            search_paths=(bindir,),
            timeout_s=60,
            lockfile_path=_lockfile(parent, bindir),
        )
    )


def _evidence_doc(out_dir, name="demo.evidence.json"):
    with open(os.path.join(out_dir, name), encoding="utf-8") as handle:
        return json.load(handle)


def _inputs_from_doc(doc):
    def hashed(entry):
        return evidence_module.HashedFile(
            path=entry["path"],
            sha256=entry["sha256"],
            size=entry["size"],
        )

    inputs = doc["inputs"]
    return evidence_module.CacheInputs(
        source=tuple(hashed(e) for e in inputs["source"]),
        imports=tuple(hashed(e) for e in inputs["imports"]),
        sdk=tuple(hashed(e) for e in inputs["sdk"]),
        manifest=hashed(inputs["manifest"]),
        compiler=tuple(inputs["compiler"]),
        flags=tuple(inputs["flags"]),
        profile_id=inputs["profile_id"],
        profile_sha256=inputs["profile_sha256"],
        adapter=tuple(inputs["adapter"]),
        tool_version=inputs["tool_version"],
        sdk_version=inputs["sdk_version"],
    )


def test_build_captures_real_sdk_and_imports():
    with _scratch() as parent:
        bindir, adapter = _fixture_tools(parent)
        project = _project(parent)
        with open(
            os.path.join(project, "mojobpf.toml"), "a",
            encoding="utf-8",
        ) as handle:
            handle.write(MAPS_TOML)
        helper = os.path.join(project, "helper.mojo")
        _write(helper, SOURCE_MOJO + "# helper module\n")
        with open(
            os.path.join(project, "prog.mojo"), "a", encoding="utf-8"
        ) as handle:
            handle.write("from helper import thing\n")
        out_dir = os.path.join(parent, "out")
        with _env(MOJOBPF_PUB_LLC="maps"):
            result = _build_demo(
                parent, bindir, adapter, project, out_dir
            )
        assert result.success is True, result.diagnostics
        doc = _evidence_doc(out_dir)
        frontend = result.commands[0].argv
        recorded_sdk = frontend[frontend.index("-I") + 1]
        # The recorded -I names the origin SDK tree (the
        # compiler read the snapshot's staged copy, retired
        # after the build); the sidecar hashes must match the
        # packaged SDK bytes it was staged from.
        assert os.path.realpath(recorded_sdk) == os.path.realpath(
            _sdk_dir()
        ), frontend
        assert "mojobpf-inputs-" not in recorded_sdk, frontend
        sdk_dir = _sdk_dir()
        expected_sdk = {}
        for root, _dirs, files in os.walk(sdk_dir):
            for name in sorted(files):
                path = os.path.join(root, name)
                rel = os.path.relpath(path, sdk_dir).replace(
                    os.sep, "/"
                )
                with open(path, "rb") as handle:
                    digest = hashlib.sha256(handle.read()).hexdigest()
                expected_sdk["sdk/" + rel] = digest
        observed_sdk = {
            item["path"]: item["sha256"]
            for item in doc["inputs"]["sdk"]
        }
        assert observed_sdk == expected_sdk
        assert len(observed_sdk) >= 1
        with open(helper, "rb") as handle:
            helper_sha = hashlib.sha256(handle.read()).hexdigest()
        assert doc["inputs"]["imports"] == [
            {
                "path": "helper.mojo",
                "sha256": helper_sha,
                "size": os.path.getsize(helper),
            }
        ]
        for tool in ("mojo", "llc"):
            with open(os.path.join(bindir, tool), "rb") as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()
            matches = [
                identity
                for identity in doc["inputs"]["compiler"]
                if identity.startswith(tool + " ")
            ]
            assert len(matches) == 1, doc["inputs"]["compiler"]
            assert matches[0].endswith(digest)
        with open(adapter, "rb") as handle:
            adapter_sha = hashlib.sha256(handle.read()).hexdigest()
        assert doc["inputs"]["adapter"] == [
            "adapter.py %s" % adapter_sha
        ]
        assert doc["inputs"]["profile_id"] == "linux-bpfel-v3"


def test_build_cache_key_invalidates_on_import_change():
    with _scratch() as parent:
        bindir, adapter = _fixture_tools(parent)
        project = _project(parent)
        helper = os.path.join(project, "helper.mojo")
        _write(helper, SOURCE_MOJO)
        with open(
            os.path.join(project, "prog.mojo"), "a", encoding="utf-8"
        ) as handle:
            handle.write("from helper import thing\n")
        out_dir = os.path.join(parent, "out")
        first = _build_demo(parent, bindir, adapter, project, out_dir)
        assert first.success is True, first.diagnostics
        before = _evidence_doc(out_dir)
        with open(helper, "a", encoding="utf-8") as handle:
            handle.write("# changed\n")
        second = _build_demo(parent, bindir, adapter, project, out_dir)
        assert second.success is True, second.diagnostics
        after = _evidence_doc(out_dir)
        assert (
            before["inputs"]["imports"] != after["inputs"]["imports"]
        )
        assert evidence_module.cache_key(
            _inputs_from_doc(before)
        ) != evidence_module.cache_key(_inputs_from_doc(after))


def test_build_cache_key_invalidates_on_sdk_change():
    with _scratch() as parent:
        bindir, adapter = _fixture_tools(parent)
        project = _project(parent)
        with open(
            os.path.join(project, "mojobpf.toml"), "a",
            encoding="utf-8",
        ) as handle:
            handle.write(MAPS_TOML)
        fake_sdk = os.path.join(parent, "fake-sdk")
        os.makedirs(os.path.join(fake_sdk, "mojobpf"))
        sdk_file = os.path.join(fake_sdk, "mojobpf", "helpers.mojo")
        _write(sdk_file, SOURCE_MOJO)
        out_dir = os.path.join(parent, "out")
        build_module = sys.modules["mojobpf.build"]
        real_build_sdk = build_module._sdk_dir
        real_evidence_sdk = evidence_module._sdk_root
        build_module._sdk_dir = lambda: fake_sdk
        evidence_module._sdk_root = lambda: fake_sdk
        try:
            with _env(MOJOBPF_PUB_LLC="maps"):
                first = _build_demo(
                    parent, bindir, adapter, project, out_dir
                )
            assert first.success is True, first.diagnostics
            before = _evidence_doc(out_dir)
            assert [item["path"] for item in before["inputs"]["sdk"]] == [
                "sdk/mojobpf/helpers.mojo"
            ]
            with open(sdk_file, "a", encoding="utf-8") as handle:
                handle.write("# changed\n")
            with _env(MOJOBPF_PUB_LLC="maps"):
                second = _build_demo(
                    parent, bindir, adapter, project, out_dir
                )
            assert second.success is True, second.diagnostics
            after = _evidence_doc(out_dir)
        finally:
            build_module._sdk_dir = real_build_sdk
            evidence_module._sdk_root = real_evidence_sdk
        assert before["inputs"]["sdk"] != after["inputs"]["sdk"]
        assert evidence_module.cache_key(
            _inputs_from_doc(before)
        ) != evidence_module.cache_key(_inputs_from_doc(after))


def _capture_demo(parent, project=None, sdk_dir=None):
    project = project or _project(parent)
    manifest = parse_manifest(os.path.join(project, "mojobpf.toml"))
    toolchain = inputs_module.ToolchainInputs(
        tools=(
            inputs_module.SnapshotTool(
                name="mojo", version="Mojo 9.9.9 (fixture)",
                sha256="1" * 64,
            ),
            inputs_module.SnapshotTool(
                name="llc", version="llc 9.9.9 (fixture)",
                sha256="2" * 64,
            ),
        ),
        distribution=("pixi-lock linux-64 pixi.lock " + "3" * 64,),
        lockfile_sha256="4" * 64,
    )
    sdk = inputs_module.SdkInputs(
        sdk_dir=sdk_dir or parent, version=SDK_VERSION
    )
    return inputs_module.capture_build_inputs(
        manifest, toolchain, sdk, work_parent=parent
    )


def _seal_from_snapshot(snapshot):
    def pairs(items):
        return tuple(
            (os.path.realpath(item.staged), item.sha256)
            for item in items
        )

    return evidence_module.SealedInputs(
        manifest_sha256=snapshot.manifest_digest,
        source_sha256=tuple(
            item.sha256 for item in snapshot.programs
        ),
        sdk=pairs(snapshot.sdk),
        imports=pairs(snapshot.imports),
        adapter=(),
        profile_sha256=snapshot.profile_sha256,
    )


def test_source_grants_imported_gpl_rejected():
    # An imported GPL helper under the declared Apache grant is
    # MBPF702, exactly like a program source. Only old SPDX
    # identifiers appear; no new grant is invented.
    with _scratch() as parent:
        prog = os.path.join(parent, "prog.mojo")
        helper = os.path.join(parent, "helper.mojo")
        _write(prog, SOURCE_MOJO)
        _write(helper, "# SPDX-License-Identifier: GPL-2.0-only\n")
        _expect_error(
            lambda: inspect_module.validate_source_grants(
                APACHE, [prog], project_dir=parent,
                imported_sources=[helper],
            ),
            "MBPF702",
            "inspect.license",
        )


def test_source_grants_imported_missing_header():
    with _scratch() as parent:
        prog = os.path.join(parent, "prog.mojo")
        helper = os.path.join(parent, "helper.mojo")
        _write(prog, SOURCE_MOJO)
        _write(helper, "# no header here\n")
        _expect_error(
            lambda: inspect_module.validate_source_grants(
                APACHE, [prog], project_dir=parent,
                imported_sources=[helper],
            ),
            "MBPF707",
            "inspect.license",
        )


def test_source_grants_imported_two_ids_rejected():
    with _scratch() as parent:
        prog = os.path.join(parent, "prog.mojo")
        helper = os.path.join(parent, "helper.mojo")
        _write(prog, SOURCE_MOJO)
        _write(
            helper,
            "# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception\n"
            "# SPDX-License-Identifier: MIT\n",
        )
        _expect_error(
            lambda: inspect_module.validate_source_grants(
                APACHE, [prog], project_dir=parent,
                imported_sources=[helper],
            ),
            "MBPF703",
            "inspect.license",
        )


def test_source_grants_imports_recorded():
    with _scratch() as parent:
        prog = os.path.join(parent, "prog.mojo")
        helper = os.path.join(parent, "helper.mojo")
        _write(prog, SOURCE_MOJO)
        _write(helper, SOURCE_MOJO)
        record = inspect_module.validate_source_grants(
            APACHE, [prog], project_dir=parent,
            imported_sources=[helper],
        )
    assert [grant.path for grant in record.imports] == ["helper.mojo"]
    assert record.imports[0].spdx == APACHE
    assert len(record.imports[0].sha256) == 64
    assert record.to_dict()["imports"] == [
        record.imports[0].to_dict()
    ]


def test_cache_key_stdlib_change_invalidates():
    base = (
        "mojo Mojo 9.9.9 abc",
        "stdlib distribution pixi-lock linux-64 pixi.lock dead",
        "stdlib lockfile beef",
    )
    changed = evidence_module.cache_key(_cache_inputs(
        compiler=base[:1] + (
            "stdlib distribution pixi-lock linux-64 pixi.lock face",
            "stdlib lockfile beef",
        ),
    ))
    assert changed != evidence_module.cache_key(
        _cache_inputs(compiler=base)
    )
    changed = evidence_module.cache_key(_cache_inputs(
        compiler=base[:2] + ("stdlib lockfile 0000",),
    ))
    assert changed != evidence_module.cache_key(
        _cache_inputs(compiler=base)
    )


def _toolchain_install(parent, std_bytes=b"stdlib-v1",
                       cfg_bytes=b"cfg-v1"):
    """Create a fake toolchain install; return (mojo, home)."""
    bindir = os.path.join(parent, "bin")
    libdir = os.path.join(parent, "lib", "mojo")
    home = os.path.join(parent, "max")
    os.makedirs(bindir)
    os.makedirs(libdir)
    os.makedirs(home)
    mojo = os.path.join(bindir, "mojo")
    _write(mojo, b"mojo-binary")
    _write(os.path.join(libdir, "std.mojoc"), std_bytes)
    _write(os.path.join(home, "modular.cfg"), cfg_bytes)
    return mojo, home


def test_stdlib_payload_swap_changes_identities():
    # The installed stdlib payload the toolchain resolves is
    # hashed, not just the lockfile record: swapping either
    # payload file changes the identity, with no paths leaking.
    with _scratch() as parent:
        mojo, home = _toolchain_install(parent)
        base = inputs_module.stdlib_payload_identities(
            mojo_binary=mojo, modular_home=home
        )
        assert len(base) == 2, base
        for entry in base:
            assert parent not in entry, entry
        std = os.path.join(parent, "lib", "mojo", "std.mojoc")
        cfg = os.path.join(home, "modular.cfg")
        _write(std, b"stdlib-v2")
        assert inputs_module.stdlib_payload_identities(
            mojo_binary=mojo, modular_home=home
        ) != base
        _write(std, b"stdlib-v1")
        _write(cfg, b"cfg-v2")
        assert inputs_module.stdlib_payload_identities(
            mojo_binary=mojo, modular_home=home
        ) != base


def test_stdlib_payload_missing_is_explicit():
    with _scratch() as parent:
        mojo, home = _toolchain_install(parent)
        os.remove(os.path.join(parent, "lib", "mojo", "std.mojoc"))
        entries = inputs_module.stdlib_payload_identities(
            mojo_binary=mojo, modular_home=home
        )
        assert len(entries) == 2, entries
        assert any("missing" in entry for entry in entries), entries
        for entry in entries:
            assert parent not in entry, entry
        assert inputs_module.stdlib_payload_identities(
            mojo_binary=None, modular_home=None
        ) == inputs_module.stdlib_payload_identities(
            mojo_binary=None, modular_home=None
        )


def test_stdlib_payload_swap_changes_snapshot_and_cache_key():
    # A payload swap with identical lockfile records changes the
    # snapshot identity and invalidates the cache key.
    with _scratch() as parent:
        project = _project(parent)
        mojo, home = _toolchain_install(parent)
        manifest = parse_manifest(
            os.path.join(project, "mojobpf.toml")
        )

        def _capture(payload):
            toolchain = inputs_module.ToolchainInputs(
                tools=(
                    inputs_module.SnapshotTool(
                        name="mojo",
                        version="Mojo 9.9.9 (fixture)",
                        sha256="1" * 64,
                    ),
                ),
                distribution=("pixi-lock linux-64 " + "3" * 64,),
                lockfile_sha256="4" * 64,
                stdlib_payload=payload,
            )
            sdk = inputs_module.SdkInputs(
                sdk_dir=parent, version=SDK_VERSION
            )
            return inputs_module.capture_build_inputs(
                manifest, toolchain, sdk, work_parent=parent
            )

        payload_v1 = inputs_module.stdlib_payload_identities(
            mojo_binary=mojo, modular_home=home
        )
        first = _capture(payload_v1)
        try:
            _write(
                os.path.join(parent, "lib", "mojo", "std.mojoc"),
                b"stdlib-v2",
            )
            payload_v2 = inputs_module.stdlib_payload_identities(
                mojo_binary=mojo, modular_home=home
            )
            second = _capture(payload_v2)
            try:
                assert first.stdlib != second.stdlib
                tools = ("mojo Mojo 9.9.9 " + "1" * 64,)
                assert evidence_module.cache_key(
                    _cache_inputs(compiler=tools + first.stdlib)
                ) != evidence_module.cache_key(
                    _cache_inputs(compiler=tools + second.stdlib)
                )
            finally:
                second.dispose()
        finally:
            first.dispose()


def test_cache_key_environment_change_invalidates():
    base = (
        "mojo Mojo 9.9.9 abc",
        "stdlib distribution unbound no-toolchain-binding",
        "env MODULAR_HOME=sha256:aaaa",
        "env PATH=sha256:bbbb",
    )
    changed = evidence_module.cache_key(_cache_inputs(
        compiler=base[:3] + ("env PATH=sha256:cccc",),
    ))
    assert changed != evidence_module.cache_key(
        _cache_inputs(compiler=base)
    )
    changed = evidence_module.cache_key(_cache_inputs(
        compiler=base + ("env MOJO_X=1",),
    ))
    assert changed != evidence_module.cache_key(
        _cache_inputs(compiler=base)
    )


def test_evidence_snapshot_uses_sealed_environment():
    # The sealed capture-time environment feeds the record and
    # the cache identity even when the ambient environment has
    # moved on by capture time.
    with _scratch() as parent:
        project = _project(parent)
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        with _env(PATH="/sealed/bin", MODULAR_HOME="/sealed/max"):
            snapshot = _capture_demo(parent, project)
        try:
            sealed_hash = hashlib.sha256(b"/sealed/bin").hexdigest()
            assert ("PATH", "sha256:" + sealed_hash) in (
                snapshot.environment
            )
            with _env(
                PATH="/ambient/bin", MODULAR_HOME="/ambient/max"
            ):
                result = _synthetic_result(project, out_dir)
                manifest = _synthetic_manifest(project)
                evidence = evidence_module.evidence_from_build(
                    result,
                    manifest,
                    project_dir=project,
                    out_dir=out_dir,
                    transforms=("frontend",),
                    sealed=_seal_from_snapshot(snapshot),
                    snapshot=snapshot,
                )
        finally:
            snapshot.dispose()
    recorded = {entry.name: entry.value for entry in evidence.environment}
    assert recorded["PATH"] == "sha256:" + sealed_hash
    assert recorded["MODULAR_HOME"] == (
        "sha256:" + hashlib.sha256(b"/sealed/max").hexdigest()
    )
    assert (
        "env PATH=sha256:%s" % sealed_hash
    ) in evidence.inputs.compiler


def test_evidence_snapshot_commands_normalize():
    with _scratch() as parent:
        project = _project(parent)
        with open(
            os.path.join(project, "mojobpf.toml"), "a",
            encoding="utf-8",
        ) as handle:
            handle.write(MAPS_TOML)
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        snapshot = _capture_demo(
            parent, project, sdk_dir=_sdk_dir()
        )
        try:
            assert snapshot.sdk_root is not None
            staged_prog = snapshot.programs[0].staged
            record = CommandRecord(
                argv=(
                    "/opt/toolchain/bin/mojo", "build", "-I",
                    snapshot.sdk_root,
                    "-o", os.path.join(out_dir, "x.bpf.o"),
                    staged_prog,
                ),
                stage="build.frontend",
                status="ok",
                exit_code=0,
                duration_s=1.0,
                log_excerpt="",
            )
            result = dataclasses.replace(
                _synthetic_result(project, out_dir),
                commands=(record,),
            )
            manifest = _synthetic_manifest(project)
            evidence = evidence_module.evidence_from_build(
                result,
                manifest,
                project_dir=project,
                out_dir=out_dir,
                transforms=("frontend",),
                sdk_files=[
                    item.staged for item in snapshot.sdk
                ],
                imported_sources=[
                    item.staged for item in snapshot.imports
                ],
                sealed=_seal_from_snapshot(snapshot),
                snapshot=snapshot,
            )
            raw = evidence_module.dumps_evidence(evidence)
        finally:
            snapshot.dispose()
    assert snapshot.root.encode() not in raw
    argv = evidence.commands[0].argv
    assert "$SRC/prog.mojo" in argv, argv
    assert "$OUT/x.bpf.o" in argv, argv
    assert "$SDK" in argv, argv


def test_snapshot_two_roots_compare_equal():
    # Identical inputs captured in two roots compare equal: the
    # capture-local paths never participate in identity.
    with _scratch() as parent:
        first = _project(parent, name="proj-a")
        second = _project(parent, name="proj-b")
        helper_a = os.path.join(first, "helper.mojo")
        helper_b = os.path.join(second, "helper.mojo")
        _write(helper_a, SOURCE_MOJO)
        _write(helper_b, SOURCE_MOJO)
        for project in (first, second):
            with open(
                os.path.join(project, "prog.mojo"), "a",
                encoding="utf-8",
            ) as handle:
                handle.write("from helper import thing\n")
        left = _capture_demo(parent, first)
        right = _capture_demo(parent, second)
        try:
            assert left.root != right.root
            assert left == right
            assert hash(left) == hash(right)
        finally:
            left.dispose()
            right.dispose()


def test_evidence_snapshot_rejects_staged_drift():
    # Staged bytes changed after capture: evidence capture
    # rejects (MBPF708) instead of reporting the clean hash for
    # changed consumed bytes.
    with _scratch() as parent:
        project = _project(parent)
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        snapshot = _capture_demo(parent, project)
        try:
            staged = snapshot.programs[0].staged
            os.chmod(staged, 0o644)
            with open(staged, "ab") as handle:
                handle.write(b"# drifted\n")
            result = _synthetic_result(project, out_dir)
            manifest = _synthetic_manifest(project)
            try:
                evidence_module.evidence_from_build(
                    result,
                    manifest,
                    project_dir=project,
                    out_dir=out_dir,
                    transforms=("frontend",),
                    sealed=_seal_from_snapshot(snapshot),
                    snapshot=snapshot,
                )
            except evidence_module.EvidenceError as exc:
                assert exc.diagnostic.code == "MBPF708"
                assert exc.diagnostic.stage == "evidence.capture"
            else:
                raise AssertionError("staged drift was attributed")
        finally:
            snapshot.dispose()


def test_snapshot_verify_rejects_tamper_add_remove():
    with _scratch() as parent:
        project = _project(parent)
        snapshot = _capture_demo(parent, project)
        try:
            staged = snapshot.programs[0].staged
            with open(staged, "rb") as handle:
                clean = handle.read()
            snapshot.verify()
            os.chmod(staged, 0o644)
            with open(staged, "ab") as handle:
                handle.write(b"# tampered\n")
            try:
                snapshot.verify()
            except inputs_module.InputError as exc:
                assert exc.diagnostic.code == "MBPF106"
                assert exc.diagnostic.stage == "build.inputs"
                assert "changed after capture" in (
                    exc.diagnostic.explanation
                )
            else:
                raise AssertionError("tamper was accepted")
            with open(staged, "wb") as handle:
                handle.write(clean)
            os.chmod(staged, 0o444)
            snapshot.verify()
            added = os.path.join(snapshot.project_root, "added.mojo")
            with open(added, "w", encoding="utf-8") as handle:
                handle.write("# added\n")
            try:
                snapshot.verify()
            except inputs_module.InputError as exc:
                assert "appeared" in exc.diagnostic.explanation
            else:
                raise AssertionError("added file was accepted")
            os.remove(added)
            snapshot.verify()
            os.chmod(staged, 0o644)
            os.remove(staged)
            try:
                snapshot.verify()
            except inputs_module.InputError as exc:
                assert "went missing" in exc.diagnostic.explanation
            else:
                raise AssertionError("missing file was accepted")
        finally:
            snapshot.dispose()


def test_stable_env_value_single_source():
    assert (
        evidence_module.stable_env_value
        is inputs_module.stable_env_value
    )
    assert (
        inputs_module.stable_env_value("/opt/bin")
    ).startswith("sha256:")
    assert inputs_module.stable_env_value("plain") == "plain"


# --- Hardened publication: owned directories, swap detection. ---

# The tests below inject the F-034 adversary deterministically:
# file-to-symlink swaps between the predecessor check and the
# backup read, predecessor changes between backup and replace, and
# output-directory swaps between renames. Publication must refuse
# every injected shape (MBPF106 at evidence.publish), keep the
# original directory's previous output intact, never mutate through
# a swapped path, and record rollback failures instead of
# swallowing them.


def test_publish_rejects_symlinked_out_dir():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = _staged(parent, "a.bpf.o", b"AAA")
        target = os.path.join(parent, "real")
        os.makedirs(target)
        link = os.path.join(parent, "out")
        os.symlink(target, link)
        exc = _expect_error(
            lambda: publish([("a.bpf.o", staged)], link),
            "MBPF106",
            "evidence.publish",
        )
        assert "symlink" in exc.diagnostic.explanation
        assert os.listdir(target) == []
        assert os.path.islink(link)


def test_publish_rejects_symlinked_out_dir_spellings():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = _staged(parent, "a.bpf.o", b"AAA")
        target = os.path.join(parent, "real")
        os.makedirs(target)
        link = os.path.join(parent, "out")
        os.symlink(target, link)
        # Trailing slashes and dots resolve the link before
        # inspection; every spelling must still be refused.
        for spelling in (
            link + "/",
            link + "//",
            link + "/.",
            link + "/./",
        ):
            exc = _expect_error(
                lambda: publish([("a.bpf.o", staged)], spelling),
                "MBPF106",
                "evidence.publish",
            )
            assert "symlink" in exc.diagnostic.explanation, spelling
        assert os.listdir(target) == []
        assert os.path.islink(link)
        # Real directories keep working under the same
        # spellings; normalization must not break them.
        out_dir = os.path.join(parent, "plain")
        os.makedirs(out_dir)
        first = _staged(parent, "first.bpf.o", b"AAA")
        published = publish(
            [("first.bpf.o", first)], out_dir + "/"
        )
        assert [item.name for item in published] == ["first.bpf.o"]
        second = _staged(parent, "second.bpf.o", b"BBB")
        published = publish(
            [("second.bpf.o", second)], out_dir + "/."
        )
        assert [item.name for item in published] == ["second.bpf.o"]
        with open(
            os.path.join(out_dir, "first.bpf.o"), "rb"
        ) as handle:
            assert handle.read() == b"AAA"


def test_publish_requires_owned_out_dir():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = _staged(parent, "a.bpf.o", b"AAA")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        real_geteuid = os.geteuid
        os.geteuid = lambda: real_geteuid() + 1
        try:
            exc = _expect_error(
                lambda: publish([("a.bpf.o", staged)], out_dir),
                "MBPF106",
                "evidence.publish",
            )
        finally:
            os.geteuid = real_geteuid
        assert "owned" in exc.diagnostic.explanation
        assert os.listdir(out_dir) == []


def test_publish_ownership_token_claim_and_enforce():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        first = _staged(parent, "a.bpf.o", b"AAA")
        out_dir = os.path.join(parent, "out")
        # The first token use claims the directory for that run.
        published = publish(
            [("a.bpf.o", first)], out_dir, ownership_token="run-A"
        )
        assert [item.name for item in published] == ["a.bpf.o"]
        record = os.path.join(out_dir, ".mojobpf-run-owner")
        with open(record, "rb") as handle:
            assert handle.read() == b"run-A"
        # The owning run republishes; another run's token is
        # rejected with nothing written.
        second = _staged(parent, "b.bpf.o", b"BBB")
        published = publish(
            [("b.bpf.o", second)], out_dir, ownership_token="run-A"
        )
        assert [item.name for item in published] == ["b.bpf.o"]
        third = _staged(parent, "c.bpf.o", b"CCC")
        exc = _expect_error(
            lambda: publish(
                [("c.bpf.o", third)], out_dir,
                ownership_token="run-B",
            ),
            "MBPF106",
            "evidence.publish",
        )
        assert "another run" in exc.diagnostic.explanation
        assert not os.path.lexists(os.path.join(out_dir, "c.bpf.o"))
        with open(record, "rb") as handle:
            assert handle.read() == b"run-A"
        # A token-less publish into a claimed directory is
        # rejected too: the claim is not optional once set.
        exc = _expect_error(
            lambda: publish([("c.bpf.o", third)], out_dir),
            "MBPF106",
            "evidence.publish",
        )
        assert "another run" in exc.diagnostic.explanation
        # Legacy unclaimed directories still publish token-less
        # and gain no record file.
        plain = os.path.join(parent, "plain")
        publish([("a.bpf.o", first)], plain)
        assert sorted(os.listdir(plain)) == ["a.bpf.o"]


def test_publish_ownership_token_malformed_and_spoofed():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = _staged(parent, "a.bpf.o", b"AAA")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        for bad in ("", b"", 123, ["run-A"], {"token": "run-A"}):
            exc = _expect_error(
                lambda b=bad: publish(
                    [("a.bpf.o", staged)], out_dir,
                    ownership_token=b,
                ),
                "MBPF106",
                "evidence.publish",
            )
            assert "ownership token" in exc.diagnostic.explanation
        assert os.listdir(out_dir) == []
        # Bytes tokens are accepted and stored verbatim.
        published = publish(
            [("a.bpf.o", staged)], out_dir,
            ownership_token=b"bytes-token",
        )
        assert [item.name for item in published] == ["a.bpf.o"]
        with open(
            os.path.join(out_dir, ".mojobpf-run-owner"), "rb"
        ) as handle:
            assert handle.read() == b"bytes-token"
        # A symlink planted at the record is never followed.
        linked = os.path.join(parent, "linked")
        os.makedirs(linked)
        foreign = os.path.join(parent, "foreign")
        _write(foreign, "run-A")
        os.symlink(
            foreign,
            os.path.join(linked, ".mojobpf-run-owner"),
        )
        exc = _expect_error(
            lambda: publish(
                [("a.bpf.o", staged)], linked,
                ownership_token="run-A",
            ),
            "MBPF106",
            "evidence.publish",
        )
        assert "ownership" in exc.diagnostic.explanation
        assert not os.path.lexists(
            os.path.join(linked, "a.bpf.o")
        )


def _swapping_lstat_factory(victim_path, make_swap, fire_on=1,
                            order="after"):
    """Wrap os.lstat to inject one swap on a victim basename.

    On the ``fire_on``-th observation of the victim, the wrapper
    runs ``make_swap`` either after the real lstat (``order``
    ``"after"``: the check sees pre-swap bytes, defeating
    single-point checks) or before it (``order`` ``"before"``: the
    check sees post-swap bytes, defeating compare-against-earlier
    rechecks only when they are absent). Returns (wrapper,
    fired-flag-list, real-lstat) for try/finally restoration by
    the caller.
    """
    real_lstat = os.lstat
    victim = os.path.basename(victim_path)
    seen = []
    fired = []

    def swapping_lstat(path, *args, **kwargs):
        name = path if isinstance(path, str) else ""
        fire = os.path.basename(name) == victim and not fired
        if fire:
            seen.append(True)
            fire = len(seen) == fire_on
        if fire and order == "before":
            fired.append(True)
            make_swap(None)
        observed = real_lstat(path, *args, **kwargs)
        if fire and order == "after":
            fired.append(True)
            make_swap(observed)
        return observed

    return swapping_lstat, fired, real_lstat


def test_publish_backup_swap_rejected():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = _staged(parent, "a.bpf.o", b"NEW")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        victim = os.path.join(out_dir, "a.bpf.o")
        _write(victim, b"OLD")
        outside = os.path.join(parent, "outside.o")
        _write(outside, b"OUTSIDE")

        def swap_to_link(_observed):
            os.remove(victim)
            os.symlink(outside, victim)

        wrapper, fired, real_lstat = _swapping_lstat_factory(
            victim, swap_to_link
        )
        os.lstat = wrapper
        try:
            exc = _expect_error(
                lambda: publish([("a.bpf.o", staged)], out_dir),
                "MBPF106",
                "evidence.publish",
            )
        finally:
            os.lstat = real_lstat
        assert fired, "swap never injected"
        assert "symlink" in exc.diagnostic.explanation
        # The injected link is left alone and the outside target
        # is never read through: no backup of foreign bytes exists.
        assert os.path.islink(victim)
        with open(outside, "rb") as handle:
            assert handle.read() == b"OUTSIDE"
        assert [
            name for name in os.listdir(out_dir)
            if name.startswith(".")
        ] == []


def test_publish_backup_swap_keeps_rollback_honest():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        first = _staged(parent, "a.bpf.o", b"NEW-A")
        second = _staged(parent, "b.bpf.o", b"NEW-B")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        victim = os.path.join(out_dir, "a.bpf.o")
        _write(victim, b"OLD-A")
        blocker = os.path.join(out_dir, "b.bpf.o")
        os.makedirs(blocker)
        outside = os.path.join(parent, "outside.o")
        _write(outside, b"OUTSIDE")

        def swap_to_link(_observed):
            os.remove(victim)
            os.symlink(outside, victim)

        wrapper, fired, real_lstat = _swapping_lstat_factory(
            victim, swap_to_link
        )
        os.lstat = wrapper
        try:
            _expect_error(
                lambda: publish(
                    [("a.bpf.o", first), ("b.bpf.o", second)],
                    out_dir,
                ),
                "MBPF106",
                "evidence.publish",
            )
        finally:
            os.lstat = real_lstat
        assert fired, "swap never injected"
        # A link-following backup would restore the outside bytes
        # as the predecessor; the link must survive instead.
        assert os.path.islink(victim)
        with open(outside, "rb") as handle:
            assert handle.read() == b"OUTSIDE"
        assert os.path.isdir(blocker)


def test_publish_predecessor_change_before_replace_rejected():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = _staged(parent, "a.bpf.o", b"NEW")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        victim = os.path.join(out_dir, "a.bpf.o")
        _write(victim, b"OLD")
        plant = os.path.join(parent, "plant.o")
        _write(plant, b"PLANT")

        def swap_inode(_observed):
            # A new directory entry: same name, new identity.
            os.remove(victim)
            shutil.copyfile(plant, victim)

        # Fire on the second observation: after the backup read,
        # before the replace. The recheck observes post-swap
        # bytes; without a recheck the planted bytes publish.
        wrapper, fired, real_lstat = _swapping_lstat_factory(
            victim, swap_inode, fire_on=2, order="before"
        )
        os.lstat = wrapper
        try:
            exc = _expect_error(
                lambda: publish([("a.bpf.o", staged)], out_dir),
                "MBPF106",
                "evidence.publish",
            )
        finally:
            os.lstat = real_lstat
        assert fired, "swap never injected"
        assert "changed" in exc.diagnostic.explanation
        with open(victim, "rb") as handle:
            assert handle.read() == b"OLD"
        assert not os.path.islink(victim)
        assert [
            name for name in os.listdir(out_dir)
            if name.startswith(".")
        ] == []


def test_publish_second_file_recheck_failure_rolls_back_first():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        first = _staged(parent, "a.bpf.o", b"NEW-A")
        second = _staged(parent, "b.bpf.o", b"NEW-B")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        first_path = os.path.join(out_dir, "a.bpf.o")
        victim = os.path.join(out_dir, "b.bpf.o")
        _write(first_path, b"OLD-A")
        _write(victim, b"OLD-B")
        plant = os.path.join(parent, "plant.o")
        _write(plant, b"PLANT")

        def swap_inode(_observed):
            os.remove(victim)
            shutil.copyfile(plant, victim)

        wrapper, fired, real_lstat = _swapping_lstat_factory(
            victim, swap_inode, fire_on=2, order="before"
        )
        os.lstat = wrapper
        try:
            exc = _expect_error(
                lambda: publish(
                    [("a.bpf.o", first), ("b.bpf.o", second)],
                    out_dir,
                ),
                "MBPF106",
                "evidence.publish",
            )
        finally:
            os.lstat = real_lstat
        assert fired, "swap never injected"
        assert "changed" in exc.diagnostic.explanation
        with open(first_path, "rb") as handle:
            assert handle.read() == b"OLD-A"
        with open(victim, "rb") as handle:
            assert handle.read() == b"OLD-B"
        assert [
            name for name in os.listdir(out_dir)
            if name.startswith(".")
        ] == []


def test_publish_out_dir_swap_mid_flight_detected():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = _staged(parent, "a.bpf.o", b"NEW")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        victim = os.path.join(out_dir, "a.bpf.o")
        _write(victim, b"OLD")
        aside = os.path.join(parent, "aside")
        real_replace = os.replace
        fired = []

        def swapping_replace(src, dst, *args, **kwargs):
            if not fired:
                fired.append(True)
                os.rename(out_dir, aside)
                os.makedirs(out_dir)
            return real_replace(src, dst, *args, **kwargs)

        os.replace = swapping_replace
        try:
            exc = _expect_error(
                lambda: publish([("a.bpf.o", staged)], out_dir),
                "MBPF106",
                "evidence.publish",
            )
        finally:
            os.replace = real_replace
        assert fired, "swap never injected"
        assert "swapped" in exc.diagnostic.explanation
        # The original directory keeps its previous output; the
        # swapped-in directory is reported, never cleaned.
        with open(os.path.join(aside, "a.bpf.o"), "rb") as handle:
            assert handle.read() == b"OLD"
        assert [
            name for name in os.listdir(aside)
            if name.startswith(".")
        ] == []
        assert os.listdir(out_dir) == []


def test_publish_out_dir_symlink_swap_mid_flight_detected():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = _staged(parent, "a.bpf.o", b"NEW")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        victim = os.path.join(out_dir, "a.bpf.o")
        _write(victim, b"OLD")
        aside = os.path.join(parent, "aside")
        fresh = os.path.join(parent, "fresh")
        os.makedirs(fresh)
        real_replace = os.replace
        fired = []

        carried_names = []

        def swapping_replace(src, dst, *args, **kwargs):
            if not fired:
                fired.append(True)
                # Swap the directory for a link, then carry the
                # in-flight temporary across: a string-path rename
                # would land in the swapped-in directory.
                os.rename(out_dir, aside)
                os.symlink(fresh, out_dir)
                carried = os.path.join(
                    fresh, os.path.basename(src)
                )
                shutil.copyfile(
                    os.path.join(aside, os.path.basename(src)),
                    carried,
                )
                carried_names.append(os.path.basename(src))
            return real_replace(src, dst, *args, **kwargs)

        os.replace = swapping_replace
        try:
            exc = _expect_error(
                lambda: publish([("a.bpf.o", staged)], out_dir),
                "MBPF106",
                "evidence.publish",
            )
        finally:
            os.replace = real_replace
        assert fired, "swap never injected"
        assert "swapped" in exc.diagnostic.explanation
        with open(os.path.join(aside, "a.bpf.o"), "rb") as handle:
            assert handle.read() == b"OLD"
        assert [
            name for name in os.listdir(aside)
            if name.startswith(".")
        ] == []
        # The rename runs through the pinned descriptor, so the
        # carried temporary is never used: no new output lands in
        # the swapped-in directory, which is left alone.
        assert carried_names, "carried temporary never staged"
        assert not os.path.lexists(os.path.join(fresh, "a.bpf.o"))
        assert sorted(os.listdir(fresh)) == sorted(carried_names)
        with open(
            os.path.join(fresh, carried_names[0]), "rb"
        ) as handle:
            assert handle.read() == b"NEW"


def test_publish_swap_rollback_failure_recorded():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = _staged(parent, "a.bpf.o", b"NEW")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        victim = os.path.join(out_dir, "a.bpf.o")
        _write(victim, b"OLD")
        aside = os.path.join(parent, "aside")
        fresh = os.path.join(parent, "fresh")
        os.makedirs(fresh)
        real_replace = os.replace
        fired = []

        def swapping_replace(src, dst, *args, **kwargs):
            if not fired:
                fired.append(True)
                os.rename(out_dir, aside)
                os.symlink(fresh, out_dir)
                shutil.copyfile(
                    os.path.join(aside, os.path.basename(src)),
                    os.path.join(fresh, os.path.basename(src)),
                )
                # Destroy the recovery backup: the pinned
                # predecessor can no longer be restored.
                for name in os.listdir(aside):
                    if ".backup." in name:
                        os.remove(os.path.join(aside, name))
            return real_replace(src, dst, *args, **kwargs)

        os.replace = swapping_replace
        try:
            exc = _expect_error(
                lambda: publish([("a.bpf.o", staged)], out_dir),
                "MBPF106",
                "evidence.publish",
            )
        finally:
            os.replace = real_replace
        assert fired, "swap never injected"
        assert "incomplete" in exc.diagnostic.explanation
        assert "missing" in exc.diagnostic.explanation
        # The rename landed in the pinned directory but the
        # predecessor backup is gone, so the rollback is honestly
        # incomplete: the new bytes stay, recorded as a failure,
        # and nothing is written through the swapped path.
        with open(os.path.join(aside, "a.bpf.o"), "rb") as handle:
            assert handle.read() == b"NEW"
        assert not os.path.lexists(os.path.join(fresh, "a.bpf.o"))


def test_publish_reswap_during_rollback_still_rolls_back():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = {
            name: _staged(parent, name, b"NEW-" + name.encode())
            for name in ("a.bpf.o", "b.bpf.o", "c.bpf.o")
        }
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        for name in staged:
            _write(
                os.path.join(out_dir, name),
                b"OLD-" + name.encode(),
            )
        aside = os.path.join(parent, "aside")
        real_replace = os.replace
        publishes = []
        swapped = []

        def flapping_replace(src, dst, *args, **kwargs):
            if ".backup." in os.path.basename(src):
                if not swapped:
                    # Re-swap mid-rollback: restores run through
                    # the pinned descriptor, so the flip must
                    # neither break them nor divert them into the
                    # swapped-in path (which holds a planted
                    # same-name file as a diversion tripwire).
                    swapped.append(True)
                    os.rename(out_dir, aside)
                    os.makedirs(out_dir)
                    _write(
                        os.path.join(out_dir, "b.bpf.o"),
                        b"PLANTED",
                    )
                return real_replace(src, dst, *args, **kwargs)
            publishes.append((src, dst))
            if len(publishes) == 3:
                raise OSError("fixture third-rename failure")
            return real_replace(src, dst, *args, **kwargs)

        os.replace = flapping_replace
        try:
            exc = _expect_error(
                lambda: publish(
                    sorted(
                        (name, path)
                        for name, path in staged.items()
                    ),
                    out_dir,
                ),
                "MBPF106",
                "evidence.publish",
            )
        finally:
            os.replace = real_replace
        assert swapped, "mid-rollback swap never injected"
        # The original rename failure is reported; the rollback
        # itself is complete despite the mid-rollback flip.
        assert "c.bpf.o" in exc.diagnostic.explanation
        assert "incomplete" not in exc.diagnostic.explanation
        for name in staged:
            with open(os.path.join(aside, name), "rb") as handle:
                assert handle.read() == b"OLD-" + name.encode()
        assert [
            name for name in os.listdir(aside)
            if ".backup." in name
        ] == [], os.listdir(aside)
        # The swapped-in path was never mutated: the planted
        # file is intact and nothing else landed there.
        assert os.listdir(out_dir) == ["b.bpf.o"]
        with open(os.path.join(out_dir, "b.bpf.o"), "rb") as handle:
            assert handle.read() == b"PLANTED"


def _failing_unlink_factory(victim_name):
    """Wrap os.unlink to fail once with EACCES on one basename.

    Returns (wrapper, fired-flag-list, real-unlink) for
    try/finally restoration by the caller; every other unlink
    is forwarded untouched.
    """
    real_unlink = os.unlink
    fired = []

    def failing_unlink(path, *args, **kwargs):
        name = path if isinstance(path, str) else ""
        if os.path.basename(name) == victim_name and not fired:
            fired.append(True)
            raise PermissionError(errno.EACCES, "fixture unlink")
        return real_unlink(path, *args, **kwargs)

    return failing_unlink, fired, real_unlink


def test_publish_failed_new_file_unlink_recorded():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        first = _staged(parent, "a.bpf.o", b"NEW")
        second = _staged(parent, "b.bpf.o", b"BBBB")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        blocker = os.path.join(out_dir, "b.bpf.o")
        os.makedirs(blocker)
        unlink, unlink_fired, real_unlink = _failing_unlink_factory(
            "a.bpf.o"
        )
        os.unlink = unlink
        try:
            exc = _expect_error(
                lambda: publish(
                    [("a.bpf.o", first), ("b.bpf.o", second)],
                    out_dir,
                ),
                "MBPF106",
                "evidence.publish",
            )
        finally:
            os.unlink = real_unlink
        assert unlink_fired, "unlink failure never injected"
        # The new file could not be removed: the rollback is
        # incomplete, the retained bytes stay, and the error
        # says so instead of reporting a clean rollback.
        assert "incomplete" in exc.diagnostic.explanation
        assert "a.bpf.o" in exc.diagnostic.explanation
        with open(os.path.join(out_dir, "a.bpf.o"), "rb") as handle:
            assert handle.read() == b"NEW"


def test_publish_interrupted_new_file_unlink_incomplete():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = _staged(parent, "a.bpf.o", b"NEW")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        real_replace = os.replace
        unlink, unlink_fired, real_unlink = _failing_unlink_factory(
            "a.bpf.o"
        )

        def interrupting(src, dst, *args, **kwargs):
            real_replace(src, dst, *args, **kwargs)
            raise KeyboardInterrupt("fixture interrupt")

        os.replace = interrupting
        os.unlink = unlink
        caught = None
        try:
            publish([("a.bpf.o", staged)], out_dir)
        except KeyboardInterrupt as exc:
            caught = exc
        else:
            raise AssertionError("expected KeyboardInterrupt")
        finally:
            os.replace = real_replace
            os.unlink = real_unlink
        assert unlink_fired, "unlink failure never injected"
        recovery = evidence_module.publication_recovery(caught)
        assert recovery is not None
        assert recovery.complete is False
        assert len(recovery.failures) == 1
        assert "a.bpf.o" in recovery.failures[0]
        with open(os.path.join(out_dir, "a.bpf.o"), "rb") as handle:
            assert handle.read() == b"NEW"


def test_publish_swapped_new_file_unlink_recorded():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = _staged(parent, "a.bpf.o", b"NEW")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        aside = os.path.join(parent, "aside")
        real_replace = os.replace
        unlink, unlink_fired, real_unlink = _failing_unlink_factory(
            "a.bpf.o"
        )
        fired = []

        def swapping_replace(src, dst, *args, **kwargs):
            if not fired:
                fired.append(True)
                os.rename(out_dir, aside)
                os.makedirs(out_dir)
            return real_replace(src, dst, *args, **kwargs)

        os.replace = swapping_replace
        os.unlink = unlink
        try:
            exc = _expect_error(
                lambda: publish([("a.bpf.o", staged)], out_dir),
                "MBPF106",
                "evidence.publish",
            )
        finally:
            os.replace = real_replace
            os.unlink = real_unlink
        assert fired, "swap never injected"
        assert unlink_fired, "unlink failure never injected"
        assert "incomplete" in exc.diagnostic.explanation
        with open(os.path.join(aside, "a.bpf.o"), "rb") as handle:
            assert handle.read() == b"NEW"
        assert os.listdir(out_dir) == []


def test_publish_swapped_result_rejected():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = _staged(parent, "a.bpf.o", b"NEW")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        victim = os.path.join(out_dir, "a.bpf.o")
        _write(victim, b"OLD")
        plant = os.path.join(parent, "plant.o")
        _write(plant, b"PLANT")
        real_open = os.open
        seen = []
        fired = []

        def swapping_open(path, flags, *args, **kwargs):
            name = path if isinstance(path, str) else ""
            if os.path.basename(name) == "a.bpf.o":
                seen.append(True)
                # The second victim open is the post-rename hash
                # read (the first is the backup read): swap the
                # installed file for planted bytes just before it.
                if len(seen) == 2 and not fired:
                    fired.append(True)
                    os.remove(victim)
                    shutil.copyfile(plant, victim)
            return real_open(path, flags, *args, **kwargs)

        os.open = swapping_open
        try:
            exc = _expect_error(
                lambda: publish([("a.bpf.o", staged)], out_dir),
                "MBPF106",
                "evidence.publish",
            )
        finally:
            os.open = real_open
        assert fired, "result swap never injected"
        assert "swapped" in exc.diagnostic.explanation
        # The planted bytes are rolled back, not reported: the
        # predecessor is restored and no digest of foreign bytes
        # is ever returned.
        with open(victim, "rb") as handle:
            assert handle.read() == b"OLD"
        assert [
            name for name in os.listdir(out_dir)
            if name.startswith(".")
        ] == []


def test_publish_final_window_symlink_never_followed():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = _staged(parent, "a.bpf.o", b"NEW")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        victim = os.path.join(out_dir, "a.bpf.o")
        _write(victim, b"OLD")
        outside = os.path.join(parent, "outside.o")
        _write(outside, b"OUTSIDE")
        real_replace = os.replace
        fired = []

        def interposing_replace(src, dst, *args, **kwargs):
            if not fired:
                # The final recheck has already passed at this
                # point; interpose a symlink to an outside
                # target in the remaining window.
                fired.append(True)
                os.remove(victim)
                os.symlink(outside, victim)
            return real_replace(src, dst, *args, **kwargs)

        os.replace = interposing_replace
        try:
            published = publish([("a.bpf.o", staged)], out_dir)
        finally:
            os.replace = real_replace
        assert fired, "symlink never interposed"
        # Residual window, pinned guarantee: the rename removes
        # the interposed link without following it. The outside
        # target is untouched, the installed bytes are exactly
        # the staged bytes, and the reported digest describes
        # them -- the success is honest.
        assert not os.path.islink(victim)
        with open(victim, "rb") as handle:
            assert handle.read() == b"NEW"
        with open(outside, "rb") as handle:
            assert handle.read() == b"OUTSIDE"
        assert published[0].sha256 == hashlib.sha256(b"NEW").hexdigest()
        assert published[0].size == 3
        assert [
            name for name in os.listdir(out_dir)
            if name.startswith(".")
        ] == []


def test_publish_replace_failure_between_backup_and_replace():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        staged = _staged(parent, "a.bpf.o", b"NEW")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        victim = os.path.join(out_dir, "a.bpf.o")
        _write(victim, b"OLD")
        real_replace = os.replace
        calls = []

        def failing_replace(src, dst, *args, **kwargs):
            calls.append((src, dst))
            raise OSError("fixture replace failure")

        os.replace = failing_replace
        try:
            exc = _expect_error(
                lambda: publish([("a.bpf.o", staged)], out_dir),
                "MBPF106",
                "evidence.publish",
            )
        finally:
            os.replace = real_replace
        assert calls, "replace boundary never exercised"
        assert "a.bpf.o" in exc.diagnostic.explanation
        with open(victim, "rb") as handle:
            assert handle.read() == b"OLD"
        assert [
            name for name in os.listdir(out_dir)
            if name.startswith(".")
        ] == []


# --- Hardened publication: concurrent publishers. ---

# test_publish_holds_exclusive_lock is the deterministic gate: it
# observes the lock directly. test_publish_concurrent_no_mixed_*
# is the behavioral proof that serialized publishers leave whole
# generations behind.


def test_publish_holds_exclusive_lock():
    publish = evidence_module.publish_artifacts
    with _scratch() as parent:
        first = _staged(parent, "a.bpf.o", b"AAA")
        second = _staged(parent, "b.bpf.o", b"BBB")
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        entered = threading.Event()
        proceed = threading.Event()
        real_replace = os.replace
        calls = []

        def gated_replace(src, dst, *args, **kwargs):
            calls.append((src, dst))
            entered.set()
            assert proceed.wait(30), "lock gate never released"
            return real_replace(src, dst, *args, **kwargs)

        outcome = []
        os.replace = gated_replace
        try:

            def run():
                try:
                    outcome.append(
                        publish(
                            [
                                ("a.bpf.o", first),
                                ("b.bpf.o", second),
                            ],
                            out_dir,
                        )
                    )
                except BaseException as exc:  # noqa: BLE001
                    outcome.append(exc)

            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            try:
                assert entered.wait(30), "publish never started"
                probe = os.open(out_dir, os.O_RDONLY)
                try:
                    try:
                        fcntl.flock(
                            probe, fcntl.LOCK_EX | fcntl.LOCK_NB
                        )
                    except BlockingIOError:
                        pass
                    else:
                        raise AssertionError(
                            "publication holds no exclusive lock"
                        )
                finally:
                    os.close(probe)
            finally:
                proceed.set()
                worker.join(30)
                assert not worker.is_alive(), "publish hung"
        finally:
            os.replace = real_replace
        assert calls, "rename boundary never exercised"
        assert len(outcome) == 1
        assert not isinstance(outcome[0], BaseException), outcome[0]
        assert [item.name for item in outcome[0]] == [
            "a.bpf.o", "b.bpf.o",
        ]
        with open(os.path.join(out_dir, "a.bpf.o"), "rb") as handle:
            assert handle.read() == b"AAA"


def test_publish_concurrent_no_mixed_generation():
    publish = evidence_module.publish_artifacts
    real_replace = os.replace

    def slow_replace(src, dst, *args, **kwargs):
        # Widen the interleave window so an unlocked
        # implementation usually mixes generations.
        time.sleep(0.005)
        return real_replace(src, dst, *args, **kwargs)

    os.replace = slow_replace
    try:
        for round_no in range(5):
            with _scratch() as parent:
                staged_a = {
                    name: _staged(
                        parent, "%d-a-%s" % (round_no, name),
                        ("A-%d-%s" % (round_no, name)).encode(),
                    )
                    for name in ("f1.bpf.o", "f2.bpf.o", "f3.bpf.o")
                }
                staged_b = {
                    name: _staged(
                        parent, "%d-b-%s" % (round_no, name),
                        ("B-%d-%s" % (round_no, name)).encode(),
                    )
                    for name in ("f1.bpf.o", "f2.bpf.o", "f3.bpf.o")
                }
                out_dir = os.path.join(parent, "out")
                os.makedirs(out_dir)
                barrier = threading.Barrier(2)
                outcomes = {}

                def run(tag, staged):
                    try:
                        barrier.wait(30)
                        outcomes[tag] = publish(
                            sorted(
                                (name, path)
                                for name, path in staged.items()
                            ),
                            out_dir,
                        )
                    except BaseException as exc:  # noqa: BLE001
                        outcomes[tag] = exc

                workers = [
                    threading.Thread(
                        target=run, args=("a", staged_a),
                        daemon=True,
                    ),
                    threading.Thread(
                        target=run, args=("b", staged_b),
                        daemon=True,
                    ),
                ]
                for worker in workers:
                    worker.start()
                for worker in workers:
                    worker.join(60)
                    assert not worker.is_alive(), (
                        "round %d hung" % round_no
                    )
                for tag in ("a", "b"):
                    assert not isinstance(
                        outcomes[tag], BaseException
                    ), (round_no, tag, outcomes[tag])
                final = {}
                for name in ("f1.bpf.o", "f2.bpf.o", "f3.bpf.o"):
                    with open(os.path.join(out_dir, name), "rb") as h:
                        final[name] = h.read()
                gen_a = {
                    name: ("A-%d-%s" % (round_no, name)).encode()
                    for name in final
                }
                gen_b = {
                    name: ("B-%d-%s" % (round_no, name)).encode()
                    for name in final
                }
                assert final == gen_a or final == gen_b, (
                    "round %d mixed generations: %r" % (
                        round_no, final,
                    )
                )
                assert [
                    name for name in os.listdir(out_dir)
                    if name.startswith(".")
                ] == [], round_no
    finally:
        os.replace = real_replace


# --- Sidecar qualification: object/input/run-plan binding. ---

# qualify_artifacts is the verification entry point F-036 calls
# for: it compares sidecar hashes to live bytes and binds the
# result to the input set and the caller's run-plan digest. Every
# negative below must fail closed with MBPF710 at evidence.verify.
# The loader never reads sidecars (see the standalone-ELF proof in
# tests/elf/test_mutations.py); qualification is the layer that
# refuses detached or inconsistent provenance.


def _captured_sidecar(parent):
    """Capture a real sidecar over synthetic object bytes."""
    project = _project(parent)
    out_dir = os.path.join(parent, "out")
    os.makedirs(out_dir)
    result = _synthetic_result(project, out_dir)
    manifest = _synthetic_manifest(project)
    sealed = _seal_for(project, manifest)
    evidence = evidence_module.evidence_from_build(
        **_capture_args(
            project, out_dir, result, manifest, sealed=sealed
        )
    )
    raw = evidence_module.dumps_evidence(evidence)
    return raw, json.loads(raw.decode("ascii"))


def _redump(doc):
    return (
        json.dumps(
            doc,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")


def _expect_verify_error(func):
    return _expect_error(func, "MBPF710", "evidence.verify")


def test_qualify_accepts_bound_sidecar():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        raw, doc = _captured_sidecar(parent)
        report = qualify(
            {"demo": raw}, {"demo.bpf.o": b"object-bytes"}
        )
        assert report.schema_version == (
            evidence_module.QUALIFICATION_SCHEMA_VERSION
        )
        assert report.run_plan_digest is None
        assert len(report.artifacts) == 1
        bound = report.artifacts[0]
        assert bound.artifact == "demo"
        assert bound.object_name == "demo.bpf.o"
        assert bound.object_sha256 == hashlib.sha256(
            b"object-bytes"
        ).hexdigest()
        assert bound.object_size == len(b"object-bytes")
        assert bound.sidecar_sha256 == hashlib.sha256(raw).hexdigest()
        # Independently rebuilt from the document: the recorded
        # digest must equal the cache key over the same inputs.
        assert bound.inputs_digest == evidence_module.cache_key(
            _inputs_from_doc(doc)
        )
        dumped = evidence_module.dumps_qualification(report)
        assert dumped.endswith(b"\n")
        assert evidence_module.dumps_qualification(report) == dumped
        assert json.loads(dumped.decode("ascii")) == (
            report.to_dict()
        )


def test_qualify_rejects_tampered_object():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        raw, _doc = _captured_sidecar(parent)
        exc = _expect_verify_error(
            lambda: qualify(
                {"demo": raw}, {"demo.bpf.o": b"object-byteX"}
            )
        )
        assert "demo.bpf.o" in exc.diagnostic.explanation
        assert "do not match" in exc.diagnostic.explanation


def test_qualify_rejects_tampered_sidecar_hash():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        _raw, doc = _captured_sidecar(parent)
        recorded = doc["outputs"][0]["sha256"]
        flipped = ("b" if recorded[-1] == "a" else "a")
        doc["outputs"][0]["sha256"] = recorded[:-1] + flipped
        exc = _expect_verify_error(
            lambda: qualify(
                {"demo": _redump(doc)},
                {"demo.bpf.o": b"object-bytes"},
            )
        )
        assert "do not match" in exc.diagnostic.explanation


def test_qualify_rejects_unknown_field():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        _raw, doc = _captured_sidecar(parent)
        doc["extra"] = 1
        exc = _expect_verify_error(
            lambda: qualify(
                {"demo": _redump(doc)},
                {"demo.bpf.o": b"object-bytes"},
            )
        )
        assert "unknown" in exc.diagnostic.explanation


def test_qualify_rejects_schema_version():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        _raw, doc = _captured_sidecar(parent)
        for bad in (3, "4", True, None):
            mutated = dict(doc)
            mutated["schema_version"] = bad
            exc = _expect_verify_error(
                lambda m=mutated: qualify(
                    {"demo": _redump(m)},
                    {"demo.bpf.o": b"object-bytes"},
                )
            )
            assert "schema_version" in exc.diagnostic.explanation, bad


def test_qualify_rejects_failed_build_sidecar():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        _raw, doc = _captured_sidecar(parent)
        doc["success"] = False
        exc = _expect_verify_error(
            lambda: qualify(
                {"demo": _redump(doc)},
                {"demo.bpf.o": b"object-bytes"},
            )
        )
        assert "success" in exc.diagnostic.explanation


def test_qualify_run_plan_binding():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        raw, _doc = _captured_sidecar(parent)
        first = "ab" * 32
        second = "cd" * 32
        bound = qualify(
            {"demo": raw},
            {"demo.bpf.o": b"object-bytes"},
            run_plan_digest=first,
        )
        assert bound.run_plan_digest == first
        assert first in evidence_module.dumps_qualification(
            bound
        ).decode("ascii")
        rebound = qualify(
            {"demo": raw},
            {"demo.bpf.o": b"object-bytes"},
            run_plan_digest=second,
        )
        assert rebound.run_plan_digest == second
        assert evidence_module.dumps_qualification(
            rebound
        ) != evidence_module.dumps_qualification(bound)
        for bad in ("zz", "z" * 64, "AB" * 32, 123, b"ab" * 32):
            exc = _expect_verify_error(
                lambda b=bad: qualify(
                    {"demo": raw},
                    {"demo.bpf.o": b"object-bytes"},
                    run_plan_digest=b,
                )
            )
            assert "run_plan_digest" in exc.diagnostic.explanation


def test_qualify_rejects_unbound_and_missing():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        raw, _doc = _captured_sidecar(parent)
        exc = _expect_verify_error(
            lambda: qualify({"demo": raw}, {})
        )
        assert "no live bytes" in exc.diagnostic.explanation
        exc = _expect_verify_error(
            lambda: qualify(
                {"demo": raw},
                {
                    "demo.bpf.o": b"object-bytes",
                    "stray.bpf.o": b"stray",
                },
            )
        )
        assert "not bound" in exc.diagnostic.explanation


def test_qualify_rejects_sidecar_entry_in_outputs():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        raw, doc = _captured_sidecar(parent)
        # A sidecar hash can never name its own final bytes, so
        # outputs[] must hold bound objects only: anything else
        # (including a self-named entry) fails closed.
        doc["outputs"].append(
            {
                "path": "demo.evidence.json",
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            }
        )
        exc = _expect_verify_error(
            lambda: qualify(
                {"demo": _redump(doc)},
                {
                    "demo.bpf.o": b"object-bytes",
                    "demo.evidence.json": raw,
                },
            )
        )
        assert "not a bound object" in exc.diagnostic.explanation


def test_qualify_rejects_malformed_and_dup_keys():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        _raw, doc = _captured_sidecar(parent)
        exc = _expect_verify_error(
            lambda: qualify(
                {"demo": b"not json"},
                {"demo.bpf.o": b"object-bytes"},
            )
        )
        assert "not valid JSON" in exc.diagnostic.explanation
        assert len(doc["outputs"]) == 1
        dup = (
            '{"schema_version":4,"schema_version":4,'
            '"artifact":"demo","profile_id":"p","success":true,'
            '"inputs":{},"outputs":[],"transforms":[],'
            '"source_license":"s","kernel_license":"k",'
            '"license_mapping_version":1,"tool_version":"t",'
            '"sdk_version":"1.1","commands":[],"environment":[]}'
        ).encode("ascii")
        exc = _expect_verify_error(
            lambda: qualify(
                {"demo": dup}, {"demo.bpf.o": b"object-bytes"}
            )
        )
        assert "duplicate" in exc.diagnostic.explanation


def test_qualify_rejects_bad_envelopes():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        raw, _doc = _captured_sidecar(parent)
        live = {"demo.bpf.o": b"object-bytes"}
        exc = _expect_verify_error(lambda: qualify({}, live))
        assert "no sidecars" in exc.diagnostic.explanation
        exc = _expect_verify_error(
            lambda: qualify("demo", live)
        )
        assert "must be a mapping" in exc.diagnostic.explanation
        exc = _expect_verify_error(
            lambda: qualify({"demo": raw.decode("ascii")}, live)
        )
        assert "must be bytes" in exc.diagnostic.explanation
        exc = _expect_verify_error(
            lambda: qualify(
                {"demo": raw}, {"demo.bpf.o": "object-bytes"}
            )
        )
        assert "must be bytes" in exc.diagnostic.explanation
        exc = _expect_verify_error(
            lambda: qualify({"WRONG": raw}, live)
        )
        assert "disagrees" in exc.diagnostic.explanation


def test_qualify_inputs_digest_binds_without_comparing():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        raw, doc = _captured_sidecar(parent)
        before = qualify(
            {"demo": raw}, {"demo.bpf.o": b"object-bytes"}
        )
        recorded = doc["inputs"]["source"][0]["sha256"]
        flipped = ("b" if recorded[-1] == "a" else "a")
        doc["inputs"]["source"][0]["sha256"] = recorded[:-1] + flipped
        after = qualify(
            {"demo": _redump(doc)},
            {"demo.bpf.o": b"object-bytes"},
        )
        # The input set is shape-valid, so the sidecar still
        # qualifies -- but under a different recorded digest. The
        # binding detects drift across runs; it authenticates
        # nothing against coordinated rewriting (see the trust
        # limit in docs/artifact-format.md).
        assert after.artifacts[0].inputs_digest != (
            before.artifacts[0].inputs_digest
        )
        assert after.artifacts[0].inputs_digest == (
            evidence_module.cache_key(_inputs_from_doc(doc))
        )


def test_qualify_multi_entry_layout():
    qualify = evidence_module.qualify_artifacts
    layout = evidence_module.layout_names
    with _scratch() as parent:
        _raw, doc = _captured_sidecar(parent)
        names = layout("demo", ("xdp_entry", "trace_entry"))
        assert names == (
            "demo.xdp_entry.bpf.o", "demo.trace_entry.bpf.o",
        )
        live = {}
        outputs = []
        for name in names:
            payload = b"object:" + name.encode("ascii")
            live[name] = payload
            outputs.append(
                {
                    "path": name,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            )
        doc["outputs"] = outputs
        report = qualify({"demo": _redump(doc)}, live)
        # Records sort by (artifact, object_name), independent of
        # the sidecar's outputs order.
        assert [item.object_name for item in report.artifacts] == [
            "demo.trace_entry.bpf.o",
            "demo.xdp_entry.bpf.o",
        ]


def test_qualify_multi_sidecar_report():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        _raw, doc = _captured_sidecar(parent)
        plan = "ef" * 32
        first = _redump(doc)
        other = json.loads(json.dumps(doc))
        other["artifact"] = "demo2"
        other["outputs"] = [
            {
                "path": "demo2.bpf.o",
                "sha256": hashlib.sha256(b"second").hexdigest(),
                "size": len(b"second"),
            }
        ]
        second = _redump(other)
        report = qualify(
            {"demo": first, "demo2": second},
            {"demo.bpf.o": b"object-bytes", "demo2.bpf.o": b"second"},
            run_plan_digest=plan,
        )
        assert report.run_plan_digest == plan
        assert [
            (item.artifact, item.object_name)
            for item in report.artifacts
        ] == [("demo", "demo.bpf.o"), ("demo2", "demo2.bpf.o")]


def test_qualify_rejects_cross_claims():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        _raw, doc = _captured_sidecar(parent)
        # "demo.xdp_entry.bpf.o" is name-valid under both "demo"
        # (multi-entry form) and "demo.xdp_entry" (single form):
        # the same live object claimed twice must fail closed.
        payload = b"object-bytes"
        first = json.loads(json.dumps(doc))
        first["outputs"] = [
            {
                "path": "demo.xdp_entry.bpf.o",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        ]
        other = json.loads(json.dumps(doc))
        other["artifact"] = "demo.xdp_entry"
        other["outputs"] = list(first["outputs"])
        exc = _expect_verify_error(
            lambda: qualify(
                {
                    "demo": _redump(first),
                    "demo.xdp_entry": _redump(other),
                },
                {"demo.xdp_entry.bpf.o": payload},
            )
        )
        assert "claimed by two sidecars" in exc.diagnostic.explanation


def test_qualify_rejects_bad_object_names():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        _raw, doc = _captured_sidecar(parent)
        live = {"demo.bpf.o": b"object-bytes"}
        for bad in ("other.bpf.o", "../evil", "demo..bpf.o", "demo.o"):
            mutated = json.loads(json.dumps(doc))
            mutated["outputs"][0]["path"] = bad
            exc = _expect_verify_error(
                lambda m=mutated: qualify(
                    {"demo": _redump(m)}, live
                )
            )
            assert "bound object" in exc.diagnostic.explanation, bad


def test_qualify_rejects_contradictory_provenance():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        raw, doc = _captured_sidecar(parent)
        live = {"demo.bpf.o": b"object-bytes"}
        before = qualify({"demo": raw}, live)
        # Top-level values must agree with the recorded inputs;
        # a one-sided change is contradictory either way.
        cases = [
            ("profile_id", "other-profile", "profile_id"),
            ("tool_version", "9.9.9", "tool_version"),
            ("sdk_version", "9.9", "sdk_version"),
        ]
        for top_key, bad, inputs_key in cases:
            mutated = json.loads(json.dumps(doc))
            mutated[top_key] = bad
            exc = _expect_verify_error(
                lambda m=mutated: qualify(
                    {"demo": _redump(m)}, live
                )
            )
            assert "contradictory" in exc.diagnostic.explanation
            drifted = json.loads(json.dumps(doc))
            drifted["inputs"][inputs_key] = bad
            exc = _expect_verify_error(
                lambda m=drifted: qualify(
                    {"demo": _redump(m)}, live
                )
            )
            assert "contradictory" in exc.diagnostic.explanation
        # A coordinated change still qualifies -- under a new
        # recorded digest, since the input set moved.
        moved = json.loads(json.dumps(doc))
        moved["profile_id"] = "other-profile"
        moved["inputs"]["profile_id"] = "other-profile"
        after = qualify({"demo": _redump(moved)}, live)
        assert after.artifacts[0].inputs_digest != (
            before.artifacts[0].inputs_digest
        )


def test_qualify_expected_inputs_compared():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        raw, doc = _captured_sidecar(parent)
        live = {"demo.bpf.o": b"object-bytes"}
        expected = _inputs_from_doc(doc)
        report = qualify(
            {"demo": raw}, live, expected_inputs=expected
        )
        assert report.artifacts[0].inputs_digest == (
            evidence_module.cache_key(expected)
        )
        # A changed source hash no longer qualifies against the
        # same expectation.
        mutated = json.loads(json.dumps(doc))
        recorded = mutated["inputs"]["source"][0]["sha256"]
        flipped = ("b" if recorded[-1] == "a" else "a")
        mutated["inputs"]["source"][0]["sha256"] = (
            recorded[:-1] + flipped
        )
        exc = _expect_verify_error(
            lambda: qualify(
                {"demo": _redump(mutated)},
                live,
                expected_inputs=expected,
            )
        )
        assert "expected" in exc.diagnostic.explanation
        # Malformed expectations fail closed.
        for bad in ("v6:digest", 123, {"profile_id": "demo"}):
            exc = _expect_verify_error(
                lambda b=bad: qualify(
                    {"demo": raw}, live, expected_inputs=b
                )
            )
            assert "expected_inputs" in exc.diagnostic.explanation


def test_qualify_expected_run_plan_compared():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        raw, _doc = _captured_sidecar(parent)
        live = {"demo.bpf.o": b"object-bytes"}
        plan = b"run-plan-content"
        digest = hashlib.sha256(plan).hexdigest()
        report = qualify(
            {"demo": raw},
            live,
            run_plan_digest=digest,
            expected_run_plan=plan,
        )
        assert report.run_plan_digest == digest
        # Without a supplied digest the plan content binds the
        # report itself.
        derived = qualify(
            {"demo": raw}, live, expected_run_plan=plan
        )
        assert derived.run_plan_digest == digest
        # Plan content that does not match the supplied digest
        # is rejected, as are malformed plans.
        exc = _expect_verify_error(
            lambda: qualify(
                {"demo": raw},
                live,
                run_plan_digest="ab" * 32,
                expected_run_plan=plan,
            )
        )
        assert "run_plan_digest" in exc.diagnostic.explanation
        for bad in ("run-plan-content", 123):
            exc = _expect_verify_error(
                lambda b=bad: qualify(
                    {"demo": raw}, live, expected_run_plan=b
                )
            )
            assert "expected_run_plan" in exc.diagnostic.explanation


def test_qualify_rejects_unhashable_command_status():
    qualify = evidence_module.qualify_artifacts
    with _scratch() as parent:
        _raw, doc = _captured_sidecar(parent)
        live = {"demo.bpf.o": b"object-bytes"}
        # Unhashable status values must fail closed with
        # MBPF710, never escape as a raw TypeError.
        for bad in ([], {}, ["ok"], 0, None):
            mutated = json.loads(json.dumps(doc))
            mutated["commands"].append(
                {
                    "stage": "build.frontend",
                    "argv": ["mojo"],
                    "status": bad,
                    "exit_code": 0,
                }
            )
            exc = _expect_verify_error(
                lambda m=mutated: qualify(
                    {"demo": _redump(m)}, live
                )
            )
            assert "status" in exc.diagnostic.explanation, bad


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
