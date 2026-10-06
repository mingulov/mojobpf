# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for artifact publication, provenance and licensing.

Covers the license layer (SPDX parsing, source-grant validation,
declaration-pair mapping, GPL requirements), stable evidence and
cache keys, and atomic publication (success, mid-publish rollback,
fail-after-success sequences). Deterministic on any host: builds run
through fixture tools resolved via ``search_paths``; only the audit
and adapter siblings run for real (both need just Python).

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3
tests/unit/test_artifact_publication.py``).
"""

import contextlib
import dataclasses
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import sys
import tempfile

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

from mojobpf import evidence as evidence_module  # noqa: E402
from mojobpf import inspect as inspect_module  # noqa: E402
from mojobpf.build import (  # noqa: E402
    BuildArtifact,
    BuildProvenance,
    BuildRequest,
    BuildResult,
    CommandRecord,
    build_project,
)
from mojobpf.diagnostics import Diagnostic  # noqa: E402
from mojobpf.manifest import lookup_profile, parse_manifest  # noqa: E402

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
import shutil
import sys


def main(argv):
    if argv[1:] == ["--version"]:
        print("llc 9.9.9 (fixture)")
        return 0
    out = argv[argv.index("-o") + 1]
    src = argv[argv.index("-o") - 1]
    shutil.copyfile(src, out)
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
    assert set(record.to_dict()) == {
        "source_license",
        "programs",
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
        lambda: check((1,), ("tracepoint",), (), "linux-bpfel-v3"),
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
    for block in (adapter.LICENSE_BLOCK, adapter.MAP_LICENSE_BLOCK):
        payload = _ir_payload(block)
        assert payload == expected, block[:60]
        head, _, _ = block.partition(" ")
        assert head.startswith("@_license"), head
    for block in (adapter.LICENSE_BLOCK, adapter.MAP_LICENSE_BLOCK):
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
    published = evidence_module.PublishedArtifact(
        schema_version=1,
        role="object",
        name="demo.bpf.o",
        sha256="a" * 64,
        size=12,
    )
    assert (
        sorted(published.to_dict()) == sorted(artifact_schema["required"])
    )
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
        )
    doc = evidence.to_dict()
    assert sorted(doc) == sorted(evidence_schema["required"])
    inputs_schema = evidence_schema["properties"]["inputs"]
    assert sorted(doc["inputs"]) == sorted(inputs_schema["required"])
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
        )
    assert evidence.success is False
    assert evidence.outputs == ()
    assert len(evidence.inputs.source) == 1
    assert evidence.inputs.manifest.path == "mojobpf.toml"
    raw = evidence_module.dumps_evidence(evidence)
    assert b'"success":false' in raw


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
    }
    fields.update(overrides)
    return evidence_module.CacheInputs(**fields)


def test_cache_key_stable_and_versioned():
    first = evidence_module.cache_key(_cache_inputs())
    second = evidence_module.cache_key(_cache_inputs())
    assert first == second
    assert first.startswith("v1:")
    assert len(first) == len("v1:") + 64
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


def test_environment_path_values_hashed():
    with _scratch() as parent:
        project = _project(parent)
        out_dir = os.path.join(parent, "out")
        os.makedirs(out_dir)
        result = _synthetic_result(project, out_dir)
        manifest = _synthetic_manifest(project)

        def capture(extra):
            return evidence_module.evidence_from_build(
                result,
                manifest,
                project_dir=project,
                out_dir=out_dir,
                transforms=("frontend",),
                environment=extra,
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
        )
        first = build_project(request)
        assert first.success is True, first.diagnostics
        assert [item.path for item in first.artifacts] == [
            os.path.join(out_dir, "demo.bpf.o")
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
        project = _project(parent, programs=2)
        out_dir = os.path.join(parent, "out")
        result = build_project(
            BuildRequest(
                manifest_path=os.path.join(project, "mojobpf.toml"),
                out_dir=out_dir,
                adapter_path=adapter,
                search_paths=(bindir,),
                timeout_s=60,
            )
        )
        assert result.success is True, result.diagnostics
        assert sorted(os.listdir(out_dir)) == sorted(
            evidence_module.layout_names(
                "demo", ("xdp_entry", "xdp_1")
            )
        )


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
