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

from mojobpf import cli as cli_module  # noqa: E402
from mojobpf.build import (  # noqa: E402
    ADAPTER_REQUEST_VERSION,
    BuildRequest,
    build_project,
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
    out = argv[argv.index("-o") + 1]
    src = argv[-1]
    with open(out, "w", encoding="utf-8") as handle:
        handle.write("; fixture raw IR for %s\\n" % src)
    if mode == "stderr-error":
        sys.stderr.write("error: fixture latent error\\n")
    if mode == "buried-error":
        sys.stderr.write("error: buried marker\\n" + "x" * 100000 + "\\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
"""

LLC_FIXTURE = """\
#!{python}
import os
import sys
import time


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
    inp = argv[argv.index("-o") - 1]
    with open(inp, "rb") as handle:
        data = handle.read()
    with open(out, "wb") as handle:
        handle.write(b"FIXTURE-OBJ:" + data)
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
name = "counts"
map_type = "array"
key_type = "u32"
value_type = "u64"
max_entries = 1
"""


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
                                                  "xdp_main"),),
                with_maps=False):
    """Create a manifest project; return (manifest_path, out_dir)."""
    root = os.path.join(parent, dirname)
    os.makedirs(root)
    blocks = []
    for source, entry in programs:
        full = os.path.join(root, source)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as handle:
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


def build_fixture(manifest_path, out_dir, parent, adapter=None,
                  **kwargs):
    bindir = write_tool_bindir(parent)
    if adapter is None:
        adapter = os.path.join(parent, "adapter-ok.py")
        write_executable(adapter, ADAPTER_OK_FIXTURE)
    request = BuildRequest(
        manifest_path=manifest_path,
        out_dir=out_dir,
        adapter_path=adapter,
        search_paths=(bindir,),
        **kwargs
    )
    return build_project(request)

def test_successful_fixture_build_publishes_object():
    parent = tempfile.mkdtemp(prefix="build-ok-")
    manifest_path, out_dir = write_project(parent)
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is True
    assert result.schema_version == 1
    assert result.diagnostics == ()
    assert result.work_dir is None
    assert len(result.artifacts) == 1
    artifact = result.artifacts[0]
    assert artifact.role == "object"
    assert artifact.path == os.path.join(out_dir, "fixture_obj.bpf.o")
    with open(artifact.path, "rb") as handle:
        content = handle.read()
    assert content.startswith(b"FIXTURE-OBJ:; fixture raw IR for ")
    assert artifact.size == len(content)
    assert artifact.sha256 == hashlib.sha256(content).hexdigest()
    assert result.provenance is not None
    assert result.provenance.profile_id == "linux-bpfel-v3"
    assert result.provenance.mojo_version == "Mojo 9.9.9 (fixture)"
    assert result.provenance.llc_version == "llc fixture 0.0"
    assert len(result.provenance.source_files) == 1
    stages = [record.stage for record in result.commands]
    assert stages == [
        "build.setup",
        "build.setup",
        "build.frontend",
        "build.adapter",
        "build.backend",
    ]
    assert all(record.status == "ok" for record in result.commands)
    assert all(isinstance(record.argv, tuple) for record in result.commands)
    frontend = result.commands[2].argv
    assert frontend[1:4] == ("build", "--emit", "llvm")
    assert "-I" not in frontend
    backend = result.commands[4].argv
    assert backend[1:5] == (
        "-mtriple=bpfel", "-mcpu=v3", "-filetype=obj", backend[4],
    )
    assert backend[-2:] == ("-o", backend[-1])


def test_spaces_and_nonnascii_paths_build():
    parent = tempfile.mkdtemp(prefix="build-uni-")
    manifest_path, out_dir = write_project(
        parent, dirname="pr ojéct ünïcode",
        programs=(("s rc/mödüle file.mojo", "xdp_main"),),
    )
    assert os.path.isfile(manifest_path)
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is True, result.diagnostics
    assert len(result.artifacts) == 1
    assert os.path.isfile(result.artifacts[0].path)
    assert "pr ojéct ünïcode" in result.artifacts[0].path


def test_maps_manifest_passes_sdk_import_path():
    parent = tempfile.mkdtemp(prefix="build-maps-")
    manifest_path, out_dir = write_project(parent, with_maps=True)
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is True, result.diagnostics
    frontend = result.commands[2].argv
    flag = frontend.index("-I")
    sdk = frontend[flag + 1]
    assert os.path.isdir(sdk)
    assert sdk.replace(os.sep, "/").endswith("mojobpf/resources/sdk")


def test_multi_program_manifest_builds_each_object():
    parent = tempfile.mkdtemp(prefix="build-multi-")
    manifest_path, out_dir = write_project(
        parent,
        programs=(("src/a.mojo", "xdp_a"), ("src/b.mojo", "xdp_b")),
    )
    result = build_fixture(manifest_path, out_dir, parent)
    assert result.success is True, result.diagnostics
    assert [item.role for item in result.artifacts] == ["object", "object"]
    names = sorted(os.path.basename(item.path) for item in result.artifacts)
    assert names == ["fixture_obj.xdp_a.bpf.o", "fixture_obj.xdp_b.bpf.o"]


def test_missing_tools_fail_without_fallback():
    parent = tempfile.mkdtemp(prefix="build-notools-")
    manifest_path, out_dir = write_project(parent)
    empty = tempfile.mkdtemp(prefix="empty-path-")
    with isolated_path(empty):
        result = build_project(
            BuildRequest(
                manifest_path=manifest_path,
                out_dir=out_dir,
                adapter_path=SERVICE,
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
    empty = tempfile.mkdtemp(prefix="empty-path-")
    with isolated_path(empty):
        result = build_project(
            BuildRequest(
                manifest_path=manifest_path,
                out_dir=out_dir,
                adapter_path=adapter,
                search_paths=(bindir,),
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
    frontend = result.commands[2]
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
    assert result.commands[2].exit_code == 0
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
    assert "buried marker" not in result.commands[2].log_excerpt
    assert len(result.commands[2].log_excerpt) <= 4000
    assert result.artifacts == ()


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
        excerpt = result.commands[2].log_excerpt
        assert len(excerpt) <= 4000
        assert result.work_dir is not None
        log_path = os.path.join(result.work_dir, "xdp_main.frontend.log")
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
            os.path.join(result.work_dir, "xdp_main.raw.ll")
        )
        assert os.path.isfile(
            os.path.join(result.work_dir, "xdp_main.frontend.log")
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
            0, "without diagnostics",
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
            0, "invalid diagnostic entry",
        ),
        "crash-without-response": (None, 3, "no usable response"),
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
    assert diagnostic.code == "MBPF301"
    assert diagnostic.stage == "adapter.transform"
    assert "rejected" in diagnostic.explanation
    assert result.artifacts == ()
    assert not os.path.exists(out_dir) or os.listdir(out_dir) == []


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
    assert result.success is True
    assert sorted(os.listdir(out_dir)) == ["fixture_obj.bpf.o"]


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
    assert result.diagnostics[0].stage == "build.publish"
    assert result.artifacts == ()
    assert os.listdir(out_dir) == []


def test_relative_request_paths_resolve_against_cwd():
    parent = tempfile.mkdtemp(prefix="build-rel-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
    old_cwd = os.getcwd()
    os.chdir(parent)
    try:
        result = build_project(
            BuildRequest(
                manifest_path=os.path.relpath(manifest_path),
                out_dir=os.path.relpath(out_dir),
                adapter_path=os.path.relpath(adapter),
                search_paths=(os.path.relpath(bindir),),
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


def test_service_rejects_invalid_ir_with_bounded_message():
    parent = tempfile.mkdtemp(prefix="service-ir-")
    request = valid_service_request(parent, ir_text="; nothing here\n")
    code, response = run_service(request, parent)
    assert code == 1
    assert response["ok"] is False
    assert len(response["diagnostics"]) == 1
    diagnostic = response["diagnostics"][0]
    assert diagnostic["code"] == "MBPF301"
    assert diagnostic["stage"] == "adapter.transform"
    assert "rejected" in diagnostic["explanation"]
    assert len(diagnostic["explanation"]) <= 2100


def test_service_transform_matches_sibling_exactly():
    sibling = load_module("mojo_ir_adapter_check", SIBLING)
    ir_text = (
        'source_filename = "fixture"\n'
        + sibling.HOST_DATALAYOUT + "\n"
        + sibling.HOST_TRIPLE + "\n"
        + sibling.ENTRY_DEFINE + "\n"
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
    base = [
        "build", "--manifest", manifest_path, "--out-dir", out_dir,
        "--adapter", adapter,
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
        "--adapter", adapter,
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


def test_interrupted_build_removes_workdir():
    parent = tempfile.mkdtemp(prefix="build-interrupt-")
    manifest_path, out_dir = write_project(parent)
    bindir = write_tool_bindir(parent)
    adapter = os.path.join(parent, "adapter-ok.py")
    write_executable(adapter, ADAPTER_OK_FIXTURE)
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
            "    search_paths=(%r,), work_parent=%r))\n"
            "print('UNREACHABLE: %%s' %% result.success)\n"
            % (
                os.path.join(REPO_ROOT, "src"),
                manifest_path, out_dir, adapter, bindir, work_parent,
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

