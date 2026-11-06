# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""In-lane LLVM verification through the real adapter service.

The service runs the pinned-family ``opt -passes=verify`` over the
input IR after the audit and before exact-match editing, so malformed
IR is rejected in-lane with ``MBPF106`` at ``adapter.verify`` instead
of deferring to llc. These tests use the real toolchain resolution
(no MOJOBPF_OPT override) and the real service subprocess, so they
need llvm-config plus opt and live outside the guarded unit lane
(which forbids LLVM tools; the stub mapping lives in
tests/unit/test_build_commands.py).

Runnable directly (``python3 tests/compile/test_adapter_verify.py``)
or under any ``test_``-style runner. Standard library only.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
SERVICE = os.path.join(REPO_ROOT, "compiler", "adapter_service.py")
SIBLING = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")


class EnvironmentFailure(Exception):
    """The lane lacks a required tool; fail loudly, never skip."""


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_tools():
    config = os.environ.get("MOJOBPF_LLVM_CONFIG") or shutil.which(
        "llvm-config"
    )
    if config is None:
        raise EnvironmentFailure("llvm-config not found on PATH")
    if not os.path.isfile(SERVICE):
        raise EnvironmentFailure("missing service: %s" % SERVICE)


def fixture_ir(extra=""):
    sibling = load_module("mojo_ir_adapter_verify_real", SIBLING)
    text = (
        'source_filename = "fixture"\n'
        + sibling.HOST_DATALAYOUT + "\n"
        + sibling.HOST_TRIPLE + "\n"
        + sibling.ENTRY_DEFINE + "\n"
        # Proof-valid minimal classifier: a u32 context word,
        # extended and reinterpreted, never dereferenced.
        + "  %x = load i32, ptr %0, align 4\n"
        + "  %y = zext i32 %x to i64\n"
        + '  %r = call ptr asm "", "=r,0"(i64 %y)\n'
        + "  ret i32 2\n"
    )
    if extra:
        text += extra
    return text + "}\n" + sibling.HOST_ATTRS + "\n"


def serve(ir_text):
    check_tools()
    parent = tempfile.mkdtemp(prefix="adapter-verify-")
    input_ir = os.path.join(parent, "input.ll")
    with open(input_ir, "w", encoding="utf-8") as handle:
        handle.write(ir_text)
    manifest = os.path.join(parent, "mojobpf.toml")
    with open(manifest, "w", encoding="utf-8") as handle:
        # The parsed route authors its lowering spec from the
        # manifest contract, so the fixture declares the
        # license and the entry program explicitly.
        handle.write(
            "[artifact]\n"
            "kernel_license = \"Apache-2.0 WITH LLVM-exception\"\n"
            "[[programs]]\n"
            "entry = \"xdp_entry\"\n"
            "program_type = \"xdp\"\n"
            "section = \"xdp\"\n"
        )
    request = {
        "schema_version": 1,
        "input_ir": input_ir,
        "manifest_path": manifest,
        "profile_id": "linux-bpfel-v3",
        "output_dir": os.path.join(parent, "adapter-out"),
        "diagnostic_mode": "text",
    }
    req_path = os.path.join(parent, "req.json")
    resp_path = os.path.join(parent, "resp.json")
    with open(req_path, "w", encoding="utf-8") as handle:
        json.dump(request, handle)
    env = dict(os.environ)
    env.pop("MOJOBPF_OPT", None)
    proc = subprocess.run(
        [sys.executable, SERVICE, "--request", req_path,
         "--response", resp_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
        env=env,
    )
    response = None
    if os.path.isfile(resp_path):
        with open(resp_path, encoding="utf-8") as handle:
            response = json.load(handle)
    return proc.returncode, response, request


def test_verify_accepts_valid_ir_through_real_opt():
    code, response, _ = serve(fixture_ir())
    assert code == 0, response
    assert response["ok"] is True
    assert response["diagnostics"] == []
    print("PASS valid IR survives the real in-lane verifier")


def test_verify_rejects_malformed_ir_before_editing():
    malformed = fixture_ir(extra="  br label %nosuch\n")
    sibling = load_module("mojo_ir_adapter_verify_audit", SIBLING)
    assert sibling.validate(malformed) == "classifier"
    code, response, request = serve(malformed)
    assert code == 1, response
    assert response["ok"] is False
    assert len(response["diagnostics"]) == 1
    diagnostic = response["diagnostics"][0]
    assert diagnostic["code"] == "MBPF106", diagnostic
    assert diagnostic["stage"] == "adapter.verify", diagnostic
    assert "undefined value" in diagnostic["explanation"], diagnostic
    assert diagnostic["location"] == request["input_ir"], diagnostic
    assert response["outputs"] == {}
    print("PASS malformed IR rejected in-lane as MBPF106")


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
    print("adapter verify: in-lane backstop holds both directions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
