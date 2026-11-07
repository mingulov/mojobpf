# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-ISA/cpu/v3-target: CPU admission + oracle reference vectors (ISA-01).

Oracle: pinned llc 22.1.8 (llvm_tool pins the binary by digest).
Admission: mojobpf-lower check-target with explicit cpu/features spec
keys; refusal is MBPF202/adapter.request naming the cpu contract.
"""
import json

import pytest

from test_target_model import (
    ROOT,
    capture,
    checked,
    llvm_tool,
    lower_tool,
    module,
    run,
    spec,
)

FIX = ROOT / "tests/fixtures/isa/cpu"
CORPUS = FIX / "oracle-corpus.ll"
BASE = FIX / "oracle-base.ll"


def llc(args, **kwargs):
    return run([llvm_tool("llc"), *args], **kwargs)


def check_cpu(tmp_path, text, cpu, features=""):
    request = spec()
    request["cpu"] = cpu
    request["features"] = features
    request_path = tmp_path / "spec.json"
    request_path.write_text(json.dumps(request))
    source = tmp_path / "input.ll"
    source.write_text(text)
    report_path = tmp_path / "cpu.report.json"
    result = run([lower_tool(), "--mode", "check-target",
                  "--input", source, "--spec", request_path,
                  "--report", report_path])
    report = (json.loads(report_path.read_text())
              if report_path.exists() else None)
    return result, report


MINIMAL_IR = module()


# --- Oracle characterization (frozen reference behavior) ---

def test_oracle_generic_equals_v1(tmp_path):
    first = tmp_path / "generic.o"
    second = tmp_path / "v1.o"
    llc(["-march=bpfel", "-mcpu=generic", "-filetype=obj",
         BASE, "-o", first])
    llc(["-march=bpfel", "-mcpu=v1", "-filetype=obj",
         BASE, "-o", second])
    assert first.read_bytes() == second.read_bytes()
    generic = llc(["-march=bpfel", "-mcpu=generic", "-filetype=obj",
                   CORPUS, "-o", tmp_path / "g.o"])
    first_v1 = llc(["-march=bpfel", "-mcpu=v1", "-filetype=obj",
                    CORPUS, "-o", tmp_path / "1.o"])
    assert generic.returncode != 0
    assert generic.stderr == first_v1.stderr


def test_oracle_v3_selects_native32(tmp_path):
    third = tmp_path / "v3.s"
    second = tmp_path / "v2.s"
    llc(["-march=bpfel", "-mcpu=v3", "-filetype=asm",
         BASE, "-o", third])
    llc(["-march=bpfel", "-mcpu=v2", "-filetype=asm",
         BASE, "-o", second])
    assert "if w1 s< 11 goto" in third.read_text()
    assert "if w1 s< 11 goto" not in second.read_text()


def test_oracle_fetch_atomics_need_v3(tmp_path):
    for cpu in ("v1", "v2"):
        result = llc(["-march=bpfel", f"-mcpu={cpu}", "-filetype=obj",
                      CORPUS, "-o", tmp_path / f"{cpu}.o"])
        assert result.returncode != 0
        assert "Invalid usage of the XADD return value" in result.stderr
    for cpu in ("v3", "v4"):
        llc(["-march=bpfel", f"-mcpu={cpu}", "-filetype=obj",
             CORPUS, "-o", tmp_path / f"{cpu}.o"])


def test_oracle_memsx_is_v4_only(tmp_path):
    third = tmp_path / "v3.s"
    fourth = tmp_path / "v4.s"
    llc(["-march=bpfel", "-mcpu=v3", "-filetype=asm",
         CORPUS, "-o", third])
    llc(["-march=bpfel", "-mcpu=v4", "-filetype=asm",
         CORPUS, "-o", fourth])
    assert "*(s16 *)" not in third.read_text()
    assert "*(s16 *)" in fourth.read_text()


def test_oracle_alu32_changes_pre_v3(tmp_path):
    plain = tmp_path / "v2.s"
    flagged = tmp_path / "v2f.s"
    llc(["-march=bpfel", "-mcpu=v2", "-filetype=asm", BASE, "-o", plain])
    llc(["-march=bpfel", "-mcpu=v2", "-mattr=+alu32", "-filetype=asm",
         BASE, "-o", flagged])
    assert plain.read_bytes() != flagged.read_bytes()


# --- Admission (RED until IsaLowering lands) ---

def test_cpu_v3_admitted_reports_facts(tmp_path):
    result, report = check_cpu(tmp_path, MINIMAL_IR, "v3")
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["ok"] is True
    isa = report["target_facts"]["isa_cpu"]
    assert isa == {"requested_cpu": "v3", "requested_features": "",
                   "resolved_cpu": "v3",
                   "resolved_llc_flags": ["-mtriple=bpfel", "-mcpu=v3"],
                   "alu32": False}


def test_cpu_v3_alu32_admitted_reports_flag(tmp_path):
    result, report = check_cpu(tmp_path, MINIMAL_IR, "v3", "+alu32")
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["ok"] is True
    isa = report["target_facts"]["isa_cpu"]
    assert isa["resolved_cpu"] == "v3" and isa["alu32"] is True
    assert isa["resolved_llc_flags"] == ["-mtriple=bpfel", "-mcpu=v3",
                                         "-mattr=+alu32"]


@pytest.mark.parametrize("cpu", ["v1", "v2", "v4", "generic", "v5", ""])
def test_cpu_other_than_v3_refused(tmp_path, cpu):
    result, _ = check_cpu(tmp_path, MINIMAL_IR, cpu)
    assert result.returncode == 2
    assert "MBPF202" in result.stderr and "cpu" in result.stderr


@pytest.mark.parametrize("features", ["+foo", "+alu32,+v4", "alu32"])
def test_cpu_bogus_features_refused(tmp_path, features):
    result, _ = check_cpu(tmp_path, MINIMAL_IR, "v3", features)
    assert result.returncode == 2
    assert "MBPF202" in result.stderr and "cpu" in result.stderr


def test_cpu_missing_key_refused(tmp_path):
    request = spec()
    del request["cpu"]
    request_path = tmp_path / "spec.json"
    request_path.write_text(json.dumps(request))
    source = tmp_path / "input.ll"
    source.write_text(MINIMAL_IR)
    report_path = tmp_path / "cpu.report.json"
    result = run([lower_tool(), "--mode", "check-target",
                  "--input", source, "--spec", request_path,
                  "--report", report_path])
    assert result.returncode == 2


def test_cpu_mojo_fixture_admitted(tmp_path):
    captured = capture(tmp_path, FIX / "v3_minimal.mojo", "llvm")
    result, report = check_cpu(tmp_path, captured.read_text(), "v3")
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["ok"] is True
    assert report["target_facts"]["isa_cpu"]["resolved_cpu"] == "v3"
