# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-ISA/cpu/v3-target: CPU admission + oracle reference vectors (ISA-01).

Oracle: pinned llc 22.1.8 (llvm_tool pins the binary by digest).
Admission: mojobpf-lower check-target with explicit cpu/features spec
keys; refusal is MBPF202/adapter.request naming the cpu contract.
"""
import json
import struct

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
        result = llc(["-march=bpfel", f"-mcpu={cpu}", "-filetype=obj",
                      CORPUS, "-o", tmp_path / f"{cpu}.o"])
        assert result.returncode == 0, result.stderr


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


@pytest.mark.parametrize("cpu", ["v1", "v2", "v4", "generic", "probe",
                               "v5", ""])
def test_cpu_other_than_v3_refused(tmp_path, cpu):
    result, _ = check_cpu(tmp_path, MINIMAL_IR, cpu)
    assert result.returncode == 2
    assert "MBPF202" in result.stderr and "cpu" in result.stderr


@pytest.mark.parametrize("features", ["+foo", "+alu32,+v4", "alu32"])
def test_cpu_bogus_features_refused(tmp_path, features):
    result, _ = check_cpu(tmp_path, MINIMAL_IR, "v3", features)
    assert result.returncode == 2
    assert "MBPF202" in result.stderr and "cpu" in result.stderr


@pytest.mark.parametrize("key", ["cpu", "features"])
def test_cpu_missing_key_refused(tmp_path, key):
    request = spec()
    del request[key]
    request_path = tmp_path / "spec.json"
    request_path.write_text(json.dumps(request))
    source = tmp_path / "input.ll"
    source.write_text(MINIMAL_IR)
    report_path = tmp_path / "cpu.report.json"
    result = run([lower_tool(), "--mode", "check-target",
                  "--input", source, "--spec", request_path,
                  "--report", report_path])
    assert result.returncode == 2


def test_cpu_bpfeb_triple_refused(tmp_path):
    text = module().replace("x86_64-unknown-linux-gnu", "bpfeb")
    result, _ = check_cpu(tmp_path, text, "v3")
    assert result.returncode == 4
    assert "MBPF319" in result.stderr


def test_cpu_mojo_fixture_admitted(tmp_path):
    captured = capture(tmp_path, FIX / "v3_minimal.mojo", "llvm")
    result, report = check_cpu(tmp_path, captured.read_text(), "v3")
    assert result.returncode == 0, result.stdout + result.stderr
    assert report["ok"] is True
    assert report["target_facts"]["isa_cpu"]["resolved_cpu"] == "v3"


def _xdp_text(object_path):
    data = object_path.read_bytes()
    assert data[:4] == b"\x7fELF" and len(data) >= 64
    (e_shoff,) = struct.unpack_from("<Q", data, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    assert e_shentsize == 64 and 0 < e_shnum <= 256
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + index * 64)
            for index in range(e_shnum)]
    base = rows[e_shstrndx][4]
    for row in rows:
        end = data.index(b"\x00", base + row[0])
        if data[base + row[0]:end] == b"xdp":
            return data[row[4]:row[4] + row[5]]
    raise AssertionError("xdp section missing in %s" % object_path)


def _jmp32_words(text):
    assert len(text) % 8 == 0
    return [word for (word,) in struct.iter_unpack("<Q", text)
            if word & 0x07 == 0x06]


def _lower_fixture(tmp_path, name, features=""):
    """Emit the genuine fixture through the parsed lowering."""
    captured = capture(tmp_path, FIX / "v3_minimal.mojo", "llvm")
    request = spec()
    request["features"] = features
    request_path = tmp_path / (name + ".spec.json")
    request_path.write_text(json.dumps(request))
    adapted = tmp_path / (name + ".bpf.ll")
    report_path = tmp_path / (name + ".report.json")
    proc = run([lower_tool(), "--mode", "lower",
                "--input", captured, "--spec", request_path,
                "--report", report_path, "--output", adapted,
                "--emit", "llvm"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    report = json.loads(report_path.read_text())
    assert report["ok"] is True
    return adapted, report


def test_fixture_v3_selects_jmp32_byte_exact(tmp_path):
    adapted, _ = _lower_fixture(tmp_path, "v3")
    first = tmp_path / "v1.o"
    third = tmp_path / "v3.o"
    assert llc(["-march=bpfel", "-mcpu=v1", "-filetype=obj",
                adapted, "-o", first]).returncode == 0
    assert llc(["-march=bpfel", "-mcpu=v3", "-filetype=obj",
                adapted, "-o", third]).returncode == 0
    v1_text, v3_text = _xdp_text(first), _xdp_text(third)
    assert v1_text != v3_text, "fixture must exercise the CPU selection"
    assert _jmp32_words(v1_text) == []
    # Byte-exact v3-only construct: if w1 s> 10 goto +1 (the gate).
    assert _jmp32_words(v3_text) == [0x0000000A00010166]


def test_fixture_alu32_form_byte_exact(tmp_path):
    adapted, report = _lower_fixture(tmp_path, "v3alu", "+alu32")
    flags = report["target_facts"]["isa_cpu"]["resolved_llc_flags"]
    assert flags == ["-mtriple=bpfel", "-mcpu=v3", "-mattr=+alu32"]
    flagged = tmp_path / "v3alu.o"
    assert llc([*flags, "-filetype=obj",
                adapted, "-o", flagged]).returncode == 0
    plain, _ = _lower_fixture(tmp_path, "v3plain")
    third = tmp_path / "v3.o"
    assert llc(["-march=bpfel", "-mcpu=v3", "-filetype=obj",
                plain, "-o", third]).returncode == 0
    assert _xdp_text(flagged) == _xdp_text(third)
    assert _jmp32_words(_xdp_text(flagged)) == [0x0000000A00010166]
