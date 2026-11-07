# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""F-ISA/cpu/refused-cpus: per-CPU refusal evidence (ISA-01).

Each refused CPU gets its own oracle characterization (what the
pinned llc emits for it, so the refusal is of something real and
distinct), its own named refusal diagnostic, and — for v4 — proof
its distinguishing forms never reach emitted objects. Characterization
pins below were recorded from the pinned oracle at RED time and
verified by decoding before pinning (see the leaf packet); the
mutant checks in the leaf receipt prove each pin bites.
"""
import hashlib
import json
import struct

import pytest

from test_isa_cpu import (
    BASE,
    CORPUS,
    FIX,
    capture,
    check_cpu,
    llc,
    lower_tool,
    run,
    spec,
)
from test_target_model import module

TEXT_SIZES = {"v1": 128, "v2": 120, "v3": 104, "v4": 104}

# Pinned oracle .text digests (llc 22.1.8 a05b677f; recorded at RED,
# verified by decoding: v1/v2 carry no JMP32 words, v3/v4 carry
# 0x0000000B000201C6 = if w2 s< 11 goto +1, v3==v4).
TEXT_DIGESTS = {
    "v1": "3d6eef3270a9eda441840e0728bc01419ce0a9b4ea4d91c45ffd85123a62c332",
    "v2": "b1e2c8cbd641304a03ac4d40381deeed78609fe26699f1d1e76b8d774ab97bf6",
    "v3": "bbc0b6fb9c02c56b6a390859d42d6f178cc0e04a9dabe2597bc1277762c7f13c",
    "v4": "bbc0b6fb9c02c56b6a390859d42d6f178cc0e04a9dabe2597bc1277762c7f13c",
}

CORPUS_V3_DIGEST = (
    "3b9c27cbf19c00d805efdca6cc3c068f196c306588c900f6ee27df0bfd74b024"
)

CORPUS_V4_DIGEST = (
    "4e6b561f4adf0af3e0eed56d1438e97e521fc4afd8bca96a74f84ef80329e247"
)

# Pinned v4-only construct (ldxsxh r0, [r1+0]; sign-extending 16-bit
# load — the MEMSX form the v3 audit does not model).
V4_MEMSX_WORDS = [0x0000000000001089]

PRE_V3_ATOMICS_STDERR = (
    "error: <unknown>:0:0: in function atomic_fetch_add i64 (ptr, i64): "
    "Invalid usage of the XADD return value\n\n"
)


def _section_words(object_path, section):
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
        if data[base + row[0]:end] == section.encode():
            text = data[row[4]:row[4] + row[5]]
            assert len(text) % 8 == 0
            return [word for (word,) in struct.iter_unpack("<Q", text)]
    raise AssertionError(
        "%s section missing in %s" % (section, object_path))


def _memsx_words(words):
    return [word for word in words
            if word & 0x07 == 0x01 and word & 0xE0 == 0x80]


def _jmp32_words(words):
    return [word for word in words if word & 0x07 == 0x06]


def _oracle_base_text(tmp_path, cpu):
    out = tmp_path / ("base-%s.o" % cpu)
    result = llc(["-march=bpfel", "-mcpu=%s" % cpu, "-filetype=obj",
                  BASE, "-o", out])
    assert result.returncode == 0, result.stderr
    words = _section_words(out, ".text")
    return words


@pytest.mark.parametrize("cpu", ["v1", "v2", "v3", "v4"])
def test_refused_cpu_oracle_base_vectors(tmp_path, cpu):
    words = _oracle_base_text(tmp_path, cpu)
    text = b"".join(struct.pack("<Q", word) for word in words)
    assert len(text) == TEXT_SIZES[cpu]
    if cpu in ("v1", "v2"):
        assert _jmp32_words(words) == []
    assert hashlib.sha256(text).hexdigest() == TEXT_DIGESTS[cpu]


def test_refused_cpu_oracle_base_pairwise(tmp_path):
    texts = {}
    for cpu in ("v1", "v2", "v3", "v4"):
        words = _oracle_base_text(tmp_path, cpu)
        texts[cpu] = b"".join(struct.pack("<Q", word) for word in words)
    assert texts["v1"] != texts["v2"] != texts["v3"]
    assert texts["v1"] != texts["v3"]
    assert texts["v3"] == texts["v4"]


def test_refused_cpu_oracle_corpus_v4_memsx(tmp_path):
    out = tmp_path / "corpus-v4.o"
    result = llc(["-march=bpfel", "-mcpu=v4", "-filetype=obj",
                  CORPUS, "-o", out])
    assert result.returncode == 0, result.stderr
    words = _section_words(out, ".text")
    assert len(words) == 18
    assert _memsx_words(words) == V4_MEMSX_WORDS
    text = b"".join(struct.pack("<Q", word) for word in words)
    assert hashlib.sha256(text).hexdigest() == CORPUS_V4_DIGEST


def test_refused_cpu_oracle_corpus_v3_no_memsx(tmp_path):
    out = tmp_path / "corpus-v3.o"
    result = llc(["-march=bpfel", "-mcpu=v3", "-filetype=obj",
                  CORPUS, "-o", out])
    assert result.returncode == 0, result.stderr
    words = _section_words(out, ".text")
    assert len(words) == 20
    assert _memsx_words(words) == []
    text = b"".join(struct.pack("<Q", word) for word in words)
    assert hashlib.sha256(text).hexdigest() == CORPUS_V3_DIGEST


@pytest.mark.parametrize("cpu", ["v1", "v2"])
def test_refused_cpu_oracle_corpus_pre_v3_fails(tmp_path, cpu):
    out = tmp_path / ("%s.o" % cpu)
    result = llc(["-march=bpfel", "-mcpu=%s" % cpu, "-filetype=obj",
                  CORPUS, "-o", out])
    assert result.returncode != 0
    assert result.stderr == PRE_V3_ATOMICS_STDERR


@pytest.mark.parametrize("cpu", ["v1", "v2", "v4"])
def test_refused_cpu_request_names_cpu(tmp_path, cpu):
    result, _ = check_cpu(tmp_path, module(), cpu)
    assert result.returncode == 2
    assert "MBPF202" in result.stderr
    assert 'got "%s"' % cpu in result.stderr


def _route_object_words(tmp_path, source, name):
    captured = capture(tmp_path, source, "llvm")
    request = spec()
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
    flags = report["target_facts"]["isa_cpu"]["resolved_llc_flags"]
    assert flags == ["-mtriple=bpfel", "-mcpu=v3"]
    out = tmp_path / (name + ".o")
    assert llc([*flags, "-filetype=obj",
                adapted, "-o", out]).returncode == 0
    return _section_words(out, "xdp")


# Complete xdp pins for the byte-identity lemma (recorded at RED from
# parsed-route emission, verified: base != mutant, JMP32 gate present,
# no MEMSX; placeholders until observed).
EMITTED_DIGESTS = {
    "base": "721d2d554950c5c67d0c567422ca6d729be3fe1f64005d79cb98ec5d18fb954a",
    "mut": "ce60a6ede2f51bc13451ef1eff6c0c0779d522bb1cfa3c59ed96dfcd3366a929",
}


def test_emitted_objects_carry_no_memsx(tmp_path):
    seen = {}
    for source, name in ((FIX / "v3_minimal.mojo", "base"),
                         (FIX / "v3_minimal_mutated.mojo", "mut")):
        words = _route_object_words(tmp_path, source, name)
        assert _memsx_words(words) == []
        assert _jmp32_words(words) == [0x0000000A00010166]
        text = b"".join(struct.pack("<Q", word) for word in words)
        seen[name] = hashlib.sha256(text).hexdigest()
        assert seen[name] == EMITTED_DIGESTS[name]
    assert seen["base"] != seen["mut"]
