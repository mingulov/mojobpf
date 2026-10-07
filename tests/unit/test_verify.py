# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the guest-backed load-and-unload wrapper.

Pins the failure classification (loader versus verifier versus
environment) against real captured loader messages, the minimal ELF
section reader against a synthetic object, the guest script's never
attach/run/link discipline, the request validation, and the kernel
lane lockfile schema. Nothing here boots a guest: the live proofs
live in ``tests/kernel/test_cleanup.py``.

Deterministic on any host: only the standard library plus pytest's
plain function collection.

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3
tests/unit/test_verify.py``).
"""

import ast
import json
import os
import struct
import sys

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

from mojobpf import verify as verify_module  # noqa: E402
from mojobpf.verify import (  # noqa: E402
    VerifyError,
    VerifyRequest,
    _FORBIDDEN_GUEST_TOKENS,
    classify_load_output,
    read_elf_sections,
)

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
HARNESS_PATH = os.path.join(
    REPO_ROOT, "tests", "harness", "bpf_test_run.py"
)
LOCK_PATH = os.path.join(REPO_ROOT, "ci", "kernels.lock.json")

# Real captured loader outputs (libbpf/bpftool wording, observed in
# disposable guests; only the temp paths are redacted).
LOADER_NOT_EBPF = (
    "libbpf: elf: /bin/true is not a valid eBPF object file\n"
    "Error: failed to open object file\n"
)
LOADER_TRUNCATED = (
    "libbpf: elf: failed to open verify-target.o: -EINVAL\n"
    "Error: failed to open object file\n"
)
ENVIRONMENT_EPERM = (
    "libbpf: Failed to bump RLIMIT_MEMLOCK (err = -EPERM), "
    "you might need to do it explicitly!\n"
    "libbpf: Error in bpf_object__probe_loading(): -EPERM. "
    "Couldn't load trivial BPF program. Make sure your kernel "
    "supports BPF (CONFIG_BPF_SYSCALL=y) and/or that RLIMIT_MEMLOCK "
    "is set to big enough value.\n"
    "Error: failed to load object file\n"
)
VERIFIER_OOB = (
    "libbpf: prog 'xdp_entry': BPF program load failed: -EACCES\n"
    "libbpf: prog 'xdp_entry': -- BEGIN PROG LOAD LOG --\n"
    "0: (b7) r1 = 0\n"
    "invalid access to map value, value_size=8 off=8 size=8\n"
    "processed 0 insns (limit 1000000) max_states_per_insn 0 "
    "total_states 0 peak_states 0 mark_read 0\n"
    "-- END PROG LOAD LOG --\n"
    "libbpf: prog 'xdp_entry': failed to load: -EACCES\n"
    "Error: failed to load object file\n"
)


def _pattern_tuple(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id == name
                    and isinstance(node.value, ast.Tuple)
                ):
                    return tuple(
                        element.value
                        for element in node.value.elts
                    )
    raise AssertionError("pattern %s not found" % name)


def test_classification_patterns_mirror_harness_rev2():
    """The wrapper classifies exactly like harness contract rev 2."""
    with open(HARNESS_PATH, encoding="utf-8") as handle:
        harness_tree = ast.parse(handle.read())
    with open(verify_module.__file__, encoding="utf-8") as handle:
        wrapper_tree = ast.parse(handle.read())
    for name in ("_PERMISSION_PATTERNS", "_VERIFIER_PATTERNS"):
        assert _pattern_tuple(wrapper_tree, name) == _pattern_tuple(
            harness_tree, name
        ), "%s drifted from the harness" % name


def test_classify_loader_cases():
    assert classify_load_output(LOADER_NOT_EBPF, "", False) == "loader"
    assert classify_load_output(LOADER_TRUNCATED, "", False) == "loader"
    assert classify_load_output("", "", False) == "loader"


def test_classify_environment_cases():
    assert classify_load_output(ENVIRONMENT_EPERM, "", False) == "environment"
    assert classify_load_output("", "", True) == "environment"
    assert (
        classify_load_output(
            "bpftool: Operation not permitted\n", "", False
        )
        == "environment"
    )


def test_classify_verifier_precedence():
    """Verifier evidence wins even when EACCES appears alongside."""
    assert "eacces" in VERIFIER_OOB.lower()
    assert classify_load_output(VERIFIER_OOB, "", False) == "verifier"
    assert classify_load_output("R0 invalid\n", "", False) == "verifier"


def _synthetic_elf():
    """Minimal 64-bit LE ELF with xdp/license/.BTF sections."""
    sections = [b"", b"xdp", b"license", b".BTF"]
    names = b"\x00"
    offsets = {}
    for name in sections[1:]:
        offsets[name] = len(names)
        names += name + b"\x00"
    license_bytes = b"Apache-2.0 WITH LLVM-exception\x00"
    bodies = {
        b"xdp": b"\x95\x00\x00\x00\x02\x00\x00\x00",
        b"license": license_bytes,
        b".BTF": b"BTF0",
    }
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF" + bytes([2, 1, 1]) + bytes(9),
        1,  # ET_REL
        247,  # EM_BPF
        1,
        0,  # entry
        0,  # phoff
        64,  # shoff
        0,  # flags
        64,  # ehsize
        0,  # phentsize
        0,  # phnum
        64,  # shentsize
        4,  # shnum
        0,  # shstrndx (section 0 holds the names here)
    )
    # Section-name table lives in section 0 for this synthetic image.
    section_names = [b"", b"xdp", b"license", b".BTF"]
    payloads = [names, bodies[b"xdp"], bodies[b"license"], bodies[b".BTF"]]
    blob = bytearray(header)
    shoff = 64
    blob += bytes(shoff - len(blob))
    offsets_out = []
    cursor = shoff + 4 * 64
    for payload in payloads:
        offsets_out.append(cursor)
        blob += bytes(cursor - len(blob)) + payload
        cursor += len(payload)
    table = bytearray()
    name_offsets = [0, offsets[b"xdp"], offsets[b"license"], offsets[b".BTF"]]
    for index in range(4):
        table += struct.pack(
            "<IIQQQQIIQQ",
            name_offsets[index],
            1 if index else 0,
            0,
            0,
            offsets_out[index],
            len(payloads[index]),
            0,
            0,
            1,
            0,
        )
    blob[shoff:shoff + len(table)] = table
    return bytes(blob), license_bytes


def test_read_elf_sections_synthetic(tmp_path=None):
    image, license_bytes = _synthetic_elf()
    # tmp_path is a pytest fixture; the direct runner passes None.
    if tmp_path is None:
        import tempfile

        path = os.path.join(tempfile.mkdtemp(prefix="verify-elf-"), "t.o")
    else:
        path = str(tmp_path / "t.o")
    with open(path, "wb") as handle:
        handle.write(image)
    names, license_out = read_elf_sections(path)
    assert names == ["", "xdp", "license", ".BTF"], names
    assert license_out == license_bytes


def test_read_elf_sections_rejects_non_elf(tmp_path=None):
    if tmp_path is None:
        import tempfile

        path = os.path.join(tempfile.mkdtemp(prefix="verify-elf-"), "t.txt")
    else:
        path = str(tmp_path / "t.txt")
    with open(path, "wb") as handle:
        handle.write(b"not an elf file\n")
    try:
        read_elf_sections(path)
    except ValueError:
        pass
    else:
        raise AssertionError("non-ELF input must raise ValueError")


def _rendered_script(**overrides):
    values = {
        "stage": "/tmp/stage",
        "object_name": "verify-target.o",
        "pin": "/sys/fs/bpf/mojobpf_verify",
        "prog_type": "xdp",
        "btf_path": "/sys/kernel/btf/vmlinux",
        "require_btf": "0",
        "as_user": "",
        "guest_preflight": 10,
        "guest_load_failed": 11,
    }
    values.update(overrides)
    return verify_module.GUEST_SCRIPT_TEMPLATE.format(**values)


def test_guest_script_never_attaches_runs_or_links():
    for require in ("0", "1"):
        script = _rendered_script(require_btf=require)
        for token in _FORBIDDEN_GUEST_TOKENS:
            assert token not in script, "forbidden %r in guest script" % token
    rooted = _rendered_script(as_user="nobody")
    assert "setpriv" in rooted
    for token in _FORBIDDEN_GUEST_TOKENS:
        assert token not in rooted, "forbidden %r (as-user)" % token


def test_snapshot_listings_avoid_volatile_fields():
    """Snapshots compare byte-for-byte, so no timestamps allowed."""
    template = verify_module.GUEST_SCRIPT_TEMPLATE
    assert "ls -la" not in template, "ls -la timestamps break comparison"
    assert "ls -l" not in template, "ls -l timestamps break comparison"


def test_guest_script_has_preflight_and_markers():
    script = _rendered_script()
    for marker in (
        "PREFLIGHT_UNAVAILABLE missing-btf",
        "PREFLIGHT_UNAVAILABLE unsupported-prog-type",
        "=== BEGIN load-log ===",
        "=== END load-log ===",
        "=== BEGIN snapshot-before ===",
        "=== BEGIN snapshot-after ===",
        "load_exit=",
        "unload_ok=",
        "guest-kernel: ",
        "guest-cmd: bpftool feature probe kernel",
        "guest-cmd: $LOAD_RUN prog load $OBJ $PIN",
        "guest-cmd: rm -f $PIN",
        "quiesced=$QUIESCED",
        "quiesce_waits=$QUIESCE_WAITS",
    ):
        assert marker in script, "missing marker %r" % marker


def test_request_validation():
    try:
        VerifyRequest(object_path="x.o", accelerator="hv")
    except VerifyError:
        pass
    else:
        raise AssertionError("bad accelerator must raise")
    try:
        VerifyRequest(object_path="x.o", pin_path="/tmp/pin")
    except VerifyError:
        pass
    else:
        raise AssertionError("pin outside bpffs must raise")
    try:
        VerifyRequest(object_path="x.o", prog_type='xdp"; evil')
    except VerifyError:
        pass
    else:
        raise AssertionError("unsafe prog type must raise")
    try:
        VerifyRequest(object_path="x.o", timeout=0)
    except VerifyError:
        pass
    else:
        raise AssertionError("non-positive timeout must raise")
    request = VerifyRequest(object_path="x.o")
    assert request.release == os.environ.get(
        verify_module.RELEASE_ENV_VAR, verify_module.DEFAULT_RELEASE
    )


def test_release_env_override(monkeypatch=None):
    if monkeypatch is not None:
        monkeypatch.setenv(verify_module.RELEASE_ENV_VAR, "v9.9")
        assert VerifyRequest(object_path="x.o").release == "v9.9"
    else:
        previous = os.environ.get(verify_module.RELEASE_ENV_VAR)
        os.environ[verify_module.RELEASE_ENV_VAR] = "v9.9"
        try:
            assert VerifyRequest(object_path="x.o").release == "v9.9"
        finally:
            if previous is None:
                del os.environ[verify_module.RELEASE_ENV_VAR]
            else:
                os.environ[verify_module.RELEASE_ENV_VAR] = previous
    assert (
        VerifyRequest(object_path="x.o", release="v6.6").release == "v6.6"
    )


def test_kernels_lock_schema():
    """The lane lockfile pins exactly two TCG lanes with hashes."""
    with open(LOCK_PATH, encoding="utf-8") as handle:
        lock = json.load(handle)
    assert lock["schema_version"] == 1, lock
    assert lock["license"] == "Apache-2.0 WITH LLVM-exception", lock
    runner = lock["runner"]
    assert runner["name"] == "vng", runner
    assert runner["version"], runner
    assert len(runner["sha256"]) == 64, runner
    lanes = lock["lanes"]
    assert len(lanes) == 2, lanes
    seen_releases = set()
    for lane in lanes:
        for key in (
            "id",
            "release",
            "accelerator",
            "kernel_release",
            "kernel_debs",
            "vng_argv_prefix",
        ):
            assert key in lane, (lane, key)
        assert lane["accelerator"] == "tcg", lane
        assert lane["vng_argv_prefix"] == [
            "vng",
            "--run",
            lane["release"],
            "--disable-kvm",
        ], lane
        assert lane["release"] not in seen_releases, lanes
        seen_releases.add(lane["release"])
        assert len(lane["kernel_debs"]) >= 1, lane
        for deb in lane["kernel_debs"]:
            assert deb["file"].endswith(".deb"), deb
            assert len(deb["sha256"]) == 64, deb


def test_cli_verify_wiring():
    """The verify subcommand exists and refuses a missing object."""
    from mojobpf import cli as cli_module

    parser = cli_module.build_parser()
    args = parser.parse_args(["verify", "--kernel", "--object", "nope.o"])
    assert args.func is cli_module._command_verify
    assert cli_module._command_verify(args) == cli_module.EXIT_USAGE
    assert cli_module.EXIT_VERIFY_LOADER == 5


def _direct_names():
    return sorted(
        name
        for name in globals()
        if name.startswith("test_") and callable(globals()[name])
    )


def _direct_run():
    failures = 0
    for name in _direct_names():
        try:
            globals()[name]()
        except Exception:
            failures += 1
            print("FAIL %s" % name)
            import traceback

            traceback.print_exc()
        else:
            print("ok %s" % name)
    print("%d tests, %d failures" % (len(_direct_names()), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_direct_run())
