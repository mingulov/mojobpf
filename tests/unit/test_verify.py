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
import shutil
import struct
import subprocess
import sys
import tempfile

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
    run_verification,
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
        "map_types": "",
        "trace_event": "",
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
        "PREFLIGHT_UNAVAILABLE unsupported-map-type",
        "PREFLIGHT_UNAVAILABLE unsupported-trace-event",
        "=== BEGIN load-log ===",
        "=== END load-log ===",
        "=== BEGIN snapshot-before ===",
        "=== BEGIN snapshot-after ===",
        "load_exit=",
        "unload_ok=",
        "guest-kernel: ",
        "guest-cmd: bpftool feature probe kernel",
        "guest-cmd: probe map types and trace event",
        "guest-cmd: $LOAD_RUN prog load $OBJ $PIN",
        "guest-cmd: rm -f $PIN",
        "quiesced=$QUIESCED",
        "quiesce_waits=$QUIESCE_WAITS",
        "map_probe_line[",
        "map_type_supported[",
        "map_preflight_ok=",
        "trace_event_supported=",
        "trace_event_id=",
    ):
        assert marker in script, "missing marker %r" % marker


def test_guest_script_renders_map_and_trace_requests():
    script = _rendered_script(
        map_types="array ringbuf",
        trace_event="syscalls:sys_enter_getpid",
    )
    assert 'MAP_TYPES="array ringbuf"' in script, script
    assert 'TRACE_EVENT="syscalls:sys_enter_getpid"' in script, script
    for token in _FORBIDDEN_GUEST_TOKENS:
        assert token not in script, "forbidden %r in guest script" % token


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
    try:
        VerifyRequest(object_path="x.o", map_types="array")
    except VerifyError:
        pass
    else:
        raise AssertionError("string map_types must raise")
    try:
        VerifyRequest(object_path="x.o", map_types=("array", "ringbuf; evil"))
    except VerifyError:
        pass
    else:
        raise AssertionError("unsafe map type must raise")
    try:
        VerifyRequest(object_path="x.o", map_types=("array", 7))
    except VerifyError:
        pass
    else:
        raise AssertionError("non-string map type must raise")
    for bad_event in (
        "syscalls; evil",
        "syscalls",
        "syscalls:",
        ":sys_enter_getpid",
        "a:b:c",
        "",
    ):
        try:
            VerifyRequest(object_path="x.o", trace_event=bad_event)
        except VerifyError:
            pass
        else:
            raise AssertionError(
                "bad trace event %r must raise" % (bad_event,)
            )
    request = VerifyRequest(object_path="x.o")
    assert request.map_types == ()
    assert request.trace_event is None
    request = VerifyRequest(
        object_path="x.o",
        map_types=["array", "ringbuf"],
        trace_event="syscalls:sys_enter_getpid",
    )
    assert request.map_types == ("array", "ringbuf"), request.map_types
    assert request.trace_event == "syscalls:sys_enter_getpid"
    request = VerifyRequest(object_path="x.o")
    assert request.release == os.environ.get(
        verify_module.RELEASE_ENV_VAR, verify_module.DEFAULT_RELEASE
    )


def test_request_rejects_nonliteral_map_names():
    """Map names are identifiers: no regex dots, glob, or traversal."""
    for bad in (
        "a..ay",  # regex dots once false-matched the array probe
        "array|ringbuf",
        "arr*",
        "arr?y",
        "array ringbuf",
        "../array",
        "array/evil",
        ".",
        "..",
        "",
        "ring-buf",
        "array\n",
        "array\ninjected=1",
    ):
        try:
            VerifyRequest(object_path="x.o", map_types=(bad,))
        except VerifyError:
            pass
        else:
            raise AssertionError("map type %r must raise" % (bad,))
    for good in (
        "array", "ringbuf", "insn_array", "arena", "percpu_array",
    ):
        request = VerifyRequest(object_path="x.o", map_types=(good,))
        assert request.map_types == (good,), request.map_types


def test_request_rejects_trace_traversal_and_newlines():
    """Each trace-event component is validated, not just the whole."""
    for bad in (
        "syscalls:../syscalls/sys_enter_getpid",
        "syscalls:..",
        "..:sys_enter_getpid",
        "..:..",
        "syscalls:sys_enter_getpid/../id",
        "syscalls:sys_enter_getpid\n",
        "syscalls:sys_enter_getpid\ninjected=1",
        "syscalls:sys.enter.getpid",
        "syscalls;evil:sys_enter_getpid",
        "sys calls:sys_enter_getpid",
        "syscalls:",
        ":sys_enter_getpid",
        "syscalls",
        "a:b:c",
        "",
        7,
        b"syscalls:sys_enter_getpid",
    ):
        try:
            VerifyRequest(object_path="x.o", trace_event=bad)
        except VerifyError:
            pass
        else:
            raise AssertionError("trace event %r must raise" % (bad,))
    for good in (
        "syscalls:sys_enter_getpid",
        "syscalls:sys_enter_no_such_event",
        "sched:sched_switch",
        "9p:9p_client_req",
    ):
        request = VerifyRequest(object_path="x.o", trace_event=good)
        assert request.trace_event == good


def test_request_rejects_trailing_newlines_everywhere():
    """The ``$``-vs-newline hole stays closed on every token field."""
    for kwargs in (
        {"release": "v6.12\n"},
        {"pin_path": "/sys/fs/bpf/mojobpf_verify\n"},
        {"prog_type": "xdp\n"},
        {"kernel_btf": "/sys/kernel/btf/vmlinux\n"},
        {"as_user": "nobody\n"},
        {"map_types": ("array\n",)},
        {"trace_event": "syscalls:sys_enter_getpid\n"},
    ):
        try:
            VerifyRequest(object_path="x.o", **kwargs)
        except VerifyError:
            pass
        else:
            raise AssertionError("%r must raise" % (kwargs,))


def test_map_probe_matches_literally_not_as_regex():
    """The guest map probe treats the requested name literally.

    Runs the template's real probe loop against a synthetic bpftool
    feature dump: ``a..ay`` must not match the ``array`` line (grep
    without -F would treat the dots as regex), while ``array``
    matches and the preflight refuses the unknown name.
    """
    import subprocess
    import tempfile

    template = verify_module.GUEST_SCRIPT_TEMPLATE
    assert 'grep -F "map_type $MAP_TYPE is"' in template
    assert 'grep -F "program_type $PROG_TYPE is"' in template
    start = template.index("for MAP_TYPE in $MAP_TYPES; do")
    end = template.index('echo "map_failed=$MAP_FAILED"')
    end += len('echo "map_failed=$MAP_FAILED"')
    loop = template[start:end]
    assert "MAP_PROBE_LINE=$(grep -F " in loop
    stage = tempfile.mkdtemp(prefix="verify-probe-")
    with open(os.path.join(stage, "feature.txt"), "w") as handle:
        handle.write(
            "eBPF map_type array is available\n"
            "eBPF map_type ringbuf is available\n"
            "eBPF map_type insn_array is NOT available\n"
        )
    driver = (
        "set -u\n"
        'STAGE="%s"\n'
        "MAP_TYPES='a..ay array'\n"
        "MAP_PREFLIGHT_OK=1\n"
        'MAP_FAILED=""\n'
        "%s\n"
    ) % (stage, loop)
    proc = subprocess.run(
        ["bash", "-c", driver],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, (proc.returncode, proc.stderr)
    assert "map_probe_line[a..ay]=" in proc.stdout, proc.stdout
    assert "map_type_supported[a..ay]=unknown" in proc.stdout, (
        proc.stdout
    )
    assert "map_type_supported[array]=1" in proc.stdout, proc.stdout
    assert "map_preflight_ok=0" in proc.stdout, proc.stdout
    assert "map_failed=a..ay" in proc.stdout, proc.stdout


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
    assert runner["exec_sha256"] is None, runner
    assert runner["qemu_binary"] == "qemu-system-x86_64", runner
    assert len(runner["qemu_sha256"]) == 64, runner
    assert runner["qemu_exec_sha256"] is None, runner
    assert len(runner["interpreter"]["sha256"]) == 64, runner
    modules = runner["package"]["modules"]
    assert runner["package"]["name"] == "virtme_ng", runner
    assert len(modules) >= 2, modules
    for dotted, digest in modules.items():
        assert dotted.split(".")[0] == "virtme_ng", modules
        assert len(digest) == 64, modules
    assert lock["distribution"]["runner"]["package"] == "virtme-ng"
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
    args = parser.parse_args(
        [
            "verify", "--kernel", "--object", "nope.o",
            "--map-type", "array", "--map-type", "ringbuf",
            "--trace-event", "syscalls:sys_enter_getpid",
        ]
    )
    assert args.map_type == ["array", "ringbuf"], args.map_type
    assert args.trace_event == "syscalls:sys_enter_getpid"
    assert cli_module._command_verify(args) == cli_module.EXIT_USAGE


# A complete successful guest transcript: clean load plus clean
# unload, exactly as the guest script prints them.
_SUCCESS_TRANSCRIPT = """\
padding-1: virtme-exec-drops-leading-bytes-0123456789abcdef
=== begin verify_kernel ===
guest-id: 0:0
guest-kernel: 6.12.0-061200-generic
kernel_btf=present
guest-cmd: bpftool feature probe kernel
probe_line=program_type xdp is available
prog_type_supported=1
guest-cmd: probe map types and trace event
map_preflight_ok=1
map_failed=
trace_event_supported=unknown
trace_event_id=
guest-cmd: bpftool prog list; bpftool map list; bpftool link list; ls /sys/fs/bpf
=== BEGIN snapshot-before ===

=== END snapshot-before ===
guest-cmd: bpftool prog load /tmp/x/y.bpf.o /sys/fs/bpf/mojobpf-verify
load_exit=0
=== BEGIN load-log ===

=== END load-log ===
guest-cmd: rm -f /sys/fs/bpf/mojobpf-verify
unload_ok=1
quiesced=1
quiesce_waits=2
guest-cmd: bpftool prog list; bpftool map list; bpftool link list; ls /sys/fs/bpf
=== BEGIN snapshot-after ===

=== END snapshot-after ===
=== end verify_kernel ===
"""


class _FakeGuestProc:
    """A canned guest child: fixed transcript, fixed exit code."""

    exit_code = 0

    def __init__(self, *args, **kwargs):
        self.pid = 424242
        self.returncode = _FakeGuestProc.exit_code

    def communicate(self, timeout=None):
        self.returncode = _FakeGuestProc.exit_code
        return (_SUCCESS_TRANSCRIPT, "")

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass


VNG_FIXTURE_VERSION = "virtme-ng 9.99-fixture"
QEMU_FIXTURE_VERSION = "QEMU fixture 9.99"


def _write_executable(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o755)


def _sha256_of(path):
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _runner_fixture(run_body=None, qemu_body=None):
    """Stage a fixture vng console script, package and emulator.

    Returns ``(root, entry, pkgdir, qemu, lock_path)`` with the
    kernels lock pinning every identity. Nothing here boots a
    guest: the entry only answers ``--version``.
    """
    root = tempfile.mkdtemp(prefix="verify-admit-")
    pkgdir = os.path.join(root, "pkg")
    package = os.path.join(pkgdir, "fixture_vng_pkg")
    os.makedirs(package)
    with open(os.path.join(package, "__init__.py"), "w") as handle:
        handle.write("")
    if run_body is None:
        run_body = (
            "VERSION = %r\n\ndef main():\n    print(VERSION)\n    return 0\n"
            % (VNG_FIXTURE_VERSION,)
        )
    with open(os.path.join(package, "run.py"), "w") as handle:
        handle.write(run_body)
    entry = os.path.join(root, "vng")
    _write_executable(
        entry,
        "#!%s\nimport sys\nfrom fixture_vng_pkg.run import main\n"
        "if __name__ == '__main__':\n"
        "    if sys.argv[1:] == ['--version']:\n"
        "        print(%r)\n    else:\n        sys.exit(main())\n"
        % (sys.executable, VNG_FIXTURE_VERSION),
    )
    qemu = os.path.join(root, "fixture-qemu")
    if qemu_body is None:
        qemu_body = "#!/bin/sh\necho '%s'\n" % QEMU_FIXTURE_VERSION
    _write_executable(qemu, qemu_body)
    lock_path = os.path.join(root, "kernels.lock.json")
    with open(lock_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "schema_version": 1,
                "runner": {
                    "name": "vng",
                    "version": VNG_FIXTURE_VERSION,
                    "sha256": _sha256_of(entry),
                    "exec_sha256": None,
                    "interpreter": {
                        "sha256": _sha256_of(
                            os.path.realpath(sys.executable)
                        ),
                    },
                    "package": {
                        "name": "fixture_vng_pkg",
                        "modules": {
                            "fixture_vng_pkg": _sha256_of(
                                os.path.join(package, "__init__.py")
                            ),
                            "fixture_vng_pkg.run": _sha256_of(
                                os.path.join(package, "run.py")
                            ),
                        },
                    },
                    "python_path": [pkgdir],
                    "qemu_binary": "fixture-qemu",
                    "qemu": QEMU_FIXTURE_VERSION,
                    "qemu_sha256": _sha256_of(qemu),
                    "qemu_exec_sha256": None,
                },
            },
            handle,
        )
    return root, entry, pkgdir, qemu, lock_path


def _run_with_fake_guest(exit_code):
    """Run one verification against the canned transcript."""
    holding = tempfile.mkdtemp(prefix="verify-unit-")
    staged = os.path.join(holding, "probe.bpf.o")
    with open(staged, "wb") as handle:
        handle.write(b"not-an-elf-object")
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    real_popen = subprocess.Popen
    saved_path = os.environ.get("PATH", "")
    _FakeGuestProc.exit_code = exit_code

    def _popping(*args, **kwargs):
        # Only the guest boot is canned; admission probes (version,
        # module path) run for real against the fixture chain.
        argv = args[0] if args else []
        if (
            isinstance(argv, list)
            and len(argv) > 2
            and argv[1] == "--run"
        ):
            return _FakeGuestProc(*args, **kwargs)
        return real_popen(*args, **kwargs)

    subprocess.Popen = _popping
    # The emulator resolves by bare name, as in production.
    os.environ["PATH"] = root + os.pathsep + saved_path
    try:
        request = VerifyRequest(
            object_path=staged,
            release="v9.99",
            vng_path=entry,
            require_btf="no",
            timeout=60,
            kernels_lock=lock_path,
        )
        return run_verification(request)
    finally:
        subprocess.Popen = real_popen
        os.environ["PATH"] = saved_path
        shutil.rmtree(holding, ignore_errors=True)


def test_pass_requires_a_clean_runner_exit():
    """A success transcript with a nonzero child exit never passes."""
    result = _run_with_fake_guest(1)
    try:
        assert result["child"]["exit"] == 1, result["child"]
        assert result["load"]["exit"] == 0, result["load"]
        assert result["unload"]["pin_absent"] is True, result["unload"]
        assert result["status"] == "fail", result
        assert result["classification"] == "environment", result
        assert "runner exited 1" in (result["note"] or ""), result
    finally:
        shutil.rmtree(result["stage_path"], ignore_errors=True)


def test_clean_runner_exit_passes():
    """The same transcript with child exit 0 passes (control)."""
    result = _run_with_fake_guest(0)
    try:
        assert result["child"]["exit"] == 0, result["child"]
        assert result["status"] == "pass", result
        assert result["stage"] == "done", result
        assert result["classification"] is None, result
    finally:
        shutil.rmtree(result["stage_path"], ignore_errors=True)


def _admit_fixture(entry, lock_path, farm_parent):
    """Admit a fixture runner with its emulator on PATH."""
    root = os.path.dirname(entry)
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = root + os.pathsep + saved_path
    try:
        return verify_module._probe_vng(
            entry, kernels_lock=lock_path, farm_parent=farm_parent
        )
    finally:
        os.environ["PATH"] = saved_path


def test_runner_admission_accepts_pinned_chain():
    """The fixture runner admits with its full attestation."""
    root, entry, _pkgdir, qemu, lock_path = _runner_fixture()
    try:
        runner = _admit_fixture(entry, lock_path, root)
        try:
            assert runner["version"] == VNG_FIXTURE_VERSION, runner
            assert runner["sha256"] == _sha256_of(entry), runner
            assert runner["exec_path"] is None, runner
            assert runner["interpreter"] is not None, runner
            assert sorted(runner["modules"]) == [
                "fixture_vng_pkg", "fixture_vng_pkg.run",
            ], runner
            assert runner["qemu"]["version"] == QEMU_FIXTURE_VERSION
            assert runner["qemu"]["sha256"] == _sha256_of(qemu)
            assert runner["digest"], runner
            farm = runner["farm"]
            assert os.path.realpath(
                os.path.join(farm, "vng")
            ) == os.path.realpath(entry)
            assert os.path.realpath(
                os.path.join(farm, "fixture-qemu")
            ) == os.path.realpath(qemu)
        finally:
            shutil.rmtree(runner["farm"], ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_arbitrary_vng_rejected_before_spawn():
    """F-001 scratch reproducer, preserved: an arbitrary vng with
    the locked version string is refused before any process
    starts (no execution marker)."""
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    marker = os.path.join(root, "EXECUTED.marker")
    try:
        _write_executable(
            entry,
            "#!/bin/sh\ntouch '%s'\necho '%s'\n"
            % (marker, VNG_FIXTURE_VERSION),
        )
        try:
            _admit_fixture(entry, lock_path, root)
        except VerifyError as exc:
            assert "admission refused" in str(exc), exc
        else:
            raise AssertionError("arbitrary vng admitted")
        assert not os.path.exists(marker), "substituted vng executed"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_pythonpath_shadow_never_imported():
    """N-3 scratch reproducer, preserved: an ambient PYTHONPATH
    shadow of the runner package is never imported -- admission
    and probes use exactly the admitted module path."""
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    marker = os.path.join(root, "EXECUTED.marker")
    shadow = os.path.join(root, "shadow", "fixture_vng_pkg")
    os.makedirs(shadow)
    with open(os.path.join(shadow, "__init__.py"), "w") as handle:
        handle.write("")
    with open(os.path.join(shadow, "run.py"), "w") as handle:
        handle.write(
            "open(%r, 'w').write('shadowed')\n"
            "VERSION = %r\n\ndef main():\n    print(VERSION)\n"
            "    return 0\n" % (marker, VNG_FIXTURE_VERSION)
        )
    saved_pythonpath = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = os.path.dirname(shadow)
    try:
        runner = _admit_fixture(entry, lock_path, root)
        try:
            assert runner["version"] == VNG_FIXTURE_VERSION, runner
            assert runner["modules"]["fixture_vng_pkg.run"] == (
                _sha256_of(
                    os.path.join(
                        root, "pkg", "fixture_vng_pkg", "run.py"
                    )
                )
            )
        finally:
            shutil.rmtree(runner["farm"], ignore_errors=True)
        assert not os.path.exists(marker), "PYTHONPATH shadow imported"
    finally:
        if saved_pythonpath is None:
            os.environ.pop("PYTHONPATH", None)
        else:
            os.environ["PYTHONPATH"] = saved_pythonpath
        shutil.rmtree(root, ignore_errors=True)


def test_modified_package_module_rejected():
    """A rewritten runner module is rejected by hash before any
    import (the marker proves the evil module never loaded)."""
    root, entry, pkgdir, _qemu, lock_path = _runner_fixture()
    marker = os.path.join(root, "EXECUTED.marker")
    try:
        with open(
            os.path.join(pkgdir, "fixture_vng_pkg", "run.py"), "w"
        ) as handle:
            handle.write(
                "open(%r, 'w').write('evil')\n"
                "VERSION = %r\n\ndef main():\n    print(VERSION)\n"
                "    return 0\n" % (marker, VNG_FIXTURE_VERSION)
            )
        try:
            _admit_fixture(entry, lock_path, root)
        except VerifyError as exc:
            assert "admission refused" in str(exc), exc
        else:
            raise AssertionError("modified package module admitted")
        assert not os.path.exists(marker), "evil module imported"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_wrong_interpreter_pin_rejected():
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    try:
        with open(lock_path, encoding="utf-8") as handle:
            data = json.load(handle)
        data["runner"]["interpreter"]["sha256"] = "0" * 64
        with open(lock_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        try:
            _admit_fixture(entry, lock_path, root)
        except VerifyError as exc:
            assert "admission refused" in str(exc), exc
        else:
            raise AssertionError("wrong interpreter pin admitted")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_missing_qemu_pin_fails_closed():
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    try:
        with open(lock_path, encoding="utf-8") as handle:
            data = json.load(handle)
        del data["runner"]["qemu_sha256"]
        with open(lock_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        try:
            _admit_fixture(entry, lock_path, root)
        except VerifyError as exc:
            assert "qemu_sha256" in str(exc), exc
        else:
            raise AssertionError("unpinned emulator admitted")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_matching_version_unrelated_qemu_rejected():
    """F-041 on the verify path: a same-version unrelated
    emulator is refused before any process starts."""
    root, entry, _pkgdir, qemu, lock_path = _runner_fixture()
    marker = os.path.join(root, "EXECUTED.marker")
    try:
        _write_executable(
            qemu,
            "#!/bin/sh\ntouch '%s'\necho '%s'\n"
            % (marker, QEMU_FIXTURE_VERSION),
        )
        try:
            _admit_fixture(entry, lock_path, root)
        except VerifyError as exc:
            assert "admission refused" in str(exc), exc
        else:
            raise AssertionError("unrelated emulator admitted")
        assert not os.path.exists(marker), "substituted qemu executed"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_wrong_identity_negative_preserved_for_vm_validation():
    """Harmless controlled wrong-identity negative, host half.

    A substituted runner is rejected without spawning and
    without booting any guest. This host-side rejection is the
    preserved negative for later VM validation: the guest half
    (the same substitution refused in matrix context) runs under
    approved guest authority, outside this leaf.
    """
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    marker = os.path.join(root, "EXECUTED.marker")
    staged = os.path.join(root, "probe.bpf.o")
    with open(staged, "wb") as handle:
        handle.write(b"not-an-elf-object")
    _write_executable(
        entry,
        "#!/bin/sh\ntouch '%s'\necho '%s'\n"
        % (marker, VNG_FIXTURE_VERSION),
    )
    saved_path = os.environ.get("PATH", "")
    os.environ["PATH"] = root + os.pathsep + saved_path
    try:
        request = VerifyRequest(
            object_path=staged,
            release="v9.99",
            vng_path=entry,
            require_btf="no",
            timeout=60,
            kernels_lock=lock_path,
        )
        try:
            run_verification(request)
        except VerifyError as exc:
            assert "admission refused" in str(exc), exc
        else:
            raise AssertionError("substituted runner verified")
        assert not os.path.exists(marker), "substituted vng executed"
    finally:
        os.environ["PATH"] = saved_path
        shutil.rmtree(root, ignore_errors=True)


def test_request_accepts_kernels_lock():
    request = VerifyRequest(
        object_path="x.o", kernels_lock="/tmp/kernels.lock.json"
    )
    assert request.kernels_lock == "/tmp/kernels.lock.json"
    assert VerifyRequest(object_path="x.o").kernels_lock is None
    try:
        VerifyRequest(object_path="x.o", kernels_lock=7)
    except VerifyError:
        pass
    else:
        raise AssertionError("non-string kernels lock must raise")


def test_default_kernels_lock_resolves_checkout():
    assert verify_module.default_kernels_lock() == LOCK_PATH


def _direct_names():
    return sorted(
        name
        for name in globals()
        if name.startswith("test_") and callable(globals()[name])
    )


def _direct_run():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
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
