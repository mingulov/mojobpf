# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the guest-backed load-and-unload wrapper.

Pins the failure classification (loader versus verifier versus
environment) against real captured loader messages, the minimal ELF
section reader against a synthetic object, the guest script's never
attach/run/link discipline, the request validation, and the kernel
lane lockfile schema. Also pins captured-byte verification (one
byte string inspected, staged and attested), restrictive staging
permissions with default cleanup and explicit retention, hostile
stage-path quoting without shell evaluation, effective
release/lane validation, doctor/check separation, and the CLI exit
contract. Nothing here boots a guest: the live proofs live in
``tests/kernel/test_cleanup.py``.

Deterministic on any host: only the standard library plus pytest's
plain function collection.

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3
tests/unit/test_verify.py``).
"""

import ast
import contextlib
import inspect
import io
import json
import os
import re
import shutil
import signal
import stat
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
from mojobpf.execution import (  # noqa: E402
    ExecutionPins,
    ExecutionRequest,
    admit_execution,
    build_path_farm,
)
from mojobpf.verify import (  # noqa: E402
    VerifyError,
    VerifyInterrupted,
    VerifyRequest,
    _FORBIDDEN_GUEST_TOKENS,
    classify_load_output,
    guest_exec_command,
    read_elf_sections,
    read_elf_sections_bytes,
    resolve_lane,
    run_verification,
    verify_bytes,
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
        "script_name": "guest_verify.sh",
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
    assert len(runner["virtme_run_sha256"]) == 64, runner
    assert runner["virtme_run_exec_sha256"] is None, runner
    assert len(runner["interpreter"]["sha256"]) == 64, runner
    modules = runner["package"]["modules"]
    assert runner["package"]["name"] == "virtme_ng", runner
    assert len(modules) >= 2, modules
    for dotted, digest in modules.items():
        assert dotted.split(".")[0] in ("virtme_ng", "_virtualenv"), (
            modules
        )
        assert len(digest) == 64, modules
    launcher_modules = runner["virtme_package"]["modules"]
    assert runner["virtme_package"]["name"] == "virtme", runner
    assert len(launcher_modules) >= 2, launcher_modules
    for dotted, digest in launcher_modules.items():
        assert dotted.split(".")[0] == "virtme", launcher_modules
        assert len(digest) == 64, launcher_modules
    distribution = lock["distribution"]
    assert distribution["runner"]["package"] == "virtme-ng"
    dependencies = distribution["runner"]["dependencies"]
    assert len(dependencies) >= 1, dependencies
    for dependency in dependencies:
        assert dependency["name"], dependency
        assert dependency["version"], dependency
        assert len(dependency["metadata_sha256"]) == 64, dependency
        assert dependency["metadata_sha256"] != "0" * 64, dependency
        assert len(dependency["record_sha256"]) == 64, dependency
        assert dependency["record_sha256"] != "0" * 64, dependency
    assert distribution["emulator"]["qemu_version"] == runner["qemu"]
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


def _hashes_for_argv(argv):
    """Hash the staged inputs the argv's --exec stage holds (or '').

    The fake guest behaves like the real one: it reports the
    hashes of the bytes it actually loads. Returns '' when the
    stage cannot be read (the host gate then fails closed on
    the missing evidence).
    """
    import hashlib as _hashlib
    import shlex as _shlex

    try:
        exec_index = argv.index("--exec")
        parts = _shlex.split(argv[exec_index + 1])
        stage = parts[2]
        lines = ["=== staged hashes ==="]
        for name in ("verify-target.o", "guest_verify.sh"):
            with open(os.path.join(stage, name), "rb") as handle:
                digest = _hashlib.sha256(handle.read()).hexdigest()
            lines.append("%s  %s" % (digest, name))
        return "\n".join(lines) + "\n"
    except Exception:
        return ""


class _FakeGuestProc:
    """A canned guest child: fixed transcript, fixed exit code."""

    exit_code = 0
    transcript = None
    emit_hashes = True

    def __init__(self, *args, **kwargs):
        self.pid = 424242
        self.returncode = _FakeGuestProc.exit_code
        self._argv = (
            list(args[0])
            if args and isinstance(args[0], list)
            else []
        )

    def communicate(self, timeout=None):
        self.returncode = _FakeGuestProc.exit_code
        if _FakeGuestProc.transcript is not None:
            body = _FakeGuestProc.transcript
        else:
            body = _SUCCESS_TRANSCRIPT
        if (
            _FakeGuestProc.emit_hashes
            and "=== staged hashes ===" not in body
        ):
            body = _hashes_for_argv(self._argv) + body
        return (body, "")

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass


VNG_FIXTURE_VERSION = "virtme-ng 9.99-fixture"
QEMU_FIXTURE_VERSION = "QEMU fixture 9.99"
LAUNCHER_FIXTURE_LINE = "virtme-run fixture 9.99"


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


def _runner_fixture(run_body=None, qemu_body=None, launcher_body=None):
    """Stage a fixture vng console script, package and emulator.

    Also stages the fixture ``virtme-run`` launcher plus its
    ``fixture_virtme_pkg`` implementation. Returns ``(root,
    entry, pkgdir, qemu, lock_path)`` with the kernels lock
    pinning every identity. Nothing here boots a guest: the
    entries only answer their probes.
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
    launcher_package = os.path.join(pkgdir, "fixture_virtme_pkg")
    launcher_commands = os.path.join(launcher_package, "commands")
    os.makedirs(launcher_commands)
    with open(
        os.path.join(launcher_package, "__init__.py"), "w"
    ) as handle:
        handle.write("")
    with open(
        os.path.join(launcher_commands, "__init__.py"), "w"
    ) as handle:
        handle.write("")
    if launcher_body is None:
        launcher_body = (
            "VERSION = %r\n\ndef main():\n    print(VERSION)\n"
            "    return 0\n" % (LAUNCHER_FIXTURE_LINE,)
        )
    with open(
        os.path.join(launcher_commands, "run.py"), "w"
    ) as handle:
        handle.write(launcher_body)
    launcher = os.path.join(root, "virtme-run")
    _write_executable(
        launcher,
        "#!%s\nimport sys\n"
        "from fixture_virtme_pkg.commands.run import main\n"
        "if __name__ == '__main__':\n"
        "    if sys.argv[1:] == ['--help']:\n"
        "        print(%r)\n    else:\n        sys.exit(main())\n"
        % (sys.executable, LAUNCHER_FIXTURE_LINE),
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
                    "virtme_run_sha256": _sha256_of(launcher),
                    "virtme_run_exec_sha256": None,
                    "virtme_package": {
                        "name": "fixture_virtme_pkg",
                        "modules": {
                            "fixture_virtme_pkg": _sha256_of(
                                os.path.join(
                                    launcher_package, "__init__.py"
                                )
                            ),
                            "fixture_virtme_pkg.commands": _sha256_of(
                                os.path.join(
                                    launcher_commands, "__init__.py"
                                )
                            ),
                            "fixture_virtme_pkg.commands.run": (
                                _sha256_of(
                                    os.path.join(
                                        launcher_commands, "run.py"
                                    )
                                )
                            ),
                        },
                    },
                },
                "lanes": [
                    {
                        "id": "v9.99-tcg",
                        "release": "v9.99",
                        "accelerator": "tcg",
                        "kernel_release": "9.99.0-fixture",
                        "kernel_debs": [
                            {
                                "file": (
                                    "linux-image-9.99-fixture"
                                    "_amd64.deb"
                                ),
                                "sha256": "1" * 64,
                            },
                        ],
                        "vng_argv_prefix": [
                            "vng", "--run", "v9.99", "--disable-kvm",
                        ],
                    },
                ],
            },
            handle,
        )
    return root, entry, pkgdir, qemu, lock_path


def _run_with_fake_guest(
    exit_code,
    transcript=None,
    keep_evidence=False,
    object_bytes=b"not-an-elf-object",
):
    """Run one verification against the canned transcript."""
    holding = tempfile.mkdtemp(prefix="verify-unit-")
    staged = os.path.join(holding, "probe.bpf.o")
    with open(staged, "wb") as handle:
        handle.write(object_bytes)
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    real_popen = subprocess.Popen
    saved_path = os.environ.get("PATH", "")
    saved_exit = _FakeGuestProc.exit_code
    saved_transcript = _FakeGuestProc.transcript
    saved_hashes = _FakeGuestProc.emit_hashes
    _FakeGuestProc.exit_code = exit_code
    _FakeGuestProc.transcript = transcript

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
            keep_evidence=keep_evidence,
        )
        return run_verification(request)
    finally:
        subprocess.Popen = real_popen
        os.environ["PATH"] = saved_path
        _FakeGuestProc.exit_code = saved_exit
        _FakeGuestProc.transcript = saved_transcript
        _FakeGuestProc.emit_hashes = saved_hashes
        shutil.rmtree(holding, ignore_errors=True)
        shutil.rmtree(root, ignore_errors=True)


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
    launcher = os.path.join(root, "virtme-run")
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
            assert runner["virtme_run"]["binary"] == "virtme-run"
            assert runner["virtme_run"]["version"] == (
                LAUNCHER_FIXTURE_LINE
            ), runner
            assert runner["virtme_run"]["sha256"] == _sha256_of(
                launcher
            )
            assert runner["digest"], runner
            farm = runner["farm"]
            assert os.path.realpath(
                os.path.join(farm, "vng")
            ) == os.path.realpath(entry)
            assert os.path.realpath(
                os.path.join(farm, "virtme-run")
            ) == os.path.realpath(launcher)
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


def test_substituted_launcher_rejected_before_spawn():
    """A substituted virtme-run launcher is refused before any
    process starts (no execution marker)."""
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    marker = os.path.join(root, "EXECUTED.marker")
    launcher = os.path.join(root, "virtme-run")
    try:
        _write_executable(
            launcher,
            "#!/bin/sh\ntouch '%s'\necho '%s'\n"
            % (marker, LAUNCHER_FIXTURE_LINE),
        )
        try:
            _admit_fixture(entry, lock_path, root)
        except VerifyError as exc:
            assert "launcher admission refused" in str(exc), exc
        else:
            raise AssertionError("substituted launcher admitted")
        assert not os.path.exists(marker), "substituted launcher executed"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_modified_launcher_package_rejected():
    """A rewritten virtme.* module is rejected by hash before any
    import (the marker proves the evil module never loaded)."""
    root, entry, pkgdir, _qemu, lock_path = _runner_fixture()
    marker = os.path.join(root, "EXECUTED.marker")
    try:
        with open(
            os.path.join(
                pkgdir, "fixture_virtme_pkg", "commands", "run.py"
            ),
            "w",
        ) as handle:
            handle.write(
                "open(%r, 'w').write('evil')\n"
                "VERSION = %r\n\ndef main():\n    print(VERSION)\n"
                "    return 0\n" % (marker, LAUNCHER_FIXTURE_LINE)
            )
        try:
            _admit_fixture(entry, lock_path, root)
        except VerifyError as exc:
            assert "launcher admission refused" in str(exc), exc
        else:
            raise AssertionError("modified launcher package admitted")
        assert not os.path.exists(marker), "evil launcher module imported"
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_missing_launcher_pin_fails_closed():
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    try:
        with open(lock_path, encoding="utf-8") as handle:
            data = json.load(handle)
        del data["runner"]["virtme_run_sha256"]
        with open(lock_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        try:
            _admit_fixture(entry, lock_path, root)
        except VerifyError as exc:
            assert "virtme_run_sha256" in str(exc), exc
        else:
            raise AssertionError("unpinned launcher admitted")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _write_dep_dist(pkgdir, name, version, files):
    """Stage a fixture distribution; return (metadata, record) digests.

    ``files`` maps root-relative paths (``pkg/__init__.py``) to
    text content. Writes the package files, the ``.dist-info``
    with ``METADATA``, and a ``RECORD`` manifest with real
    per-file hashes plus its own empty-hash self entry.
    """
    import base64
    import hashlib

    dist_info = "%s-%s.dist-info" % (name, version)
    os.makedirs(os.path.join(pkgdir, dist_info), exist_ok=True)
    staged = {}
    for rel, text in files.items():
        path = os.path.join(pkgdir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        staged[rel] = path
    metadata_rel = "%s/METADATA" % dist_info
    metadata = os.path.join(pkgdir, metadata_rel)
    with open(metadata, "w", encoding="utf-8") as handle:
        handle.write(
            "Metadata-Version: 2.1\nName: %s\nVersion: %s\n"
            % (name, version)
        )
    staged[metadata_rel] = metadata

    def _record_hash(path):
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return (
            "sha256="
            + base64.urlsafe_b64encode(digest.digest())
            .rstrip(b"=")
            .decode("ascii")
        )

    rows = [
        "%s,%s," % (rel, _record_hash(path))
        for rel, path in sorted(staged.items())
    ]
    rows.append("%s/RECORD,," % dist_info)
    record = os.path.join(pkgdir, dist_info, "RECORD")
    with open(record, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(rows) + "\n")
    return _sha256_of(metadata), _sha256_of(record)


def _lock_with_distribution(lock_path, distribution):
    with open(lock_path, encoding="utf-8") as handle:
        data = json.load(handle)
    data["distribution"] = distribution
    with open(lock_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle)


def test_runner_distribution_enforced():
    """The lock's distribution bindings are verified on the
    verify path too, never trusted descriptively."""
    root, entry, pkgdir, _qemu, lock_path = _runner_fixture()
    metadata_digest, record_digest = _write_dep_dist(
        pkgdir,
        "verify_dep",
        "1.0",
        {"verify_dep/__init__.py": "VALUE = 1\n"},
    )
    try:
        _lock_with_distribution(
            lock_path,
            {
                "runner": {
                    "dependencies": [
                        {
                            "name": "verify_dep",
                            "version": "1.0",
                            "metadata_sha256": metadata_digest,
                            "record_sha256": record_digest,
                        },
                    ],
                },
                "emulator": {"qemu_version": QEMU_FIXTURE_VERSION},
            },
        )
        runner = _admit_fixture(entry, lock_path, root)
        shutil.rmtree(runner["farm"], ignore_errors=True)
        assert runner["version"] == VNG_FIXTURE_VERSION, runner

        _lock_with_distribution(
            lock_path,
            {
                "runner": {
                    "dependencies": [
                        {
                            "name": "verify_dep",
                            "version": "1.0",
                            "metadata_sha256": "0" * 64,
                            "record_sha256": record_digest,
                        },
                    ],
                },
            },
        )
        try:
            _admit_fixture(entry, lock_path, root)
        except VerifyError as exc:
            assert "distribution" in str(exc), exc
            assert "zero" in str(exc), exc
        else:
            raise AssertionError("zero-digest distribution admitted")

        _lock_with_distribution(
            lock_path,
            {
                "runner": {
                    "dependencies": [
                        {
                            "name": "verify_dep",
                            "version": "1.0",
                            "metadata_sha256": metadata_digest,
                            "record_sha256": "0" * 64,
                        },
                    ],
                },
            },
        )
        try:
            _admit_fixture(entry, lock_path, root)
        except VerifyError as exc:
            assert "distribution" in str(exc), exc
            assert "zero" in str(exc), exc
        else:
            raise AssertionError("zero-record distribution admitted")

        _lock_with_distribution(
            lock_path,
            {
                "runner": {
                    "dependencies": [
                        {
                            "name": "verify_absent",
                            "version": "1.0",
                            "metadata_sha256": metadata_digest,
                            "record_sha256": record_digest,
                        },
                    ],
                },
            },
        )
        try:
            _admit_fixture(entry, lock_path, root)
        except VerifyError as exc:
            assert "distribution" in str(exc), exc
        else:
            raise AssertionError("missing distribution admitted")

        _lock_with_distribution(
            lock_path,
            {"emulator": {"qemu_version": "QEMU tampered 0.0"}},
        )
        try:
            _admit_fixture(entry, lock_path, root)
        except VerifyError as exc:
            assert "distribution" in str(exc), exc
        else:
            raise AssertionError("tampered emulator claim admitted")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_runner_distribution_substituted_content_refused():
    """METADATA alone cannot bind a dependency: substituting the
    actually-imported package bytes while METADATA is untouched
    is refused through the RECORD chain before any probe, so the
    substituted program leaves no execution marker."""
    root, entry, pkgdir, _qemu, lock_path = _runner_fixture(
        run_body=(
            "import verify_dep\nVERSION = %r\n\ndef main():\n"
            "    print(VERSION)\n    return 0\n"
            % (VNG_FIXTURE_VERSION,)
        )
    )
    marker = os.path.join(root, "DEP.marker")
    metadata_digest, record_digest = _write_dep_dist(
        pkgdir,
        "verify_dep",
        "1.0",
        {"verify_dep/__init__.py": "VALUE = 1\n"},
    )
    try:
        _lock_with_distribution(
            lock_path,
            {
                "runner": {
                    "dependencies": [
                        {
                            "name": "verify_dep",
                            "version": "1.0",
                            "metadata_sha256": metadata_digest,
                            "record_sha256": record_digest,
                        },
                    ],
                },
                "emulator": {"qemu_version": QEMU_FIXTURE_VERSION},
            },
        )
        runner = _admit_fixture(entry, lock_path, root)
        shutil.rmtree(runner["farm"], ignore_errors=True)
        assert runner["version"] == VNG_FIXTURE_VERSION, runner
        with open(
            os.path.join(pkgdir, "verify_dep", "__init__.py"), "w"
        ) as handle:
            handle.write(
                "open(%r, 'w').write('evil')\nVALUE = 1\n" % marker
            )
        try:
            _admit_fixture(entry, lock_path, root)
        except VerifyError as exc:
            assert "distribution" in str(exc), exc
        else:
            raise AssertionError("substituted dependency admitted")
        assert not os.path.exists(marker), (
            "substituted dependency executed"
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_runner_distribution_shadow_dependency_refused():
    """Import selection binds to the verified roots on the verify
    path too: a shadow dependency on an earlier declared root is
    refused before any probe, leaving no execution marker."""
    root, entry, pkgdir, _qemu, lock_path = _runner_fixture(
        run_body=(
            "import verify_dep\nVERSION = %r\n\ndef main():\n"
            "    print(VERSION)\n    return 0\n"
            % (VNG_FIXTURE_VERSION,)
        )
    )
    marker = os.path.join(root, "DEP-SHADOW.marker")
    metadata_digest, record_digest = _write_dep_dist(
        pkgdir,
        "verify_dep",
        "1.0",
        {"verify_dep/__init__.py": "VALUE = 1\n"},
    )
    evil = os.path.join(root, "evil")
    os.makedirs(os.path.join(evil, "verify_dep"))
    with open(
        os.path.join(evil, "verify_dep", "__init__.py"), "w"
    ) as handle:
        handle.write("open(%r, 'w').write('evil')\n" % marker)
    try:
        with open(lock_path, encoding="utf-8") as handle:
            data = json.load(handle)
        data["runner"]["python_path"] = [evil, pkgdir]
        data["distribution"] = {
            "runner": {
                "dependencies": [
                    {
                        "name": "verify_dep",
                        "version": "1.0",
                        "metadata_sha256": metadata_digest,
                        "record_sha256": record_digest,
                    },
                ],
            },
            "emulator": {"qemu_version": QEMU_FIXTURE_VERSION},
        }
        with open(lock_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        # Positive control: the earlier root wins selection.
        env = dict(os.environ)
        env["PYTHONPATH"] = evil + os.pathsep + pkgdir
        proc = subprocess.run(
            [sys.executable, "-P", "-c", "import verify_dep"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            env=env,
        )
        assert proc.returncode == 0, proc
        assert os.path.exists(marker), "shadow fixture cannot emit"
        os.unlink(marker)
        try:
            _admit_fixture(entry, lock_path, root)
        except VerifyError as exc:
            assert "distribution" in str(exc), exc
            assert "shadowed" in str(exc), exc
        else:
            raise AssertionError("shadow dependency admitted")
        assert not os.path.exists(marker), (
            "shadow dependency executed"
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_runner_distribution_failure_allows_zero_probes():
    """A failed distribution binding is enforced before ANY
    entry probe: with an all-zero dependency digest, the
    vng/qemu/launcher entries never spawn."""
    root, entry, pkgdir, _qemu, lock_path = _runner_fixture()
    _metadata_digest, record_digest = _write_dep_dist(
        pkgdir,
        "verify_dep",
        "1.0",
        {"verify_dep/__init__.py": "VALUE = 1\n"},
    )
    _lock_with_distribution(
        lock_path,
        {
            "runner": {
                "dependencies": [
                    {
                        "name": "verify_dep",
                        "version": "1.0",
                        "metadata_sha256": "0" * 64,
                        "record_sha256": record_digest,
                    },
                ],
            },
        },
    )
    spawns = []
    real_popen = subprocess.Popen

    def _spy(*args, **kwargs):
        argv = args[0] if args else kwargs.get("args", [])
        spawns.append(list(argv))
        return real_popen(*args, **kwargs)

    subprocess.Popen = _spy
    try:
        try:
            _admit_fixture(entry, lock_path, root)
        except VerifyError as exc:
            assert "distribution" in str(exc), exc
            assert "zero" in str(exc), exc
        else:
            raise AssertionError("zero-digest distribution admitted")
    finally:
        subprocess.Popen = real_popen
        shutil.rmtree(root, ignore_errors=True)
    entry_probes = [
        argv
        for argv in spawns
        if argv and argv[0].startswith(root + os.path.sep)
    ]
    assert entry_probes == [], entry_probes


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


# --- A07: verify exactly captured objects (host scope) ---


@contextlib.contextmanager
def _saved_env(name, value):
    """Set an env var (None deletes it), restoring afterwards."""
    missing = object()
    previous = os.environ.get(name, missing)
    if value is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = value
    try:
        yield
    finally:
        if previous is missing:
            os.environ.pop(name, None)
        else:
            os.environ[name] = previous


@contextlib.contextmanager
def _saved_tmpdir(value):
    """Redirect tempfile.mkdtemp at TMPDIR (busting its cache)."""
    previous_tempdir = tempfile.tempdir
    tempfile.tempdir = None
    try:
        with _saved_env("TMPDIR", value):
            yield
    finally:
        tempfile.tempdir = previous_tempdir


@contextlib.contextmanager
def _fake_guest_run(transcript=None, exit_code=0):
    """Admit a fixture runner with the guest boot canned.

    Yields ``(root, entry, lock_path)`` with PATH and Popen
    patched; admission probes run for real, only the guest boot
    is canned. Restores Popen/PATH/fake-proc state and removes
    the fixture root on exit.
    """
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    real_popen = subprocess.Popen
    saved_path = os.environ.get("PATH", "")
    saved_exit = _FakeGuestProc.exit_code
    saved_transcript = _FakeGuestProc.transcript
    saved_hashes = _FakeGuestProc.emit_hashes
    _FakeGuestProc.exit_code = exit_code
    _FakeGuestProc.transcript = transcript

    def _popping(*args, **kwargs):
        argv = args[0] if args else []
        if (
            isinstance(argv, list)
            and len(argv) > 2
            and argv[1] == "--run"
        ):
            return _FakeGuestProc(*args, **kwargs)
        return real_popen(*args, **kwargs)

    subprocess.Popen = _popping
    os.environ["PATH"] = root + os.pathsep + saved_path
    try:
        yield root, entry, lock_path
    finally:
        subprocess.Popen = real_popen
        os.environ["PATH"] = saved_path
        _FakeGuestProc.exit_code = saved_exit
        _FakeGuestProc.transcript = saved_transcript
        _FakeGuestProc.emit_hashes = saved_hashes
        shutil.rmtree(root, ignore_errors=True)


def _load_failed_transcript(log):
    """A guest transcript whose load failed with ``log`` as the log."""
    return (
        "=== begin verify_kernel ===\n"
        "guest-id: 0:0\n"
        "guest-kernel: 9.99.0-fixture\n"
        "kernel_btf=present\n"
        "guest-cmd: bpftool feature probe kernel\n"
        "probe_line=program_type xdp is available\n"
        "prog_type_supported=1\n"
        "guest-cmd: probe map types and trace event\n"
        "map_preflight_ok=1\n"
        "map_failed=\n"
        "trace_event_supported=unknown\n"
        "trace_event_id=\n"
        "guest-cmd: bpftool prog list; bpftool map list; "
        "bpftool link list; ls /sys/fs/bpf\n"
        "=== BEGIN snapshot-before ===\n"
        "\n"
        "=== END snapshot-before ===\n"
        "guest-cmd: bpftool prog load $OBJ $PIN\n"
        "load_exit=1\n"
        "=== BEGIN load-log ===\n"
        "%s\n"
        "=== END load-log ===\n"
        "=== end verify_kernel ===\n"
    ) % log


_PREFLIGHT_TRANSCRIPT = """\
=== begin verify_kernel ===
guest-id: 0:0
guest-kernel: 9.99.0-fixture
kernel_btf=absent
guest-cmd: bpftool feature probe kernel
probe_line=program_type xdp is NOT available
prog_type_supported=0
guest-cmd: probe map types and trace event
map_preflight_ok=1
map_failed=
trace_event_supported=unknown
trace_event_id=
guest-cmd: bpftool prog list; bpftool map list; bpftool link list; ls /sys/fs/bpf
=== BEGIN snapshot-before ===

=== END snapshot-before ===
PREFLIGHT_UNAVAILABLE unsupported-prog-type
=== end verify_kernel ===
"""


def test_read_elf_sections_bytes_matches_path_reader(tmp_path=None):
    image, license_bytes = _synthetic_elf()
    names, payload = read_elf_sections_bytes(image)
    assert names == ["", "xdp", "license", ".BTF"], names
    assert payload == license_bytes
    try:
        read_elf_sections_bytes(b"not an elf file\n")
    except ValueError:
        pass
    else:
        raise AssertionError("non-ELF bytes must raise ValueError")
    if tmp_path is None:
        parent = tempfile.mkdtemp(prefix="verify-elf-")
        path = os.path.join(parent, "t.o")
    else:
        parent = None
        path = str(tmp_path / "t.o")
    try:
        with open(path, "wb") as handle:
            handle.write(image)
        assert read_elf_sections(path) == (names, payload)
    finally:
        if parent is not None:
            shutil.rmtree(parent, ignore_errors=True)


def test_verify_bytes_rejects_unapproved_execution():
    """Anything but the admitted runner record is refused at the
    admission boundary, before any staging or spawn."""
    image, _license_bytes = _synthetic_elf()
    lane = resolve_lane("v6.12", "tcg", LOCK_PATH)
    scratch = tempfile.mkdtemp(prefix="verify-noexec-")
    try:
        with _saved_tmpdir(scratch):
            for bad in (
                None,
                {},
                {"farm": scratch},
                {"execution": 1},
            ):
                try:
                    verify_bytes(image, lane, bad)
                except VerifyError as exc:
                    assert "unapproved runner chain" in str(exc), exc
                else:
                    raise AssertionError(
                        "unapproved execution %r admitted" % (bad,)
                    )
            forged = {
                "execution": 1,
                "virtme_run_execution": 2,
                "qemu_execution": 3,
                "farm": scratch,
            }
            try:
                verify_bytes(image, lane, forged)
            except VerifyError as exc:
                assert "unapproved runner chain" in str(exc), exc
            else:
                raise AssertionError("forged farm admitted")
            assert os.listdir(scratch) == [], os.listdir(scratch)
        farmish = os.path.join(scratch, "mojobpf-farm-forged")
        os.makedirs(farmish)
        with open(os.path.join(farmish, "vng"), "w") as handle:
            handle.write("not a link")
        forged["farm"] = farmish
        try:
            verify_bytes(image, lane, forged)
        except VerifyError as exc:
            assert "non-link entries" in str(exc), exc
        else:
            raise AssertionError("non-link farm admitted")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def test_verify_bytes_rejects_bad_bytes_lane_and_options():
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    try:
        runner = _admit_fixture(entry, lock_path, root)
        try:
            lane = resolve_lane("v9.99", "tcg", lock_path)
            image, _license_bytes = _synthetic_elf()
            bad_calls = [
                (
                    {"object_bytes": "not-bytes"},
                    "object bytes must be bytes",
                ),
                ({"lane": {}}, "lacks"),
                (
                    {
                        "lane": dict(
                            lane, vng_argv_prefix=["evil"]
                        )
                    },
                    "malformed vng_argv_prefix",
                ),
                ({"pin_path": "/tmp/pin"}, "pin path must live under"),
                ({"prog_type": 'xdp"; evil'}, "carries characters"),
                ({"map_types": ("array; evil",)}, "identifier"),
                ({"trace_event": "nope"}, "category:name"),
                ({"require_btf": "sometimes"}, "require_btf"),
                ({"timeout": 0}, "timeout must be positive"),
                ({"keep_evidence": "yes"}, "keep_evidence must be a bool"),
            ]
            for kwargs, needle in bad_calls:
                call = {
                    "object_bytes": image,
                    "lane": lane,
                    "execution": runner,
                }
                call.update(kwargs)
                try:
                    verify_bytes(**call)
                except VerifyError as exc:
                    assert needle in str(exc), (needle, exc)
                else:
                    raise AssertionError(
                        "bad call admitted: %r" % (kwargs,)
                    )
        finally:
            shutil.rmtree(runner["farm"], ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_verify_bytes_inspects_stages_attests_same_bytes():
    """N-1 core: one captured byte string feeds inspection,
    staging and attestation; expected/actual kernels reported."""
    import hashlib

    image, license_bytes = _synthetic_elf()
    expected_digest = hashlib.sha256(image).hexdigest()
    with _fake_guest_run() as (_root, entry, lock_path):
        runner = verify_module._probe_vng(
            entry, kernels_lock=lock_path
        )
        farm = runner["farm"]
        try:
            lane = resolve_lane("v9.99", "tcg", lock_path)
            result = verify_bytes(
                image,
                lane,
                runner,
                object_path="synthetic.bpf.o",
                keep_evidence=True,
            )
        except BaseException:
            shutil.rmtree(farm, ignore_errors=True)
            raise
        try:
            assert result["schema"] == 2, result.get("schema")
            obj = result["object"]
            assert obj["sha256"] == expected_digest, obj
            assert obj["size"] == len(image), obj
            assert obj["sections"] == ["", "xdp", "license", ".BTF"], obj
            assert obj["license"] == license_bytes.decode(
                "ascii"
            ).rstrip("\x00"), obj
            assert obj["has_btf"] is True, obj
            assert obj["elf_parse_error"] is None, obj
            assert obj["path"] == "synthetic.bpf.o", obj
            staged = os.path.join(result["stage_path"], "verify-target.o")
            with open(staged, "rb") as handle:
                assert handle.read() == image
            assert result["lane"]["id"] == "v9.99-tcg", result["lane"]
            assert result["guest"]["kernel_expected"] == (
                "9.99.0-fixture"
            ), result["guest"]
            assert result["guest"]["kernel"] == (
                "6.12.0-061200-generic"
            ), result["guest"]
            assert result["status"] == "pass", result
            assert result["cleanup"] == {
                "staging_removed": False,
                "kept": True,
                "error": None,
            }, result["cleanup"]
        finally:
            shutil.rmtree(result["stage_path"], ignore_errors=True)
            shutil.rmtree(farm, ignore_errors=True)


def test_run_verification_captures_once_sequential_replacement():
    """N-1: a file replaced between the old read points cannot split
    inspected/staged/attested identity: one capture feeds all three."""
    import hashlib

    image, _license_bytes = _synthetic_elf()
    evil = b"replaced-after-capture"
    calls = []
    real_reader = verify_module._read_object_bytes

    def _swapping_reader(path):
        data = real_reader(path)
        calls.append(data)
        with open(path, "wb") as handle:
            handle.write(evil)
        return data

    verify_module._read_object_bytes = _swapping_reader
    try:
        with _fake_guest_run() as (_root, entry, lock_path):
            holding = tempfile.mkdtemp(prefix="verify-swap-")
            try:
                staged = os.path.join(holding, "probe.bpf.o")
                with open(staged, "wb") as handle:
                    handle.write(image)
                request = VerifyRequest(
                    object_path=staged,
                    release="v9.99",
                    vng_path=entry,
                    require_btf="no",
                    timeout=60,
                    kernels_lock=lock_path,
                    keep_evidence=True,
                )
                result = run_verification(request)
            finally:
                shutil.rmtree(holding, ignore_errors=True)
    finally:
        verify_module._read_object_bytes = real_reader
    try:
        assert len(calls) == 1, len(calls)
        assert calls[0] == image
        obj = result["object"]
        assert obj["sha256"] == hashlib.sha256(image).hexdigest(), obj
        assert obj["sections"] == ["", "xdp", "license", ".BTF"], obj
        with open(
            os.path.join(result["stage_path"], "verify-target.o"), "rb"
        ) as handle:
            assert handle.read() == image
    finally:
        shutil.rmtree(result["stage_path"], ignore_errors=True)
        shutil.rmtree(result["runner"]["farm"], ignore_errors=True)


def test_stage_path_never_interpolated():
    """F-032: the stage travels as guest argv, never interpolated."""
    import inspect

    assert "{stage}" not in verify_module.GUEST_SCRIPT_TEMPLATE
    params = inspect.signature(
        verify_module._render_guest_script
    ).parameters
    assert "stage" not in params, sorted(params)
    script = verify_module._render_guest_script(
        pin_path="/sys/fs/bpf/mojobpf_verify",
        prog_type="xdp",
        map_types=(),
        trace_event=None,
        kernel_btf="/sys/kernel/btf/vmlinux",
        require_btf_flag="0",
        as_user=None,
    )
    assert 'STAGE="${1:?missing stage argument}"' in script, script


def _forged_hashes_section(obj_hash=None, script_hash=None):
    """A staged-hashes section with the given (possibly forged) lines."""
    lines = ["=== staged hashes ==="]
    if obj_hash is not None:
        lines.append("%s  verify-target.o" % obj_hash)
    if script_hash is not None:
        lines.append("%s  guest_verify.sh" % script_hash)
    return "\n".join(lines) + "\n"


def _forged_hash_line(name, digest):
    """A bare injected hash line (no section header).

    The fake guest still prepends its truthful section to a
    header-free transcript, so the gate sees both the true
    line and the injected one; every printed line must match.
    """
    return "%s  %s\n" % (digest, name)


def _result_of_verify_bytes(image, transcript=None, **kwargs):
    """Run verify_bytes against the canned guest; return the result."""
    with _fake_guest_run() as (_root, entry, lock_path):
        runner = verify_module._probe_vng(
            entry, kernels_lock=lock_path
        )
        farm = runner["farm"]
        if transcript is not None:
            _FakeGuestProc.transcript = transcript
        try:
            lane = resolve_lane("v9.99", "tcg", lock_path)
            params = {
                "object_path": "synthetic.bpf.o",
                "keep_evidence": True,
            }
            params.update(kwargs)
            return verify_bytes(image, lane, runner, **params)
        finally:
            shutil.rmtree(farm, ignore_errors=True)


def test_verify_bytes_rejects_guest_object_hash_mismatch():
    # A1M4-3: the guest's staged hash must bind the loaded
    # bytes to the host capture. An injected object line that
    # disagrees with the capture fails closed (fail/run)
    # instead of attesting the capture, even though the guest
    # also prints its truthful section.
    image, _license = _synthetic_elf()
    transcript = _forged_hash_line(
        "verify-target.o", "0" * 64
    ) + _SUCCESS_TRANSCRIPT
    result = _result_of_verify_bytes(image, transcript)
    assert result["status"] == "fail", result
    assert result["stage"] == "run", result
    assert result["classification"] == "environment", result
    assert "verify-target.o" in result["note"], result


def test_verify_bytes_rejects_guest_script_hash_mismatch():
    # A1M4-3: the staged script is bound the same way; an
    # injected script line fails closed even when the object
    # line matches.
    image, _license = _synthetic_elf()
    transcript = _forged_hash_line(
        "guest_verify.sh", "0" * 64
    ) + _SUCCESS_TRANSCRIPT
    result = _result_of_verify_bytes(image, transcript)
    assert result["status"] == "fail", result
    assert result["stage"] == "run", result
    assert result["classification"] == "environment", result
    assert "guest_verify.sh" in result["note"], result


def test_verify_bytes_rejects_spaced_absolute_hash_mismatch():
    # A1M5-4: sha256sum does not escape spaces, so an
    # absolute hash line under a whitespace-containing
    # TMPDIR must still bind: a later wrong spaced line
    # fails closed even though the early relative lines
    # match.
    image, _license = _synthetic_elf()
    transcript = (
        "%s  /tmp/dir with space/mojobpf-verify-x/"
        "verify-target.o\n" % ("0" * 64)
    ) + _SUCCESS_TRANSCRIPT
    result = _result_of_verify_bytes(image, transcript)
    assert result["status"] == "fail", result
    assert result["stage"] == "run", result
    assert result["classification"] == "environment", result
    assert "verify-target.o" in result["note"], result


def test_verify_bytes_rejects_missing_staged_hashes():
    # A1M4-3: no staged hashes from the guest means no loaded
    # evidence; the run fails closed instead of attesting the
    # host capture alone.
    image, _license = _synthetic_elf()
    with _fake_guest_run() as (_root, entry, lock_path):
        runner = verify_module._probe_vng(
            entry, kernels_lock=lock_path
        )
        farm = runner["farm"]
        _FakeGuestProc.transcript = _SUCCESS_TRANSCRIPT
        _FakeGuestProc.emit_hashes = False
        try:
            lane = resolve_lane("v9.99", "tcg", lock_path)
            result = verify_bytes(
                image, lane, runner,
                object_path="synthetic.bpf.o",
                keep_evidence=True,
            )
        finally:
            _FakeGuestProc.emit_hashes = True
            shutil.rmtree(farm, ignore_errors=True)
    assert result["status"] == "fail", result
    assert result["stage"] == "run", result
    assert "staged hashes" in result["note"], result


def _swap_before_communicate(swap):
    """Wrap the guest proc so ``swap(stage)`` runs first."""
    real_popen = subprocess.Popen

    def _wrapping(*args, **kwargs):
        proc = real_popen(*args, **kwargs)
        argv = args[0] if args else []
        if isinstance(argv, list) and "--exec" in argv:
            import shlex as _shlex

            parts = _shlex.split(argv[argv.index("--exec") + 1])
            swap(parts[2])
        return proc

    return _wrapping


def test_verify_bytes_rejects_inner_object_replacement():
    # A1M4-3: substituting the staged object after capture
    # must fail even though the host-capture digest is
    # unchanged: the fake guest hashes what it loads (like
    # the real one), and the loaded hash differs. The seal
    # alone cannot stop a same-UID attacker (they own the
    # file, so chmod re-arms writability); the gate must.
    image, _license = _synthetic_elf()
    evil = b"evil-object-bytes-padded...."

    def _substitute(stage):
        path = os.path.join(stage, "verify-target.o")
        os.chmod(path, 0o644)
        with open(path, "wb") as handle:
            handle.write(evil)
        os.chmod(path, 0o444)

    with _fake_guest_run() as (_root, entry, lock_path):
        runner = verify_module._probe_vng(
            entry, kernels_lock=lock_path
        )
        farm = runner["farm"]
        _FakeGuestProc.transcript = _SUCCESS_TRANSCRIPT
        real_popen = subprocess.Popen
        subprocess.Popen = _swap_before_communicate(_substitute)
        try:
            lane = resolve_lane("v9.99", "tcg", lock_path)
            result = verify_bytes(
                image, lane, runner,
                object_path="synthetic.bpf.o",
                keep_evidence=True,
            )
        finally:
            subprocess.Popen = real_popen
            shutil.rmtree(farm, ignore_errors=True)
    assert result["status"] == "fail", result
    assert result["stage"] == "run", result
    assert "verify-target.o" in result["note"], result


def test_verify_bytes_rejects_inner_change_and_restore():
    # A1M4-3: touching the staged object and restoring it
    # before the guest reads still fails: the monitor and the
    # snapshots observe the touch even though the printed
    # hashes match the capture.
    image, _license = _synthetic_elf()

    def _touch_and_restore(stage):
        path = os.path.join(stage, "verify-target.o")
        with open(path, "rb") as handle:
            original = handle.read()
        os.chmod(path, 0o644)
        with open(path, "wb") as handle:
            handle.write(b"evil-object-bytes-padded....")
        with open(path, "wb") as handle:
            handle.write(original)
        os.chmod(path, 0o444)

    with _fake_guest_run() as (_root, entry, lock_path):
        runner = verify_module._probe_vng(
            entry, kernels_lock=lock_path
        )
        farm = runner["farm"]
        _FakeGuestProc.transcript = _SUCCESS_TRANSCRIPT
        real_popen = subprocess.Popen
        subprocess.Popen = _swap_before_communicate(
            _touch_and_restore
        )
        try:
            lane = resolve_lane("v9.99", "tcg", lock_path)
            result = verify_bytes(
                image, lane, runner,
                object_path="synthetic.bpf.o",
                keep_evidence=True,
            )
        finally:
            subprocess.Popen = real_popen
            shutil.rmtree(farm, ignore_errors=True)
    assert result["status"] == "fail", result
    assert result["stage"] == "run", result


def _recorded_stage_dir():
    # Resolve the inner stage through the monitor seam and
    # record it for a later substitution; returns the
    # (wrapper, record, original) triple for installation.
    recorded = []
    real_watch = verify_module.sealed_fs.NameWatch

    def _recording_watch(directory):
        if not recorded:
            if directory.startswith("/proc/self/fd/"):
                recorded.append(os.readlink(directory))
            else:
                recorded.append(directory)
        return real_watch(directory)

    return _recording_watch, recorded, real_watch


def _substitute_stage_with_foreign(stage):
    relocated = stage + ".relocated"
    os.rename(stage, relocated)
    os.mkdir(stage)
    foreign = os.path.join(stage, "foreign")
    with open(foreign, "wb") as handle:
        handle.write(b"foreign-bytes")
    return relocated, foreign


def _run_with_poisoned_prefix(image, prefix_cls, poison_lane, expect):
    # Drive verify_bytes with a lane argv prefix that swaps
    # the staged directory for foreign content when first
    # iterated after staging armed (runner preparation),
    # then fails preparation per ``poison_lane``. Earlier
    # iterations (lane validation) pass through untouched.
    # Returns (recorded stage, error note); the caller
    # asserts survival and cleans up.
    _recording, recorded, real_watch = _recorded_stage_dir()
    substituted = []
    after_swap = []
    note = []

    class _Prefix(prefix_cls):
        def __iter__(self):
            if recorded and not substituted:
                substituted.append(True)
                _substitute_stage_with_foreign(recorded[0])
                if after_swap:
                    raise after_swap[0]()
            return list.__iter__(self)

    verify_module.sealed_fs.NameWatch = _recording
    try:
        with _fake_guest_run() as (_root, entry, lock_path):
            runner = verify_module._probe_vng(
                entry, kernels_lock=lock_path
            )
            farm = runner["farm"]
            try:
                lane = resolve_lane("v9.99", "tcg", lock_path)
                lane["vng_argv_prefix"] = _Prefix(
                    lane["vng_argv_prefix"]
                )
                poison_lane(lane, _Prefix, after_swap)
                try:
                    verify_bytes(
                        image, lane, runner,
                        object_path="synthetic.bpf.o",
                        keep_evidence=False,
                    )
                except expect as exc:
                    note.append(str(exc))
                else:
                    raise AssertionError(
                        "preparation failure was not raised"
                    )
            finally:
                shutil.rmtree(farm, ignore_errors=True)
    finally:
        verify_module.sealed_fs.NameWatch = real_watch
    assert recorded, "watch installation seam never fired"
    assert substituted, "substitution seam never fired"
    return recorded[0], note[0] if note else ""


def _clear_substituted_stage(stage):
    shutil.rmtree(stage, ignore_errors=True)
    shutil.rmtree(stage + ".relocated", ignore_errors=True)


def test_preparation_base_failure_refuses_substituted_stage():
    # A1M6-3: the preparation BaseException arm tears down
    # through the pinned identity: a stage substituted
    # before the failure is refused (foreign content
    # survives) instead of deleted.
    image, _license = _synthetic_elf()

    def _poison(lane, cls, after_swap):
        after_swap.append(
            lambda: KeyError("injected preparation failure")
        )

    stage, _note = _run_with_poisoned_prefix(
        image, list, _poison, KeyError
    )
    try:
        with open(os.path.join(stage, "foreign"), "rb") as handle:
            assert handle.read() == b"foreign-bytes"
    finally:
        _clear_substituted_stage(stage)


def test_preparation_interrupt_refuses_substituted_stage():
    # A1M6-3: the preparation VerifyInterrupted arm tears
    # down through the pinned identity with its cleanup
    # report: a substituted stage is refused and the
    # refusal stays visible on the raised error.
    image, _license = _synthetic_elf()

    def _poison(lane, cls, after_swap):
        after_swap.append(
            lambda: verify_module.VerifyInterrupted(
                "injected preparation interruption"
            )
        )

    stage, note = _run_with_poisoned_prefix(
        image, list, _poison, verify_module.VerifyInterrupted
    )
    try:
        assert "staging cleanup failed" in note, note
        with open(os.path.join(stage, "foreign"), "rb") as handle:
            assert handle.read() == b"foreign-bytes"
    finally:
        _clear_substituted_stage(stage)


def test_teardown_owned_pair_refuses_substituted_stage():
    # A1M5-3: centralized pre-result teardown removes a
    # sealed stage through its pinned identity: a
    # substitute is refused (foreign content survives
    # with an error recorded) instead of silently
    # deleted.
    stage = tempfile.mkdtemp(prefix="mojobpf-verify-teardown-")
    with open(os.path.join(stage, "verify-target.o"), "wb") as handle:
        handle.write(b"captured-bytes")
    pinned = os.stat(stage, follow_symlinks=False)
    pin = (pinned.st_dev, pinned.st_ino)
    relocated = stage + ".relocated"
    os.rename(stage, relocated)
    os.mkdir(stage)
    foreign = os.path.join(stage, "foreign")
    with open(foreign, "wb") as handle:
        handle.write(b"foreign-bytes")
    try:
        errors = []
        verify_module._teardown_owned_pair(stage, pin, None, errors)
        assert errors, "substitute removal was not refused"
        with open(foreign, "rb") as handle:
            assert handle.read() == b"foreign-bytes"
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        shutil.rmtree(relocated, ignore_errors=True)


def test_discard_owned_refuses_absent_stage_as_clean():
    # A1M5-2: a pinned stage renamed away before cleanup
    # survives elsewhere; pathname absence alone must not
    # establish CLEAN. The cleanup records the vanished
    # stage instead of reporting it removed.
    stage = tempfile.mkdtemp(prefix="mojobpf-verify-absent-")
    with open(os.path.join(stage, "verify-target.o"), "wb") as handle:
        handle.write(b"captured-bytes")
    pinned = os.stat(stage, follow_symlinks=False)
    pin = (pinned.st_dev, pinned.st_ino)
    relocated = stage + ".relocated"
    os.rename(stage, relocated)
    try:
        result = {}
        verify_module._discard_owned(
            result, stage, None, False, stage_pin=pin,
        )
        cleanup = result["cleanup"]
        assert cleanup["staging_removed"] is False, cleanup
        assert cleanup["error"] is not None, cleanup
        assert stage in (cleanup["error"] or ""), cleanup
    finally:
        shutil.rmtree(stage, ignore_errors=True)
        shutil.rmtree(relocated, ignore_errors=True)


def test_discard_owned_repeat_discard_stays_clean():
    # A1M5-2 guard: a proved removal stays CLEAN when
    # discarded again (interruption during cleanup safely
    # discards twice); only a never-proved absence errors.
    stage = tempfile.mkdtemp(prefix="mojobpf-verify-rediscard-")
    with open(os.path.join(stage, "verify-target.o"), "wb") as handle:
        handle.write(b"captured-bytes")
    pinned = os.stat(stage, follow_symlinks=False)
    pin = (pinned.st_dev, pinned.st_ino)
    result = {}
    verify_module._discard_owned(
        result, stage, None, False, stage_pin=pin,
    )
    assert result["cleanup"]["error"] is None, result
    assert not os.path.lexists(stage)
    again = {}
    verify_module._discard_owned(
        again, stage, None, False, stage_pin=pin,
    )
    assert again["cleanup"]["error"] is None, again
    assert again["cleanup"]["staging_removed"] is True, again


def test_verify_bytes_refuses_postinstall_inner_substitution():
    # A1M6-1: a byte-identical replacement inserted after
    # installation returns but before the baseline is
    # adopted must not become the expected identity: the
    # baseline comes from the installer-held inode, never
    # a later pathname read.
    image, _license = _synthetic_elf()
    real_install = verify_module.sealed_fs.install_sealed
    swapped = []

    def _swapping_install(dirfd, name, data, seal):
        out = real_install(dirfd, name, data, seal)
        if not swapped and name == "verify-target.o":
            swapped.append(True)
            fd = os.open(
                name, os.O_RDONLY, dir_fd=dirfd,
            )
            try:
                chunks = []
                while True:
                    block = os.read(fd, 65536)
                    if not block:
                        break
                    chunks.append(block)
            finally:
                os.close(fd)
            sub = name + ".substitute"
            wfd = os.open(
                sub, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o644, dir_fd=dirfd,
            )
            try:
                os.write(wfd, b"".join(chunks))
            finally:
                os.close(wfd)
            os.rename(sub, name, src_dir_fd=dirfd, dst_dir_fd=dirfd)
        return out

    verify_module.sealed_fs.install_sealed = _swapping_install
    try:
        with _fake_guest_run() as (_root, entry, lock_path):
            runner = verify_module._probe_vng(
                entry, kernels_lock=lock_path
            )
            farm = runner["farm"]
            try:
                lane = resolve_lane("v9.99", "tcg", lock_path)
                try:
                    verify_bytes(
                        image, lane, runner,
                        object_path="synthetic.bpf.o",
                        keep_evidence=True,
                    )
                except AssertionError:
                    pass
                else:
                    raise AssertionError(
                        "post-install substitution was not refused"
                    )
            finally:
                shutil.rmtree(farm, ignore_errors=True)
    finally:
        verify_module.sealed_fs.install_sealed = real_install
    assert swapped, "install seam never fired"


def test_verify_bytes_refuses_inwindow_inner_mapping():
    # A1M7-1: a chmod+mmap+restore between the inner
    # publication and the installer's snapshot refuses at
    # install time, so the blessed inner inode can hold no
    # retained writable mapping.
    import errno as _errno
    import mmap as _mmap

    image, _license = _synthetic_elf()
    real_verify = verify_module.sealed_fs._verify_install
    held = []
    fired = []

    def _attacking_verify(dirfd, name, tmpfd, data):
        if not fired and name == "verify-target.o":
            fired.append(True)
            fd = os.open(
                name, os.O_RDONLY, dir_fd=dirfd,
            )
            try:
                before = os.fstat(fd)
            finally:
                os.close(fd)
            os.chmod(name, 0o644, dir_fd=dirfd)
            try:
                wfd = os.open(
                    name, os.O_RDWR | os.O_NONBLOCK,
                    dir_fd=dirfd,
                )
            except OSError as exc:
                if exc.errno != _errno.EWOULDBLOCK:
                    raise
                os.chmod(name, 0o444, dir_fd=dirfd)
                return real_verify(dirfd, name, tmpfd, data)
            try:
                mapping = _mmap.mmap(
                    wfd, before.st_size,
                    access=_mmap.ACCESS_WRITE,
                )
            except BaseException:
                os.close(wfd)
                raise
            mapping[0:8] = b"ATTACK!!"
            mapping[0:8] = bytes(data[0:8])
            os.fchmod(wfd, 0o444)
            os.utime(
                wfd,
                ns=(before.st_atime_ns, before.st_mtime_ns),
            )
            os.close(wfd)
            held.append(mapping)
        return real_verify(dirfd, name, tmpfd, data)

    verify_module.sealed_fs._verify_install = _attacking_verify
    try:
        with _fake_guest_run() as (_root, entry, lock_path):
            runner = verify_module._probe_vng(
                entry, kernels_lock=lock_path
            )
            farm = runner["farm"]
            try:
                lane = resolve_lane("v9.99", "tcg", lock_path)
                try:
                    verify_bytes(
                        image, lane, runner,
                        object_path="synthetic.bpf.o",
                        keep_evidence=True,
                    )
                except AssertionError:
                    pass
                else:
                    raise AssertionError(
                        "in-window mapping was not refused"
                    )
            finally:
                shutil.rmtree(farm, ignore_errors=True)
    finally:
        verify_module.sealed_fs._verify_install = real_verify
    assert fired, "verify seam never fired"
    for mapping in held:
        mapping.close()


def test_verify_bytes_fails_postrun_inner_alias_mapping():
    # A1M8-1: an acquire-flip-restore through an alias
    # after the guest ran fails the run at the inner
    # integrity gate: the transcript matches and no
    # handed-name event fired, but the metadata no
    # longer matches the installer baseline.
    import mmap as _mmap

    image, _license = _synthetic_elf()
    real_violation = verify_module._inner_stage_violation
    held = []

    def _attacking_violation(
        output, stage, pin, snaps, watch, expected
    ):
        if not held:
            name = verify_module.STAGED_OBJECT_NAME
            path = os.path.join(stage, name)
            alias = os.path.join(stage, "alias-0")
            before = os.stat(path)
            with open(path, "rb") as handle:
                original = handle.read()
            os.link(path, alias)
            os.chmod(alias, 0o644)
            wfd = os.open(alias, os.O_RDWR)
            try:
                mapping = _mmap.mmap(
                    wfd, before.st_size,
                    access=_mmap.ACCESS_WRITE,
                )
            except BaseException:
                os.close(wfd)
                raise
            mapping[0:8] = b"ATTACK!!"
            mapping[:] = original
            os.fchmod(wfd, before.st_mode & 0o777)
            os.utime(
                wfd,
                ns=(before.st_atime_ns, before.st_mtime_ns),
            )
            os.close(wfd)
            os.unlink(alias)
            held.append(mapping)
        return real_violation(
            output, stage, pin, snaps, watch, expected
        )

    verify_module._inner_stage_violation = _attacking_violation
    try:
        with _fake_guest_run() as (_root, entry, lock_path):
            runner = verify_module._probe_vng(
                entry, kernels_lock=lock_path
            )
            farm = runner["farm"]
            try:
                lane = resolve_lane("v9.99", "tcg", lock_path)
                result = verify_bytes(
                    image, lane, runner,
                    object_path="synthetic.bpf.o",
                    keep_evidence=True,
                )
            except BaseException:
                shutil.rmtree(farm, ignore_errors=True)
                raise
            try:
                assert result["status"] == "fail", result
                assert "touched" in result["note"], result
            finally:
                shutil.rmtree(
                    result["stage_path"], ignore_errors=True
                )
                shutil.rmtree(farm, ignore_errors=True)
    finally:
        verify_module._inner_stage_violation = real_violation
    assert held, "violation seam never fired"
    held[0].close()


def test_verify_bytes_refuses_prearm_inner_substitution():
    # A1M5-1: a substitution after install verification but
    # before the monitor arms predates all observation; the
    # staging must re-verify the sealed inode and its bytes
    # under the monitor and refuse, so the substitute can
    # never become the snapshot baseline. Byte-identical
    # backing defeats a byte comparison, so the refusal is
    # on identity.
    image, _license = _synthetic_elf()
    real_watch = verify_module.sealed_fs.NameWatch
    swapped = []
    constructions = []

    def _swapping_watch(directory):
        # The two inner installs construct publication
        # gates first (A1M7-1); the substitution targets
        # the arm, which is the third construction here.
        constructions.append(directory)
        if len(constructions) == 3:
            swapped.append(True)
            if directory.startswith("/proc/self/fd/"):
                resolved = os.readlink(directory)
            else:
                resolved = directory
            target = os.path.join(resolved, "verify-target.o")
            with open(target, "rb") as handle:
                original = handle.read()
            substitute = target + ".substitute"
            with open(substitute, "wb") as handle:
                handle.write(original)
            os.rename(substitute, target)
        return real_watch(directory)

    verify_module.sealed_fs.NameWatch = _swapping_watch
    try:
        with _fake_guest_run() as (_root, entry, lock_path):
            runner = verify_module._probe_vng(
                entry, kernels_lock=lock_path
            )
            farm = runner["farm"]
            try:
                lane = resolve_lane("v9.99", "tcg", lock_path)
                try:
                    verify_bytes(
                        image, lane, runner,
                        object_path="synthetic.bpf.o",
                        keep_evidence=True,
                    )
                except AssertionError:
                    pass
                else:
                    raise AssertionError(
                        "pre-arm substitution was not refused"
                    )
            finally:
                shutil.rmtree(farm, ignore_errors=True)
    finally:
        verify_module.sealed_fs.NameWatch = real_watch
    assert swapped, "watch installation seam never fired"


def test_verify_bytes_gate_snapshot_failure_fails_closed():
    # A1M5-3: an unreadable inner stage at gate time fails
    # closed (fail/run/environment) through the normal
    # gate-failure path with its cleanup, never as a raw
    # escaping error that leaks the stage.
    image, _license = _synthetic_elf()
    real_snapshot = verify_module.sealed_fs.snapshot_at
    armed = []

    def _failing_snapshot(dirfd, name):
        if armed:
            raise OSError("injected gate unreadable")
        return real_snapshot(dirfd, name)

    def _arm(_stage):
        armed.append(True)

    verify_module.sealed_fs.snapshot_at = _failing_snapshot
    try:
        with _fake_guest_run() as (_root, entry, lock_path):
            runner = verify_module._probe_vng(
                entry, kernels_lock=lock_path
            )
            farm = runner["farm"]
            _FakeGuestProc.transcript = _SUCCESS_TRANSCRIPT
            real_popen = subprocess.Popen
            subprocess.Popen = _swap_before_communicate(_arm)
            try:
                lane = resolve_lane("v9.99", "tcg", lock_path)
                try:
                    result = verify_bytes(
                        image, lane, runner,
                        object_path="synthetic.bpf.o",
                        keep_evidence=False,
                    )
                except OSError:
                    result = None
            finally:
                subprocess.Popen = real_popen
                shutil.rmtree(farm, ignore_errors=True)
    finally:
        verify_module.sealed_fs.snapshot_at = real_snapshot
    assert armed, "guest spawn seam never fired"
    assert result is not None, "gate snapshot error escaped raw"
    assert result["status"] == "fail", result
    assert result["stage"] == "run", result
    assert result["classification"] == "environment", result
    assert "unreadable" in result["note"], result
    assert not os.path.lexists(result["stage_path"]), (
        "failed gate leaked its stage",
    )


def test_verify_bytes_seals_inner_stage():
    # A1M4-3: the staged object and script are read-only from
    # publication (sealed backing, never a writable window).
    image, _license = _synthetic_elf()
    result = _result_of_verify_bytes(image)
    try:
        for name in ("verify-target.o", "guest_verify.sh"):
            path = os.path.join(result["stage_path"], name)
            assert os.stat(path).st_mode & 0o777 == 0o444, (
                name, oct(os.stat(path).st_mode & 0o777)
            )
            try:
                opened = os.open(path, os.O_RDWR)
            except OSError:
                pass
            else:
                os.close(opened)
                raise AssertionError(
                    "staged %r is writable" % name
                )
    finally:
        shutil.rmtree(result["stage_path"], ignore_errors=True)


def test_guest_script_hashes_staged_inputs_around_load():
    # A1M4-3: the guest hashes the staged object and its own
    # script early, immediately before the load, and after the
    # load, so a substitution between capture and load cannot
    # hide from the host comparison.
    script = _rendered_script()
    early = script.index("=== staged hashes ===")
    assert "sha256sum verify-target.o" in script[:early + 200]
    assert "sha256sum guest_verify.sh" in script[:early + 200]
    load_at = script.index('$LOAD_RUN prog load "$OBJ"')
    window = script[max(0, load_at - 400):load_at]
    assert "sha256sum" in window, window
    end_at = script.index("=== END load-log ===")
    after = script[end_at:end_at + 400]
    assert "sha256sum" in after, after
    # A1M5-4: every placement hashes the fixed relative
    # names (the script runs inside $STAGE), never absolute
    # paths that whitespace in TMPDIR would make unparsable.
    assert 'sha256sum "$' not in script, script
    assert (
        script.count("sha256sum verify-target.o guest_verify.sh")
        == 2
    ), script


_EVIL_PATH_PIECES = (
    "with space",
    "uni-\u00e9-\u4e2d",
    "single'quote",
    'double"quote',
    "dollar$var",
    "back`tick",
    "semi;colon",
    "pipe|name",
    "amp&ersand",
    "star*glob",
    "paren(a)b",
    "new\nline",
)


def _run_exec_probe(cmd):
    """Run an --exec string with a stub bash; return recorded argv."""
    root = tempfile.mkdtemp(prefix="verify-quote-")
    marker = os.path.join(root, "PWNED")
    stubdir = os.path.join(root, "bin")
    os.makedirs(stubdir)
    argv_file = os.path.join(root, "argv.json")
    with open(os.path.join(stubdir, "bash"), "w", encoding="utf-8") as handle:
        handle.write(
            "#!%s\nimport json\nimport sys\n"
            "open(%r, \"w\").write(json.dumps(sys.argv[1:]))\n"
            % (sys.executable, argv_file)
        )
    os.chmod(os.path.join(stubdir, "bash"), 0o755)
    env = dict(os.environ)
    env["PATH"] = stubdir + os.pathsep + env.get("PATH", "")
    proc = subprocess.run(
        ["/bin/bash", "-c", cmd],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, (proc.returncode, proc.stderr)
    assert not os.path.exists(marker), "stage path evaluated by the shell"
    with open(argv_file, encoding="utf-8") as handle:
        argv = json.load(handle)
    shutil.rmtree(root, ignore_errors=True)
    return argv


def test_guest_exec_command_quotes_hostile_paths():
    """F-032: spaces, non-ASCII, quotes, $/backticks arrive
    literally at the guest script; nothing evaluates."""
    for piece in _EVIL_PATH_PIECES:
        stage = "/tmp/stage-%s/x" % piece
        script = "/tmp/stage-%s/guest_verify.sh" % piece
        cmd = guest_exec_command(script, stage)
        assert cmd.startswith("bash "), cmd
        argv = _run_exec_probe(cmd)
        assert argv == [script, stage], (piece, argv)
    owned = tempfile.mkdtemp(prefix="verify-quote-owned-")
    try:
        fixed = os.path.join(owned, "PWNED")
        evil = os.path.join(owned, "x$(touch %s)" % fixed, "y`id`")
        argv = _run_exec_probe(guest_exec_command(evil + ".sh", evil))
        assert argv == [evil + ".sh", evil], argv
        assert not os.path.exists(fixed), "substitution evaluated"
    finally:
        shutil.rmtree(owned, ignore_errors=True)


def test_hostile_tmpdir_end_to_end_without_evaluation():
    """F-032 end to end: an owned TMPDIR with spaces, non-ASCII,
    quotes, dollar signs and backticks stages without evaluation."""
    parent = tempfile.mkdtemp(prefix="verify-tmpdir-")
    evil = os.path.join(
        parent, "sp ace-\u00e9-'\"-$HOME-`id`-;|&*",
    )
    os.makedirs(evil)
    with _saved_tmpdir(evil):
        result = _run_with_fake_guest(0, keep_evidence=True)
    try:
        stage = result["stage_path"]
        assert stage.startswith(evil + os.sep), stage
        assert os.path.isdir(stage), stage
        assert stat.S_IMODE(os.stat(stage).st_mode) == 0o700
        argv = result["runner"]["argv"]
        assert argv[1:4] == ["--run", "v9.99", "--disable-kvm"], argv
        exec_index = argv.index("--exec")
        assert _run_exec_probe(argv[exec_index + 1]) == [
            os.path.join(stage, "guest_verify.sh"),
            stage,
        ]
        assert result["status"] == "pass", result
    finally:
        shutil.rmtree(result["stage_path"], ignore_errors=True)
        shutil.rmtree(result["runner"]["farm"], ignore_errors=True)
        shutil.rmtree(parent, ignore_errors=True)


def test_effective_release_validated_after_env_fallback():
    """F-020: the ambient release gets the same token check as an
    explicit one; selection precedes validation."""
    for bad in (
        "v6.12\n",
        'v6.12"; evil',
        "v 6",
        "v6.12`id`",
        "v6.12$HOME",
    ):
        with _saved_env(verify_module.RELEASE_ENV_VAR, bad):
            try:
                VerifyRequest(object_path="x.o")
            except VerifyError as exc:
                assert "release" in str(exc), exc
            else:
                raise AssertionError("env release %r accepted" % (bad,))
    with _saved_env(verify_module.RELEASE_ENV_VAR, "v6.6"):
        assert VerifyRequest(object_path="x.o").release == "v6.6"
    with _saved_env(verify_module.RELEASE_ENV_VAR, None):
        request = VerifyRequest(object_path="x.o")
        assert request.release == verify_module.DEFAULT_RELEASE


def test_request_accepts_keep_evidence():
    assert VerifyRequest(object_path="x.o").keep_evidence is False
    request = VerifyRequest(object_path="x.o", keep_evidence=True)
    assert request.keep_evidence is True
    try:
        VerifyRequest(object_path="x.o", keep_evidence="yes")
    except VerifyError:
        pass
    else:
        raise AssertionError("non-bool keep_evidence must raise")


def test_resolve_lane_against_checkout_lock():
    """F-035 host half: the effective release/accelerator must
    match a locked lane."""
    lane = resolve_lane("v6.12", "tcg", LOCK_PATH)
    assert lane["id"] == "v6.12-tcg", lane
    assert lane["kernel_release"] == "6.12.0-061200-generic", lane
    assert lane["vng_argv_prefix"] == [
        "vng", "--run", "v6.12", "--disable-kvm",
    ], lane
    lane = resolve_lane("v6.6", "tcg")
    assert lane["id"] == "v6.6-tcg", lane
    try:
        resolve_lane("v9.99", "tcg", LOCK_PATH)
    except VerifyError as exc:
        assert "matches no lane" in str(exc), exc
        assert "v6.12/tcg" in str(exc), exc
        assert "v6.6/tcg" in str(exc), exc
    else:
        raise AssertionError("unlisted release resolved")
    try:
        resolve_lane("v6.12", "kvm", LOCK_PATH)
    except VerifyError as exc:
        assert "matches no lane" in str(exc), exc
    else:
        raise AssertionError("unlisted accelerator resolved")
    try:
        resolve_lane("v6.12\n", "tcg", LOCK_PATH)
    except VerifyError as exc:
        assert "release" in str(exc), exc
    else:
        raise AssertionError("evil release resolved")
    try:
        resolve_lane("v6.12", "tcg", "/nonexistent/kernels.lock.json")
    except VerifyError as exc:
        assert "kernels lock not found" in str(exc), exc
    else:
        raise AssertionError("missing lock resolved")


def test_resolve_lane_rejects_laneless_and_malformed_locks():
    root = tempfile.mkdtemp(prefix="verify-lanes-")
    try:
        laneless = os.path.join(root, "laneless.json")
        with open(laneless, "w", encoding="utf-8") as handle:
            json.dump({"schema_version": 1, "runner": {}}, handle)
        try:
            resolve_lane("v6.12", "tcg", laneless)
        except VerifyError as exc:
            assert "carries no lanes" in str(exc), exc
        else:
            raise AssertionError("laneless lock resolved")
        malformed = os.path.join(root, "malformed.json")
        with open(malformed, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "schema_version": 1,
                    "lanes": [{"id": "x-tcg", "release": "x"}],
                },
                handle,
            )
        try:
            resolve_lane("x", "tcg", malformed)
        except VerifyError as exc:
            assert "lacks" in str(exc), exc
        else:
            raise AssertionError("malformed lane resolved")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_run_verification_rejects_unlisted_release_before_spawn():
    """An unlisted release fails lane resolution before any spawn."""
    holding = tempfile.mkdtemp(prefix="verify-nolane-")
    staged = os.path.join(holding, "probe.bpf.o")
    with open(staged, "wb") as handle:
        handle.write(b"not-an-elf-object")
    spawns = []
    real_popen = subprocess.Popen

    def _spy(*args, **kwargs):
        spawns.append(args[0] if args else None)
        return real_popen(*args, **kwargs)

    subprocess.Popen = _spy
    try:
        request = VerifyRequest(
            object_path=staged,
            release="v9.99",
            timeout=60,
            kernels_lock=LOCK_PATH,
        )
        try:
            run_verification(request)
        except VerifyError as exc:
            assert "matches no lane" in str(exc), exc
        else:
            raise AssertionError("unlisted release verified")
    finally:
        subprocess.Popen = real_popen
        shutil.rmtree(holding, ignore_errors=True)
    assert spawns == [], spawns


def test_run_verification_reports_lane_and_uses_pinned_argv():
    result = _run_with_fake_guest(0)
    try:
        assert result["schema"] == 2, result.get("schema")
        lane = result["lane"]
        assert lane["id"] == "v9.99-tcg", lane
        assert lane["release"] == "v9.99", lane
        assert lane["accelerator"] == "tcg", lane
        assert lane["kernel_release"] == "9.99.0-fixture", lane
        argv = result["runner"]["argv"]
        assert argv[1:4] == ["--run", "v9.99", "--disable-kvm"], argv
        assert argv[4] == "--exec", argv
        assert argv[5].startswith("bash "), argv
        assert result["guest"]["kernel_expected"] == "9.99.0-fixture"
        assert result["guest"]["kernel"] == "6.12.0-061200-generic"
        summary = verify_module.format_summary(result)
        assert "v9.99-tcg" in summary, summary
        assert "staging:" in summary, summary
    finally:
        shutil.rmtree(result["stage_path"], ignore_errors=True)


def test_staging_keeps_restrictive_permissions():
    """F-033: the owned stage keeps 0700/0444 even under a
    permissive umask (A1M4-1 seals staged files read-only)."""
    previous_umask = os.umask(0o022)
    try:
        result = _run_with_fake_guest(0, keep_evidence=True)
    finally:
        os.umask(previous_umask)
    try:
        stage = result["stage_path"]
        mode = stat.S_IMODE(os.stat(stage).st_mode)
        assert mode == 0o700, oct(mode)
        staged_object = os.path.join(stage, "verify-target.o")
        mode = stat.S_IMODE(os.stat(staged_object).st_mode)
        assert mode == 0o444, oct(mode)
        script = os.path.join(stage, "guest_verify.sh")
        mode = stat.S_IMODE(os.stat(script).st_mode)
        assert mode == 0o444, oct(mode)
    finally:
        shutil.rmtree(result["stage_path"], ignore_errors=True)
        shutil.rmtree(result["runner"]["farm"], ignore_errors=True)


def test_default_cleanup_removes_stage_on_success():
    """F-033: default retention removes owned staging on success
    and leaves no residue."""
    scratch = tempfile.mkdtemp(prefix="verify-clean-")
    with _saved_tmpdir(scratch):
        result = _run_with_fake_guest(0)
    try:
        assert result["status"] == "pass", result
        assert result["cleanup"] == {
            "staging_removed": True,
            "kept": False,
            "error": None,
        }, result["cleanup"]
        assert not os.path.exists(result["stage_path"])
        assert not os.path.exists(result["runner"]["farm"])
        assert os.listdir(scratch) == [], os.listdir(scratch)
    finally:
        shutil.rmtree(result["stage_path"], ignore_errors=True)
        shutil.rmtree(result["runner"]["farm"], ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def test_default_cleanup_removes_stage_on_failure():
    """F-033: default retention removes owned staging on a failed
    load too."""
    result = _run_with_fake_guest(
        11, _load_failed_transcript(LOADER_NOT_EBPF)
    )
    try:
        assert result["status"] == "load-failed", result
        assert result["classification"] == "loader", result
        assert result["cleanup"]["staging_removed"] is True, (
            result["cleanup"]
        )
        assert not os.path.exists(result["stage_path"])
        assert not os.path.exists(result["runner"]["farm"])
    finally:
        shutil.rmtree(result["stage_path"], ignore_errors=True)
        shutil.rmtree(result["runner"]["farm"], ignore_errors=True)


def test_keep_evidence_retains_stage_and_farm():
    """F-033: explicit --keep-evidence retention keeps the owned
    stage and PATH farm."""
    result = _run_with_fake_guest(0, keep_evidence=True)
    try:
        assert result["cleanup"] == {
            "staging_removed": False,
            "kept": True,
            "error": None,
        }, result["cleanup"]
        assert os.path.isdir(result["stage_path"])
        assert os.path.isdir(result["runner"]["farm"])
    finally:
        shutil.rmtree(result["stage_path"], ignore_errors=True)
        shutil.rmtree(result["runner"]["farm"], ignore_errors=True)


def test_failed_cleanup_stays_visible():
    """F-033: a failed cleanup is reported, never silent."""
    real_pinned = verify_module._remove_pinned_tree

    def _failing_pinned(path, pin):
        # Post-staging cleanup goes through the fd-bound
        # pinned removal (A1M4-2); fail the stage there.
        if os.path.basename(path).startswith("mojobpf-verify-"):
            return "%s: EACCES: keep-out for the test" % path
        return real_pinned(path, pin)

    verify_module._remove_pinned_tree = _failing_pinned
    try:
        result = _run_with_fake_guest(0)
    finally:
        verify_module._remove_pinned_tree = real_pinned
    try:
        assert result["status"] == "pass", result
        cleanup = result["cleanup"]
        assert cleanup["staging_removed"] is False, cleanup
        assert cleanup["kept"] is False, cleanup
        assert "keep-out" in (cleanup["error"] or ""), cleanup
        assert os.path.isdir(result["stage_path"])
        summary = verify_module.format_summary(result)
        assert "cleanup failed" in summary, summary
    finally:
        shutil.rmtree(result["stage_path"], ignore_errors=True)
        shutil.rmtree(result["runner"]["farm"], ignore_errors=True)


class _InterruptingGuestProc(_FakeGuestProc):
    """A guest child that SIGTERMs the test process mid-run."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # The runner is alive until the signal arrives (poll()
        # None), so interruption exercises the group-kill branch;
        # the pid sits above pid_max (whose ceiling is 2**22) yet
        # inside C int range, so the group kill can never collide
        # with a real process group.
        self.pid = 1000000007
        self.returncode = None

    def communicate(self, timeout=None):
        os.kill(os.getpid(), signal.SIGTERM)
        return super().communicate(timeout=timeout)


def _run_until_sigterm(entry, lock_path, keep_evidence):
    """Run one verification whose guest child SIGTERMs the test."""
    holding = tempfile.mkdtemp(prefix="verify-intr-")
    staged = os.path.join(holding, "probe.bpf.o")
    with open(staged, "wb") as handle:
        handle.write(b"not-an-elf-object")
    real_popen = subprocess.Popen

    def _interrupting(*args, **kwargs):
        argv = args[0] if args else []
        if (
            isinstance(argv, list)
            and len(argv) > 2
            and argv[1] == "--run"
        ):
            return _InterruptingGuestProc(*args, **kwargs)
        return real_popen(*args, **kwargs)

    subprocess.Popen = _interrupting
    try:
        request = VerifyRequest(
            object_path=staged,
            release="v9.99",
            vng_path=entry,
            require_btf="no",
            timeout=60,
            kernels_lock=lock_path,
            keep_evidence=keep_evidence,
        )
        try:
            run_verification(request)
        except VerifyInterrupted as exc:
            assert "signal 15" in str(exc), exc
        else:
            raise AssertionError("SIGTERM during guest run ignored")
    finally:
        subprocess.Popen = real_popen
        shutil.rmtree(holding, ignore_errors=True)


def test_staging_failure_cleans_partial_stage():
    """F-033: a staging failure reports setup error and leaks
    nothing, including on KeyboardInterrupt."""
    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-stagefail-")
    real_mkdtemp = tempfile.mkdtemp
    with _fake_guest_run() as (_root, entry, lock_path):
        runner = verify_module._probe_vng(
            entry, kernels_lock=lock_path
        )
        farm = runner["farm"]
        lane = resolve_lane("v9.99", "tcg", lock_path)
        try:
            with _saved_tmpdir(scratch):
                tempfile.mkdtemp = _failing_mkdtemp_oserror
                try:
                    verify_bytes(image, lane, runner)
                except VerifyError as exc:
                    assert "cannot stage" in str(exc), exc
                else:
                    raise AssertionError("staging failure admitted")
                finally:
                    tempfile.mkdtemp = real_mkdtemp
                assert os.listdir(scratch) == [], os.listdir(scratch)
                real_chmod = os.chmod
                chmod_calls = []

                def _interrupting_chmod(path, mode, *args, **kwargs):
                    chmod_calls.append(path)
                    raise KeyboardInterrupt("test interrupt")

                os.chmod = _interrupting_chmod
                try:
                    verify_bytes(image, lane, runner)
                except KeyboardInterrupt:
                    pass
                else:
                    raise AssertionError("interrupt swallowed")
                finally:
                    os.chmod = real_chmod
                assert chmod_calls, "staging never reached chmod"
                assert os.listdir(scratch) == [], os.listdir(scratch)
        finally:
            shutil.rmtree(farm, ignore_errors=True)
            shutil.rmtree(scratch, ignore_errors=True)


def _failing_mkdtemp_oserror(*args, **kwargs):
    raise OSError("EACCES: staging denied for the test")


def test_interruption_removes_stage():
    """F-033: interruption removes owned staging by default."""
    scratch = tempfile.mkdtemp(prefix="verify-intr-")
    with _saved_tmpdir(scratch):
        with _fake_guest_run() as (_root, entry, lock_path):
            _run_until_sigterm(entry, lock_path, False)
    try:
        assert os.listdir(scratch) == [], os.listdir(scratch)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def test_interruption_keeps_evidence_when_asked():
    """F-033: interruption honors explicit evidence retention."""
    scratch = tempfile.mkdtemp(prefix="verify-intr-keep-")
    with _saved_tmpdir(scratch):
        with _fake_guest_run() as (_root, entry, lock_path):
            _run_until_sigterm(entry, lock_path, True)
    try:
        leftovers = sorted(os.listdir(scratch))
        assert len(leftovers) == 2, leftovers
        assert leftovers[0].startswith("mojobpf-farm-"), leftovers
        assert leftovers[1].startswith("mojobpf-verify-"), leftovers
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


_STAGING_SIG_BREAK_CHILD = """\
import errno
import os
import shutil
import signal
import sys
import tempfile
import threading

SIGNO = int(sys.argv[1])
sys.path.insert(0, sys.argv[2])
sys.path.insert(0, sys.argv[3])

import test_verify as T
from mojobpf import sealed_fs

real_verify_install = sealed_fs._verify_install
linked = threading.Event()
proceed = threading.Event()
published = {}


def blocking(dirfd, name, heldfd, data):
    if not published:
        assert signal.getsignal(signal.SIGIO) == signal.SIG_DFL
        published["dirfd"] = dirfd
        published["name"] = name
        linked.set()
        # Park: nobody sets proceed; the signal raises out
        # of the wait (the timeout is a hang backstop).
        if not proceed.wait(120):
            raise AssertionError("signal never arrived during staging")
    return real_verify_install(dirfd, name, heldfd, data)


def attacker():
    assert linked.wait(120), "install never reached the seam"
    path = "/proc/self/fd/%d/%s" % (
        published["dirfd"], published["name"],
    )
    alias = "/proc/self/fd/%d/alias-a1m10-1" % published["dirfd"]
    try:
        os.link(path, alias)
    except FileExistsError:
        pass
    # Reach the lease check (a 0444 open would EACCES first).
    os.chmod(alias, 0o644)
    try:
        wfd = os.open(alias, os.O_RDWR | os.O_NONBLOCK)
    except OSError as exc:
        assert exc.errno == errno.EWOULDBLOCK, exc
    else:
        os.close(wfd)
        raise AssertionError("writer open admitted during the lease")
    # EWOULDBLOCK proves the break was initiated: SIGIO is now
    # pending (blocked) on the lease-owning main thread.
    # Restore the pre-attack directory state (the P1
    # instrument): the queued notification survives, but
    # teardown's removal proof sees no extra link.
    os.chmod(alias, 0o444)
    os.unlink(alias)
    os.kill(os.getpid(), SIGNO)


def main():
    image, _license = T._synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-sigio-")
    sealed_fs._verify_install = blocking
    worker = threading.Thread(target=attacker, daemon=True)
    try:
        with T._fake_guest_run() as (_root, entry, lock_path):
            runner = T.verify_module._probe_vng(
                entry, kernels_lock=lock_path
            )
            farm = runner["farm"]
            lane = T.resolve_lane("v9.99", "tcg", lock_path)
            try:
                worker.start()
                with T._saved_tmpdir(scratch):
                    try:
                        T.verify_bytes(image, lane, runner)
                    except T.VerifyInterrupted as exc:
                        assert ("signal %d" % SIGNO) in str(exc), exc
                    else:
                        raise AssertionError(
                            "signal %d ignored" % SIGNO
                        )
                    assert os.listdir(scratch) == [], os.listdir(scratch)
            finally:
                shutil.rmtree(farm, ignore_errors=True)
    finally:
        sealed_fs._verify_install = real_verify_install
        shutil.rmtree(scratch, ignore_errors=True)
    print("INTERRUPTED-OK signo=%d" % SIGNO, flush=True)


main()
"""


def _run_sig_with_pending_break(signo):
    """A1M10-1: signal with a pending lease break interrupts cleanly."""
    scratch = tempfile.mkdtemp(prefix="verify-sigio-parent-")
    try:
        child = os.path.join(scratch, "child_sig_break.py")
        with open(child, "w") as handle:
            handle.write(_STAGING_SIG_BREAK_CHILD)
        unit_dir = os.path.dirname(os.path.abspath(__file__))
        src_dir = os.path.join(unit_dir, "..", "..", "src")
        proc = subprocess.run(
            [sys.executable, child, str(signo), unit_dir, src_dir],
            capture_output=True, text=True, timeout=180,
        )
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    marker = "INTERRUPTED-OK signo=%d" % signo
    assert proc.returncode == 0, (
        "signo=%d returncode=%r stderr=%s"
        % (signo, proc.returncode, proc.stderr[-2000:])
    )
    assert marker in proc.stdout, (
        "signo=%d stdout=%s stderr=%s"
        % (signo, proc.stdout[-1000:], proc.stderr[-2000:])
    )


def test_staging_sigterm_with_pending_lease_break_interrupts():
    # A1M10-1: SIGTERM while a lease break is pending reports
    # VerifyInterrupted (never dies on the break signal).
    _run_sig_with_pending_break(signal.SIGTERM)


def test_staging_sigint_with_pending_lease_break_interrupts():
    # A1M10-1: SIGINT while a lease break is pending reports
    # VerifyInterrupted (never dies on the break signal).
    _run_sig_with_pending_break(signal.SIGINT)


_CLI_VERSION_STUB = """\
#!{python}
import sys


def main(argv):
    print({version!r})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
"""


def _write_cli_bindir(parent):
    """Create fixture mojo/llc/bpftool/python3 version stubs."""
    bindir = tempfile.mkdtemp(prefix="cli-bin-", dir=parent)
    for name, version in (
        ("mojo", "Mojo 9.9.9 (fixture)"),
        ("llc", "llc fixture 9.9.9"),
        ("bpftool", "bpftool v0.0-fixture"),
        ("python3", "Python 9.9.9-fixture"),
    ):
        path = os.path.join(bindir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                _CLI_VERSION_STUB.format(
                    python=sys.executable, version=version
                )
            )
        os.chmod(path, 0o755)
    return bindir


def _write_cli_manifest(parent):
    """Create a minimal valid manifest project; return its path."""
    root = os.path.join(parent, "proj")
    os.makedirs(os.path.join(root, "src"))
    with open(
        os.path.join(root, "src", "main.mojo"), "w", encoding="utf-8"
    ) as handle:
        handle.write(
            "# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception\n"
        )
    manifest_path = os.path.join(root, "mojobpf.toml")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(
            "schema_version = 1\n"
            "\n"
            "[project]\n"
            'name = "cli-fixture"\n'
            "\n"
            "[target]\n"
            'profile = "linux-bpfel-v3"\n'
            "core = false\n"
            "\n"
            "[artifact]\n"
            'name = "fixture_obj"\n'
            'source_license = "Apache-2.0 WITH LLVM-exception"\n'
            'kernel_license = "Apache-2.0 WITH LLVM-exception"\n'
            "\n"
            "[[programs]]\n"
            'source = "src/main.mojo"\n'
            'entry = "xdp_entry"\n'
            'program_type = "xdp"\n'
            'section = "xdp"\n'
        )
    return manifest_path


def _write_cli_lockfile(parent, bindir, name, mismatched_tool=None):
    """Pin the fixture tools; optionally mismatch one tool."""
    import hashlib

    tools = {}
    for tool, argv0 in (
        ("mojo", "mojo"),
        ("llc", "llc"),
        ("bpftool", "bpftool"),
        ("python", "python3"),
    ):
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
        if tool == mismatched_tool:
            version, digest = "wrong version", "0" * 64
        tools[tool] = {"version": version, "sha256": digest}
    lock_path = os.path.join(parent, name)
    with open(lock_path, "w", encoding="utf-8") as handle:
        json.dump({"schema_version": 1, "tools": tools}, handle)
    return lock_path


def _run_cli(argv, path=None):
    """Run the CLI in-process with captured streams."""
    from mojobpf import cli as cli_module

    out, err = io.StringIO(), io.StringIO()
    saved_path = os.environ.get("PATH")
    try:
        if path is not None:
            os.environ["PATH"] = path
        with contextlib.redirect_stdout(out):
            with contextlib.redirect_stderr(err):
                try:
                    code = cli_module.main(argv)
                except SystemExit as exc:
                    code = exc.code
    finally:
        if saved_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = saved_path
    return code, out.getvalue(), err.getvalue()


def test_doctor_is_informational_discovery():
    """F-031: doctor reports discovery, always exits 0, and says
    it never qualifies pins."""
    parent = tempfile.mkdtemp(prefix="cli-doctor-")
    try:
        empty = tempfile.mkdtemp(prefix="empty-path-", dir=parent)
        code, out, _ = _run_cli(["doctor"], path=empty)
        assert code == 0, out
        assert "informational discovery only" in out, out
        code, out, _ = _run_cli(["doctor", "--json"], path=empty)
        assert code == 0, out
        document = json.loads(out)
        assert document["discovery_only"] is True, document
        code, out, _ = _run_cli(
            ["doctor", "--lockfile", os.path.join(parent, "missing.json")],
            path=empty,
        )
        assert code == 0, out
        assert "unreadable" in out, out
        assert "never here" in out, out
        bindir = _write_cli_bindir(parent)
        lock = _write_cli_lockfile(parent, bindir, "toolchains.lock.json")
        code, out, _ = _run_cli(
            ["doctor", "--lockfile", lock], path=bindir
        )
        assert code == 0, out
        assert "lockfile %s: matched" % lock in out, out
        assert "observed; qualification verdicts" in out, out
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def test_check_without_lockfile_reports_unvalidated():
    """F-031: check without --lockfile reports discovery and says
    the pins are not validated, on success and failure paths."""
    parent = tempfile.mkdtemp(prefix="cli-check-")
    try:
        manifest_path = _write_cli_manifest(parent)
        bindir = _write_cli_bindir(parent)
        code, out, err = _run_cli(
            ["check", "--manifest", manifest_path], path=bindir
        )
        assert code == 0, out + err
        assert "manifest OK" in out, out
        assert "MBPF105" in err, err
        assert "no lockfile supplied" in err, err
        empty = tempfile.mkdtemp(prefix="empty-path-", dir=parent)
        code, _out, err = _run_cli(
            ["check", "--manifest", manifest_path], path=empty
        )
        assert code == 3, err
        assert "MBPF105" in err, err
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def test_check_with_lockfile_qualifies():
    """F-031: check with --lockfile qualifies pins (exit 3 on
    mismatch), unlike informational doctor."""
    parent = tempfile.mkdtemp(prefix="cli-checklock-")
    try:
        manifest_path = _write_cli_manifest(parent)
        bindir = _write_cli_bindir(parent)
        lock = _write_cli_lockfile(parent, bindir, "toolchains.lock.json")
        code, _out, err = _run_cli(
            ["check", "--manifest", manifest_path, "--lockfile", lock],
            path=bindir,
        )
        assert code == 0, err
        assert "MBPF105" not in err, err
        bad = _write_cli_lockfile(
            parent, bindir, "bad.lock.json", mismatched_tool="mojo"
        )
        code, _out, err = _run_cli(
            ["check", "--manifest", manifest_path, "--lockfile", bad],
            path=bindir,
        )
        assert code == 3, err
        assert "MBPF102" in err, err
        code, out, _ = _run_cli(
            ["doctor", "--lockfile", bad], path=bindir
        )
        assert code == 0, out
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def test_verify_cli_usage_and_missing_input():
    """CLI contract: usage errors and missing input exit 2."""
    from mojobpf import cli as cli_module

    code, _out, err = _run_cli(["verify", "--object", "x.o"])
    assert code == 2, err
    assert "--kernel" in err and "required" in err, err
    code, _out, err = _run_cli(
        ["verify", "--kernel", "--object", "nope.o"]
    )
    assert code == cli_module.EXIT_USAGE, err
    assert "object not found" in err, err


def test_verify_cli_unavailable_runner_is_usage():
    """CLI contract (F-021): setup failures, including an
    unavailable runner, exit 2 with the cause on stderr."""
    from mojobpf import cli as cli_module

    parent = tempfile.mkdtemp(prefix="cli-verify-")
    try:
        staged = os.path.join(parent, "probe.bpf.o")
        with open(staged, "wb") as handle:
            handle.write(b"not-an-elf-object")
        code, _out, err = _run_cli(
            [
                "verify", "--kernel", "--object", staged,
                "--release", "v6.12",
                "--vng", os.path.join(parent, "no-such-vng"),
            ]
        )
        assert code == cli_module.EXIT_USAGE, err
        assert "admission refused" in err, err
        code, _out, err = _run_cli(
            [
                "verify", "--kernel", "--object", staged,
                "--kernels-lock", os.path.join(parent, "missing.json"),
            ]
        )
        assert code == cli_module.EXIT_USAGE, err
        assert "kernels lock not found" in err, err
        code, _out, err = _run_cli(
            [
                "verify", "--kernel", "--object", staged,
                "--release", "v9.99",
            ]
        )
        assert code == cli_module.EXIT_USAGE, err
        assert "matches no lane" in err, err
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def test_verify_cli_loader_verifier_environment_exits():
    """CLI contract: loader/verifier/environment are distinct
    conditions with distinct exits (5/4/3)."""
    from mojobpf import cli as cli_module

    with _fake_guest_run() as (_root, entry, lock_path):
        holding = tempfile.mkdtemp(prefix="cli-verify-")
        try:
            staged = os.path.join(holding, "probe.bpf.o")
            with open(staged, "wb") as handle:
                handle.write(b"not-an-elf-object")
            base = [
                "verify", "--kernel", "--object", staged,
                "--release", "v9.99", "--vng", entry,
                "--kernels-lock", lock_path, "--json",
            ]
            cases = [
                (
                    _load_failed_transcript(LOADER_NOT_EBPF),
                    11,
                    cli_module.EXIT_VERIFY_LOADER,
                    "loader",
                ),
                (
                    _load_failed_transcript(VERIFIER_OOB),
                    11,
                    cli_module.EXIT_COMPILE,
                    "verifier",
                ),
                (
                    _PREFLIGHT_TRANSCRIPT,
                    10,
                    cli_module.EXIT_ENVIRONMENT,
                    "environment",
                ),
            ]
            for transcript, exit_code, expected, label in cases:
                _FakeGuestProc.transcript = transcript
                _FakeGuestProc.exit_code = exit_code
                code, out, err = _run_cli(base)
                assert code == expected, (label, code, out, err)
                document = json.loads(out)
                assert document["classification"] == label, document
        finally:
            shutil.rmtree(holding, ignore_errors=True)


def test_verify_cli_pass_and_interrupted():
    """CLI contract: a clean run exits 0; interruption exits 130."""
    from mojobpf import cli as cli_module

    with _fake_guest_run() as (_root, entry, lock_path):
        holding = tempfile.mkdtemp(prefix="cli-verify-")
        try:
            staged = os.path.join(holding, "probe.bpf.o")
            with open(staged, "wb") as handle:
                handle.write(b"not-an-elf-object")
            code, out, err = _run_cli(
                [
                    "verify", "--kernel", "--object", staged,
                    "--release", "v9.99", "--vng", entry,
                    "--kernels-lock", lock_path,
                ]
            )
            assert code == cli_module.EXIT_OK, (out, err)
            assert "status=pass" in out, out
        finally:
            shutil.rmtree(holding, ignore_errors=True)
    real_runner = verify_module.run_verification

    def _interrupted(_request):
        raise VerifyInterrupted("signal 15 during guest run")

    verify_module.run_verification = _interrupted
    try:
        code, _out, err = _run_cli(
            ["verify", "--kernel", "--object", "whatever.o"]
        )
    finally:
        verify_module.run_verification = real_runner
    assert code == cli_module.EXIT_INTERRUPTED, err
    assert "signal 15" in err, err


def test_verify_cli_accepts_kernels_lock_and_keep_evidence():
    from mojobpf import cli as cli_module

    parser = cli_module.build_parser()
    args = parser.parse_args(["verify", "--kernel", "--object", "x.o"])
    assert args.kernels_lock is None
    assert args.keep_evidence is False
    args = parser.parse_args(
        [
            "verify", "--kernel", "--object", "x.o",
            "--kernels-lock", "/tmp/k.json", "--keep-evidence",
        ]
    )
    assert args.kernels_lock == "/tmp/k.json"
    assert args.keep_evidence is True


# --- A07 R1 review closure (REQUEST_CHANGES items 1-7) ---


def _r1_admit_loose(path, name):
    """Admit any path with empty pins and an empty trust root.

    Mirrors the reviewer's item-1 trace: no version/entry pins,
    no trust root, no version probe (nothing executes here).
    """
    return admit_execution(
        ExecutionRequest(name=name, argv0=path, probe_version=False),
        ExecutionPins(),
    )


def _r1_loose_execution(record, farm):
    return {
        "execution": record,
        "virtme_run_execution": record,
        "qemu_execution": record,
        "farm": farm,
    }


def test_r1_item1_unapproved_true_record_rejected_without_execution():
    """MAJOR item 1: a /usr/bin/true record admitted with empty
    pins and an empty trust root is rejected at the admission
    boundary and never executes."""
    image, _license_bytes = _synthetic_elf()
    lane = resolve_lane("v6.12", "tcg", LOCK_PATH)
    scratch = tempfile.mkdtemp(prefix="verify-r1admit-")
    try:
        loose = _r1_admit_loose("/usr/bin/true", "true")
        farm = build_path_farm({"vng": "/usr/bin/true"}, parent=scratch)
        with _saved_tmpdir(scratch):
            try:
                verify_bytes(
                    image, lane, _r1_loose_execution(loose, farm)
                )
            except VerifyError as exc:
                assert "unapproved runner chain" in str(exc), exc
            else:
                raise AssertionError("unapproved /usr/bin/true admitted")
        marker = os.path.join(scratch, "EXECUTED.marker")
        script = os.path.join(scratch, "evil-runner.sh")
        _write_executable(script, "#!/bin/sh\ntouch '%s'\n" % marker)
        loose_script = _r1_admit_loose(script, "vng")
        assert not os.path.exists(marker), "admission executed the script"
        farm2 = build_path_farm({"vng": script}, parent=scratch)
        with _saved_tmpdir(scratch):
            try:
                verify_bytes(
                    image, lane, _r1_loose_execution(loose_script, farm2)
                )
            except VerifyError as exc:
                assert "unapproved runner chain" in str(exc), exc
            else:
                raise AssertionError("unapproved script admitted")
        assert not os.path.exists(marker), "unapproved script executed"
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def test_r1_item1_empty_farm_rejected_before_spawn():
    """MAJOR item 1: an empty farm is rejected before any spawn,
    so nested commands cannot fall through to ambient PATH."""
    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r1farm-")
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    try:
        runner = _admit_fixture(entry, lock_path, root)
        real_farm = runner["farm"]
        try:
            empty = os.path.join(scratch, "mojobpf-farm-empty")
            os.makedirs(empty)
            runner["farm"] = empty
            lane = resolve_lane("v9.99", "tcg", lock_path)
            spawns = []
            real_popen = subprocess.Popen

            def _refusing(*args, **kwargs):
                spawns.append(args[0] if args else None)
                raise AssertionError("spawned past an empty farm")

            subprocess.Popen = _refusing
            try:
                with _saved_tmpdir(scratch):
                    try:
                        verify_bytes(image, lane, runner)
                    except VerifyError as exc:
                        assert "unapproved runner chain" in str(exc), exc
                    else:
                        raise AssertionError("empty farm admitted")
            finally:
                subprocess.Popen = real_popen
            assert spawns == [], spawns
        finally:
            shutil.rmtree(real_farm, ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def test_r1_item1_integer_records_rejected_for_values():
    """MAJOR item 1: integer records are rejected for their
    admission values even behind a well-formed farm."""
    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r1ints-")
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    try:
        runner = _admit_fixture(entry, lock_path, root)
        try:
            forged = {
                "execution": 1,
                "virtme_run_execution": 2,
                "qemu_execution": 3,
                "farm": runner["farm"],
            }
            lane = resolve_lane("v9.99", "tcg", lock_path)
            with _saved_tmpdir(scratch):
                try:
                    verify_bytes(image, lane, forged)
                except VerifyError as exc:
                    assert "unapproved runner chain" in str(exc), exc
                    assert "admitted execution" in str(exc), exc
                except BaseException as exc:
                    raise AssertionError(
                        "integer records escaped the boundary: %r" % (exc,)
                    )
                else:
                    raise AssertionError("integer records admitted")
            assert os.listdir(scratch) == [], os.listdir(scratch)
        finally:
            shutil.rmtree(runner["farm"], ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def test_r1_item1_farm_targets_and_digests_bound():
    """MAJOR item 1: the farm must carry exactly the expected
    names resolving to the admitted targets, and each record's
    digest must match its content."""
    import dataclasses

    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r1bind-")
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    try:
        runner = _admit_fixture(entry, lock_path, root)
        try:
            lane = resolve_lane("v9.99", "tcg", lock_path)
            farm = runner["farm"]
            decoy = os.path.join(scratch, "decoy")
            _write_executable(decoy, "#!/bin/sh\nexit 0\n")
            os.unlink(os.path.join(farm, "vng"))
            os.symlink(decoy, os.path.join(farm, "vng"))
            try:
                verify_bytes(image, lane, runner)
            except VerifyError as exc:
                assert "unapproved runner chain" in str(exc), exc
                assert "admitted target" in str(exc), exc
            else:
                raise AssertionError("repointed farm target admitted")
            os.unlink(os.path.join(farm, "vng"))
            os.symlink(entry, os.path.join(farm, "vng"))
            os.symlink(decoy, os.path.join(farm, "extra"))
            try:
                verify_bytes(image, lane, runner)
            except VerifyError as exc:
                assert "unapproved runner chain" in str(exc), exc
            else:
                raise AssertionError("extra farm entry admitted")
            os.unlink(os.path.join(farm, "extra"))
            tampered = dict(runner)
            tampered["execution"] = dataclasses.replace(
                runner["execution"], digest="0" * 64
            )
            try:
                verify_bytes(image, lane, tampered)
            except VerifyError as exc:
                assert "unapproved runner chain" in str(exc), exc
                assert "digest" in str(exc), exc
            else:
                raise AssertionError("forged digest admitted")
        finally:
            shutil.rmtree(runner["farm"], ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def test_r1_item2_sigterm_during_staging_runs_teardown():
    """MINOR item 2: SIGTERM during staging reaches the
    protected lifecycle (teardown runs), not ambient handling."""
    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r1stage-")
    ambient_calls = []
    previous = signal.getsignal(signal.SIGTERM)

    def _ambient(signum, _frame):
        ambient_calls.append(signum)

    signal.signal(signal.SIGTERM, _ambient)
    try:
        with _fake_guest_run() as (_root, entry, lock_path):
            runner = verify_module._probe_vng(
                entry, kernels_lock=lock_path, farm_parent=scratch
            )
            try:
                lane = resolve_lane("v9.99", "tcg", lock_path)
                real_chmod = os.chmod
                fired = []

                def _signalling_chmod(path, mode, *args, **kwargs):
                    if not fired:
                        fired.append(path)
                        os.kill(os.getpid(), signal.SIGTERM)
                    return real_chmod(path, mode, *args, **kwargs)

                os.chmod = _signalling_chmod
                try:
                    with _saved_tmpdir(scratch):
                        try:
                            verify_bytes(image, lane, runner)
                        except BaseException as exc:
                            got = exc
                        else:
                            got = None
                        leftovers = sorted(os.listdir(scratch))
                finally:
                    os.chmod = real_chmod
            finally:
                shutil.rmtree(runner["farm"], ignore_errors=True)
    finally:
        signal.signal(signal.SIGTERM, previous)
        shutil.rmtree(scratch, ignore_errors=True)
    assert fired, "staging never reached chmod"
    assert ambient_calls == [], ambient_calls
    assert isinstance(got, VerifyInterrupted), repr(got)
    assert "signal 15" in str(got), got
    assert [
        name for name in leftovers if name.startswith("mojobpf-verify-")
    ] == [], leftovers


def test_r1_item2_sigint_during_postprocessing_cleans_stage():
    """MINOR item 2: SIGINT during postprocessing still removes
    owned staging through the protected lifecycle."""
    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r1post-")
    try:
        with _fake_guest_run() as (_root, entry, lock_path):
            runner = verify_module._probe_vng(
                entry, kernels_lock=lock_path, farm_parent=scratch
            )
            try:
                lane = resolve_lane("v9.99", "tcg", lock_path)
                real_kernel = verify_module._guest_kernel
                fired = []

                def _signalling_kernel(output):
                    if not fired:
                        fired.append(True)
                        os.kill(os.getpid(), signal.SIGINT)
                    return real_kernel(output)

                verify_module._guest_kernel = _signalling_kernel
                try:
                    with _saved_tmpdir(scratch):
                        try:
                            verify_bytes(image, lane, runner)
                        except BaseException as exc:
                            got = exc
                        else:
                            got = None
                        leftovers = sorted(os.listdir(scratch))
                finally:
                    verify_module._guest_kernel = real_kernel
            finally:
                shutil.rmtree(runner["farm"], ignore_errors=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    assert fired, "postprocessing never ran"
    assert isinstance(got, VerifyInterrupted), repr(got)
    assert [
        name for name in leftovers if name.startswith("mojobpf-verify-")
    ] == [], leftovers


def test_r1_item2_decode_error_routes_through_teardown():
    """MINOR item 2: undecodable runner output is a reported
    setup failure with owned staging removed."""
    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r1decode-")
    try:
        with _fake_guest_run() as (_root, entry, lock_path):
            runner = verify_module._probe_vng(
                entry, kernels_lock=lock_path, farm_parent=scratch
            )
            try:
                lane = resolve_lane("v9.99", "tcg", lock_path)
                real_communicate = _FakeGuestProc.communicate

                def _undecodable(self, timeout=None):
                    raise UnicodeDecodeError(
                        "utf-8", b"\xff", 0, 1, "test decode"
                    )

                _FakeGuestProc.communicate = _undecodable
                try:
                    with _saved_tmpdir(scratch):
                        try:
                            verify_bytes(image, lane, runner)
                        except BaseException as exc:
                            got = exc
                        else:
                            got = None
                        leftovers = sorted(os.listdir(scratch))
                finally:
                    _FakeGuestProc.communicate = real_communicate
            finally:
                shutil.rmtree(runner["farm"], ignore_errors=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    assert isinstance(got, VerifyError), repr(got)
    assert "undecodable" in str(got), got
    assert leftovers == [], leftovers


def test_r1_item3_staging_cleanup_failure_surfaced():
    """MINOR item 3: when the partial stage cannot be removed,
    the setup error reports the cleanup failure too."""
    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r1stagefail-")
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    try:
        runner = _admit_fixture(entry, lock_path, root)
        try:
            lane = resolve_lane("v9.99", "tcg", lock_path)
            real_chmod = os.chmod
            real_rmtree = shutil.rmtree

            def _denied_chmod(path, mode, *args, **kwargs):
                raise OSError("chmod denied for the test")

            def _denied_rmtree(path, *args, **kwargs):
                if os.path.basename(path).startswith("mojobpf-verify-"):
                    raise OSError("EACCES: keep-out for the test")
                return real_rmtree(path, *args, **kwargs)

            os.chmod = _denied_chmod
            shutil.rmtree = _denied_rmtree
            try:
                with _saved_tmpdir(scratch):
                    try:
                        verify_bytes(image, lane, runner)
                    except BaseException as exc:
                        got = exc
                    else:
                        got = None
            finally:
                os.chmod = real_chmod
                shutil.rmtree = real_rmtree
        finally:
            shutil.rmtree(runner["farm"], ignore_errors=True)
            shutil.rmtree(scratch, ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    assert isinstance(got, VerifyError), repr(got)
    assert "cannot stage" in str(got), got
    assert "staging cleanup failed" in str(got), got


def test_r1_item3_keep_evidence_retains_partial_stage_on_sigint():
    """MINOR item 3: SIGINT during staging with keep_evidence
    retains both the partial stage and the PATH farm."""
    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r1keep-")
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    try:
        runner = _admit_fixture(entry, lock_path, scratch)
        farm = runner["farm"]
        lane = resolve_lane("v9.99", "tcg", lock_path)
        real_chmod = os.chmod
        real_mkdtemp = tempfile.mkdtemp
        created = []
        fired = []

        def _recording_mkdtemp(*args, **kwargs):
            path = real_mkdtemp(*args, **kwargs)
            created.append(path)
            return path

        def _signalling_chmod(path, mode, *args, **kwargs):
            if not fired:
                fired.append(path)
                os.kill(os.getpid(), signal.SIGINT)
            return real_chmod(path, mode, *args, **kwargs)

        os.chmod = _signalling_chmod
        tempfile.mkdtemp = _recording_mkdtemp
        try:
            with _saved_tmpdir(scratch):
                try:
                    verify_bytes(image, lane, runner, keep_evidence=True)
                except BaseException as exc:
                    got = exc
                else:
                    got = None
        finally:
            os.chmod = real_chmod
            tempfile.mkdtemp = real_mkdtemp
        stages = [
            path
            for path in created
            if os.path.basename(path).startswith("mojobpf-verify-")
        ]
        try:
            assert fired, "staging never reached chmod"
            assert isinstance(got, VerifyInterrupted), repr(got)
            assert len(stages) == 1, created
            assert os.path.isdir(stages[0]), stages
            assert os.path.isdir(farm), farm
        finally:
            for path in created:
                shutil.rmtree(path, ignore_errors=True)
            shutil.rmtree(farm, ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def test_r1_item4_interruption_during_registration_kills_owned_child():
    """MAJOR item 4: a signal after child creation but before
    registration still terminates and reaps the owned child."""
    sleep = shutil.which("sleep") or "/bin/sleep"
    assert os.path.isfile(sleep) and os.access(sleep, os.X_OK), sleep
    image = b"not-an-elf-object"
    scratch = tempfile.mkdtemp(prefix="verify-r1race-")
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    children = []
    kill_calls = []
    try:
        saved_path = os.environ.get("PATH", "")
        os.environ["PATH"] = root + os.pathsep + saved_path
        try:
            runner = verify_module._probe_vng(
                entry, kernels_lock=lock_path, farm_parent=scratch
            )
        finally:
            os.environ["PATH"] = saved_path
        lane = resolve_lane("v9.99", "tcg", lock_path)
        real_spawn = verify_module.popen_admitted
        real_kill_group = verify_module._kill_group

        def _racing(_execution, _argv_suffix, **kwargs):
            proc = subprocess.Popen(
                [sleep, "60"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            children.append(proc)
            os.kill(os.getpid(), signal.SIGTERM)
            return proc

        def _counting_kill(pgid):
            kill_calls.append(pgid)
            return real_kill_group(pgid)

        verify_module.popen_admitted = _racing
        verify_module._kill_group = _counting_kill
        try:
            with _saved_tmpdir(scratch):
                try:
                    verify_bytes(image, lane, runner, timeout=60)
                except BaseException as exc:
                    got = exc
                else:
                    got = None
                leftovers = sorted(os.listdir(scratch))
        finally:
            verify_module.popen_admitted = real_spawn
            verify_module._kill_group = real_kill_group
        try:
            assert children, "racing spawn never ran"
            assert isinstance(got, VerifyInterrupted), repr(got)
            assert kill_calls, "no group-kill attempted for the child"
            for child in children:
                assert child.poll() is not None, "owned child left alive"
            assert leftovers == [], leftovers
        finally:
            for child in children:
                try:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=30)
                except Exception:
                    pass
            shutil.rmtree(runner["farm"], ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


class _R1ExitedInterruptingProc(_FakeGuestProc):
    """An exited runner (poll()==0) that SIGTERMs mid-communicate."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.returncode = 0

    def communicate(self, timeout=None):
        os.kill(os.getpid(), signal.SIGTERM)
        return super().communicate(timeout=timeout)


def _run_until_sigterm_with(proc_cls):
    """Run one verification whose guest boot uses proc_cls; the
    SIGTERM it delivers mid-run escapes to the caller."""
    with _fake_guest_run() as (_root, entry, lock_path):
        holding = tempfile.mkdtemp(prefix="verify-r1intr-")
        staged = os.path.join(holding, "probe.bpf.o")
        with open(staged, "wb") as handle:
            handle.write(b"not-an-elf-object")
        real_popen = subprocess.Popen

        def _selecting(*args, **kwargs):
            argv = args[0] if args else []
            if (
                isinstance(argv, list)
                and len(argv) > 2
                and argv[1] == "--run"
            ):
                return proc_cls(*args, **kwargs)
            return real_popen(*args, **kwargs)

        subprocess.Popen = _selecting
        try:
            request = VerifyRequest(
                object_path=staged,
                release="v9.99",
                vng_path=entry,
                require_btf="no",
                timeout=60,
                kernels_lock=lock_path,
            )
            run_verification(request)
        finally:
            subprocess.Popen = real_popen
            shutil.rmtree(holding, ignore_errors=True)


def test_r1_item5_interruption_reports_process_cleanup_failure():
    """MINOR item 5: a failed group cleanup is reported on the
    interruption error instead of disappearing."""
    real_kill = verify_module._kill_group
    calls = []

    def _failing_kill(pgid):
        calls.append(pgid)
        return False

    verify_module._kill_group = _failing_kill
    try:
        try:
            _run_until_sigterm_with(_InterruptingGuestProc)
        except BaseException as exc:
            got = exc
        else:
            got = None
    finally:
        verify_module._kill_group = real_kill
    assert calls, "group cleanup never attempted"
    assert isinstance(got, VerifyInterrupted), repr(got)
    assert "signal 15" in str(got), got
    assert "process cleanup failed" in str(got), got


def test_r1_item5_descendants_reaped_after_runner_exit():
    """MINOR item 5: group cleanup runs when descendants remain
    even after the runner itself exited."""
    real_kill = verify_module._kill_group
    real_members = verify_module._group_members
    calls = []

    def _recording_kill(pgid):
        calls.append(pgid)
        return True

    def _live_descendants(pgid):
        return [
            {
                "pid": 424242424,
                "state": "S",
                "comm": "qemu-system-x86_64",
            }
        ]

    verify_module._kill_group = _recording_kill
    verify_module._group_members = _live_descendants
    try:
        try:
            _run_until_sigterm_with(_R1ExitedInterruptingProc)
        except BaseException as exc:
            got = exc
        else:
            got = None
    finally:
        verify_module._kill_group = real_kill
        verify_module._group_members = real_members
    assert isinstance(got, VerifyInterrupted), repr(got)
    assert calls, "descendants never reaped after runner exit"


def test_r1_item7_exit_wording_covers_prespawn_runner_failure():
    """MINOR item 7: exit-3 wording covers post-spawn failures;
    an admitted runner exiting 127 pre-transcript still exits 3
    with no guest kernel observed."""
    from mojobpf import cli as cli_module

    doc = cli_module.__doc__ or ""
    assert "Only a guest\nthat booted" not in doc, doc
    result = _run_with_fake_guest(127, "")
    try:
        assert result["child"]["exit"] == 127, result["child"]
        assert result["guest"]["kernel"] is None, result["guest"]
        assert result["classification"] == "environment", result
    finally:
        shutil.rmtree(result["stage_path"], ignore_errors=True)
        shutil.rmtree(result["runner"]["farm"], ignore_errors=True)
    with _fake_guest_run("", 127) as (_root, entry, lock_path):
        holding = tempfile.mkdtemp(prefix="cli-verify-127-")
        try:
            staged = os.path.join(holding, "probe.bpf.o")
            with open(staged, "wb") as handle:
                handle.write(b"not-an-elf-object")
            code, out, _err = _run_cli(
                [
                    "verify", "--kernel", "--object", staged,
                    "--release", "v9.99", "--vng", entry,
                    "--kernels-lock", lock_path, "--json",
                ]
            )
            assert code == cli_module.EXIT_ENVIRONMENT, (code, out)
            document = json.loads(out)
            assert document["guest"]["kernel"] is None, document
        finally:
            shutil.rmtree(holding, ignore_errors=True)


def test_r2_item1_substituted_argv_with_recomputed_digest_rejected():
    """R2 item 1: an approved record copied with a substituted
    argv_prefix and a recomputed digest is rejected at the admission
    boundary and never executes."""
    import dataclasses

    from mojobpf.execution import _admission_digest

    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r2argv-")
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    try:
        lane = resolve_lane("v9.99", "tcg", lock_path)
        # Reviewer's exact trace: the approved record copied with
        # argv_prefix=("/usr/bin/true",), pinned identities kept, the
        # displayed digest updated.
        runner = _admit_fixture(entry, lock_path, root)
        try:
            approved = runner["execution"]
            substituted = dataclasses.replace(
                approved, argv_prefix=("/usr/bin/true",)
            )
            substituted = dataclasses.replace(
                substituted, digest=_admission_digest(substituted)
            )
            tampered = dict(runner)
            tampered["execution"] = substituted
            tampered["digest"] = substituted.digest
            real_popen = subprocess.Popen
            spawns = []

            def _recording(*args, **kwargs):
                spawns.append(args[0] if args else None)
                return real_popen(*args, **kwargs)

            subprocess.Popen = _recording
            try:
                with _saved_tmpdir(scratch):
                    try:
                        result = verify_bytes(image, lane, tampered)
                    except VerifyError as exc:
                        assert "unapproved runner chain" in str(exc), exc
                    else:
                        raise AssertionError(
                            "substituted argv admitted: %r"
                            % (result["child"],)
                        )
            finally:
                subprocess.Popen = real_popen
            assert spawns == [], spawns
        finally:
            shutil.rmtree(runner["farm"], ignore_errors=True)
        # Marker variant: the substituted argv must not execute either.
        runner = _admit_fixture(entry, lock_path, root)
        try:
            marker = os.path.join(scratch, "EXECUTED.marker")
            script = os.path.join(scratch, "evil-runner.sh")
            _write_executable(script, "#!/bin/sh\ntouch '%s'\n" % marker)
            evil = dataclasses.replace(
                runner["execution"], argv_prefix=(script,)
            )
            evil = dataclasses.replace(
                evil, digest=_admission_digest(evil)
            )
            tampered = dict(runner)
            tampered["execution"] = evil
            tampered["digest"] = evil.digest
            with _saved_tmpdir(scratch):
                try:
                    verify_bytes(image, lane, tampered)
                except VerifyError as exc:
                    assert "unapproved runner chain" in str(exc), exc
                else:
                    raise AssertionError("substituted script argv admitted")
            assert not os.path.exists(marker), "substituted argv executed"
        finally:
            shutil.rmtree(runner["farm"], ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def test_r2_item1_cleared_env_with_recomputed_digest_rejected():
    """R2 item 1: an approved record copied with cleared env
    sanitization and a recomputed digest is rejected; ambient
    PYTHONPATH must never reach the spawn."""
    import dataclasses

    from mojobpf.execution import _admission_digest

    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r2env-")
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    try:
        runner = _admit_fixture(entry, lock_path, root)
        try:
            lane = resolve_lane("v9.99", "tcg", lock_path)
            approved = runner["execution"]
            cleared = dataclasses.replace(
                approved, env_unset=(), env_set=()
            )
            cleared = dataclasses.replace(
                cleared, digest=_admission_digest(cleared)
            )
            tampered = dict(runner)
            tampered["execution"] = cleared
            tampered["digest"] = cleared.digest
            real_popen = subprocess.Popen
            seen = []

            def _capturing(*args, **kwargs):
                env = kwargs.get("env") or {}
                seen.append(env.get("PYTHONPATH", "<absent>"))
                argv = args[0] if args else []
                if (
                    isinstance(argv, list)
                    and len(argv) > 2
                    and argv[1] == "--run"
                ):
                    return _FakeGuestProc(*args, **kwargs)
                return real_popen(*args, **kwargs)

            sentinel = os.path.join(scratch, "ambient-shadow")
            os.makedirs(sentinel)
            subprocess.Popen = _capturing
            try:
                with _saved_env("PYTHONPATH", sentinel):
                    with _saved_tmpdir(scratch):
                        try:
                            verify_bytes(image, lane, tampered)
                        except VerifyError as exc:
                            assert (
                                "unapproved runner chain" in str(exc)
                            ), exc
                        else:
                            raise AssertionError("cleared env admitted")
            finally:
                subprocess.Popen = real_popen
            assert seen == [], seen
        finally:
            shutil.rmtree(runner["farm"], ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def test_r2_item2a_staging_failures_restore_signal_handlers():
    """R2 item 2a: staging interruption and allocation/chmod
    failures restore the installed signal handlers."""
    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r2handlers-")
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    try:
        runner = _admit_fixture(entry, lock_path, root)
        try:
            lane = resolve_lane("v9.99", "tcg", lock_path)
            real_mkdtemp = tempfile.mkdtemp
            real_chmod = os.chmod

            def _sentinel(signum, _frame):
                raise AssertionError("sentinel must not fire")

            previous_term = signal.getsignal(signal.SIGTERM)
            previous_int = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGTERM, _sentinel)
            signal.signal(signal.SIGINT, _sentinel)
            try:
                # Allocation failure.
                def _failing_mkdtemp(*args, **kwargs):
                    raise OSError("allocation denied for the test")

                tempfile.mkdtemp = _failing_mkdtemp
                try:
                    with _saved_tmpdir(scratch):
                        try:
                            verify_bytes(image, lane, runner)
                        except VerifyError as exc:
                            assert "cannot stage" in str(exc), exc
                        else:
                            raise AssertionError(
                                "allocation failure admitted"
                            )
                finally:
                    tempfile.mkdtemp = real_mkdtemp
                assert (
                    signal.getsignal(signal.SIGTERM) is _sentinel
                ), "SIGTERM handler left behind after allocation failure"
                assert (
                    signal.getsignal(signal.SIGINT) is _sentinel
                ), "SIGINT handler left behind after allocation failure"
                # chmod failure.
                def _denied_chmod(path, mode, *args, **kwargs):
                    raise OSError("chmod denied for the test")

                os.chmod = _denied_chmod
                try:
                    with _saved_tmpdir(scratch):
                        try:
                            verify_bytes(image, lane, runner)
                        except VerifyError as exc:
                            assert "cannot stage" in str(exc), exc
                        else:
                            raise AssertionError("chmod failure admitted")
                finally:
                    os.chmod = real_chmod
                assert (
                    signal.getsignal(signal.SIGTERM) is _sentinel
                ), "SIGTERM handler left behind after chmod failure"
                assert (
                    signal.getsignal(signal.SIGINT) is _sentinel
                ), "SIGINT handler left behind after chmod failure"
                # Real interruption during staging.
                fired = []

                def _signalling_chmod(path, mode, *args, **kwargs):
                    if not fired:
                        fired.append(path)
                        os.kill(os.getpid(), signal.SIGTERM)
                    return real_chmod(path, mode, *args, **kwargs)

                os.chmod = _signalling_chmod
                try:
                    with _saved_tmpdir(scratch):
                        try:
                            verify_bytes(image, lane, runner)
                        except VerifyInterrupted as exc:
                            assert "signal 15" in str(exc), exc
                        else:
                            raise AssertionError(
                                "staging SIGTERM swallowed"
                            )
                finally:
                    os.chmod = real_chmod
                assert fired, "staging never reached chmod"
                assert (
                    signal.getsignal(signal.SIGTERM) is _sentinel
                ), "SIGTERM handler left behind after staging SIGTERM"
                assert (
                    signal.getsignal(signal.SIGINT) is _sentinel
                ), "SIGINT handler left behind after staging SIGTERM"
            finally:
                signal.signal(signal.SIGTERM, previous_term)
                signal.signal(signal.SIGINT, previous_int)
        finally:
            shutil.rmtree(runner["farm"], ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def test_r2_item2b_sigint_during_preparation_removes_stage_and_farm():
    """R2 item 2b: a real SIGINT during runner preparation removes
    both the stage and the PATH farm."""
    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r2prep-")
    holding = tempfile.mkdtemp(prefix="verify-r2prep-obj-")
    try:
        with _fake_guest_run() as (_root, entry, lock_path):
            staged = os.path.join(holding, "probe.bpf.o")
            with open(staged, "wb") as handle:
                handle.write(image)
            real_exec = verify_module.guest_exec_command
            fired = []

            def _signalling_exec(script_path, stage):
                if not fired:
                    fired.append(stage)
                    os.kill(os.getpid(), signal.SIGINT)
                return real_exec(script_path, stage)

            verify_module.guest_exec_command = _signalling_exec
            previous_term = signal.getsignal(signal.SIGTERM)
            previous_int = signal.getsignal(signal.SIGINT)
            try:
                with _saved_tmpdir(scratch):
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
                    except BaseException as exc:
                        got = exc
                    else:
                        got = None
                    leftovers = sorted(os.listdir(scratch))
                    after_term = signal.getsignal(signal.SIGTERM)
                    after_int = signal.getsignal(signal.SIGINT)
            finally:
                verify_module.guest_exec_command = real_exec
                signal.signal(signal.SIGTERM, previous_term)
                signal.signal(signal.SIGINT, previous_int)
            assert fired, "preparation never built the guest command"
            assert isinstance(got, VerifyInterrupted), repr(got)
            assert "signal 2" in str(got), got
            assert after_term is previous_term, "SIGTERM handler leaked"
            assert after_int is previous_int, "SIGINT handler leaked"
            assert leftovers == [], leftovers
    finally:
        shutil.rmtree(holding, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def test_r2_item2c_decode_error_kills_surviving_descendant():
    """R2 item 2c: undecodable runner output with an exited runner
    and a surviving descendant still runs group cleanup: the
    descendant is killed, owned staging is removed."""
    sleep = shutil.which("sleep") or "/bin/sleep"
    assert os.path.isfile(sleep) and os.access(sleep, os.X_OK), sleep
    image = b"not-an-elf-object"
    scratch = tempfile.mkdtemp(prefix="verify-r2decode-")
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    descendants = []
    kill_calls = []
    try:
        runner = _admit_fixture(entry, lock_path, root)
        lane = resolve_lane("v9.99", "tcg", lock_path)
        real_spawn = verify_module.popen_admitted
        real_kill_group = verify_module._kill_group
        pidfile = os.path.join(scratch, "descendant.pid")

        def _decoding_spawn(_execution, _argv_suffix, **kwargs):
            script = (
                "sleep 60 </dev/null >/dev/null 2>&1 & "
                "echo $! > '%s'; "
                "printf '\\377'; exit 0" % pidfile
            )
            return subprocess.Popen(
                ["/bin/sh", "-c", script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )

        def _counting_kill(pgid):
            kill_calls.append(pgid)
            return real_kill_group(pgid)

        verify_module.popen_admitted = _decoding_spawn
        verify_module._kill_group = _counting_kill
        try:
            with _saved_tmpdir(scratch):
                try:
                    verify_bytes(image, lane, runner, timeout=60)
                except BaseException as exc:
                    got = exc
                else:
                    got = None
                leftovers = sorted(
                    name
                    for name in os.listdir(scratch)
                    if name.startswith("mojobpf-")
                )
        finally:
            verify_module.popen_admitted = real_spawn
            verify_module._kill_group = real_kill_group
            try:
                with open(pidfile) as handle:
                    descendants.append(int(handle.read().strip()))
            except (OSError, ValueError):
                pass
        try:
            assert isinstance(got, VerifyError), repr(got)
            assert "undecodable" in str(got), got
            assert kill_calls, "decode path made zero group-kill calls"
            assert descendants, "descendant pid never recorded"
            for descendant in descendants:
                try:
                    os.kill(descendant, 0)
                except ProcessLookupError:
                    pass
                else:
                    raise AssertionError(
                        "surviving descendant %d left alive"
                        % (descendant,)
                    )
            assert leftovers == [], leftovers
        finally:
            for descendant in descendants:
                try:
                    os.kill(descendant, signal.SIGKILL)
                except OSError:
                    pass
            shutil.rmtree(runner["farm"], ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def test_r3_item2_install_window_leaves_no_handler():
    """R3 item 2.1: a real SIGTERM arriving between the two handler
    installs still restores both handlers: installation is atomic
    with respect to delivery, and the signal mask is left clean."""
    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r3install-")
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    try:
        runner = _admit_fixture(entry, lock_path, root)
        try:
            lane = resolve_lane("v9.99", "tcg", lock_path)

            def _sentinel(signum, _frame):
                raise AssertionError("sentinel must not fire")

            previous_term = signal.getsignal(signal.SIGTERM)
            previous_int = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGTERM, _sentinel)
            signal.signal(signal.SIGINT, _sentinel)
            fired = []
            real_kill = os.kill

            def _tracer(frame, event, _arg):
                if (
                    not fired
                    and event == "line"
                    and frame.f_code.co_name == "verify_bytes"
                    and signal.getsignal(signal.SIGTERM)
                    is not _sentinel
                    and signal.getsignal(signal.SIGINT) is _sentinel
                ):
                    fired.append(True)
                    real_kill(os.getpid(), signal.SIGTERM)
                return _tracer

            try:
                with _saved_tmpdir(scratch):
                    sys.settrace(_tracer)
                    try:
                        try:
                            verify_bytes(image, lane, runner)
                        except BaseException as exc:
                            got = exc
                        else:
                            got = None
                    finally:
                        sys.settrace(None)
                    after_term = signal.getsignal(signal.SIGTERM)
                    after_int = signal.getsignal(signal.SIGINT)
                    mask = signal.pthread_sigmask(
                        signal.SIG_BLOCK, set()
                    )
                    leftovers = sorted(os.listdir(scratch))
            finally:
                sys.settrace(None)
                signal.signal(signal.SIGTERM, previous_term)
                signal.signal(signal.SIGINT, previous_int)
            assert fired, "trace never observed the install window"
            assert isinstance(got, VerifyInterrupted), repr(got)
            assert "signal 15" in str(got), got
            assert after_term is _sentinel, (
                "SIGTERM handler left behind after install-window "
                "SIGTERM"
            )
            assert after_int is _sentinel, (
                "SIGINT handler left behind after install-window "
                "SIGTERM"
            )
            assert signal.SIGTERM not in mask, mask
            assert signal.SIGINT not in mask, mask
            assert leftovers == [], leftovers
        finally:
            shutil.rmtree(runner["farm"], ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def test_r3_item2_gap_sigint_removes_stage_and_farm():
    """R3 item 2.2: a real SIGINT landing on the lifecycle transition
    between staging and runner preparation runs full teardown: both
    the owned stage and the PATH farm are removed."""
    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r3gap-")
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    try:
        runner = _admit_fixture(entry, lock_path, scratch)
        farm = runner["farm"]
        try:
            lane = resolve_lane("v9.99", "tcg", lock_path)
            source, first = inspect.getsourcelines(verify_bytes)
            matches = [
                first + index
                for index, text in enumerate(source)
                if text.strip() == "assert stage is not None"
            ]
            assert len(matches) == 1, matches
            gap_line = matches[0]
            fired = []
            real_kill = os.kill
            code = verify_bytes.__code__

            def _tracer(frame, event, _arg):
                if (
                    not fired
                    and event == "line"
                    and frame.f_code is code
                    and frame.f_lineno == gap_line
                ):
                    fired.append(True)
                    real_kill(os.getpid(), signal.SIGINT)
                return _tracer

            previous_term = signal.getsignal(signal.SIGTERM)
            previous_int = signal.getsignal(signal.SIGINT)
            try:
                with _saved_tmpdir(scratch):
                    sys.settrace(_tracer)
                    try:
                        try:
                            verify_bytes(image, lane, runner)
                        except BaseException as exc:
                            got = exc
                        else:
                            got = None
                    finally:
                        sys.settrace(None)
                    leftovers = sorted(os.listdir(scratch))
                    after_term = signal.getsignal(signal.SIGTERM)
                    after_int = signal.getsignal(signal.SIGINT)
            finally:
                sys.settrace(None)
                signal.signal(signal.SIGTERM, previous_term)
                signal.signal(signal.SIGINT, previous_int)
            assert fired, "lifecycle transition line never executed"
            assert isinstance(got, VerifyInterrupted), repr(got)
            assert "signal 2" in str(got), got
            assert after_term is previous_term, (
                "SIGTERM handler leaked"
            )
            assert after_int is previous_int, "SIGINT handler leaked"
            assert leftovers == [], leftovers
        finally:
            shutil.rmtree(farm, ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def test_r3_item2_preparation_cleanup_failures_all_reported():
    """R3 item 2.3: a preparation failure with denied removals reports
    every cleanup failure (stage and farm), never just the farm."""
    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r3preperr-")
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    try:
        runner = _admit_fixture(entry, lock_path, root)
        farm = runner["farm"]
        try:
            lane = resolve_lane("v9.99", "tcg", lock_path)
            real_attestation = verify_module._runner_attestation
            real_rmtree = shutil.rmtree
            attempted = []

            def _injected(_runner):
                raise VerifyError("injected preparation failure")

            real_pinned = verify_module._remove_pinned_tree

            def _denied_rmtree(path, *args, **kwargs):
                name = os.path.basename(path)
                if name.startswith("mojobpf-farm-"):
                    attempted.append(path)
                    raise OSError("EACCES: keep-out for the test")
                return real_rmtree(path, *args, **kwargs)

            def _denied_pinned(path, pin):
                # Preparation teardown removes a sealed stage
                # through its pinned identity (A1M6-3); deny
                # the stage there, reporting the seam's error
                # strings (never raising).
                name = os.path.basename(path)
                if name.startswith("mojobpf-verify-"):
                    attempted.append(path)
                    return "%s: EACCES: keep-out for the test" % path
                return real_pinned(path, pin)

            verify_module._runner_attestation = _injected
            verify_module._remove_pinned_tree = _denied_pinned
            shutil.rmtree = _denied_rmtree
            try:
                with _saved_tmpdir(scratch):
                    try:
                        verify_bytes(image, lane, runner)
                    except BaseException as exc:
                        got = exc
                    else:
                        got = None
            finally:
                verify_module._runner_attestation = real_attestation
                verify_module._remove_pinned_tree = real_pinned
                shutil.rmtree = real_rmtree
            stages = [
                path
                for path in attempted
                if os.path.basename(path).startswith("mojobpf-verify-")
            ]
            farms = [
                path
                for path in attempted
                if os.path.basename(path).startswith("mojobpf-farm-")
            ]
            try:
                assert isinstance(got, VerifyError), repr(got)
                assert "injected preparation failure" in str(got), got
                assert stages, attempted
                assert farms, attempted
                assert "staging cleanup failed" in str(got), got
                for path in attempted:
                    assert path in str(got), (path, got)
                    assert os.path.lexists(path), path
            finally:
                for path in attempted:
                    real_rmtree(path, ignore_errors=True)
        finally:
            shutil.rmtree(farm, ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def test_r3_item2_preparation_cleanup_failures_surfaced():
    """R3 item 2.3 (surfaced): the run_verification error for a
    preparation failure with denied removals still names the failed
    stage removal alongside the farm failure."""
    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r3surfaced-")
    holding = tempfile.mkdtemp(prefix="verify-r3surfaced-obj-")
    try:
        with _fake_guest_run() as (_root, entry, lock_path):
            staged = os.path.join(holding, "probe.bpf.o")
            with open(staged, "wb") as handle:
                handle.write(image)
            real_attestation = verify_module._runner_attestation
            real_rmtree = shutil.rmtree
            attempted = []

            def _injected(_runner):
                raise VerifyError("injected preparation failure")

            real_pinned = verify_module._remove_pinned_tree

            def _denied_rmtree(path, *args, **kwargs):
                name = os.path.basename(path)
                if name.startswith("mojobpf-farm-"):
                    attempted.append(path)
                    raise OSError("EACCES: keep-out for the test")
                return real_rmtree(path, *args, **kwargs)

            def _denied_pinned(path, pin):
                # Preparation teardown removes a sealed stage
                # through its pinned identity (A1M6-3); deny
                # the stage there, reporting the seam's error
                # strings (never raising).
                name = os.path.basename(path)
                if name.startswith("mojobpf-verify-"):
                    attempted.append(path)
                    return "%s: EACCES: keep-out for the test" % path
                return real_pinned(path, pin)

            verify_module._runner_attestation = _injected
            verify_module._remove_pinned_tree = _denied_pinned
            shutil.rmtree = _denied_rmtree
            try:
                with _saved_tmpdir(scratch):
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
                    except BaseException as exc:
                        got = exc
                    else:
                        got = None
            finally:
                verify_module._runner_attestation = real_attestation
                verify_module._remove_pinned_tree = real_pinned
                shutil.rmtree = real_rmtree
            stages = [
                path
                for path in attempted
                if os.path.basename(path).startswith("mojobpf-verify-")
            ]
            farms = [
                path
                for path in attempted
                if os.path.basename(path).startswith("mojobpf-farm-")
            ]
            try:
                assert isinstance(got, VerifyError), repr(got)
                assert "injected preparation failure" in str(got), got
                assert stages, attempted
                assert farms, attempted
                for path in stages:
                    assert path in str(got), (path, got)
                for path in farms:
                    assert path in str(got), (path, got)
            finally:
                for path in attempted:
                    real_rmtree(path, ignore_errors=True)
    finally:
        shutil.rmtree(holding, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def _run_try_lines():
    """Locate the nested run-block ``try:`` lines (reviewer 1826/1827).

    Those two adjacent ``try:`` lines compile to NOPs without
    exception-table protection; returns ``(outer, inner)``.
    """
    source, first = inspect.getsourcelines(verify_bytes)
    pairs = [
        (first + index, first + index + 1)
        for index in range(len(source) - 1)
        if source[index].strip() == "try:"
        and source[index + 1].strip() == "try:"
    ]
    assert len(pairs) == 1, pairs
    outer, inner = pairs[0]
    following = "".join(source[outer - first:outer - first + 10])
    assert "registration window" in following, following
    return outer, inner


def _restore_block_line():
    """Locate the restoration mask-block line (reviewer 2212)."""
    source, first = inspect.getsourcelines(verify_bytes)
    anchors = [
        index
        for index, text in enumerate(source)
        if "Delivery held here reaches the previous handlers" in text
    ]
    assert len(anchors) == 1, anchors
    for index in range(anchors[0] + 1, min(anchors[0] + 12, len(source))):
        if "signal.pthread_sigmask(" in source[index]:
            return first + index
    raise AssertionError("restoration mask-block not found")


def _run_line_sigint_trace(target_line):
    """Fire one real SIGINT at ``target_line``; return observations.

    Returns ``(fired, got, leftovers, after_term, after_int, mask,
    previous_term, previous_int)``. A canned guest bounds the run so
    a missed hook fails loudly instead of spawning the fixture chain.
    """
    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r4trace-")
    try:
        with _fake_guest_run() as (_root, entry, lock_path):
            runner = verify_module._probe_vng(
                entry, kernels_lock=lock_path, farm_parent=scratch
            )
            try:
                lane = resolve_lane("v9.99", "tcg", lock_path)
                fired = []
                real_kill = os.kill
                code = verify_bytes.__code__

                def _tracer(frame, event, _arg):
                    if (
                        not fired
                        and event == "line"
                        and frame.f_code is code
                        and frame.f_lineno == target_line
                    ):
                        fired.append(True)
                        real_kill(os.getpid(), signal.SIGINT)
                    return _tracer

                previous_term = signal.getsignal(signal.SIGTERM)
                previous_int = signal.getsignal(signal.SIGINT)
                try:
                    with _saved_tmpdir(scratch):
                        sys.settrace(_tracer)
                        try:
                            try:
                                verify_bytes(image, lane, runner)
                            except BaseException as exc:
                                got = exc
                            else:
                                got = None
                        finally:
                            sys.settrace(None)
                        leftovers = sorted(os.listdir(scratch))
                        after_term = signal.getsignal(signal.SIGTERM)
                        after_int = signal.getsignal(signal.SIGINT)
                        mask = signal.pthread_sigmask(
                            signal.SIG_BLOCK, set()
                        )
                finally:
                    sys.settrace(None)
                    signal.signal(signal.SIGTERM, previous_term)
                    signal.signal(signal.SIGINT, previous_int)
            finally:
                shutil.rmtree(runner["farm"], ignore_errors=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return (
        fired, got, leftovers, after_term, after_int, mask,
        previous_term, previous_int,
    )


def test_r4_item1_sigint_at_outer_run_try_leaves_nothing():
    """R4 item 1 (outer): a real SIGINT on the run-block ``try:``
    line (no exception-table protection there) still tears down the
    owned stage and PATH farm and restores both handlers and the
    incoming signal mask."""
    outer, _inner = _run_try_lines()
    (
        fired, got, leftovers, after_term, after_int, mask,
        previous_term, previous_int,
    ) = _run_line_sigint_trace(outer)
    assert fired, "outer run-block try: line never executed"
    assert isinstance(got, VerifyInterrupted), repr(got)
    assert "signal 2" in str(got), got
    assert after_term is previous_term, "SIGTERM handler leaked"
    assert after_int is previous_int, "SIGINT handler leaked"
    assert signal.SIGTERM not in mask, mask
    assert signal.SIGINT not in mask, mask
    assert leftovers == [], leftovers


def test_r4_item1_sigint_at_inner_run_try_leaves_nothing():
    """R4 item 1 (inner): like the outer run-block ``try:`` trace,
    but firing independently on the nested ``try:`` line."""
    _outer, inner = _run_try_lines()
    (
        fired, got, leftovers, after_term, after_int, mask,
        previous_term, previous_int,
    ) = _run_line_sigint_trace(inner)
    assert fired, "inner run-block try: line never executed"
    assert isinstance(got, VerifyInterrupted), repr(got)
    assert "signal 2" in str(got), got
    assert after_term is previous_term, "SIGTERM handler leaked"
    assert after_int is previous_int, "SIGINT handler leaked"
    assert signal.SIGTERM not in mask, mask
    assert signal.SIGINT not in mask, mask
    assert leftovers == [], leftovers


def test_r4_item1_sigint_at_restoration_start_restores_handlers():
    """R4 item 1 (restoration): a real SIGINT at the start of
    handler restoration still leaves both previous handlers
    installed, the incoming mask in place and no owned staging."""
    restore_line = _restore_block_line()
    (
        fired, got, leftovers, after_term, after_int, mask,
        previous_term, previous_int,
    ) = _run_line_sigint_trace(restore_line)
    assert fired, "restoration block line never executed"
    assert isinstance(got, VerifyInterrupted), repr(got)
    assert "signal 2" in str(got), got
    assert after_term is previous_term, (
        "SIGTERM handler left behind after restoration SIGINT"
    )
    assert after_int is previous_int, (
        "SIGINT handler left behind after restoration SIGINT"
    )
    assert signal.SIGTERM not in mask, mask
    assert signal.SIGINT not in mask, mask
    assert leftovers == [], leftovers


def test_r4_item2_incoming_mask_preserved_on_all_exit_paths():
    """R4 item 2: an incoming mask blocking SIGINT/SIGTERM is
    restored exactly on the failure, success and interruption
    exits (never unconditionally unblocked)."""
    incoming = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    image, _license_bytes = _synthetic_elf()

    # Failure: injected preparation VerifyError before spawn with
    # both signals blocked.
    scratch = tempfile.mkdtemp(prefix="verify-r4mask-fail-")
    root, entry, _pkgdir, _qemu, lock_path = _runner_fixture()
    try:
        runner = _admit_fixture(entry, lock_path, scratch)
        try:
            lane = resolve_lane("v9.99", "tcg", lock_path)
            real_attestation = verify_module._runner_attestation
            previous_term = signal.getsignal(signal.SIGTERM)
            previous_int = signal.getsignal(signal.SIGINT)

            def _injected(_runner):
                raise VerifyError("injected preparation failure")

            verify_module._runner_attestation = _injected
            signal.pthread_sigmask(
                signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM}
            )
            try:
                with _saved_tmpdir(scratch):
                    try:
                        verify_bytes(image, lane, runner)
                    except BaseException as exc:
                        fail_got = exc
                    else:
                        fail_got = None
                    fail_mask = signal.pthread_sigmask(
                        signal.SIG_BLOCK, set()
                    )
                    fail_leftovers = sorted(os.listdir(scratch))
                    fail_term = signal.getsignal(signal.SIGTERM)
                    fail_int = signal.getsignal(signal.SIGINT)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, incoming)
                verify_module._runner_attestation = real_attestation
        finally:
            shutil.rmtree(runner["farm"], ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)

    # Success: a canned passing run with both signals blocked.
    scratch_ok = tempfile.mkdtemp(prefix="verify-r4mask-ok-")
    try:
        with _fake_guest_run() as (_root, entry_ok, lock_ok):
            runner_ok = verify_module._probe_vng(
                entry_ok, kernels_lock=lock_ok, farm_parent=scratch_ok
            )
            try:
                lane_ok = resolve_lane("v9.99", "tcg", lock_ok)
                ok_term_before = signal.getsignal(signal.SIGTERM)
                ok_int_before = signal.getsignal(signal.SIGINT)
                signal.pthread_sigmask(
                    signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM}
                )
                try:
                    with _saved_tmpdir(scratch_ok):
                        try:
                            ok_got = verify_bytes(
                                image, lane_ok, runner_ok
                            )
                        except BaseException as exc:
                            ok_got = exc
                        ok_mask = signal.pthread_sigmask(
                            signal.SIG_BLOCK, set()
                        )
                        ok_leftovers = sorted(os.listdir(scratch_ok))
                        ok_term = signal.getsignal(signal.SIGTERM)
                        ok_int = signal.getsignal(signal.SIGINT)
                finally:
                    signal.pthread_sigmask(
                        signal.SIG_SETMASK, incoming
                    )
            finally:
                shutil.rmtree(runner_ok["farm"], ignore_errors=True)
    finally:
        shutil.rmtree(scratch_ok, ignore_errors=True)

    # Interruption: SIGTERM blocked, a real SIGINT delivered on the
    # staging-to-preparation transition.
    scratch_int = tempfile.mkdtemp(prefix="verify-r4mask-int-")
    try:
        with _fake_guest_run() as (_root, entry_int, lock_int):
            runner_int = verify_module._probe_vng(
                entry_int, kernels_lock=lock_int,
                farm_parent=scratch_int,
            )
            try:
                lane_int = resolve_lane("v9.99", "tcg", lock_int)
                source, first = inspect.getsourcelines(verify_bytes)
                matches = [
                    first + index
                    for index, text in enumerate(source)
                    if text.strip() == "assert stage is not None"
                ]
                assert len(matches) == 1, matches
                gap_line = matches[0]
                fired = []
                real_kill = os.kill
                code = verify_bytes.__code__

                def _tracer(frame, event, _arg):
                    if (
                        not fired
                        and event == "line"
                        and frame.f_code is code
                        and frame.f_lineno == gap_line
                    ):
                        fired.append(True)
                        real_kill(os.getpid(), signal.SIGINT)
                    return _tracer

                int_term_before = signal.getsignal(signal.SIGTERM)
                int_int_before = signal.getsignal(signal.SIGINT)
                signal.pthread_sigmask(
                    signal.SIG_BLOCK, {signal.SIGTERM}
                )
                try:
                    with _saved_tmpdir(scratch_int):
                        sys.settrace(_tracer)
                        try:
                            try:
                                verify_bytes(
                                    image, lane_int, runner_int
                                )
                            except BaseException as exc:
                                int_got = exc
                            else:
                                int_got = None
                        finally:
                            sys.settrace(None)
                        int_mask = signal.pthread_sigmask(
                            signal.SIG_BLOCK, set()
                        )
                        int_leftovers = sorted(os.listdir(scratch_int))
                        int_term = signal.getsignal(signal.SIGTERM)
                        int_int = signal.getsignal(signal.SIGINT)
                finally:
                    sys.settrace(None)
                    signal.pthread_sigmask(
                        signal.SIG_SETMASK, incoming
                    )
                    signal.signal(signal.SIGTERM, int_term_before)
                    signal.signal(signal.SIGINT, int_int_before)
            finally:
                shutil.rmtree(runner_int["farm"], ignore_errors=True)
    finally:
        shutil.rmtree(scratch_int, ignore_errors=True)

    assert isinstance(fail_got, VerifyError), repr(fail_got)
    assert "injected preparation failure" in str(fail_got), fail_got
    assert fail_mask == {signal.SIGINT, signal.SIGTERM}, fail_mask
    assert fail_term is previous_term, "SIGTERM handler leaked"
    assert fail_int is previous_int, "SIGINT handler leaked"
    assert fail_leftovers == [], fail_leftovers
    assert isinstance(ok_got, dict), repr(ok_got)
    assert ok_got["cleanup"]["staging_removed"] is True, ok_got
    assert ok_mask == {signal.SIGINT, signal.SIGTERM}, ok_mask
    assert ok_term is ok_term_before, "SIGTERM handler leaked"
    assert ok_int is ok_int_before, "SIGINT handler leaked"
    assert ok_leftovers == [], ok_leftovers
    assert fired, "staging-to-preparation transition never executed"
    assert isinstance(int_got, VerifyInterrupted), repr(int_got)
    assert "signal 2" in str(int_got), int_got
    assert int_mask == {signal.SIGTERM}, int_mask
    assert int_term is int_term_before, "SIGTERM handler leaked"
    assert int_int is int_int_before, "SIGINT handler leaked"
    assert int_leftovers == [], int_leftovers


def _transition_line():
    """Locate the staging-to-preparation transition line."""
    source, first = inspect.getsourcelines(verify_bytes)
    matches = [
        first + index
        for index, text in enumerate(source)
        if text.strip() == "assert stage is not None"
    ]
    assert len(matches) == 1, matches
    return matches[0]


def _r5_fire_sigint(target_line, invoke, scratch):
    """Deny stage removal, fire one real SIGINT at ``target_line``.

    ``invoke`` runs the verification under test; returns ``(fired,
    got, denied, after_term, after_int, previous_term,
    previous_int)``. Stage removals (``mojobpf-verify-*``) are
    refused and recorded in ``denied`` (owned by the caller);
    farm removals proceed for real.
    """
    real_rmtree = shutil.rmtree
    real_pinned = verify_module._remove_pinned_tree
    denied = []
    fired = []
    real_kill = os.kill
    code = verify_bytes.__code__

    def _denied_rmtree(path, *args, **kwargs):
        if os.path.basename(path).startswith("mojobpf-verify-"):
            denied.append(path)
            raise OSError("EACCES: keep-out for the test")
        return real_rmtree(path, *args, **kwargs)

    def _denied_pinned(path, pin):
        # Post-staging teardown goes through the fd-bound
        # pinned removal (A1M4-2), not shutil.rmtree; deny
        # the stage there with the same predicate so the
        # interruption report is still exercised. The seam
        # reports failures as error strings (never raises),
        # so the denial takes that same shape.
        if os.path.basename(path).startswith("mojobpf-verify-"):
            denied.append(path)
            return "%s: EACCES: keep-out for the test" % path
        return real_pinned(path, pin)

    def _tracer(frame, event, _arg):
        if (
            not fired
            and event == "line"
            and frame.f_code is code
            and frame.f_lineno == target_line
        ):
            fired.append(True)
            real_kill(os.getpid(), signal.SIGINT)
        return _tracer

    previous_term = signal.getsignal(signal.SIGTERM)
    previous_int = signal.getsignal(signal.SIGINT)
    shutil.rmtree = _denied_rmtree
    verify_module._remove_pinned_tree = _denied_pinned
    try:
        with _saved_tmpdir(scratch):
            sys.settrace(_tracer)
            try:
                try:
                    invoke()
                except BaseException as exc:
                    got = exc
                else:
                    got = None
            finally:
                sys.settrace(None)
            after_term = signal.getsignal(signal.SIGTERM)
            after_int = signal.getsignal(signal.SIGINT)
    finally:
        sys.settrace(None)
        shutil.rmtree = real_rmtree
        verify_module._remove_pinned_tree = real_pinned
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)
    return (
        fired, got, denied, after_term, after_int,
        previous_term, previous_int,
    )


def _r5_check_cleanup_reported(
    fired, got, denied, after_term, after_int,
    previous_term, previous_int, farm, line_label,
):
    """Shared R5 assertions: the denied stage is left behind and
    named exactly once on the interruption error."""
    assert fired, "%s line never executed" % line_label
    assert isinstance(got, VerifyInterrupted), repr(got)
    assert "signal 2" in str(got), got
    assert denied, "no stage removal was attempted"
    assert "staging cleanup failed" in str(got), got
    assert str(got).count("staging cleanup failed") == 1, got
    for path in denied:
        assert path in str(got), (path, got)
        assert str(got).count(path) == 1, (path, got)
        assert os.path.lexists(path), path
    assert not os.path.lexists(farm), farm
    assert after_term is previous_term, "SIGTERM handler leaked"
    assert after_int is previous_int, "SIGINT handler leaked"


def _r5_trace_via_bytes(target_line, line_label):
    """Run ``verify_bytes`` under a canned guest with a real SIGINT
    at ``target_line`` and stage removal denied."""
    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r5trace-")
    try:
        with _fake_guest_run() as (_root, entry, lock_path):
            runner = verify_module._probe_vng(
                entry, kernels_lock=lock_path, farm_parent=scratch
            )
            try:
                lane = resolve_lane("v9.99", "tcg", lock_path)
                observed = _r5_fire_sigint(
                    target_line,
                    lambda: verify_bytes(image, lane, runner),
                    scratch,
                )
                (fired, got, denied) = observed[:3]
                try:
                    _r5_check_cleanup_reported(
                        *observed, runner["farm"], line_label
                    )
                finally:
                    for path in denied:
                        shutil.rmtree(path, ignore_errors=True)
            finally:
                shutil.rmtree(runner["farm"], ignore_errors=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _r5_trace_via_request(target_line, line_label):
    """Run ``run_verification`` under a canned guest with a real
    SIGINT at ``target_line`` and stage removal denied."""
    image, _license_bytes = _synthetic_elf()
    scratch = tempfile.mkdtemp(prefix="verify-r5trace-")
    holding = tempfile.mkdtemp(prefix="verify-r5trace-obj-")
    try:
        with _fake_guest_run() as (_root, entry, lock_path):
            staged = os.path.join(holding, "probe.bpf.o")
            with open(staged, "wb") as handle:
                handle.write(image)
            request = VerifyRequest(
                object_path=staged,
                release="v9.99",
                vng_path=entry,
                require_btf="no",
                timeout=60,
                kernels_lock=lock_path,
            )
            observed = _r5_fire_sigint(
                target_line,
                lambda: run_verification(request),
                scratch,
            )
            (fired, got, denied) = observed[:3]
            farms = [
                name
                for name in os.listdir(scratch)
                if name.startswith("mojobpf-farm-")
            ]
            leftover_farm = (
                os.path.join(scratch, farms[0])
                if farms
                else os.path.join(scratch, "no-farm-left")
            )
            try:
                _r5_check_cleanup_reported(
                    fired, got, denied, *observed[3:7],
                    leftover_farm, line_label,
                )
                assert farms == [], farms
            finally:
                for path in denied:
                    shutil.rmtree(path, ignore_errors=True)
    finally:
        shutil.rmtree(holding, ignore_errors=True)
        shutil.rmtree(scratch, ignore_errors=True)


def test_r5_transition_sigint_reports_denied_stage_removal():
    """R5: a real SIGINT on the staging-to-preparation transition
    with stage removal denied reports the stage cleanup failure
    (not just the signal) through ``verify_bytes``."""
    _r5_trace_via_bytes(_transition_line(), "transition")


def test_r5_transition_sigint_reports_denied_stage_removal_request():
    """R5: the transition-trace cleanup report also surfaces
    through ``run_verification``."""
    _r5_trace_via_request(_transition_line(), "transition")


def test_r5_outer_run_try_sigint_reports_denied_stage_removal():
    """R5: a real SIGINT on the outer run-block ``try:`` line with
    stage removal denied reports the stage cleanup failure
    through ``verify_bytes``."""
    outer, _inner = _run_try_lines()
    _r5_trace_via_bytes(outer, "outer run-block try:")


def test_r5_inner_run_try_sigint_reports_denied_stage_removal():
    """R5: like the outer run-block ``try:`` trace, but firing
    independently on the nested ``try:`` line."""
    _outer, inner = _run_try_lines()
    _r5_trace_via_bytes(inner, "inner run-block try:")


def test_r5_inner_run_try_sigint_leaks_no_monitor():
    # A1M5-3 guard: a mid-run interruption (monitor armed)
    # leaves no inotify descriptor behind, whether the
    # signal-owned teardown or the exit backstop closes it.
    # A guard, not a red-green control: both closers predate
    # it; it pins the no-leak property instead.
    def _inotify_count():
        found = 0
        for name in os.listdir("/proc/self/fd"):
            try:
                target = os.readlink(
                    os.path.join("/proc/self/fd", name)
                )
            except OSError:
                continue
            if target == "anon_inode:inotify":
                found += 1
        return found

    before = _inotify_count()
    _outer, inner = _run_try_lines()
    _r5_trace_via_bytes(inner, "inner run-block try:")
    after = _inotify_count()
    assert after <= before, (before, after)


def test_r5_outer_run_try_sigint_reports_denied_stage_request():
    """R5: the outer run-block ``try:`` cleanup report also
    surfaces through ``run_verification``."""
    outer, _inner = _run_try_lines()
    _r5_trace_via_request(outer, "outer run-block try:")


def test_r5_inner_run_try_sigint_reports_denied_stage_request():
    """R5: the inner run-block ``try:`` cleanup report also
    surfaces through ``run_verification``."""
    _outer, inner = _run_try_lines()
    _r5_trace_via_request(inner, "inner run-block try:")


_QUIESCE_FIXTURE_SHOW = (
    "10: array  name libbpf_global  flags 0x0\n"
    "\tkey 4B  value 32B  max_entries 1  memlock 296B\n"
    "11: array  name pid_iter.rodata  flags 0x480\n"
    "\tkey 4B  value 4B  max_entries 1  memlock 8192B\n"
    "\tbtf_id 71  frozen\n"
    "\tpids bpftool(218)\n"
    "12: array  name libbpf_det_bind  flags 0x0\n"
    "\tkey 4B  value 32B  max_entries 1  memlock 296B\n"
    "30: array  name mojobpf_map0  flags 0x0\n"
    "\tkey 4B  value 8B  max_entries 2  memlock 4096B\n"
    "\tpids bpftool(219)\n"
)


def _quiesce_filter_program(script):
    match = re.search(
        r"bpftool map list 2>&1 \| awk '\n(.*?)'\n\}",
        script,
        re.S,
    )
    if match is None:
        raise AssertionError("quiesce map filter not found")
    return match.group(1)


def test_map_type_section_retained():
    """The guest template retains the complete map_type probe section.

    Unknown-name versus unavailable verdicts must be backed by the
    retained observation, not by bare assertions: the section holds
    every map_type line from feature.txt (or nothing when the probe
    produced none), framed in a marked block the record parses."""
    script = _rendered_script(map_types="arena")
    assert "=== BEGIN map-types ===" in script, script[-2000:]
    assert 'grep -F "map_type " ' in script, script[-2000:]
    assert "=== END map-types ===" in script, script[-2000:]
    canned = (
        "map_probe_line[arena]=eBPF map_type arena is available\n"
        "=== BEGIN map-types ===\n"
        "eBPF map_type hash is available\n"
        "eBPF map_type arena is available\n"
        "=== END map-types ===\n"
    )
    section = verify_module._parse_marked_block(canned, "map-types")
    assert section is not None, canned
    assert "eBPF map_type arena is available" in section, section
    assert "insn_array" not in section, section
    assert (
        verify_module._parse_marked_block("no block here", "map-types")
        is None
    )


def test_quiesce_comparison_filters_tool_owned_maps():
    """Quiesce compares filtered listings: bpftool 7.6 observes
    its own ephemeral iterator maps with per-run IDs/PIDs and
    leaks its skeleton maps, so raw consecutive listings never
    repeat and quiesce always fails. The embedded filter drops
    exactly the tool-owned entries; suite maps pass through."""
    if shutil.which("awk") is None:
        raise AssertionError("awk is required for this test")
    script = _rendered_script()
    assert "bpftool map list 2>&1;" not in script, (
        "quiesce CUR captures raw map list"
    )
    program = _quiesce_filter_program(script)
    proc = subprocess.run(
        ["awk", program],
        input=_QUIESCE_FIXTURE_SHOW,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr[-500:]
    filtered = proc.stdout
    for name in ("libbpf_global", "pid_iter", "det_bind"):
        assert name not in filtered, filtered
    assert "pids" not in filtered, filtered
    assert "mojobpf_map0" in filtered, filtered


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
