# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Reproducibility, restricted-environment, and cleanup proofs.

This suite owns three behaviors of the load-and-unload workflow:

* Reproducible builds: the same pinned inputs built in two clean
  absolute paths produce byte-identical objects, both through the
  direct frontend/adapter/backend pipeline and through a manifest
  ``mojobpf build``. Stage paths must not leak into object bytes.
* Restricted environments: a load without privilege, a BTF-carrying
  object without kernel BTF, a program type the guest kernel lacks,
  and a guest command that exceeds its budget each produce their own
  accurate ``unavailable``/``timeout`` result -- never a pass, never
  a crash.
* Cleanup: repeated load/test/unload cycles leave the owned guest
  resources (programs, maps, links, pins) exactly as found, and
  interrupting the wrapper mid-run (SIGTERM) or killing its runner
  child (SIGKILL) reaps the whole runner group with no stray host
  emulator processes.

It also proves the wrapper's loader-versus-verifier classification
with real failing inputs: a truncated object and a non-ELF file
classify as ``loader``, while a Mojo-authored out-of-bounds store
(which the genuine pipeline builds but the kernel verifier rejects)
classifies as ``verifier`` with its predicted log line.

Every kernel interaction goes through the real ``mojobpf verify
--kernel`` command (checkout CLI) or the frozen test-run harness
(contract revision 2, used as-is) inside disposable guests. Nothing
here attaches a hook, runs a live workload, or loads on the host.

Requires working ``mojo``/``llc``, ``vng`` (virtme-ng) with a
cached guest image on PATH (default release v6.12;
MOJOBPF_VNG_RELEASE selects the matrix lane), and an unprivileged
``nobody`` account in the guest. Missing tools fail loudly as
environment failures, never as passes.

Runnable directly (``python3 tests/kernel/test_cleanup.py``) or
under any ``test_``-style runner. Standard library only.
"""

import difflib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
EXAMPLE_DIR = os.path.join(REPO_ROOT, "examples", "xdp_pass")
CLASSIFIER_SOURCE = os.path.join(EXAMPLE_DIR, "xdp_pass.mojo")
MAP_SOURCE = os.path.join(REPO_ROOT, "tests", "compile", "map_roundtrip.mojo")
OOB_SOURCE = os.path.join(
    REPO_ROOT, "tests", "compile", "subset", "subset_oob_store.mojo"
)
CONSUMER_DIR = os.path.join(
    REPO_ROOT, "tests", "packaging", "external_consumer"
)
ADAPTER = os.path.join(REPO_ROOT, "compiler", "mojo_ir_adapter.py")
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")
SDK_INCLUDE = os.path.join(
    REPO_ROOT, "src", "mojobpf", "resources", "sdk"
)

# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
GUEST_KERNEL_PREFIX = (
    VNG_RELEASE[1:] if VNG_RELEASE.startswith("v") else VNG_RELEASE
)
VNG_TIMEOUT = 900

XDP_DROP = 1
XDP_PASS = 2

# Pinned genuine-pipeline object hashes (the feasibility baseline):
# reproducibility must reproduce these exact bytes, not merely agree
# with itself.
EXPECTED_CLASSIFIER_OBJECT = (
    "17570ee79a16b64ccc4f723d00d26ae316a286cffdd3382ba3a6e6b4be95097c"
)
EXPECTED_MAP_OBJECT = (
    "18f7490634c6462360aafcb1ece85406b2374b4b74a2ca4501f90b5781e8a540"
)
EXPECTED_OOB_LOG_LINE = (
    "invalid access to map value, value_size=8 off=8 size=8"
)

# A real program type (probed by bpftool from its known list) that
# the pinned guest kernels do not support.
UNSUPPORTED_PROG_TYPE = "lirc_mode2"

REPEAT_CYCLES = 5


class EnvironmentFailure(Exception):
    """The toolchain or VM needed by this test is missing or broken."""


def sha256_file(path):
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_step(argv, timeout=600, env=None, cwd=None):
    return subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        env=env,
        cwd=cwd,
    )


def check_tools():
    for tool in ("mojo", "llc", "vng"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure("%s not found on PATH" % tool)
    for path in (
        CLASSIFIER_SOURCE,
        MAP_SOURCE,
        OOB_SOURCE,
        ADAPTER,
        HARNESS,
        os.path.join(CONSUMER_DIR, "mojobpf.toml"),
        os.path.join(CONSUMER_DIR, "canary.mojo"),
    ):
        if not os.path.isfile(path):
            raise EnvironmentFailure("missing repo file: %s" % path)
    if not os.path.isdir(SDK_INCLUDE):
        raise EnvironmentFailure("missing SDK directory: %s" % SDK_INCLUDE)


def build_object(source, workdir, name, include_sdk):
    """Build one object through the genuine pipeline."""
    raw_path = os.path.join(workdir, name + ".ll")
    adapted_path = os.path.join(workdir, name + ".bpf.ll")
    object_path = os.path.join(workdir, name + ".bpf.o")
    frontend = ["mojo", "build", "--emit", "llvm"]
    if include_sdk:
        frontend += ["-I", SDK_INCLUDE]
    frontend += ["-o", raw_path, source]
    proc = run_step(frontend)
    if proc.returncode != 0 or not os.path.isfile(raw_path):
        raise AssertionError(
            "frontend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    if "error:" in proc.stderr.lower() or "warning:" in proc.stderr.lower():
        raise AssertionError(
            "frontend diagnostics for %s:\n%s" % (source, proc.stderr)
        )
    proc = run_step(
        [sys.executable, ADAPTER, "--input", raw_path, "--output", adapted_path]
    )
    if proc.returncode != 0 or not os.path.isfile(adapted_path):
        raise AssertionError(
            "adapter failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    proc = run_step(
        [
            "llc",
            "-mtriple=bpfel",
            "-mcpu=v3",
            "-filetype=obj",
            adapted_path,
            "-o",
            object_path,
        ]
    )
    if proc.returncode != 0 or not os.path.isfile(object_path):
        raise AssertionError(
            "backend failed for %s (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )
    return {
        "raw": raw_path,
        "adapted": adapted_path,
        "object": object_path,
    }


_FIXTURE = {}


def fixture():
    """Build the shared objects once per process; return their paths."""
    if "stage" in _FIXTURE:
        return _FIXTURE
    check_tools()
    stage = tempfile.mkdtemp(prefix="mojo-cleanup-", dir="/tmp")
    built = {}
    built["classifier"] = build_object(
        CLASSIFIER_SOURCE, stage, "classifier", include_sdk=False
    )
    built["map"] = build_object(
        MAP_SOURCE, stage, "map", include_sdk=True
    )
    built["oob"] = build_object(
        OOB_SOURCE, stage, "oob", include_sdk=True
    )
    with open(built["classifier"]["object"], "rb") as handle:
        head = handle.read(300)
    trunc_path = os.path.join(stage, "truncated.bpf.o")
    with open(trunc_path, "wb") as handle:
        handle.write(head)
    text_path = os.path.join(stage, "not-an-object.txt")
    with open(text_path, "w", encoding="utf-8") as handle:
        handle.write("this file is not an ELF object\n")
    for fixture_name in ("pkt_drop.bin", "pkt_pass.bin"):
        with open(os.path.join(EXAMPLE_DIR, fixture_name), "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, fixture_name), "wb") as handle:
            handle.write(data)
    for name in os.listdir(stage):
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    _FIXTURE.update(
        {
            "stage": stage,
            "built": built,
            "truncated": trunc_path,
            "text": text_path,
        }
    )
    return _FIXTURE


def cli_env():
    """Environment that runs the checkout CLI without installing it."""
    env = dict(os.environ)
    src_dir = os.path.join(REPO_ROOT, "src")
    previous = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        src_dir if not previous else src_dir + os.pathsep + previous
    )
    return env


def verify_cli(extra_args, timeout=600):
    """Run the real ``mojobpf verify --kernel``; return (exit, record).

    ``record`` is the parsed JSON result (``--json`` is always
    passed); the raw outputs ride along as ``_stdout``/``_stderr``.
    """
    argv = [
        sys.executable,
        "-m",
        "mojobpf.cli",
        "verify",
        "--kernel",
        "--release",
        VNG_RELEASE,
        "--json",
    ] + list(extra_args)
    proc = run_step(argv, timeout=timeout, env=cli_env(), cwd=REPO_ROOT)
    try:
        record = json.loads(proc.stdout)
    except ValueError:
        raise AssertionError(
            "verify printed invalid JSON (exit %d):\nstdout:\n%s\nstderr:\n%s"
            % (proc.returncode, proc.stdout[-2000:], proc.stderr[-2000:])
        )
    record["_exit"] = proc.returncode
    record["_stderr"] = proc.stderr
    return proc.returncode, record


def guest_exec(script_text, name, timeout=VNG_TIMEOUT):
    """Boot one guest running ``script_text``; return the transcript."""
    fix = fixture()
    script_path = os.path.join(fix["stage"], name)
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script_text)
    os.chmod(script_path, 0o644)
    try:
        proc = subprocess.run(
            ["vng", "--run", VNG_RELEASE, "--disable-kvm",
             "--exec", "bash %s" % script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise EnvironmentFailure(
            "vng guest run timed out after %ds (stage kept at %s):\n%s"
            % (
                timeout,
                fix["stage"],
                (exc.stdout or "") + (exc.stderr or ""),
            )
        )
    output = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "vng guest run failed (exit %d, stage kept at %s):\n%s"
            % (proc.returncode, fix["stage"], output[-4000:])
        )
    return output


def live_processes():
    """Snapshot live (non-zombie) host processes as {pid: cmdline}."""
    found = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % entry, encoding="utf-8") as handle:
                fields = handle.read().rsplit(")", 1)
            with open(
                "/proc/%s/cmdline" % entry, "rb"
            ) as handle:
                cmdline = handle.read().replace(b"\x00", b" ").decode(
                    "utf-8", "replace"
                )
        except OSError:
            continue
        if len(fields) != 2:
            continue
        state = fields[1].split()[0] if fields[1].split() else ""
        if state in ("Z", "X"):
            continue
        found[int(entry)] = cmdline
    return found


def runner_pids(snapshot):
    """Pids in a snapshot that belong to guest runners/emulators."""
    return {
        pid
        for pid, cmdline in snapshot.items()
        if "qemu-system-" in cmdline
        or "vng --run" in cmdline
        or "virtme-run" in cmdline
    }


def fd_count():
    return len(os.listdir("/proc/self/fd"))


def assert_guest_lane(record, where):
    kernel = (record.get("guest") or {}).get("kernel") or ""
    assert kernel.startswith(GUEST_KERNEL_PREFIX), (
        "%s: guest kernel %r must start with %r (release %s)"
        % (where, kernel, GUEST_KERNEL_PREFIX, VNG_RELEASE)
    )
    return kernel


def assert_no_never_tokens(commands, where):
    never = (
        "attach",
        "detach",
        "prog run",
        "link pin",
        "map pin",
        "net attach",
        "tc filter",
        "test-run",
    )
    for command in commands:
        for token in never:
            assert token not in command, (
                "%s: guest command carries forbidden %r: %r"
                % (where, token, command)
            )


def test_reproducible_two_paths():
    """Same pinned inputs in two clean paths: identical objects."""
    fix = fixture()
    dir_a = tempfile.mkdtemp(prefix="t016-a-")
    deep = tempfile.mkdtemp(prefix="t016-b-much-longer-prefix-")
    dir_b = os.path.join(deep, "nested", "deeper")
    os.makedirs(dir_b)
    assert len(os.path.abspath(dir_b)) > len(
        os.path.abspath(dir_a)
    ) + 20, "the two paths must differ in length too"
    try:
        for key, source, include_sdk, expected in (
            (
                "classifier",
                CLASSIFIER_SOURCE,
                False,
                EXPECTED_CLASSIFIER_OBJECT,
            ),
            ("map", MAP_SOURCE, True, EXPECTED_MAP_OBJECT),
        ):
            built_a = build_object(source, dir_a, key, include_sdk)
            built_b = build_object(source, dir_b, key, include_sdk)
            hash_a = sha256_file(built_a["object"])
            hash_b = sha256_file(built_b["object"])
            assert hash_a == hash_b, (
                "%s: %s (%s) != %s (%s)"
                % (key, hash_a, dir_a, hash_b, dir_b)
            )
            assert hash_a == expected, (
                "%s: reproduced %s, feasibility pin is %s"
                % (key, hash_a, expected)
            )
            # The shared fixture object must equal the same bytes:
            # one pipeline, one answer, however many directories.
            assert sha256_file(fix["built"][key]["object"]) == expected, (
                "%s: fixture object drifted from the pin" % key
            )
            with open(built_a["object"], "rb") as handle:
                image = handle.read()
            for path in (
                os.path.abspath(dir_a),
                os.path.abspath(dir_b),
            ):
                assert path.encode() not in image, (
                    "%s: stage path leaks into object bytes: %s" % (key, path)
                )
            print(
                "PASS two-path %s identical: %s (ir %s/%s)" % (
                    key,
                    hash_a[:16],
                    sha256_file(built_a["raw"])[:12],
                    sha256_file(built_a["adapted"])[:12],
                )
            )
    finally:
        shutil.rmtree(dir_a, ignore_errors=True)
        shutil.rmtree(deep, ignore_errors=True)


def test_reproducible_manifest_build():
    """A manifest build in two clean paths: identical objects."""
    check_tools()
    roots = []
    objects = []
    sidecars = []
    try:
        for index in range(2):
            root = tempfile.mkdtemp(
                prefix="t016-manifest-%d-with-a-longer-tail-" % index
            )
            roots.append(root)
            project = os.path.join(root, "project")
            out_dir = os.path.join(root, "out")
            os.makedirs(project)
            for name in ("mojobpf.toml", "canary.mojo"):
                with open(
                    os.path.join(CONSUMER_DIR, name), "rb"
                ) as handle:
                    data = handle.read()
                with open(os.path.join(project, name), "wb") as handle:
                    handle.write(data)
            proc = run_step(
                [
                    sys.executable,
                    "-m",
                    "mojobpf.cli",
                    "build",
                    "--manifest",
                    os.path.join(project, "mojobpf.toml"),
                    "--out-dir",
                    out_dir,
                    "--lockfile",
                    os.path.join(REPO_ROOT, "toolchains.lock.json"),
                ],
                timeout=900,
                env=cli_env(),
                cwd=REPO_ROOT,
            )
            assert proc.returncode == 0, (
                "manifest build %d failed (exit %d):\n%s\n%s"
                % (index, proc.returncode, proc.stdout, proc.stderr)
            )
            found = sorted(
                entry
                for entry in os.listdir(out_dir)
                if entry.endswith(".bpf.o")
            )
            assert len(found) == 1, (index, found)
            objects.append(os.path.join(out_dir, found[0]))
            sidecar = os.path.join(
                out_dir, found[0].replace(".bpf.o", ".evidence.json")
            )
            assert os.path.isfile(sidecar), (index, os.listdir(out_dir))
            sidecars.append(sidecar)
        hash_0 = sha256_file(objects[0])
        hash_1 = sha256_file(objects[1])
        assert hash_0 == hash_1, (hash_0, hash_1)
        with open(objects[0], "rb") as handle:
            image = handle.read()
        for root in roots:
            assert os.path.abspath(root).encode() not in image, (
                "build root leaks into object bytes: %s" % root
            )
            assert os.path.abspath(root).encode() not in open(
                sidecars[0], "rb"
            ).read(), "build root leaks into sidecar bytes: %s" % root
        # The evidence sidecar carries no absolute build paths, so it
        # is identical too -- stronger than the object-only rule.
        sidecar_0 = sha256_file(sidecars[0])
        sidecar_1 = sha256_file(sidecars[1])
        assert sidecar_0 == sidecar_1, (sidecar_0, sidecar_1)
        print(
            "PASS manifest two-path identical: object %s sidecar %s"
            % (hash_0[:16], sidecar_0[:16])
        )
    finally:
        for root in roots:
            shutil.rmtree(root, ignore_errors=True)


def test_verify_load_unload_pass():
    """Positive control: the wrapper loads and unloads, then proves it."""
    fix = fixture()
    expected = sha256_file(fix["built"]["classifier"]["object"])
    exit_code, record = verify_cli(
        ["--object", fix["built"]["classifier"]["object"]]
    )
    assert exit_code == 0, json.dumps(record, indent=2)[-3000:]
    assert record["status"] == "pass", record["status"]
    assert record["stage"] == "done", record["stage"]
    assert record["classification"] is None, record["classification"]
    assert record["object"]["sha256"] == expected, "hash must match inputs"
    kernel = assert_guest_lane(record, "pass control")
    assert record["guest"]["btf"] == "present", record["guest"]
    assert record["guest"]["prog_type_supported"] is True, record["guest"]
    assert record["load"]["attempted"] is True, record["load"]
    assert record["load"]["exit"] == 0, record["load"]
    assert record["unload"]["attempted"] is True, record["unload"]
    assert record["unload"]["pin_absent"] is True, record["unload"]
    assert record["unload"]["quiesced"] is True, record["unload"]
    print(
        "unload quiesced after %s polls"
        % (record["unload"]["quiesce_waits"],)
    )
    commands = record["guest_commands"]
    assert any("prog load" in item for item in commands), commands
    assert any(item.startswith("rm -f ") for item in commands), commands
    assert_no_never_tokens(commands, "pass control")
    res_before = record["resources"]["before"] or ""
    res_after = record["resources"]["after"] or ""
    assert "mojobpf" not in res_before, res_before
    assert "mojobpf" not in res_after, res_after
    if res_before != res_after:
        diff = "".join(
            difflib.unified_diff(
                res_before.splitlines(True),
                res_after.splitlines(True),
                "res-before",
                "res-after",
            )
        )
        raise AssertionError(
            "a lone load/unload must leave guest resources unchanged:\n%s"
            % diff
        )
    print("PASS load/unload on %s, %d guest commands" % (kernel, len(commands)))


def test_verify_loader_classification():
    """Real unloadable inputs classify as loader (exit 5), twice."""
    fix = fixture()
    for label, path in (
        ("truncated", fix["truncated"]),
        ("text", fix["text"]),
    ):
        exit_code, record = verify_cli(["--object", path])
        assert exit_code == 5, (label, exit_code, record["status"])
        assert record["status"] == "load-failed", (label, record["status"])
        assert record["stage"] == "load", (label, record["stage"])
        assert record["classification"] == "loader", (
            label, record["classification"], record["load"],
        )
        assert record["load"]["attempted"] is True, (label, record["load"])
        assert record["load"]["exit"] != 0, (label, record["load"])
        assert record["unload"]["attempted"] is False, (label, record)
        assert_guest_lane(record, label)
        print(
            "PASS loader %s: exit=%s log=%r" % (
                label,
                record["load"]["exit"],
                (record["load"]["log_excerpt"] or "").splitlines()[:1],
            )
        )


def test_verify_verifier_classification():
    """A Mojo oob store classifies as verifier (exit 4) with its line."""
    fix = fixture()
    exit_code, record = verify_cli(
        ["--object", fix["built"]["oob"]["object"]]
    )
    assert exit_code == 4, (exit_code, record["status"])
    assert record["status"] == "load-failed", record["status"]
    assert record["stage"] == "load", record["stage"]
    assert record["classification"] == "verifier", (
        record["classification"], record["load"],
    )
    assert record["load"]["attempted"] is True, record["load"]
    assert record["unload"]["attempted"] is False, record
    assert_guest_lane(record, "verifier proof")
    log = record["load"]["log_excerpt"] or ""
    assert EXPECTED_OOB_LOG_LINE in log, (
        "kernel verifier log must carry the predicted line:\n%s" % log[-2000:]
    )
    print("PASS verifier rejection carries %r" % EXPECTED_OOB_LOG_LINE)


def test_unprivileged_load_unavailable():
    """A load without privilege: environment, never a pass."""
    fix = fixture()
    exit_code, record = verify_cli(
        [
            "--object",
            fix["built"]["classifier"]["object"],
            "--as-user",
            "nobody",
        ]
    )
    assert exit_code == 3, (exit_code, record["status"])
    assert record["status"] == "load-failed", record["status"]
    assert record["stage"] == "load", record["stage"]
    assert record["classification"] == "environment", (
        record["classification"], record["load"],
    )
    assert record["load"]["attempted"] is True, record["load"]
    assert record["load"]["exit"] != 0, record["load"]
    assert record["unload"]["attempted"] is False, record
    assert_guest_lane(record, "unprivileged")
    # The guest itself runs privileged; only the load dropped to
    # nobody (the recorded guest command proves which side ran as
    # whom).
    assert record["guest"]["id"] == "0:0", record["guest"]
    assert any("setpriv" in item for item in record["guest_commands"]), (
        record["guest_commands"]
    )
    print("PASS unprivileged load denied as environment")


def test_missing_btf_unavailable():
    """A BTF object without kernel BTF: unavailable; policy proven."""
    fix = fixture()
    # The refusal: a .BTF-carrying object with no kernel BTF at the
    # checked path is unavailable, and no load is attempted.
    exit_code, record = verify_cli(
        [
            "--object",
            fix["built"]["map"]["object"],
            "--kernel-btf",
            "/nonexistent-btf-for-test",
        ]
    )
    assert exit_code == 3, (exit_code, record["status"])
    assert record["status"] == "unavailable", record["status"]
    assert record["stage"] == "preflight", record["stage"]
    assert record["classification"] == "environment", record["classification"]
    assert record["preflight"]["unavailable_reason"] == "missing-btf", (
        record["preflight"]
    )
    assert record["load"]["attempted"] is False, record["load"]
    assert record["guest"]["btf"] == "absent", record["guest"]
    assert_guest_lane(record, "missing-btf")
    # Auto mode only requires BTF for objects that carry BTF
    # sections: the classifier (no .BTF) proceeds on the same path.
    exit_code, record = verify_cli(
        [
            "--object",
            fix["built"]["classifier"]["object"],
            "--kernel-btf",
            "/nonexistent-btf-for-test",
        ]
    )
    assert exit_code == 0, (exit_code, record["status"])
    assert record["status"] == "pass", record["status"]
    assert (
        record["preflight"]["require_btf_effective"] is False
    ), record["preflight"]
    # The refusal is wrapper policy, not a kernel verdict: with the
    # requirement lifted the same BTF object loads (the kernel
    # accepts BTF-annotated loads without its own BTF -- observed).
    exit_code, record = verify_cli(
        [
            "--object",
            fix["built"]["map"]["object"],
            "--kernel-btf",
            "/nonexistent-btf-for-test",
            "--require-btf",
            "no",
        ]
    )
    assert exit_code == 0, (exit_code, record["status"])
    assert record["status"] == "pass", record["status"]
    print("PASS missing-btf unavailable; auto/no semantics proven")


def test_unsupported_prog_type_unavailable():
    """A program type the kernel lacks: unavailable, no load."""
    fix = fixture()
    exit_code, record = verify_cli(
        [
            "--object",
            fix["built"]["classifier"]["object"],
            "--prog-type",
            UNSUPPORTED_PROG_TYPE,
        ]
    )
    assert exit_code == 3, (exit_code, record["status"])
    assert record["status"] == "unavailable", record["status"]
    assert record["stage"] == "preflight", record["stage"]
    assert record["classification"] == "environment", record["classification"]
    assert (
        record["preflight"]["unavailable_reason"] == "unsupported-prog-type"
    ), record["preflight"]
    assert record["load"]["attempted"] is False, record["load"]
    assert record["guest"]["prog_type_supported"] is False, record["guest"]
    # bpftool probed the type by name and reported it missing: this
    # is a real unsupported type, not a misspelled flag.
    probe = record["guest"]["probe_line"] or ""
    assert UNSUPPORTED_PROG_TYPE in probe, record["guest"]
    assert "NOT available" in probe, record["guest"]
    assert_guest_lane(record, "unsupported-prog-type")
    # Positive control on the same lane: xdp is supported.
    exit_code, control = verify_cli(
        [
            "--object",
            fix["built"]["classifier"]["object"],
            "--prog-type",
            "xdp",
        ]
    )
    assert exit_code == 0, (exit_code, control["status"])
    assert control["guest"]["prog_type_supported"] is True, control["guest"]
    print("PASS unsupported type refused; xdp control passes")


def test_harness_timeout():
    """A guest command past its budget: timeout, group reaped."""
    fix = fixture()
    before = runner_pids(live_processes())
    exit_code, record = verify_cli(
        ["--object", fix["built"]["classifier"]["object"], "--timeout", "5"],
        timeout=300,
    )
    assert exit_code == 3, (exit_code, record["status"])
    assert record["status"] == "timeout", record["status"]
    assert record["stage"] == "run", record["stage"]
    assert record["classification"] == "environment", record["classification"]
    assert record["child"]["timed_out"] is True, record["child"]
    assert record["child"]["group_killed"] is True, record["child"]
    assert record["child"]["group_reaped"] is True, record["child"]
    members = record["child"]["group_members"] or []
    assert all(
        item["state"] in ("Z", "X") for item in members
    ), ("live group members after timeout kill", members)
    survivors = runner_pids(live_processes()) - before
    assert not survivors, ("stray runner processes", survivors)
    print(
        "PASS timeout reaped the group (residual members: %s)" % (members,)
    )


REPEAT_GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin guest_repeat ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
sha256sum bpf_test_run.py repeat.bpf.o pkt_drop.bin pkt_pass.bin
snapshot() {{
  echo "--- progs ---"
  bpftool prog list 2>&1
  echo "--- maps ---"
  bpftool map list 2>&1
  echo "--- links ---"
  bpftool link list 2>&1
  echo "--- pins ---"
  ls /sys/fs/bpf/ 2>&1
}}
echo "=== BEGIN res-before ==="
snapshot
echo "=== END res-before ==="
FAILURES=0
for i in $(seq 1 {cycles}); do
  for case in drop:1:pkt_drop pass:2:pkt_pass; do
    tag="${{case%%:*}}"; rest="${{case#*:}}"; expect="${{rest%%:*}}"; data="${{rest#*:}}"
    out="/tmp/repeat-$tag-$i.json"
    python3 bpf_test_run.py --object repeat.bpf.o --expect-action "$expect" \\
      --data-in "$data.bin" --output "$out" >/tmp/repeat-$tag-$i.stdout 2>/tmp/repeat-$tag-$i.stderr
    code=$?
    echo "=== BEGIN cycle-$tag-$i exit=$code ==="
    cat "$out"
    echo "=== END cycle-$tag-$i ==="
    if [ "$code" -ne 0 ]; then FAILURES=$((FAILURES + 1)); fi
  done
  pin="/sys/fs/bpf/mojobpf_repeat_$i"
  bpftool prog load repeat.bpf.o "$pin" >/tmp/repeat-plain-$i.log 2>&1 || FAILURES=$((FAILURES + 1))
  rm -f "$pin"
  if [ -e "$pin" ]; then FAILURES=$((FAILURES + 1)); fi
done
echo "plain/harness failures: $FAILURES"
# Pin removal is synchronous, but the kernel may free programs
# asynchronously (observed: still listed for ~2s under emulation),
# so quiesce on stable listings before the after-snapshot.
QUIESCED=0
QUIESCE_WAITS=0
PREV="__unset__"
for i in $(seq 1 60); do
  QUIESCE_WAITS=$i
  if ls /sys/fs/bpf/mojobpf* >/dev/null 2>&1; then sleep 1; continue; fi
  CUR=$(bpftool prog list 2>&1; bpftool map list 2>&1; bpftool link list 2>&1)
  if [ "$PREV" != "__unset__" ] && [ "$CUR" = "$PREV" ]; then
    QUIESCED=1
    break
  fi
  PREV="$CUR"
  sleep 1
done
echo "quiesced=$QUIESCED"
echo "quiesce_waits=$QUIESCE_WAITS"
echo "=== BEGIN res-after ==="
snapshot
echo "=== END res-after ==="
echo "=== end guest_repeat ==="
"""


def test_repeated_load_unload_no_leak():
    """Repeated load/test/unload cycles: owned resources unchanged."""
    fix = fixture()
    before = runner_pids(live_processes())
    stage = fix["stage"]
    for name, src in (
        ("bpf_test_run.py", HARNESS),
        ("repeat.bpf.o", fix["built"]["classifier"]["object"]),
    ):
        with open(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
        os.chmod(os.path.join(stage, name), 0o644)
    expected_obj = sha256_file(os.path.join(stage, "repeat.bpf.o"))
    expected_drop = sha256_file(os.path.join(stage, "pkt_drop.bin"))
    expected_pass = sha256_file(os.path.join(stage, "pkt_pass.bin"))
    output = guest_exec(
        REPEAT_GUEST_SCRIPT.format(stage=stage, cycles=REPEAT_CYCLES),
        "guest_repeat.sh",
    )
    assert "guest-kernel: %s" % GUEST_KERNEL_PREFIX in output, (
        "guest kernel must be v%s" % GUEST_KERNEL_PREFIX
    )
    for digest in (expected_obj, expected_drop, expected_pass):
        assert digest in output, "guest must re-verify staged hash %s" % digest
    cycles = {}
    for match in re.finditer(
        r"=== BEGIN (\S+) exit=(\d+) ===\n(.*?)\n=== END \1 ===",
        output,
        re.DOTALL,
    ):
        tag, exit_code, body = match.groups()
        cycles[tag] = (int(exit_code), json.loads(body))
    want = REPEAT_CYCLES * 2
    assert len(cycles) == want, (
        "expected %d harness cycles, found %d" % (want, len(cycles))
    )
    for tag, (exit_code, record) in sorted(cycles.items()):
        assert exit_code == 0, (tag, exit_code, record)
        assert record["status"] == "pass", (tag, record)
        assert record["cleanup_ok"] is True, (tag, record)
        assert record["contract_version"] == 2, (tag, record)
    assert "plain/harness failures: 0" in output, output[-2000:]
    assert "\nquiesced=1\n" in output, (
        "guest resources must quiesce after the cycles"
    )
    waits = re.search(r"^quiesce_waits=(\d+)$", output, re.MULTILINE)
    print("repeat quiesced after %s polls" % (waits.group(1) if waits else "?"))
    before_block = re.search(
        r"=== BEGIN res-before ===\n(.*?)\n=== END res-before ===",
        output,
        re.DOTALL,
    )
    after_block = re.search(
        r"=== BEGIN res-after ===\n(.*?)\n=== END res-after ===",
        output,
        re.DOTALL,
    )
    assert before_block and after_block, "guest must print both snapshots"
    res_before = before_block.group(1)
    res_after = after_block.group(1)
    assert "mojobpf" not in res_before, res_before
    assert "mojobpf" not in res_after, res_after
    if res_before != res_after:
        diff = "".join(
            difflib.unified_diff(
                res_before.splitlines(True),
                res_after.splitlines(True),
                "res-before",
                "res-after",
            )
        )
        raise AssertionError(
            "owned guest resources changed across %d cycles:\n%s"
            % (REPEAT_CYCLES, diff)
        )
    survivors = runner_pids(live_processes()) - before
    assert not survivors, ("stray runner processes", survivors)
    print(
        "PASS %d harness + %d plain cycles, guest resources identical"
        % (want, REPEAT_CYCLES)
    )


def _spawn_wrapper(object_path, extra_args):
    argv = [
        sys.executable,
        "-m",
        "mojobpf.cli",
        "verify",
        "--kernel",
        "--release",
        VNG_RELEASE,
        "--timeout",
        "600",
        "--object",
        object_path,
    ] + list(extra_args)
    return subprocess.Popen(
        argv,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=cli_env(),
        cwd=REPO_ROOT,
        start_new_session=True,
    )


def _wait_for_runner(baseline, timeout=180):
    """Wait for a new runner pid; return it."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        fresh = runner_pids(live_processes()) - baseline
        if fresh:
            return sorted(fresh)[0]
        time.sleep(1)
    raise EnvironmentFailure(
        "no guest runner appeared within %ds" % timeout
    )


def _wait_for_pids_gone(pids, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        live = {
            pid
            for pid in pids
            if os.path.isdir("/proc/%d" % pid)
            and _pid_state(pid) not in ("Z", "X")
        }
        if not live:
            return set()
        time.sleep(1)
    return live


def _pid_state(pid):
    try:
        with open("/proc/%d/stat" % pid, encoding="utf-8") as handle:
            fields = handle.read().rsplit(")", 1)
    except OSError:
        return None
    if len(fields) != 2 or not fields[1].split():
        return None
    return fields[1].split()[0]


def test_interrupt_sigterm_reaps():
    """SIGTERM mid-run: the wrapper exits 130 with no stray runners."""
    fix = fixture()
    baseline = runner_pids(live_processes())
    fds_before = fd_count()
    proc = _spawn_wrapper(fix["built"]["classifier"]["object"], [])
    try:
        runner = _wait_for_runner(baseline)
        proc.send_signal(signal.SIGTERM)
        try:
            exit_code = proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            raise AssertionError(
                "wrapper ignored SIGTERM (runner was %d)" % runner
            )
        assert exit_code == 130, (
            "interrupted wrapper must exit 130, got %r" % (exit_code,)
        )
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    leftover = _wait_for_pids_gone({runner}, timeout=60)
    assert not leftover, ("runner survived the interrupt", leftover)
    survivors = runner_pids(live_processes()) - baseline
    assert not survivors, ("stray runner processes", survivors)
    assert fd_count() == fds_before, "test leaked file descriptors"
    print("PASS SIGTERM reaped runner %d; exit 130, no strays" % runner)


def test_killed_child_no_hang():
    """A SIGKILLed runner child: the wrapper fails fast, no strays."""
    fix = fixture()
    baseline = runner_pids(live_processes())
    proc = _spawn_wrapper(fix["built"]["classifier"]["object"], [])
    try:
        runner = _wait_for_runner(baseline)
        try:
            os.kill(runner, signal.SIGKILL)
        except ProcessLookupError:
            raise AssertionError("runner %d vanished before the kill" % runner)
        start = time.monotonic()
        try:
            exit_code = proc.wait(timeout=180)
        except subprocess.TimeoutExpired:
            raise AssertionError(
                "wrapper hung after its runner died (runner %d)" % runner
            )
        elapsed = time.monotonic() - start
        assert exit_code != 0, "wrapper must not pass a dead runner"
        assert exit_code in (2, 3), (
            "wrapper must fail as setup/environment, got %r" % (exit_code,)
        )
        assert elapsed < 120, (
            "wrapper must fail fast on a dead runner, took %.1fs" % elapsed
        )
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    leftover = _wait_for_pids_gone({runner}, timeout=60)
    assert not leftover, ("runner survived SIGKILL", leftover)
    survivors = runner_pids(live_processes()) - baseline
    assert not survivors, ("stray runner processes", survivors)
    print(
        "PASS killed runner %d: wrapper exit %d, no strays, no hang"
        % (runner, exit_code)
    )


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    for name, func in sorted(
        [(k, v) for k, v in globals().items() if k.startswith("test_")]
    ):
        try:
            func()
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
    print("cleanup: reproducibility, restriction, and interruption proofs")
    if "stage" in _FIXTURE:
        print("guest stage kept at: %s" % _FIXTURE["stage"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
