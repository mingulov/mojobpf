# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""WP-4 exit gate: hostile inputs replayed end-to-end (Task 13).

One test per gap exit item, each driven through the public CLI (not
unit seams). Every behavior here was implemented in Tasks 2-12; any
failure reopens the owning task.
"""

import hashlib
import os
import sys
import tempfile
import threading

from test_build_commands import (
    ADAPTER_OK_FIXTURE,
    SOURCE_HEADER,
    run_cli,
    write_executable,
    write_lockfile,
    write_project,
    write_tool_bindir,
)

from mojobpf import cli as cli_module
from mojobpf import execution as execution_module

OBJECT_LIMIT = 16 * 1024 * 1024


def _sparse(path, size):
    with open(path, "wb") as handle:
        handle.truncate(size)
    return path


def test_pack_huge_object_refused():
    parent = tempfile.mkdtemp(prefix="pack-huge-")
    obj = _sparse(os.path.join(parent, "huge.o"), OBJECT_LIMIT + 1)
    code, _, err = run_cli(["inspect", "--object", obj])
    assert code == cli_module.EXIT_COMPILE, err
    assert str(OBJECT_LIMIT) in err, err


def test_pack_fifo_object_refused_fast():
    parent = tempfile.mkdtemp(prefix="pack-fifo-")
    fifo = os.path.join(parent, "swap.o")
    os.mkfifo(fifo)
    outcome = []

    def _run():
        try:
            outcome.append(run_cli(["inspect", "--object", fifo]))
        except Exception as exc:
            outcome.append(exc)

    worker = threading.Thread(target=_run, daemon=True)
    worker.start()
    worker.join(30)
    assert not worker.is_alive(), "inspect blocked on a FIFO"
    assert len(outcome) == 1
    result = outcome[0]
    assert not isinstance(result, Exception), result
    code, _, err = result
    assert code == cli_module.EXIT_COMPILE, err
    assert "regular file" in err, err


def test_pack_chatty_tool_bounded_with_verdict(monkeypatch):
    # A version probe emitting 10 MiB of noise still reports its
    # verdict: the capture stays bounded and the version parses
    # from the head. The fixture is a childless Python script
    # (shell pipelines would need unadmitted nested tools under
    # the lane guard); the noise volume is unchanged.
    # The capture observer below witnesses through the public CLI
    # run (pass-through, no behavior change): the CLI verdict
    # alone would also pass if capture regressed to unbounded
    # buffering, so the bound itself is pinned here.
    parent = tempfile.mkdtemp(prefix="pack-chatty-")
    bindir = write_tool_bindir(parent)
    llc_path = os.path.join(bindir, "llc")
    llc_text = (
        "#!{python}\n"
        "import sys\n"
        "sys.stdout.write('LLC-CHATTY 0.0\\n')\n"
        "sys.stdout.write(('n' * 65535 + '\\n') * 160)\n"
    ).format(python=sys.executable)
    with open(llc_path, "w", encoding="utf-8") as handle:
        handle.write(llc_text)
    os.chmod(llc_path, 0o755)
    total_bytes = len('LLC-CHATTY 0.0\n') + 160 * 65536
    llc_digest = hashlib.sha256(llc_text.encode("utf-8")).hexdigest()
    lockfile = write_lockfile(
        parent, bindir, pins={"llc": ("LLC-CHATTY 0.0", llc_digest)}
    )
    seen = []
    real_output = execution_module._CappedCapture.output

    def observing_output(self):
        result = real_output(self)
        seen.append(result)
        return result

    monkeypatch.setattr(
        execution_module._CappedCapture, "output", observing_output
    )
    code, out, err = run_cli(
        ["doctor", "--lockfile", lockfile], path=bindir
    )
    assert code == cli_module.EXIT_OK, out + err
    assert "tool llc: present LLC-CHATTY 0.0" in out, out
    truncated = [result for result in seen if result.truncated]
    assert len(truncated) == 1, seen
    capture = truncated[0]
    assert capture.stdout.startswith("LLC-CHATTY 0.0\n"), capture.stdout[:64]
    assert capture.stderr == "", capture.stderr
    head, note = capture.stdout.rsplit("...[capture truncated ", 1)
    assert head.endswith("\n"), repr(head[-8:])
    assert note.endswith("]...\n"), repr(note[-32:])
    discarded, label, _rest = note[:-5].split(" ", 2)
    assert label == "stdout", note
    assert "1048576-byte head" in note, note
    # The pump pads a non-newline head with one newline before the
    # note; conservation counts stream bytes only.
    pad = 0 if head[:-1].endswith("\n") else 1
    kept = len(head.encode("utf-8")) - pad
    assert kept + int(discarded) == total_bytes, (
        kept, discarded, total_bytes,
    )
    assert kept <= 1048576 + 1, kept


def test_pack_canary_secret_absent_from_bundle():
    # MOJO_API_KEY is ambient-captured (MOJO_ prefix) but
    # secret-named (KEY), so it must be dropped entirely; the
    # benign MOJO_PACK_MARKER proves the capture ran (its name
    # lands in the bundle with a hashed value).
    canary = "CANARY-pack-%s-s3cr3t" % os.getpid()
    secret_name = "MOJO_API_KEY"
    marker = "MOJO_PACK_MARKER"
    old_secret = os.environ.get(secret_name)
    old_marker = os.environ.get(marker)
    os.environ[secret_name] = canary
    os.environ[marker] = "marker-value-7zq"
    try:
        parent = tempfile.mkdtemp(prefix="pack-canary-")
        manifest_path, out_dir = write_project(parent)
        bindir = write_tool_bindir(parent)
        adapter = os.path.join(parent, "adapter-ok.py")
        write_executable(adapter, ADAPTER_OK_FIXTURE)
        lockfile = write_lockfile(parent, bindir)
        code, _, err = run_cli(
            [
                "build",
                "--manifest", manifest_path,
                "--out-dir", out_dir,
                "--adapter", adapter,
                "--lockfile", lockfile,
            ],
            path=bindir,
        )
        assert code == cli_module.EXIT_OK, err
        sidecars = [
            os.path.join(out_dir, name)
            for name in os.listdir(out_dir)
            if name.endswith(".evidence.json")
        ]
        assert sidecars, os.listdir(out_dir)
        parts = []
        for path in sidecars:
            with open(path, "rb") as handle:
                parts.append(handle.read())
        raw = b"".join(parts)
        assert canary.encode() not in raw
        assert secret_name.encode() not in raw
        assert marker.encode() in raw
        assert b"marker-value-7zq" not in raw
    finally:
        if old_secret is None:
            os.environ.pop(secret_name, None)
        else:
            os.environ[secret_name] = old_secret
        if old_marker is None:
            os.environ.pop(marker, None)
        else:
            os.environ[marker] = old_marker


def test_pack_symlink_escape_refused():
    parent = tempfile.mkdtemp(prefix="pack-symlink-")
    proj = os.path.join(parent, "proj")
    os.makedirs(os.path.join(proj, "src"))
    outside = os.path.join(parent, "outside.mojo")
    with open(outside, "w", encoding="utf-8") as handle:
        handle.write(SOURCE_HEADER)
        handle.write("# outside bytes must never build\n")
    os.symlink(outside, os.path.join(proj, "src", "evil.mojo"))
    manifest_path = os.path.join(proj, "mojobpf.toml")
    with open(manifest_path, "w", encoding="utf-8") as handle:
        handle.write(
            "schema_version = 1\n"
            "\n"
            "[project]\n"
            'name = "pack-proj"\n'
            "\n"
            "[target]\n"
            'profile = "linux-bpfel-v3"\n'
            "core = false\n"
            "\n"
            "[artifact]\n"
            'name = "pack_obj"\n'
            'source_license = "Apache-2.0 WITH LLVM-exception"\n'
            'kernel_license = "Apache-2.0 WITH LLVM-exception"\n'
            "\n"
            "[[programs]]\n"
            'source = "src/evil.mojo"\n'
            'entry = "pack_entry"\n'
            'program_type = "xdp"\n'
            'section = "xdp"\n'
        )
    code, _, err = run_cli(
        ["build", "--manifest", manifest_path,
         "--out-dir", os.path.join(proj, "out")]
    )
    assert code == cli_module.EXIT_USAGE, err
    assert "MBPF207" in err, err
    assert "resolves outside" in err, err


def test_pack_pin_traversal_refused():
    # Pin validation precedes object handling: a traversal pin is
    # refused even for a missing object, with no guest involved.
    code, _, err = run_cli(
        [
            "verify", "--kernel",
            "--object", "no-such-object.o",
            "--pin-path", "/sys/fs/bpf/../x",
        ]
    )
    assert code == cli_module.EXIT_USAGE, err
    assert "normalized" in err, err
