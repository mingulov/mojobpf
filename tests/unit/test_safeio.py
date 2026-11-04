"""Capped reads and streamed hashing for untrusted file inputs (WP-4 Task 8).

Every test here replays a hostile input end-to-end through the converted
reader: an over-cap file must be refused with the byte limit named, and a
FIFO swapped in for a regular file must be refused without hanging.
"""

import base64
import csv
import hashlib
import importlib
import inspect
import io
import os
import threading

import pytest

# Byte limits from the Task 8 cap table (mirrored here so RED fails on the
# callers' behavior even before ``mojobpf.safeio`` exists; the pin test
# below asserts the module constants match).
OBJECT_LIMIT = 16 * 1024 * 1024
MANIFEST_LIMIT = 1024 * 1024
LOCK_LIMIT = 1024 * 1024
MOJO_LIMIT = 8 * 1024 * 1024
IR_LIMIT = 32 * 1024 * 1024
JSON_LIMIT = 1024 * 1024
DIST_LIMIT = 1024 * 1024
SDK_CONFIG_LIMIT = 1024 * 1024
STDLIB_PAYLOAD_LIMIT = 32 * 1024 * 1024


def _safeio():
    return importlib.import_module("mojobpf.safeio")


def _sparse(path, size):
    with open(path, "wb") as handle:
        handle.truncate(size)
    return path


def _feeder(fifo_path, payload=b"x" * 4096):
    """Feed a FIFO from a daemon thread without ever blocking the test.

    The writer retries O_WRONLY|O_NONBLOCK until a reader appears (uncapped
    readers block in open until then) or a short deadline passes (capped
    readers refuse and close, so ENXIO persists and the thread exits).
    Both phases terminate.
    """

    def _run():
        fd = None
        for _ in range(200):
            try:
                fd = os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)
                break
            except OSError:
                threading.Event().wait(0.05)
        if fd is None:
            return
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
        except (BrokenPipeError, OSError):
            pass

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return thread


# ---------------------------------------------------------------------------
# safeio unit contract
# ---------------------------------------------------------------------------


def test_read_capped_exact_limit_ok(tmp_path):
    safeio = _safeio()
    path = tmp_path / "exact.bin"
    path.write_bytes(b"a" * 64)
    assert safeio.read_capped(str(path), limit=64, kind="probe") == b"a" * 64


def test_read_capped_limit_plus_one_refused_naming_limit(tmp_path):
    safeio = _safeio()
    path = tmp_path / "over.bin"
    path.write_bytes(b"a" * 65)
    with pytest.raises(safeio.FileTooLargeError, match="64") as excinfo:
        safeio.read_capped(str(path), limit=64, kind="probe")
    assert isinstance(excinfo.value, OSError)


def test_read_capped_missing_preserved(tmp_path):
    safeio = _safeio()
    with pytest.raises(FileNotFoundError):
        safeio.read_capped(str(tmp_path / "absent.bin"), limit=64, kind="probe")


def test_read_capped_directory_refused(tmp_path):
    safeio = _safeio()
    with pytest.raises(safeio.NonRegularFileError, match="regular"):
        safeio.read_capped(str(tmp_path), limit=64, kind="probe")


def test_read_capped_fifo_refused_without_hanging(tmp_path):
    safeio = _safeio()
    fifo = str(tmp_path / "swap.fifo")
    os.mkfifo(fifo)
    _feeder(fifo)
    with pytest.raises(safeio.NonRegularFileError, match="regular"):
        safeio.read_capped(fifo, limit=64, kind="probe")


def test_limit_constants_pinned():
    safeio = _safeio()
    assert safeio.OBJECT_LIMIT == OBJECT_LIMIT
    assert safeio.MANIFEST_LIMIT == MANIFEST_LIMIT
    assert safeio.LOCK_LIMIT == LOCK_LIMIT
    assert safeio.MOJO_LIMIT == MOJO_LIMIT
    assert safeio.IR_LIMIT == IR_LIMIT
    assert safeio.JSON_LIMIT == JSON_LIMIT
    assert safeio.DIST_LIMIT == DIST_LIMIT
    assert safeio.SDK_CONFIG_LIMIT == SDK_CONFIG_LIMIT
    assert safeio.STDLIB_PAYLOAD_LIMIT == STDLIB_PAYLOAD_LIMIT


def test_streamed_hash_matches_whole_hash(tmp_path):
    safeio = _safeio()
    blob = os.urandom(256 * 1024)
    path = tmp_path / "bulk.bin"
    path.write_bytes(blob)
    observed = safeio.hash_file_capped(str(path), limit=1024 * 1024, kind="probe")
    assert observed.hexdigest() == hashlib.sha256(blob).hexdigest()


def test_hash_over_cap_refused(tmp_path):
    safeio = _safeio()
    path = tmp_path / "over.bin"
    path.write_bytes(b"a" * 65)
    with pytest.raises(safeio.FileTooLargeError, match="64"):
        safeio.hash_file_capped(str(path), limit=64, kind="probe")


def test_hash_fifo_refused_without_hanging(tmp_path):
    safeio = _safeio()
    fifo = str(tmp_path / "swap.fifo")
    os.mkfifo(fifo)
    _feeder(fifo)
    with pytest.raises(safeio.NonRegularFileError, match="regular"):
        safeio.hash_file_capped(fifo, limit=64, kind="probe")


# ---------------------------------------------------------------------------
# objects (16 MiB)
# ---------------------------------------------------------------------------


def test_huge_object_refused_naming_limit(tmp_path):
    from mojobpf import verify

    path = _sparse(str(tmp_path / "huge.o"), OBJECT_LIMIT + 1)
    with pytest.raises(Exception, match=str(OBJECT_LIMIT)):
        verify.read_elf_sections(path)


def test_huge_object_inspect_refused(tmp_path):
    from mojobpf import inspect as inspect_mod

    path = _sparse(str(tmp_path / "huge.o"), OBJECT_LIMIT + 1)
    with pytest.raises(Exception, match=str(OBJECT_LIMIT)):
        inspect_mod._read_object_bytes(path)


def test_fifo_object_refused_without_hanging(tmp_path):
    from mojobpf import verify

    fifo = str(tmp_path / "swap.o")
    os.mkfifo(fifo)
    _feeder(fifo)
    with pytest.raises(Exception, match="regular"):
        verify.read_elf_sections(fifo)


# ---------------------------------------------------------------------------
# manifests (1 MiB)
# ---------------------------------------------------------------------------


def test_huge_manifest_refused_naming_limit(tmp_path):
    from mojobpf import manifest

    path = _sparse(str(tmp_path / "huge.toml"), MANIFEST_LIMIT + 1)
    with pytest.raises(Exception, match=str(MANIFEST_LIMIT)):
        manifest.parse_manifest(path)


def test_fifo_manifest_refused_without_hanging(tmp_path):
    from mojobpf import manifest

    fifo = str(tmp_path / "swap.toml")
    os.mkfifo(fifo)
    _feeder(fifo, b"[project]\n")
    with pytest.raises(Exception, match="regular"):
        manifest.parse_manifest(fifo)


# ---------------------------------------------------------------------------
# lockfiles (1 MiB)
# ---------------------------------------------------------------------------


def test_huge_toolchain_lock_refused(tmp_path):
    # load_toolchain_lock never raises: the refusal is an MBPF104
    # diagnostic naming the limit, with no tools table.
    from mojobpf import toolchain

    path = _sparse(str(tmp_path / "huge.lock"), LOCK_LIMIT + 1)
    table, _status, diagnostics = toolchain.load_toolchain_lock(path)
    assert table is None
    assert any(str(LOCK_LIMIT) in diag.explanation for diag in diagnostics)


def test_huge_toolchain_document_absent_while_lock_names_limit(tmp_path):
    # load_toolchain_document keeps its None-on-unreadable contract (the
    # cap is memory defense there); the loud refusal naming the limit
    # rides the sibling load_toolchain_lock MBPF104 every admission flow
    # calls first. A huge-but-valid lock must read as absent here.
    import json

    from mojobpf import toolchain

    path = str(tmp_path / "huge.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"schema_version": 1, "padding": "x" * (LOCK_LIMIT + 1)},
                  handle)
    assert toolchain.load_toolchain_document(path) is None
    _table, _status, diagnostics = toolchain.load_toolchain_lock(path)
    assert any(str(LOCK_LIMIT) in diag.explanation for diag in diagnostics)


def test_fifo_lock_refused_without_hanging(tmp_path):
    from mojobpf import toolchain

    fifo = str(tmp_path / "swap.lock")
    os.mkfifo(fifo)
    _feeder(fifo, b"{}")
    table, _status, diagnostics = toolchain.load_toolchain_lock(fifo)
    assert table is None
    assert any("regular" in diag.explanation for diag in diagnostics)


def test_huge_kernels_lock_refused(tmp_path):
    from mojobpf import verify

    path = _sparse(str(tmp_path / "kernels.json"), LOCK_LIMIT + 1)
    with pytest.raises(Exception, match=str(LOCK_LIMIT)):
        verify._load_lock_document(path)


# ---------------------------------------------------------------------------
# Mojo sources (8 MiB)
# ---------------------------------------------------------------------------


def test_huge_mojo_imports_refused(tmp_path):
    from mojobpf import inputs

    path = _sparse(str(tmp_path / "huge.mojo"), MOJO_LIMIT + 1)
    with pytest.raises(Exception, match=str(MOJO_LIMIT)):
        inputs.parse_mojo_imports(path)


def test_huge_sdk_check_refused(tmp_path):
    from mojobpf import sdk

    path = _sparse(str(tmp_path / "huge.mojo"), MOJO_LIMIT + 1)
    with pytest.raises(Exception, match=str(MOJO_LIMIT)):
        sdk.check_mojo_file(path)


def test_huge_sdk_module_refused(tmp_path):
    from mojobpf import sdk

    path = _sparse(str(tmp_path / "huge.mojo"), MOJO_LIMIT + 1)
    with pytest.raises(Exception, match=str(MOJO_LIMIT)):
        sdk.parse_sdk_module(path)


def test_read_once_huge_source_refused(tmp_path):
    from mojobpf import inputs

    path = _sparse(str(tmp_path / "huge.mojo"), MOJO_LIMIT + 1)
    with pytest.raises(Exception, match=str(MOJO_LIMIT)):
        inputs._read_once(path, limit=MOJO_LIMIT)


def test_read_once_small_source_ok(tmp_path):
    from mojobpf import inputs

    path = tmp_path / "small.mojo"
    path.write_bytes(b"from python import Python\n")
    assert inputs._read_once(str(path), limit=MOJO_LIMIT) == (
        b"from python import Python\n"
    )


# ---------------------------------------------------------------------------
# error-path source reads (unequal, never OOM)
# ---------------------------------------------------------------------------


def test_same_file_bytes_over_cap_unequal(tmp_path):
    from mojobpf import build

    first = _sparse(str(tmp_path / "first.mojo"), MOJO_LIMIT + 1)
    second = _sparse(str(tmp_path / "second.mojo"), MOJO_LIMIT + 1)
    assert build._same_file_bytes(first, second) is False


# ---------------------------------------------------------------------------
# licensed-file scans (8 MiB): sources, SDK files, license texts
# ---------------------------------------------------------------------------


def test_mojo_source_between_1_and_8_mib_scans(tmp_path):
    # License scans read sources: a 2 MiB source with a valid SPDX
    # header must scan, not refuse.
    from mojobpf import inspect as inspect_mod

    path = str(tmp_path / "big.mojo")
    with open(path, "wb") as handle:
        handle.write(
            b"# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception\n"
        )
        handle.truncate(2 * 1024 * 1024)
    grant = inspect_mod._check_single_header(
        path, "program source",
        "Apache-2.0 WITH LLVM-exception", str(tmp_path),
        "MBPF702", "align the header",
    )
    assert grant.spdx == "Apache-2.0 WITH LLVM-exception"


def test_huge_licensed_file_refused_naming_limit(tmp_path):
    from mojobpf import inspect as inspect_mod

    path = str(tmp_path / "huge.mojo")
    with open(path, "wb") as handle:
        handle.write(
            b"# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception\n"
        )
        handle.truncate(MOJO_LIMIT + 1)
    with pytest.raises(Exception, match=str(MOJO_LIMIT)):
        inspect_mod._read_grant_file(path)


# ---------------------------------------------------------------------------
# distribution binding (1 MiB): METADATA / RECORD / listed candidates
# ---------------------------------------------------------------------------


def _craft_dist(root, *, record_text=None, metadata=b"Name: demo\nVersion: 1\n"):
    dist_info = os.path.join(root, "demo-1.dist-info")
    os.makedirs(dist_info, exist_ok=True)
    with open(os.path.join(dist_info, "METADATA"), "wb") as handle:
        handle.write(metadata)
    if record_text is None:
        record_text = "METADATA,,\nRECORD,,\n"
    record_path = os.path.join(dist_info, "RECORD")
    with open(record_path, "w", encoding="utf-8", newline="") as handle:
        handle.write(record_text)
    with open(record_path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    return dist_info, digest


def test_huge_record_refused_naming_limit(tmp_path):
    from mojobpf import execution

    root = str(tmp_path)
    dist_info = os.path.join(root, "demo-1.dist-info")
    os.makedirs(dist_info, exist_ok=True)
    with open(os.path.join(dist_info, "METADATA"), "wb") as handle:
        handle.write(b"Name: demo\nVersion: 1\n")
    record_path = os.path.join(dist_info, "RECORD")
    _sparse(record_path, DIST_LIMIT + 1)
    with open(record_path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    with pytest.raises(execution.AdmissionError, match=str(DIST_LIMIT)):
        execution._verify_dependency_record("demo", "1", digest, dist_info, root)


def test_huge_metadata_refused_naming_limit(tmp_path):
    from mojobpf import execution

    root = str(tmp_path)
    dist_info, record_digest = _craft_dist(root)
    metadata_path = os.path.join(dist_info, "METADATA")
    _sparse(metadata_path, DIST_LIMIT + 1)
    with open(metadata_path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    with pytest.raises(Exception, match=str(DIST_LIMIT)):
        execution._verify_one_dependency(
            "demo", "1", digest, record_digest, [root], []
        )


def test_huge_candidate_hash_refused_naming_limit(tmp_path):
    from mojobpf import execution

    root = str(tmp_path)
    payload = os.path.join(root, "payload.bin")
    _sparse(payload, DIST_LIMIT + 1)
    with open(payload, "rb") as handle:
        tag = base64.urlsafe_b64encode(hashlib.sha256(handle.read()).digest())
    rows = io.StringIO()
    writer = csv.writer(rows, lineterminator="\n")
    writer.writerow(["payload.bin", "sha256=" + tag.decode("ascii"),
                     str(DIST_LIMIT + 1)])
    writer.writerow(["METADATA", "", ""])
    writer.writerow(["RECORD", "", ""])
    dist_info, digest = _craft_dist(root, record_text=rows.getvalue())
    with pytest.raises(Exception, match=str(DIST_LIMIT)):
        execution._verify_dependency_record("demo", "1", digest, dist_info, root)


# ---------------------------------------------------------------------------
# IR (32 MiB): deep pipeline sites pin the limit at unit level plus the
# caller-pin test below
# ---------------------------------------------------------------------------


def test_ir_limit_unit(tmp_path):
    safeio = _safeio()
    path = _sparse(str(tmp_path / "huge.mir"), IR_LIMIT + 1)
    with pytest.raises(safeio.FileTooLargeError, match=str(IR_LIMIT)):
        safeio.read_capped(path, limit=IR_LIMIT, kind="ir")


# ---------------------------------------------------------------------------
# SDK roots (1 MiB config / 32 MiB payload): hostile MODULAR_HOME
# ---------------------------------------------------------------------------


def test_huge_sdk_config_falls_back_to_prefix_guess(tmp_path):
    from mojobpf import inputs

    hostile = tmp_path / "home"
    hostile.mkdir()
    with open(hostile / "modular.cfg", "wb") as handle:
        handle.write(b"import_path = /hostile/payload\n")
        handle.write(b"x" * (SDK_CONFIG_LIMIT + 1))
    entries = dict(
        inputs.stdlib_payload_paths(
            mojo_binary="/opt/x/bin/mojo", modular_home=str(hostile)
        )
    )
    assert entries["std.mojoc"] == os.path.join(
        "/opt", "x", "lib", "mojo", "std.mojoc"
    )
    assert entries["modular.cfg"] == os.path.join(
        str(hostile), "modular.cfg"
    )


def test_huge_stdlib_payload_identity_missing(tmp_path):
    from mojobpf import inputs

    hostile = tmp_path / "home"
    hostile.mkdir()
    with open(hostile / "modular.cfg", "w", encoding="utf-8") as handle:
        handle.write("import_path = %s\n" % hostile)
    _sparse(str(hostile / "std.mojoc"), STDLIB_PAYLOAD_LIMIT + 1)
    entries = inputs.stdlib_payload_identities(
        mojo_binary="/opt/x/bin/mojo", modular_home=str(hostile)
    )
    assert "stdlib payload std.mojoc missing" in entries, entries


def test_huge_stdlib_payload_stage_names_limit(tmp_path):
    from mojobpf import inputs

    payload = _sparse(
        str(tmp_path / "std.mojoc"), STDLIB_PAYLOAD_LIMIT + 1
    )
    seal = [
        inputs.StdlibSealEntry(
            logical="std.mojoc", path=payload, sha256="0" * 64,
            staged=None,
        )
    ]
    try:
        inputs._stage_stdlib_payload(seal, str(tmp_path / "staged"))
    except inputs.InputError as exc:
        assert str(STDLIB_PAYLOAD_LIMIT) in (
            exc.diagnostic.explanation
        ), exc.diagnostic
    else:
        raise AssertionError("huge stdlib payload was staged")


# ---------------------------------------------------------------------------
# caller pins: every converted site routes through the capped helpers
# ---------------------------------------------------------------------------


def test_converted_callers_use_capped_helpers():
    from mojobpf import build
    from mojobpf import execution
    from mojobpf import inputs
    from mojobpf import inspect as inspect_mod
    from mojobpf import manifest
    from mojobpf import sdk
    from mojobpf import toolchain
    from mojobpf import verify

    capped = (
        (verify.read_elf_sections, "read_capped", "OBJECT_LIMIT"),
        (verify._read_object_bytes, "read_capped", "OBJECT_LIMIT"),
        (inspect_mod._read_object_bytes, "read_capped", "OBJECT_LIMIT"),
        (inspect_mod._read_grant_file, "read_capped", "MOJO_LIMIT"),
        (manifest.parse_manifest, "read_capped", "MANIFEST_LIMIT"),
        (toolchain.load_toolchain_lock, "read_capped", "LOCK_LIMIT"),
        (toolchain.load_toolchain_document, "read_capped", "LOCK_LIMIT"),
        (verify._load_lock_document, "read_capped", "LOCK_LIMIT"),
        (inputs.parse_mojo_imports, "read_capped", "MOJO_LIMIT"),
        (inputs._read_once, "read_capped", "limit"),
        (sdk.check_mojo_file, "read_capped", "MOJO_LIMIT"),
        (sdk.parse_sdk_module, "read_capped", "MOJO_LIMIT"),
        (build._same_file_bytes, "read_capped", "MOJO_LIMIT"),
        (build._spill_gate_outcome, "read_capped", "IR_LIMIT"),
        (build._map_entries_outcome, "read_capped", "IR_LIMIT"),
        (build._run_adapter, "read_capped", "JSON_LIMIT"),
        (execution._verify_dependency_record, "read_capped", "DIST_LIMIT"),
        (execution._verify_dependency_record, "hash_file_capped", "DIST_LIMIT"),
        (execution._verify_one_dependency, "read_capped", "DIST_LIMIT"),
        (inputs.stdlib_payload_paths, "read_capped", "SDK_CONFIG_LIMIT"),
        (
            inputs.stdlib_payload_identities,
            "hash_file_capped",
            "STDLIB_PAYLOAD_LIMIT",
        ),
        (
            inputs._stage_stdlib_payload,
            "read_capped",
            "STDLIB_PAYLOAD_LIMIT",
        ),
    )
    for func, helper, token in capped:
        source = inspect.getsource(func)
        assert helper in source, func.__qualname__
        assert token in source, func.__qualname__
