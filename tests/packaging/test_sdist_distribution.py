# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Real offline archive, wheel and installed setup controls; no compiler/guest."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
from urllib.parse import unquote, urlsplit
import zipfile

import pytest
import test_wheel_contents as wheel_contract
import packaging_source

ROOT = Path(wheel_contract.REPO_ROOT)
PIN = Path(__file__).with_name("sdist-members.json")


def _populated_source(root):
    root.mkdir()
    (root / "src").mkdir()
    (root / "src/tool.py").write_bytes(b"print('public source')\n")
    (root / "src/tool.py").chmod(0o751)
    (root / "tools").mkdir()
    (root / "tools/build").write_bytes(b"#!/bin/sh\nexit 0\n")
    (root / "tools/build").chmod(0o751)
    (root / "README.md").write_bytes(b"public documentation\n")
    for relative in ("build", "dist", "out", "artifacts", "src/tool.egg-info",
                     ".pixi", ".venv", ".worktrees", ".pytest_cache", "__pycache__"):
        directory = root / relative
        directory.mkdir(parents=True)
        (directory / "keep.bin").write_bytes(b"unrelated original material\n")
        directory.chmod(0o750)
    return root


def test_packaging_source_copy_preserves_inputs_and_excludes_residue(tmp_path):
    source = _populated_source(tmp_path / "origin")
    before = packaging_source.snapshot_source(source)
    destination = tmp_path / "owned-source"
    record = packaging_source.copy_source_tree(source, destination)
    assert record["origin_kind"] == "filesystem"
    assert record["git_top_level"] is None
    assert set(record["files"]) == {"README.md", "src/tool.py", "tools/build"}
    assert (destination / "src/tool.py").read_bytes() == b"print('public source')\n"
    assert (destination / "src/tool.py").stat().st_mode & 0o7777 == 0o751
    assert (destination / "README.md").read_bytes() == b"public documentation\n"
    assert (destination / "tools/build").read_bytes() == b"#!/bin/sh\nexit 0\n"
    assert (destination / "tools/build").stat().st_mode & 0o7777 == 0o751
    assert packaging_source.snapshot_source(source) == before
    for name, pin in record["files"].items():
        import hashlib
        path = destination / name
        assert pin == {"size": path.stat().st_size,
                       "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                       "mode": path.stat().st_mode & 0o7777}


def test_packaging_source_rejects_existing_or_overlapping_destination(tmp_path):
    source = _populated_source(tmp_path / "origin")
    existing = tmp_path / "existing"
    existing.mkdir()
    (existing / "keep").write_bytes(b"owned by another caller")
    link = tmp_path / "link"
    link.symlink_to(existing, target_is_directory=True)
    for destination in (existing, link, source / "nested", tmp_path):
        before = packaging_source.snapshot_source(tmp_path)
        with pytest.raises((ValueError, FileExistsError)):
            packaging_source.copy_source_tree(source, destination)
        assert packaging_source.snapshot_source(tmp_path) == before
    outside = tmp_path / "outside-input"
    outside.write_bytes(b"must never be followed")
    (source / "escape").symlink_to(outside)
    before = packaging_source.snapshot_source(tmp_path)
    with pytest.raises(ValueError, match="regular|symlink|outside"):
        packaging_source.copy_source_tree(source, tmp_path / "rejected")
    assert packaging_source.snapshot_source(tmp_path) == before


def test_packaging_source_owns_git_membership(tmp_path):
    source = tmp_path / "git-source"
    source.mkdir()
    (source / ".gitignore").write_text("ignored.bin\n")
    (source / "tracked.txt").write_bytes(b"tracked public input")
    initial = packaging_source.initialize_fixture_git(source)
    assert initial["git_top_level"] == str(source.resolve())
    assert set(initial["indexed_members"]) == {".gitignore", "tracked.txt"}
    (source / "untracked.txt").write_bytes(b"untracked public input")
    (source / "ignored.bin").write_bytes(b"ignored material")
    before = packaging_source.snapshot_source(source)
    kind, members = packaging_source.source_members(source)
    actual = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=source).decode().split("\0")
    assert kind == "git"
    assert members == tuple(sorted(set(actual) - {""}))
    record = packaging_source.copy_source_tree(source, tmp_path / "git-copy")
    assert set(record["files"]) == {".gitignore", "tracked.txt", "untracked.txt"}
    assert record["git_top_level"] == str(source.resolve())
    assert not (tmp_path / "git-copy/.git").exists()
    assert packaging_source.snapshot_source(source) == before


def test_packaging_source_ignores_ancestor_git(tmp_path):
    ancestor = tmp_path / "unrelated-repository"
    ancestor.mkdir()
    (ancestor / "outside-marker").write_bytes(b"ancestor-only public input")
    packaging_source.initialize_fixture_git(ancestor)
    source = ancestor / "export"
    source.mkdir()
    (source / "README.md").write_bytes(b"only export content")
    record = packaging_source.copy_source_tree(source, tmp_path / "export-copy")
    assert record["origin_kind"] == "filesystem"
    assert record["git_top_level"] is None
    assert set(record["files"]) == {"README.md"}
    # An explicit but invalid/misowned Git identity must never fall back.
    checked(["git", "config", "core.worktree", str(ancestor.resolve())], cwd=ancestor)
    (source / ".git").write_text("gitdir: " + str(ancestor / ".git") + "\n")
    before = packaging_source.snapshot_source(ancestor)
    with pytest.raises(ValueError, match="Git|git|owner"):
        packaging_source.copy_source_tree(source, tmp_path / "misowned-copy")
    assert packaging_source.snapshot_source(ancestor) == before


# NOTE (staged scope): preservation/canary tests (adapter +
# native-install coupled) return with the deferred installed-v2
# feature package.

def checked(argv, *, cwd, env=None):
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True,
                            text=True, timeout=600)
    assert result.returncode == 0, (argv, result.stdout, result.stderr)
    return result


@pytest.fixture(scope="module")
def distribution(tmp_path_factory):
    work = tmp_path_factory.mktemp("source-distribution")
    exported = work / "source"
    record = packaging_source.copy_source_tree(ROOT, exported)
    (work / "source-copy.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    archives = work / "archives"
    archives.mkdir()
    checked([sys.executable, "-c", "from setuptools.build_meta import build_sdist; build_sdist(" + repr(str(archives)) + ")"], cwd=exported,
            env={**os.environ, "PIP_NO_INDEX": "1"})
    archive, = archives.glob("*.tar.gz")
    unpack = work / "unpacked"
    unpack.mkdir()
    with tarfile.open(archive) as source:
        source.extractall(unpack, filter="data")
    source, = unpack.iterdir()
    return work, exported, source, archive


def test_source_archive_exact_member_inventory(distribution):
    _, _, _, path = distribution
    with tarfile.open(path) as archive:
        members = sorted(member.name.split("/", 1)[1] for member in archive
                         if member.isfile())
    assert members == json.loads(PIN.read_text()), sorted(set(members) ^ set(json.loads(PIN.read_text())))


def test_all_archive_markdown_links_resolve(distribution):
    _, _, source, _ = distribution
    broken = []
    for path in source.rglob("*.md"):
        for target in re.findall(r"\[[^][\]]+\]\(([^)\s]+)\)", path.read_text()):
            url = urlsplit(target)
            if url.scheme or url.netloc or not url.path:
                continue
            destination = (path.parent / unquote(url.path)).resolve()
            valid = destination.is_relative_to(source.resolve()) and destination.exists()
            if valid and url.fragment and destination.suffix == ".md":
                headings = re.findall(r"^#{1,6}\s+(.+)$", destination.read_text(), re.MULTILINE)
                anchors = {re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-") for heading in headings}
                valid = unquote(url.fragment) in anchors
            if not valid:
                broken.append((str(path.relative_to(source)), target))
    assert broken == [], broken


def assert_native_fixture_inventory(source):
    # NOTE (staged scope): tests/packaging/test_native_adapter_install.py
    # rejoins with the deferred installed-v2 feature package.
    required = ["tests/harness/packaging_source.py",
                "tests/packaging/test_adapter_generation.py",
                "tests/compile/probe.mojo", "tests/compile/map_roundtrip.mojo",
                "tests/compile/map_roundtrip_mutated.mojo", "tests/ir/test_audit.py",
                "tests/reference_c/xdp_classifier_ref.bpf.c",
                "tests/reference_c/map_roundtrip_ref.bpf.c"]
    ledger = source / "compiler/tests/target_model_cases.json"
    required += json.loads(ledger.read_text())["lowering"]["source_fixtures"]
    for name in required:
        assert (source / name).is_file(), "missing native fixture: " + name
        assert (source / name).read_bytes() == (ROOT / name).read_bytes(), name


def test_archive_required_native_fixture_inventory(distribution):
    _, _, source, _ = distribution
    assert_native_fixture_inventory(source)


@pytest.mark.parametrize("name", ["xdp_classifier_ref.bpf.c", "map_roundtrip_ref.bpf.c"])
def test_archive_missing_c_reference_fails_before_compilation(distribution, tmp_path, name):
    _, _, source, _ = distribution
    damaged = tmp_path / "damaged-archive"
    shutil.copytree(source, damaged)
    reference = damaged / "tests/reference_c" / name
    assert reference.is_file(), "archive omitted independent C reference: " + name
    reference.unlink()
    # The same packaging inventory rejects the missing input without invoking
    # any compiler, loader or native fixture.
    with pytest.raises(AssertionError, match="missing native fixture: .*" + re.escape(name)):
        assert_native_fixture_inventory(damaged)


def run_archive_python(work, exported, source, args):
    bubblewrap = shutil.which("bwrap")
    assert bubblewrap, "ENVIRONMENT FAILURE: bwrap required for denied-source collection"
    denied = [str(ROOT), str(exported)] + [
        path for path in os.environ.get("MOJOBPF_TEST_DENY_ROOTS", "").split(os.pathsep) if path]
    denied = sorted({str(Path(path).resolve()) for path in denied}, key=len)
    for path in denied:
        assert not work.resolve().is_relative_to(Path(path)), (
            "writable work directory overlaps denied source root", str(work), path)
    # Mount writable parents first: a later parent bind would expose a hidden
    # child source export again. No bind may follow these denial mounts.
    sandbox = [bubblewrap, "--ro-bind", "/", "/", "--dev", "/dev",
               "--bind", str(work), str(work)]
    for path in denied:
        sandbox += ["--tmpfs", path]
    sandbox += ["--unshare-net", "--chdir", str(source), "--"]
    env = {**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(source / "src")}
    # Verify the denial inside the very process namespace used for the test.
    # Both roots have populated MANIFEST.in inputs before entering the sandbox.
    canaries = [str(ROOT / "MANIFEST.in"), str(exported / "MANIFEST.in")]
    assert all(Path(path).is_file() for path in canaries), canaries
    canaries += [str(Path(path) / name) for path in denied
                 for name in ("AGENTS.md", "README.md", "MANIFEST.in")
                 if (Path(path) / name).is_file()]
    probe = (
        "import os, sys; from pathlib import Path; "
        "denied, source, args = __import__('json').loads(sys.argv[1]); "
        "assert all(not Path(path).exists() for path in denied), "
        "'source denial failed: ' + repr(denied); "
        "assert (Path(source) / 'MANIFEST.in').is_file(), 'archive unavailable'; "
        "print('archive source denial verified', flush=True); "
        "os.execv(sys.executable, [sys.executable] + args)"
    )
    argv = sandbox + [sys.executable, "-c", probe,
                      json.dumps([canaries, str(source), args])]
    result = subprocess.run(argv, cwd=source, env=env, capture_output=True,
                            text=True, timeout=120)
    (work / ("archive-python-" + str(len(list(work.glob("archive-python-*.json")))) + ".json")).write_text(json.dumps({
        "argv": argv, "exit": result.returncode, "stdout": result.stdout,
        "stderr": result.stderr}, indent=2) + "\n")
    return result



def test_archive_denial_rejects_overlapping_work_root(distribution, monkeypatch):
    work, exported, source, _ = distribution
    monkeypatch.setenv("MOJOBPF_TEST_DENY_ROOTS", str(work.parent))
    with pytest.raises(AssertionError, match="overlaps denied source root"):
        run_archive_python(work, exported, source, ["-c", "raise AssertionError('must not run')"])


def test_archive_python_tests_collect_without_checkout(distribution):
    work, exported, source, _ = distribution
    result = run_archive_python(work, exported, source,
                                ["-m", "pytest", "--collect-only", "-q",
                                 "tests", "compiler/tests"])
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "test_build_commands.py::" in result.stdout
    assert "test_native_adapter.py::" in result.stdout
    assert "test_parsed_elf.py::" in result.stdout


def test_archive_native_fixture_imports_without_checkout(distribution):
    work, exported, source, _ = distribution
    # real_bundle imports compiler_controls lazily. Exercise that import seam
    # explicitly; fixture execution would compile and belongs in the native lane.
    result = run_archive_python(work, exported, source, ["-c",
        "import sys; from pathlib import Path; "
        "sys.path.insert(0, 'tests/unit'); import test_native_adapter as native; "
        "controls = native.compiler_controls(); "
        "assert Path(controls.__file__).resolve().is_relative_to(Path.cwd()); "
        "assert callable(controls.lower_tool)"])
    assert result.returncode == 0, (result.stdout, result.stderr)


def test_archive_lock_regeneration_inputs_runnable_without_checkout(distribution):
    # Machines the reviewed pins do not cover (docs/install.md)
    # regenerate the toolchain lock from the archive alone: the
    # refresh tool and the inventory probe it consumes must both
    # ship in the archive and run with no checkout. Spawn-free
    # (--help plus one fail-closed input error); the genuine
    # inventory/generate flow is proven live from a clean clone.
    work, exported, source, _ = distribution
    for name in ("tools/lock_refresh.py",
                 "tests/probes/toolchain_inventory.py"):
        assert (source / name).is_file(), "archive omitted " + name
    result = run_archive_python(work, exported, source,
                                ["tools/lock_refresh.py", "--help"])
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "generate" in result.stdout and "verify" in result.stdout
    result = run_archive_python(work, exported, source,
                                ["tests/probes/toolchain_inventory.py",
                                 "--help"])
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "--output" in result.stdout
    result = run_archive_python(work, exported, source,
                                ["tools/lock_refresh.py", "generate",
                                 "--kind", "toolchains",
                                 "--inventory", "missing-inventory.json",
                                 "--pixi-lock", "pixi.lock",
                                 "--adapter-dir", "compiler",
                                 "--out", "out.lock.json",
                                 "--report", "out.report.json"])
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert "cannot read inventory" in result.stderr
    assert not (source / "out.lock.json").exists()
    assert not (source / "out.report.json").exists()


def _collect_archive_packaging(work, exported, source):
    import hashlib
    helper_sha = hashlib.sha256((ROOT / "tests/harness/packaging_source.py").read_bytes()).hexdigest()
    script = """
import hashlib, importlib, json, sys
from pathlib import Path
root = Path.cwd().resolve()
sys.path.insert(0, str(root / 'tests/packaging'))
names = ['test_adapter_generation', 'test_wheel_contents',
         'test_sdist_distribution']
origins = {}
for name in names:
    module = importlib.import_module(name)
    path = Path(module.__file__).resolve()
    assert path.is_relative_to(root), (name, str(path))
    origins[name] = str(path)
helper = importlib.import_module('packaging_source')
path = Path(helper.__file__).resolve()
assert path == root / 'tests/harness/packaging_source.py', str(path)
assert hashlib.sha256(path.read_bytes()).hexdigest() == sys.argv[1]
kind, members = helper.source_members(root)
assert kind == 'filesystem', kind
assert not (root / '.git').exists()
assert 'outside-marker' not in members
print('archive packaging origins ' + json.dumps(origins, sort_keys=True), flush=True)
import pytest
raise SystemExit(pytest.main(['--collect-only', '-q'] +
    ['tests/packaging/' + name + '.py' for name in names]))
"""
    result = run_archive_python(work, exported, source, ["-c", script, helper_sha])
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "archive packaging origins " in result.stdout
    for module, node in (
        ("test_adapter_generation", "test_wheel_build_regenerates_stale_copies"),
        ("test_wheel_contents", "test_payload_pinned_exact"),
        ("test_sdist_distribution", "test_packaging_source_ignores_ancestor_git"),
    ):
        assert module + ".py::" + node in result.stdout, result.stdout


def test_archive_packaging_fixtures_collect_without_checkout(distribution):
    work, exported, source, _ = distribution
    _collect_archive_packaging(work, exported, source)
    ancestor = work / "unrelated-git-ancestor"
    ancestor.mkdir()
    (ancestor / "outside-marker").write_bytes(b"unrelated ancestor input\n")
    packaging_source.initialize_fixture_git(ancestor)
    archive_copy = ancestor / "archive-source"
    shutil.copytree(source, archive_copy)
    _collect_archive_packaging(work, exported, archive_copy)


def test_archive_missing_packaging_helper_fails_collection(distribution):
    work, exported, source, _ = distribution
    damaged = work / "missing-packaging-helper"
    shutil.copytree(source, damaged)
    helper = damaged / "tests/harness/packaging_source.py"
    assert helper.is_file(), "archive omitted packaging source helper"
    helper.unlink()
    result = run_archive_python(work, exported, damaged, [
        "-m", "pytest", "--collect-only", "-q",
        "tests/packaging/test_adapter_generation.py",
        "tests/packaging/test_wheel_contents.py",
        "tests/packaging/test_sdist_distribution.py",
    ])
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert "ModuleNotFoundError: No module named 'packaging_source'" in result.stdout


def test_archive_missing_test_import_fails_collection(distribution):
    work, exported, source, _ = distribution
    damaged = work / "missing-test-import"
    shutil.copytree(source, damaged)
    (damaged / "tests/unit/test_native_adapter.py").unlink()
    result = run_archive_python(work, exported, damaged,
                                ["-m", "pytest", "--collect-only", "-q",
                                 "tests/unit/test_build_commands.py"])
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert "ModuleNotFoundError: No module named 'test_native_adapter'" in result.stdout


@pytest.fixture(scope="module")
def wheel_pair(distribution):
    work, exported, source, _ = distribution
    wheels_built = []
    for label, root in (("direct", exported), ("archive", source)):
        wheels = work / label
        wheels.mkdir()
        checked([sys.executable, "-m", "pip", "wheel", str(root), "--no-index", "--no-deps", "--no-build-isolation", "-w", str(wheels)], cwd=work)
        wheel, = wheels.glob("*.whl")
        wheels_built.append(wheel)
    return wheels_built


def test_source_archive_and_direct_wheel_payloads_equal(distribution, wheel_pair):
    payloads = []
    for wheel in wheel_pair:
        with zipfile.ZipFile(wheel) as archive:
            payloads.append({name: archive.read(name) for name in archive.namelist()})
    assert payloads[0] == payloads[1]
    _, _, source, _ = distribution
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
        assert (source / name).read_bytes() == (ROOT / name).read_bytes()


def _installed_proof_sandbox(work, consumer):
    """Build the denied-source sandbox prefix for the installed proof.

    Returns ``(sandbox, canaries)``: the bubblewrap argv prefix through
    ``--``, and outside-visible checkout files the in-sandbox probe
    must NOT see. Raises AssertionError when the writable work root
    overlaps a denied source root: a void denial would certify an
    installed proof that can still see the checkout, so the overlap
    fails LOUDLY instead of running blind.
    """
    bubblewrap = shutil.which("bwrap")
    assert bubblewrap, "ENVIRONMENT FAILURE: bwrap required for denied-source consumer proof"
    # Additional source/coordination roots are an explicit test-environment
    # input, so public tests contain no machine-specific checkout paths.
    denied = [str(ROOT)] + [path for path in os.environ.get("MOJOBPF_TEST_DENY_ROOTS", "").split(os.pathsep) if path]
    denied = sorted({str(Path(path).resolve()) for path in denied}, key=len)
    for path in denied:
        assert not work.resolve().is_relative_to(Path(path)), (
            "writable work directory overlaps denied source root", str(work), path)
    # Mount writable work FIRST: bwrap applies mounts in order, so a work
    # bind AFTER a denial tmpfs would re-expose a denied child inside work
    # (bind-after-deny). Denial mounts come last so they win; no bind may
    # follow them. (work-inside-denied is rejected above: the denial would
    # hide the work root the proof must run from.)
    sandbox = [bubblewrap, "--ro-bind", "/", "/", "--dev", "/dev",
               "--bind", str(work), str(work)]
    for path in denied:
        sandbox += ["--tmpfs", path]
    sandbox += ["--unshare-net", "--chdir", str(consumer), "--"]
    # The checkout root has a populated canary input before entering the
    # sandbox; every extra denied root contributes its populated canaries.
    canaries = [str(ROOT / "MANIFEST.in")]
    assert all(Path(path).is_file() for path in canaries), canaries
    canaries += [str(Path(path) / name) for path in denied
                 for name in ("AGENTS.md", "README.md", "MANIFEST.in")
                 if (Path(path) / name).is_file()]
    return sandbox, canaries


def test_installed_denial_rejects_overlapping_work_root(distribution, monkeypatch):
    work, _, _, _ = distribution
    monkeypatch.setenv("MOJOBPF_TEST_DENY_ROOTS", str(work.parent))
    with pytest.raises(AssertionError, match="overlaps denied source root"):
        _installed_proof_sandbox(work, work / "relocated-consumer")


def test_normal_offline_install_setup_outside_checkout(distribution, wheel_pair):
    work, _, source, _ = distribution
    wheel = wheel_pair[1]
    venv = work / "venv"
    checked([sys.executable, "-m", "venv", str(venv)], cwd=work)
    checked([str(venv / "bin/python"), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)], cwd=work)
    consumer = work / "relocated-consumer"
    consumer.mkdir()
    home = work / "empty-home"
    home.mkdir()
    guards = work / "guard-bin"
    guards.mkdir()
    marker = work / "execution-forbidden"
    for name in ("vng", "virtme-run", "qemu-system-x86_64", "bpftool", "mojo", "llc"):
        entry = guards / name
        entry.write_text("#!/bin/sh\n: > '" + str(marker) + "'\nexit 99\n")
        entry.chmod(0o755)
    lock = consumer / "kernels.lock.json"
    shutil.copyfile(source / "ci/kernels.lock.json", lock)
    (consumer / "counter.bpf.o").write_bytes(b"inert setup-boundary object; never loaded")
    env = {"HOME": str(home), "PATH": str(venv / "bin") + os.pathsep + str(guards),
           "PYTHONDONTWRITEBYTECODE": "1"}
    sandbox, canaries = _installed_proof_sandbox(work, consumer)
    python = str(venv / "bin/python")
    # Verify the denial inside the very process namespace used for the
    # proof, on EVERY invocation: the canaries must be absent while the
    # consumer and venv stay present. The verdict goes to stderr so the
    # proof commands' stdout stays byte-clean for exact assertions.
    probe = (
        "import os, sys; from pathlib import Path; "
        "denied, consumer, venvpython, args = __import__('json').loads(sys.argv[1]); "
        "assert all(not Path(path).exists() for path in denied), "
        "'installed source denial failed: ' + repr(denied); "
        "assert Path(consumer).is_dir(), 'consumer unavailable'; "
        "assert Path(venvpython).is_file(), 'venv unavailable'; "
        "print('installed source denial verified', file=sys.stderr, flush=True); "
        "os.execv(args[0], args)"
    )
    records = []

    def run(argv):
        payload = json.dumps([canaries, str(consumer), python, argv])
        wrapped = [sys.executable, "-c", probe, payload]
        result = subprocess.run(sandbox + wrapped, cwd=consumer, env=env,
                                capture_output=True, text=True, timeout=60)
        records.append({"argv": sandbox + wrapped, "exit": result.returncode,
                        "stdout": result.stdout, "stderr": result.stderr})
        (work / "installed-command-results.json").write_text(json.dumps(records, indent=2) + "\n")
        return result

    result = run([python, "-c", "from mojobpf.verify import resolve_lane; print(resolve_lane('v6.12', 'tcg', 'kernels.lock.json')['id'])"])
    assert result.returncode == 0 and result.stdout.strip() == "v6.12-tcg", result.stderr
    result = run([python, "-c", "from mojobpf.validation import digest_of, export_schema_bundle; print(digest_of(export_schema_bundle('schemas')))"])
    assert result.returncode == 0, result.stderr
    assert len(list((consumer / "schemas").glob("*.schema.json"))) == 5
    cli = str(venv / "bin/mojobpf")
    cases = [([], "kernels lock not found"),
             (["--kernels-lock", "missing.lock.json"], "kernels lock not found"),
             (["--kernels-lock", "kernels.lock.json"], "runner admission refused")]
    document = json.loads(lock.read_text())
    document["schema_version"] = 2
    (consumer / "tampered.lock.json").write_text(json.dumps(document))
    cases.append((["--kernels-lock", "tampered.lock.json"], "schema_version must be 1"))
    for args, expected in cases:
        result = run([cli, "verify", "--kernel", "--object", "counter.bpf.o"] + args)
        assert result.returncode == 2 and expected in result.stderr, (args, result.stdout, result.stderr)
        assert result.stdout == ""
    assert not marker.exists(), "setup controls executed a guarded producer/runner"
