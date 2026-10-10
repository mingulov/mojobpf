# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Adapter generation equivalence: wheel/sdist/standalone agree.

``compiler/`` is the authoritative adapter source; the packaged
``mojobpf/resources/adapter/`` copies are generated from it. This
suite proves every install lane ships the same generated
implementation:

* the tree's packaged copies equal the ``compiler/`` sources
  (the generation step's input/output identity, via the shared
  mirror table);
* a wheel install, an sdist install, and a standalone source-tree
  install (``pip install`` from each artifact, all offline with
  ``--no-deps --no-build-isolation``) each carry adapter scripts
  byte-identical to the ``compiler/`` sources;
* the builds genuinely regenerate: a wheel build restores stale
  committed copies from ``compiler/`` before packaging, and an
  sdist build restores deleted copies (the setuptools hook in
  ``setup.py`` runs the generator for both commands);
* the build-hook table in ``pyproject.toml`` names the same file
  set as the shared mirror table (one file set, two readers,
  pinned equal);
* generation fails closed: missing inputs fail the generator
  with a nonzero exit (never silently keep stale bytes), and a
  wheel built from the sdist regenerates from the carried
  generator and authoritative sources;
* the admission descriptor (``admission.json``) is derived from
  the capability registry, shipped byte-identically in both
  lanes, pinned in the lockfile, and required by both routes:
  host lookup and the adapter subprocess admit the same
  profiles with no live-registry fallback.

The sdist lane additionally unpacks the archive and checks the
adapter sources travel inside it, so the equivalence holds for
the published artifact itself, not just its install result.

Requires ``pip`` with ``setuptools``/``wheel`` for the running
interpreter. A missing builder is an environment failure, never a
pass. Build residue (``build/``, ``dist/``, ``*.egg-info``) the
lanes create under the checkout is removed afterwards.

Runnable directly (``python3
tests/packaging/test_adapter_generation.py``) or under any
``test_``-style runner. Standard library only, plus pytest
solely for the module-teardown fixture (guarded import; direct
runs are unaffected).
"""

import atexit
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

try:
    import pytest as _pytest
except ImportError:
    _pytest = None

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(
    0, os.path.join(REPO_ROOT, "tests", "harness")
)
import mirror_sync  # noqa: E402

_FIXTURE = {}


def _cleanup_fixture():
    """Remove the fixture's temporary parent, if still present.

    Idempotent: safe to call from ``main()``, the ``atexit``
    hook registered by ``fixture()``, and the module-teardown
    pytest fixture below.
    """
    parent = _FIXTURE.pop("dir", None)
    _FIXTURE.pop("lanes", None)
    if parent is not None:
        shutil.rmtree(parent, ignore_errors=True)


if _pytest is not None:

    @_pytest.fixture(scope="module", autouse=True)
    def _pytest_bundle_teardown():
        """Remove the lane bundle at test teardown, not process exit.

        Autouse over this module: after the module's last test,
        the cached bundle directory is removed immediately, so
        embedded ``pytest.main()`` runs release it on return
        instead of retaining it until interpreter exit. The
        ``atexit`` hook stays as the backstop for direct runs
        and non-pytest runners.
        """
        yield
        _cleanup_fixture()


class EnvironmentFailure(Exception):
    """The builder needed by this test is missing or broken."""


def _run(argv, cwd, timeout=600):
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except OSError as exc:
        raise EnvironmentFailure(
            "cannot run %s: %s" % (argv[:2], exc)
        ) from None


def _clean_build_residue(preexisting):
    for path in (
        os.path.join(REPO_ROOT, "build"),
        os.path.join(REPO_ROOT, "dist"),
        os.path.join(REPO_ROOT, "src", "mojobpf.egg-info"),
    ):
        if path not in preexisting and os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)


def _build_wheel(parent, cwd=None):
    proc = _run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            ".",
            "--no-deps",
            "--no-build-isolation",
            "-w",
            parent,
        ],
        REPO_ROOT if cwd is None else cwd,
    )
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "pip wheel failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    wheels = sorted(
        entry
        for entry in os.listdir(parent)
        if entry.endswith(".whl")
    )
    if len(wheels) != 1:
        raise EnvironmentFailure(
            "expected exactly one wheel, found: %s" % wheels
        )
    return os.path.join(parent, wheels[0])


def _build_sdist(parent):
    # No network, no isolation: invoke the configured build
    # backend's sdist hook in-process through a subprocess pinned
    # to the checkout (pip has no sdist verb of its own).
    script = (
        "import os, sys;"
        "sys.path.insert(0, os.getcwd());"
        "from setuptools import build_meta;"
        "print(build_meta.build_sdist(%r))" % parent
    )
    proc = _run([sys.executable, "-c", script], REPO_ROOT)
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "sdist build failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    archives = sorted(
        entry
        for entry in os.listdir(parent)
        if entry.endswith(".tar.gz")
    )
    if len(archives) != 1:
        raise EnvironmentFailure(
            "expected exactly one sdist, found: %s" % archives
        )
    return os.path.join(parent, archives[0])


def _install(source, target):
    proc = _run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            source,
            "--no-deps",
            "--no-build-isolation",
            "--no-index",
            "--target",
            target,
        ],
        REPO_ROOT,
    )
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "pip install %s failed (exit %d):\n%s\n%s"
            % (source, proc.returncode, proc.stdout, proc.stderr)
        )


def _installed_adapter_bytes(target):
    found = {}
    for shipped, _source in mirror_sync.SYNCED_FILES:
        path = os.path.join(target, *shipped.split("/"))
        if not os.path.isfile(path):
            raise AssertionError(
                "installed adapter script missing: %s" % shipped
            )
        with open(path, "rb") as handle:
            found[shipped] = handle.read()
    return found


def fixture():
    """Build all three lanes once per process; return their bytes."""
    if "lanes" in _FIXTURE:
        return _FIXTURE["lanes"]
    parent = tempfile.mkdtemp(prefix="mojobpf-adapter-gen-")
    _FIXTURE["dir"] = parent
    atexit.register(_cleanup_fixture)
    scratch = (
        os.path.join(REPO_ROOT, "build"),
        os.path.join(REPO_ROOT, "dist"),
        os.path.join(REPO_ROOT, "src", "mojobpf.egg-info"),
    )
    preexisting = {path for path in scratch if os.path.exists(path)}
    try:
        wheel_dir = os.path.join(parent, "wheelhouse")
        sdist_dir = os.path.join(parent, "dist")
        os.makedirs(wheel_dir)
        os.makedirs(sdist_dir)
        wheel = _build_wheel(wheel_dir)
        sdist = _build_sdist(sdist_dir)
        lanes = {}
        for label, source in (
            ("wheel", wheel),
            ("sdist", sdist),
            ("standalone", "."),
        ):
            target = os.path.join(parent, "install-%s" % label)
            os.makedirs(target)
            _install(source, target)
            lanes[label] = _installed_adapter_bytes(target)
        lanes["sdist_archive"] = sdist
        _FIXTURE["lanes"] = lanes
        return lanes
    finally:
        _clean_build_residue(preexisting)


def _compiler_bytes():
    found = {}
    for shipped, source in mirror_sync.SYNCED_FILES:
        with open(os.path.join(REPO_ROOT, source), "rb") as handle:
            found[shipped] = handle.read()
    return found


def test_tree_copies_match_authoritative_source():
    try:
        checked = mirror_sync.check_tree_mirrors(REPO_ROOT)
    except mirror_sync.MirrorDriftError as exc:
        raise AssertionError(str(exc))
    assert checked == 3, checked


def test_wheel_matches_authoritative_source():
    lanes = fixture()
    want = _compiler_bytes()
    for shipped, body in want.items():
        assert lanes["wheel"][shipped] == body, shipped


def test_sdist_matches_authoritative_source():
    lanes = fixture()
    want = _compiler_bytes()
    for shipped, body in want.items():
        assert lanes["sdist"][shipped] == body, shipped


def test_standalone_matches_authoritative_source():
    lanes = fixture()
    want = _compiler_bytes()
    for shipped, body in want.items():
        assert lanes["standalone"][shipped] == body, shipped


def test_sdist_archive_carries_adapter_sources():
    lanes = fixture()
    with tarfile.open(lanes["sdist_archive"], "r:gz") as archive:
        members = {
            member.name: member for member in archive.getmembers()
        }
    want = _compiler_bytes()
    for shipped, body in want.items():
        tree_rel = os.path.join(
            "src", "mojobpf", shipped[len("mojobpf/"):]
        )
        matches = sorted(
            name
            for name in members
            if name.replace(os.sep, "/").endswith(
                tree_rel.replace(os.sep, "/")
            )
        )
        assert len(matches) == 1, (shipped, matches)
        with tarfile.open(lanes["sdist_archive"], "r:gz") as archive:
            assert archive.extractfile(matches[0]).read() == body, (
                shipped
            )


def _hook_table():
    """Return the build-hook generation table from pyproject.toml."""
    import tomllib

    with open(
        os.path.join(REPO_ROOT, "pyproject.toml"), "rb"
    ) as handle:
        document = tomllib.load(handle)
    return document["tool"]["mojobpf"]["adapter_generation"]


def test_hook_table_matches_mirror_table():
    table = _hook_table()
    assert table["source_dir"] == "compiler", table
    assert table["target_dir"] == (
        "src/mojobpf/resources/adapter"
    ), table
    hooked = [
        ("mojobpf/resources/adapter/" + name, "compiler/" + name)
        for name in table["files"]
    ]
    assert sorted(hooked) == sorted(mirror_sync.SYNCED_FILES), (
        hooked, mirror_sync.SYNCED_FILES,
    )


def _stash_tree_copies():
    """Read every committed packaged copy; return (path, body) pairs."""
    stashed = []
    for shipped, _source in mirror_sync.SYNCED_FILES:
        copy_path = mirror_sync.packaged_path(REPO_ROOT, shipped)
        with open(copy_path, "rb") as handle:
            stashed.append((copy_path, handle.read()))
    return stashed


def _restore_tree_copies(stashed):
    """Write stashed bodies back (belt and suspenders restore)."""
    for copy_path, body in stashed:
        os.makedirs(os.path.dirname(copy_path), exist_ok=True)
        with open(copy_path, "wb") as handle:
            handle.write(body)


def _scratch_preexisting():
    scratch = (
        os.path.join(REPO_ROOT, "build"),
        os.path.join(REPO_ROOT, "dist"),
        os.path.join(REPO_ROOT, "src", "mojobpf.egg-info"),
    )
    return {path for path in scratch if os.path.exists(path)}


def test_wheel_build_regenerates_stale_copies():
    stashed = _stash_tree_copies()
    parent = tempfile.mkdtemp(prefix="mojobpf-adapter-gen-")
    preexisting = _scratch_preexisting()
    try:
        for copy_path, _body in stashed:
            with open(copy_path, "wb") as handle:
                handle.write(b"# stale copy for regeneration proof\n")
        try:
            mirror_sync.check_tree_mirrors(REPO_ROOT)
        except mirror_sync.MirrorDriftError:
            pass
        else:
            raise AssertionError("staled copies must read as drift")
        wheel_dir = os.path.join(parent, "wheelhouse")
        os.makedirs(wheel_dir)
        wheel = _build_wheel(wheel_dir)
        try:
            mirror_sync.check_tree_mirrors(REPO_ROOT)
        except mirror_sync.MirrorDriftError as exc:
            raise AssertionError(
                "wheel build did not regenerate stale copies: %s"
                % exc
            )
        target = os.path.join(parent, "install-regen")
        os.makedirs(target)
        _install(wheel, target)
        installed = _installed_adapter_bytes(target)
        for shipped, body in _compiler_bytes().items():
            assert installed[shipped] == body, shipped
    finally:
        _restore_tree_copies(stashed)
        _clean_build_residue(preexisting)
        shutil.rmtree(parent, ignore_errors=True)


def test_sdist_build_regenerates_deleted_copies():
    stashed = _stash_tree_copies()
    parent = tempfile.mkdtemp(prefix="mojobpf-adapter-gen-")
    preexisting = _scratch_preexisting()
    try:
        for copy_path, _body in stashed:
            os.remove(copy_path)
        try:
            mirror_sync.check_tree_mirrors(REPO_ROOT)
        except mirror_sync.MirrorDriftError:
            pass
        else:
            raise AssertionError("deleted copies must read as drift")
        sdist_dir = os.path.join(parent, "dist")
        os.makedirs(sdist_dir)
        sdist = _build_sdist(sdist_dir)
        try:
            mirror_sync.check_tree_mirrors(REPO_ROOT)
        except mirror_sync.MirrorDriftError as exc:
            raise AssertionError(
                "sdist build did not regenerate deleted copies: %s"
                % exc
            )
        with tarfile.open(sdist, "r:gz") as archive:
            members = {
                member.name: member for member in archive.getmembers()
            }
        for shipped, body in _compiler_bytes().items():
            tree_rel = os.path.join(
                "src", "mojobpf", shipped[len("mojobpf/"):]
            )
            matches = sorted(
                name
                for name in members
                if name.replace(os.sep, "/").endswith(
                    tree_rel.replace(os.sep, "/")
                )
            )
            assert len(matches) == 1, (shipped, matches)
            with tarfile.open(sdist, "r:gz") as archive:
                assert archive.extractfile(matches[0]).read() == body, (
                    shipped
                )
    finally:
        _restore_tree_copies(stashed)
        _clean_build_residue(preexisting)
        shutil.rmtree(parent, ignore_errors=True)


def _run_generator(args):
    """Run the tree generator as a subprocess; return its exit code."""
    proc = subprocess.run(
        [
            sys.executable,
            os.path.join(
                REPO_ROOT, "tools", "generate_adapter_resources.py"
            ),
        ]
        + args,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=300,
    )
    return proc.returncode


def test_generation_check_passes_on_clean_tree():
    assert _run_generator(["--root", REPO_ROOT, "--check"]) == 0


def _tree_src_on_path():
    src = os.path.join(REPO_ROOT, "src")
    if src not in sys.path:
        sys.path.insert(0, src)
    return src


def _compiler_admission_bytes():
    with open(
        os.path.join(REPO_ROOT, "compiler", "admission.json"), "rb"
    ) as handle:
        return handle.read()


def test_admission_descriptor_pinned_and_mirrored():
    author = _compiler_admission_bytes()
    with open(
        os.path.join(
            REPO_ROOT,
            "src",
            "mojobpf",
            "resources",
            "adapter",
            "admission.json",
        ),
        "rb",
    ) as handle:
        packed = handle.read()
    assert author == packed, "admission descriptor lanes disagree"
    digest = hashlib.sha256(author).hexdigest()
    with open(
        os.path.join(REPO_ROOT, "toolchains.lock.json"),
        encoding="utf-8",
    ) as handle:
        lock = json.load(handle)
    assert lock["adapter"]["siblings"]["admission.json"] == digest
    with open(
        os.path.join(
            REPO_ROOT,
            "src",
            "mojobpf",
            "resources",
            "adapter",
            "adapter_service.py",
        ),
        "rb",
    ) as handle:
        service = handle.read()
    assert lock["adapter"]["service_sha256"] == hashlib.sha256(
        service
    ).hexdigest()
    _tree_src_on_path()
    from mojobpf.capabilities import (
        SUPPORTED_PROFILES,
        lookup_profile,
        profile_digest,
    )

    document = json.loads(author.decode("utf-8"))
    assert document["schema_version"] == 1
    assert list(document["profiles"]) == list(SUPPORTED_PROFILES)
    for profile_id, literal in SUPPORTED_PROFILES.items():
        resolved = lookup_profile(profile_id)
        assert resolved == literal, profile_id
        assert profile_digest(resolved) == profile_digest(
            literal
        ), profile_id


def _write_hook_pyproject(root):
    with open(
        os.path.join(root, "pyproject.toml"), "w", encoding="utf-8"
    ) as handle:
        handle.write(
            "[tool.mojobpf.adapter_generation]\n"
            "source_dir = \"compiler\"\n"
            "target_dir = \"src/mojobpf/resources/adapter\"\n"
            "files = [\n"
            "    \"adapter_service.py\",\n"
            "    \"audit.py\",\n"
            "    \"mojo_ir_adapter.py\",\n"
            "]\n"
        )


def test_generator_fails_closed_without_inputs():
    parent = tempfile.mkdtemp(prefix="mojobpf-adapter-gen-closed-")
    try:
        assert _run_generator(["--root", parent]) == 2
        _write_hook_pyproject(parent)
        assert _run_generator(["--root", parent]) == 2
        shutil.copytree(
            os.path.join(REPO_ROOT, "src"),
            os.path.join(parent, "src"),
        )
        shutil.rmtree(
            os.path.join(
                parent, "src", "mojobpf", "resources", "adapter"
            ),
            ignore_errors=True,
        )
        compiler = os.path.join(parent, "compiler")
        os.makedirs(compiler)
        for name in ("adapter_service.py", "audit.py"):
            shutil.copyfile(
                os.path.join(REPO_ROOT, "compiler", name),
                os.path.join(compiler, name),
            )
        code = _run_generator(["--root", parent])
        assert code == 2, code
        assert not os.path.exists(
            os.path.join(compiler, "admission.json")
        )
        assert not os.path.exists(
            os.path.join(
                parent, "src", "mojobpf", "resources", "adapter"
            )
        )
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def _write_admission_probe_request(parent, profile_id):
    request_path = os.path.join(parent, "req.json")
    response_path = os.path.join(parent, "resp.json")
    with open(request_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "schema_version": 1,
                "input_ir": os.path.join(parent, "missing.ll"),
                "manifest_path": os.path.join(parent, "missing.toml"),
                "profile_id": profile_id,
                "output_dir": os.path.join(parent, "out"),
                "diagnostic_mode": "text",
            },
            handle,
        )
    return request_path, response_path


def _run_service_script(service_path, request_path, response_path, env):
    proc = subprocess.run(
        [
            sys.executable,
            service_path,
            "--request",
            request_path,
            "--response",
            response_path,
        ],
        cwd=os.path.dirname(response_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=300,
        env=env,
    )
    with open(response_path, encoding="utf-8") as handle:
        return proc.returncode, json.load(handle), proc.stderr


def test_host_and_adapter_agree_without_live_registry():
    _tree_src_on_path()
    from mojobpf import capabilities as capabilities_module

    saved = dict(capabilities_module.SUPPORTED_PROFILES)
    try:
        clone_id = "linux-bpfel-v3-review-clone"
        capabilities_module.SUPPORTED_PROFILES[clone_id] = saved[
            "linux-bpfel-v3"
        ]
        try:
            capabilities_module.lookup_profile(clone_id)
        except capabilities_module.ProfileError as exc:
            assert exc.diagnostic.code == "MBPF101", exc.diagnostic
        else:
            raise AssertionError("host admitted a registry-only clone")
        del capabilities_module.SUPPORTED_PROFILES["linux-bpfel-v3"]
        resolved = capabilities_module.lookup_profile("linux-bpfel-v3")
        assert resolved.profile_id == "linux-bpfel-v3"
        assert capabilities_module.helpers_for_profile(
            "linux-bpfel-v3"
        ) == (1, 2, 3, 5, 8, 14, 130)
    finally:
        capabilities_module.SUPPORTED_PROFILES.clear()
        capabilities_module.SUPPORTED_PROFILES.update(saved)
    assert capabilities_module.SUPPORTED_PROFILES == saved
    parent = tempfile.mkdtemp(prefix="mojobpf-adapter-agree-")
    try:
        fake = os.path.join(parent, "fake-site")
        pkg = os.path.join(fake, "mojobpf")
        os.makedirs(pkg)
        with open(
            os.path.join(pkg, "__init__.py"), "w", encoding="utf-8"
        ) as handle:
            handle.write("")
        with open(
            os.path.join(pkg, "capabilities.py"), "w", encoding="utf-8"
        ) as handle:
            handle.write(
                "raise RuntimeError("
                "'the adapter must never import the host registry')\n"
            )
        clean_env = dict(os.environ)
        clean_env.pop("PYTHONPATH", None)
        trap_env = dict(clean_env)
        trap_env["PYTHONPATH"] = fake
        services = (
            os.path.join(REPO_ROOT, "compiler", "adapter_service.py"),
            os.path.join(
                REPO_ROOT,
                "src",
                "mojobpf",
                "resources",
                "adapter",
                "adapter_service.py",
            ),
        )
        for service in services:
            seen = {}
            for label, env in (
                ("clean", clean_env),
                ("import-trap", trap_env),
            ):
                probe_dir = os.path.join(
                    parent, "%s-%s" % (os.path.basename(
                        os.path.dirname(service)
                    ), label),
                )
                os.makedirs(probe_dir)
                request_path, response_path = (
                    _write_admission_probe_request(
                        probe_dir, "linux-bpfel-v3-review-clone"
                    )
                )
                code, response, err = _run_service_script(
                    service, request_path, response_path, env
                )
                assert code == 1, (service, label, code, response)
                assert response["ok"] is False
                assert len(response["diagnostics"]) == 1
                diagnostic = response["diagnostics"][0]
                assert diagnostic["code"] == "MBPF212", diagnostic
                assert diagnostic["stage"] == "adapter.request", (
                    diagnostic
                )
                assert "unsupported target profile" in diagnostic[
                    "explanation"
                ], diagnostic
                assert err == "", (service, label, err)
                seen[label] = (
                    code,
                    diagnostic["code"],
                    diagnostic["stage"],
                )
                request_path, response_path = (
                    _write_admission_probe_request(
                        probe_dir, "linux-bpfel-v3"
                    )
                )
                code, response, err = _run_service_script(
                    service, request_path, response_path, env
                )
                assert code == 1, (service, label, code, response)
                assert response["ok"] is False
                assert len(response["diagnostics"]) == 1
                diagnostic = response["diagnostics"][0]
                assert diagnostic["code"] == "MBPF212", diagnostic
                assert diagnostic["stage"] == "adapter.request", (
                    diagnostic
                )
                assert "input IR not found" in diagnostic[
                    "explanation"
                ], diagnostic
                assert err == "", (service, label, err)
                seen[label] = seen[label] + (
                    code,
                    diagnostic["code"],
                    diagnostic["stage"],
                )
            assert seen["clean"] == seen["import-trap"], service
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def test_wheel_from_sdist_regenerates():
    parent = tempfile.mkdtemp(prefix="mojobpf-adapter-sdist-wheel-")
    preexisting = _scratch_preexisting()
    try:
        sdist_dir = os.path.join(parent, "sdist")
        os.makedirs(sdist_dir)
        sdist = _build_sdist(sdist_dir)
        with tarfile.open(sdist, "r:gz") as archive:
            members = [
                member.name.replace(os.sep, "/")
                for member in archive.getmembers()
            ]
        for required in (
            "tools/generate_adapter_resources.py",
            "compiler/adapter_service.py",
            "compiler/audit.py",
            "compiler/mojo_ir_adapter.py",
            "compiler/admission.json",
        ):
            assert any(
                name.endswith(required) for name in members
            ), (required, members)
        unpack = os.path.join(parent, "unpacked")
        os.makedirs(unpack)
        with tarfile.open(sdist, "r:gz") as archive:
            archive.extractall(unpack, filter="data")
        tops = sorted(
            entry
            for entry in os.listdir(unpack)
            if os.path.isdir(os.path.join(unpack, entry))
        )
        assert len(tops) == 1, tops
        root = os.path.join(unpack, tops[0])
        stale = b"# stale copy for wheel-from-sdist proof\n"
        for rel in (
            os.path.join(
                "src", "mojobpf", "resources", "adapter", "audit.py"
            ),
            os.path.join(
                "src", "mojobpf", "resources", "adapter",
                "admission.json",
            ),
            os.path.join("compiler", "admission.json"),
        ):
            with open(os.path.join(root, rel), "wb") as handle:
                handle.write(stale)
        wheel_dir = os.path.join(parent, "wheelhouse")
        os.makedirs(wheel_dir)
        wheel = _build_wheel(wheel_dir, cwd=root)
        target = os.path.join(parent, "install-sdist-wheel")
        os.makedirs(target)
        _install(wheel, target)
        installed = _installed_adapter_bytes(target)
        for shipped, body in _compiler_bytes().items():
            assert installed[shipped] == body, shipped
        with open(
            os.path.join(
                target, "mojobpf", "resources", "adapter",
                "admission.json",
            ),
            "rb",
        ) as handle:
            assert handle.read() == _compiler_admission_bytes(), (
                "admission.json"
            )
    finally:
        _clean_build_residue(preexisting)
        shutil.rmtree(parent, ignore_errors=True)


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    names = sorted(k for k in globals() if k.startswith("test_"))
    try:
        for name in names:
            try:
                globals()[name]()
            except EnvironmentFailure as exc:
                print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
                return 2
            except AssertionError as exc:
                print("FAIL %s: %s" % (name, exc))
                failures += 1
            else:
                print("PASS %s" % name)
    finally:
        _cleanup_fixture()
    if failures:
        return 1
    print("adapter generation: wheel/sdist/standalone equivalence passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
