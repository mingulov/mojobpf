# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""External consumer canary: independent source plus installed tool.

Builds the release-candidate wheel, installs it as a normal
dependency (``pip install --no-index``, no network) in a fresh
virtual environment, then copies the consumer project
(``tests/packaging/external_consumer/``: its own manifest plus its
own Mojo XDP counter source) to an unrelated working directory and
builds it there through the installed ``mojobpf`` command with the
MojoBPF source tree scrubbed from every search path and from the
working directory. The built object is executed in a disposable
guest through the standard loader/test runner
(``tests/harness/bpf_test_run.py``, contract revision 2, used as-is)
and a bpftool map lifecycle; the kernel result must be exact.

Toolchain independence is the point of this suite. ``mojo`` and
``llc`` resolve PATH-only from the ambient machine: there is no
checkout gate, no checkout-derived ``MODULAR_HOME``, and no
checkout lockfile copy. The consumer pins its own toolchain the way
a real user pins theirs (a ``toolchains.lock.json`` written beside
the copied manifest from the PATH-resolved tools); the suite
records which ``mojo`` ran and where it came from, and fails
cleanly as an environment failure when no Mojo 1.1.0 is on PATH.
Only the tool under test (package, SDK, adapter) must come from the
fresh virtual environment; only the toolchain (Mojo, LLVM, guest
runner) comes from the ambient machine.

The suite also proves the negative sides: the consumer imports no
compiler internals (every import inside the installed SDK export
list), copies no SDK implementation (its source matches no shipped
or tree source byte-for-byte), keeps no path back into the MojoBPF
tree, compiles from its own source (the evidence sidecar seals its
source hash and records the frontend/adapter/backend stages -- a
copied prebuilt object is not a consumer build), and cannot build
once the package is uninstalled.

The virtual environments and the consumer working copy are
ephemeral fixtures under a temporary directory, removed afterwards;
they are not the project's environment. The guest stage
(``/tmp/consumer-canary-*``) is removed after the run, like every
other guest suite's stage. Requires ``pip`` with
``setuptools``/``wheel`` for the running interpreter, the ``venv``
module, genuine ``mojo``/``llc`` on PATH, and ``vng`` (virtme-ng)
with a cached guest image on PATH (default release v6.12;
MOJOBPF_VNG_RELEASE selects the matrix lane). Anything missing is
an environment failure, never a pass.

Runnable directly (``python3
tests/packaging/test_external_consumer.py``) or under any
``test_``-style runner. Standard library only. The guest boot takes
a few minutes under software emulation.

Consumer toolchain admission: when MOJOBPF_CONSUMER_TOOLCHAIN_BIN
(a compiler prefix directory) and MOJOBPF_CONSUMER_TOOLCHAIN_LOCK
(independently recorded mojo/llc pins) are both set, the suite
admits the prefix tools against those pins before executing them;
a same-version replacement or an unpinned exec chain fails loudly
without running. Without both variables the suite keeps the
historical PATH discovery, but the written lockfile is labeled
bootstrap: a self-pin is never an independent trust root.

Guest bpftool staging admits the shared-rootfs bpftool against
independently reviewed pins (MOJOBPF_BPFTOOL_PINS) before probing
it; without reviewed pins, or on any mismatch, staging refuses
without executing. The staged pins are the reviewed pins
verbatim: the version probe only verifies them.

Every host-runnable check (isolated builds, toolchain
resolution, admission mechanics, lock and schema checks) runs
by default, including under pytest. Only the guest-backed
checks gate: under pytest they skip unless
MOJOBPF_CONSUMER_FULL=1 is set, and every run (direct or
pytest) boots a guest only with an explicit target lease
(MOJOBPF_CONSUMER_GUEST_LEASE=1); without a lease the guest
checks report required-unavailable loudly, never a silent
skip and never a pass.
"""

import atexit
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(
    0, os.path.join(REPO_ROOT, "tests", "harness")
)
sys.path.insert(
    0, os.path.join(REPO_ROOT, "src")
)
from mojobpf import execution  # noqa: E402
import guest_proc  # noqa: E402
import lane_lock  # noqa: E402
import tool_admission  # noqa: E402
CONSUMER_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "external_consumer"
)
HARNESS = os.path.join(REPO_ROOT, "tests", "harness", "bpf_test_run.py")

CONSUMER_FILES = ("README.md", "mojobpf.toml", "canary.mojo")
CONSUMER_LOCKFILE = "toolchains.lock.json"
CONSUMER_OBJECT = "canary_counter.bpf.o"
CONSUMER_SIDECAR = "canary_counter.evidence.json"

# Tokens that must never appear in the consumer's own files: adapter
# and compiler internals, tree-relative escapes, SDK source paths,
# and developer-environment markers.
FORBIDDEN_TOKENS = (
    "mojo_ir_adapter",
    "adapter_service",
    "compiler/",
    "../mojobpf",
    "resources/sdk",
    "src/mojobpf",
    ".pixi",
    "MODULAR_HOME",
)

XDP_PASS = 2
# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = 900
MAP_NAME = "mojobpf_map0"
INIT_VALUE = 41
AFTER_FIRST = 42
AFTER_SECOND = 43

_FIXTURE = {}
_GUEST = {}


class EnvironmentFailure(Exception):
    """The toolchain, builder, or VM needed by this test is missing."""


CONSUMER_FULL_ENV = "MOJOBPF_CONSUMER_FULL"
CONSUMER_PREFIX_ENV = "MOJOBPF_CONSUMER_TOOLCHAIN_BIN"
CONSUMER_PINS_ENV = "MOJOBPF_CONSUMER_TOOLCHAIN_LOCK"
CONSUMER_GUEST_ENV = "MOJOBPF_CONSUMER_GUEST_LEASE"
BPFTOOL_PINS_ENV = tool_admission.BPFTOOL_PINS_ENV


# B1: the admission trio lives in tests/harness/tool_admission.py;
# these aliases keep the pinned test surface verbatim while the
# implementation is single-sourced in the helper.
ConsumerAdmissionError = tool_admission.ToolAdmissionError


class GuestRequiredError(Exception):
    """A guest boot was requested without a target lease."""


def _require_full_run(caller):
    """Skip guest-backed work unless a full run is requested.

    Direct runs (``python3 tests/packaging/test_*_consumer.py``, the
    form the VM matrix uses) always opt in: ``main()`` sets
    ``MOJOBPF_CONSUMER_FULL=1``. Under pytest the guest tests
    skip without it; the skip reason names the missing guest
    capability. Host work never calls this gate.
    """
    if os.environ.get(CONSUMER_FULL_ENV) == "1":
        return
    try:
        import pytest as _pytest
    except ImportError:
        raise EnvironmentFailure(
            "%s needs a leased guest target (set %s=1 and %s=1 "
            "with a disposable vng lane)"
            % (caller, CONSUMER_FULL_ENV, CONSUMER_GUEST_ENV)
        )
    _pytest.skip(
        "%s needs a leased guest target (set %s=1 and %s=1 "
        "with a disposable vng lane)"
        % (caller, CONSUMER_FULL_ENV, CONSUMER_GUEST_ENV)
    )


def _require_guest(caller):
    """Refuse guest boots without an explicit target lease.

    The full-run gate runs first (pytest skips without it, with
    the missing guest capability named). A full run without
    ``MOJOBPF_CONSUMER_GUEST_LEASE=1`` then raises
    :class:`GuestRequiredError`: a disposable guest is never
    booted without a lease, never skipped silently, and never
    counted as a pass.
    """
    _require_full_run(caller)
    if os.environ.get(CONSUMER_GUEST_ENV) != "1":
        raise GuestRequiredError(
            "%s: guest required, no target lease (set %s=1 with "
            "a disposable vng lane to boot)"
            % (caller, CONSUMER_GUEST_ENV)
        )


def _run(argv, cwd, env, timeout):
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except OSError as exc:
        raise EnvironmentFailure(
            "cannot run %s: %s" % (argv[:2], exc)
        ) from None


def _sha256_file(path):
    digest = hashlib.sha256()
    with guest_proc.open_consumed(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _under_repo(path):
    try:
        return os.path.commonpath(
            [os.path.realpath(path), os.path.realpath(REPO_ROOT)]
        ) == os.path.realpath(REPO_ROOT)
    except (OSError, ValueError):
        return True


def _build_wheel(parent):
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
        REPO_ROOT,
        dict(os.environ),
        600,
    )
    for path in (
        os.path.join(REPO_ROOT, "build"),
        os.path.join(REPO_ROOT, "src", "mojobpf.egg-info"),
    ):
        if os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)
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


def _scrubbed_env(venv_bin):
    """Consumer base environment: ambient PATH minus the checkout tree.

    The base carries PATH and HOME only, never MODULAR_HOME: the
    fixture adds the toolchain home derived from the resolved
    ``mojo`` binary itself (see :func:`_derive_toolchain_home`),
    so the consumer build cannot inherit ambient developer
    state.
    """
    kept = []
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry or _under_repo(entry):
            continue
        kept.append(entry)
    for entry in [venv_bin] + kept:
        assert not _under_repo(entry), entry
    env = {
        "PATH": os.pathsep.join([venv_bin] + kept),
        "HOME": os.environ.get("HOME", "/tmp"),
    }
    assert "PYTHONPATH" not in env
    assert "MODULAR_HOME" not in env
    return env


def _derive_toolchain_home(mojo_path, exec_path):
    """Derive the toolchain's MODULAR_HOME from its install prefix.

    The max-packaged Mojo frontend resolves ``modular.cfg`` (and
    through it the compiled standard library) via MODULAR_HOME;
    without it every compile fails with ``unable to locate
    module 'std'``. The home is derived strictly from the
    resolved ``mojo`` binary's own install prefix --
    ``<prefix>/share/max`` validated by the presence of
    ``modular.cfg`` -- trying the executed image first and the
    PATH entry second, and both the ``bin/``-nested and the
    prefix-flat layouts. It reads only its path arguments and
    the toolchain prefix, never the ambient environment, so the
    consumer env cannot inherit developer state. Returns None
    when the toolchain carries no provable home (a
    self-contained install compiles without one).
    """
    candidates = []
    for anchor in (exec_path, mojo_path):
        if not anchor:
            continue
        try:
            real = os.path.realpath(anchor)
        except OSError:
            continue
        entry_dir = os.path.dirname(real)
        for base in (os.path.dirname(entry_dir), entry_dir):
            candidate = os.path.join(base, "share", "max")
            if candidate not in candidates:
                candidates.append(candidate)
    for candidate in candidates:
        if os.path.isfile(os.path.join(candidate, "modular.cfg")):
            return candidate
    return None


def _probe_tool(name, env):
    """Resolve one toolchain binary PATH-only; record its identity.

    Bootstrap observation, never a trust root: the chain is
    captured, then admitted record-only and probed through the
    shared execution contract's verify-then-spawn path, so the
    reported identity always describes the executed bytes and a
    replacement landing between capture and probe is refused
    instead of executed.
    """
    path = shutil.which(name, path=env["PATH"])
    if path is None:
        raise EnvironmentFailure(
            "required tool %r is not on the consumer PATH" % name
        )
    if _under_repo(path) or _under_repo(os.path.realpath(path)):
        raise EnvironmentFailure(
            "tool %r resolves into the checkout tree: %s" % (name, path)
        )
    realpath = os.path.realpath(path)
    try:
        captured = execution.capture_chain(realpath)
    except execution.AdmissionError as exc:
        raise EnvironmentFailure(
            "tool %r cannot be captured: %s" % (name, exc.detail)
        )
    if captured.form == execution.FORM_UNKNOWN:
        raise EnvironmentFailure(
            "tool %r has an unresolvable launcher chain: %s"
            % (name, captured.note)
        )
    if captured.form == execution.FORM_EXEC_LAUNCHER:
        entry_sha256 = captured.hops[0].sha256
        exec_sha256 = captured.image.sha256
        exec_pin_present = True
    else:
        entry_sha256 = captured.image.sha256
        exec_sha256 = None
        exec_pin_present = False
    try:
        admitted = execution.admit_execution(
            execution.ExecutionRequest(
                name=name,
                argv0=realpath,
                allow_path_lookup=False,
                forms=execution.DEFAULT_FORMS,
                probe_version=True,
                trust_root="bootstrap",
            ),
            execution.ExecutionPins(
                entry_sha256=entry_sha256,
                exec_sha256=exec_sha256,
                exec_pin_present=exec_pin_present,
            ),
            probe_timeout=120,
        )
    except execution.AdmissionError as exc:
        raise EnvironmentFailure(
            "tool %r refused between capture and probe: %s"
            % (name, exc)
        )
    if admitted.form == execution.FORM_EXEC_LAUNCHER:
        exec_path = admitted.image.realpath
        final_exec_sha256 = admitted.image.sha256
    else:
        exec_path = None
        final_exec_sha256 = None
    return {
        "name": name,
        "path": path,
        "realpath": admitted.entry.realpath,
        "version": admitted.version,
        "sha256": admitted.entry.sha256,
        "exec_path": exec_path,
        "exec_sha256": final_exec_sha256,
    }


def _resolve_prefix_tool(name, prefix):
    """Resolve one tool strictly under the admitted prefix directory."""
    if not prefix or not os.path.isdir(prefix):
        raise ConsumerAdmissionError(
            "consumer toolchain prefix is not a directory: %r"
            % (prefix,)
        )
    candidate = os.path.join(prefix, name)
    if not os.path.isfile(candidate):
        raise ConsumerAdmissionError(
            "required tool %r is missing from the admitted prefix %s"
            % (name, prefix)
        )
    if _under_repo(candidate) or _under_repo(os.path.realpath(candidate)):
        raise ConsumerAdmissionError(
            "tool %r resolves into the checkout tree: %s"
            % (name, candidate)
        )
    return candidate


def _admit_tool(name, path, expected, env, timeout=120):
    """Admit one prefix-resolved tool against independent pins.

    Capture, pin checks and the version probe all run through
    the shared execution contract: the entry/exec/version pins
    are enforced before any process starts, the probe spawns
    the admitted image through the verify-then-spawn path, and
    a replacement landing between capture and probe is refused
    instead of executed. Any mismatch -- including an
    unresolvable launcher chain -- raises ConsumerAdmissionError
    without executing the tool. ``expected`` carries
    version/sha256 plus exec_sha256 (None requires the entry to
    be its own image). ``env`` is kept for the call shape; the
    probe runs under the contract's sanitized environment.
    Returns the same record shape as :func:`_probe_tool`.
    """
    for key in ("version", "sha256"):
        if not isinstance(expected.get(key), str) or not expected[key]:
            raise ConsumerAdmissionError(
                "independent pins for %r lack %r" % (name, key)
            )
    realpath = os.path.realpath(path)
    try:
        admitted = execution.admit_execution(
            execution.ExecutionRequest(
                name=name,
                argv0=realpath,
                allow_path_lookup=False,
                forms=execution.DEFAULT_FORMS,
                probe_version=True,
                trust_root="independent-pins",
            ),
            execution.ExecutionPins(
                version=expected["version"],
                entry_sha256=expected["sha256"],
                exec_sha256=expected.get("exec_sha256"),
                exec_pin_present=(
                    expected.get("exec_sha256") is not None
                ),
            ),
            probe_timeout=timeout,
        )
    except execution.AdmissionError as exc:
        raise ConsumerAdmissionError(
            "tool %r refused: %s" % (name, exc)
        )
    if admitted.form == execution.FORM_EXEC_LAUNCHER:
        exec_path = admitted.image.realpath
        exec_sha256 = admitted.image.sha256
    else:
        exec_path = None
        exec_sha256 = None
    return {
        "name": name,
        "path": path,
        "realpath": admitted.entry.realpath,
        "version": admitted.version,
        "sha256": admitted.entry.sha256,
        "exec_path": exec_path,
        "exec_sha256": exec_sha256,
    }


def _load_independent_pins():
    """Load independently recorded compiler pins, or None for bootstrap.

    Both MOJOBPF_CONSUMER_TOOLCHAIN_BIN (a compiler prefix
    directory) and MOJOBPF_CONSUMER_TOOLCHAIN_LOCK (a pins JSON
    document recorded out of band) must be set; anything else is
    bootstrap mode. The pins document admits only with the
    explicitly reviewed status (``reviewed``): any other status,
    including a missing one, stays unadmitted. A
    configured-but-unusable pins document fails loudly: silent
    fallback would hide a broken independent channel. A
    consumer-generated self-pin is never accepted as the
    independent record.
    """
    prefix = os.environ.get(CONSUMER_PREFIX_ENV, "")
    pins_path = os.environ.get(CONSUMER_PINS_ENV, "")
    if not prefix or not pins_path:
        return None
    try:
        with open(pins_path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ConsumerAdmissionError(
            "cannot load independent pins %s: %s" % (pins_path, exc)
        )
    if not isinstance(document, dict):
        raise ConsumerAdmissionError(
            "independent pins %s is not an object" % pins_path
        )
    if document.get("status") != "reviewed":
        raise ConsumerAdmissionError(
            "independent pins %s carry status %r: only the "
            "explicitly reviewed admission state admits "
            "(anything else, including a test-generated "
            "self-pin, is not an independent trust root)"
            % (pins_path, document.get("status"))
        )
    if "consumer" in str(document.get("generated_by", "")).lower():
        raise ConsumerAdmissionError(
            "independent pins %s were generated by a consumer "
            "suite: a self-pin is not an independent trust root"
            % pins_path
        )
    if document.get("schema_version") != 1:
        raise ConsumerAdmissionError(
            "independent pins %s have unsupported schema_version"
            % pins_path
        )
    tools = document.get("tools")
    if not isinstance(tools, dict):
        raise ConsumerAdmissionError(
            "independent pins %s have no tools table" % pins_path
        )
    expected = {}
    for name in ("mojo", "llc"):
        entry = tools.get(name)
        if not isinstance(entry, dict):
            raise ConsumerAdmissionError(
                "independent pins %s lack %r" % (pins_path, name)
            )
        for key in ("version", "sha256"):
            if not isinstance(entry.get(key), str) or not entry[key]:
                raise ConsumerAdmissionError(
                    "independent pins %s entry %r lacks %r"
                    % (pins_path, name, key)
                )
        expected[name] = {
            "exec_sha256": entry.get("exec_sha256"),
            "sha256": entry["sha256"],
            "version": entry["version"],
        }
    return {
        "llc": expected["llc"],
        "mojo": expected["mojo"],
        "path": pins_path,
        "prefix": prefix,
        "source_sha256": _sha256_file(pins_path),
    }


def _installed_adapter_dir(venv):
    """Locate the installed adapter resources inside a venv."""
    for lib in sorted(os.listdir(venv)):
        if not lib.startswith("lib"):
            continue
        site = os.path.join(venv, lib)
        for entry in sorted(os.listdir(site)):
            if not entry.startswith("python"):
                continue
            candidate = os.path.join(
                site, entry, "site-packages", "mojobpf",
                "resources", "adapter",
            )
            if os.path.isfile(
                os.path.join(candidate, "adapter_service.py")
            ):
                return candidate
    raise EnvironmentFailure(
        "installed adapter resources missing in %s" % venv
    )


def _write_consumer_lockfile(project, mojo, llc, trust,
                             adapter_pins=None):
    """Pin the consumer's toolchain plus its trust origin.

    ``trust`` is ``{"status": "admitted"|"bootstrap", ...}``:
    admitted pins were checked against the independently recorded
    compiler pins before execution; bootstrap pins are PATH
    self-pins and never qualify as independently trusted.
    """
    admitted = trust.get("status") == "admitted"
    document = {
        "generated_by": (
            "external consumer (independently admitted pins)"
            if admitted
            else "external consumer (PATH-resolved pins)"
        ),
        "license": "Apache-2.0 WITH LLVM-exception",
        "schema_version": 1,
        "status": trust["status"],
        "trust": dict(trust),
        "tools": {
            "llc": {
                "exec_sha256": llc["exec_sha256"],
                "sha256": llc["sha256"],
                "version": llc["version"],
            },
            "mojo": {
                "exec_sha256": mojo["exec_sha256"],
                "sha256": mojo["sha256"],
                "version": mojo["version"],
            },
        },
    }
    if adapter_pins is not None:
        document["adapter"] = adapter_pins
    lockfile_path = os.path.join(project, CONSUMER_LOCKFILE)
    with open(lockfile_path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return lockfile_path


def _make_venv(root, name):
    venv = os.path.join(root, name)
    proc = _run(
        [sys.executable, "-m", "venv", venv],
        REPO_ROOT,
        dict(os.environ),
        300,
    )
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "venv creation failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    venv_bin = os.path.join(venv, "bin")
    if not os.path.isfile(os.path.join(venv_bin, "pip")):
        raise EnvironmentFailure("venv has no pip")
    return venv, venv_bin


def fixture():
    """Install the wheel fresh, then run the isolated consumer build.

    Host-only: the wheel build, fresh virtualenv,
    installed-package build and toolchain probing all run on the
    build host, under pytest by default. Guest booting lives in
    :func:`guest_run` behind the target-lease gate; the ``vng``
    guest runner is probed there, never here.
    """
    if "root" in _FIXTURE:
        return _FIXTURE
    independent = _load_independent_pins()
    if independent is None:
        for tool in ("mojo", "llc"):
            if shutil.which(tool) is None:
                raise EnvironmentFailure(
                    "%s not found on PATH" % tool
                )
    for name in CONSUMER_FILES:
        if not os.path.isfile(os.path.join(CONSUMER_DIR, name)):
            raise EnvironmentFailure("missing consumer file: %s" % name)
    if not os.path.isfile(HARNESS):
        raise EnvironmentFailure("missing harness: %s" % HARNESS)
    root = tempfile.mkdtemp(prefix="mojobpf-consumer-")
    _FIXTURE["root"] = root
    atexit.register(_cleanup)
    venv, venv_bin = _make_venv(root, "venv")
    venv_python = os.path.join(venv_bin, "python")
    venv_mojobpf = os.path.join(venv_bin, "mojobpf")
    wheel = _build_wheel(os.path.join(root, "dist"))
    proc = _run(
        [os.path.join(venv_bin, "pip"), "install",
         "--no-index", "--no-deps", wheel],
        root,
        dict(os.environ),
        300,
    )
    if proc.returncode != 0:
        raise EnvironmentFailure(
            "pip install failed (exit %d):\n%s\n%s"
            % (proc.returncode, proc.stdout, proc.stderr)
        )
    if not os.path.isfile(venv_mojobpf):
        raise EnvironmentFailure("installed console script missing")
    adapter_dir = _installed_adapter_dir(venv)
    adapter_pins = {
        "service_sha256": _sha256_file(
            os.path.join(adapter_dir, "adapter_service.py")
        ),
        "siblings": {
            name: _sha256_file(os.path.join(adapter_dir, name))
            for name in (
                "mojo_ir_adapter.py",
                "audit.py",
                "admission.json",
            )
        },
    }
    work = os.path.join(root, "work")
    project = os.path.join(work, "consumer")
    os.makedirs(project)
    for name in CONSUMER_FILES:
        with guest_proc.open_consumed(os.path.join(CONSUMER_DIR, name), "rb") as handle:
            data = handle.read()
        with open(os.path.join(project, name), "wb") as handle:
            handle.write(data)
    env = _scrubbed_env(venv_bin)
    if independent is not None:
        prefix = independent["prefix"]
        entries = env["PATH"].split(os.pathsep)
        assert entries and entries[0] == venv_bin, entries
        assert not _under_repo(prefix), prefix
        env["PATH"] = os.pathsep.join(
            [venv_bin, prefix] + entries[1:]
        )
        mojo = _admit_tool(
            "mojo",
            _resolve_prefix_tool("mojo", prefix),
            independent["mojo"],
            env,
        )
        llc = _admit_tool(
            "llc",
            _resolve_prefix_tool("llc", prefix),
            independent["llc"],
            env,
        )
        trust = {
            "origin": (
                "independently admitted compiler prefix %s "
                "(pins %s sha256 %s)"
                % (
                    prefix,
                    independent["path"],
                    independent["source_sha256"],
                )
            ),
            "pins": independent["path"],
            "pins_sha256": independent["source_sha256"],
            "prefix": prefix,
            "status": "admitted",
        }
    else:
        mojo = _probe_tool("mojo", env)
        llc = _probe_tool("llc", env)
        trust = {
            "origin": (
                "self-pin from PATH discovery; not an independent "
                "trust root (set %s and %s for admitted pins)"
                % (CONSUMER_PREFIX_ENV, CONSUMER_PINS_ENV)
            ),
            "status": "bootstrap",
        }
    home = _derive_toolchain_home(mojo["path"], mojo["exec_path"])
    if home is not None and _under_repo(home):
        raise EnvironmentFailure(
            "derived toolchain home resolves into the checkout "
            "tree: %s" % home
        )
    mojo["home"] = home
    if home is not None:
        env["MODULAR_HOME"] = home
    lockfile_path = _write_consumer_lockfile(
        project, mojo, llc, trust, adapter_pins
    )
    manifest_path = os.path.join(project, "mojobpf.toml")
    out_dir = os.path.join(work, "out")
    for path in (manifest_path, out_dir, lockfile_path, work):
        assert os.path.isabs(path), path
        assert not _under_repo(path), path
    proc = _run(
        [
            venv_mojobpf,
            "build",
            "--manifest", manifest_path,
            "--out-dir", out_dir,
            "--lockfile", lockfile_path,
        ],
        project,
        env,
        600,
    )
    _FIXTURE.update(
        {
            "venv": venv,
            "venv_bin": venv_bin,
            "venv_python": venv_python,
            "venv_mojobpf": venv_mojobpf,
            "work": work,
            "project": project,
            "manifest_path": manifest_path,
            "lockfile_path": lockfile_path,
            "out_dir": out_dir,
            "env": env,
            "mojo": mojo,
            "llc": llc,
            "trust": trust,
            "independent_pins": (
                independent["path"] if independent is not None else None
            ),
            "build": proc,
        }
    )
    return _FIXTURE


def _cleanup():
    root = _FIXTURE.pop("root", None)
    if root is not None:
        shutil.rmtree(root, ignore_errors=True)


def _evidence_document(fix):
    sidecar = os.path.join(fix["out_dir"], CONSUMER_SIDECAR)
    assert os.path.isfile(sidecar), "evidence sidecar missing"
    with guest_proc.open_consumed(sidecar, "rb") as handle:
        raw = handle.read()
    assert REPO_ROOT.encode() not in raw, "sidecar leaks checkout bytes"
    assert os.path.dirname(REPO_ROOT).encode() not in raw
    return json.loads(raw.decode("ascii")), raw


def test_consumer_builds_with_installed_tool():
    fix = fixture()
    proc = fix["build"]
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
    objects = sorted(
        entry
        for entry in os.listdir(fix["out_dir"])
        if entry.endswith(".bpf.o")
    )
    assert objects == [CONSUMER_OBJECT], objects
    doc, _raw = _evidence_document(fix)
    assert doc["schema_version"] == 4, doc
    assert doc["success"] is True
    assert doc["tool_version"] == "0.3.0a1", doc
    assert doc["sdk_version"] == "1.5", doc
    assert doc["artifact"] == "canary_counter", doc


def test_consumer_toolchain_resolved_path_only():
    fix = fixture()
    mojo = fix["mojo"]
    assert mojo["version"].startswith("Mojo 1.1.0"), mojo
    assert not _under_repo(mojo["path"]), mojo
    assert not _under_repo(mojo["realpath"]), mojo
    home = fix["mojo"].get("home")
    if home is None:
        assert "MODULAR_HOME" not in fix["env"], (
            "a toolchain without a provable home must leave the "
            "consumer env clean"
        )
    else:
        assert fix["env"].get("MODULAR_HOME") == home, fix["env"]
        assert not _under_repo(home), home
        assert os.path.isfile(os.path.join(home, "modular.cfg")), home
        assert home == _derive_toolchain_home(
            mojo["path"], mojo["exec_path"]
        ), "consumer home must re-derive from the resolved binary"
    assert "PYTHONPATH" not in fix["env"]
    for entry in fix["env"]["PATH"].split(os.pathsep):
        assert not _under_repo(entry), entry
    proc = _run(
        [fix["venv_python"], "-c",
         "import sys; print(sys.path)"],
        fix["project"],
        fix["env"],
        60,
    )
    assert proc.returncode == 0, proc.stderr
    assert REPO_ROOT not in proc.stdout, proc.stdout
    proc = _run(
        [fix["venv_mojobpf"], "doctor", "--json"],
        fix["project"],
        fix["env"],
        120,
    )
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    package = os.path.realpath(doc["package_path"])
    assert package.startswith(
        os.path.realpath(fix["venv"]) + os.sep
    ), package
    tools = {
        item["name"]: item
        for item in doc["toolchain"]["tools"]
    }
    assert tools["mojo"]["status"] == "present", tools
    assert tools["mojo"]["version"] == mojo["version"], tools
    assert tools["mojo"]["sha256"] == mojo["sha256"], tools
    assert not _under_repo(tools["mojo"]["path"]), tools
    assert tools["mojo"]["exec_path"] == mojo["exec_path"], tools
    assert tools["mojo"]["exec_sha256"] == mojo["exec_sha256"], tools
    if mojo["exec_path"] is None:
        assert mojo["exec_sha256"] is None, mojo
    else:
        assert mojo["exec_sha256"] != mojo["sha256"], mojo
        assert not _under_repo(mojo["exec_path"]), mojo
        assert os.path.isfile(mojo["exec_path"]), mojo


def test_consumer_imports_only_the_sdk_surface():
    fix = fixture()
    source = os.path.join(fix["project"], "canary.mojo")
    proc = _run(
        [
            fix["venv_python"], "-c",
            "import json, sys; "
            "from mojobpf.sdk import check_mojo_file; "
            "sys.stdout.write(json.dumps("
            "[(v.line, v.statement, v.explanation) "
            "for v in check_mojo_file(sys.argv[1])]))",
            source,
        ],
        fix["project"],
        fix["env"],
        120,
    )
    assert proc.returncode == 0, proc.stderr
    violations = json.loads(proc.stdout)
    assert violations == [], violations


def test_consumer_has_no_copy_no_path_back():
    fix = fixture()
    project_files = sorted(os.listdir(fix["project"]))
    assert project_files == sorted(
        list(CONSUMER_FILES) + [CONSUMER_LOCKFILE]
    ), project_files
    for name in CONSUMER_FILES:
        with guest_proc.open_consumed(
            os.path.join(fix["project"], name), "rb"
        ) as handle:
            data = handle.read()
        for token in FORBIDDEN_TOKENS:
            assert token.encode() not in data, (name, token)
        assert REPO_ROOT.encode() not in data, name
    assert not [
        name for name in project_files
        if name.endswith((".bpf.o", ".ll", ".json"))
        and name != CONSUMER_LOCKFILE
    ], "consumer must compile; no prebuilt object may ride along"
    canary_sha = _sha256_file(os.path.join(fix["project"], "canary.mojo"))
    own_source = os.path.join(CONSUMER_DIR, "canary.mojo")
    compared = 0
    for current, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [
            entry for entry in dirs
            if entry not in ("__pycache__", ".git", ".pixi", "build")
        ]
        for name in files:
            if not name.endswith(".mojo"):
                continue
            other = os.path.join(current, name)
            if os.path.realpath(other) == os.path.realpath(own_source):
                continue
            compared += 1
            assert _sha256_file(other) != canary_sha, (
                "consumer source copies %s" % other
            )
    assert compared > 0, "no in-tree Mojo sources compared"
    print("PASS no-copy corpus: canary differs from %d sources" % compared)


def test_consumer_object_compiled_from_own_source():
    fix = fixture()
    assert fix["build"].returncode == 0
    doc, _raw = _evidence_document(fix)
    by_stage = {}
    for item in doc["commands"]:
        by_stage.setdefault(item["stage"], []).append(item)
    for stage in ("build.frontend", "build.adapter", "build.backend"):
        assert stage in by_stage, sorted(by_stage)
        for item in by_stage[stage]:
            assert item["status"] == "ok", item
            assert item["exit_code"] == 0, item
    frontend_argv = " ".join(by_stage["build.frontend"][0]["argv"])
    assert "mojo" in frontend_argv, frontend_argv
    assert "--emit" in frontend_argv, frontend_argv
    backend_argv = " ".join(by_stage["build.backend"][0]["argv"])
    assert "llc" in backend_argv, backend_argv
    assert "bpfel" in backend_argv, backend_argv
    sources = {
        item["path"]: item["sha256"]
        for item in doc["inputs"]["source"]
    }
    assert sources == {
        "canary.mojo": _sha256_file(
            os.path.join(fix["project"], "canary.mojo")
        )
    }, sources
    compiler_blob = " ".join(doc["inputs"]["compiler"])
    assert fix["mojo"]["version"] in compiler_blob, compiler_blob
    assert fix["mojo"]["sha256"] in compiler_blob, compiler_blob
    assert fix["llc"]["version"] in compiler_blob, compiler_blob
    assert fix["llc"]["sha256"] in compiler_blob, compiler_blob
    obj = os.path.join(fix["out_dir"], CONSUMER_OBJECT)
    proc = _run(
        [
            fix["venv_mojobpf"],
            "inspect",
            "--object", obj,
            "--source-license", "Apache-2.0 WITH LLVM-exception",
            "--kernel-license", "Apache-2.0 WITH LLVM-exception",
        ],
        fix["project"],
        fix["env"],
        120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ok" in proc.stdout


def test_build_fails_without_installed_package():
    fix = fixture()
    bare_venv, bare_bin = _make_venv(fix["root"], "bare-venv")
    bare_python = os.path.join(bare_bin, "python")
    assert not os.path.exists(os.path.join(bare_bin, "mojobpf"))
    env = _scrubbed_env(bare_bin)
    proc = _run(
        [bare_python, "-c", "import mojobpf"],
        fix["project"],
        env,
        60,
    )
    assert proc.returncode != 0, "mojobpf resolves without install"
    proc = _run(
        [
            bare_python, "-m", "mojobpf", "build",
            "--manifest", fix["manifest_path"],
            "--out-dir", os.path.join(fix["work"], "bare-out"),
            "--lockfile", fix["lockfile_path"],
        ],
        fix["project"],
        env,
        120,
    )
    assert proc.returncode != 0, "build works without the package"
    assert "No module named mojobpf" in proc.stderr, proc.stderr
    assert not os.path.exists(os.path.join(fix["work"], "bare-out"))


def hexle(value):
    """Lowercase hex of a u64 value without spaces (bpftool order)."""
    return "".join(
        "%02x" % byte for byte in value.to_bytes(8, byteorder="little")
    )


GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
{bpftool_prologue}
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin guest_canary ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "=== staged hashes ==="
sha256sum bpf_test_run.py canary.bpf.o data.bin guest_canary.sh
map_case() {{
  tag="$1"; obj="$2"
  pin="/sys/fs/bpf/mojobpf_map_$tag"
  out="/tmp/xdp-$tag.fields"
  : > "$out"
  "$BPFTOOL" prog load "$obj" "$pin" type xdp >/tmp/xdp-$tag.load 2>&1
  echo "load_exit=$?" >> "$out"
  python3 - "$out" >/tmp/xdp-$tag.mapinfo 2>&1 <<'PYEOF'
import json
import subprocess
import sys
fields = sys.argv[1]
info = {{"map_found": "0"}}
try:
    raw = subprocess.run(
        [{bpftool_argv0}, "-j", "map", "show"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    for entry in json.loads(raw.stdout or "[]"):
        if entry.get("name") == "{map_name}":
            info = {{
                "map_found": "1",
                "map_id": str(entry.get("id")),
                "map_type": str(entry.get("type")),
                "map_key": str(entry.get("bytes_key")),
                "map_value": str(entry.get("bytes_value")),
                "map_entries": str(entry.get("max_entries")),
            }}
except Exception as exc:
    info = {{"map_found": "0", "map_error": str(exc)}}
with open(fields, "a") as handle:
    for key in sorted(info):
        handle.write("%s=%s\\n" % (key, info[key]))
PYEOF
  echo "mapinfo_exit=$?" >> "$out"
  map_id=$(grep '^map_id=' "$out" | cut -d= -f2)
  "$BPFTOOL" map update id "$map_id" key 0 0 0 0 value {init} 0 0 0 0 0 0 0 >/tmp/xdp-$tag.update 2>&1
  echo "init_exit=$?" >> "$out"
  "$BPFTOOL" map lookup id "$map_id" key 0 0 0 0 > /tmp/xdp-$tag.before 2>&1
  echo "before_exit=$?" >> "$out"
  "$BPFTOOL" prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run1 2>&1
  echo "run1_exit=$?" >> "$out"
  "$BPFTOOL" map lookup id "$map_id" key 0 0 0 0 > /tmp/xdp-$tag.after1 2>&1
  echo "after1_exit=$?" >> "$out"
  "$BPFTOOL" prog run pinned "$pin" data_in data.bin repeat 1 > /tmp/xdp-$tag.run2 2>&1
  echo "run2_exit=$?" >> "$out"
  "$BPFTOOL" map lookup id "$map_id" key 0 0 0 0 > /tmp/xdp-$tag.after2 2>&1
  echo "after2_exit=$?" >> "$out"
  rm -f "$pin"
  if [ -e "$pin" ]; then echo "unload_ok=0" >> "$out"; else echo "unload_ok=1" >> "$out"; fi
  echo "=== BEGIN $tag ==="
  cat "$out"
  echo "--- $tag before ---"
  cat /tmp/xdp-$tag.before
  echo "--- $tag run1 ---"
  cat /tmp/xdp-$tag.run1
  echo "--- $tag after1 ---"
  cat /tmp/xdp-$tag.after1
  echo "--- $tag run2 ---"
  cat /tmp/xdp-$tag.run2
  echo "--- $tag after2 ---"
  cat /tmp/xdp-$tag.after2
  echo "=== END $tag ==="
}}
harness_case() {{
  tag="$1"; obj="$2"
  out="/tmp/xdp-$tag.json"
  pin="/sys/fs/bpf/$tag/prog"
  mkdir -p "/sys/fs/bpf/$tag"
  python3 bpf_test_run.py --object "$obj" --expect-action {action} \\
    --data-in data.bin --pin-path "$pin" --owned-root /sys/fs/bpf \\
    --ownership-token "$tag" --bpftool {bpftool_path} \\
    --bpftool-sha256 {bpftool_sha256} {bpftool_exec_arg} \\
    --bpftool-version {bpftool_version} \\
    --output "$out" >/tmp/xdp-$tag.stdout 2>/tmp/xdp-$tag.stderr
  code=$?
  rm -f "$pin"
  rmdir "/sys/fs/bpf/$tag" 2>/dev/null
  echo "=== BEGIN $tag exit=$code ==="
  cat "$out"
  echo "=== END $tag ==="
}}
{commands}
echo "=== pin check ==="
stray=0
for pin in /sys/fs/bpf/mojobpf_map_* /sys/fs/bpf/mojobpf_control; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; stray=1; fi
done
if [ "$stray" -eq 0 ]; then echo "pin absent (unloaded)"; fi
echo "=== end guest_canary ==="
"""

CASES = (
    ("canary", "canary.bpf.o", "map"),
    ("canary-harness", "canary.bpf.o", "harness"),
)


_load_reviewed_bpftool_pins = tool_admission.load_reviewed_pins


_stage_bpftool_pins = tool_admission.stage_tool_pins


_render_bpftool_prologue = tool_admission.render_prologue
_render_guest_mount = tool_admission.render_guest_mount


def _render_guest_script(stage, commands, pins):
    """Render the guest script with the staged harness pins.

    The admitted bpftool chain re-verifies in the guest
    prologue before any probe runs; every guest probe runs
    ``"$BPFTOOL"``, never a bare PATH-resolved ``bpftool``.
    """
    return GUEST_SCRIPT.format(
        stage=stage,
        commands="\n".join(commands),
        map_name=MAP_NAME,
        init=INIT_VALUE,
        action=XDP_PASS,
        bpftool_prologue=(_render_bpftool_prologue(pins)
                + "\n"
                + _render_guest_mount()),
        bpftool_path=shlex.quote(pins["path"]),
        bpftool_argv0=json.dumps(pins["path"]),
        bpftool_sha256=pins["sha256"],
        bpftool_exec_arg=(
            "--bpftool-exec-sha256 " + pins["exec_sha256"]
            if pins["exec_sha256"] is not None
            else ""
        ),
        bpftool_version=shlex.quote(pins["version"]),
    )


def _run_guest(argv, stage, timeout):
    """Run the guest command; return (exit code, output text).

    Thin mapping over the shared owned runner
    (tests/harness/guest_proc.py): a timeout surfaces as
    EnvironmentFailure carrying the partial output.
    """
    try:
        return guest_proc.run_owned(argv, stage, timeout)
    except guest_proc.GuestTimeout as exc:
        raise EnvironmentFailure(
            "vng guest run timed out after %ds (stage %s):\n%s"
            % (timeout, stage, exc.output[-4000:])
        )


def guest_run():
    """Stage the consumer object, boot one guest, return case results."""
    _require_guest("guest_run")
    if "run" in _GUEST:
        return _GUEST["run"]
    fix = fixture()
    assert fix["build"].returncode == 0, "consumer build must pass first"
    # The guest boots with the scrubbed-PATH vng binary probed
    # here -- after the lease gate -- never an ambient
    # re-resolution and never fixture work.
    vng = _probe_tool("vng", fix["env"])
    vng_path = vng["path"]
    stage = guest_proc.owned_stage(prefix="consumer-canary-", dir="/tmp")
    staged = {
        "bpf_test_run.py": HARNESS,
        "canary.bpf.o": os.path.join(fix["out_dir"], CONSUMER_OBJECT),
    }
    with open(os.path.join(stage, "data.bin"), "wb") as handle:
        handle.write(bytes(60))
    for name, src in staged.items():
        with guest_proc.open_consumed(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    host_shas = {
        name: _sha256_file(os.path.join(stage, name))
        for name in list(staged) + ["data.bin"]
    }
    commands = []
    for tag, obj, kind in CASES:
        if kind == "map":
            commands.append("map_case %s %s" % (tag, obj))
        else:
            commands.append("harness_case %s %s" % (tag, obj))
    try:
        pins = _stage_bpftool_pins(fix["env"])
    except tool_admission.ToolMissingError as exc:
        raise EnvironmentFailure(str(exc))
    script = _render_guest_script(stage, commands, pins)
    script_path = os.path.join(stage, "guest_canary.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["data.bin", "guest_canary.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(stage, 0o755)
    # A1 guest handoff: consume the staged bytes through the recorder
    # and re-stage from the consumed buffers; the pre-staging host
    # hashes above must equal these consumed buffers, and the
    # guest-reported hashes compare against the same identity.
    handed = guest_proc.stage_consumed_for_guest(
        guest_proc.active_recorder(), stage,
        tuple(staged) + ("data.bin", "guest_canary.sh"),
    )
    if guest_proc.active_recorder() is not None:
        for _name, _sha in sorted(host_shas.items()):
            assert handed.get(_name) == _sha, (
                "staged bytes changed between staging "
                "and seal: %s" % _name
            )
    returncode, output = _run_guest(
        [vng_path, "--run", VNG_RELEASE, "--disable-kvm",
        "--exec", "bash %s" % script_path],
        stage, VNG_TIMEOUT,
    )
    results = {}
    for match in re.finditer(
        r"=== BEGIN (\S+)(?: exit=(\d+))? ===\n(.*?)\n=== END \1 ===",
        output,
        re.DOTALL,
    ):
        tag, exit_code, body = match.groups()
        results[tag] = {
            "exit": int(exit_code) if exit_code is not None else None,
            "body": body,
        }
    verdict = guest_proc.classify_guest_exit(
        returncode, output,
        records=list(results.values()),
        progress_banner="=== begin guest_canary ===",
    )
    if verdict == "proof":
        raise AssertionError(
            "vng guest run failed with proof evidence (exit %d, "
            "stage %s):\n%s"
            % (returncode, stage, output[-4000:])
        )
    if verdict == "env":
        raise EnvironmentFailure(
            "vng guest run failed (exit %d, stage %s):\n%s"
            % (returncode, stage, output[-4000:])
        )
    # Retain the raw guest transcript alongside the staged inputs
    # so observed results stay auditable after the run; the stage
    # directory is never cleaned by the suite itself.
    transcript_path = os.path.join(stage, "guest_transcript.log")
    with open(transcript_path, "w", encoding="utf-8") as handle:
        handle.write(output)
    print("guest transcript: %s" % transcript_path)
    missing = [tag for tag, _, _ in CASES if tag not in results]
    if missing:
        raise guest_proc.GuestMissing(
            "guest output lacks cases %s (stage %s):\n%s"
            % (", ".join(missing), stage, output[-4000:])
        )
    _GUEST["run"] = {
        "stage": stage,
        "output": output,
        "results": results,
        "host_shas": host_shas,
    }
    return _GUEST["run"]


def test_guest_harness_case_carries_admission():
    pins = {
        "path": "/usr/sbin/bpftool",
        "sha256": "1" * 64,
        "exec_sha256": None,
        "version": "bpftool v7.7.0",
    }
    script = _render_guest_script(
        "/tmp/stage", ["harness_case TAG obj.bpf.o"], pins
    )
    assert "--bpftool /usr/sbin/bpftool" in script, script
    assert "--bpftool-sha256 %s" % ("1" * 64) in script
    assert "--bpftool-version 'bpftool v7.7.0'" in script
    assert "--bpftool-exec-sha256" not in script
    assert "--ownership-token \"$tag\"" in script
    assert "--pin-path \"$pin\"" in script
    assert "mkdir -p \"/sys/fs/bpf/$tag\"" in script
    assert "rmdir \"/sys/fs/bpf/$tag\"" in script
    pins["exec_sha256"] = "2" * 64
    script = _render_guest_script(
        "/tmp/stage", ["harness_case TAG obj.bpf.o"], pins
    )
    assert "--bpftool-exec-sha256 %s" % ("2" * 64) in script


def test_guest_script_binds_bpftool_to_reviewed_pins():
    pins = {
        "path": "/usr/sbin/bpftool",
        "sha256": "1" * 64,
        "exec_sha256": None,
        "version": "v7.7.0",
    }
    script = _render_guest_script(
        "/tmp/stage", ["harness_case TAG obj.bpf.o"], pins
    )
    assert "BPFTOOL=/usr/sbin/bpftool" in script, script
    assert "%s  $BPFTOOL" % ("1" * 64) in script, script
    assert "BPFTOOL-PIN-MISMATCH" in script, script
    assert '"/usr/sbin/bpftool"' in script, script
    assert '"bpftool"' not in script, script
    body = "\n".join(
        line
        for line in script.splitlines()
        if not line.startswith("BPFTOOL=")
    )
    assert "$BPFTOOL" in body, body
    assert not re.search(
        r"(?<![/\w$.\-])bpftool(?![\w])", body
    ), body


def _count_marker_lines(path):
    if not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8") as handle:
        return len(handle.readlines())


def test_guest_prologue_rejects_post_staging_image_replacement():
    # Round-4 item 2: staging admits the launcher entry
    # `exec "<image>" "$@"`; replacing the exec image after
    # staging must refuse in the guest prologue, before any
    # guest probe runs. The rendered prologue executes here
    # under /bin/sh against the staged files: intact bytes
    # pass, replaced image bytes refuse with zero new probes.
    workdir = tempfile.mkdtemp(prefix="consumer-imagegap-")
    saved = _save_consumer_env()
    try:
        image = _write_staging_bpftool(workdir, name="bpftool-image")
        entry = os.path.join(workdir, "bpftool")
        _write_host_script(
            entry,
            '#!/bin/sh\nexec "%s" "$@"\n' % image["path"],
        )
        pins_path = _write_reviewed_bpftool_pins(
            workdir, entry, image["version"]
        )
        os.environ[BPFTOOL_PINS_ENV] = pins_path
        env = {
            "PATH": workdir + os.pathsep + "/usr/bin:/bin",
            "HOME": workdir,
        }
        pins = _stage_bpftool_pins(env)
        assert pins["exec_sha256"] == _sha256_file(
            os.path.realpath(image["path"])
        ), pins
        staged_probes = _count_marker_lines(image["marker"])
        assert staged_probes >= 1, (
            "staging must probe the admitted chain"
        )
        prologue = _render_bpftool_prologue(pins)
        script_path = os.path.join(workdir, "prologue.sh")
        with open(script_path, "w", encoding="utf-8") as handle:
            handle.write(prologue + "\n")
        run = subprocess.run(
            ["/bin/sh", script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
            env={"PATH": "/usr/bin:/bin"},
        )
        assert run.returncode == 0, (
            run.returncode, run.stdout, run.stderr,
        )
        assert _count_marker_lines(image["marker"]) == staged_probes, (
            "the prologue itself must not execute bpftool"
        )
        with open(image["path"], "a", encoding="utf-8") as handle:
            handle.write("# same-version image replacement\n")
        assert _sha256_file(os.path.realpath(image["path"])) != (
            pins["exec_sha256"]
        )
        refused = subprocess.run(
            ["/bin/sh", script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
            env={"PATH": "/usr/bin:/bin"},
        )
        assert refused.returncode != 0, (
            refused.returncode, refused.stdout, refused.stderr,
        )
        assert "BPFTOOL-EXEC-MISMATCH" in refused.stdout, (
            refused.returncode, refused.stdout, refused.stderr,
        )
        assert _count_marker_lines(image["marker"]) == staged_probes, (
            "a refused prologue must start zero new probes"
        )
        script = _render_guest_script(
            "/tmp/stage", ["harness_case TAG obj.bpf.o"], pins
        )
        assert prologue in script, script
        head = script.split(prologue, 1)[0]
        assert '"$BPFTOOL"' not in head, head
        assert '"$BPFTOOL"' in script, script
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_guest_prologue_rejects_post_staging_middle_replacement():
    # Round-5 item 1: staging admits the launcher chain
    # entry -> middle -> image; replacing the MIDDLE after
    # staging must refuse in the guest prologue, before any
    # guest probe runs. Entry and image hashes stay valid
    # across the swap, so only the intermediate check can
    # refuse. The rendered prologue executes here under
    # /bin/sh against the staged files.
    workdir = tempfile.mkdtemp(prefix="consumer-middlegap-")
    saved = _save_consumer_env()
    try:
        image = _write_staging_bpftool(workdir, name="bpftool-image")
        middle = os.path.join(workdir, "bpftool-middle")
        _write_host_script(
            middle,
            '#!/bin/sh\nexec "%s" "$@"\n' % image["path"],
        )
        entry = os.path.join(workdir, "bpftool")
        _write_host_script(
            entry,
            '#!/bin/sh\nexec "%s" "$@"\n' % middle,
        )
        pins_path = _write_reviewed_bpftool_pins(
            workdir, entry, image["version"]
        )
        os.environ[BPFTOOL_PINS_ENV] = pins_path
        env = {
            "PATH": workdir + os.pathsep + "/usr/bin:/bin",
            "HOME": workdir,
        }
        pins = _stage_bpftool_pins(env)
        assert pins["exec_sha256"] == _sha256_file(
            os.path.realpath(image["path"])
        ), pins
        middle_sha256 = _sha256_file(os.path.realpath(middle))
        staged_probes = _count_marker_lines(image["marker"])
        assert staged_probes >= 1, (
            "staging must probe the admitted chain"
        )
        prologue = _render_bpftool_prologue(pins)
        script_path = os.path.join(workdir, "prologue.sh")
        with open(script_path, "w", encoding="utf-8") as handle:
            handle.write(prologue + "\n")
        run = subprocess.run(
            ["/bin/sh", script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
            env={"PATH": "/usr/bin:/bin"},
        )
        assert run.returncode == 0, (
            run.returncode, run.stdout, run.stderr,
        )
        assert _count_marker_lines(image["marker"]) == staged_probes, (
            "the prologue itself must not execute bpftool"
        )
        # Replace the middle with an unresolved exec launcher.
        # Both checked endpoint hashes stay valid: only the
        # complete-chain check refuses.
        _write_host_script(
            middle,
            '#!/bin/sh\nexec "$UNAPPROVED_TOOL" "$@"\n',
        )
        assert _sha256_file(os.path.realpath(entry)) == (
            pins["sha256"]
        ), pins
        assert _sha256_file(os.path.realpath(image["path"])) == (
            pins["exec_sha256"]
        ), pins
        refused = subprocess.run(
            ["/bin/sh", script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
            env={"PATH": "/usr/bin:/bin"},
        )
        assert refused.returncode != 0, (
            refused.returncode, refused.stdout, refused.stderr,
        )
        assert "BPFTOOL-CHAIN-MISMATCH" in refused.stdout, (
            refused.returncode, refused.stdout, refused.stderr,
        )
        assert _count_marker_lines(image["marker"]) == staged_probes, (
            "a refused prologue must start zero new probes"
        )
        # The complete admitted chain is pinned: the staging
        # return carries the intermediate launcher's path and
        # hash alongside the entry and final image pins.
        chain = pins["chain"]
        assert [link["path"] for link in chain] == [middle], pins
        assert [link["realpath"] for link in chain] == [
            os.path.realpath(middle)
        ], pins
        assert chain[0]["sha256"] == middle_sha256, pins
        # The shared admission agrees with the guest refusal:
        # the swapped chain no longer resolves.
        captured = execution.capture_chain(os.path.realpath(entry))
        assert captured.form == execution.FORM_UNKNOWN, captured
        script = _render_guest_script(
            "/tmp/stage", ["harness_case TAG obj.bpf.o"], pins
        )
        assert prologue in script, script
        head = script.split(prologue, 1)[0]
        assert '"$BPFTOOL"' not in head, head
        assert '"$BPFTOOL"' in script, script
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_guest_prologue_rejects_post_staging_chain_symlink_retarget():
    # Round-6 item 1: staging admits the launcher chain
    # entry -> middle -> image where the middle hop and the
    # exec image are both reached through symlinks;
    # retargeting either link after staging must refuse in
    # the guest prologue, before any guest probe runs. Every
    # recorded hash stays valid across each retarget, so only
    # a live resolution recheck of the recorded hop pathname
    # refuses. The rendered prologue executes here under
    # /bin/sh against the staged files.
    workdir = tempfile.mkdtemp(prefix="consumer-linkgap-")
    saved = _save_consumer_env()
    try:
        image = _write_staging_bpftool(workdir, name="bpftool-image")
        image_link = os.path.join(workdir, "bpftool-image-link")
        os.symlink(image["path"], image_link)
        good = os.path.join(workdir, "bpftool-good-middle")
        _write_host_script(
            good,
            '#!/bin/sh\nexec "%s" "$@"\n' % image_link,
        )
        middle = os.path.join(workdir, "bpftool-middle")
        os.symlink(good, middle)
        entry = os.path.join(workdir, "bpftool")
        _write_host_script(
            entry,
            '#!/bin/sh\nexec "%s" "$@"\n' % middle,
        )
        pins_path = _write_reviewed_bpftool_pins(
            workdir, entry, image["version"]
        )
        os.environ[BPFTOOL_PINS_ENV] = pins_path
        env = {
            "PATH": workdir + os.pathsep + "/usr/bin:/bin",
            "HOME": workdir,
        }
        pins = _stage_bpftool_pins(env)
        assert pins["exec_sha256"] == _sha256_file(
            os.path.realpath(image["path"])
        ), pins
        good_sha256 = _sha256_file(os.path.realpath(good))
        staged_probes = _count_marker_lines(image["marker"])
        assert staged_probes >= 1, (
            "staging must probe the admitted chain"
        )
        prologue = _render_bpftool_prologue(pins)
        script_path = os.path.join(workdir, "prologue.sh")
        with open(script_path, "w", encoding="utf-8") as handle:
            handle.write(prologue + "\n")
        run = subprocess.run(
            ["/bin/sh", script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
            env={"PATH": "/usr/bin:/bin"},
        )
        assert run.returncode == 0, (
            run.returncode, run.stdout, run.stderr,
        )
        assert _count_marker_lines(image["marker"]) == staged_probes, (
            "the prologue itself must not execute bpftool"
        )
        # Retarget the middle link to an unresolvable exec
        # launcher. Entry, image and staging-observed middle
        # bytes all stay valid: only the resolution recheck
        # of the recorded hop pathname refuses.
        bad = os.path.join(workdir, "bpftool-bad-middle")
        _write_host_script(
            bad,
            '#!/bin/sh\nexec "$UNAPPROVED_TOOL" "$@"\n',
        )
        os.unlink(middle)
        os.symlink(bad, middle)
        assert _sha256_file(os.path.realpath(entry)) == (
            pins["sha256"]
        ), pins
        assert _sha256_file(os.path.realpath(image["path"])) == (
            pins["exec_sha256"]
        ), pins
        assert _sha256_file(os.path.realpath(good)) == good_sha256
        refused = subprocess.run(
            ["/bin/sh", script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
            env={"PATH": "/usr/bin:/bin"},
        )
        assert refused.returncode != 0, (
            refused.returncode, refused.stdout, refused.stderr,
        )
        assert "BPFTOOL-CHAIN-MISMATCH" in refused.stdout, (
            refused.returncode, refused.stdout, refused.stderr,
        )
        assert _count_marker_lines(image["marker"]) == staged_probes, (
            "a refused prologue must start zero new probes"
        )
        # The staging return preserves each original hop
        # pathname alongside its staging resolution: the
        # middle hop names the link, not the bytes behind it,
        # and the exec image likewise keeps its link.
        chain = pins["chain"]
        assert [link["path"] for link in chain] == [middle], pins
        assert [link["realpath"] for link in chain] == [
            os.path.realpath(good)
        ], pins
        assert chain[0]["sha256"] == good_sha256, pins
        assert pins["exec_link"] == image_link, pins
        assert pins["exec_path"] == os.path.realpath(
            image["path"]
        ), pins
        # The shared admission agrees with the guest refusal:
        # the retargeted chain no longer resolves.
        captured = execution.capture_chain(os.path.realpath(entry))
        assert captured.form == execution.FORM_UNKNOWN, captured
        # Restore the middle and retarget the image link
        # instead: the exec-image resolution recheck refuses.
        os.unlink(middle)
        os.symlink(good, middle)
        bad_image = os.path.join(workdir, "bpftool-bad-image")
        _write_host_script(
            bad_image,
            '#!/bin/sh\nexec "$UNAPPROVED_TOOL" "$@"\n',
        )
        os.unlink(image_link)
        os.symlink(bad_image, image_link)
        assert _sha256_file(os.path.realpath(image["path"])) == (
            pins["exec_sha256"]
        ), pins
        refused = subprocess.run(
            ["/bin/sh", script_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
            env={"PATH": "/usr/bin:/bin"},
        )
        assert refused.returncode != 0, (
            refused.returncode, refused.stdout, refused.stderr,
        )
        assert "BPFTOOL-EXEC-MISMATCH" in refused.stdout, (
            refused.returncode, refused.stdout, refused.stderr,
        )
        assert _count_marker_lines(image["marker"]) == staged_probes, (
            "a refused prologue must start zero new probes"
        )
        captured = execution.capture_chain(os.path.realpath(entry))
        assert captured.form == execution.FORM_UNKNOWN, captured
        script = _render_guest_script(
            "/tmp/stage", ["harness_case TAG obj.bpf.o"], pins
        )
        assert prologue in script, script
        head = script.split(prologue, 1)[0]
        assert '"$BPFTOOL"' not in head, head
        assert '"$BPFTOOL"' in script, script
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_stage_bpftool_pins_reject_unresolvable_launcher():
    workdir = tempfile.mkdtemp(prefix="consumer-bpftoollauncher-")
    saved = _save_consumer_env()
    ambient = os.environ.pop("UNAPPROVED_TOOL", None)
    try:
        marker = os.path.join(workdir, "launcher-marker.log")
        path = os.path.join(workdir, "bpftool")
        _write_host_script(
            path,
            "#!/bin/sh\necho probe >> %s\n"
            "exec</dev/null \"$UNAPPROVED_TOOL\" \"$@\"\n" % marker,
        )
        document = {
            "bpftool": {
                "exec_sha256": None,
                "sha256": _sha256_file(os.path.realpath(path)),
                "version": "bpftool v9.9.9",
            },
            "generated_by": (
                "host fixture (independent bpftool record)"
            ),
            "schema_version": 1,
            "status": "reviewed",
        }
        pins_path = os.path.join(workdir, "bpftool-pins.json")
        with open(pins_path, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.environ[BPFTOOL_PINS_ENV] = pins_path
        env = {
            "PATH": workdir + os.pathsep + "/usr/bin:/bin",
            "HOME": workdir,
        }
        try:
            _stage_bpftool_pins(env)
        except ConsumerAdmissionError as exc:
            note = str(exc)
            assert (
                "chain" in note
                or "unsupported" in note
                or "launcher" in note
            ), note
        else:
            raise AssertionError("unresolvable launcher staged")
        assert not os.path.exists(marker), (
            "unresolvable launcher must never execute"
        )
    finally:
        if ambient is None:
            os.environ.pop("UNAPPROVED_TOOL", None)
        else:
            os.environ["UNAPPROVED_TOOL"] = ambient
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def _write_staging_bpftool(workdir, name="bpftool"):
    """Fixture bpftool entry: direct script reporting a fixed version."""
    marker = os.path.join(workdir, "%s-marker.log" % name)
    version = "bpftool v9.9.9"
    path = os.path.join(workdir, name)
    _write_host_script(
        path,
        "#!/bin/sh\necho probe >> %s\necho '%s'\n"
        % (marker, version),
    )
    return {"marker": marker, "path": path, "version": version}


def _write_reviewed_bpftool_pins(
    workdir, path, version, mutate=None, name="bpftool-pins.json"
):
    """Independently reviewed bpftool pins for one entry's bytes."""
    captured = execution.capture_chain(os.path.realpath(path))
    assert captured.form != execution.FORM_UNKNOWN, captured.note
    if captured.form == execution.FORM_EXEC_LAUNCHER:
        exec_sha256 = captured.image.sha256
    else:
        exec_sha256 = None
    document = {
        "bpftool": {
            "exec_sha256": exec_sha256,
            "sha256": _sha256_file(os.path.realpath(path)),
            "version": version,
        },
        "generated_by": "host fixture (independent bpftool record)",
        "schema_version": 1,
        "status": "reviewed",
    }
    if mutate is not None:
        mutate(document)
    pins_path = os.path.join(workdir, name)
    with open(pins_path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return pins_path


def test_stage_bpftool_pins_refuse_without_reviewed_pins():
    workdir = tempfile.mkdtemp(prefix="consumer-nobpfpins-")
    saved = _save_consumer_env()
    real_run = subprocess.run
    real_popen = subprocess.Popen
    try:
        tool = _write_staging_bpftool(workdir)
        env = {
            "PATH": workdir + os.pathsep + "/usr/bin:/bin",
            "HOME": workdir,
        }
        subprocess.run = _refusing_spawn
        subprocess.Popen = _refusing_spawn
        try:
            _stage_bpftool_pins(env)
        except ConsumerAdmissionError as exc:
            assert "reviewed" in str(exc), exc
        else:
            raise AssertionError("staged bpftool pins without review")
        finally:
            subprocess.run = real_run
            subprocess.Popen = real_popen
        assert not os.path.exists(tool["marker"]), (
            "unstaged bpftool must never execute"
        )
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_stage_bpftool_pins_reject_replacement():
    workdir = tempfile.mkdtemp(prefix="consumer-bpftoolswap-")
    saved = _save_consumer_env()
    real_run = subprocess.run
    real_popen = subprocess.Popen
    try:
        original_dir = os.path.join(workdir, "original")
        replacement_dir = os.path.join(workdir, "replacement")
        os.makedirs(original_dir)
        os.makedirs(replacement_dir)
        original = _write_staging_bpftool(original_dir)
        replacement = _write_staging_bpftool(replacement_dir)
        with open(
            replacement["path"], "a", encoding="utf-8"
        ) as handle:
            handle.write("# same-version replacement\n")
        pins_path = _write_reviewed_bpftool_pins(
            workdir, original["path"], original["version"]
        )
        os.environ[BPFTOOL_PINS_ENV] = pins_path
        env = {
            "PATH": os.pathsep.join(
                [replacement_dir, original_dir, "/usr/bin", "/bin"]
            ),
            "HOME": workdir,
        }
        subprocess.run = _refusing_spawn
        subprocess.Popen = _refusing_spawn
        try:
            _stage_bpftool_pins(env)
        except ConsumerAdmissionError:
            pass
        else:
            raise AssertionError("replacement bpftool self-pinned")
        finally:
            subprocess.run = real_run
            subprocess.Popen = real_popen
        assert not os.path.exists(replacement["marker"]), (
            "replacement bpftool must never execute"
        )
        assert not os.path.exists(original["marker"]), (
            "staging must stop at the resolved replacement"
        )
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_stage_bpftool_pins_require_reviewed_status():
    workdir = tempfile.mkdtemp(prefix="consumer-bpfreviewed-")
    saved = _save_consumer_env()
    try:
        tool = _write_staging_bpftool(workdir)
        env = {
            "PATH": workdir + os.pathsep + "/usr/bin:/bin",
            "HOME": workdir,
        }

        def _check_rejected(tag, mutate, marker):
            pins_path = _write_reviewed_bpftool_pins(
                workdir, tool["path"], tool["version"],
                mutate=mutate,
            )
            os.environ[BPFTOOL_PINS_ENV] = pins_path
            try:
                _stage_bpftool_pins(env)
            except ConsumerAdmissionError as exc:
                assert marker in str(exc), (tag, exc)
            else:
                raise AssertionError(
                    "%s bpftool pins staged" % tag
                )

        def _draft_observational(document):
            document["status"] = "draft"
            document["generated_by"] = (
                "tests/probes/toolchain_inventory.py"
            )

        _check_rejected(
            "draft observational", _draft_observational, "reviewed"
        )

        def _bootstrap(document):
            document["status"] = "bootstrap"

        _check_rejected("bootstrap", _bootstrap, "reviewed")

        def _admitted_label(document):
            document["status"] = "admitted"

        _check_rejected(
            "admitted-labeled", _admitted_label, "reviewed"
        )
        _check_rejected(
            "unreviewed",
            lambda document: document.pop("status", None),
            "reviewed",
        )

        def _consumer_self_pin(document):
            document["generated_by"] = (
                "external consumer (PATH-resolved pins)"
            )

        _check_rejected(
            "consumer self-pin",
            _consumer_self_pin,
            "not an independent trust root",
        )
        assert not os.path.exists(tool["marker"]), (
            "unreviewed bpftool must never execute"
        )
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_stage_bpftool_pins_admit_reviewed_tool():
    workdir = tempfile.mkdtemp(prefix="consumer-bpfadmit-")
    saved = _save_consumer_env()
    try:
        tool = _write_staging_bpftool(workdir)
        pins_path = _write_reviewed_bpftool_pins(
            workdir, tool["path"], tool["version"]
        )
        os.environ[BPFTOOL_PINS_ENV] = pins_path
        env = {
            "PATH": workdir + os.pathsep + "/usr/bin:/bin",
            "HOME": workdir,
        }
        pins = _stage_bpftool_pins(env)
        assert pins == {
            "chain": [],
            "exec_link": None,
            "exec_path": None,
            "exec_sha256": None,
            "path": os.path.realpath(tool["path"]),
            "sha256": _sha256_file(os.path.realpath(tool["path"])),
            "version": tool["version"],
        }, pins
        assert os.path.isfile(tool["marker"]), (
            "the admitted probe must run the reviewed bytes"
        )
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_stage_bpftool_pins_from_shared_rootfs():
    bpftool = shutil.which("bpftool")
    assert bpftool is not None, (
        "host needs bpftool to stage harness admission pins"
    )
    workdir = tempfile.mkdtemp(prefix="consumer-bpftoolpins-")
    saved = _save_consumer_env()
    try:
        proc = subprocess.run(
            [os.path.realpath(bpftool), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        text = proc.stdout if proc.stdout.strip() else proc.stderr
        version = None
        for line in text.splitlines():
            if line.strip():
                version = line.strip()
                break
        assert version is not None
        pins_path = _write_reviewed_bpftool_pins(
            workdir, os.path.realpath(bpftool), version
        )
        os.environ[BPFTOOL_PINS_ENV] = pins_path
        pins = _stage_bpftool_pins({"PATH": os.environ.get("PATH", "")})
        assert pins["path"] == os.path.realpath(bpftool)
        assert pins["sha256"] == _sha256_file(
            os.path.realpath(bpftool)
        )
        assert pins["version"] == version, pins
        if pins["exec_sha256"] is not None:
            assert len(pins["exec_sha256"]) == 64, pins
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def parse_fields(body):
    fields = {}
    for line in body.splitlines():
        if "=" in line and not line.startswith(("key:", "---", "Return")):
            key, _, value = line.partition("=")
            key = key.strip()
            if key and " " not in key:
                fields[key] = value.strip()
    return fields


def parse_lookup_hex(body, marker):
    """Extract the looked-up value bytes as compact lowercase hex."""
    section = body.split(marker, 1)[1]
    match = re.search(r"value:\s*([0-9a-fA-F ]+)", section)
    assert match, "no bpftool value line after %r" % marker
    return match.group(1).replace(" ", "").lower()


def parse_run_action(body, marker):
    section = body.split(marker, 1)[1]
    match = re.search(r"Return value:\s*(\d+)", section)
    assert match, "no bpftool return-value line after %r" % marker
    return int(match.group(1))


def test_consumer_exact_kernel_result():
    run = guest_run()
    body = run["results"]["canary"]["body"]
    fields = parse_fields(body)
    for key in (
        "load_exit",
        "mapinfo_exit",
        "init_exit",
        "before_exit",
        "run1_exit",
        "after1_exit",
        "run2_exit",
        "after2_exit",
    ):
        assert fields.get(key) == "0", "%s=%r" % (key, fields.get(key))
    assert fields.get("map_found") == "1", "map not found"
    assert fields.get("map_type") == "array", "not an array map"
    assert fields.get("map_key") == "4", "key size is not u32"
    assert fields.get("map_value") == "8", "value size is not u64"
    assert fields.get("map_entries") == "1", "not one entry"
    assert fields.get("unload_ok") == "1", "pin was not removed"
    before = parse_lookup_hex(body, "before ---")
    assert before == hexle(INIT_VALUE), (
        "userspace init must read back %d first, got %s"
        % (INIT_VALUE, before)
    )
    assert parse_run_action(body, "run1 ---") == XDP_PASS
    after_first = parse_lookup_hex(body, "after1 ---")
    assert after_first == hexle(AFTER_FIRST), (
        "first run must observe %d, got %s" % (AFTER_FIRST, after_first)
    )
    assert parse_run_action(body, "run2 ---") == XDP_PASS
    after_second = parse_lookup_hex(body, "after2 ---")
    assert after_second == hexle(AFTER_SECOND), (
        "second run must observe %d, got %s"
        % (AFTER_SECOND, after_second)
    )


def test_consumer_standard_runner_passes():
    run = guest_run()
    record = run["results"]["canary-harness"]
    try:
        doc = json.loads(record["body"])
    except ValueError:
        raise guest_proc.GuestMissing(
            "harness did not emit JSON:\n%s" % record["body"][-500:]
        )
    guest_proc.check_harness_exit(
        "canary-harness", exit=record["exit"],
        classification=doc.get("classification"),
        stage=doc.get("stage"),
        contract_version=doc.get("contract_version"),
        note=doc.get("note"), expect=0)
    assert doc.get("contract_version") == 2, doc
    assert doc.get("status") == "pass", doc
    assert doc.get("stage") == "run", doc
    assert doc.get("classification") is None, doc
    assert doc.get("expected_action") == XDP_PASS, doc
    assert doc.get("actual_action") == XDP_PASS, doc
    assert doc.get("cleanup_ok") is True, doc
    assert doc.get("object", {}).get("sha256") == run["host_shas"][
        "canary.bpf.o"
    ], doc


def test_consumer_guest_provenance():
    run = guest_run()
    try:
        observed_kernel = lane_lock.booted_kernel_from_output(run["output"])
        lane_lock.check_booted_kernel(
            observed_kernel, REPO_ROOT, VNG_RELEASE
        )
    except lane_lock.LaneLockError as exc:
        raise AssertionError("guest kernel must be locked: %s" % exc)
    assert "pin absent (unloaded)" in run["output"], "pins must go"
    assert "PIN STILL PRESENT" not in run["output"], "pins must go"
    for name, sha in sorted(run["host_shas"].items()):
        assert "%s  %s" % (sha, name) in run["output"], (
            "guest must re-verify staged bytes for %s" % name
        )
    rec = guest_proc.active_recorder()
    if rec is not None:
        expected = rec.consumed_staged_digest(
            "guest_canary.sh", run["stage"]
        )
        assert expected is not None, (
            "staged bytes missing for guest_canary.sh"
        )
        assert "%s  guest_canary.sh" % expected in run["output"], (
            "guest must re-verify staged bytes for guest_canary.sh"
        )


def _write_host_script(path, body):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
    os.chmod(path, 0o755)


def _make_host_prefix(workdir):
    """Fixture compiler prefix: launcher mojo plus script llc."""
    bindir = os.path.join(workdir, "prefix", "bin")
    realdir = os.path.join(workdir, "prefix", "real")
    os.makedirs(bindir)
    os.makedirs(realdir)
    mojo_marker = os.path.join(workdir, "mojo-marker.log")
    llc_marker = os.path.join(workdir, "llc-marker.log")
    mojo_version = "Mojo 1.1.0 (host-fixture)"
    llc_version = "Host LLVM version 1.0"
    real = os.path.join(realdir, "mojo")
    _write_host_script(
        real,
        "#!/bin/sh\necho probe >> %s\necho '%s'\n"
        % (mojo_marker, mojo_version),
    )
    entry = os.path.join(bindir, "mojo")
    _write_host_script(
        entry,
        "#!/bin/sh\nTC=%s\nexec \"$TC/mojo\" \"$@\"\n" % realdir,
    )
    llc = os.path.join(bindir, "llc")
    _write_host_script(
        llc,
        "#!/bin/sh\necho probe >> %s\necho '%s'\n"
        % (llc_marker, llc_version),
    )
    return {
        "bin": bindir,
        "mojo": entry,
        "mojo_marker": mojo_marker,
        "mojo_version": mojo_version,
        "llc": llc,
        "llc_marker": llc_marker,
        "llc_version": llc_version,
    }


def _make_host_pins(workdir, prefix, mutate=None):
    document = {
        "generated_by": "host fixture (independent toolchain record)",
        "schema_version": 1,
        "status": "reviewed",
        "tools": {
            "llc": {
                "sha256": _sha256_file(prefix["llc"]),
                "version": prefix["llc_version"],
            },
            "mojo": {
                "exec_sha256": _sha256_file(
                    os.path.join(
                        os.path.dirname(prefix["bin"]), "real", "mojo"
                    )
                ),
                "sha256": _sha256_file(prefix["mojo"]),
                "version": prefix["mojo_version"],
            },
        },
    }
    if mutate is not None:
        mutate(document)
    pins_path = os.path.join(workdir, "independent-pins.json")
    with open(pins_path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return pins_path


def _host_env(prefix):
    return {"PATH": prefix["bin"] + os.pathsep + "/usr/bin:/bin"}


def _save_consumer_env():
    saved = {}
    for key in (
        CONSUMER_FULL_ENV,
        CONSUMER_PREFIX_ENV,
        CONSUMER_PINS_ENV,
        BPFTOOL_PINS_ENV,
    ):
        saved[key] = os.environ.pop(key, None)
    return saved


def _restore_consumer_env(saved):
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def _bootstrap_trust():
    return {
        "origin": (
            "self-pin from PATH discovery; not an independent "
            "trust root"
        ),
        "status": "bootstrap",
    }


def test_consumer_lock_declares_trust():
    fix = fixture()
    with open(fix["lockfile_path"], encoding="utf-8") as handle:
        document = json.load(handle)
    assert document["status"] == fix["trust"]["status"]
    if fix["independent_pins"] is None:
        assert document["status"] == "bootstrap"
        assert "not an independent" in document["trust"]["origin"]
    else:
        assert document["status"] == "admitted"
        assert fix["independent_pins"] in document["trust"]["origin"]


def test_consumer_admission_rejects_replacement():
    workdir = tempfile.mkdtemp(prefix="consumer-admission-")
    saved = _save_consumer_env()
    try:
        prefix = _make_host_prefix(workdir)
        pins_path = _make_host_pins(workdir, prefix)
        os.environ[CONSUMER_PREFIX_ENV] = prefix["bin"]
        os.environ[CONSUMER_PINS_ENV] = pins_path
        independent = _load_independent_pins()
        assert independent["prefix"] == prefix["bin"]
        env = _host_env(prefix)
        record = _admit_tool(
            "mojo", prefix["mojo"], independent["mojo"], env
        )
        assert record["version"] == prefix["mojo_version"]
        assert os.path.isfile(prefix["mojo_marker"])
        os.unlink(prefix["mojo_marker"])
        with open(prefix["mojo"], "a", encoding="utf-8") as handle:
            handle.write("# same-version replacement\n")
        try:
            _admit_tool(
                "mojo", prefix["mojo"], independent["mojo"], env
            )
        except ConsumerAdmissionError as exc:
            assert "hash" in str(exc), exc
        else:
            raise AssertionError("replacement compiler admitted")
        assert not os.path.exists(prefix["mojo_marker"]), (
            "replaced compiler must never execute"
        )
        probed = _probe_tool(
            "mojo", {"PATH": prefix["bin"], "HOME": workdir}
        )
        assert probed["version"] == prefix["mojo_version"]
        assert os.path.isfile(prefix["mojo_marker"]), (
            "control: PATH-only probing executes whatever it finds"
        )
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_consumer_admission_rejects_unapproved_chain():
    workdir = tempfile.mkdtemp(prefix="consumer-chain-")
    saved = _save_consumer_env()
    try:
        prefix = _make_host_prefix(workdir)
        env = _host_env(prefix)

        def _drop_exec(document):
            del document["tools"]["mojo"]["exec_sha256"]

        pins_path = _make_host_pins(workdir, prefix, mutate=_drop_exec)
        os.environ[CONSUMER_PREFIX_ENV] = prefix["bin"]
        os.environ[CONSUMER_PINS_ENV] = pins_path
        independent = _load_independent_pins()
        try:
            _admit_tool(
                "mojo", prefix["mojo"], independent["mojo"], env
            )
        except ConsumerAdmissionError as exc:
            assert "pinned" in str(exc), exc
        else:
            raise AssertionError("unpinned launcher chain admitted")
        assert not os.path.exists(prefix["mojo_marker"])

        def _wrong_exec(document):
            document["tools"]["mojo"]["exec_sha256"] = "5" * 64

        pins_path = _make_host_pins(workdir, prefix, mutate=_wrong_exec)
        os.environ[CONSUMER_PINS_ENV] = pins_path
        independent = _load_independent_pins()
        try:
            _admit_tool(
                "mojo", prefix["mojo"], independent["mojo"], env
            )
        except ConsumerAdmissionError as exc:
            assert "exec" in str(exc), exc
        else:
            raise AssertionError("mismatched exec image admitted")
        assert not os.path.exists(prefix["mojo_marker"])
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def _write_unresolvable_prefix(workdir, marker):
    """Prefix tools whose launcher chains never resolve to an image."""
    bindir = os.path.join(workdir, "prefix", "bin")
    os.makedirs(bindir)
    wrappers = {
        "unresolvable-var": (
            "#!/bin/sh\necho probe >> %s\nexec "
            "\"$UNAPPROVED_TOOL\" \"$@\"\n" % marker
        ),
        "exact-trace": (
            "#!/bin/sh\nexec \"$UNAPPROVED_TOOL\" \"$@\"\n"
        ),
        "dangling": (
            "#!/bin/sh\necho probe >> %s\nexec "
            "/nonexistent-target-xyz\n" % marker
        ),
        "ambiguous": (
            "#!/bin/sh\necho probe >> %s\nexec /bin/true\n"
            "exec /bin/false\n" % marker
        ),
    }
    paths = {}
    for tag, body in sorted(wrappers.items()):
        path = os.path.join(bindir, "mojo-%s" % tag)
        _write_host_script(path, body)
        paths[tag] = path
    first = os.path.join(bindir, "mojo-cycle-a")
    second = os.path.join(bindir, "mojo-cycle-b")
    _write_host_script(
        first,
        "#!/bin/sh\necho probe >> %s\nexec %s \"$@\"\n"
        % (marker, second),
    )
    _write_host_script(
        second,
        "#!/bin/sh\necho probe >> %s\nexec %s \"$@\"\n"
        % (marker, first),
    )
    paths["cyclic"] = first
    return bindir, paths


def test_consumer_admission_rejects_unresolvable_chain():
    if os.path.join(REPO_ROOT, "src") not in sys.path:
        sys.path.insert(0, os.path.join(REPO_ROOT, "src"))
    from mojobpf import execution

    workdir = tempfile.mkdtemp(prefix="consumer-unknown-")
    try:
        marker = os.path.join(workdir, "probe-marker.log")
        bindir, wrappers = _write_unresolvable_prefix(
            workdir, marker
        )
        env = {"PATH": bindir + os.pathsep + "/usr/bin:/bin"}
        for tag, wrapper in sorted(wrappers.items()):
            captured = execution.capture_chain(
                os.path.realpath(wrapper)
            )
            assert captured.form == execution.FORM_UNKNOWN, (
                tag, captured.form, captured.note,
            )
            expected = {
                "exec_sha256": None,
                "sha256": _sha256_file(
                    os.path.realpath(wrapper)
                ),
                "version": "Mojo 9.9.9",
            }
            try:
                _admit_tool("mojo", wrapper, expected, env)
            except ConsumerAdmissionError as exc:
                message = str(exc)
            else:
                raise AssertionError(
                    "unresolvable %s launcher admitted" % tag
                )
            assert not os.path.exists(marker), (
                "unresolvable %s launcher must never execute" % tag
            )
            assert "chain" in message or "launcher" in message, (
                tag, message,
            )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_consumer_admission_probes_the_captured_image():
    workdir = tempfile.mkdtemp(prefix="consumer-argv0-")
    try:
        realdir = os.path.join(workdir, "real")
        bindir = os.path.join(workdir, "prefix", "bin")
        os.makedirs(realdir)
        os.makedirs(bindir)
        zero_log = os.path.join(workdir, "argv0.log")
        version = "Host LLVM version 1.0"
        real = os.path.join(realdir, "llc")
        _write_host_script(
            real,
            "#!/bin/sh\nsha256sum \"$0\" >> %s\necho '%s'\n"
            % (zero_log, version),
        )
        link = os.path.join(bindir, "llc")
        os.symlink(real, link)
        expected = {
            "exec_sha256": None,
            "sha256": _sha256_file(os.path.realpath(link)),
            "version": version,
        }
        env = {"PATH": bindir + os.pathsep + "/usr/bin:/bin"}
        record = _admit_tool("llc", link, expected, env)
        assert record["realpath"] == os.path.realpath(link)
        with open(zero_log, encoding="utf-8") as handle:
            logged = handle.read().splitlines()
        assert len(logged) == 1, logged
        executed_sha, _, _ = logged[0].partition(" ")
        assert executed_sha == expected["sha256"], (
            "probe must execute the admitted image bytes, got %r"
            % logged
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _replace_entry_bytes(entry):
    """Rewrite a fixture entry in place with observably new bytes.

    The replacement stays a launcher to the same image with the
    same version output; only the entry bytes (size and mtime)
    change, so a spawn-time re-verification must catch it.
    """
    with open(entry, "a", encoding="utf-8") as handle:
        handle.write("# replacement\n")
    stat_result = os.stat(entry)
    os.utime(
        entry,
        ns=(
            stat_result.st_atime_ns,
            stat_result.st_mtime_ns + 1000000000,
        ),
    )


def _refusing_spawn(*args, **kwargs):
    raise AssertionError(
        "process start during a refusal trace: %r" % (args,)
    )


def test_consumer_admission_refuses_swap_before_capture():
    from mojobpf import execution as _execution

    workdir = tempfile.mkdtemp(prefix="consumer-swapbefore-")
    try:
        prefix = _make_host_prefix(workdir)
        env = _host_env(prefix)
        entry = prefix["mojo"]
        expected = {
            "exec_sha256": _sha256_file(
                os.path.join(
                    os.path.dirname(prefix["bin"]), "real", "mojo"
                )
            ),
            "sha256": _sha256_file(entry),
            "version": prefix["mojo_version"],
        }
        real_capture = _execution.capture_chain
        real_run = subprocess.run
        real_popen = subprocess.Popen

        def _swap_then_capture(path):
            _replace_entry_bytes(entry)
            return real_capture(path)

        _execution.capture_chain = _swap_then_capture
        subprocess.run = _refusing_spawn
        subprocess.Popen = _refusing_spawn
        try:
            _admit_tool("mojo", entry, expected, env)
        except ConsumerAdmissionError:
            pass
        else:
            raise AssertionError(
                "replacement before capture admitted"
            )
        finally:
            _execution.capture_chain = real_capture
            subprocess.run = real_run
            subprocess.Popen = real_popen
        assert not os.path.exists(prefix["mojo_marker"]), (
            "swapped compiler must never execute"
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_consumer_admission_refuses_swap_after_capture():
    from mojobpf import execution as _execution

    workdir = tempfile.mkdtemp(prefix="consumer-swapafter-")
    try:
        prefix = _make_host_prefix(workdir)
        env = _host_env(prefix)
        entry = prefix["mojo"]
        expected = {
            "exec_sha256": _sha256_file(
                os.path.join(
                    os.path.dirname(prefix["bin"]), "real", "mojo"
                )
            ),
            "sha256": _sha256_file(entry),
            "version": prefix["mojo_version"],
        }
        real_capture = _execution.capture_chain
        real_run = subprocess.run
        real_popen = subprocess.Popen

        def _capture_then_swap(path):
            record = real_capture(path)
            _replace_entry_bytes(entry)
            return record

        _execution.capture_chain = _capture_then_swap
        subprocess.run = _refusing_spawn
        subprocess.Popen = _refusing_spawn
        try:
            _admit_tool("mojo", entry, expected, env)
        except ConsumerAdmissionError as exc:
            assert "refus" in str(exc), exc
        else:
            raise AssertionError(
                "replacement after capture admitted"
            )
        finally:
            _execution.capture_chain = real_capture
            subprocess.run = real_run
            subprocess.Popen = real_popen
        assert not os.path.exists(prefix["mojo_marker"]), (
            "swapped compiler must never execute"
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_consumer_admission_spawns_only_through_the_contract():
    workdir = tempfile.mkdtemp(prefix="consumer-contractspawn-")
    saved = _save_consumer_env()
    real_run = subprocess.run
    try:
        prefix = _make_host_prefix(workdir)
        pins_path = _make_host_pins(workdir, prefix)
        os.environ[CONSUMER_PREFIX_ENV] = prefix["bin"]
        os.environ[CONSUMER_PINS_ENV] = pins_path
        independent = _load_independent_pins()
        env = _host_env(prefix)
        subprocess.run = _refusing_spawn
        try:
            mojo = _admit_tool(
                "mojo", prefix["mojo"], independent["mojo"], env
            )
            llc = _admit_tool(
                "llc", prefix["llc"], independent["llc"], env
            )
            probed = _probe_tool(
                "mojo", {"PATH": prefix["bin"], "HOME": workdir}
            )
        finally:
            subprocess.run = real_run
        assert mojo["version"] == prefix["mojo_version"]
        assert llc["version"] == prefix["llc_version"]
        assert probed["version"] == prefix["mojo_version"]
        assert probed["sha256"] == _sha256_file(prefix["mojo"])
        assert os.path.isfile(prefix["mojo_marker"])
        assert os.path.isfile(prefix["llc_marker"])
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_consumer_probe_refuses_swap_before_probe():
    from mojobpf import execution as _execution

    workdir = tempfile.mkdtemp(prefix="consumer-probeswap-")
    try:
        prefix = _make_host_prefix(workdir)
        entry = prefix["llc"]
        calls = []
        real_capture = _execution.capture_chain

        def _capture_then_swap_on_second(path):
            record = real_capture(path)
            calls.append(path)
            if len(calls) == 2:
                _replace_entry_bytes(entry)
            return record

        _execution.capture_chain = _capture_then_swap_on_second
        try:
            _probe_tool(
                "llc", {"PATH": prefix["bin"], "HOME": workdir}
            )
        except EnvironmentFailure:
            pass
        else:
            raise AssertionError(
                "replacement between capture and probe reported"
            )
        finally:
            _execution.capture_chain = real_capture
        assert not os.path.exists(prefix["llc_marker"]), (
            "swapped tool must never execute"
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_consumer_admits_independent_prefix():
    workdir = tempfile.mkdtemp(prefix="consumer-admitted-")
    saved = _save_consumer_env()
    try:
        prefix = _make_host_prefix(workdir)
        pins_path = _make_host_pins(workdir, prefix)
        os.environ[CONSUMER_PREFIX_ENV] = prefix["bin"]
        os.environ[CONSUMER_PINS_ENV] = pins_path
        independent = _load_independent_pins()
        env = _host_env(prefix)
        mojo = _admit_tool(
            "mojo",
            _resolve_prefix_tool("mojo", independent["prefix"]),
            independent["mojo"],
            env,
        )
        llc = _admit_tool(
            "llc",
            _resolve_prefix_tool("llc", independent["prefix"]),
            independent["llc"],
            env,
        )
        assert mojo["version"] == prefix["mojo_version"]
        assert llc["version"] == prefix["llc_version"]
        assert os.path.isfile(prefix["mojo_marker"])
        assert os.path.isfile(prefix["llc_marker"])
        project = os.path.join(workdir, "project")
        os.makedirs(project)
        trust = {
            "origin": (
                "independently admitted compiler prefix %s "
                "(pins %s sha256 %s)"
                % (
                    independent["prefix"],
                    independent["path"],
                    independent["source_sha256"],
                )
            ),
            "pins": independent["path"],
            "pins_sha256": independent["source_sha256"],
            "prefix": independent["prefix"],
            "status": "admitted",
        }
        lockfile_path = _write_consumer_lockfile(
            project, mojo, llc, trust
        )
        with open(lockfile_path, encoding="utf-8") as handle:
            document = json.load(handle)
        assert document["status"] == "admitted"
        assert pins_path in document["trust"]["origin"]
        assert document["tools"]["mojo"]["exec_sha256"] == (
            independent["mojo"]["exec_sha256"]
        )
        assert "(independently admitted pins)" in document[
            "generated_by"
        ]
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_consumer_independent_pins_require_reviewed_status():
    workdir = tempfile.mkdtemp(prefix="consumer-reviewed-")
    saved = _save_consumer_env()
    try:
        prefix = _make_host_prefix(workdir)
        os.environ[CONSUMER_PREFIX_ENV] = prefix["bin"]

        def _check_rejected(tag, mutate, marker):
            pins_path = _make_host_pins(
                workdir, prefix, mutate=mutate
            )
            os.environ[CONSUMER_PINS_ENV] = pins_path
            try:
                _load_independent_pins()
            except ConsumerAdmissionError as exc:
                assert marker in str(exc), (tag, exc)
            else:
                raise AssertionError(
                    "%s pins accepted as independent" % tag
                )

        def _draft_observational(document):
            document["status"] = "draft"
            document["generated_by"] = (
                "tests/probes/toolchain_inventory.py"
            )

        _check_rejected(
            "draft observational", _draft_observational, "reviewed"
        )

        def _bootstrap(document):
            document["status"] = "bootstrap"

        _check_rejected("bootstrap", _bootstrap, "reviewed")

        def _admitted_label(document):
            document["status"] = "admitted"

        _check_rejected(
            "admitted-labeled", _admitted_label, "reviewed"
        )
        # No status at all stays unadmitted too.
        _check_rejected(
            "unreviewed",
            lambda document: document.pop("status", None),
            "reviewed",
        )

        def _reviewed(document):
            document["status"] = "reviewed"

        pins_path = _make_host_pins(
            workdir, prefix, mutate=_reviewed
        )
        os.environ[CONSUMER_PINS_ENV] = pins_path
        independent = _load_independent_pins()
        assert independent["prefix"] == prefix["bin"]
        assert independent["mojo"]["version"] == (
            prefix["mojo_version"]
        )
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def _make_real_tool_prefix(workdir):
    """Approved prefix outside PATH: wrappers around the real tools.

    Returns ``(bindir, pins_path)`` with reviewed pins for the
    wrapper entries (exec pins name the real tools). Raises
    EnvironmentFailure when the ambient tools are missing.
    """
    for tool in ("mojo", "llc"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure(
                "needs ambient %s to wrap" % tool
            )
    bindir = os.path.join(workdir, "prefix", "bin")
    os.makedirs(bindir)
    reals = {
        name: os.path.realpath(shutil.which(name))
        for name in ("mojo", "llc")
    }
    entries = {}
    for name, real in sorted(reals.items()):
        entry = os.path.join(bindir, name)
        _write_host_script(
            entry,
            "#!/bin/sh\nTC=%s\nexec \"$TC/%s\" \"$@\"\n"
            % (
                os.path.dirname(real),
                os.path.basename(real),
            ),
        )
        entries[name] = entry
    versions = {}
    for name, entry in sorted(entries.items()):
        proc = subprocess.run(
            [entry, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
        assert proc.returncode == 0, (name, proc.stderr)
        text = proc.stdout if proc.stdout.strip() else proc.stderr
        first = None
        for line in text.splitlines():
            if line.strip():
                first = line.strip()
                break
        assert first is not None, name
        versions[name] = first
    document = {
        "generated_by": (
            "prefix-build test (independent toolchain record)"
        ),
        "schema_version": 1,
        "status": "reviewed",
        "tools": {
            name: {
                "exec_sha256": _sha256_file(reals[name]),
                "sha256": _sha256_file(entries[name]),
                "version": versions[name],
            }
            for name in ("mojo", "llc")
        },
    }
    pins_path = os.path.join(workdir, "independent-pins.json")
    with open(pins_path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return bindir, pins_path


def _restore_fixture(saved_fix):
    """Restore the cached fixture, removing the temporary root."""
    prefix_root = _FIXTURE.get("root")
    _FIXTURE.clear()
    _FIXTURE.update(saved_fix)
    if prefix_root is not None and (
        prefix_root != saved_fix.get("root")
    ):
        shutil.rmtree(prefix_root, ignore_errors=True)


def test_consumer_builds_through_admitted_prefix():
    workdir = tempfile.mkdtemp(prefix="consumer-prefixbuild-")
    saved = _save_consumer_env()
    try:
        bindir, pins_path = _make_real_tool_prefix(workdir)
        assert bindir not in os.environ.get("PATH", "").split(
            os.pathsep
        ), "the approved prefix must start outside PATH"
        os.environ[CONSUMER_PREFIX_ENV] = bindir
        os.environ[CONSUMER_PINS_ENV] = pins_path
        saved_fix = dict(_FIXTURE)
        _FIXTURE.clear()
        try:
            fix = fixture()
            proc = fix["build"]
            assert proc.returncode == 0, (
                proc.stdout + "\n" + proc.stderr
            )
            assert fix["trust"]["status"] == "admitted"
            assert pins_path in fix["trust"]["origin"]
            entries = fix["env"]["PATH"].split(os.pathsep)
            assert entries[1] == bindir, (
                "the installed build must resolve the admitted "
                "prefix first: %r" % (entries,)
            )
            objects = sorted(
                entry
                for entry in os.listdir(fix["out_dir"])
                if entry.endswith(".bpf.o")
            )
            assert objects == [CONSUMER_OBJECT], objects
            doc, _raw = _evidence_document(fix)
            assert doc["success"] is True
            ambient_mojo_sha = _sha256_file(
                os.path.realpath(shutil.which("mojo"))
            )
            assert fix["mojo"]["sha256"] != ambient_mojo_sha, (
                "prefix wrapper must be distinguishable from "
                "ambient bytes"
            )
            compiler_blob = " ".join(doc["inputs"]["compiler"])
            for name in ("mojo", "llc"):
                assert fix[name]["sha256"] in compiler_blob, (
                    name, compiler_blob,
                )
                assert fix[name]["version"] in compiler_blob, (
                    name, compiler_blob,
                )
        finally:
            _restore_fixture(saved_fix)
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_consumer_prefix_replaces_ambient_probe():
    workdir = tempfile.mkdtemp(prefix="consumer-prefixprobe-")
    saved = _save_consumer_env()
    real_which = shutil.which
    try:
        bindir, pins_path = _make_real_tool_prefix(workdir)
        os.environ[CONSUMER_PREFIX_ENV] = bindir
        os.environ[CONSUMER_PINS_ENV] = pins_path

        def _hidden(name, *args, **kwargs):
            if name in ("mojo", "llc"):
                return None
            return real_which(name, *args, **kwargs)

        shutil.which = _hidden
        try:
            assert shutil.which("mojo") is None
            saved_fix = dict(_FIXTURE)
            _FIXTURE.clear()
            try:
                fix = fixture()
                assert fix["build"].returncode == 0, (
                    fix["build"].stdout
                    + "\n"
                    + fix["build"].stderr
                )
                assert fix["trust"]["status"] == "admitted"
            finally:
                _restore_fixture(saved_fix)
        finally:
            shutil.which = real_which
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_consumer_bootstrap_without_independent_pins():
    workdir = tempfile.mkdtemp(prefix="consumer-bootstrap-")
    saved = _save_consumer_env()
    try:
        assert _load_independent_pins() is None
        os.environ[CONSUMER_PREFIX_ENV] = os.path.join(workdir, "bin")
        assert _load_independent_pins() is None
        prefix = _make_host_prefix(workdir)
        project = os.path.join(workdir, "project")
        os.makedirs(project)
        mojo = {
            "exec_sha256": "5" * 64,
            "sha256": _sha256_file(prefix["mojo"]),
            "version": prefix["mojo_version"],
        }
        llc = {
            "exec_sha256": None,
            "sha256": _sha256_file(prefix["llc"]),
            "version": prefix["llc_version"],
        }
        lockfile_path = _write_consumer_lockfile(
            project, mojo, llc, _bootstrap_trust()
        )
        with open(lockfile_path, encoding="utf-8") as handle:
            document = json.load(handle)
        assert document["status"] == "bootstrap"
        assert "not an independent" in document["trust"]["origin"]
        assert "(PATH-resolved pins)" in document["generated_by"]
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_consumer_self_pin_is_not_a_trust_root():
    workdir = tempfile.mkdtemp(prefix="consumer-selfpin-")
    saved = _save_consumer_env()
    try:
        prefix = _make_host_prefix(workdir)
        project = os.path.join(workdir, "project")
        os.makedirs(project)
        mojo = {
            "exec_sha256": "5" * 64,
            "sha256": _sha256_file(prefix["mojo"]),
            "version": prefix["mojo_version"],
        }
        llc = {
            "exec_sha256": None,
            "sha256": _sha256_file(prefix["llc"]),
            "version": prefix["llc_version"],
        }
        self_pin = _write_consumer_lockfile(
            project, mojo, llc, _bootstrap_trust()
        )
        os.environ[CONSUMER_PREFIX_ENV] = prefix["bin"]
        os.environ[CONSUMER_PINS_ENV] = self_pin
        try:
            _load_independent_pins()
        except ConsumerAdmissionError as exc:
            assert "not an independent trust root" in str(exc), exc
        else:
            raise AssertionError("self-pin accepted as independent")
        broken = os.path.join(workdir, "broken.json")
        with open(broken, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        os.environ[CONSUMER_PINS_ENV] = broken
        try:
            _load_independent_pins()
        except ConsumerAdmissionError:
            pass
        else:
            raise AssertionError("malformed pins silently accepted")
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def test_consumer_lockfile_schema_for_build():
    workdir = tempfile.mkdtemp(prefix="consumer-schema-")
    saved = _save_consumer_env()
    try:
        prefix = _make_host_prefix(workdir)
        project = os.path.join(workdir, "project")
        os.makedirs(project)
        mojo = {
            "exec_sha256": "5" * 64,
            "sha256": _sha256_file(prefix["mojo"]),
            "version": prefix["mojo_version"],
        }
        llc = {
            "exec_sha256": None,
            "sha256": _sha256_file(prefix["llc"]),
            "version": prefix["llc_version"],
        }
        lockfile_path = _write_consumer_lockfile(
            project, mojo, llc, _bootstrap_trust()
        )
        with open(lockfile_path, "rb") as handle:
            raw = handle.read()
        assert REPO_ROOT.encode() not in raw
        document = json.loads(raw.decode("utf-8"))
        assert document["schema_version"] == 1
        assert set(document["tools"]) == {"llc", "mojo"}
        for name in ("llc", "mojo"):
            entry = document["tools"][name]
            assert isinstance(entry["version"], str), entry
            assert isinstance(entry["sha256"], str), entry
            assert "exec_sha256" in entry, entry
        assert document["tools"]["llc"]["exec_sha256"] is None
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


def _consumer_paths():
    return [
        os.path.join(CONSUMER_DIR, name) for name in CONSUMER_FILES
    ]


# Admission negatives stay positive: refusal tests assert the
# refusal internally (try/except plus assert) and return no
# FAIL hint, so no case denies another plan case.
CASE_DENIALS = {}


# Durable inputs per case: absolute repo paths plus ("stage",
# basename) entries resolved against the guest stage at finish.
# Host checks pin the consumer project they validate; kernel
# checks additionally pin the staged object, packet data and
# rendered guest script. A class with any missing file digests
# to zeros and can never back a PASS.
CASE_INPUTS = {
    "test_build_fails_without_installed_package": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_admission_probes_the_captured_image": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_admission_refuses_swap_after_capture": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_admission_refuses_swap_before_capture": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_admission_rejects_replacement": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_admission_rejects_unapproved_chain": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_admission_rejects_unresolvable_chain": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_admission_spawns_only_through_the_contract": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_admits_independent_prefix": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_bootstrap_without_independent_pins": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_builds_through_admitted_prefix": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_builds_with_installed_tool": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_exact_kernel_result": {
        "sources": _consumer_paths() + [
            ("stage", "guest_canary.sh")
        ],
        "objects": [("stage", "canary.bpf.o")],
        "corpus": [("stage", "data.bin")],
    },
    "test_consumer_guest_provenance": {
        "sources": _consumer_paths() + [
            HARNESS, ("stage", "guest_canary.sh")
        ],
        "objects": [("stage", "canary.bpf.o")],
        "corpus": [("stage", "data.bin")],
    },
    "test_consumer_has_no_copy_no_path_back": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_imports_only_the_sdk_surface": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_independent_pins_require_reviewed_status": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_lock_declares_trust": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_lockfile_schema_for_build": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_object_compiled_from_own_source": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_prefix_replaces_ambient_probe": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_probe_refuses_swap_before_probe": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_self_pin_is_not_a_trust_root": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_consumer_standard_runner_passes": {
        "sources": _consumer_paths() + [
            HARNESS, ("stage", "guest_canary.sh")
        ],
        "objects": [("stage", "canary.bpf.o")],
        "corpus": [("stage", "data.bin")],
    },
    "test_consumer_toolchain_resolved_path_only": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_guest_harness_case_carries_admission": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_guest_prologue_rejects_post_staging_chain_symlink_retarget": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_guest_prologue_rejects_post_staging_image_replacement": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_guest_prologue_rejects_post_staging_middle_replacement": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_guest_script_binds_bpftool_to_reviewed_pins": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_stage_bpftool_pins_admit_reviewed_tool": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_stage_bpftool_pins_from_shared_rootfs": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_stage_bpftool_pins_refuse_without_reviewed_pins": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_stage_bpftool_pins_reject_replacement": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_stage_bpftool_pins_reject_unresolvable_launcher": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
    "test_stage_bpftool_pins_require_reviewed_status": {
        "sources": _consumer_paths(),
        "objects": [],
        "corpus": [],
    },
}


def _finish(rec, unavailable_seen=False):
    """Attach the guest transcript and finish the typed suite."""
    stage = None
    try:
        run = guest_run()
        stage = run["stage"]
        rec.note_transcript("guest", run["output"])
    except (EnvironmentFailure, guest_proc.HarnessEnvironment,
            AssertionError, ConsumerAdmissionError,
            GuestRequiredError, subprocess.TimeoutExpired):
        pass
    code = rec.finish(
        stage_dir=stage, unavailable_seen=unavailable_seen
    )
    guest_proc.discard_owned_stages()
    return code


def main():
    names = sorted(k for k in globals() if k.startswith("test_"))
    rec = guest_proc.SuiteRecorder(
        suite_id="packaging-consumer", suite_path=__file__,
        case_ids=names, denials=CASE_DENIALS, inputs=CASE_INPUTS,
        lane_release=VNG_RELEASE)
    # Attestation context: fixture consumption reads route
    # through this recorder from here (warmup included).
    guest_proc.set_active_recorder(rec)
    if not __debug__:
        return rec.finish_unrun(
            "must not run under python -O (asserts stripped)"
        )
    # Direct runs always execute every host check and opt into
    # the full run; the guest checks additionally need a target
    # lease (MOJOBPF_CONSUMER_GUEST_LEASE=1) or report
    # required-unavailable. Under pytest the guest checks skip by
    # default instead.
    os.environ[CONSUMER_FULL_ENV] = "1"
    failures = 0
    unavailable_seen = False
    # Stage before any begin_case: the begin seals must observe
    # the staged input bytes (bytes first seen after begin can
    # never back a PASS), so warm the cached guest run here. A
    # warm failure is ignored: each case body retries and
    # records it per case below.
    try:
        guest_run()
    except (
        EnvironmentFailure, guest_proc.HarnessEnvironment,
        AssertionError, ConsumerAdmissionError,
        GuestRequiredError, subprocess.TimeoutExpired,
        guest_proc.TargetLeaseRequired,
    ):
        pass
    for name in names:
        func = globals()[name]
        rec.begin_case(name)
        try:
            hint = func()
        except guest_proc.HarnessEnvironment as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            rec.end_case_infra(name, exc.stage, exc.availability)
            return _finish(rec, unavailable_seen)
        except EnvironmentFailure as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            rec.end_case_infra(name, "INFRA", "UNKNOWN")
            return _finish(rec, unavailable_seen)
        except ConsumerAdmissionError as exc:
            print("ADMISSION FAILURE in %s: %s" % (name, exc))
            rec.end_case_fail(name, "INFRA")
            return _finish(rec, unavailable_seen)
        except GuestRequiredError as exc:
            print("REQUIRED-UNAVAILABLE %s: %s" % (name, exc))
            rec.end_case_not_run(name, "TARGET_RESOURCE_ABSENT")
            unavailable_seen = True
        except subprocess.TimeoutExpired as exc:
            print("ENVIRONMENT FAILURE in %s: timed out: %s" % (name, exc))
            rec.end_case_infra(name, "INFRA", "TOOLCHAIN_UNAVAILABLE")
            return _finish(rec, unavailable_seen)
        except guest_proc.TargetLeaseRequired as exc:
            print("REQUIRED-UNAVAILABLE %s: %s" % (name, exc))
            rec.end_case_not_run(name, "TARGET_RESOURCE_ABSENT")
            unavailable_seen = True
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            rec.end_case_fail(name)
            failures += 1
        else:
            print("PASS %s" % name)
            rec.end_case_hint(name, hint)
    if failures:
        return _finish(rec, unavailable_seen)
    fix = fixture()
    obj = os.path.join(fix["out_dir"], CONSUMER_OBJECT)
    print("consumer: %s" % fix["mojo"]["path"])
    print(
        "consumer mojo: %s sha256 %s"
        % (fix["mojo"]["version"], fix["mojo"]["sha256"])
    )
    print(
        "consumer object: %s sha256 %s" % (CONSUMER_OBJECT, _sha256_file(obj))
    )
    try:
        guest_run()
    except GuestRequiredError as exc:
        print("REQUIRED-UNAVAILABLE guest summary: %s" % exc)
        return _finish(rec, True)
    except guest_proc.TargetLeaseRequired as exc:
        print("REQUIRED-UNAVAILABLE guest summary: %s" % exc)
        return _finish(rec, True)
    except (EnvironmentFailure, guest_proc.HarnessEnvironment,
            subprocess.TimeoutExpired):
        return _finish(rec, unavailable_seen)
    print(
        "consumer kernel: action %d, map %d -> %d -> %d"
        % (XDP_PASS, INIT_VALUE, AFTER_FIRST, AFTER_SECOND)
    )
    print("external consumer: isolated build plus exact kernel result")
    return _finish(rec, unavailable_seen)


if __name__ == "__main__":
    sys.exit(main())
