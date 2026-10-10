# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Third-party usability proof for the controlled uprobe shape.

Installs the release-candidate wheel into a fresh virtual
environment, copies ``tests/packaging/uprobe_consumer/`` (the
subscriber's own manifest plus its own ``subscriber.mojo``
uprobe source, which differs from every in-tree Mojo source, and
its own ``consumer_target.c`` probe-target executable, which
carries the subscriber's own probe sites) to an unrelated
working directory with the MojoBPF tree scrubbed from every
search path, resolves ``mojo`` from PATH only (an independently
installed Mojo 1.1.0, never the checkout's developer
environment), builds through the installed ``mojobpf`` command,
and requires the exact kernel result through the standard
loader/attach flow.

The subscriber counts probed calls carrying a watched argument:
entry 0 holds the watched value, entry 1 the tally. The guest
suite loads the consumer-built object, attaches it to the
subscriber's own executable, and requires 200/200 with every
oracle word equal to the watched value 97, 0/100 with every
oracle word equal to the other value 98, 0 on the never-watched
symbol, plus pin absence and residue checks.

The consumer pins its own toolchain: the suite writes a
``toolchains.lock.json`` beside the copied manifest from the
PATH-resolved tools, the way a real user pins theirs.

Requires an independent Mojo 1.1.0 plus ``llc`` and ``vng`` on
PATH outside the checkout, and ``cc`` plus ``readelf`` for
suite-side staging of the subscriber's own C sources. The guest
release comes from ``MOJOBPF_VNG_RELEASE`` (``v6.12`` by
default). Only the vng guest performs BPF loads and uprobe
attaches; the host never attaches to anything. The guest boots
as a session leader, so a timeout kills the whole owned guest
tree, never just the direct child.

Runnable directly
(``python3 tests/packaging/test_uprobe_consumer.py``) or under
any ``test_``-style runner. Standard library only.

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
import lane_lock  # noqa: E402
import guest_proc  # noqa: E402
CONSUMER_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "uprobe_consumer"
)
HOLDER_SOURCE = os.path.join(REPO_ROOT, "tests", "harness", "uprobe_attach.c")

CONSUMER_FILES = (
    "README.md", "mojobpf.toml", "subscriber.mojo",
    "consumer_target.c",
)
CONSUMER_LOCKFILE = "toolchains.lock.json"
CONSUMER_OBJECT = "subscriber_probe.bpf.o"
CONSUMER_SIDECAR = "subscriber_probe.evidence.json"
CONSUMER_SOURCE = "subscriber.mojo"
CONSUMER_TARGET_SOURCE = "consumer_target.c"
CONSUMER_PROFILE = "linux-bpfel-v3-uprobe"
BASE_PROFILE = "linux-bpfel-v3"

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

CONSUMER_N = 200
CONSUMER_M = 100
CONSUMER_WATCHED = 97
CONSUMER_OTHER = 98
# Guest release under test. The VM matrix selects the lane through
# MOJOBPF_VNG_RELEASE; standalone runs keep the default release.
VNG_RELEASE = os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")
VNG_TIMEOUT = 900

_FIXTURE = {}
_GUEST = {}


class EnvironmentFailure(Exception):
    """The toolchain, builder, or VM needed by this test is missing."""


CONSUMER_FULL_ENV = "MOJOBPF_CONSUMER_FULL"
CONSUMER_PREFIX_ENV = "MOJOBPF_CONSUMER_TOOLCHAIN_BIN"
CONSUMER_PINS_ENV = "MOJOBPF_CONSUMER_TOOLCHAIN_LOCK"
CONSUMER_GUEST_ENV = "MOJOBPF_CONSUMER_GUEST_LEASE"
BPFTOOL_PINS_ENV = "MOJOBPF_BPFTOOL_PINS"


class ConsumerAdmissionError(Exception):
    """A substituted consumer toolchain was refused before execution."""


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
    with open(path, "rb") as handle:
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


def _write_consumer_lockfile(project, mojo, llc, trust):
    """Pin the consumer's toolchain plus its trust origin.

    ``trust`` is ``{"status": "admitted"|"bootstrap", ...}``:
    admitted pins were checked against the independently recorded
    compiler pins before execution; bootstrap pins are PATH
    self-pins and never qualify as independently trusted.
    """
    admitted = trust.get("status") == "admitted"
    document = {
        "generated_by": (
            "uprobe consumer (independently admitted pins)"
            if admitted
            else "uprobe consumer (PATH-resolved pins)"
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


def _compile(path, argv):
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EnvironmentFailure("cannot run cc: %s" % exc)
    if proc.returncode != 0 or proc.stderr != "":
        raise EnvironmentFailure(
            "suite-side C build failed for %s: exit=%d stderr=%r"
            % (path, proc.returncode, proc.stderr[-2000:])
        )


def _resolve_offsets(target_path):
    """Resolve probe file offsets from the consumer binary bytes.

    Suite-side staging (ambient readelf): both subscriber symbols
    must be global functions in .text of a non-PIE executable.
    """
    try:
        header = subprocess.run(
            ["readelf", "-h", "-W", target_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=120,
        )
        sections = subprocess.run(
            ["readelf", "-S", "-W", target_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=120,
        )
        symbols = subprocess.run(
            ["readelf", "-s", "-W", target_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EnvironmentFailure("cannot run readelf: %s" % exc)
    if header.returncode != 0 or "EXEC" not in header.stdout:
        raise EnvironmentFailure(
            "consumer target must be non-PIE (ET_EXEC)"
        )
    section_map = {}
    for line in sections.stdout.splitlines():
        match = re.match(
            r"\s*\[(\d+)\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)",
            line,
        )
        if match:
            section_map[int(match.group(1))] = (
                match.group(2),
                int(match.group(3), 16),
                int(match.group(4), 16),
            )
    offsets = {}
    for line in symbols.stdout.splitlines():
        match = re.match(
            r"\s*\d+:\s+([0-9a-f]+)\s+\d+\s+(\S+)\s+(\S+)\s+\S+\s+"
            r"(\d+)\s+(\S+)",
            line,
        )
        if not match:
            continue
        value, sym_type, bind, ndx, name = (
            int(match.group(1), 16),
            match.group(2),
            match.group(3),
            int(match.group(4)),
            match.group(5),
        )
        if name not in ("watched_call", "never_watched"):
            continue
        if sym_type != "FUNC" or bind != "GLOBAL":
            raise EnvironmentFailure(
                "consumer symbol %s must be a global function" % name
            )
        section_name, vma, file_off = section_map[ndx]
        if section_name != ".text":
            raise EnvironmentFailure(
                "consumer symbol %s must live in .text" % name
            )
        offsets[name] = "0x%x" % (value - vma + file_off)
    if set(offsets) != {"watched_call", "never_watched"}:
        raise EnvironmentFailure(
            "consumer probe symbols missing: %r" % (offsets,)
        )
    if offsets["watched_call"] == offsets["never_watched"]:
        raise EnvironmentFailure("consumer probe symbols must be distinct")
    return offsets


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
    for tool in ("cc", "readelf"):
        if shutil.which(tool) is None:
            raise EnvironmentFailure(
                "%s not found on PATH (suite-side staging)" % tool
            )
    for name in CONSUMER_FILES:
        if not os.path.isfile(os.path.join(CONSUMER_DIR, name)):
            raise EnvironmentFailure("missing consumer file: %s" % name)
    if not os.path.isfile(HOLDER_SOURCE):
        raise EnvironmentFailure("missing harness: %s" % HOLDER_SOURCE)
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
    work = os.path.join(root, "work")
    project = os.path.join(work, "consumer")
    os.makedirs(project)
    for name in CONSUMER_FILES:
        with open(os.path.join(CONSUMER_DIR, name), "rb") as handle:
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
    lockfile_path = _write_consumer_lockfile(project, mojo, llc, trust)
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
    # Suite-side staging of the subscriber's own C sources (ambient
    # cc/readelf): the consumer's binary carries the probe sites.
    staging = os.path.join(root, "staging")
    os.makedirs(staging)
    consumer_target = os.path.join(staging, "consumer_target")
    _compile(
        CONSUMER_TARGET_SOURCE,
        [
            "cc", "-no-pie", "-fno-pie", "-O2", "-Wall", "-Wextra",
            "-o", consumer_target,
            os.path.join(project, CONSUMER_TARGET_SOURCE),
        ],
    )
    holder = os.path.join(staging, "uprobe_attach")
    _compile(
        HOLDER_SOURCE,
        ["cc", "-O2", "-Wall", "-Wextra", "-o", holder, HOLDER_SOURCE],
    )
    offsets = _resolve_offsets(consumer_target)
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
            "consumer_target": consumer_target,
            "holder": holder,
            "offsets": offsets,
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
    with open(sidecar, "rb") as handle:
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
    assert doc["tool_version"] == "0.2.0", doc
    assert doc["sdk_version"] == "1.5", doc
    assert doc["artifact"] == "subscriber_probe", doc


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
    source = os.path.join(fix["project"], CONSUMER_SOURCE)
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
        with open(
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
    subscriber_sha = _sha256_file(
        os.path.join(fix["project"], CONSUMER_SOURCE)
    )
    own_source = os.path.join(CONSUMER_DIR, CONSUMER_SOURCE)
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
            assert _sha256_file(other) != subscriber_sha, (
                "consumer source copies %s" % other
            )
    assert compared > 0, "no in-tree Mojo sources compared"
    print(
        "PASS no-copy corpus: subscriber differs from %d sources" % compared
    )


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
        CONSUMER_SOURCE: _sha256_file(
            os.path.join(fix["project"], CONSUMER_SOURCE)
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
            "--profile", CONSUMER_PROFILE,
            "--source-license", "Apache-2.0 WITH LLVM-exception",
            "--kernel-license", "Apache-2.0 WITH LLVM-exception",
        ],
        fix["project"],
        fix["env"],
        120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ok" in proc.stdout
    proc = _run(
        [
            fix["venv_mojobpf"],
            "inspect",
            "--object", obj,
            "--profile", BASE_PROFILE,
            "--source-license", "Apache-2.0 WITH LLVM-exception",
            "--kernel-license", "Apache-2.0 WITH LLVM-exception",
        ],
        fix["project"],
        fix["env"],
        120,
    )
    assert proc.returncode != 0, proc.stdout
    assert "MBPF406" in proc.stdout, proc.stdout


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


GUEST_SCRIPT = """#!/bin/bash
set -u
export PYTHONDONTWRITEBYTECODE=1
cd "{stage}"
WATCHED_OFFSET="{watched_offset}"
NEVER_OFFSET="{never_offset}"
{bpftool_prologue}
for i in 1 2 3 4 5 6; do echo "padding-$i: virtme-exec-drops-leading-bytes-0123456789abcdef"; done
echo "=== begin guest_subscriber ==="
echo "guest-id: $(id -u):$(id -g)"
echo "guest-kernel: $(uname -r)"
"$BPFTOOL" version | head -2
echo "=== staged hashes ==="
sha256sum subscriber.bpf.o consumer_target uprobe_attach
map_u64() {{
  "$BPFTOOL" map lookup pinned "$1" key "$2" 0 0 0 | python3 -c "import sys; print(int.from_bytes(bytes(int(tok, 16) for tok in sys.stdin.read().split('value:')[1].splitlines()[0].split()), 'little'))"
}}
u64_bytes() {{
  python3 -c "print(' '.join('%d' % b for b in ($1).to_bytes(8, 'little')))"
}}
map_set_u64() {{
  "$BPFTOOL" map update pinned "$1" key "$2" 0 0 0 value $(u64_bytes "$3")
}}
"$BPFTOOL" feature probe kernel >feature.txt 2>&1
grep -q "eBPF program_type kprobe is available" feature.txt || {{ echo "KPROBE-MISSING"; exit 3; }}
[ -w /sys/kernel/tracing/uprobe_events ] || {{ echo "UPROBE-IFACE-MISSING"; exit 3; }}
PINS_BEFORE=$(ls /sys/fs/bpf/)
LINKS_BEFORE=$("$BPFTOOL" link show)
PROGS_BEFORE=$("$BPFTOOL" prog show)
MAPS_BEFORE=$("$BPFTOOL" map show)
EVENTS_BEFORE=$(cat /sys/kernel/tracing/uprobe_events)
run_phase() {{
  LABEL="$1"; OFFSET="$2"; FILTER="$3"; CALLS="$4"; VALUE="$5"
  PIN="/sys/fs/bpf/mojobpf_sub_$LABEL"
  MAP_DIR="$PIN-maps"
  mkdir -p "$MAP_DIR" || {{ echo "$LABEL-MAPDIR-FAILED"; exit 1; }}
  "$BPFTOOL" prog load subscriber.bpf.o "$PIN" type kprobe pinmaps "$MAP_DIR/" >"/tmp/csub-$LABEL.load" 2>&1
  [ $? = 0 ] || {{ echo "$LABEL-LOAD-FAILED"; cat "/tmp/csub-$LABEL.load"; exit 1; }}
  MAP_PIN="$MAP_DIR/mojobpf_map0"
  [ -e "$MAP_PIN" ] || {{ echo "$LABEL-MAP-PIN-MISSING"; exit 1; }}
  rm -f "$LABEL-rel" "$LABEL-ora"
  mkfifo "$LABEL-rel" "$LABEL-ora"
  ./uprobe_attach "$PIN" "{stage}" "{stage}/consumer_target" "$OFFSET" "csub_$LABEL" <"$LABEL-rel" >"/tmp/csub-$LABEL.holder.log" 2>&1 &
  HOLDER_PID=$!
  exec 8<>"$LABEL-rel"
  for _ in $(seq 1 600); do
    grep -q "^ATTACHED " "/tmp/csub-$LABEL.holder.log" 2>/dev/null && break
    kill -0 "$HOLDER_PID" 2>/dev/null || break
    sleep 0.1
  done
  grep -q "^ATTACHED " "/tmp/csub-$LABEL.holder.log" || {{ echo "$LABEL-ATTACH-TIMEOUT"; cat "/tmp/csub-$LABEL.holder.log"; exit 1; }}
  map_set_u64 "$MAP_PIN" 0 "$FILTER" || {{ echo "$LABEL-FILTER-INIT-FAILED"; exit 1; }}
  map_set_u64 "$MAP_PIN" 1 0 || {{ echo "$LABEL-COUNT-INIT-FAILED"; exit 1; }}
  FILTER_READ=$(map_u64 "$MAP_PIN" 0)
  echo "=== BEGIN $LABEL ==="
  echo "filter: want=$FILTER readback=$FILTER_READ"
  timeout 300 python3 - "$LABEL" "$CALLS" "$VALUE" <<'PYEOF' || {{ echo "$LABEL-ORACLE-FAILED"; exit 1; }}
import struct, subprocess, sys
label, calls, value = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
proc = subprocess.Popen(['./consumer_target', str(calls), str(value), label + '-ora'],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
with open(label + '-ora', 'rb') as reader:
    data = reader.read()
out, err = proc.communicate()
print('%s-target-exit: %d' % (label, proc.returncode))
print('%s-target-out: %s %s' % (label, out.strip(), err.strip()))
if proc.returncode != 0:
    sys.exit(1)
words = struct.unpack('<%dQ' % (len(data) // 8), data) if data else ()
print('%s-oracle: n=%d distinct=%s' % (label, len(words), sorted(set(words))))
PYEOF
  echo "$LABEL-counter: $(map_u64 "$MAP_PIN" 1)"
  exec 8>&-
  wait "$HOLDER_PID"
  echo "$LABEL-detach-exit: $?"
  rm -f "$PIN" "$MAP_PIN"
  rmdir "$MAP_DIR" || {{ echo "$LABEL-MAPDIR-NOT-EMPTY"; exit 1; }}
  rm -f "$LABEL-rel" "$LABEL-ora"
  echo "=== END $LABEL ==="
}}
run_phase match "$WATCHED_OFFSET" {watched} {calls_n} {watched}
run_phase mismatch "$WATCHED_OFFSET" {watched} {calls_m} {other}
run_phase never "$NEVER_OFFSET" {watched} {calls_n} {watched}
echo "=== BEGIN residue ==="
echo "--- prog ---"
"$BPFTOOL" prog show
echo "--- map ---"
"$BPFTOOL" map show
echo "--- link ---"
"$BPFTOOL" link show
echo "--- events ---"
cat /sys/kernel/tracing/uprobe_events
echo "=== END residue ==="
echo "=== pin check ==="
stray=0
for pin in /sys/fs/bpf/mojobpf_sub_*; do
  if [ -e "$pin" ]; then echo "PIN STILL PRESENT: $pin"; stray=1; fi
done
if [ "$stray" -eq 0 ]; then echo "pin absent (unloaded)"; fi
echo "=== end guest_subscriber ==="
"""

CASES = ("match", "mismatch", "never", "residue")


def _load_reviewed_bpftool_pins():
    """Load reviewed bpftool pins, or refuse staging without them.

    MOJOBPF_BPFTOOL_PINS names a pins JSON document recorded out
    of band. Staging admits only with the explicitly reviewed
    status (``reviewed``): any other status, including a missing
    one, stays unadmitted, and a consumer-generated self-pin is
    never accepted. Absence refuses too: the probe must never
    generate the pins it runs under.
    """
    pins_path = os.environ.get(BPFTOOL_PINS_ENV, "")
    if not pins_path:
        raise ConsumerAdmissionError(
            "bpftool staging refused: set %s to a reviewed pins "
            "document (staging never self-pins the resolved "
            "bytes)" % (BPFTOOL_PINS_ENV,)
        )
    try:
        with open(pins_path, encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ConsumerAdmissionError(
            "cannot load bpftool pins %s: %s" % (pins_path, exc)
        )
    if not isinstance(document, dict):
        raise ConsumerAdmissionError(
            "bpftool pins %s is not an object" % pins_path
        )
    if document.get("status") != "reviewed":
        raise ConsumerAdmissionError(
            "bpftool pins %s carry status %r: only the "
            "explicitly reviewed admission state admits "
            "(anything else, including a test-generated "
            "self-pin, is not an independent trust root)"
            % (pins_path, document.get("status"))
        )
    if "consumer" in str(document.get("generated_by", "")).lower():
        raise ConsumerAdmissionError(
            "bpftool pins %s were generated by a consumer "
            "suite: a self-pin is not an independent trust root"
            % pins_path
        )
    if document.get("schema_version") != 1:
        raise ConsumerAdmissionError(
            "bpftool pins %s have unsupported schema_version"
            % pins_path
        )
    entry = document.get("bpftool")
    if not isinstance(entry, dict):
        raise ConsumerAdmissionError(
            "bpftool pins %s lack the bpftool entry" % pins_path
        )
    for key in ("version", "sha256"):
        if not isinstance(entry.get(key), str) or not entry[key]:
            raise ConsumerAdmissionError(
                "bpftool pins %s entry lacks %r" % (pins_path, key)
            )
    return {
        "bpftool": {
            "exec_sha256": entry.get("exec_sha256"),
            "sha256": entry["sha256"],
            "version": entry["version"],
        },
        "exec_pin_present": entry.get("exec_sha256") is not None,
        "path": pins_path,
        "source_sha256": _sha256_file(pins_path),
    }


def _stage_bpftool_pins(env):
    """Stage reviewed guest bpftool admission pins.

    Host-side admission, run before the guest boots: the virtme
    guest shares the host rootfs, so the host-resolved bpftool
    bytes are the bytes the guest will execute. The resolved
    entry is admitted against the reviewed pins (entry hash,
    exec chain, version) before any process starts, through
    the shared execution contract's verify-then-spawn path;
    any mismatch refuses without executing. The returned
    ``{"path", "sha256", "exec_path", "exec_sha256", "chain",
    "version"}`` pins carry the reviewed entry, exec-image
    and version pins verbatim (the probe only verifies them,
    it never generates the pins it runs under), plus the
    complete admitted launcher chain: ``chain`` lists every
    intermediate hop's staging-observed path and hash in
    order (empty for directly executed entries and
    single-hop launchers). The intermediate hashes are
    staging observations, not trust roots -- admission
    already constrained them (exact launcher grammar
    resolving to the reviewed image) -- and the guest
    prologue re-verifies them to detect post-staging
    replacement of any link. The guest re-admits the
    staged bytes before executing them.
    """
    reviewed = _load_reviewed_bpftool_pins()
    path = shutil.which("bpftool", path=env["PATH"])
    if path is None:
        raise EnvironmentFailure(
            "bpftool is not on the staging PATH"
        )
    if _under_repo(path) or _under_repo(os.path.realpath(path)):
        raise ConsumerAdmissionError(
            "bpftool resolves into the checkout tree: %s" % path
        )
    realpath = os.path.realpath(path)
    expected = reviewed["bpftool"]
    try:
        admitted = execution.admit_execution(
            execution.ExecutionRequest(
                name="bpftool",
                argv0=realpath,
                allow_path_lookup=False,
                forms=execution.DEFAULT_FORMS,
                probe_version=True,
                trust_root=reviewed["path"],
            ),
            execution.ExecutionPins(
                version=expected["version"],
                entry_sha256=expected["sha256"],
                exec_sha256=expected["exec_sha256"],
                exec_pin_present=reviewed["exec_pin_present"],
            ),
            probe_timeout=120,
        )
    except execution.AdmissionError as exc:
        raise ConsumerAdmissionError(
            "bpftool staging refused: %s" % exc
        )
    if admitted.form == execution.FORM_EXEC_LAUNCHER:
        exec_path = admitted.image.realpath
        chain = [
            {"path": hop.realpath, "sha256": hop.sha256}
            for hop in admitted.hops[1:-1]
        ]
    else:
        exec_path = None
        chain = []
    return {
        "path": admitted.entry.realpath,
        "sha256": expected["sha256"],
        "exec_path": exec_path,
        "exec_sha256": expected["exec_sha256"],
        "chain": chain,
        "version": expected["version"],
    }


def _render_bpftool_prologue(pins):
    """Render the guest prologue re-verifying the admitted chain.

    The staged entry path+hash always re-verify; a launcher
    entry additionally re-verifies every intermediate hop's
    path+hash and then its admitted exec image path+hash.
    All checks run before any guest probe, so a
    post-staging replacement of any link refuses instead
    of executing. Entry and image hashes are the reviewed
    pins verbatim; intermediate hashes are the staging
    observations; paths are the staging resolution baked
    in at render. An exec hash without a staged image path
    refuses outright.
    """
    lines = [
        "BPFTOOL=%s" % shlex.quote(pins["path"]),
        'echo "%s  $BPFTOOL" | sha256sum -c - || '
        '{ echo "BPFTOOL-PIN-MISMATCH"; exit 1; }'
        % pins["sha256"],
    ]
    for position, link in enumerate(pins.get("chain") or []):
        lines.extend(
            [
                "BPFTOOL_CHAIN_%d=%s"
                % (position, shlex.quote(link["path"])),
                'echo "%s  $BPFTOOL_CHAIN_%d" | sha256sum -c - || '
                '{ echo "BPFTOOL-CHAIN-MISMATCH"; exit 1; }'
                % (link["sha256"], position),
            ]
        )
    if pins.get("exec_sha256") is not None:
        if not pins.get("exec_path"):
            lines.append('{ echo "BPFTOOL-EXEC-MISSING"; exit 1; }')
        else:
            lines.extend(
                [
                    "BPFTOOL_IMAGE=%s"
                    % shlex.quote(pins["exec_path"]),
                    'echo "%s  $BPFTOOL_IMAGE" | sha256sum -c - || '
                    '{ echo "BPFTOOL-EXEC-MISMATCH"; exit 1; }'
                    % pins["exec_sha256"],
                ]
            )
    return "\n".join(lines)


def _render_guest_script(stage, offsets, pins):
    """Render the guest script with the staged bpftool pins.

    The admitted bpftool chain re-verifies in the guest
    prologue before any probe runs; every guest probe runs
    ``"$BPFTOOL"``, never a bare PATH-resolved ``bpftool``.
    """
    return GUEST_SCRIPT.format(
        stage=stage,
        watched_offset=offsets["watched_call"],
        never_offset=offsets["never_watched"],
        watched=CONSUMER_WATCHED,
        other=CONSUMER_OTHER,
        calls_n=CONSUMER_N,
        calls_m=CONSUMER_M,
        bpftool_prologue=_render_bpftool_prologue(pins),
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
            "guest run timed out after %ds (stage kept at %s):\n%s"
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
    stage = tempfile.mkdtemp(prefix="consumer-subscriber-", dir="/tmp")
    staged = {
        "subscriber.bpf.o": os.path.join(fix["out_dir"], CONSUMER_OBJECT),
        "consumer_target": fix["consumer_target"],
        "uprobe_attach": fix["holder"],
    }
    for name, src in staged.items():
        with open(src, "rb") as handle:
            data = handle.read()
        with open(os.path.join(stage, name), "wb") as handle:
            handle.write(data)
    host_shas = {
        name: _sha256_file(os.path.join(stage, name))
        for name in staged
    }
    pins = _stage_bpftool_pins(fix["env"])
    script = _render_guest_script(stage, fix["offsets"], pins)
    script_path = os.path.join(stage, "guest_subscriber.sh")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write(script)
    for name in list(staged) + ["guest_subscriber.sh"]:
        os.chmod(os.path.join(stage, name), 0o644)
    os.chmod(os.path.join(stage, "consumer_target"), 0o755)
    os.chmod(os.path.join(stage, "uprobe_attach"), 0o755)
    os.chmod(stage, 0o755)
    exit_code, output = _run_guest(
        [vng_path, "--run", VNG_RELEASE, "--disable-kvm",
         "--exec", "bash %s" % script_path],
        stage,
        VNG_TIMEOUT,
    )
    if "KPROBE-MISSING" in output or "UPROBE-IFACE-MISSING" in output:
        raise EnvironmentFailure(
            "guest lacks the kprobe program type or the tracefs "
            "uprobe interface (stage kept at %s)" % stage
        )
    if exit_code != 0:
        raise EnvironmentFailure(
            "vng guest run failed (exit %d, stage kept at %s):\n%s"
            % (exit_code, stage, output[-4000:])
        )
    transcript_path = os.path.join(stage, "guest_transcript.log")
    with open(transcript_path, "w", encoding="utf-8") as handle:
        handle.write(output)
    print("guest transcript: %s" % transcript_path)
    results = {}
    for match in re.finditer(
        r"=== BEGIN (\S+)(?: exit=(\d+))? ===\n(.*?)\n=== END \1 ===",
        output,
        re.DOTALL,
    ):
        tag, exit_text, body = match.groups()
        results[tag] = {
            "exit": int(exit_text) if exit_text is not None else None,
            "body": body,
        }
    missing = [tag for tag in CASES if tag not in results]
    if missing:
        raise EnvironmentFailure(
            "guest output lacks cases %s (stage kept at %s):\n%s"
            % (", ".join(missing), stage, output[-4000:])
        )
    _GUEST["run"] = {
        "stage": stage,
        "output": output,
        "results": results,
        "host_shas": host_shas,
    }
    return _GUEST["run"]


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


def test_guest_script_binds_bpftool_to_reviewed_pins():
    pins = {
        "path": "/usr/sbin/bpftool",
        "sha256": "1" * 64,
        "exec_sha256": None,
        "version": "v7.7.0",
    }
    script = _render_guest_script(
        "/tmp/stage",
        {"watched_call": 16, "never_watched": 32},
        pins,
    )
    assert "BPFTOOL=/usr/sbin/bpftool" in script, script
    assert "%s  $BPFTOOL" % ("1" * 64) in script, script
    assert "BPFTOOL-PIN-MISMATCH" in script, script
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
            "/tmp/stage",
            {"watched_call": 16, "never_watched": 32},
            pins,
        )
        assert prologue in script, script
        head = script.split(prologue, 1)[0]
        assert '"$BPFTOOL"' not in head, head
        assert '"$BPFTOOL"' in script, script
    finally:
        _restore_consumer_env(saved)
        shutil.rmtree(workdir, ignore_errors=True)


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
                "uprobe consumer (PATH-resolved pins)"
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
        assert [link["path"] for link in chain] == [
            os.path.realpath(middle)
        ], pins
        assert chain[0]["sha256"] == middle_sha256, pins
        # The shared admission agrees with the guest refusal:
        # the swapped chain no longer resolves.
        captured = execution.capture_chain(os.path.realpath(entry))
        assert captured.form == execution.FORM_UNKNOWN, captured
        script = _render_guest_script(
            "/tmp/stage",
            {"watched_call": 16, "never_watched": 32},
            pins,
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


def parse_board(body, label):
    """Parse one phase board into its fields."""
    fields = {}
    for line in body.splitlines():
        if line.startswith(label + "-") or line.startswith("filter:"):
            key, _, value = line.partition(": ")
            fields[key.strip()] = value.strip()
    for key in (
        "%s-target-exit" % label,
        "%s-target-out" % label,
        "%s-oracle" % label,
        "%s-counter" % label,
        "%s-detach-exit" % label,
        "filter",
    ):
        assert key in fields, "%s board lacks %s:\n%s" % (label, key, body)
    return fields


def check_board(label, calls, value, want_counter):
    run = guest_run()
    fields = parse_board(run["results"][label]["body"], label)
    assert fields["%s-target-exit" % label] == "0", fields
    assert fields["%s-target-out" % label].startswith(
        "done calls=%d value=%d" % (calls, value)
    ), fields
    assert fields["%s-oracle" % label] == "n=%d distinct=[%d]" % (
        calls, value,
    ), fields
    assert fields["filter"] == "want=%d readback=%d" % (
        CONSUMER_WATCHED, CONSUMER_WATCHED,
    ), fields
    assert fields["%s-counter" % label] == str(want_counter), fields
    assert fields["%s-detach-exit" % label] == "0", fields


def test_consumer_exact_kernel_result():
    check_board("match", CONSUMER_N, CONSUMER_WATCHED, CONSUMER_N)
    check_board("mismatch", CONSUMER_M, CONSUMER_OTHER, 0)
    check_board("never", CONSUMER_N, CONSUMER_WATCHED, 0)
    print(
        "consumer kernel: match/mismatch/never = %d/0/0 "
        "with oracle agreement" % CONSUMER_N
    )


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
    residue = run["results"]["residue"]["body"]
    for name in ("uprobe_entry", "mojobpf", "mojobpf_sub_", "csub_"):
        assert name not in residue, (
            "residue still names %r:\n%s" % (name, residue)
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
            "#!/bin/sh\necho \"$0\" >> %s\necho '%s'\n"
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
        assert logged == [os.path.realpath(link)], (
            "probe must execute the admitted image, got %r" % logged
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


def main():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    # Direct runs always execute every host check and opt into
    # the full run; the guest checks additionally need a target
    # lease (MOJOBPF_CONSUMER_GUEST_LEASE=1) or report
    # required-unavailable. Under pytest the guest checks skip by
    # default instead.
    os.environ[CONSUMER_FULL_ENV] = "1"
    failures = 0
    unavailable = 0
    names = sorted(k for k in globals() if k.startswith("test_"))
    for name in names:
        try:
            globals()[name]()
        except EnvironmentFailure as exc:
            print("ENVIRONMENT FAILURE in %s: %s" % (name, exc))
            return 2
        except ConsumerAdmissionError as exc:
            print("ADMISSION FAILURE in %s: %s" % (name, exc))
            return 1
        except GuestRequiredError as exc:
            print("REQUIRED-UNAVAILABLE %s: %s" % (name, exc))
            unavailable += 1
        except AssertionError as exc:
            print("FAIL %s: %s" % (name, exc))
            failures += 1
        else:
            print("PASS %s" % name)
    if failures:
        return 1
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
        return 3
    print(
        "consumer kernel: match/mismatch/never = %d/0/0"
        % CONSUMER_N
    )
    print("uprobe consumer: isolated build plus exact kernel result")
    return 3 if unavailable else 0


if __name__ == "__main__":
    sys.exit(main())
