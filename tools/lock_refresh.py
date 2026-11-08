# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Deterministic lock refresh for reviewable pin admission (A03).

The release and lane locks are reviewed pins, not PATH observations.
This tool regenerates them deterministically from named source
artifacts and writes a generation report naming the source artifacts,
the digest types, the executable closures and the trust/bootstrap
origin. Generation never auto-promotes discovered PATH tools to
``release-approved`` pins: every generated lock carries the
``bootstrap`` label, and only the reviewed identity/source checks in
:func:`verify_toolchains_lock` / :func:`verify_kernels_lock` accept
the ``release-approved`` label.

Subcommands::

    tools/lock_refresh.py generate --kind toolchains \\
        --inventory INV.json --pixi-lock pixi.lock \\
        --adapter-dir DIR --out LOCK --report REPORT
    tools/lock_refresh.py generate --kind kernels \\
        --vng PATH --qemu PATH --qemu-binary NAME \\
        --module-root DIR --first-party virtme_ng,virtme \\
        --extra-module _virtualenv --lanes LANES.json \\
        --out LOCK --report REPORT
    tools/lock_refresh.py verify --kind toolchains|kernels \\
        --lock LOCK [--repo-root DIR]

``generate`` observes the machine (it runs ``--version`` probes like
``tests/probes/toolchain_inventory.py`` does); its output is
observational bootstrap until reviewed. Versions are never invented:
a missing or failing probe is a hard error, and a failure writes
neither output. ``verify`` checks a lock's reviewed state: the
reviewed labels, the bound bytes beside the lock (never through
ambient PATH), and every pinned executable re-hashed against its
recorded source on the qualifying machine (recorded tool paths,
PATH-resolved runner binaries, cached lane artifacts). Promotion
verification is machine-scoped by design: it passes only where the
pinned sources are installed.

Exit codes: 0 on success, 1 when verification finds errors, 2 for
usage and input errors. Running under ``python -O`` is refused.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "src",
    ),
)

from mojobpf import execution  # noqa: E402

LOCK_TOOL = "tools/lock_refresh.py"
REPORT_SCHEMA_VERSION = 1
LOCK_SCHEMA_VERSION = 1
LOCK_LICENSE = "Apache-2.0 WITH LLVM-exception"
STATUS_BOOTSTRAP = "bootstrap"
STATUS_RELEASE = "release-approved"
GENERATED_BY_BOOTSTRAP = "tools/lock_refresh.py (bootstrap)"

REQUIRED_TOOLS = ("mojo", "llc", "bpftool", "python")

TOOL_PROBES = {
    "mojo": "mojo_version",
    "llc": "llc_version",
    "bpftool": "bpftool_version",
    "clang": "clang_version",
    "llvm-config": "llvm_config_version",
    "python": "python_version",
}

DIGESTS = [
    {"subject": "file bytes", "type": "sha256"},
    {"subject": "first version line", "type": "verbatim"},
]

TRUST_NOTE = (
    "PATH discovery recorded as bootstrap; never release-approved "
    "without the reviewed identity/source checks "
    "(tools/lock_refresh.py verify --kind toolchains|kernels)"
)

PROBE_TIMEOUT = 60


class LockRefreshError(Exception):
    """A refresh input is missing, unreadable or inconsistent."""


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_bytes(document):
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def write_canonical(path, document):
    with open(path, "wb") as handle:
        handle.write(canonical_json_bytes(document))


def _is_hex_digest(value):
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _load_json(path, role):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise LockRefreshError(
            "cannot read %s %s: %s" % (role, path, exc)
        )
    except ValueError as exc:
        raise LockRefreshError(
            "%s %s is not valid JSON: %s" % (role, path, exc)
        )


def _probe_first_line(argv, role):
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=PROBE_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LockRefreshError(
            "%s version probe failed for %s: %s" % (role, argv[0], exc)
        )
    if completed.returncode != 0:
        raise LockRefreshError(
            "%s version probe exited %d for %s"
            % (role, completed.returncode, argv[0])
        )
    version = execution.first_output_line(
        completed.stdout.decode("utf-8", "replace"),
        completed.stderr.decode("utf-8", "replace"),
    )
    if version is None:
        raise LockRefreshError(
            "%s version probe printed nothing for %s" % (role, argv[0])
        )
    return version


def _capture_entry(path, role):
    abspath = os.path.abspath(path)
    if not os.path.isfile(abspath):
        raise LockRefreshError(
            "%s is not a file: %s" % (role, path)
        )
    try:
        captured = execution.capture_chain(abspath)
    except execution.AdmissionError as exc:
        raise LockRefreshError(
            "%s cannot be captured (%s); refusing to pin an "
            "unadmittable chain" % (path, exc.detail)
        )
    if captured.form == execution.FORM_UNKNOWN:
        raise LockRefreshError(
            "%s is not a supported executable form (%s); refusing "
            "to pin an unadmittable chain" % (path, captured.note)
        )
    return captured


def _entry_closure(captured):
    """Entry/exec/interpreter hashes for one captured chain."""
    if captured.form == execution.FORM_EXEC_LAUNCHER:
        entry_sha256 = captured.hops[0].sha256
        exec_sha256 = captured.image.sha256
    else:
        entry_sha256 = captured.image.sha256
        exec_sha256 = None
    interpreter_sha256 = None
    if captured.interpreter is not None:
        interpreter_sha256 = sha256_file(captured.interpreter)
    return {
        "entry_sha256": entry_sha256,
        "exec_sha256": exec_sha256,
        "form": captured.form,
        "interpreter_sha256": interpreter_sha256,
    }


def _dir_digest(root, suffix=".py"):
    """Deterministic digest of a source directory's file set.

    Generated bytecode caches (``__pycache__`` directories and
    ``*.pyc``/``*.pyo`` files) are not inputs: they are excluded so
    a cache landing mid-run cannot perturb the digest.
    """
    entries = {}
    for current, dirs, files in os.walk(root):
        for cached in [
            name for name in dirs if name == "__pycache__"
        ]:
            dirs.remove(cached)
        dirs.sort()
        for name in sorted(files):
            if not name.endswith(suffix):
                continue
            if name.endswith((".pyc", ".pyo")):
                continue
            full = os.path.join(current, name)
            relpath = os.path.relpath(full, root)
            entries[relpath] = sha256_file(full)
    digest = hashlib.sha256()
    digest.update(canonical_json_bytes(entries))
    return digest.hexdigest(), sorted(entries)


def _source_name(path):
    """Portable artifact name for report bytes (location-free).

    Reports name the consumed artifact, never the absolute input
    location, so identical input bytes produce identical report
    bytes wherever they are read from.
    """
    return os.path.basename(os.path.abspath(path))


def generate_toolchains(*, inventory, pixi_lock, adapter_dir):
    """Build a bootstrap toolchains lock plus its report.

    Returns ``(lock, report)``; raises :class:`LockRefreshError`
    without writing anything when a required probe is missing or a
    source is unreadable. The lock carries ``status: bootstrap``
    unconditionally; the ``vm`` record (guest-observed) is never
    generated.
    """
    document = _load_json(inventory, "inventory")
    if not isinstance(document, dict) or (
        document.get("schema_version") != 1
    ):
        raise LockRefreshError(
            "inventory %s has unsupported schema_version" % inventory
        )
    by_name = {}
    commands = document.get("commands")
    if not isinstance(commands, list):
        raise LockRefreshError(
            "inventory %s has no commands table" % inventory
        )
    for entry in commands:
        if isinstance(entry, dict) and "name" in entry:
            by_name[entry["name"]] = entry
    tools = {}
    closures = {}
    limitations = []
    for tool_name in (
        "mojo",
        "llc",
        "bpftool",
        "clang",
        "llvm-config",
        "python",
    ):
        record = by_name.get(TOOL_PROBES[tool_name])
        if (
            not isinstance(record, dict)
            or not record.get("ok")
            or not record.get("realpath")
            or not record.get("sha256")
        ):
            if tool_name in REQUIRED_TOOLS:
                raise LockRefreshError(
                    "inventory %s has no usable %s probe; refusing "
                    "to invent the %s pin"
                    % (inventory, TOOL_PROBES[tool_name], tool_name)
                )
            limitations.append(
                "optional tool %s has no usable probe; omitted" % tool_name
            )
            continue
        version = execution.first_output_line(
            record.get("stdout", ""), record.get("stderr", "")
        )
        if version is None:
            if tool_name in REQUIRED_TOOLS:
                raise LockRefreshError(
                    "inventory %s probe %s printed no version; "
                    "refusing to invent the %s pin"
                    % (inventory, TOOL_PROBES[tool_name], tool_name)
                )
            limitations.append(
                "optional tool %s printed no version; omitted" % tool_name
            )
            continue
        captured = _capture_entry(record["realpath"], tool_name)
        closure = _entry_closure(captured)
        closures[tool_name] = dict(closure)
        closures[tool_name]["realpath"] = captured.image.realpath
        tools[tool_name] = {
            "exec_sha256": closure["exec_sha256"],
            "path": record.get("path"),
            "realpath": record["realpath"],
            "sha256": record["sha256"],
            "status": "present",
            "version": version,
        }
        if closure["entry_sha256"] != record["sha256"]:
            raise LockRefreshError(
                "inventory %s sha256 for %s does not match the "
                "live bytes; refusing to pin drifted input"
                % (inventory, tool_name)
            )
    observations = document.get("observations", {})
    libbpf = observations.get("libbpf", {})
    runtime_objects = libbpf.get("runtime_objects", [])
    if runtime_objects:
        runtime = runtime_objects[0]
        tools["libbpf"] = {
            "bpftool_reported": libbpf.get("bpftool_reported"),
            "pkg_config_version": libbpf.get("pkg_config_version"),
            "runtime": {
                "path": runtime.get("path"),
                "realpath": runtime.get("realpath"),
                "sha256": runtime.get("sha256"),
            },
            "status": "present",
        }
    else:
        limitations.append("no libbpf runtime object observed; omitted")
    header = observations.get("environment", {}).get(
        "uapi_bpf_header", {}
    )
    if header.get("present") and header.get("sha256"):
        tools["uapi_bpf_header"] = {
            "path": header.get("path"),
            "sha256": header.get("sha256"),
            "status": "present",
        }
    else:
        limitations.append("UAPI bpf.h not observed; omitted")
    if not os.path.isfile(pixi_lock):
        raise LockRefreshError(
            "pixi lockfile is not a file: %s" % pixi_lock
        )
    pixi_sha256 = sha256_file(pixi_lock)
    distribution = {
        "file": os.path.basename(pixi_lock),
        "kind": "pixi-lock",
        "note": (
            "Native dynamic closure (loader, libc, linked shared "
            "libraries) and the toolchain install are bound to this "
            "locked distribution (bootstrap record; reviewed "
            "promotion required)."
        ),
        "platform": "linux-64",
        "sha256": pixi_sha256,
    }
    if not os.path.isdir(adapter_dir):
        raise LockRefreshError(
            "adapter directory is not a directory: %s" % adapter_dir
        )
    service_path = os.path.join(adapter_dir, "adapter_service.py")
    if not os.path.isfile(service_path):
        raise LockRefreshError(
            "adapter service missing under %s; refusing a lock "
            "without adapter pins" % adapter_dir
        )
    siblings = {}
    for name in sorted(os.listdir(adapter_dir)):
        if not name.endswith(".py") or name == "adapter_service.py":
            continue
        siblings[name] = sha256_file(os.path.join(adapter_dir, name))
    # The driver requires the admission descriptor pin for
    # default-adapter builds; a lock without it fails every build,
    # so generation refuses instead of emitting an unusable lock.
    descriptor_path = os.path.join(adapter_dir, "admission.json")
    if not os.path.isfile(descriptor_path):
        raise LockRefreshError(
            "adapter admission descriptor missing under %s; refusing "
            "a lock without adapter pins" % adapter_dir
        )
    siblings["admission.json"] = sha256_file(descriptor_path)
    adapter = {
        "note": (
            "execution-contract-v1 pins for the packaged default "
            "adapter service (bootstrap record; reviewed promotion "
            "required)."
        ),
        "service_sha256": sha256_file(service_path),
        "siblings": siblings,
    }
    limitations.append(
        "guest-observed vm record (host/guest kernels, emulator "
        "claim) is never generated from PATH discovery"
    )
    lock = {
        "adapter": adapter,
        "distribution": distribution,
        "generated_by": GENERATED_BY_BOOTSTRAP,
        "license": LOCK_LICENSE,
        "schema_version": LOCK_SCHEMA_VERSION,
        "status": STATUS_BOOTSTRAP,
        "tools": tools,
    }
    adapter_digest, adapter_files = _dir_digest(adapter_dir)
    report = {
        "digests": [dict(item) for item in DIGESTS],
        "kind": "toolchains",
        "limitations": limitations,
        "lock": {"schema_version": LOCK_SCHEMA_VERSION},
        "outputs": {
            "lock_sha256": hashlib.sha256(
                canonical_json_bytes(lock)
            ).hexdigest()
        },
        "closures": closures,
        "schema_version": REPORT_SCHEMA_VERSION,
        "sources": [
            {
                "path": _source_name(inventory),
                "role": "inventory",
                "sha256": sha256_file(inventory),
            },
            {
                "path": _source_name(pixi_lock),
                "role": "pixi-lock",
                "sha256": pixi_sha256,
            },
            {
                "files": adapter_files,
                "path": _source_name(adapter_dir),
                "role": "adapter-dir",
                "sha256": adapter_digest,
            },
        ],
        "status": STATUS_BOOTSTRAP,
        "tool": LOCK_TOOL,
        "trust": {"note": TRUST_NOTE, "origin": STATUS_BOOTSTRAP},
    }
    return lock, report


def _normalize_dist_name(name):
    import re

    return re.sub(r"[-_.]+", "-", name).lower()


def _read_dist_info(dist_info_dir):
    metadata_path = os.path.join(dist_info_dir, "METADATA")
    record_path = os.path.join(dist_info_dir, "RECORD")
    for path in (metadata_path, record_path):
        if not os.path.isfile(path):
            raise LockRefreshError(
                "distribution record %s is incomplete (missing %s)"
                % (dist_info_dir, os.path.basename(path))
            )
    with open(metadata_path, encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    name = None
    version = None
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() == "name" and name is None:
            name = value.strip()
        elif key.strip().lower() == "version" and version is None:
            version = value.strip()
    if not name or not version:
        raise LockRefreshError(
            "distribution METADATA %s names no Name/Version"
            % metadata_path
        )
    return {
        "metadata_sha256": sha256_file(metadata_path),
        "name": name,
        "record_sha256": sha256_file(record_path),
        "version": version,
    }


def _walk_first_party(module_root, package):
    """Hash every module under one first-party package or module."""
    modules = {}
    package_dir = os.path.join(module_root, package)
    if os.path.isdir(package_dir):
        for current, dirs, files in os.walk(package_dir):
            dirs.sort()
            for name in sorted(files):
                if not name.endswith(".py"):
                    continue
                full = os.path.join(current, name)
                relpath = os.path.relpath(full, package_dir)
                parts = relpath.split(os.sep)
                if parts[-1] == "__init__.py":
                    parts = parts[:-1]
                else:
                    parts[-1] = os.path.splitext(parts[-1])[0]
                dotted = ".".join([package] + parts)
                modules[dotted] = sha256_file(full)
    else:
        module_file = os.path.join(module_root, package + ".py")
        if not os.path.isfile(module_file):
            raise LockRefreshError(
                "first-party module %s is neither a package nor a "
                "module under %s" % (package, module_root)
            )
        modules[package] = sha256_file(module_file)
    if not modules:
        raise LockRefreshError(
            "first-party package %s has no modules under %s"
            % (package, module_root)
        )
    return modules


def _interpreter_tag(interpreter_path):
    try:
        completed = subprocess.run(
            [
                interpreter_path,
                "-c",
                "import platform, sys; "
                "sys.stdout.write("
                "platform.python_implementation().lower() + '-' "
                "+ '.'.join(str(part) for part in sys.version_info[:2]))",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=PROBE_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LockRefreshError(
            "cannot identify interpreter %s: %s" % (interpreter_path, exc)
        )
    if completed.returncode != 0:
        raise LockRefreshError(
            "cannot identify interpreter %s" % interpreter_path
        )
    return completed.stdout.decode("utf-8", "replace").strip()


def generate_kernels(
    *,
    vng,
    qemu,
    qemu_binary,
    lanes_path,
    virtme_run=None,
    module_root=None,
    first_party=(),
    extra_modules=(),
    runner_kind="uv-tool",
    emulator_kind="debian-package",
):
    """Build a bootstrap kernels lock plus its report.

    Returns ``(lock, report)``; raises :class:`LockRefreshError`
    without writing anything when a source is missing or two
    sources disagree. Lane metadata (argv prefixes, rootfs URLs,
    observed guest strings) is recorded from the operator-supplied
    lanes document, never observed; the report says so.
    """
    vng_captured = _capture_entry(vng, "vng")
    vng_closure = _entry_closure(vng_captured)
    vng_version = _probe_first_line(
        [os.path.abspath(vng), "--version"], "runner"
    )
    qemu_captured = _capture_entry(qemu, "qemu")
    qemu_closure = _entry_closure(qemu_captured)
    qemu_version = _probe_first_line(
        [os.path.abspath(qemu), "--version"], "emulator"
    )
    runner = {
        "exec_sha256": vng_closure["exec_sha256"],
        "name": "vng",
        "qemu": qemu_version,
        "qemu_binary": qemu_binary,
        "qemu_exec_sha256": qemu_closure["exec_sha256"],
        "qemu_sha256": qemu_closure["entry_sha256"],
        "sha256": vng_closure["entry_sha256"],
        "version": vng_version,
    }
    closures = {
        "vng": dict(vng_closure),
        "qemu": dict(qemu_closure),
    }
    limitations = []
    if virtme_run is not None:
        launcher = _capture_entry(virtme_run, "virtme-run")
        launcher_closure = _entry_closure(launcher)
        runner["virtme_run_exec_sha256"] = launcher_closure[
            "exec_sha256"
        ]
        runner["virtme_run_sha256"] = launcher_closure["entry_sha256"]
        closures["virtme-run"] = dict(launcher_closure)
    else:
        limitations.append("virtme-run not supplied; unpinned")
    if vng_captured.interpreter is not None:
        runner["interpreter"] = {
            "description": (
                "console-script interpreter resolved via the entry "
                "shebang and hash-pinned (install paths are not "
                "pinned)"
            ),
            "sha256": vng_closure["interpreter_sha256"],
        }
    else:
        limitations.append("runner has no script interpreter")
    distribution = None
    if module_root is not None:
        if not os.path.isdir(module_root):
            raise LockRefreshError(
                "module root is not a directory: %s" % module_root
            )
        if len(first_party) != 2:
            raise LockRefreshError(
                "kernels generation needs exactly two first-party "
                "packages (got %r); extend the tool explicitly for "
                "any other runner shape" % (list(first_party),)
            )
        if vng_captured.interpreter is None:
            raise LockRefreshError(
                "module bindings need a script interpreter for vng"
            )
        first_modules = _walk_first_party(module_root, first_party[0])
        for extra in extra_modules:
            extra_file = os.path.join(module_root, extra + ".py")
            if not os.path.isfile(extra_file):
                raise LockRefreshError(
                    "extra module %s.py missing under %s"
                    % (extra, module_root)
                )
            first_modules[extra] = sha256_file(extra_file)
        second_modules = _walk_first_party(module_root, first_party[1])
        runner["package"] = {
            "modules": first_modules,
            "name": first_party[0],
        }
        runner["virtme_package"] = {
            "modules": second_modules,
            "name": first_party[1],
        }
        closures["modules"] = dict(first_modules)
        closures["modules"].update(second_modules)
        excluded = {
            _normalize_dist_name(item) for item in first_party
        }
        dependencies = []
        runner_identity = None
        for name in sorted(os.listdir(module_root)):
            if not name.endswith(".dist-info"):
                continue
            record = _read_dist_info(os.path.join(module_root, name))
            if (
                _normalize_dist_name(record["name"])
                in excluded
            ):
                if (
                    _normalize_dist_name(record["name"])
                    == _normalize_dist_name(first_party[0])
                ):
                    runner_identity = record
                continue
            dependencies.append(record)
        dependencies.sort(key=lambda item: (item["name"], item["version"]))
        if runner_identity is None:
            raise LockRefreshError(
                "no installed distribution matches first-party %s "
                "under %s; refusing to invent the runner identity"
                % (first_party[0], module_root)
            )
        if runner_identity["version"] not in vng_version:
            raise LockRefreshError(
                "runner probe %r disagrees with installed %s %s; "
                "refusing inconsistent input"
                % (
                    vng_version,
                    runner_identity["name"],
                    runner_identity["version"],
                )
            )
        distribution = {
            "emulator": {
                "kind": emulator_kind,
                "qemu_version": qemu_version,
            },
            "note": (
                "First-party runner modules are hashed per-file; "
                "third-party dependencies are bound to their "
                "installed METADATA bytes plus the RECORD manifest "
                "(bootstrap record; reviewed promotion required)."
            ),
            "runner": {
                "dependencies": dependencies,
                "interpreter": _interpreter_tag(
                    vng_captured.interpreter
                ),
                "kind": runner_kind,
                "package": runner_identity["name"],
                "version": runner_identity["version"],
            },
        }
        closures["dependencies"] = {
            item["name"]: {
                "metadata_sha256": item["metadata_sha256"],
                "record_sha256": item["record_sha256"],
                "version": item["version"],
            }
            for item in dependencies
        }
        limitations.append(
            "runner kind %r and emulator kind %r are "
            "operator-supplied, not observed" % (runner_kind, emulator_kind)
        )
    elif first_party:
        raise LockRefreshError(
            "first-party modules need --module-root"
        )
    else:
        limitations.append(
            "no module root supplied; runner modules and third-party "
            "dependencies are unpinned"
        )
    lanes_document = _load_json(lanes_path, "lanes")
    raw_lanes = (
        lanes_document.get("lanes")
        if isinstance(lanes_document, dict)
        else None
    )
    if not raw_lanes or not isinstance(raw_lanes, list):
        raise LockRefreshError(
            "lanes %s names no lanes" % lanes_path
        )
    lanes = []
    deb_sources = []
    for index, spec in enumerate(raw_lanes):
        if not isinstance(spec, dict):
            raise LockRefreshError(
                "lanes %s entry %d is not an object" % (lanes_path, index)
            )
        for key in (
            "id",
            "release",
            "kernel_release",
            "accelerator",
            "vng_argv_prefix",
        ):
            if not spec.get(key):
                raise LockRefreshError(
                    "lanes %s entry %d lacks %r"
                    % (lanes_path, index, key)
                )
        debs = spec.get("debs")
        if not debs or not isinstance(debs, list):
            raise LockRefreshError(
                "lanes %s entry %d names no debs" % (lanes_path, index)
            )
        kernel_debs = []
        for deb in debs:
            if not os.path.isfile(deb):
                raise LockRefreshError(
                    "lane %s deb is not a file: %s"
                    % (spec.get("id"), deb)
                )
            kernel_debs.append(
                {
                    "file": os.path.basename(deb),
                    "sha256": sha256_file(deb),
                }
            )
            deb_sources.append(
                {
                    "path": _source_name(deb),
                    "role": "kernel-deb",
                    "sha256": kernel_debs[-1]["sha256"],
                }
            )
        lane = {
            "accelerator": spec["accelerator"],
            "id": spec["id"],
            "kernel_debs": kernel_debs,
            "kernel_release": spec["kernel_release"],
            "release": spec["release"],
            "vng_argv_prefix": list(spec["vng_argv_prefix"]),
        }
        for key in ("arch", "cross_compiler", "suite"):
            if spec.get(key):
                lane[key] = spec[key]
        rootfs = spec.get("rootfs")
        if rootfs is not None:
            image_path = rootfs.get("image_path")
            if not image_path or not os.path.isfile(image_path):
                raise LockRefreshError(
                    "lane %s rootfs image is not a file: %s"
                    % (spec.get("id"), image_path)
                )
            if not rootfs.get("url") or not rootfs.get("release"):
                raise LockRefreshError(
                    "lane %s rootfs lacks url/release" % spec.get("id")
                )
            lane["rootfs"] = {
                "bytes": os.path.getsize(image_path),
                "image": os.path.basename(image_path),
                "release": rootfs["release"],
                "sha256": sha256_file(image_path),
                "url": rootfs["url"],
            }
            deb_sources.append(
                {
                    "path": _source_name(image_path),
                    "role": "rootfs-image",
                    "sha256": lane["rootfs"]["sha256"],
                }
            )
        provisioning = spec.get("guest_provisioning")
        if provisioning is not None:
            lane["guest_provisioning"] = dict(provisioning)
        lanes.append(lane)
    limitations.append(
        "lane argv prefixes, rootfs URLs, cross-compiler strings and "
        "observed guest versions are operator-supplied, not observed"
    )
    limitations.append(
        "guest-side payloads staged into the initramfs and "
        "PATH-resolved distribution auxiliaries stay outside the "
        "host admission chain"
    )
    lock = {
        "generated_by": GENERATED_BY_BOOTSTRAP,
        "lanes": lanes,
        "license": LOCK_LICENSE,
        "notes": [
            "Bootstrap pins from tools/lock_refresh.py; reviewed "
            "promotion required before release use."
        ],
        "runner": runner,
        "schema_version": LOCK_SCHEMA_VERSION,
        "status": STATUS_BOOTSTRAP,
    }
    if distribution is not None:
        lock["distribution"] = distribution
    module_digest, module_files = (
        _dir_digest(module_root, suffix="") if module_root else ("", [])
    )
    sources = [
        {
            "path": _source_name(vng),
            "role": "vng",
            "sha256": runner["sha256"],
        },
        {
            "path": _source_name(qemu),
            "role": "qemu",
            "sha256": runner["qemu_sha256"],
        },
        {
            "path": _source_name(lanes_path),
            "role": "lanes",
            "sha256": sha256_file(lanes_path),
        },
    ]
    if virtme_run is not None:
        sources.append(
            {
                "path": _source_name(virtme_run),
                "role": "virtme-run",
                "sha256": runner["virtme_run_sha256"],
            }
        )
    if module_root is not None:
        sources.append(
            {
                "files": module_files,
                "path": _source_name(module_root),
                "role": "module-root",
                "sha256": module_digest,
            }
        )
    sources.extend(deb_sources)
    report = {
        "digests": [dict(item) for item in DIGESTS],
        "kind": "kernels",
        "limitations": limitations,
        "lock": {"schema_version": LOCK_SCHEMA_VERSION},
        "outputs": {
            "lock_sha256": hashlib.sha256(
                canonical_json_bytes(lock)
            ).hexdigest()
        },
        "closures": closures,
        "schema_version": REPORT_SCHEMA_VERSION,
        "sources": sources,
        "status": STATUS_BOOTSTRAP,
        "tool": LOCK_TOOL,
        "trust": {"note": TRUST_NOTE, "origin": STATUS_BOOTSTRAP},
    }
    return lock, report


def _load_lock(lock_path):
    try:
        with open(lock_path, encoding="utf-8") as handle:
            document = json.load(handle)
    except OSError as exc:
        return None, ["cannot read lockfile %s: %s" % (lock_path, exc)]
    except ValueError as exc:
        return None, [
            "lockfile %s is not valid JSON: %s" % (lock_path, exc)
        ]
    if not isinstance(document, dict):
        return None, ["lockfile %s is not an object" % lock_path]
    return document, []


def _resolve_tool_source(entry, repo_root):
    """Resolve one tool pin to its verifiable source bytes.

    Returns ``(role, abspath)`` or ``(role, None)`` with a note
    appended to the second element's place when the recorded
    location is malformed. A repo-relative ``binary`` anchors
    lexically under ``repo_root`` (symlinks along the way resolve
    normally: the pinned bytes are the identity, not the
    confinement); otherwise the recorded absolute
    ``realpath``/``path`` is used as-is.
    """
    binary = entry.get("binary")
    if isinstance(binary, str) and binary:
        if os.path.isabs(binary) or ".." in binary.split(os.sep):
            return (
                "binary",
                None,
                "binary %r is outside the owned lock root"
                % (binary,),
            )
        return (
            "binary",
            os.path.abspath(os.path.join(repo_root, binary)),
            None,
        )
    for key in ("realpath", "path"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            if not os.path.isabs(value):
                return (
                    key,
                    None,
                    "%s %r is not absolute" % (key, value),
                )
            return (key, os.path.abspath(value), None)
    return (
        None,
        None,
        "names no verifiable path (binary/realpath/path)",
    )


def _check_tool_identity(name, entry, repo_root, errors):
    """Bind one required tool pin to its executable bytes.

    The recorded source must exist on the qualifying machine, be
    a supported executable form, and hash to the pinned digests
    (entry plus exec chain). Appends errors, never raises.
    """
    role, source, note = _resolve_tool_source(entry, repo_root)
    if note is not None:
        errors.append("tool %s %s" % (name, note))
        return
    if not os.path.isfile(source):
        errors.append(
            "tool %s %s %r is not a file on the qualifying "
            "machine; install the pinned toolchain to verify "
            "promotion" % (name, role, source)
        )
        return
    try:
        captured = execution.capture_chain(source)
    except execution.AdmissionError as exc:
        errors.append(
            "tool %s %r cannot be captured (%s)"
            % (name, source, exc.detail)
        )
        return
    if captured.form == execution.FORM_UNKNOWN:
        errors.append(
            "tool %s %r is not a supported executable form "
            "(%s)" % (name, source, captured.note)
        )
        return
    if captured.form == execution.FORM_EXEC_LAUNCHER:
        entry_sha256 = captured.hops[0].sha256
        exec_sha256 = captured.image.sha256
    else:
        entry_sha256 = captured.image.sha256
        exec_sha256 = None
    if entry_sha256 != entry.get("sha256"):
        errors.append(
            "tool %s entry bytes do not match the pinned "
            "sha256" % name
        )
    expected_exec = entry.get("exec_sha256")
    if exec_sha256 is not None and expected_exec is None:
        errors.append(
            "tool %s is a launcher but the lock carries no exec "
            "pin" % name
        )
    elif exec_sha256 is None and expected_exec is not None:
        errors.append(
            "tool %s is its own image but the lock pins exec %s"
            % (name, expected_exec)
        )
    elif exec_sha256 != expected_exec:
        errors.append(
            "tool %s exec image bytes do not match the pinned "
            "exec_sha256" % name
        )


def verify_toolchains_lock(lock_path, repo_root):
    """Reviewed identity/source checks for a toolchains lock.

    Returns the list of errors (empty when the lock is accepted as
    ``release-approved``). The ``release-approved`` label verifies
    only with a reviewed ``generated_by`` record, the bound bytes
    beside the lock (distribution, adapter), and every required
    tool's executable bytes re-hashed against its pins on the
    qualifying machine. Bound bytes resolve under ``repo_root``,
    never through ambient PATH; required tools resolve to their
    recorded locations (repo-relative ``binary`` or absolute
    machine path).
    """
    document, errors = _load_lock(lock_path)
    if document is None:
        return errors
    if document.get("schema_version") != LOCK_SCHEMA_VERSION:
        errors.append(
            "schema_version %r is not the supported version %d"
            % (document.get("schema_version"), LOCK_SCHEMA_VERSION)
        )
    if document.get("license") != LOCK_LICENSE:
        errors.append(
            "license %r is not %r"
            % (document.get("license"), LOCK_LICENSE)
        )
    status = document.get("status")
    if status != STATUS_RELEASE:
        errors.append(
            "status %r is not release-approved: an unreviewed "
            "(draft/bootstrap) label never admits" % (status,)
        )
    generated_by = document.get("generated_by", "")
    if not isinstance(generated_by, str) or not generated_by.startswith(
        LOCK_TOOL
    ):
        errors.append(
            "generated_by %r does not name %s: an observational "
            "inventory is not reviewed pin admission"
            % (generated_by, LOCK_TOOL)
        )
    elif "(reviewed" not in generated_by:
        errors.append(
            "generated_by %r is not a reviewed record: a "
            "generated (bootstrap) label never verifies without "
            "the reviewer ceremony" % (generated_by,)
        )
    tools = document.get("tools")
    if not isinstance(tools, dict):
        errors.append("lockfile has no tools table")
        tools = {}
    for name in REQUIRED_TOOLS:
        entry = tools.get(name)
        if not isinstance(entry, dict):
            errors.append("tool %s has no pin in the lockfile" % name)
            continue
        version = entry.get("version")
        if not isinstance(version, str) or not version.strip():
            errors.append("tool %s pin lacks a version string" % name)
        if not _is_hex_digest(entry.get("sha256")):
            errors.append("tool %s pin lacks a sha256 digest" % name)
        if "exec_sha256" not in entry:
            errors.append("tool %s pin lacks the exec_sha256 key" % name)
        elif entry["exec_sha256"] is not None and not _is_hex_digest(
            entry["exec_sha256"]
        ):
            errors.append(
                "tool %s exec_sha256 is not a sha256 digest" % name
            )
        _check_tool_identity(name, entry, repo_root, errors)
    distribution = document.get("distribution")
    if not isinstance(distribution, dict):
        errors.append("lockfile has no distribution binding")
    else:
        if distribution.get("kind") != "pixi-lock":
            errors.append(
                "distribution kind %r is not pixi-lock"
                % (distribution.get("kind"),)
            )
        relpath = distribution.get("file")
        digest = distribution.get("sha256")
        if not isinstance(relpath, str) or not relpath:
            errors.append("distribution names no file")
        elif os.path.isabs(relpath) or ".." in relpath.split(os.sep):
            errors.append(
                "distribution file %r is outside the owned lock root"
                % (relpath,)
            )
        else:
            resolved = os.path.realpath(os.path.join(repo_root, relpath))
            root = os.path.realpath(repo_root)
            if os.path.commonpath([resolved, root]) != root:
                errors.append(
                    "distribution file %r escapes the owned lock root"
                    % (relpath,)
                )
            elif not os.path.isfile(resolved):
                errors.append(
                    "distribution file %r is missing beside the lock"
                    % (relpath,)
                )
            elif digest == "0" * 64:
                errors.append(
                    "distribution digest is the all-zero "
                    "placeholder; it never admits"
                )
            elif not _is_hex_digest(digest):
                errors.append("distribution sha256 is not a digest")
            elif sha256_file(resolved) != digest:
                errors.append(
                    "distribution file %r bytes do not match the "
                    "pinned sha256" % (relpath,)
                )
        if distribution.get("platform") != "linux-64":
            errors.append(
                "distribution platform %r is not linux-64"
                % (distribution.get("platform"),)
            )
    adapter = document.get("adapter")
    adapter_dir = os.path.join(
        repo_root, "src", "mojobpf", "resources", "adapter"
    )
    if not isinstance(adapter, dict):
        errors.append("lockfile has no adapter pins")
    else:
        service = adapter.get("service_sha256")
        service_path = os.path.join(adapter_dir, "adapter_service.py")
        if not os.path.isfile(service_path):
            errors.append(
                "adapter service source is missing under %s" % adapter_dir
            )
        elif service != sha256_file(service_path):
            errors.append(
                "adapter service_sha256 does not match the adapter "
                "service bytes"
            )
        siblings = adapter.get("siblings")
        if not isinstance(siblings, dict):
            errors.append("adapter pins name no siblings table")
        else:
            for sibling, digest in sorted(siblings.items()):
                sibling_path = os.path.join(adapter_dir, sibling)
                if not os.path.isfile(sibling_path):
                    errors.append(
                        "adapter sibling %s is missing" % sibling
                    )
                elif digest != sha256_file(sibling_path):
                    errors.append(
                        "adapter sibling %s sha256 does not match its "
                        "bytes" % sibling
                    )
            if os.path.isdir(adapter_dir):
                for name in sorted(os.listdir(adapter_dir)):
                    if not name.endswith(".py"):
                        continue
                    if name == "adapter_service.py":
                        continue
                    if name not in siblings:
                        errors.append(
                            "adapter file %s is not pinned" % name
                        )
    return errors


def _check_modules_table(runner, key, errors):
    table = runner.get(key)
    if table is None:
        return
    if not isinstance(table, dict):
        errors.append("runner %s is not an object" % key)
        return
    if not table.get("name"):
        errors.append("runner %s names no package" % key)
    modules = table.get("modules")
    if not isinstance(modules, dict) or not modules:
        errors.append("runner %s names no modules" % key)
        return
    for dotted, digest in sorted(modules.items()):
        if not _is_hex_digest(digest):
            errors.append(
                "runner %s module %s lacks a sha256 digest"
                % (key, dotted)
            )


def _default_virtme_cache():
    """Conventional virtme-ng runner cache on this machine."""
    return os.path.join(
        os.path.expanduser("~"), ".cache", "virtme-ng"
    )


def _check_runner_binary(binary, runner, entry_key, exec_key, errors):
    """Bind one runner binary pin to the installed executable bytes.

    ``binary`` resolves once via PATH on the qualifying machine
    (the lock intentionally pins no absolute install paths); the
    captured chain must hash to the pinned entry/exec digests.
    Returns the captured chain, or None when it was rejected.
    Appends errors, never raises.
    """
    resolved = shutil.which(binary)
    if resolved is None:
        errors.append(
            "runner %r is not on PATH: verify promotion on the "
            "qualifying machine with the pinned runner "
            "installed" % (binary,)
        )
        return None
    try:
        captured = execution.capture_chain(
            os.path.abspath(resolved)
        )
    except execution.AdmissionError as exc:
        errors.append(
            "runner %r (%s) cannot be captured (%s)"
            % (binary, resolved, exc.detail)
        )
        return None
    if captured.form == execution.FORM_UNKNOWN:
        errors.append(
            "runner %r (%s) is not a supported executable form "
            "(%s)" % (binary, resolved, captured.note)
        )
        return None
    if captured.form == execution.FORM_EXEC_LAUNCHER:
        entry_sha256 = captured.hops[0].sha256
        exec_sha256 = captured.image.sha256
    else:
        entry_sha256 = captured.image.sha256
        exec_sha256 = None
    if entry_sha256 != runner.get(entry_key):
        errors.append(
            "runner %r entry bytes do not match the pinned %s"
            % (binary, entry_key)
        )
    expected_exec = runner.get(exec_key)
    if exec_key not in runner:
        if exec_sha256 is not None:
            errors.append(
                "runner %r is a launcher but the lock carries no "
                "%s" % (binary, exec_key)
            )
    elif exec_sha256 is not None and expected_exec is None:
        errors.append(
            "runner %r is a launcher but the lock carries no "
            "exec pin" % (binary,)
        )
    elif exec_sha256 is None and expected_exec is not None:
        errors.append(
            "runner %r is its own image but the lock pins %s"
            % (binary, expected_exec)
        )
    elif exec_sha256 != expected_exec:
        errors.append(
            "runner %r exec image bytes do not match the pinned "
            "%s" % (binary, exec_key)
        )
    return captured


def _is_cache_segment(value):
    return (
        isinstance(value, str)
        and value
        and value not in (".", "..")
        and os.sep not in value
        and (os.altsep is None or os.altsep not in value)
        and ".." not in value.split(os.sep)
    )


def _check_lane_deb(lane_id, release, deb, cache_root, errors):
    """Bind one lane kernel deb pin to the cached artifact bytes."""
    filename = deb.get("file")
    if not _is_cache_segment(filename):
        errors.append(
            "lane %s deb file %r is not a cache filename"
            % (lane_id, filename)
        )
        return
    found = None
    for subdir in ("", "amd64", "arm64"):
        if subdir:
            candidate = os.path.join(
                cache_root, release, subdir, filename
            )
        else:
            candidate = os.path.join(cache_root, release, filename)
        if os.path.isfile(candidate):
            found = candidate
            break
    if found is None:
        errors.append(
            "lane %s deb %s is not in the runner cache under "
            "%s" % (lane_id, filename, cache_root)
        )
        return
    if sha256_file(found) != deb.get("sha256"):
        errors.append(
            "lane %s deb %s bytes do not match the pinned "
            "sha256" % (lane_id, filename)
        )


def _check_lane_rootfs(index, lane, cache_root, rootfs, errors):
    """Bind one arch-lane rootfs pin to the cached image bytes."""
    image = rootfs.get("image")
    if not _is_cache_segment(image):
        errors.append(
            "arch lane %d rootfs image %r is not a cache "
            "filename" % (index, image)
        )
        return
    release = lane.get("release")
    candidates = [os.path.join(cache_root, "roots", image)]
    if _is_cache_segment(release):
        for subdir in ("", "amd64", "arm64"):
            if subdir:
                candidates.append(
                    os.path.join(
                        cache_root, release, subdir, image
                    )
                )
            else:
                candidates.append(
                    os.path.join(cache_root, release, image)
                )
    found = None
    for candidate in candidates:
        if os.path.isfile(candidate):
            found = candidate
            break
    if found is None:
        errors.append(
            "arch lane %d rootfs image %s is not in the runner "
            "cache under %s" % (index, image, cache_root)
        )
        return
    if sha256_file(found) != rootfs.get("sha256"):
        errors.append(
            "arch lane %d rootfs image %s bytes do not match "
            "the pinned sha256" % (index, image)
        )
    if isinstance(rootfs.get("bytes"), int) and (
        os.path.getsize(found) != rootfs["bytes"]
    ):
        errors.append(
            "arch lane %d rootfs image %s bytes do not match "
            "the pinned size" % (index, image)
        )


def verify_kernels_lock(lock_path, cache_root=None):
    """Reviewed identity/source checks for a kernels lock.

    Returns the list of errors (empty when the lock is accepted as
    ``release-approved``). Runner and emulator pins are re-hashed
    against the installed executables (resolved once via PATH on
    the qualifying machine -- the lock intentionally pins no
    absolute install paths), and lane kernel artifacts are
    re-hashed against the runner cache (``cache_root``, default
    ``~/.cache/virtme-ng``). Third-party distribution bindings
    keep their shape checks here; admission enforces them live.
    """
    if cache_root is None:
        cache_root = _default_virtme_cache()
    document, errors = _load_lock(lock_path)
    if document is None:
        return errors
    if document.get("schema_version") != LOCK_SCHEMA_VERSION:
        errors.append(
            "schema_version %r is not the supported version %d"
            % (document.get("schema_version"), LOCK_SCHEMA_VERSION)
        )
    if document.get("license") != LOCK_LICENSE:
        errors.append(
            "license %r is not %r"
            % (document.get("license"), LOCK_LICENSE)
        )
    status = document.get("status")
    if status != STATUS_RELEASE:
        errors.append(
            "status %r is not release-approved: an unreviewed "
            "label never admits" % (status,)
        )
    generated_by = document.get("generated_by", "")
    if not isinstance(generated_by, str) or not generated_by.strip():
        errors.append("generated_by names no provenance record")
    elif "bootstrap" in generated_by.lower():
        errors.append(
            "generated_by %r is a generated bootstrap record: it "
            "never verifies without the reviewer ceremony"
            % (generated_by,)
        )
    runner = document.get("runner")
    if not isinstance(runner, dict):
        errors.append("lockfile has no runner record")
        runner = {}
    else:
        if not runner.get("name"):
            errors.append("runner names no binary")
        if not runner.get("version"):
            errors.append("runner pins no version string")
        if not _is_hex_digest(runner.get("sha256")):
            errors.append("runner entry lacks a sha256 digest")
        if not runner.get("qemu"):
            errors.append("runner pins no qemu version string")
        if not runner.get("qemu_binary"):
            errors.append("runner names no qemu binary")
        if not _is_hex_digest(runner.get("qemu_sha256")):
            errors.append(
                "runner qemu_sha256 is missing: the emulator image "
                "stays unpinned"
            )
        for key in (
            "exec_sha256",
            "qemu_exec_sha256",
            "virtme_run_exec_sha256",
        ):
            if key in runner and runner[key] is not None:
                if not _is_hex_digest(runner[key]):
                    errors.append(
                        "runner %s is not a sha256 digest" % key
                    )
        if "virtme_run_sha256" in runner and not _is_hex_digest(
            runner["virtme_run_sha256"]
        ):
            errors.append("runner virtme_run_sha256 is not a digest")
        interpreter = runner.get("interpreter")
        if interpreter is not None:
            if not isinstance(interpreter, dict) or not _is_hex_digest(
                interpreter.get("sha256")
            ):
                errors.append("runner interpreter lacks a digest")
        _check_modules_table(runner, "package", errors)
        _check_modules_table(runner, "virtme_package", errors)
        vng_captured = None
        binary = runner.get("name")
        if isinstance(binary, str) and binary:
            vng_captured = _check_runner_binary(
                binary, runner, "sha256", "exec_sha256", errors
            )
        qemu_binary = runner.get("qemu_binary")
        if isinstance(qemu_binary, str) and qemu_binary:
            _check_runner_binary(
                qemu_binary, runner, "qemu_sha256",
                "qemu_exec_sha256", errors,
            )
        if "virtme_run_sha256" in runner:
            _check_runner_binary(
                "virtme-run", runner, "virtme_run_sha256",
                "virtme_run_exec_sha256", errors,
            )
        if (
            isinstance(interpreter, dict)
            and _is_hex_digest(interpreter.get("sha256"))
            and vng_captured is not None
        ):
            if vng_captured.interpreter is None:
                errors.append(
                    "runner vng has no script interpreter but the "
                    "lock pins one"
                )
            else:
                try:
                    interpreter_sha256 = sha256_file(
                        vng_captured.interpreter
                    )
                except OSError:
                    interpreter_sha256 = None
                if interpreter_sha256 != interpreter["sha256"]:
                    errors.append(
                        "runner vng interpreter bytes do not match "
                        "the pinned sha256"
                    )
    lanes = document.get("lanes")
    if not isinstance(lanes, list) or not lanes:
        errors.append("lockfile names no lanes")
        lanes = []
    for index, lane in enumerate(lanes):
        if not isinstance(lane, dict):
            errors.append("lane %d is not an object" % index)
            continue
        for key in ("id", "release", "kernel_release", "accelerator"):
            if not lane.get(key):
                errors.append("lane %d lacks %r" % (index, key))
        debs = lane.get("kernel_debs")
        if not isinstance(debs, list) or not debs:
            errors.append("lane %d names no kernel debs" % index)
        else:
            for position, deb in enumerate(debs):
                if not isinstance(deb, dict):
                    errors.append(
                        "lane %d deb %d is not an object"
                        % (index, position)
                    )
                    continue
                if not deb.get("file"):
                    errors.append(
                        "lane %d deb %d names no file" % (index, position)
                    )
                if not _is_hex_digest(deb.get("sha256")):
                    errors.append(
                        "lane %d deb %d lacks a sha256 digest"
                        % (index, position)
                    )
                release = lane.get("release")
                if (
                    deb.get("file")
                    and _is_hex_digest(deb.get("sha256"))
                    and _is_cache_segment(release)
                ):
                    _check_lane_deb(
                        lane.get("id") or index, release, deb,
                        cache_root, errors,
                    )
        argv = lane.get("vng_argv_prefix")
        if (
            not isinstance(argv, list)
            or not argv
            or argv[0] != "vng"
            or not all(isinstance(word, str) for word in argv)
        ):
            errors.append("lane %d vng_argv_prefix is malformed" % index)
        if document.get("kind") == "arch-lane":
            for key in ("arch", "suite", "cross_compiler"):
                if not lane.get(key):
                    errors.append(
                        "arch lane %d lacks %r" % (index, key)
                    )
            rootfs = lane.get("rootfs")
            if not isinstance(rootfs, dict):
                errors.append("arch lane %d has no rootfs" % index)
            else:
                if not isinstance(rootfs.get("bytes"), int):
                    errors.append("arch lane %d rootfs lacks bytes" % index)
                for key in ("image", "release", "url"):
                    if not rootfs.get(key):
                        errors.append(
                            "arch lane %d rootfs lacks %r" % (index, key)
                        )
                if not _is_hex_digest(rootfs.get("sha256")):
                    errors.append(
                        "arch lane %d rootfs lacks a sha256 digest" % index
                    )
                elif rootfs.get("image"):
                    _check_lane_rootfs(
                        index, lane, cache_root, rootfs, errors
                    )
            provisioning = lane.get("guest_provisioning")
            if not isinstance(provisioning, dict):
                errors.append(
                    "arch lane %d has no guest_provisioning" % index
                )
            else:
                for key in (
                    "clock",
                    "network",
                    "observed_bpftool",
                    "observed_libbpf",
                ):
                    if not provisioning.get(key):
                        errors.append(
                            "arch lane %d provisioning lacks %r"
                            % (index, key)
                        )
                if not isinstance(provisioning.get("packages"), list):
                    errors.append(
                        "arch lane %d provisioning names no packages"
                        % index
                    )
    distribution = document.get("distribution")
    if document.get("kind") == "arch-lane":
        if distribution is not None:
            errors.append("arch-lane lock carries a distribution record")
    else:
        if not isinstance(distribution, dict):
            errors.append("matrix lock has no distribution binding")
        else:
            bound = distribution.get("runner")
            if not isinstance(bound, dict):
                errors.append("distribution names no runner binding")
            else:
                for key in ("kind", "package", "version", "interpreter"):
                    if not bound.get(key):
                        errors.append(
                            "distribution runner lacks %r" % key
                        )
                dependencies = bound.get("dependencies")
                if not isinstance(dependencies, list) or not dependencies:
                    errors.append(
                        "distribution runner names no dependencies"
                    )
                else:
                    for position, dependency in enumerate(dependencies):
                        if not isinstance(dependency, dict):
                            errors.append(
                                "dependency %d is not an object" % position
                            )
                            continue
                        for key in ("name", "version"):
                            if not dependency.get(key):
                                errors.append(
                                    "dependency %d lacks %r"
                                    % (position, key)
                                )
                        if not _is_hex_digest(
                            dependency.get("metadata_sha256")
                        ):
                            errors.append(
                                "dependency %d metadata lacks a digest"
                                % position
                            )
                        if not _is_hex_digest(
                            dependency.get("record_sha256")
                        ):
                            errors.append(
                                "dependency %d record lacks a digest"
                                % position
                            )
            emulator = distribution.get("emulator")
            if not isinstance(emulator, dict):
                errors.append("distribution names no emulator binding")
            else:
                if not emulator.get("kind"):
                    errors.append("distribution emulator lacks kind")
                if not emulator.get("qemu_version"):
                    errors.append(
                        "distribution emulator pins no qemu_version"
                    )
    return errors


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Deterministically regenerate bootstrap locks plus a "
            "generation report, or verify a lock's reviewed state."
        )
    )
    sub = parser.add_subparsers(dest="command", required=True)
    generate = sub.add_parser(
        "generate", help="write a bootstrap lock plus its report"
    )
    generate.add_argument(
        "--kind", choices=("toolchains", "kernels"), required=True
    )
    generate.add_argument("--inventory", default=None)
    generate.add_argument("--pixi-lock", default=None)
    generate.add_argument("--adapter-dir", default=None)
    generate.add_argument("--vng", default=None)
    generate.add_argument("--virtme-run", default=None)
    generate.add_argument("--qemu", default=None)
    generate.add_argument("--qemu-binary", default=None)
    generate.add_argument("--module-root", default=None)
    generate.add_argument("--first-party", default="")
    generate.add_argument("--extra-module", action="append", default=[])
    generate.add_argument("--runner-kind", default="uv-tool")
    generate.add_argument("--emulator-kind", default="debian-package")
    generate.add_argument("--lanes", default=None)
    generate.add_argument("--out", required=True)
    generate.add_argument("--report", required=True)
    verify = sub.add_parser(
        "verify", help="check a lock's reviewed release state"
    )
    verify.add_argument(
        "--kind", choices=("toolchains", "kernels"), required=True
    )
    verify.add_argument("--lock", required=True)
    verify.add_argument("--repo-root", default=None)
    return parser


def _run_generate(args):
    if args.kind == "toolchains":
        for key in ("inventory", "pixi_lock", "adapter_dir"):
            if getattr(args, key) is None:
                raise LockRefreshError(
                    "toolchains generation needs --%s"
                    % key.replace("_", "-")
                )
        lock, report = generate_toolchains(
            inventory=args.inventory,
            pixi_lock=args.pixi_lock,
            adapter_dir=args.adapter_dir,
        )
    else:
        for key in ("vng", "qemu", "qemu_binary", "lanes"):
            if getattr(args, key) is None:
                raise LockRefreshError(
                    "kernels generation needs --%s"
                    % key.replace("_", "-")
                )
        first_party = tuple(
            item.strip()
            for item in args.first_party.split(",")
            if item.strip()
        )
        lock, report = generate_kernels(
            vng=args.vng,
            qemu=args.qemu,
            qemu_binary=args.qemu_binary,
            lanes_path=args.lanes,
            virtme_run=args.virtme_run,
            module_root=args.module_root,
            first_party=first_party,
            extra_modules=tuple(args.extra_module),
            runner_kind=args.runner_kind,
            emulator_kind=args.emulator_kind,
        )
    try:
        write_canonical(args.out, lock)
    except OSError as exc:
        raise LockRefreshError(
            "cannot write lock %s: %s" % (args.out, exc)
        )
    try:
        write_canonical(args.report, report)
    except OSError as exc:
        raise LockRefreshError(
            "cannot write report %s: %s" % (args.report, exc)
        )
    return 0


def _run_verify(args):
    if args.kind == "toolchains":
        repo_root = args.repo_root
        if repo_root is None:
            repo_root = os.path.dirname(os.path.abspath(args.lock))
        errors = verify_toolchains_lock(args.lock, repo_root)
    else:
        errors = verify_kernels_lock(args.lock)
    if errors:
        for item in errors:
            sys.stderr.write("error: %s\n" % item)
        return 1
    sys.stdout.write("verified %s %s\n" % (args.kind, args.lock))
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not __debug__:
        sys.stderr.write(
            "REFUSED: must not run under python -O (checks stripped)\n"
        )
        return 2
    try:
        if args.command == "generate":
            return _run_generate(args)
        return _run_verify(args)
    except LockRefreshError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
