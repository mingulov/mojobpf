# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Record exact toolchain identities for BPF experiments.

Runs each probe command, captures stdout, exit codes, resolved binary paths
and SHA-256 hashes, and writes one JSON report (to stdout, or to --output).
Also records small read-only observations (libbpf linkage, UAPI headers,
kernel BTF presence, BPF sysctl, OS release).

Exit status is 0 only when every probe command was found and exited 0;
otherwise it exits 1. Missing tools are reported as missing -- versions are
never invented. A nonzero exit therefore means "inventory incomplete", not
"machine unusable"; callers decide which tools their experiment needs.
Running under ``python -O`` is refused outright with exit 2.
"""

import argparse
import datetime
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

SCHEMA_VERSION = 1
DEFAULT_TIMEOUT = 60

PROBE_COMMANDS = [
    ("mojo_version", ["mojo", "--version"]),
    ("mojo_build_help", ["mojo", "build", "--help"]),
    ("mojo_build_targets", ["mojo", "build", "--print-supported-targets"]),
    ("llvm_config_version", ["llvm-config", "--version"]),
    ("llc_version", ["llc", "--version"]),
    ("bpftool_version", ["bpftool", "version"]),
    ("uname", ["uname", "-a"]),
    ("clang_version", ["clang", "--version"]),
    ("python_version", ["python3", "--version"]),
]


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def probe_command(name, argv, timeout):
    record = {
        "name": name,
        "argv": list(argv),
        "path": None,
        "realpath": None,
        "sha256": None,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "timeout": False,
        "found": False,
        "ok": False,
    }
    path = shutil.which(argv[0])
    if path is None:
        record["stderr"] = "binary not found on PATH"
        return record
    record["path"] = path
    record["found"] = True
    try:
        record["realpath"] = os.path.realpath(path)
        record["sha256"] = sha256_file(record["realpath"])
    except OSError as exc:
        record["stderr"] = "cannot hash binary: %s" % exc
        return record
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        record["timeout"] = True
        record["stdout"] = (exc.stdout or b"").decode("utf-8", "replace")
        record["stderr"] = (exc.stderr or b"").decode("utf-8", "replace")
        return record
    record["exit_code"] = completed.returncode
    record["stdout"] = completed.stdout.decode("utf-8", "replace")
    record["stderr"] = completed.stderr.decode("utf-8", "replace")
    record["ok"] = completed.returncode == 0
    return record


def read_text_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read().strip()
    except OSError:
        return None


def observe_libbpf(bpftool_stdout):
    observation = {
        "bpftool_reported": None,
        "pkg_config_version": None,
        "runtime_objects": [],
    }
    match = re.search(r"using libbpf\s+v?([^\s]+)", bpftool_stdout or "")
    if match:
        observation["bpftool_reported"] = match.group(1)
    pkg_config = shutil.which("pkg-config")
    if pkg_config is not None:
        try:
            completed = subprocess.run(
                [pkg_config, "--modversion", "libbpf"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=DEFAULT_TIMEOUT,
            )
            if completed.returncode == 0:
                observation["pkg_config_version"] = (
                    completed.stdout.decode("utf-8", "replace").strip()
                )
        except (OSError, subprocess.TimeoutExpired):
            pass
    seen = set()
    for path in sorted(glob.glob("/usr/lib/*/libbpf.so*")):
        try:
            realpath = os.path.realpath(path)
        except OSError:
            continue
        if realpath in seen:
            continue
        seen.add(realpath)
        entry = {"path": path, "realpath": realpath, "sha256": None}
        try:
            if os.path.isfile(realpath):
                entry["sha256"] = sha256_file(realpath)
        except OSError:
            pass
        observation["runtime_objects"].append(entry)
    return observation


def observe_environment():
    header = "/usr/include/linux/bpf.h"
    header_info = {"path": header, "present": os.path.isfile(header), "sha256": None}
    if header_info["present"]:
        try:
            header_info["sha256"] = sha256_file(header)
        except OSError:
            pass
    btf = "/sys/kernel/btf/vmlinux"
    btf_info = {"path": btf, "present": os.path.isfile(btf), "size": None}
    if btf_info["present"]:
        try:
            btf_info["size"] = os.path.getsize(btf)
        except OSError:
            pass
    os_release = read_text_file("/etc/os-release") or ""
    pretty = None
    match = re.search(r'^PRETTY_NAME="([^"]+)"', os_release, re.MULTILINE)
    if match:
        pretty = match.group(1)
    return {
        "uapi_bpf_header": header_info,
        "kernel_btf": btf_info,
        "unprivileged_bpf_disabled": read_text_file(
            "/proc/sys/kernel/unprivileged_bpf_disabled"
        ),
        "os_pretty_name": pretty,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Probe toolchain identities and write a JSON report."
    )
    parser.add_argument("--output", default=None, help="Write JSON report to FILE")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    args = parser.parse_args(argv)
    if not __debug__:
        sys.stderr.write(
            "REFUSED: must not run under python -O (checks stripped)\n"
        )
        return 2

    commands = [
        probe_command(name, cmd, args.timeout) for name, cmd in PROBE_COMMANDS
    ]
    by_name = {entry["name"]: entry for entry in commands}
    report = {
        "tool": "toolchain_inventory",
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ok": all(entry["ok"] for entry in commands),
        "commands": commands,
        "observations": {
            "python": {
                "executable": sys.executable,
                "version": sys.version.splitlines()[0] if sys.version else None,
            },
            "libbpf": observe_libbpf(by_name["bpftool_version"]["stdout"]),
            "environment": observe_environment(),
        },
    }
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    missing = sorted(entry["name"] for entry in commands if not entry["ok"])
    if missing:
        sys.stderr.write("inventory incomplete: %s\n" % ", ".join(missing))
        return 1
    sys.stderr.write("inventory complete: all probe commands passed\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
