# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the deterministic lock generator (tools/lock_refresh.py).

The release and lane locks are reviewed pins, not PATH observations:
generation is deterministic (same inputs give identical bytes), every
generated lock carries the ``bootstrap`` label, and generation never
auto-promotes discovered PATH tools to ``release-approved`` pins.
Promotion happens only through reviewed identity/source checks
(:func:`verify_toolchains_lock` / :func:`verify_kernels_lock`), which
these tests pin with tamper negatives.

Deterministic on any host for the fixture cases; the committed-lock
cases assert the reviewed state of this checkout's own locks (adapter
and distribution bytes resolve beside the lock, never through PATH).

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3
tests/unit/test_lock_refresh.py``).
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

TOOL_PATH = os.path.join(REPO_ROOT, "tools", "lock_refresh.py")
RELEASE_LOCK = os.path.join(REPO_ROOT, "toolchains.lock.json")
X86_LOCK = os.path.join(REPO_ROOT, "ci", "kernels.lock.json")
ARM64_LOCK = os.path.join(REPO_ROOT, "ci", "kernels.arm64.lock.json")


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "lock_refresh", TOOL_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write(path, data, mode=0o644):
    with open(path, "wb") as handle:
        handle.write(data)
    os.chmod(path, mode)


def _write_script(path, body):
    _write(path, body.encode("utf-8"), 0o755)


def _make_inventory(workdir):
    """Fixture toolchain: launcher mojo, script llc/bpftool/python."""
    bindir = os.path.join(workdir, "bin")
    realdir = os.path.join(workdir, "real")
    os.makedirs(bindir)
    os.makedirs(realdir)
    real_mojo = os.path.join(realdir, "mojo")
    _write_script(
        real_mojo, "#!/bin/sh\necho 'Mojo 9.9.9 (fixture)'\n"
    )
    mojo = os.path.join(bindir, "mojo")
    _write_script(
        mojo,
        "#!/bin/sh\nTC=%s\nexec \"$TC/mojo\" \"$@\"\n" % realdir,
    )
    versions = {
        "mojo": "Mojo 9.9.9 (fixture)",
        "llc": "Fixture LLVM version 99.0",
        "bpftool": "bpftool v9.9.9",
        "clang": "Fixture clang version 99.0",
        "llvm-config": "99.0",
        "python": "Python 9.9.9",
    }
    for name in ("llc", "bpftool", "clang", "llvm-config", "python"):
        _write_script(
            os.path.join(bindir, name),
            "#!/bin/sh\necho '%s'\n" % versions[name],
        )
    probes = {
        "mojo": "mojo_version",
        "llc": "llc_version",
        "bpftool": "bpftool_version",
        "clang": "clang_version",
        "llvm-config": "llvm_config_version",
        "python": "python_version",
    }
    commands = []
    for tool, record in sorted(probes.items()):
        path = os.path.join(bindir, tool)
        commands.append(
            {
                "name": record,
                "argv": [tool, "--version"
                         if tool != "bpftool" else "version"],
                "path": path,
                "realpath": os.path.realpath(path),
                "sha256": _sha256_file(os.path.realpath(path)),
                "exit_code": 0,
                "stdout": versions[tool] + "\n",
                "stderr": "",
                "timeout": False,
                "found": True,
                "ok": True,
            }
        )
    header = os.path.join(workdir, "bpf.h")
    _write(header, b"/* fixture UAPI header */\n")
    libbpf = os.path.join(workdir, "libbpf.so.1")
    _write(libbpf, b"fixture libbpf bytes\n")
    inventory = {
        "tool": "toolchain_inventory",
        "schema_version": 1,
        "generated_at": "2026-10-10T00:00:00+00:00",
        "ok": True,
        "commands": commands,
        "observations": {
            "python": {
                "executable": os.path.join(bindir, "python"),
                "version": "Python 9.9.9",
            },
            "libbpf": {
                "bpftool_reported": "9.9",
                "pkg_config_version": None,
                "runtime_objects": [
                    {
                        "path": libbpf,
                        "realpath": os.path.realpath(libbpf),
                        "sha256": _sha256_file(libbpf),
                    }
                ],
            },
            "environment": {
                "uapi_bpf_header": {
                    "path": header,
                    "present": True,
                    "sha256": _sha256_file(header),
                },
            },
        },
    }
    inventory_path = os.path.join(workdir, "inventory.json")
    with open(inventory_path, "w", encoding="utf-8") as handle:
        json.dump(inventory, handle, indent=2, sort_keys=True)
        handle.write("\n")
    pixi_lock = os.path.join(workdir, "pixi.lock")
    _write(pixi_lock, b"fixture pixi lock bytes\n")
    adapter_dir = os.path.join(workdir, "adapter")
    os.makedirs(adapter_dir)
    _write(
        os.path.join(adapter_dir, "adapter_service.py"),
        b"# fixture adapter service\n",
    )
    _write(
        os.path.join(adapter_dir, "audit.py"), b"# fixture audit\n"
    )
    _write(
        os.path.join(adapter_dir, "mojo_ir_adapter.py"),
        b"# fixture adapter\n",
    )
    return {
        "bindir": bindir,
        "realdir": realdir,
        "versions": versions,
        "inventory": inventory_path,
        "pixi_lock": pixi_lock,
        "adapter_dir": adapter_dir,
    }


def _sha256_file(path):
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _make_runner(workdir):
    """Fixture kernels inputs: vng console script, qemu, debs, venv."""
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    vng = os.path.join(bindir, "vng")
    _write_script(
        vng,
        "#!%s\nimport sys\nprint('virtme-ng 9.9')\n"
        % sys.executable,
    )
    virtme_run = os.path.join(bindir, "virtme-run")
    _write_script(
        virtme_run,
        "#!%s\nimport sys\nprint('virtme-run fixture')\n"
        % sys.executable,
    )
    qemu = os.path.join(bindir, "qemu-system-x86_64")
    _write_script(
        qemu, "#!/bin/sh\necho 'QEMU emulator version 9.9 (fixture)'\n"
    )
    site = os.path.join(workdir, "site")
    for package in ("virtme_ng", "virtme"):
        os.makedirs(os.path.join(site, package))
        _write(
            os.path.join(site, package, "__init__.py"),
            ("# fixture %s\n" % package).encode("utf-8"),
        )
    _write(
        os.path.join(site, "virtme_ng", "run.py"),
        b"# fixture runner implementation\n",
    )
    _write(
        os.path.join(site, "_virtualenv.py"), b"# fixture shim\n"
    )
    dist_info = os.path.join(site, "fixturedep-1.0.dist-info")
    os.makedirs(dist_info)
    _write(
        os.path.join(dist_info, "METADATA"),
        b"Metadata-Version: 2.1\nName: fixturedep\nVersion: 1.0\n",
    )
    _write(
        os.path.join(dist_info, "RECORD"),
        b"fixturedep/__init__.py,,\n",
    )
    first_info = os.path.join(site, "virtme_ng-9.9.dist-info")
    os.makedirs(first_info)
    _write(
        os.path.join(first_info, "METADATA"),
        b"Metadata-Version: 2.1\nName: virtme-ng\nVersion: 9.9\n",
    )
    _write(
        os.path.join(first_info, "RECORD"),
        b"virtme_ng/__init__.py,,\nvirtme_ng/run.py,,\n",
    )
    debs = []
    for name in ("fixture-image.deb", "fixture-modules.deb"):
        path = os.path.join(workdir, name)
        _write(path, ("fixture %s\n" % name).encode("utf-8"))
        debs.append(path)
    lanes_path = os.path.join(workdir, "lanes.json")
    with open(lanes_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "lanes": [
                    {
                        "id": "v9.9-tcg",
                        "release": "v9.9",
                        "kernel_release": "9.9.0-fixture",
                        "accelerator": "tcg",
                        "debs": debs,
                        "vng_argv_prefix": [
                            "vng", "--run", "v9.9", "--disable-kvm",
                        ],
                    }
                ]
            },
            handle,
            indent=2,
            sort_keys=True,
        )
        handle.write("\n")
    return {
        "vng": vng,
        "virtme_run": virtme_run,
        "qemu": qemu,
        "site": site,
        "debs": debs,
        "lanes": lanes_path,
    }


def _generate_toolchains(tool, workdir, override=None):
    fix = _make_inventory(workdir)
    out = os.path.join(workdir, "toolchains.lock.json")
    report = os.path.join(workdir, "report.json")
    argv = [
        "generate",
        "--kind", "toolchains",
        "--inventory", fix["inventory"],
        "--pixi-lock", fix["pixi_lock"],
        "--adapter-dir", fix["adapter_dir"],
        "--out", out,
        "--report", report,
    ]
    if override:
        argv = override(argv, fix)
    code = tool.main(argv)
    assert code == 0, code
    with open(out, encoding="utf-8") as handle:
        lock = json.load(handle)
    with open(report, encoding="utf-8") as handle:
        document = json.load(handle)
    return fix, lock, document, out, report


def test_toolchains_generate_records_pins_and_report():
    tool = _load_tool()
    workdir = tempfile.mkdtemp(prefix="lock-refresh-toolchains-")
    try:
        fix, lock, document, _out, _report = _generate_toolchains(
            tool, workdir
        )
        assert lock["schema_version"] == 1
        assert lock["license"] == "Apache-2.0 WITH LLVM-exception"
        assert lock["status"] == "bootstrap"
        assert lock["generated_by"] == (
            "tools/lock_refresh.py (bootstrap)"
        )
        assert set(lock["tools"]) == {
            "mojo", "llc", "bpftool", "clang",
            "llvm-config", "python", "libbpf", "uapi_bpf_header",
        }
        mojo = lock["tools"]["mojo"]
        assert mojo["version"] == "Mojo 9.9.9 (fixture)"
        assert mojo["sha256"] == _sha256_file(
            os.path.join(fix["bindir"], "mojo")
        )
        assert mojo["exec_sha256"] == _sha256_file(
            os.path.join(fix["realdir"], "mojo")
        )
        llc = lock["tools"]["llc"]
        assert llc["version"] == "Fixture LLVM version 99.0"
        assert llc["exec_sha256"] is None
        for name in ("mojo", "llc", "bpftool", "python"):
            entry = lock["tools"][name]
            assert entry["status"] == "present", name
            assert "exec_sha256" in entry, name
        assert lock["distribution"]["file"] == "pixi.lock"
        assert lock["distribution"]["sha256"] == _sha256_file(
            fix["pixi_lock"]
        )
        assert lock["adapter"]["service_sha256"] == _sha256_file(
            os.path.join(fix["adapter_dir"], "adapter_service.py")
        )
        assert set(lock["adapter"]["siblings"]) == {
            "audit.py", "mojo_ir_adapter.py"
        }
        assert "vm" not in lock
        assert document["tool"] == "tools/lock_refresh.py"
        assert document["kind"] == "toolchains"
        assert document["status"] == "bootstrap"
        roles = {item["role"] for item in document["sources"]}
        assert {
            "inventory", "pixi-lock", "adapter-dir",
        } <= roles, roles
        for item in document["sources"]:
            assert len(item["sha256"]) == 64, item
        assert document["digests"] == [
            {"subject": "file bytes", "type": "sha256"},
            {"subject": "first version line", "type": "verbatim"},
        ]
        assert document["closures"]["mojo"]["exec_sha256"] == (
            mojo["exec_sha256"]
        )
        assert document["trust"]["origin"] == "bootstrap"
        assert "release-approved" in document["trust"]["note"]
        assert any(
            "vm" in item for item in document["limitations"]
        )
        with open(
            os.path.join(workdir, "toolchains.lock.json"), "rb"
        ) as handle:
            raw = handle.read()
        import hashlib

        assert document["outputs"]["lock_sha256"] == (
            hashlib.sha256(raw).hexdigest()
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_toolchains_generate_is_deterministic():
    tool = _load_tool()
    workdir = tempfile.mkdtemp(prefix="lock-refresh-determinism-")
    try:
        first = os.path.join(workdir, "run-a")
        second = os.path.join(workdir, "run-b")
        os.makedirs(first)
        os.makedirs(second)
        fix = _make_inventory(first)
        # Identical input bytes at a distinct location.
        shutil.copyfile(
            fix["inventory"], os.path.join(second, "inventory.json")
        )
        shutil.copyfile(
            fix["pixi_lock"], os.path.join(second, "pixi.lock")
        )
        shutil.copytree(
            fix["adapter_dir"], os.path.join(second, "adapter")
        )
        blobs = []
        for inputs in (
            (fix["inventory"], fix["pixi_lock"], fix["adapter_dir"]),
            (
                os.path.join(second, "inventory.json"),
                os.path.join(second, "pixi.lock"),
                os.path.join(second, "adapter"),
            ),
        ):
            tag = "a" if blobs == [] else "b"
            out = os.path.join(workdir, "lock-%s.json" % tag)
            report = os.path.join(workdir, "report-%s.json" % tag)
            code = tool.main(
                [
                    "generate",
                    "--kind", "toolchains",
                    "--inventory", inputs[0],
                    "--pixi-lock", inputs[1],
                    "--adapter-dir", inputs[2],
                    "--out", out,
                    "--report", report,
                ]
            )
            assert code == 0
            with open(out, "rb") as handle:
                lock_bytes = handle.read()
            with open(report, "rb") as handle:
                report_bytes = handle.read()
            assert b"generated_at" not in report_bytes
            blobs.append((lock_bytes, report_bytes))
        assert blobs[0][0] == blobs[1][0], "lock bytes vary by input dir"
        assert blobs[0][1] == blobs[1][1], (
            "report bytes embed the input location"
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_kernels_generate_is_deterministic_across_dirs():
    tool = _load_tool()
    workdir = tempfile.mkdtemp(prefix="lock-refresh-kdet-")
    try:
        first = os.path.join(workdir, "run-a")
        second = os.path.join(workdir, "run-b")
        os.makedirs(first)
        os.makedirs(second)
        fix = _make_runner(first)
        # Identical input bytes at a distinct location.
        shutil.copytree(
            os.path.join(first, "bin"), os.path.join(second, "bin")
        )
        shutil.copytree(
            fix["site"], os.path.join(second, "site")
        )
        for deb in fix["debs"]:
            shutil.copyfile(
                deb,
                os.path.join(second, os.path.basename(deb)),
            )
        shutil.copyfile(
            fix["lanes"], os.path.join(second, "lanes.json")
        )
        blobs = []
        for root in (first, second):
            out = os.path.join(
                workdir, "kernels-%s.lock.json" % root[-1]
            )
            report = os.path.join(
                workdir, "kernels-%s.report.json" % root[-1]
            )
            code = tool.main(
                [
                    "generate",
                    "--kind", "kernels",
                    "--vng", os.path.join(root, "bin", "vng"),
                    "--virtme-run",
                    os.path.join(root, "bin", "virtme-run"),
                    "--qemu",
                    os.path.join(
                        root, "bin", "qemu-system-x86_64"
                    ),
                    "--qemu-binary", "qemu-system-x86_64",
                    "--module-root",
                    os.path.join(root, "site"),
                    "--first-party", "virtme_ng,virtme",
                    "--extra-module", "_virtualenv",
                    "--lanes", os.path.join(root, "lanes.json"),
                    "--out", out,
                    "--report", report,
                ]
            )
            assert code == 0
            with open(out, "rb") as handle:
                lock_bytes = handle.read()
            with open(report, "rb") as handle:
                report_bytes = handle.read()
            blobs.append((lock_bytes, report_bytes))
        assert blobs[0][0] == blobs[1][0], "lock bytes vary by input dir"
        assert blobs[0][1] == blobs[1][1], (
            "report bytes embed the input location"
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_module_digest_ignores_generated_caches():
    tool = _load_tool()
    workdir = tempfile.mkdtemp(prefix="lock-refresh-cache-")
    try:
        fix = _make_runner(workdir)
        base = [
            "generate",
            "--kind", "kernels",
            "--vng", fix["vng"],
            "--virtme-run", fix["virtme_run"],
            "--qemu", fix["qemu"],
            "--qemu-binary", "qemu-system-x86_64",
            "--module-root", fix["site"],
            "--first-party", "virtme_ng,virtme",
            "--extra-module", "_virtualenv",
            "--lanes", fix["lanes"],
        ]
        out = os.path.join(workdir, "kernels.lock.json")
        report = os.path.join(workdir, "report.json")
        assert tool.main(base + ["--out", out, "--report", report]) == 0
        with open(out, "rb") as handle:
            lock_bytes = handle.read()
        with open(report, "rb") as handle:
            report_bytes = handle.read()
        # Generated bytecode caches land after the first read.
        cachedir = os.path.join(
            fix["site"], "virtme_ng", "__pycache__"
        )
        os.makedirs(cachedir)
        with open(
            os.path.join(cachedir, "run.cpython-313.pyc"), "wb"
        ) as handle:
            handle.write(b"junk bytecode\n")
        with open(
            os.path.join(fix["site"], "stray.pyc"), "wb"
        ) as handle:
            handle.write(b"more junk\n")
        out2 = os.path.join(workdir, "kernels-2.lock.json")
        report2 = os.path.join(workdir, "report-2.json")
        assert (
            tool.main(base + ["--out", out2, "--report", report2])
            == 0
        )
        with open(out2, "rb") as handle:
            assert handle.read() == lock_bytes
        with open(report2, "rb") as handle:
            assert handle.read() == report_bytes, (
                "generated caches feed the module digest"
            )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_toolchains_generate_never_promotes_to_release():
    tool = _load_tool()
    workdir = tempfile.mkdtemp(prefix="lock-refresh-nopromote-")
    try:
        _fix, lock, document, out, _report = _generate_toolchains(
            tool, workdir
        )
        assert lock["status"] == "bootstrap"
        assert lock["status"] != "release-approved"
        assert document["trust"]["origin"] == "bootstrap"
        errors = tool.verify_toolchains_lock(out, workdir)
        assert errors, "generated lock must fail reviewed verification"
        assert any("bootstrap" in item for item in errors), errors
        with open(RELEASE_LOCK, encoding="utf-8") as handle:
            released = json.load(handle)
        missing = _missing_tool_source_paths(released, REPO_ROOT)
        errors = tool.verify_toolchains_lock(RELEASE_LOCK, REPO_ROOT)
        if missing:
            assert errors, "expected availability errors, got none"
            assert all(
                "is not a file on the qualifying machine" in item
                for item in errors
            ), (missing, errors)
        else:
            assert errors == [], errors
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_toolchains_generate_refuses_to_invent_versions():
    tool = _load_tool()
    workdir = tempfile.mkdtemp(prefix="lock-refresh-noinvent-")
    try:
        fix = _make_inventory(workdir)
        with open(fix["inventory"], encoding="utf-8") as handle:
            inventory = json.load(handle)
        for entry in inventory["commands"]:
            if entry["name"] == "mojo_version":
                entry["ok"] = False
                entry["exit_code"] = 1
                entry["stdout"] = ""
                entry["stderr"] = "binary not found on PATH"
        broken = os.path.join(workdir, "broken-inventory.json")
        with open(broken, "w", encoding="utf-8") as handle:
            json.dump(inventory, handle, indent=2, sort_keys=True)
        out = os.path.join(workdir, "toolchains.lock.json")
        report = os.path.join(workdir, "report.json")
        try:
            tool.generate_toolchains(
                inventory=broken,
                pixi_lock=fix["pixi_lock"],
                adapter_dir=fix["adapter_dir"],
            )
        except tool.LockRefreshError as exc:
            assert "mojo" in str(exc), exc
        else:
            raise AssertionError("missing required probe invented")
        assert not os.path.exists(out)
        assert not os.path.exists(report)
        code = tool.main(
            [
                "generate",
                "--kind", "toolchains",
                "--inventory", os.path.join(workdir, "absent.json"),
                "--pixi-lock", fix["pixi_lock"],
                "--adapter-dir", fix["adapter_dir"],
                "--out", out,
                "--report", report,
            ]
        )
        assert code == 2
        assert not os.path.exists(out)
        assert not os.path.exists(report)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _generate_kernels(tool, workdir):
    fix = _make_runner(workdir)
    out = os.path.join(workdir, "kernels.lock.json")
    report = os.path.join(workdir, "report.json")
    code = tool.main(
        [
            "generate",
            "--kind", "kernels",
            "--vng", fix["vng"],
            "--virtme-run", fix["virtme_run"],
            "--qemu", fix["qemu"],
            "--qemu-binary", "qemu-system-x86_64",
            "--module-root", fix["site"],
            "--first-party", "virtme_ng,virtme",
            "--extra-module", "_virtualenv",
            "--lanes", fix["lanes"],
            "--out", out,
            "--report", report,
        ]
    )
    assert code == 0, code
    with open(out, encoding="utf-8") as handle:
        lock = json.load(handle)
    with open(report, encoding="utf-8") as handle:
        document = json.load(handle)
    return fix, lock, document, out, report


def test_kernels_generate_records_runner_lanes_and_report():
    tool = _load_tool()
    workdir = tempfile.mkdtemp(prefix="lock-refresh-kernels-")
    try:
        fix, lock, document, out, report = _generate_kernels(
            tool, workdir
        )
        assert lock["schema_version"] == 1
        assert lock["license"] == "Apache-2.0 WITH LLVM-exception"
        assert lock["status"] == "bootstrap"
        assert lock["generated_by"] == (
            "tools/lock_refresh.py (bootstrap)"
        )
        runner = lock["runner"]
        assert runner["name"] == "vng"
        assert runner["version"] == "virtme-ng 9.9"
        assert runner["sha256"] == _sha256_file(fix["vng"])
        assert runner["qemu"] == "QEMU emulator version 9.9 (fixture)"
        assert runner["qemu_binary"] == "qemu-system-x86_64"
        assert runner["qemu_sha256"] == _sha256_file(fix["qemu"])
        assert runner["virtme_run_sha256"] == _sha256_file(
            fix["virtme_run"]
        )
        assert runner["interpreter"]["sha256"] == _sha256_file(
            os.path.realpath(sys.executable)
        )
        assert set(runner["package"]["modules"]) == {
            "_virtualenv",
            "virtme_ng",
            "virtme_ng.run",
        }
        assert set(runner["virtme_package"]["modules"]) == {"virtme"}
        (dependency,) = lock["distribution"]["runner"][
            "dependencies"
        ]
        assert dependency["name"] == "fixturedep"
        assert dependency["version"] == "1.0"
        assert lock["distribution"]["emulator"]["qemu_version"] == (
            "QEMU emulator version 9.9 (fixture)"
        )
        (lane,) = lock["lanes"]
        assert lane["id"] == "v9.9-tcg"
        assert [deb["file"] for deb in lane["kernel_debs"]] == [
            "fixture-image.deb", "fixture-modules.deb",
        ]
        assert lane["kernel_debs"][0]["sha256"] == _sha256_file(
            fix["debs"][0]
        )
        assert lane["vng_argv_prefix"] == [
            "vng", "--run", "v9.9", "--disable-kvm",
        ]
        assert document["kind"] == "kernels"
        assert document["trust"]["origin"] == "bootstrap"
        roles = {item["role"] for item in document["sources"]}
        assert {
            "vng", "virtme-run", "qemu", "module-root",
            "kernel-deb", "lanes",
        } <= roles, roles
        assert document["closures"]["vng"]["entry_sha256"] == (
            runner["sha256"]
        )
        second = os.path.join(workdir, "kernels-2.lock.json")
        report2 = os.path.join(workdir, "report-2.json")
        code = tool.main(
            [
                "generate",
                "--kind", "kernels",
                "--vng", fix["vng"],
                "--virtme-run", fix["virtme_run"],
                "--qemu", fix["qemu"],
                "--qemu-binary", "qemu-system-x86_64",
                "--module-root", fix["site"],
                "--first-party", "virtme_ng,virtme",
                "--extra-module", "_virtualenv",
                "--lanes", fix["lanes"],
                "--out", second,
                "--report", report2,
            ]
        )
        assert code == 0
        with open(out, "rb") as handle:
            first_bytes = handle.read()
        with open(second, "rb") as handle:
            assert handle.read() == first_bytes
        with open(report, "rb") as handle:
            first_report = handle.read()
        with open(report2, "rb") as handle:
            assert handle.read() == first_report
        errors = tool.verify_kernels_lock(out)
        assert errors, "generated lock must fail reviewed verification"
        assert any("bootstrap" in item for item in errors), errors
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _mutated_lock_copy(path, mutate):
    workdir = tempfile.mkdtemp(prefix="lock-refresh-tamper-")
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    mutate(document)
    copy_path = os.path.join(workdir, os.path.basename(path))
    with open(copy_path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return workdir, copy_path


def test_verify_release_rejects_unreviewed_labels():
    tool = _load_tool()

    def _draft(document):
        document["status"] = "draft"

    workdir, copy_path = _mutated_lock_copy(RELEASE_LOCK, _draft)
    try:
        errors = tool.verify_toolchains_lock(copy_path, REPO_ROOT)
        assert errors, "draft label accepted as reviewed"
        assert any("draft" in item for item in errors), errors
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    def _bootstrap(document):
        document["status"] = "bootstrap"

    workdir, copy_path = _mutated_lock_copy(RELEASE_LOCK, _bootstrap)
    try:
        errors = tool.verify_toolchains_lock(copy_path, REPO_ROOT)
        assert errors, "bootstrap label accepted as reviewed"
        assert any("bootstrap" in item for item in errors), errors
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    def _observational(document):
        document["generated_by"] = (
            "tests/probes/toolchain_inventory.py"
        )

    workdir, copy_path = _mutated_lock_copy(RELEASE_LOCK, _observational)
    try:
        errors = tool.verify_toolchains_lock(copy_path, REPO_ROOT)
        assert errors, "observational inventory accepted as admission"
        assert any("inventory" in item for item in errors), errors
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_verify_release_checks_bound_bytes():
    tool = _load_tool()

    def _zero_distribution(document):
        document["distribution"]["sha256"] = "0" * 64

    workdir, copy_path = _mutated_lock_copy(
        RELEASE_LOCK, _zero_distribution
    )
    try:
        errors = tool.verify_toolchains_lock(copy_path, REPO_ROOT)
        assert errors, "all-zero distribution digest accepted"
        assert any("zero" in item for item in errors), errors
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    def _wrong_distribution(document):
        document["distribution"]["sha256"] = "1" * 64

    workdir, copy_path = _mutated_lock_copy(
        RELEASE_LOCK, _wrong_distribution
    )
    try:
        errors = tool.verify_toolchains_lock(copy_path, REPO_ROOT)
        assert errors, "distribution byte mismatch accepted"
        assert any(
            "distribution" in item for item in errors
        ), errors
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    def _outside_distribution(document):
        document["distribution"]["file"] = "/tmp/elsewhere.lock"

    workdir, copy_path = _mutated_lock_copy(
        RELEASE_LOCK, _outside_distribution
    )
    try:
        errors = tool.verify_toolchains_lock(copy_path, REPO_ROOT)
        assert errors, "out-of-root distribution accepted"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    def _wrong_adapter(document):
        document["adapter"]["siblings"]["audit.py"] = "2" * 64

    workdir, copy_path = _mutated_lock_copy(RELEASE_LOCK, _wrong_adapter)
    try:
        errors = tool.verify_toolchains_lock(copy_path, REPO_ROOT)
        assert errors, "adapter byte mismatch accepted"
        assert any("adapter" in item for item in errors), errors
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_verify_release_checks_pin_shapes():
    tool = _load_tool()
    cases = []

    def _missing_version(document):
        del document["tools"]["mojo"]["version"]

    cases.append((_missing_version, "mojo"))

    def _bad_sha(document):
        document["tools"]["llc"]["sha256"] = "not-a-digest"

    cases.append((_bad_sha, "llc"))

    def _missing_exec_key(document):
        del document["tools"]["bpftool"]["exec_sha256"]

    cases.append((_missing_exec_key, "bpftool"))

    def _bad_schema(document):
        document["schema_version"] = 2

    cases.append((_bad_schema, "schema"))

    def _bad_license(document):
        document["license"] = "MIT"

    cases.append((_bad_license, "license"))
    for mutate, marker in cases:
        workdir, copy_path = _mutated_lock_copy(RELEASE_LOCK, mutate)
        try:
            errors = tool.verify_toolchains_lock(copy_path, REPO_ROOT)
            assert errors, "malformed lock accepted: %s" % marker
            assert any(
                marker in item for item in errors
            ), (marker, errors)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


def test_verify_kernels_accepts_committed_locks():
    tool = _load_tool()
    cache_root = _default_cache_root()
    for lock_path in (X86_LOCK, ARM64_LOCK):
        with open(lock_path, encoding="utf-8") as handle:
            lock = json.load(handle)
        missing = _missing_kernel_sources(lock, cache_root)
        errors = tool.verify_kernels_lock(lock_path)
        _assert_machine_scoped_verify(errors, missing)
    with open(X86_LOCK, encoding="utf-8") as handle:
        x86 = json.load(handle)
    with open(ARM64_LOCK, encoding="utf-8") as handle:
        arm64 = json.load(handle)
    assert x86["status"] == "release-approved"
    assert arm64["status"] == "release-approved"
    assert len(arm64["runner"]["qemu_sha256"]) == 64


def test_verify_kernels_rejects_tampered_locks():
    tool = _load_tool()

    def _no_status(document):
        del document["status"]

    workdir, copy_path = _mutated_lock_copy(X86_LOCK, _no_status)
    try:
        errors = tool.verify_kernels_lock(copy_path)
        assert errors, "unreviewed kernels lock accepted"
        assert any("status" in item for item in errors), errors
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    def _bad_deb(document):
        document["lanes"][0]["kernel_debs"][0]["sha256"] = "xyz"

    workdir, copy_path = _mutated_lock_copy(X86_LOCK, _bad_deb)
    try:
        errors = tool.verify_kernels_lock(copy_path)
        assert errors, "malformed deb pin accepted"
        assert any("sha256" in item for item in errors), errors
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    def _no_qemu_sha(document):
        del document["runner"]["qemu_sha256"]

    workdir, copy_path = _mutated_lock_copy(ARM64_LOCK, _no_qemu_sha)
    try:
        errors = tool.verify_kernels_lock(copy_path)
        assert errors, "unpinned emulator accepted"
        assert any("qemu" in item for item in errors), errors
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    def _bad_record(document):
        document["distribution"]["runner"]["dependencies"][0][
            "record_sha256"
        ] = "0" * 63

    workdir, copy_path = _mutated_lock_copy(X86_LOCK, _bad_record)
    try:
        errors = tool.verify_kernels_lock(copy_path)
        assert errors, "malformed RECORD binding accepted"
        assert any("record" in item for item in errors), errors
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_required_tools_match_driver():
    tool = _load_tool()
    from mojobpf import toolchain

    assert tool.REQUIRED_TOOLS == tuple(toolchain.REQUIRED_TOOLS)


def test_verify_command_exits():
    tool = _load_tool()
    workdir = tempfile.mkdtemp(prefix="lock-refresh-cli-")
    try:
        fix = _make_inventory(workdir)
        lock, _report = tool.generate_toolchains(
            inventory=fix["inventory"],
            pixi_lock=fix["pixi_lock"],
            adapter_dir=fix["adapter_dir"],
        )
        _review_toolchains_lock(lock)
        reviewed = os.path.join(workdir, "reviewed.lock.json")
        _write_json(reviewed, lock)
        root = _fixture_repo_root(workdir, fix)
        proc = subprocess.run(
            [
                sys.executable, TOOL_PATH,
                "verify", "--kind", "toolchains",
                "--lock", reviewed, "--repo-root", root,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        assert "verified" in proc.stdout
        lock["status"] = "draft"
        draft = os.path.join(workdir, "draft.lock.json")
        _write_json(draft, lock)
        proc = subprocess.run(
            [
                sys.executable, TOOL_PATH,
                "verify", "--kind", "toolchains",
                "--lock", draft, "--repo-root", root,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
        assert proc.returncode == 1, proc.stdout
        assert "draft" in proc.stderr
        kdir = os.path.join(workdir, "kernels")
        os.makedirs(kdir)
        runner, klock, _doc, _out, _rep = _generate_kernels(
            tool, kdir
        )
        _review_kernels_lock(klock)
        kreviewed = os.path.join(kdir, "reviewed.lock.json")
        _write_json(kreviewed, klock)
        home = os.path.join(kdir, "home")
        cache = os.path.join(
            home, ".cache", "virtme-ng", "v9.9", "amd64"
        )
        os.makedirs(cache)
        for deb in runner["debs"]:
            shutil.copyfile(
                deb, os.path.join(cache, os.path.basename(deb))
            )
        env = dict(os.environ)
        env["PATH"] = os.path.join(kdir, "bin") + os.pathsep + env.get(
            "PATH", ""
        )
        env["HOME"] = home
        proc = subprocess.run(
            [
                sys.executable, TOOL_PATH,
                "verify", "--kind", "kernels",
                "--lock", kreviewed,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            env=env,
        )
        assert proc.returncode == 0, proc.stderr
        assert "verified" in proc.stdout
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _review_toolchains_lock(lock):
    """Apply the reviewer ceremony labels to a generated lock."""
    lock["status"] = "release-approved"
    lock["generated_by"] = (
        "tools/lock_refresh.py (reviewed; test ceremony)"
    )
    return lock


def _review_kernels_lock(lock):
    """Apply the reviewer ceremony labels to a generated lock."""
    lock["status"] = "release-approved"
    lock["generated_by"] = (
        "recorded by hand from the qualifying host (reviewed)"
    )
    return lock


def _write_json(path, document):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _fixture_repo_root(workdir, fix):
    """Repo root carrying the fixture's bound bytes (adapter+pixi)."""
    root = os.path.join(workdir, "root")
    adapter_dest = os.path.join(
        root, "src", "mojobpf", "resources", "adapter"
    )
    os.makedirs(adapter_dest)
    for name in os.listdir(fix["adapter_dir"]):
        shutil.copyfile(
            os.path.join(fix["adapter_dir"], name),
            os.path.join(adapter_dest, name),
        )
    shutil.copyfile(
        fix["pixi_lock"], os.path.join(root, "pixi.lock")
    )
    return root


class _PatchedEnv:
    """Temporarily override PATH/HOME, restoring both afterwards."""

    def __init__(self, path=None, home=None):
        self.path = path
        self.home = home
        self.saved = {}

    def __enter__(self):
        for key, value in (
            ("PATH", self.path), ("HOME", self.home),
        ):
            if value is None:
                continue
            self.saved[key] = os.environ.get(key)
            os.environ[key] = value
        return self

    def __exit__(self, *exc):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return False


def _missing_tool_source_paths(lock, repo_root):
    """Recorded tool sources absent on this machine (test helper).

    Mirrors the tool's resolution rule (repo-relative ``binary``
    under ``repo_root``, else the recorded absolute path) so the
    committed-lock tests can tell a machine without the pinned
    toolchain (availability-only errors) from a real mismatch.
    """
    missing = []
    tools = lock.get("tools", {})
    for name in ("mojo", "llc", "bpftool", "python"):
        entry = tools.get(name)
        if not isinstance(entry, dict):
            missing.append("%s:<no pin>" % name)
            continue
        binary = entry.get("binary")
        if isinstance(binary, str) and binary:
            candidate = os.path.join(repo_root, binary)
        else:
            candidate = entry.get("realpath") or entry.get("path")
        if not candidate or not os.path.isfile(candidate):
            missing.append("%s:%s" % (name, candidate))
    return missing


def _missing_kernel_sources(lock, cache_root):
    """Pinned kernel sources absent on this machine (test helper).

    Mirrors the tool's lookup (runner binaries via PATH, lane
    artifacts under the runner cache) so the committed-lock tests
    can tell a machine without the pinned runner/cache
    (availability-only errors) from a real mismatch.
    """
    missing = []
    runner = lock.get("runner", {})
    if not isinstance(runner, dict):
        return ["runner:<no record>"]
    for binary in (runner.get("name"), runner.get("qemu_binary")):
        if binary and shutil.which(binary) is None:
            missing.append("PATH:%s" % binary)
    if "virtme_run_sha256" in runner and (
        shutil.which("virtme-run") is None
    ):
        missing.append("PATH:virtme-run")
    lanes = lock.get("lanes", [])
    if not isinstance(lanes, list):
        return missing + ["lanes:<malformed>"]
    for lane in lanes:
        if not isinstance(lane, dict):
            continue
        release = lane.get("release")
        for deb in lane.get("kernel_debs", []) or []:
            filename = (
                deb.get("file") if isinstance(deb, dict) else None
            )
            found = False
            if release and filename:
                for subdir in ("", "amd64", "arm64"):
                    parts = [cache_root, release]
                    if subdir:
                        parts.append(subdir)
                    parts.append(filename)
                    if os.path.isfile(os.path.join(*parts)):
                        found = True
                        break
            if not found:
                missing.append(
                    "cache:%s/%s" % (release, filename)
                )
        rootfs = lane.get("rootfs")
        if isinstance(rootfs, dict):
            image = rootfs.get("image")
            found = image and os.path.isfile(
                os.path.join(cache_root, "roots", image)
            )
            if not found and image and release:
                for subdir in ("", "amd64", "arm64"):
                    parts = [cache_root, release]
                    if subdir:
                        parts.append(subdir)
                    parts.append(image)
                    if os.path.isfile(os.path.join(*parts)):
                        found = True
                        break
            if not found:
                missing.append("cache:roots/%s" % image)
    return missing


def _default_cache_root():
    return os.path.join(
        os.path.expanduser("~"), ".cache", "virtme-ng"
    )


def _assert_machine_scoped_verify(errors, missing):
    """Full pass where sources exist, availability-only elsewhere."""
    if missing:
        assert errors, "expected availability errors, got none"
        assert all(
            "is not on PATH" in item
            or "is not in the runner cache" in item
            for item in errors
        ), (missing, errors)
    else:
        assert errors == [], errors


def test_verify_rejects_status_only_promotion():
    tool = _load_tool()
    workdir = tempfile.mkdtemp(prefix="lock-refresh-promotion-")
    try:
        fix = _make_inventory(workdir)
        lock, _report = tool.generate_toolchains(
            inventory=fix["inventory"],
            pixi_lock=fix["pixi_lock"],
            adapter_dir=fix["adapter_dir"],
        )
        # Status-only promotion: the bootstrap record is relabeled
        # without the reviewed identity/source checks.
        lock["status"] = "release-approved"
        lock_path = os.path.join(workdir, "promoted.lock.json")
        _write_json(lock_path, lock)
        root = _fixture_repo_root(workdir, fix)
        errors = tool.verify_toolchains_lock(lock_path, root)
        assert errors, "status-only promotion passed verification"
        assert any(
            "reviewed" in item for item in errors
        ), errors
        kdir = os.path.join(workdir, "kernels")
        os.makedirs(kdir)
        runner = _make_runner(kdir)
        out = os.path.join(kdir, "kernels.lock.json")
        report = os.path.join(workdir, "kernels-report.json")
        code = tool.main(
            [
                "generate",
                "--kind", "kernels",
                "--vng", runner["vng"],
                "--virtme-run", runner["virtme_run"],
                "--qemu", runner["qemu"],
                "--qemu-binary", "qemu-system-x86_64",
                "--module-root", runner["site"],
                "--first-party", "virtme_ng,virtme",
                "--extra-module", "_virtualenv",
                "--lanes", runner["lanes"],
                "--out", out,
                "--report", report,
            ]
        )
        assert code == 0
        with open(out, encoding="utf-8") as handle:
            kernels = json.load(handle)
        kernels["status"] = "release-approved"
        flipped = os.path.join(kdir, "kernels-flipped.lock.json")
        _write_json(flipped, kernels)
        errors = tool.verify_kernels_lock(flipped)
        assert errors, "status-only kernels promotion passed"
        assert any(
            "bootstrap" in item for item in errors
        ), errors
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_verify_rejects_fabricated_tool_identities():
    tool = _load_tool()
    workdir = tempfile.mkdtemp(prefix="lock-refresh-fabricated-")
    try:
        fix = _make_inventory(workdir)
        lock, _report = tool.generate_toolchains(
            inventory=fix["inventory"],
            pixi_lock=fix["pixi_lock"],
            adapter_dir=fix["adapter_dir"],
        )
        _review_toolchains_lock(lock)
        # Nonexistent tool paths with fabricated digests.
        lock["tools"]["mojo"]["path"] = os.path.join(
            workdir, "no-such-mojo"
        )
        lock["tools"]["mojo"]["realpath"] = os.path.join(
            workdir, "no-such-mojo"
        )
        lock["tools"]["mojo"]["sha256"] = "9" * 64
        # An existent path with a fabricated digest.
        lock["tools"]["llc"]["sha256"] = "8" * 64
        # A fabricated exec-chain pin over real entry bytes.
        lock["tools"]["bpftool"]["exec_sha256"] = "7" * 64
        lock_path = os.path.join(workdir, "fabricated.lock.json")
        _write_json(lock_path, lock)
        root = _fixture_repo_root(workdir, fix)
        errors = tool.verify_toolchains_lock(lock_path, root)
        assert errors, "fabricated tool identities passed"
        for marker in ("mojo", "llc", "bpftool"):
            assert any(
                marker in item for item in errors
            ), (marker, errors)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_verify_rejects_fabricated_kernel_identities():
    tool = _load_tool()
    workdir = tempfile.mkdtemp(prefix="lock-refresh-kfabric-")
    try:
        _fix, lock, _document, _out, _report = _generate_kernels(
            tool, workdir
        )
        _review_kernels_lock(lock)
        lock["runner"]["sha256"] = "9" * 64
        lock["runner"]["qemu_sha256"] = "8" * 64
        lock["lanes"][0]["kernel_debs"][0]["sha256"] = "7" * 64
        lock_path = os.path.join(workdir, "fabricated.lock.json")
        _write_json(lock_path, lock)
        empty_home = os.path.join(workdir, "empty-home")
        os.makedirs(empty_home)
        with _PatchedEnv(home=empty_home):
            errors = tool.verify_kernels_lock(lock_path)
        assert errors, "fabricated kernel identities passed"
        assert any("runner" in item for item in errors), errors
        assert any("qemu" in item for item in errors), errors
        assert any("deb" in item for item in errors), errors
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_verify_accepts_reviewed_toolchains_fixture():
    tool = _load_tool()
    workdir = tempfile.mkdtemp(prefix="lock-refresh-reviewed-")
    try:
        fix = _make_inventory(workdir)
        lock, _report = tool.generate_toolchains(
            inventory=fix["inventory"],
            pixi_lock=fix["pixi_lock"],
            adapter_dir=fix["adapter_dir"],
        )
        _review_toolchains_lock(lock)
        lock_path = os.path.join(workdir, "reviewed.lock.json")
        _write_json(lock_path, lock)
        root = _fixture_repo_root(workdir, fix)
        errors = tool.verify_toolchains_lock(lock_path, root)
        assert errors == [], errors
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_verify_accepts_reviewed_kernels_fixture():
    tool = _load_tool()
    workdir = tempfile.mkdtemp(prefix="lock-refresh-kreviewed-")
    try:
        fix, lock, _document, _out, _report = _generate_kernels(
            tool, workdir
        )
        _review_kernels_lock(lock)
        lock_path = os.path.join(workdir, "reviewed.lock.json")
        _write_json(lock_path, lock)
        home = os.path.join(workdir, "home")
        cache = os.path.join(
            home, ".cache", "virtme-ng", "v9.9", "amd64"
        )
        os.makedirs(cache)
        for deb in fix["debs"]:
            shutil.copyfile(
                deb, os.path.join(cache, os.path.basename(deb))
            )
        path = fix["vng"] and os.path.join(
            workdir, "bin"
        ) or None
        assert path is not None and os.path.isdir(path)
        with _PatchedEnv(
            path=path + os.pathsep + os.environ.get("PATH", ""),
            home=home,
        ):
            errors = tool.verify_kernels_lock(lock_path)
        assert errors == [], errors
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _load_probe():
    spec = importlib.util.spec_from_file_location(
        "toolchain_inventory",
        os.path.join(REPO_ROOT, "tests", "probes", "toolchain_inventory.py"),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_probe_searches_multiarch_and_lib64_libbpf():
    probe = _load_probe()
    patterns = []
    real_glob = probe.glob.glob

    def fake_glob(pattern):
        patterns.append(pattern)
        return []

    probe.glob.glob = fake_glob
    try:
        observation = probe.observe_libbpf("")
    finally:
        probe.glob.glob = real_glob
    assert sorted(patterns) == [
        "/usr/lib/*/libbpf.so*",
        "/usr/lib64/libbpf.so*",
    ]
    assert observation["runtime_objects"] == []


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
