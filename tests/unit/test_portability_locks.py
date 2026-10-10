# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the portability lane locks.

Pins the AArch64 lane lock (``ci/kernels.arm64.lock.json``) and
the investigational compiler lock
(``ci/toolchains.investigational.lock.json``) field by field, and
guards the release freeze around them: the release toolchain
pins, the two-lane x86-64 matrix lock, the 25-suite matrix
shape, and the compatibility document's tested-only claims.
The portability guest suite itself stays out of the matrix
wiring; these tests assert that separation too.

Deterministic on any host: only the standard library plus
pytest's plain function collection. Nothing here boots a guest
or needs either Mojo toolchain installed.

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3
tests/unit/test_portability_locks.py``).
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
ARM64_LOCK = os.path.join(REPO_ROOT, "ci", "kernels.arm64.lock.json")
X86_LOCK = os.path.join(REPO_ROOT, "ci", "kernels.lock.json")
RELEASE_LOCK = os.path.join(REPO_ROOT, "toolchains.lock.json")
VM_MATRIX = os.path.join(
    REPO_ROOT, ".github", "workflows", "vm-matrix.yml"
)
HARNESS_PATH = os.path.join(
    REPO_ROOT, "tests", "harness", "bpf_test_run.py"
)
TOOL_PATH = os.path.join(REPO_ROOT, "tools", "lock_refresh.py")
INVESTIGATIONAL_LOCK = os.path.join(
    REPO_ROOT, "ci", "toolchains.investigational.lock.json"
)
COMPAT_DOC = os.path.join(REPO_ROOT, "docs", "compatibility.md")
PORTABILITY_SUITE = os.path.join(
    REPO_ROOT, "tests", "kernel", "test_arch_portability.py"
)


def _load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _load_runner_module():
    spec = importlib.util.spec_from_file_location(
        "matrix_runner",
        os.path.join(REPO_ROOT, "ci", "run_vm_tests.py"),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_arm64_lane_lock_pins_observed_lane():
    lock = _load_json(ARM64_LOCK)
    assert set(lock) == {
        "generated_by",
        "kind",
        "license",
        "notes",
        "runner",
        "schema_version",
        "status",
        "lanes",
    }
    assert lock["schema_version"] == 1
    assert lock["status"] == "release-approved"
    assert lock["kind"] == "arch-lane"
    assert lock["license"] == "Apache-2.0 WITH LLVM-exception"
    assert lock["generated_by"] == (
        "observed virtme-ng arm64 runs on the qualified x86-64 host "
        "(recorded by hand)"
    )
    assert lock["notes"] == [
        "AArch64 companion to ci/kernels.lock.json, which keeps the two "
        "x86-64 lanes and the 25-suite matrix shape. This file is not "
        "consumed by ci/run_vm_tests.py; the portability suite "
        "(tests/kernel/test_arch_portability.py) reads its lane selection "
        "from MOJOBPF_VNG_RELEASE / MOJOBPF_VNG_ARCH / MOJOBPF_VNG_ROOT.",
        "The runner binary is resolved via PATH at run time; its version "
        "and SHA-256 must match this lock, and must equal the "
        "ci/kernels.lock.json runner (same vng binary drives both "
        "architectures). Absolute install paths are intentionally not "
        "pinned.",
        "Kernel images are the Ubuntu mainline builds cached by virtme-ng "
        "under ~/.cache/virtme-ng/<release>/arm64/; the .deb file names "
        "and hashes below identify the exact artifacts. The downloader "
        "also fetches the -64k image+modules variants; the lane boots the "
        "plain generic image only (uname proves it). A lane whose cache "
        "is absent fails the suite; lanes are never silently skipped.",
        "The guest root is the pinned Ubuntu cloud image below, unpacked "
        "once with sudo (vng reuses an existing --root dir; it would "
        "otherwise download the same URL itself). The suite stages into "
        "the root's world-writable /tmp unprivileged and maps it with an "
        "explicit --rwdir guestpath=hostpath pair, because virtme "
        "rejects host paths outside a cross root.",
        "Every boot provisions its observer from scratch (guest writes "
        "are ephemeral): the suite fixes the guest clock from a staged "
        "host epoch (the TCG guest boots thinking it is 1970, which "
        "makes apt reject every Release file), then apt-get update plus "
        "apt-get install -y --no-install-recommends bpftool over "
        "user-mode networking. The observed observer versions below are "
        "what the archive served on the recorded runs; the suite echoes "
        "the per-run versions and the board records them, so archive "
        "drift is visible, never silent.",
        "Raw-syscall C holders are built on the host with the pinned "
        "cross compiler (they use symbolic SYS_/__NR_ names, so they "
        "resolve per target). The in-guest raw bpf() reader selects its "
        "syscall number from the guest machine name (321 on x86-64, 280 "
        "on AArch64) and refuses anything else.",
        "Correctness only: nothing in this lane measures performance, "
        "and emulation timing is never quoted as a performance result.",
    ]
    (lane,) = lock["lanes"]
    assert set(lane) == {
        "accelerator",
        "arch",
        "cross_compiler",
        "guest_provisioning",
        "id",
        "kernel_debs",
        "kernel_release",
        "release",
        "rootfs",
        "suite",
        "vng_argv_prefix",
    }
    assert lane["id"] == "v6.12-arm64-tcg"
    assert lane["release"] == "v6.12"
    assert lane["arch"] == "arm64"
    assert lane["accelerator"] == "tcg"
    assert lane["kernel_release"] == "6.12.0-061200-generic"
    assert lane["suite"] == "tests/kernel/test_arch_portability.py"
    assert (
        lane["cross_compiler"]
        == "aarch64-linux-gnu-gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0"
    )
    for deb in lane["kernel_debs"]:
        assert set(deb) == {"file", "sha256"}
    assert [deb["file"] for deb in lane["kernel_debs"]] == [
        "linux-image-unsigned-6.12.0-061200-generic_"
        "6.12.0-061200.202411220723_arm64.deb",
        "linux-modules-6.12.0-061200-generic_"
        "6.12.0-061200.202411220723_arm64.deb",
    ]
    assert [deb["sha256"] for deb in lane["kernel_debs"]] == [
        "a57ec147f75009d75c121edcb54e02b4ce897380f1afd36ef55ba8bceb88dada",
        "1dfd453bae8a7e8dec96d4bd9733c62ba6d247d89b52936d83a143d8aa37f84b",
    ]
    rootfs = lane["rootfs"]
    assert set(rootfs) == {"bytes", "image", "release", "sha256", "url"}
    assert rootfs["release"] == "resolute"
    assert (
        rootfs["image"]
        == "resolute-server-cloudimg-arm64-root.tar.xz"
    )
    assert rootfs["bytes"] == 252430860
    assert (
        rootfs["sha256"]
        == "6ed455eb3a048eab4ff7cc08fe9f4126875b82c06260117c2ec1cddc391ad0d7"
    )
    assert (
        rootfs["url"]
        == "https://cloud-images.ubuntu.com/resolute/current/"
        "resolute-server-cloudimg-arm64-root.tar.xz"
    )
    provisioning = lane["guest_provisioning"]
    assert set(provisioning) == {
        "clock",
        "network",
        "observed_bpftool",
        "observed_libbpf",
        "packages",
    }
    assert (
        provisioning["clock"] == "date -u --set=@<staged host epoch>"
    )
    assert provisioning["network"] == "user"
    assert provisioning["packages"] == ["bpftool"]
    assert provisioning["observed_bpftool"] == "bpftool v7.7.0"
    assert provisioning["observed_libbpf"] == "using libbpf v1.7"
    assert lane["vng_argv_prefix"] == [
        "vng",
        "--arch",
        "arm64",
        "--root",
        "<ROOT>",
        "--run",
        "v6.12",
        "--disable-kvm",
        "--network",
        "user",
        "--rwdir",
        "<GUEST_STAGE>=<HOST_STAGE>",
    ]


def test_arm64_runner_matches_x86_matrix_runner():
    arm64 = _load_json(ARM64_LOCK)["runner"]
    x86 = _load_json(X86_LOCK)["runner"]
    assert set(arm64) == {
        "name",
        "qemu",
        "qemu_binary",
        "qemu_sha256",
        "sha256",
        "version",
    }
    assert arm64["name"] == "vng" == x86["name"]
    assert arm64["version"] == x86["version"] == "virtme-ng 1.41"
    assert (
        arm64["sha256"]
        == x86["sha256"]
        == "f044af46bab9e9d867464be9fc6abb757a0ffc1d6b0d1dafe1c9341a3cb82f63"
    )
    assert (
        arm64["qemu"]
        == x86["qemu"]
        == "QEMU emulator version 10.2.1 (Debian 1:10.2.1+ds-1ubuntu3.2)"
    )
    assert arm64["qemu_binary"] == "qemu-system-aarch64"
    assert arm64["qemu_sha256"] == (
        "c232f67cee378d22414d869b36fd9bcbaa5009630e12fbfb50fa5c9449593da5"
    )
    assert x86["qemu_sha256"] == (
        "0cd4112a8f0cb891eb7c10e8df38c9dfeec8c7389bb22db6aa425f0d6fe733dc"
    )
    assert x86["qemu_binary"] == "qemu-system-x86_64"


def test_investigational_lock_pins_second_combo():
    lock = _load_json(INVESTIGATIONAL_LOCK)
    assert set(lock) == {
        "generated_by",
        "license",
        "notes",
        "observed",
        "schema_version",
        "status",
        "combo",
    }
    assert lock["schema_version"] == 1
    assert lock["status"] == "investigational"
    assert lock["license"] == "Apache-2.0 WITH LLVM-exception"
    assert lock["generated_by"] == (
        "observed runs with the investigational second-combo workspace "
        "(recorded by hand)"
    )
    assert lock["notes"] == [
        "Investigational compatibility record: exactly one second "
        "Mojo/LLVM combination, tested before any promotion. This file "
        "promotes nothing: the release pins stay in toolchains.lock.json "
        "and pixi.toml/pixi.lock, which this lane never touches, and any "
        "promotion needs its own maintainer decision.",
        "The combination differs from the release pin in the compiler "
        "frontend/stdlib and its bundled LLVM snapshot (same major, five "
        "weeks older). The BPF backend (host llc) is the same binary the "
        "release lane uses.",
        "LLVM identity is two-route corroborated: the Mojo source tree's "
        "Bazel LLVM pin at the matching tag plus the shipped "
        "llvm-symbolizer/lldb version string. The conda package hashes "
        "come from the investigational workspace's own lockfile.",
        "Observed verdict, kept current with the runs below: the 1.0.0 "
        "frontend compiles SDK-free kernel sources to byte-identical IR "
        "and objects as 1.1.0 (proven in-guest), but it cannot parse the "
        "packaged SDK surface, which uses the 1.1 decorator-argument "
        "spelling @inline(.always) in every module. Build-driver paths "
        "refuse the unpinned compiler at the toolchain gate (MBPF102) "
        "exactly as designed.",
    ]
    combo = lock["combo"]
    assert set(combo) == {"backend_llc", "bundled_llvm", "mojo"}
    mojo = combo["mojo"]
    assert set(mojo) == {"binary_sha256", "channel", "packages", "version"}
    assert mojo["version"] == "Mojo 1.0.0 (ed45d567)"
    assert mojo["channel"] == "https://conda.modular.com/max"
    assert (
        mojo["binary_sha256"]
        == "0bce743c710ca91b9513eb6bbe600dcce41892dd2b52f29427b17eeeb97d32fa"
    )
    assert [pkg["file"] for pkg in mojo["packages"]] == [
        "mojo-1.0.0-release.conda",
        "mojo-compiler-1.0.0-release.conda",
    ]
    assert [pkg["sha256"] for pkg in mojo["packages"]] == [
        "5778f999b69cf77bd6f07ccaf32d0bafc258fe75206afc8e88919269cebb6e75",
        "4394c6146d47ec7794a9a3ed5775ae158f59f83f8e1aed59408b17c4909821b3",
    ]
    for pkg in mojo["packages"]:
        assert set(pkg) == {"file", "sha256"}
    llvm = combo["bundled_llvm"]
    assert set(llvm) == {"bazel_ref", "commit", "commit_date", "version"}
    assert llvm["version"] == "24.0.0git"
    assert (
        llvm["commit"]
        == "21b0fc84c2f5fac1d3f763cfa581762684ad2a89"
    )
    assert llvm["commit_date"] == "2026-07-31T07:45:37Z"
    assert (
        llvm["bazel_ref"]
        == "modular/modular@mojo/v1.0.0:bazel/public-patches/llvm_source.bzl"
    )
    backend = combo["backend_llc"]
    assert set(backend) == {"note", "version"}
    assert backend["version"] == "Ubuntu LLVM version 21.1.8"
    assert backend["note"] == "same host backend binary as the release lane"
    observed = lock["observed"]
    assert set(observed) == {"date", "fast_suites", "kernel_lane"}
    assert observed["date"] == "2026-10-08"
    fast = observed["fast_suites"]
    assert set(fast) == {"pytest_unit", "plain_host_suites"}
    assert fast["pytest_unit"] == "311 passed"
    assert fast["plain_host_suites"] == (
        "mojo-independent suites green; SDK-importing suites fail at "
        "frontend parse (see verdict); pin-gated driver suites refuse "
        "MBPF102"
    )
    lane = observed["kernel_lane"]
    assert set(lane) == {
        "lane",
        "note",
        "object_sha256",
        "raw_ir_sha256",
        "result",
        "suite",
    }
    assert lane["result"] == "5/5 PASS"
    assert lane["lane"] == "x86-64 v6.12 (TCG)"
    assert lane["suite"] == "tests/kernel/test_mojo_xdp.py"
    assert lane["note"] == (
        "SDK-free sources only; identical bytes to the 1.1.0 build "
        "observed in-guest"
    )
    assert (
        lane["object_sha256"]
        == "17570ee79a16b64ccc4f723d00d26ae316a286cffdd3382ba3a6e6b4be95097c"
    )
    assert (
        lane["raw_ir_sha256"]
        == "aea81a0f56b2ecbaecd3b84c04cc3c3c373c7759ccacdcb30380ab2d2b32a39a"
    )


def test_release_toolchain_pins_unchanged():
    lock = _load_json(RELEASE_LOCK)
    mojo = lock["tools"]["mojo"]
    assert mojo["version"] == "Mojo 1.1.0 (8189361e)"
    assert (
        mojo["sha256"]
        == "1250f6dc59317aa7c85718d425900aff89558fc851fab50a3c61ae2236b3f738"
    )
    llc = lock["tools"]["llc"]
    assert llc["version"] == "Ubuntu LLVM version 21.1.8"
    assert (
        llc["sha256"]
        == "935bdae46915daba23b279efebc04400c085c56a8536dea633f1f5a96c9fd382"
    )
    with open(os.path.join(REPO_ROOT, "pixi.toml"), encoding="utf-8") as handle:
        pixi = handle.read()
    assert 'mojo = "==1.1.0"' in pixi


def test_x86_matrix_shape_unchanged():
    lock = _load_json(X86_LOCK)
    assert [lane["id"] for lane in lock["lanes"]] == [
        "v6.12-tcg",
        "v6.6-tcg",
    ]
    runner = _load_runner_module()
    assert len(runner.SUITES) == 25
    paths = [relpath for (_suite_id, relpath, _timeout) in runner.SUITES]
    assert "tests/kernel/test_arch_portability.py" not in paths


def test_portability_suite_selects_lane_from_birth():
    assert os.path.isfile(PORTABILITY_SUITE)
    with open(PORTABILITY_SUITE, encoding="utf-8") as handle:
        source = handle.read()
    assert 'os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")' in source
    assert 'os.environ.get("MOJOBPF_VNG_ARCH", "")' in source
    assert 'os.environ.get("MOJOBPF_VNG_ROOT", "")' in source
    # Spawning is delegated to the shared owned runner; the own-session
    # discipline is pinned there, not inlined per suite.
    assert "guest_proc.run_owned" in source
    runner_path = os.path.join(
        REPO_ROOT, "tests", "harness", "guest_proc.py"
    )
    with open(runner_path, encoding="utf-8") as handle:
        runner_source = handle.read()
    assert "start_new_session=True" in runner_source


def test_compatibility_doc_claims_only_tested_combos():
    with open(COMPAT_DOC, encoding="utf-8") as handle:
        text = handle.read()
    flat = " ".join(text.split())
    assert "AArch64" in text
    assert "tests/kernel/test_arch_portability.py" in text
    assert "ci/kernels.arm64.lock.json" in text
    assert "Mojo 1.0.0" in text
    assert "investigational" in text
    assert "ci/toolchains.investigational.lock.json" in text
    assert "bpfeb" in text
    assert "separate project" in flat
    assert "need their own runs" in flat
    assert "AArch64 and other host architectures" not in flat
    assert "95 files: 80 tests + 15 examples" in flat
    assert "96 counting the SDK's own self-import" in flat
    assert "source inventory, not 95 individually observed" in flat
    assert "(74 files)" not in text


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "lock_refresh", TOOL_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_harness():
    spec = importlib.util.spec_from_file_location(
        "bpf_test_run", HARNESS_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256_file(path):
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_script(path, body):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
    os.chmod(path, 0o755)


def _missing_tool_sources(lock):
    """Recorded tool sources absent on this machine (test helper).

    Mirrors the tool's resolution rule (repo-relative ``binary``
    under the checkout, else the recorded absolute path) so the
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
            candidate = os.path.join(REPO_ROOT, binary)
        else:
            candidate = entry.get("realpath") or entry.get("path")
        if not candidate or not os.path.isfile(candidate):
            missing.append("%s:%s" % (name, candidate))
    return missing


def _missing_kernel_sources(lock, cache_root):
    """Pinned kernel sources absent on this machine (test helper)."""
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


def test_release_lock_is_reviewed():
    tool = _load_tool()
    lock = _load_json(RELEASE_LOCK)
    assert lock["status"] == "release-approved"
    assert lock["generated_by"].startswith("tools/lock_refresh.py")
    assert lock["generated_by"] != (
        "tests/probes/toolchain_inventory.py"
    )
    missing = _missing_tool_sources(lock)
    errors = tool.verify_toolchains_lock(RELEASE_LOCK, REPO_ROOT)
    if missing:
        assert errors, "expected availability errors, got none"
        assert all(
            "is not a file on the qualifying machine" in item
            for item in errors
        ), (missing, errors)
    else:
        assert errors == [], errors


def test_release_label_requires_identity_checks():
    tool = _load_tool()
    workdir = tempfile.mkdtemp(prefix="portability-release-")
    try:
        with open(RELEASE_LOCK, encoding="utf-8") as handle:
            document = json.load(handle)
        document["status"] = "draft"
        copy_path = os.path.join(workdir, "toolchains.lock.json")
        with open(copy_path, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
        errors = tool.verify_toolchains_lock(copy_path, REPO_ROOT)
        assert errors, "draft label passed the reviewed checks"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_doctor_inventory_is_not_pin_admission():
    from mojobpf import toolchain

    workdir = tempfile.mkdtemp(prefix="portability-doctor-")
    try:
        bindir = os.path.join(workdir, "bin")
        os.makedirs(bindir)
        marker = os.path.join(workdir, "marker.log")
        binaries = {
            "mojo": "mojo",
            "llc": "llc",
            "bpftool": "bpftool",
            "python": "python3",
        }
        for name, binary in sorted(binaries.items()):
            _write_script(
                os.path.join(bindir, binary),
                "#!/bin/sh\necho \"$0\" >> %s\necho '%s 1.0'\n"
                % (marker, name),
            )
        observed = toolchain.probe_toolchain(
            toolchain.ToolchainConfig(search_paths=(bindir,))
        )
        assert observed.lockfile_status == "not_checked"
        assert observed.supported is False
        assert [item.code for item in observed.diagnostics] == [
            "MBPF105"
        ]
        assert os.path.isfile(marker), (
            "observational discovery runs the entries it reports"
        )
        os.unlink(marker)
        lockfile = os.path.join(workdir, "toolchains.lock.json")
        tools = {}
        for name in toolchain.REQUIRED_TOOLS:
            tools[name] = {
                "sha256": "0" * 64,
                "version": "%s 1.0" % name,
            }
        with open(lockfile, "w", encoding="utf-8") as handle:
            json.dump(
                {"schema_version": 1, "tools": tools}, handle
            )
        report = toolchain.probe_toolchain(
            toolchain.ToolchainConfig(
                search_paths=(bindir,), lockfile_path=lockfile
            )
        )
        assert report.lockfile_status == "mismatched"
        assert report.supported is False
        assert "MBPF102" in [
            item.code for item in report.diagnostics
        ]
        for item in report.tools:
            assert item.version is None, item
        assert not os.path.exists(marker), (
            "pin mismatch must reject before any probe executes"
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _write_fixture_toolchain(workdir, version="Mojo 9.9.9 (fixture)"):
    bindir = os.path.join(workdir, "bin")
    realdir = os.path.join(workdir, "real")
    os.makedirs(bindir)
    os.makedirs(realdir)
    marker = os.path.join(workdir, "marker.log")
    mojo_marker = os.path.join(workdir, "mojo-marker.log")
    real = os.path.join(realdir, "mojo")
    _write_script(
        real,
        "#!/bin/sh\necho probe >> %s\necho '%s'\n"
        % (mojo_marker, version),
    )
    entry = os.path.join(bindir, "mojo")
    _write_script(
        entry,
        "#!/bin/sh\nTC=%s\nexec \"$TC/mojo\" \"$@\"\n" % realdir,
    )
    for name, binary in (
        ("llc", "llc"),
        ("bpftool", "bpftool"),
        ("python", "python3"),
    ):
        _write_script(
            os.path.join(bindir, binary),
            "#!/bin/sh\necho probe >> %s\necho '%s 9.9'\n"
            % (marker, name),
        )
    return bindir, realdir, marker, mojo_marker


def _write_pinned_lock(workdir, bindir, realdir, version, mutate=None):
    from mojobpf import toolchain

    tools = {}
    for name, binary in (
        ("llc", "llc"),
        ("bpftool", "bpftool"),
        ("python", "python3"),
    ):
        path = os.path.join(bindir, binary)
        tools[name] = {
            "sha256": _sha256_file(path),
            "version": "%s 9.9" % name,
        }
    mojo_entry = os.path.join(bindir, "mojo")
    tools["mojo"] = {
        "exec_sha256": _sha256_file(os.path.join(realdir, "mojo")),
        "sha256": _sha256_file(mojo_entry),
        "version": version,
    }
    if mutate is not None:
        mutate(tools)
    lockfile = os.path.join(workdir, "toolchains.lock.json")
    with open(lockfile, "w", encoding="utf-8") as handle:
        json.dump({"schema_version": 1, "tools": tools}, handle)
    return lockfile


def test_consumer_compiler_replacement_rejected_before_probe():
    from mojobpf import toolchain

    workdir = tempfile.mkdtemp(prefix="portability-replacement-")
    try:
        version = "Mojo 9.9.9 (fixture)"
        bindir, realdir, _marker, mojo_marker = _write_fixture_toolchain(
            workdir, version
        )
        lockfile = _write_pinned_lock(
            workdir, bindir, realdir, version
        )
        report = toolchain.probe_toolchain(
            toolchain.ToolchainConfig(
                search_paths=(bindir,), lockfile_path=lockfile
            )
        )
        assert report.lockfile_status == "matched", [
            (item.code, item.explanation)
            for item in report.diagnostics
        ]
        mojo = [
            item for item in report.tools if item.name == "mojo"
        ][0]
        assert mojo.version == version
        assert os.path.isfile(mojo_marker)
        os.unlink(mojo_marker)
        # Same-version replacement: identical --version output,
        # different entry bytes.
        with open(os.path.join(bindir, "mojo"), "a",
                  encoding="utf-8") as handle:
            handle.write("# same-version replacement\n")
        report = toolchain.probe_toolchain(
            toolchain.ToolchainConfig(
                search_paths=(bindir,), lockfile_path=lockfile
            )
        )
        assert report.lockfile_status == "mismatched"
        assert "MBPF102" in [
            item.code for item in report.diagnostics
        ]
        mojo = [
            item for item in report.tools if item.name == "mojo"
        ][0]
        assert mojo.version is None
        assert not os.path.exists(mojo_marker), (
            "replaced compiler must never execute"
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_consumer_compiler_exec_chain_must_be_pinned():
    from mojobpf import toolchain

    workdir = tempfile.mkdtemp(prefix="portability-execpin-")
    try:
        version = "Mojo 9.9.9 (fixture)"
        bindir, realdir, _marker, mojo_marker = _write_fixture_toolchain(
            workdir, version
        )

        def _drop_exec(tools):
            del tools["mojo"]["exec_sha256"]

        lockfile = _write_pinned_lock(
            workdir, bindir, realdir, version, mutate=_drop_exec
        )
        report = toolchain.probe_toolchain(
            toolchain.ToolchainConfig(
                search_paths=(bindir,), lockfile_path=lockfile
            )
        )
        assert report.lockfile_status == "mismatched"
        assert "MBPF102" in [
            item.code for item in report.diagnostics
        ]
        assert not os.path.exists(mojo_marker), (
            "unpinned launcher chain must never execute"
        )

        def _wrong_exec(tools):
            tools["mojo"]["exec_sha256"] = "3" * 64

        lockfile = _write_pinned_lock(
            workdir, bindir, realdir, version, mutate=_wrong_exec
        )
        report = toolchain.probe_toolchain(
            toolchain.ToolchainConfig(
                search_paths=(bindir,), lockfile_path=lockfile
            )
        )
        assert report.lockfile_status == "mismatched"
        assert not os.path.exists(mojo_marker), (
            "mismatched exec image must never execute"
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _read_workflow():
    with open(VM_MATRIX, encoding="utf-8") as handle:
        return handle.read()


def test_ci_actions_are_pinned():
    import re

    text = _read_workflow()
    assert "actions/checkout@v4\n" not in text
    assert "actions/upload-artifact@v4\n" not in text
    assert "setup-python" not in text, (
        "the interpreter installs from a digest-pinned archive, "
        "not a manifest-resolved action"
    )
    assert re.search(r"actions/[a-z0-9-]+@v\d", text) is None, (
        "floating major action reference"
    )
    pinned = re.findall(
        r"uses:\s*actions/([a-z0-9-]+)@([0-9a-f]{40})\s+#\s*(v[\d.]+)",
        text,
    )
    assert ("checkout", "11d5960a326750d5838078e36cf38b85af677262", "v4.4.0") in pinned
    assert (
        "upload-artifact",
        "ea165f8d65b6e75b540449e92b4886f43607fa02",
        "v4.6.2",
    ) in pinned
    uses = re.findall(r"uses:\s*(\S+)", text)
    assert len(uses) == 5, uses
    for reference in uses:
        _action, _, revision = reference.partition("@")
        assert len(revision) == 40, reference
        int(revision, 16)


def test_ci_interpreter_install_is_digest_pinned():
    text = _read_workflow()
    assert "setup-python" not in text, (
        "setup-python resolves a mutable manifest and downloads "
        "an unhashed interpreter archive"
    )
    assert "python-version" not in text, (
        "a python-version line floats across patch releases; "
        "pin the exact interpreter"
    )
    version = "3.11.17"
    digest = (
        "035b0ccfe7f3d38ab3ddab505290d200c6a265b95fbd5fac"
        "76c358751d6bb6a8"
    )
    assert len(digest) == 64, digest
    assert version in text, "the exact interpreter is not pinned"
    assert digest in text, "the interpreter archive digest is missing"
    assert (
        "cpython-%s+" % version in text
        and "install_only.tar.gz" in text
    ), "the pinned interpreter archive URL is missing"
    lines = text.splitlines()

    def _line_of(marker):
        for index, line in enumerate(lines):
            if marker in line:
                return index
        raise AssertionError("workflow lacks %r" % marker)

    verify_at = _line_of("sha256sum -c")
    extract_at = _line_of("tar -xzf")
    path_at = _line_of("GITHUB_PATH")
    pip_at = _line_of("pip install")
    pytest_at = _line_of("pytest tests/unit")
    assert verify_at < extract_at < path_at < pip_at < pytest_at, (
        "the expected archive digest must verify before the "
        "archive is extracted, installed, or executed"
    )
    assert "sys.version_info[:3]" in text, (
        "the installed interpreter version is not asserted exactly"
    )


def test_ci_python_installs_are_hashed():
    import re

    text = _read_workflow()
    assert "pip install \"pytest==9.0.2\"" not in text
    installs = [
        line for line in text.splitlines() if "pip install" in line
    ]
    assert len(installs) == 3, installs
    for line in installs:
        assert "--require-hashes" in line, line
        assert "-r " in line, line
    chunks = text.split("<<'EOF'")
    assert len(chunks) == 4, "one hashed requirements block per pip job"
    for chunk in chunks[1:]:
        lines = []
        terminated = False
        for line in chunk.splitlines()[1:]:
            if line.strip() == "EOF":
                terminated = True
                break
            lines.append(line)
        assert terminated, "unterminated requirements heredoc"
        block = "\n".join(lines)
        assert "pytest==9.0.2" in block, block
        for package in ("iniconfig", "packaging", "pluggy", "pygments"):
            assert re.search(
                r"^\s*%s==[0-9.]+" % package, block, re.MULTILINE
            ), (package, block)
        hashes = re.findall(r"--hash=sha256:([0-9a-f]+)", block)
        assert len(hashes) >= 10, block
        for digest in hashes:
            assert len(digest) == 64, digest


def test_pixi_provenance_retained():
    with open(
        os.path.join(REPO_ROOT, "pixi.lock"), encoding="utf-8"
    ) as handle:
        text = handle.read()
    count = sum(
        1 for line in text.splitlines() if "sha256" in line or "md5" in line
    )
    assert count == 100, count
    lock = _load_json(RELEASE_LOCK)
    assert lock["distribution"]["file"] == "pixi.lock"
    pixi_path = os.path.join(REPO_ROOT, "pixi.lock")
    assert lock["distribution"]["sha256"] == _sha256_file(pixi_path)


def test_kernels_locks_are_reviewed():
    tool = _load_tool()
    x86 = _load_json(X86_LOCK)
    arm64 = _load_json(ARM64_LOCK)
    assert x86["status"] == "release-approved"
    assert arm64["status"] == "release-approved"
    assert [lane["id"] for lane in x86["lanes"]] == [
        "v6.12-tcg",
        "v6.6-tcg",
    ]
    cache_root = os.path.join(
        os.path.expanduser("~"), ".cache", "virtme-ng"
    )
    for lock_path, lock in ((X86_LOCK, x86), (ARM64_LOCK, arm64)):
        missing = _missing_kernel_sources(lock, cache_root)
        errors = tool.verify_kernels_lock(lock_path)
        if missing:
            assert errors, "expected availability errors, got none"
            assert all(
                "is not on PATH" in item
                or "is not in the runner cache" in item
                for item in errors
            ), (missing, errors)
        else:
            assert errors == [], errors


FAKE_BPFTOOL = """#!%s
import os
import sys

marker = os.environ.get("FAKE_BPFTOOL_MARKER")
if marker:
    with open(marker, "a", encoding="utf-8") as handle:
        handle.write(" ".join(sys.argv[1:]) + "\\n")
mode = os.environ.get("FAKE_BPFTOOL_MODE", "ok")
if sys.argv[1:] == ["version"]:
    print("bpftool v9.9.9")
elif sys.argv[1:3] == ["prog", "load"]:
    if mode == "verifier":
        sys.stderr.write("libbpf: prog load log: verifier rejected\\n")
        sys.exit(1)
    sys.exit(0)
elif sys.argv[1:2] == ["prog"] and sys.argv[2:3] == ["run"]:
    print("Return value: %%s" %% os.environ.get("FAKE_BPFTOOL_ACTION", "2"))
else:
    sys.stderr.write("unexpected argv %%r\\n" %% (sys.argv[1:],))
    sys.exit(3)
"""


def _write_fake_bpftool(workdir, name="bpftool"):
    path = os.path.join(workdir, name)
    _write_script(path, FAKE_BPFTOOL % sys.executable)
    return path


def _run_harness(harness, argv, env_extra=None):
    env = dict(os.environ)
    env.update(env_extra or {})
    old = dict(os.environ)
    os.environ.clear()
    os.environ.update(env)
    try:
        return harness.main(argv)
    finally:
        os.environ.clear()
        os.environ.update(old)


def _harness_case(workdir, harness, argv, env_extra=None):
    output = os.path.join(workdir, "result.json")
    code = _run_harness(
        harness, argv + ["--output", output], env_extra=env_extra
    )
    with open(output, encoding="utf-8") as handle:
        return code, json.load(handle)


def test_harness_rejects_replacement_bpftool_before_execution():
    harness = _load_harness()
    workdir = tempfile.mkdtemp(prefix="portability-bpftool-")
    try:
        fake = _write_fake_bpftool(workdir)
        marker = os.path.join(workdir, "marker.log")
        env = {"FAKE_BPFTOOL_MARKER": marker, "FAKE_BPFTOOL_MODE": "ok"}
        obj = os.path.join(workdir, "prog.bpf.o")
        with open(obj, "wb") as handle:
            handle.write(b"fixture object\n")
        root = os.path.join(workdir, "pins")
        os.makedirs(root)
        pin = os.path.join(root, "run-a", "prog")
        expected = _sha256_file(os.path.realpath(fake))
        argv = [
            "--object", obj,
            "--expect-action", "2",
            "--pin-path", pin,
            "--owned-root", root,
            "--ownership-token", "run-a",
            "--bpftool", fake,
            "--bpftool-sha256", expected,
            "--bpftool-version", "bpftool v9.9.9",
        ]
        code, document = _harness_case(
            workdir, harness, argv, env_extra=env
        )
        assert code == 0, document
        assert document["status"] == "pass"
        assert os.path.isfile(marker)
        os.unlink(marker)
        with open(fake, "a", encoding="utf-8") as handle:
            handle.write("# same-version replacement\n")
        code, document = _harness_case(
            workdir, harness, argv, env_extra=env
        )
        assert code == 6, document
        assert document["stage"] == "setup"
        assert document["classification"] == "setup"
        assert "hash" in (document["note"] or ""), document
        assert not os.path.exists(marker), (
            "replaced bpftool must never execute"
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_harness_rejects_unapproved_exec_chain():
    harness = _load_harness()
    workdir = tempfile.mkdtemp(prefix="portability-bpftool-chain-")
    try:
        realdir = os.path.join(workdir, "real")
        os.makedirs(realdir)
        real = os.path.join(realdir, "bpftool")
        _write_script(real, FAKE_BPFTOOL % sys.executable)
        entry = os.path.join(workdir, "bpftool")
        _write_script(
            entry,
            "#!/bin/sh\nTC=%s\nexec \"$TC/bpftool\" \"$@\"\n" % realdir,
        )
        marker = os.path.join(workdir, "marker.log")
        env = {"FAKE_BPFTOOL_MARKER": marker}
        obj = os.path.join(workdir, "prog.bpf.o")
        with open(obj, "wb") as handle:
            handle.write(b"fixture object\n")
        root = os.path.join(workdir, "pins")
        os.makedirs(root)
        pin = os.path.join(root, "run-a", "prog")
        entry_sha = _sha256_file(entry)
        base = [
            "--object", obj,
            "--expect-action", "2",
            "--pin-path", pin,
            "--owned-root", root,
            "--ownership-token", "run-a",
            "--bpftool", entry,
            "--bpftool-sha256", entry_sha,
            "--bpftool-version", "bpftool v9.9.9",
        ]
        # Launcher without an exec pin is refused unexecuted.
        code, document = _harness_case(
            workdir, harness, base, env_extra=env
        )
        assert code == 6, document
        assert "exec" in (document["note"] or ""), document
        assert not os.path.exists(marker)
        # Launcher with the wrong exec pin is refused unexecuted.
        code, document = _harness_case(
            workdir,
            harness,
            base + ["--bpftool-exec-sha256", "4" * 64],
            env_extra=env,
        )
        assert code == 6, document
        assert not os.path.exists(marker)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_harness_version_pin_checked_after_admission():
    harness = _load_harness()
    workdir = tempfile.mkdtemp(prefix="portability-bpftool-ver-")
    try:
        fake = _write_fake_bpftool(workdir)
        marker = os.path.join(workdir, "marker.log")
        env = {"FAKE_BPFTOOL_MARKER": marker}
        obj = os.path.join(workdir, "prog.bpf.o")
        with open(obj, "wb") as handle:
            handle.write(b"fixture object\n")
        root = os.path.join(workdir, "pins")
        os.makedirs(root)
        pin = os.path.join(root, "run-a", "prog")
        code, document = _harness_case(
            workdir,
            harness,
            [
                "--object", obj,
                "--expect-action", "2",
                "--pin-path", pin,
                "--owned-root", root,
                "--ownership-token", "run-a",
                "--bpftool", fake,
                "--bpftool-sha256", _sha256_file(
                    os.path.realpath(fake)
                ),
                "--bpftool-version", "bpftool v1.2.3",
            ],
            env_extra=env,
        )
        assert code == 6, document
        assert "version" in (document["note"] or ""), document
        assert os.path.isfile(marker), (
            "version is checked after the admitted probe runs"
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_harness_rejects_pins_outside_owned_root():
    harness = _load_harness()
    workdir = tempfile.mkdtemp(prefix="portability-pinroot-")
    try:
        fake = _write_fake_bpftool(workdir)
        marker = os.path.join(workdir, "marker.log")
        env = {"FAKE_BPFTOOL_MARKER": marker}
        obj = os.path.join(workdir, "prog.bpf.o")
        with open(obj, "wb") as handle:
            handle.write(b"fixture object\n")
        root = os.path.join(workdir, "pins")
        os.makedirs(root)
        entry_sha = _sha256_file(os.path.realpath(fake))
        cases = [
            ("relative", os.path.join("pins", "prog"), None),
            ("escape", os.path.join(root, "..", "prog"), None),
            ("root-itself", root, None),
            ("sibling-prefix", root + "2", None),
            (
                "other-token",
                os.path.join(root, "other-run", "prog"),
                "run-a",
            ),
            ("unowned-subdir", os.path.join(root, "stray", "prog"), "run-a"),
        ]
        for tag, pin, token in cases:
            argv = [
                "--object", obj,
                "--expect-action", "2",
                "--pin-path", pin,
                "--owned-root", root,
                "--bpftool", fake,
                "--bpftool-sha256", entry_sha,
            ]
            if token is not None:
                argv += ["--ownership-token", token]
            code, document = _harness_case(
                workdir, harness, argv, env_extra=env
            )
            assert code == 6, (tag, document)
            assert document["stage"] == "setup", (tag, document)
        assert not os.path.exists(marker), (
            "pin validation precedes any execution"
        )
        # A malformed ownership token is refused, not normalized.
        code, document = _harness_case(
            workdir,
            harness,
            [
                "--object", obj,
                "--expect-action", "2",
                "--pin-path", os.path.join(root, "run-a", "prog"),
                "--owned-root", root,
                "--ownership-token", "../run-a",
                "--bpftool", fake,
                "--bpftool-sha256", entry_sha,
            ],
            env_extra=env,
        )
        assert code == 6, document
        # A malformed owned root is refused as well.
        code, document = _harness_case(
            workdir,
            harness,
            [
                "--object", obj,
                "--expect-action", "2",
                "--pin-path", os.path.join(root, "prog"),
                "--owned-root", os.path.join(root, "..", "pins") + "/",
                "--bpftool", fake,
                "--bpftool-sha256", entry_sha,
            ],
            env_extra=env,
        )
        assert code == 6, document
        # The owned pin with the run's own token is accepted.
        own = os.path.join(root, "run-a", "prog")
        code, document = _harness_case(
            workdir,
            harness,
            [
                "--object", obj,
                "--expect-action", "2",
                "--pin-path", own,
                "--owned-root", root,
                "--ownership-token", "run-a",
                "--bpftool", fake,
                "--bpftool-sha256", entry_sha,
                "--bpftool-version", "bpftool v9.9.9",
            ],
            env_extra=env,
        )
        assert code == 0, document
        assert document["status"] == "pass"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_harness_refuses_unadmitted_execution():
    harness = _load_harness()
    assert harness.CONTRACT_VERSION == 2
    workdir = tempfile.mkdtemp(prefix="portability-noadmit-")
    try:
        fake = _write_fake_bpftool(workdir)
        marker = os.path.join(workdir, "marker.log")
        env = {"FAKE_BPFTOOL_MARKER": marker}
        obj = os.path.join(workdir, "prog.bpf.o")
        with open(obj, "wb") as handle:
            handle.write(b"fixture object\n")
        root = os.path.join(workdir, "pins")
        os.makedirs(root)
        pin = os.path.join(root, "prog")
        # No admission flags at all: a substituted bpftool must
        # never reach version, load or run.
        code, document = _harness_case(
            workdir,
            harness,
            [
                "--object", obj,
                "--expect-action", "2",
                "--pin-path", pin,
                "--owned-root", root,
                "--bpftool", fake,
            ],
            env_extra=env,
        )
        assert code == 6, document
        assert document["stage"] == "setup", document
        assert document["classification"] == "setup", document
        note = document["note"] or ""
        assert "mandatory" in note, document
        assert "admission" in note or "ownership" in note, document
        assert not os.path.exists(marker), (
            "unadmitted bpftool must never execute"
        )
        assert document["commands"] == [], document
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_harness_requires_version_with_byte_identity():
    harness = _load_harness()
    workdir = tempfile.mkdtemp(prefix="portability-pinfull-")
    try:
        fake = _write_fake_bpftool(workdir)
        marker = os.path.join(workdir, "marker.log")
        env = {"FAKE_BPFTOOL_MARKER": marker}
        obj = os.path.join(workdir, "prog.bpf.o")
        with open(obj, "wb") as handle:
            handle.write(b"fixture object\n")
        root = os.path.join(workdir, "pins")
        os.makedirs(root)
        pin = os.path.join(root, "run-a", "prog")
        entry_sha = _sha256_file(os.path.realpath(fake))
        base = [
            "--object", obj,
            "--expect-action", "2",
            "--pin-path", pin,
            "--owned-root", root,
            "--bpftool", fake,
        ]
        cases = [
            (
                "entry-without-version",
                base
                + ["--bpftool-sha256", entry_sha]
                + ["--ownership-token", "run-a"],
                "version",
            ),
            (
                "version-without-entry",
                base
                + ["--bpftool-version", "bpftool v9.9.9"]
                + ["--ownership-token", "run-a"],
                "sha256",
            ),
            (
                "pins-without-ownership",
                base
                + ["--bpftool-sha256", entry_sha]
                + ["--bpftool-version", "bpftool v9.9.9"],
                "ownership",
            ),
        ]
        for tag, argv, marker_text in cases:
            code, document = _harness_case(
                workdir, harness, argv, env_extra=env
            )
            assert code == 6, (tag, document)
            assert document["stage"] == "setup", (tag, document)
            note = document["note"] or ""
            assert "mandatory" in note, (tag, document)
            assert marker_text in note, (tag, document)
        assert not os.path.exists(marker), (
            "partially pinned bpftool must never execute"
        )
        # The full triple admits and runs.
        code, document = _harness_case(
            workdir,
            harness,
            base
            + ["--bpftool-sha256", entry_sha]
            + ["--bpftool-version", "bpftool v9.9.9"]
            + ["--ownership-token", "run-a"],
            env_extra=env,
        )
        assert code == 0, document
        assert document["status"] == "pass", document
        assert document["admission"]["bpftool_admitted"] is True
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_harness_follower_matches_exec_chain():
    harness = _load_harness()
    sys.path.insert(0, os.path.join(REPO_ROOT, "tests", "harness"))
    import exec_chain

    workdir = tempfile.mkdtemp(prefix="portability-follower-")
    try:
        binary = os.path.join(workdir, "binary")
        with open(binary, "wb") as handle:
            handle.write(b"\x7fELFfixture-binary\n")
        os.chmod(binary, 0o755)
        direct = os.path.join(workdir, "direct")
        _write_script(direct, "#!/bin/sh\necho direct\n")
        realdir = os.path.join(workdir, "real")
        os.makedirs(realdir)
        target = os.path.join(realdir, "target")
        _write_script(target, "#!/bin/sh\necho target\n")
        launcher = os.path.join(workdir, "launcher")
        _write_script(
            launcher,
            "#!/bin/sh\nTC=%s\nexec \"$TC/target\" \"$@\"\n" % realdir,
        )
        ambiguous = os.path.join(workdir, "ambiguous")
        _write_script(
            ambiguous,
            "#!/bin/sh\nexec /bin/true\nexec /bin/false\n",
        )
        dangling = os.path.join(workdir, "dangling")
        _write_script(
            dangling, "#!/bin/sh\nexec /nonexistent-target-xyz\n"
        )
        for path in (binary, direct, launcher, ambiguous, dangling):
            assert harness.follow_exec_target(path) == (
                exec_chain.follow_exec_target(path)
            ), path
        assert harness.follow_exec_target(launcher) == os.path.realpath(
            target
        )
        assert harness.follow_exec_target(binary) is None
        assert harness.follow_exec_target(direct) is None
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_harness_unlinks_packet_on_early_failure():
    harness = _load_harness()
    workdir = tempfile.mkdtemp(prefix="portability-packet-")
    real_named_temporary = tempfile.NamedTemporaryFile
    allocated = []

    def _recording(*args, **kwargs):
        handle = real_named_temporary(*args, **kwargs)
        allocated.append(handle.name)
        return handle

    try:
        fake = _write_fake_bpftool(workdir)
        obj = os.path.join(workdir, "prog.bpf.o")
        with open(obj, "wb") as handle:
            handle.write(b"fixture object\n")
        root = os.path.join(workdir, "pins")
        os.makedirs(root)
        pin = os.path.join(root, "run-a", "prog")
        base = [
            "--object", obj,
            "--expect-action", "2",
            "--pin-path", pin,
            "--owned-root", root,
            "--ownership-token", "run-a",
            "--bpftool", fake,
            "--bpftool-version", "bpftool v9.9.9",
        ]
        tempfile.NamedTemporaryFile = _recording
        try:
            # Admission refusal must still unlink the packet.
            code, document = _harness_case(
                workdir, harness,
                base + ["--bpftool-sha256", "6" * 64],
            )
            assert code == 6, document
            assert allocated, "no packet was allocated"
            for path in allocated:
                assert not os.path.exists(path), (
                    "admission refusal leaked %s" % path
                )
            del allocated[:]
            # Load failure must unlink the packet as well.
            code, document = _harness_case(
                workdir, harness,
                base + [
                    "--bpftool-sha256",
                    _sha256_file(os.path.realpath(fake)),
                ],
                env_extra={"FAKE_BPFTOOL_MODE": "verifier"},
            )
            assert code == 4, document
            assert allocated, "no packet was allocated"
            for path in allocated:
                assert not os.path.exists(path), (
                    "load failure leaked %s" % path
                )
        finally:
            tempfile.NamedTemporaryFile = real_named_temporary
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_harness_unlinks_packet_on_write_failure():
    harness = _load_harness()
    workdir = tempfile.mkdtemp(prefix="portability-packetwrite-")
    real_named_temporary = tempfile.NamedTemporaryFile
    real_unlink = os.unlink
    allocated = []
    unlinks = []

    class _FailingHandle:
        def __init__(self, wrapped):
            self._wrapped = wrapped
            self.name = wrapped.name

        def write(self, data):
            raise OSError("injected packet write failure")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._wrapped.close()
            return False

    def _failing_temporary(*args, **kwargs):
        handle = real_named_temporary(*args, **kwargs)
        allocated.append(handle.name)
        return _FailingHandle(handle)

    def _counting_unlink(path, *args, **kwargs):
        unlinks.append(path)
        return real_unlink(path, *args, **kwargs)

    try:
        fake = _write_fake_bpftool(workdir)
        obj = os.path.join(workdir, "prog.bpf.o")
        with open(obj, "wb") as handle:
            handle.write(b"fixture object\n")
        root = os.path.join(workdir, "pins")
        os.makedirs(root)
        pin = os.path.join(root, "run-a", "prog")
        argv = [
            "--object", obj,
            "--expect-action", "2",
            "--pin-path", pin,
            "--owned-root", root,
            "--ownership-token", "run-a",
            "--bpftool", fake,
            "--bpftool-sha256",
            _sha256_file(os.path.realpath(fake)),
            "--bpftool-version", "bpftool v9.9.9",
        ]
        tempfile.NamedTemporaryFile = _failing_temporary
        os.unlink = _counting_unlink
        try:
            _run_harness(harness, argv)
        except OSError as exc:
            assert "injected packet write failure" in str(exc), exc
        else:
            raise AssertionError("injected write error was swallowed")
        finally:
            tempfile.NamedTemporaryFile = real_named_temporary
            os.unlink = real_unlink
        assert allocated, "no packet was allocated"
        assert unlinks == allocated, (
            "write failure leaked the packet: %r" % (unlinks,)
        )
        for path in allocated:
            assert not os.path.exists(path), (
                "write failure leaked %s" % path
            )
    finally:
        for path in allocated:
            try:
                os.unlink(path)
            except OSError:
                pass
        shutil.rmtree(workdir, ignore_errors=True)


def test_harness_rejects_symlink_escape_from_owned_root():
    harness = _load_harness()
    workdir = tempfile.mkdtemp(prefix="portability-symlink-")
    try:
        outside = os.path.join(workdir, "outside")
        os.makedirs(outside)
        root = os.path.join(workdir, "pins")
        os.makedirs(root)
        os.symlink(outside, os.path.join(root, "link"))
        # Lexically inside, resolved outside: the pin escapes
        # through the existing ancestor symlink.
        escaped = os.path.join(root, "link", "prog")
        assert os.path.realpath(escaped) == os.path.join(
            os.path.realpath(outside), "prog"
        )
        note = harness.validate_owned_pin(escaped, root, None)
        assert note is not None, "symlink escape accepted"
        assert "outside" in note, note
        # Same escape with an ownership token naming the link.
        note = harness.validate_owned_pin(escaped, root, "link")
        assert note is not None, "token symlink escape accepted"
        # The escape is refused end to end before any execution.
        fake = _write_fake_bpftool(workdir)
        marker = os.path.join(workdir, "marker.log")
        env = {"FAKE_BPFTOOL_MARKER": marker}
        obj = os.path.join(workdir, "prog.bpf.o")
        with open(obj, "wb") as handle:
            handle.write(b"fixture object\n")
        code, document = _harness_case(
            workdir,
            harness,
            [
                "--object", obj,
                "--expect-action", "2",
                "--pin-path", escaped,
                "--owned-root", root,
                "--ownership-token", "link",
                "--bpftool", fake,
                "--bpftool-sha256",
                _sha256_file(os.path.realpath(fake)),
                "--bpftool-version", "bpftool v9.9.9",
            ],
            env_extra=env,
        )
        assert code == 6, document
        assert "outside" in (document["note"] or ""), document
        assert not os.path.exists(marker)
        # A benign link staying inside the root still admits.
        inner = os.path.join(root, "inner")
        os.makedirs(inner)
        os.symlink(inner, os.path.join(root, "alias"))
        code, document = _harness_case(
            workdir,
            harness,
            [
                "--object", obj,
                "--expect-action", "2",
                "--pin-path", os.path.join(root, "alias", "prog"),
                "--owned-root", root,
                "--ownership-token", "alias",
                "--bpftool", fake,
                "--bpftool-sha256",
                _sha256_file(os.path.realpath(fake)),
                "--bpftool-version", "bpftool v9.9.9",
            ],
            env_extra=env,
        )
        assert code == 0, document
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_harness_rechecks_containment_before_load_and_unload():
    harness = _load_harness()
    workdir = tempfile.mkdtemp(prefix="portability-recheck-")
    real_validate = harness.validate_owned_pin
    try:
        fake = _write_fake_bpftool(workdir)
        marker = os.path.join(workdir, "marker.log")
        env = {"FAKE_BPFTOOL_MARKER": marker}
        obj = os.path.join(workdir, "prog.bpf.o")
        with open(obj, "wb") as handle:
            handle.write(b"fixture object\n")
        root = os.path.join(workdir, "pins")
        os.makedirs(root)
        pin = os.path.join(root, "run-a", "prog")
        argv = [
            "--object", obj,
            "--expect-action", "2",
            "--pin-path", pin,
            "--owned-root", root,
            "--ownership-token", "run-a",
            "--bpftool", fake,
            "--bpftool-sha256",
            _sha256_file(os.path.realpath(fake)),
            "--bpftool-version", "bpftool v9.9.9",
        ]
        calls = []

        def _swap_at_load(pin_path, owned_root, token):
            calls.append(pin_path)
            if len(calls) == 1:
                return real_validate(pin_path, owned_root, token)
            return (
                "pin path %r resolves outside the owned root "
                "(test swap)" % (pin_path,)
            )

        harness.validate_owned_pin = _swap_at_load
        try:
            code, document = _harness_case(
                workdir, harness, argv, env_extra=env
            )
        finally:
            harness.validate_owned_pin = real_validate
        assert code == 6, document
        assert "outside" in (document["note"] or ""), document
        with open(marker, encoding="utf-8") as handle:
            ran = handle.read().splitlines()
        assert ran == ["version"], (
            "load must not run after the pin escapes: %r" % (ran,)
        )

        def _swap_at_unload(pin_path, owned_root, token):
            calls.append(pin_path)
            if len(calls) <= 2:
                return real_validate(pin_path, owned_root, token)
            return (
                "pin path %r resolves outside the owned root "
                "(test swap)" % (pin_path,)
            )

        del calls[:]
        os.unlink(marker)
        harness.validate_owned_pin = _swap_at_unload
        try:
            code, document = _harness_case(
                workdir, harness, argv, env_extra=env
            )
        finally:
            harness.validate_owned_pin = real_validate
        assert code == 3, document
        assert "outside" in (document["note"] or ""), document
        assert document["cleanup_ok"] is False, document
        argvs = [item["argv"] for item in document["commands"]]
        assert ["rm", "-f", pin] not in argvs, (
            "cleanup must not run rm on an escaped pin"
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _write_unresolvable_wrappers(workdir, marker):
    """Launcher entries whose chain never resolves to an image."""
    wrappers = {}
    wrappers["unresolvable-var"] = (
        "#!/bin/sh\necho probe >> %s\nexec "
        "\"$UNAPPROVED_TOOL\" \"$@\"\n" % marker
    )
    wrappers["exact-trace"] = (
        "#!/bin/sh\nexec \"$UNAPPROVED_TOOL\" \"$@\"\n"
    )
    wrappers["equivalent-tab"] = (
        "#!/bin/sh\necho probe >> %s\nexec\t"
        "\"$UNAPPROVED_TOOL\" \"$@\"\n" % marker
    )
    wrappers["dangling"] = (
        "#!/bin/sh\necho probe >> %s\nexec "
        "/nonexistent-target-xyz\n" % marker
    )
    wrappers["ambiguous"] = (
        "#!/bin/sh\necho probe >> %s\nexec /bin/true\n"
        "exec /bin/false\n" % marker
    )
    paths = {}
    for tag, body in sorted(wrappers.items()):
        path = os.path.join(workdir, "bpftool-%s" % tag)
        _write_script(path, body)
        paths[tag] = path
    first = os.path.join(workdir, "bpftool-cycle-a")
    second = os.path.join(workdir, "bpftool-cycle-b")
    _write_script(
        first,
        "#!/bin/sh\necho probe >> %s\nexec %s \"$@\"\n"
        % (marker, second),
    )
    _write_script(
        second,
        "#!/bin/sh\necho probe >> %s\nexec %s \"$@\"\n"
        % (marker, first),
    )
    paths["cyclic"] = first
    return paths


def test_harness_rejects_unresolvable_launcher_chain():
    from mojobpf import execution

    harness = _load_harness()
    workdir = tempfile.mkdtemp(prefix="portability-unknown-")
    try:
        marker = os.path.join(workdir, "marker.log")
        wrappers = _write_unresolvable_wrappers(workdir, marker)
        obj = os.path.join(workdir, "prog.bpf.o")
        with open(obj, "wb") as handle:
            handle.write(b"fixture object\n")
        root = os.path.join(workdir, "pins")
        os.makedirs(root)
        pin = os.path.join(root, "run-a", "prog")
        for tag, wrapper in sorted(wrappers.items()):
            # The shared contract rejects the same wrapper: the
            # harness must agree with the reference path.
            captured = execution.capture_chain(
                os.path.realpath(wrapper)
            )
            assert captured.form == execution.FORM_UNKNOWN, (
                tag, captured.form, captured.note,
            )
            kind, _target, note = harness.classify_exec_chain(
                os.path.realpath(wrapper)
            )
            assert kind == "unknown", (tag, kind, note)
            code, document = _harness_case(
                workdir,
                harness,
                [
                    "--object", obj,
                    "--expect-action", "2",
                    "--pin-path", pin,
                    "--owned-root", root,
                    "--ownership-token", "run-a",
                    "--bpftool", wrapper,
                    "--bpftool-sha256",
                    _sha256_file(os.path.realpath(wrapper)),
                    "--bpftool-version", "bpftool v9.9.9",
                ],
            )
            assert code == 6, (tag, document)
            assert "chain" in (document["note"] or ""), (
                tag, document,
            )
            assert not os.path.exists(marker), (
                "unresolvable %s launcher must never execute" % tag
            )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_harness_exec_word_separator_parity():
    from mojobpf import execution

    harness = _load_harness()
    workdir = tempfile.mkdtemp(prefix="portability-execsep-")
    try:
        target = os.path.join(workdir, "target")
        _write_script(target, "#!/bin/sh\nexit 0\n")

        def _check(body, shared_form, harness_kind, tag):
            wrapper = os.path.join(workdir, "wrap-%s" % tag)
            _write_script(wrapper, body)
            resolved = os.path.realpath(wrapper)
            captured = execution.capture_chain(resolved)
            assert captured.form == shared_form, (
                tag, captured.form, captured.note,
            )
            kind, _target, note = harness.classify_exec_chain(
                resolved
            )
            assert kind == harness_kind, (tag, kind, note)
            assert harness.follow_exec_target(resolved) == (
                execution.follow_exec_target(resolved)
            ), tag

        # Word breaks after ``exec`` (space, tab): the line is an
        # exec invocation. A resolvable target is a launcher in
        # both paths; an unresolvable one is unknown in both.
        for index, separator in enumerate(
            [" ", "\t", "  ", "\t ", " \t"]
        ):
            tag = "break-%d" % index
            _check(
                "#!/bin/sh\nexec%s%s \"$@\"\n"
                % (separator, target),
                execution.FORM_EXEC_LAUNCHER,
                "launcher",
                tag,
            )
            _check(
                "#!/bin/sh\nexec%s\"$UNAPPROVED_TOOL\" \"$@\"\n"
                % separator,
                execution.FORM_UNKNOWN,
                "unknown",
                "%s-unresolved" % tag,
            )
        # Shell operators glued to ``exec`` still invoke it:
        # ``exec;...``/``exec&...``/``exec|...`` run a bare exec
        # before the separator, ``exec<...``/``exec>...`` attach
        # a redirection to the exec invocation, and
        # ``exec(...``/``exec)...`` are unparseable, so every
        # operator spelling is an unresolved launcher in both
        # paths, never silently direct. Name bytes glued to
        # ``exec`` (``exec-...``, ``executable ...``) name some
        # other command instead, so those stay direct.
        for index, separator in enumerate(
            (";", "&", "|", "<", ">", "(", ")")
        ):
            _check(
                "#!/bin/sh\nexec%s%s \"$@\"\n"
                % (separator, target),
                execution.FORM_UNKNOWN,
                "unknown",
                "glued-%d" % index,
            )
        for index, first_line in enumerate(
            ["exec-%s \"$@\"" % target,
             "executable %s \"$@\"" % target]
        ):
            _check(
                "#!/bin/sh\n%s\n" % first_line,
                execution.FORM_DIRECT_SCRIPT,
                "direct",
                "glued-name-%d" % index,
            )
        # Carriage return, vertical tab and form feed split the
        # physical line for both parsers: the bare ``exec`` is
        # an invocation without a target, unknown in both
        # paths, never silently direct.
        for index, separator in enumerate(["\r", "\x0b", "\x0c"]):
            _check(
                "#!/bin/sh\nexec%s%s \"$@\"\n"
                % (separator, target),
                execution.FORM_UNKNOWN,
                "unknown",
                "split-%d" % index,
            )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_harness_exec_shape_parity():
    from mojobpf import execution

    harness = _load_harness()
    workdir = tempfile.mkdtemp(prefix="portability-execshape-")
    try:
        target = os.path.join(workdir, "target")
        _write_script(target, "#!/bin/sh\nexit 0\n")
        marker = os.path.join(workdir, "marker.log")
        obj = os.path.join(workdir, "prog.bpf.o")
        with open(obj, "wb") as handle:
            handle.write(b"fixture object\n")
        root = os.path.join(workdir, "pins")
        os.makedirs(root)
        pin = os.path.join(root, "run-a", "prog")

        def _rejects(tag, body):
            wrapper = os.path.join(workdir, "shape-%s" % tag)
            _write_script(wrapper, body)
            resolved = os.path.realpath(wrapper)
            captured = execution.capture_chain(resolved)
            assert captured.form == execution.FORM_UNKNOWN, (
                tag, captured.form, captured.note,
            )
            kind, _target, note = harness.classify_exec_chain(
                resolved
            )
            assert kind == "unknown", (tag, kind, note)
            assert harness.follow_exec_target(resolved) == (
                execution.follow_exec_target(resolved)
            ), tag
            assert execution.follow_exec_target(resolved) is None, (
                tag,
            )
            code, document = _harness_case(
                workdir,
                harness,
                [
                    "--object", obj,
                    "--expect-action", "2",
                    "--pin-path", pin,
                    "--owned-root", root,
                    "--ownership-token", "run-a",
                    "--bpftool", wrapper,
                    "--bpftool-sha256",
                    _sha256_file(resolved),
                    "--bpftool-version", "bpftool v9.9.9",
                ],
            )
            assert code == 6, (tag, document)
            assert "chain" in (document["note"] or ""), (
                tag, document,
            )
            assert not os.path.exists(marker), (
                "unresolved %s launcher must never execute" % tag
            )

        # Every reproduced bypass plus self-devised variants:
        # redirections glued to exec, separators, quoting and
        # escaping of the exec word, expansions, continuations,
        # env prefixes, command/eval wrappers and control
        # keywords all select their image outside the modeled
        # grammar, so both paths refuse them as unresolved
        # launchers with zero probe starts.
        unapproved = '"$UNAPPROVED_TOOL" "$@"'
        cases = [
            ("redirect-glue", 'exec</dev/null %s' % unapproved),
            ("redirect-fd", 'exec 2>/tmp/x-shape %s' % unapproved),
            ("redirect-dup", 'exec >&2 %s' % unapproved),
            ("redirect-rw", 'exec <>/tmp/x-shape %s' % unapproved),
            ("redirect-lead", '</dev/null exec %s' % unapproved),
            ("separator-semi", ':;exec %s' % unapproved),
            ("separator-and", 'true && exec %s' % unapproved),
            ("separator-or", 'false || exec %s' % unapproved),
            ("separator-pipe", 'echo hi | exec %s' % unapproved),
            ("subshell", '(exec %s)' % unapproved),
            ("quoted-double", '"exec" %s' % unapproved),
            ("quoted-single", "'exec' %s" % unapproved),
            ("quoted-part", '"ex"ec %s' % unapproved),
            ("escaped", '\\exec %s' % unapproved),
            ("ifs-braced", 'exec${IFS}%s' % unapproved),
            ("ifs-plain", 'exec$IFS%s' % unapproved),
            ("subst-dollar", '$(printf exec) %s' % unapproved),
            ("subst-backquote", '`printf exec` %s' % unapproved),
            ("command-word", '$XSH %s' % unapproved),
            ("command-quoted", "'$XSH' %s" % unapproved),
            ("env-prefix", 'VAR=x-shape exec %s' % unapproved),
            ("command-exec", 'command exec %s' % unapproved),
            ("builtin-exec", 'builtin exec %s' % unapproved),
            ("eval-exec", 'eval "exec $UNAPPROVED_TOOL"'),
            ("if-exec", 'if true; then exec %s; fi' % unapproved),
            ("for-exec", 'for i in 1; do exec %s; done'
             % unapproved),
            ("while-exec", 'while false; do exec %s; done'
             % unapproved),
            ("bang-exec", '! exec %s' % unapproved),
            ("group-exec", '{ exec %s; }' % unapproved),
            ("time-exec", 'time exec %s' % unapproved),
            ("case-exec", 'case x in a) exec %s;; esac'
             % unapproved),
            ("continuation-glue", 'exec\\\n%s' % unapproved),
        ]
        for tag, line in cases:
            _rejects(
                tag,
                "#!/bin/sh\necho probe >> %s\n%s\n"
                % (marker, line),
            )
        _rejects(
            "assigned-command-word",
            "#!/bin/sh\necho probe >> %s\nXSH=exec\n$XSH %s\n"
            % (marker, unapproved),
        )
        # Shell-true execs outside the exact grammar are still
        # refused: a resolvable target behind a redirection, a
        # separator or an env prefix never defaults to direct.
        for tag, line in (
            ("prefix", 'VAR=x-shape exec "%s" "$@"' % target),
            ("redirect", 'exec 2>/tmp/x-shape "%s" "$@"' % target),
            ("and", 'true && exec "%s" "$@"' % target),
            ("command", 'command exec "%s" "$@"' % target),
        ):
            _rejects(
                "resolvable-but-unguarded-%s" % tag,
                "#!/bin/sh\necho probe >> %s\n%s\n"
                % (marker, line),
            )

        def _launcher(tag, body):
            wrapper = os.path.join(workdir, "shape-%s" % tag)
            _write_script(wrapper, body)
            resolved = os.path.realpath(wrapper)
            captured = execution.capture_chain(resolved)
            assert captured.form == (
                execution.FORM_EXEC_LAUNCHER
            ), (tag, captured.form, captured.note)
            assert captured.image.realpath == os.path.realpath(
                target
            ), (tag, captured)
            kind, found, note = harness.classify_exec_chain(
                resolved
            )
            assert kind == "launcher", (tag, kind, note)
            assert found == os.path.realpath(target), (
                tag, found,
            )
            assert harness.follow_exec_target(resolved) == (
                os.path.realpath(target)
            ), tag
            assert execution.follow_exec_target(resolved) == (
                os.path.realpath(target)
            ), tag

        # Quoted exec words still name the exec builtin, so a
        # quoted exec of a pinned absolute target is a genuine
        # launcher in both paths, not a bypass.
        _launcher(
            "quoted-double-resolvable",
            '#!/bin/sh\n"exec" "%s" "$@"\n' % target,
        )
        _launcher(
            "quoted-single-resolvable",
            "#!/bin/sh\n'exec' \"%s\" \"$@\"\n" % target,
        )

        def _direct(tag, body):
            wrapper = os.path.join(workdir, "shape-%s" % tag)
            _write_script(wrapper, body)
            resolved = os.path.realpath(wrapper)
            captured = execution.capture_chain(resolved)
            assert captured.form == (
                execution.FORM_DIRECT_SCRIPT
            ), (tag, captured.form, captured.note)
            kind, _target, note = harness.classify_exec_chain(
                resolved
            )
            assert kind == "direct", (tag, kind, note)
            assert harness.follow_exec_target(resolved) is None, (
                tag,
            )
            assert execution.follow_exec_target(resolved) is None, (
                tag,
            )

        # Controls that must stay directly run: plain commands,
        # conditionals without exec, PATH probes, multiline
        # quoted strings, case dispatch, loop variables named
        # exec, function definitions and non-assignments.
        _direct("plain", "#!/bin/sh\necho direct\n")
        _direct(
            "conditional",
            "#!/bin/sh\nif true; then echo yes; fi\n"
            "export A=b\n",
        )
        _direct(
            "command-probe",
            "#!/bin/sh\ncommand -v missing-tool-xyz || true\n",
        )
        _direct(
            "multiline-quote",
            '#!/bin/sh\necho "line-one\nline-two"\n',
        )
        _direct(
            "case-dispatch",
            "#!/bin/sh\ncase $WANT in a) echo hi;; *) echo lo;; "
            "esac\n",
        )
        _direct(
            "loop-var",
            "#!/bin/sh\nfor exec in a b; do echo $exec; done\n",
        )
        _direct(
            "function-def",
            "#!/bin/sh\nexec-other() { echo fn; }\n",
        )
        _direct("not-assignment", "#!/bin/sh\nX-cmd=exec\n")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_shell_oracle_confirms_exec_shapes_execute():
    from mojobpf import execution

    harness = _load_harness()
    workdir = tempfile.mkdtemp(prefix="portability-shoracle-")
    try:
        shapes = [
            ("redirect", 'exec</dev/null %s %s'),
            ("separator", ':;exec %s %s'),
            ("quoted", '"exec" %s %s'),
            ("ifs", 'exec${IFS}%s %s'),
            ("continuation", 'ex\\\nec %s %s'),
            ("prefix", 'VAR=oracletest exec %s %s'),
            ("and", 'true && exec %s %s'),
            ("eval", 'eval "exec %s %s"'),
        ]
        for tag, template in shapes:
            oracle_body = "#!/bin/sh\n%s\n" % (
                template % ("/bin/echo", "ORACLE-%s" % tag.upper())
            )
            oracle = os.path.join(workdir, "oracle-%s" % tag)
            _write_script(oracle, oracle_body)
            proc = subprocess.run(
                ["/bin/sh", oracle],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60,
                env={"PATH": "/usr/bin:/bin"},
            )
            assert "ORACLE-%s" % tag.upper() in proc.stdout, (
                tag, proc.returncode, proc.stdout, proc.stderr,
            )
            twin_body = "#!/bin/sh\n%s\n" % (
                template % ('"$UNAPPROVED_TOOL"', '"$@"')
            )
            twin = os.path.join(workdir, "twin-%s" % tag)
            _write_script(twin, twin_body)
            resolved = os.path.realpath(twin)
            captured = execution.capture_chain(resolved)
            assert captured.form == execution.FORM_UNKNOWN, (
                tag, captured.form, captured.note,
            )
            kind, _target, note = harness.classify_exec_chain(
                resolved
            )
            assert kind == "unknown", (tag, kind, note)
        # The continuation of a resolvable target is shell-true
        # exec: the staged harness joins it and follows it to
        # the pinned image, in agreement with the shared
        # follower, while the shared capture keeps its
        # never-guess-continuations refusal.
        target = os.path.join(workdir, "target")
        _write_script(target, "#!/bin/sh\nexit 0\n")
        wrapper = os.path.join(workdir, "shape-continuation")
        _write_script(
            wrapper, '#!/bin/sh\nex\\\nec "%s" "$@"\n' % target
        )
        resolved = os.path.realpath(wrapper)
        captured = execution.capture_chain(resolved)
        assert captured.form == execution.FORM_UNKNOWN, (
            captured.form, captured.note,
        )
        kind, found, note = harness.classify_exec_chain(resolved)
        assert kind == "launcher", (kind, note)
        assert found == os.path.realpath(target), found
        assert harness.follow_exec_target(resolved) == (
            os.path.realpath(target)
        )
        assert execution.follow_exec_target(resolved) == (
            os.path.realpath(target)
        )
        _admitted, _entry, exec_path, _sha, note = (
            harness.admit_bpftool(
                resolved,
                _sha256_file(resolved),
                _sha256_file(os.path.realpath(target)),
            )
        )
        assert note is None, note
        assert exec_path == os.path.realpath(target), exec_path
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_non_shell_scripts_keep_direct_forms():
    from mojobpf import execution

    harness = _load_harness()
    workdir = tempfile.mkdtemp(prefix="portability-nonshell-")
    try:
        bodies = {
            # MIR strings carry `$` registers, parens and
            # quotes; python is not shell, so none of it is
            # an exec shape.
            "mir": (
                "#!%s\nMIR = \"  $r0 = MOV_32_64 2\\n\"\n"
                "print(MIR)\n" % sys.executable
            ),
            # A python ``exec()`` call is a function call,
            # not the shell builtin.
            "exec-call": (
                "#!%s\ndef run(code):\n    exec(code)\n"
                "run(\"x = 1\")\n" % sys.executable
            ),
            # Shell comment characters and separators inside
            # python strings are data.
            "strings": (
                "#!%s\nMSG = \"a;b | (c) # $x\"\n"
                "print(MSG)\n" % sys.executable
            ),
        }
        for tag, body in sorted(bodies.items()):
            path = os.path.join(workdir, "tool-%s" % tag)
            _write_script(path, body)
            resolved = os.path.realpath(path)
            captured = execution.capture_chain(resolved)
            assert captured.form == (
                execution.FORM_CONSOLE_SCRIPT
            ), (tag, captured.form, captured.note)
            kind, _target, note = harness.classify_exec_chain(
                resolved
            )
            assert kind == "direct", (tag, kind, note)
            assert harness.follow_exec_target(resolved) is None, (
                tag,
            )
            assert execution.follow_exec_target(resolved) is None, (
                tag,
            )
        # A perl script stays on the historical predicate: no
        # shell tokenization, no new refusal.
        perl = os.path.join(workdir, "tool-perl")
        _write_script(
            perl, "#!/usr/bin/perl\nprint \"hi $x\\n\";\n"
        )
        resolved = os.path.realpath(perl)
        captured = execution.capture_chain(resolved)
        assert captured.form == (
            execution.FORM_DIRECT_SCRIPT
        ), (captured.form, captured.note)
        kind, _target, note = harness.classify_exec_chain(
            resolved
        )
        assert kind == "direct", (kind, note)
        # Busybox runs scripts through its shell applet, so a
        # busybox entry faces shell-shape detection.
        busybox = os.path.join(workdir, "tool-busybox")
        _write_script(
            busybox,
            "#!/bin/busybox\nexec</dev/null "
            "\"$UNAPPROVED_TOOL\" \"$@\"\n",
        )
        resolved = os.path.realpath(busybox)
        captured = execution.capture_chain(resolved)
        assert captured.form == execution.FORM_UNKNOWN, (
            captured.form, captured.note,
        )
        kind, _target, note = harness.classify_exec_chain(
            resolved
        )
        assert kind == "unknown", (kind, note)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def test_harness_spawns_the_admitted_image():
    harness = _load_harness()
    workdir = tempfile.mkdtemp(prefix="portability-argv0-")
    try:
        real = _write_fake_bpftool(workdir, name="real-bpftool")
        linkdir = os.path.join(workdir, "linkdir")
        os.makedirs(linkdir)
        link = os.path.join(linkdir, "bpftool")
        os.symlink(real, link)
        obj = os.path.join(workdir, "prog.bpf.o")
        with open(obj, "wb") as handle:
            handle.write(b"fixture object\n")
        root = os.path.join(workdir, "pins")
        os.makedirs(root)
        pin = os.path.join(root, "run-a", "prog")
        code, document = _harness_case(
            workdir,
            harness,
            [
                "--object", obj,
                "--expect-action", "2",
                "--pin-path", pin,
                "--owned-root", root,
                "--ownership-token", "run-a",
                "--bpftool", link,
                "--bpftool-sha256",
                _sha256_file(os.path.realpath(link)),
                "--bpftool-version", "bpftool v9.9.9",
            ],
        )
        assert code == 0, document
        admitted = os.path.realpath(link)
        assert document["bpftool"]["path"] == admitted, document
        for record in document["commands"]:
            assert record["argv"][0] in (admitted, "rm"), record
        assert document["commands"][0]["argv"][0] == admitted
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


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
