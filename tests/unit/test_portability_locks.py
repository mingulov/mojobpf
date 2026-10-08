# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the portability lane locks.

Pins the AArch64 lane lock (``ci/kernels.arm64.lock.json``) and
the investigational compiler lock
(``ci/toolchains.investigational.lock.json``) field by field, and
guards the release freeze around them: the release toolchain
pins, the two-lane x86-64 matrix lock, the 16-suite matrix
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
import sys

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
ARM64_LOCK = os.path.join(REPO_ROOT, "ci", "kernels.arm64.lock.json")
X86_LOCK = os.path.join(REPO_ROOT, "ci", "kernels.lock.json")
INVESTIGATIONAL_LOCK = os.path.join(
    REPO_ROOT, "ci", "toolchains.investigational.lock.json"
)
RELEASE_LOCK = os.path.join(REPO_ROOT, "toolchains.lock.json")
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
        "lanes",
    }
    assert lock["schema_version"] == 1
    assert lock["kind"] == "arch-lane"
    assert lock["license"] == "Apache-2.0 WITH LLVM-exception"
    assert lock["generated_by"] == (
        "observed virtme-ng arm64 runs on the qualified x86-64 host "
        "(recorded by hand)"
    )
    assert lock["notes"] == [
        "AArch64 companion to ci/kernels.lock.json, which keeps the two "
        "x86-64 lanes and the 16-suite matrix shape. This file is not "
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
    assert set(arm64) == {"name", "qemu", "qemu_binary", "sha256", "version"}
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
    assert len(runner.SUITES) == 16
    paths = [relpath for (_suite_id, relpath, _timeout) in runner.SUITES]
    assert "tests/kernel/test_arch_portability.py" not in paths


def test_portability_suite_selects_lane_from_birth():
    assert os.path.isfile(PORTABILITY_SUITE)
    with open(PORTABILITY_SUITE, encoding="utf-8") as handle:
        source = handle.read()
    assert 'os.environ.get("MOJOBPF_VNG_RELEASE", "v6.12")' in source
    assert 'os.environ.get("MOJOBPF_VNG_ARCH", "")' in source
    assert 'os.environ.get("MOJOBPF_VNG_ROOT", "")' in source
    assert "start_new_session=True" in source


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
    assert "80 files: 66 tests + 14 examples" in flat
    assert "81 counting the SDK's own self-import" in flat
    assert "source inventory, not 80 individually observed" in flat
    assert "(74 files)" not in text


def _direct_names():
    return sorted(
        name
        for name in globals()
        if name.startswith("test_") and callable(globals()[name])
    )


def _direct_run():
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
