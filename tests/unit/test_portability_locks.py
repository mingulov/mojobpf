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
    assert lock["schema_version"] == 1
    assert lock["kind"] == "arch-lane"
    assert lock["license"] == "Apache-2.0 WITH LLVM-exception"
    (lane,) = lock["lanes"]
    assert lane["id"] == "v6.12-arm64-tcg"
    assert lane["release"] == "v6.12"
    assert lane["arch"] == "arm64"
    assert lane["accelerator"] == "tcg"
    assert lane["kernel_release"] == "6.12.0-061200-generic"
    assert lane["suite"] == "tests/kernel/test_arch_portability.py"
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
    assert rootfs["url"].endswith("/" + rootfs["image"])
    provisioning = lane["guest_provisioning"]
    assert provisioning["network"] == "user"
    assert provisioning["packages"] == ["bpftool"]
    assert provisioning["observed_bpftool"] == "bpftool v7.7.0"
    assert provisioning["observed_libbpf"] == "using libbpf v1.7"
    argv = lane["vng_argv_prefix"]
    assert argv[0] == "vng"
    for flag in (
        "--arch",
        "arm64",
        "--root",
        "--run",
        "v6.12",
        "--disable-kvm",
        "--network",
        "user",
        "--rwdir",
    ):
        assert flag in argv, "lane argv lacks %s: %r" % (flag, argv)


def test_arm64_runner_matches_x86_matrix_runner():
    arm64 = _load_json(ARM64_LOCK)["runner"]
    x86 = _load_json(X86_LOCK)["runner"]
    assert arm64["name"] == "vng" == x86["name"]
    assert arm64["version"] == x86["version"] == "virtme-ng 1.41"
    assert arm64["sha256"] == x86["sha256"]
    assert arm64["qemu"] == x86["qemu"]
    assert arm64["qemu_binary"] == "qemu-system-aarch64"


def test_investigational_lock_pins_second_combo():
    lock = _load_json(INVESTIGATIONAL_LOCK)
    assert lock["schema_version"] == 1
    assert lock["status"] == "investigational"
    assert lock["license"] == "Apache-2.0 WITH LLVM-exception"
    combo = lock["combo"]
    mojo = combo["mojo"]
    assert mojo["version"] == "Mojo 1.0.0 (ed45d567)"
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
    llvm = combo["bundled_llvm"]
    assert llvm["version"] == "24.0.0git"
    assert (
        llvm["commit"]
        == "21b0fc84c2f5fac1d3f763cfa581762684ad2a89"
    )
    assert llvm["commit_date"] == "2026-07-31T07:45:37Z"
    assert (
        combo["backend_llc"]["version"] == "Ubuntu LLVM version 21.1.8"
    )
    observed = lock["observed"]
    assert observed["kernel_lane"]["result"] == "5/5 PASS"
    assert (
        observed["kernel_lane"]["object_sha256"]
        == "17570ee79a16b64ccc4f723d00d26ae316a286cffdd3382ba3a6e6b4be95097c"
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
