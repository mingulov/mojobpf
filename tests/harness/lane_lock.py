# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Supra-level VM lane pins: the kernels lockfiles as the single source.

Every guest suite boots a kernel from the virtme-ng cache. The exact
kernel release, the kernel DEB filenames and hashes, and (for the
AArch64 lane) the guest root identity are reserved in
``ci/kernels.lock.json`` (x86-64) and ``ci/kernels.arm64.lock.json``.
Suites resolve those pins through this module and assert EQUALITY
against them. A locally derived ``"6.12"`` prefix would also match a
sibling image -- vng downloads the ``-64k`` image and modules variants
into the same cache directory, and a rebuilt image keeps the same
major.minor -- so prefix checks are refused here: anything less than
the locked release fails.

Standard library only. Imported host-side by the directly runnable
suites (``sys.path``-relative to this directory); never staged into
a guest.
"""

import hashlib
import json
import os


class LaneLockError(Exception):
    """A lane pin is missing, unverifiable, or mismatched."""


def lock_path(repo_root, arch=""):
    """Return the lockfile path for ``arch`` (AArch64 or x86-64)."""
    name = (
        "kernels.arm64.lock.json"
        if arch in ("arm64", "aarch64")
        else "kernels.lock.json"
    )
    return os.path.join(repo_root, "ci", name)


def lane_for_release(repo_root, release, arch=""):
    """Return the locked lane dict for ``release``.

    Raises :class:`LaneLockError` when the lockfile is unreadable or
    carries no lane for the release. Missing lanes fail; they are
    never skipped.
    """
    path = lock_path(repo_root, arch)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lock = json.load(handle)
    except (OSError, ValueError) as exc:
        raise LaneLockError(
            "cannot read lane lock %s: %s" % (path, exc)
        )
    lanes = lock.get("lanes", [])
    for lane in lanes:
        if lane.get("release") == release:
            if arch in ("arm64", "aarch64"):
                lane_arch = lane.get("arch", "")
                if lane_arch not in ("arm64", "aarch64", ""):
                    continue
            return lane
    known = sorted(
        str(lane.get("release", "?")) for lane in lanes
    )
    raise LaneLockError(
        "lane lock %s carries no lane for release %r "
        "(known: %s)" % (path, release, ", ".join(known))
    )


def expected_kernel_release(repo_root, release, arch=""):
    """Return the exact locked ``kernel_release`` for the lane."""
    lane = lane_for_release(repo_root, release, arch)
    kernel_release = lane.get("kernel_release", "")
    if not kernel_release:
        raise LaneLockError(
            "lane %r reserves no kernel_release"
            % (lane.get("id", "?"),)
        )
    return kernel_release


def booted_kernel_from_output(output):
    """Return the guest-reported ``guest-kernel`` value.

    The last ``guest-kernel:`` line wins, matching the suites'
    historical parse loops. Raises :class:`LaneLockError` when the
    guest reported no kernel line.
    """
    kernel = ""
    for line in output.splitlines():
        if line.startswith("guest-kernel:"):
            kernel = line.split("guest-kernel:", 1)[1].strip()
    if not kernel:
        raise LaneLockError("guest reported no guest-kernel line")
    return kernel


def check_booted_kernel(observed, repo_root, release, arch=""):
    """Fail unless ``observed`` equals the locked ``kernel_release``.

    Equality is exact: a sibling image (``-64k``) or a rebuilt image
    with the same major.minor is refused.
    """
    want = expected_kernel_release(repo_root, release, arch)
    if observed != want:
        raise LaneLockError(
            "guest booted kernel %r, lane %s/%s locks %r"
            % (observed, release, arch or "x86-64", want)
        )
    return want


def sha256_file(path):
    """Return the hex SHA-256 of a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_kernel_cache(repo_root, release, arch=""):
    """Fail unless every locked kernel DEB is cached with its hash.

    Returns ``{"cache": ..., "debs": [...]}`` for suite boards.
    A cache holding two files under one locked basename is refused
    instead of verified against an arbitrary first match.
    """
    lane = lane_for_release(repo_root, release, arch)
    cache = os.path.join(
        os.path.expanduser("~"), ".cache", "virtme-ng", release
    )
    if not os.path.isdir(cache):
        raise LaneLockError(
            "lane %s cache is absent (%s); fetch it with "
            "`vng --run %s --disable-kvm --exec true` and re-run"
            % (lane.get("id", release), cache, release)
        )
    found = []
    for root, _dirs, files in os.walk(cache):
        for name in files:
            if name.endswith(".deb"):
                found.append(os.path.join(root, name))
    problems = []
    for deb in lane.get("kernel_debs", []):
        matches = [
            path
            for path in found
            if os.path.basename(path) == deb.get("file", "")
        ]
        if not matches:
            problems.append("missing %s" % deb.get("file", "?"))
            continue
        if len(matches) > 1:
            problems.append(
                "ambiguous %s (%d copies; refusing to pick)"
                % (deb.get("file", "?"), len(matches))
            )
            continue
        digest = sha256_file(matches[0])
        if digest != deb.get("sha256", ""):
            problems.append(
                "%s hash mismatch (cache %s)"
                % (deb.get("file", "?"), digest)
            )
    if problems:
        raise LaneLockError(
            "lane %s cache mismatch: %s"
            % (lane.get("id", release), "; ".join(problems))
        )
    return {
        "cache": cache,
        "debs": sorted(os.path.basename(p) for p in found),
    }


def check_guest_root(root_dir, repo_root, release, arch=""):
    """Tie an unpacked ``--root`` dir to the locked rootfs pin.

    Lanes without a ``rootfs`` pin (the x86-64 lanes boot the host
    root) return ``None`` unchecked. Lanes with a pin require the
    unpacked root's ``etc/os-release`` to identify the locked release
    codename, and verify the locked tarball hash and size when the
    tarball sits next to the unpacked root. Returns the observed
    identity mapping for suite boards.
    """
    lane = lane_for_release(repo_root, release, arch)
    pin = lane.get("rootfs")
    if not pin:
        return None
    if not os.path.isdir(root_dir):
        raise LaneLockError(
            "lane %s guest root is not a directory: %r"
            % (lane.get("id", release), root_dir)
        )
    os_release = os.path.join(root_dir, "etc", "os-release")
    try:
        with open(os_release, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        raise LaneLockError(
            "lane %s guest root %r carries no etc/os-release; "
            "it cannot be the locked %s image"
            % (lane.get("id", release), root_dir, pin.get("image", "?"))
        )
    fields = {}
    for line in text.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip().strip('"')
    codename = fields.get("VERSION_CODENAME", "")
    if codename != pin.get("release", ""):
        raise LaneLockError(
            "lane %s guest root codename %r is not the locked %r "
            "(os-release: %s)"
            % (
                lane.get("id", release),
                codename,
                pin.get("release", "?"),
                os_release,
            )
        )
    observed = {"codename": codename}
    tarball = os.path.join(
        os.path.dirname(os.path.abspath(root_dir)), pin.get("image", "")
    )
    if pin.get("image") and os.path.isfile(tarball):
        size = os.path.getsize(tarball)
        if size != pin.get("bytes", -1):
            raise LaneLockError(
                "lane %s rootfs tarball size %d is not the locked %d"
                % (lane.get("id", release), size, pin.get("bytes", -1))
            )
        digest = sha256_file(tarball)
        if digest != pin.get("sha256", ""):
            raise LaneLockError(
                "lane %s rootfs tarball hash mismatch (observed %s)"
                % (lane.get("id", release), digest)
            )
        observed["tarball"] = tarball
        observed["tarball_sha256"] = digest
    return observed
