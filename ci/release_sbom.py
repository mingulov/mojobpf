# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Emit a minimal CycloneDX SBOM for one release artifact.

Reads Name/Version/License and the Requires-Dist closure from the
artifact's own METADATA (wheel) or PKG-INFO (sdist), hashes the
artifact file, and writes a CycloneDX 1.6 document. Stdlib only, so
the release job needs no new pinned inputs to run it.

Fail-closed: any Requires-Dist entry or a version mismatch exits 2,
because the empty-dependency claim would be false and the SBOM shape
needs a conscious redesign. Usage:

    python3 ci/release_sbom.py <artifact.whl|artifact.tar.gz> \\
        <expected-version> <out.cyclonedx.json>
"""

import datetime
import hashlib
import json
import sys
import tarfile
import uuid
import zipfile
from email.parser import Parser


def _read_dist_meta(path):
    if path.endswith(".whl"):
        with zipfile.ZipFile(path) as archive:
            names = [
                name
                for name in archive.namelist()
                if name.endswith(".dist-info/METADATA")
            ]
            if len(names) != 1:
                return None, "want exactly one .dist-info/METADATA, found %d" % len(names)
            text = archive.read(names[0]).decode("utf-8")
    elif path.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            names = [
                name
                for name in archive.getnames()
                if name.count("/") == 1 and name.endswith("/PKG-INFO")
            ]
            if len(names) != 1:
                return None, "want exactly one top-level PKG-INFO, found %d" % len(names)
            member = archive.extractfile(names[0])
            text = member.read().decode("utf-8")
    else:
        return None, "not a .whl or .tar.gz artifact: %s" % path
    return Parser().parsestr(text), None


def _sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv):
    if len(argv) != 3:
        print("usage: release_sbom.py <artifact> <expected-version> <out>", file=sys.stderr)
        return 2
    artifact, expected, out = argv
    try:
        meta, error = _read_dist_meta(artifact)
    except (OSError, ValueError, KeyError, EOFError) as exc:
        print("cannot read dist metadata: %s" % exc, file=sys.stderr)
        return 2
    if error is not None:
        print(error, file=sys.stderr)
        return 2
    requires = meta.get_all("Requires-Dist") or []
    if requires:
        print(
            "refusing: %d Requires-Dist entries; the empty-dependency SBOM no longer holds"
            % len(requires),
            file=sys.stderr,
        )
        return 2
    name = (meta.get("Name") or "").strip()
    version = (meta.get("Version") or "").strip()
    if not name or not version:
        print("refusing: Name/Version missing from dist metadata", file=sys.stderr)
        return 2
    if version != expected:
        print(
            "refusing: artifact version %s != expected %s" % (version, expected),
            file=sys.stderr,
        )
        return 2
    license_expression = (meta.get("License-Expression") or meta.get("License") or "").strip()
    if not license_expression:
        print("refusing: no License-Expression/License in dist metadata", file=sys.stderr)
        return 2
    try:
        digest = _sha256_of(artifact)
    except OSError as exc:
        print("cannot hash artifact: %s" % exc, file=sys.stderr)
        return 2
    purl = "pkg:pypi/%s@%s" % (name.lower(), version)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:%s" % uuid.uuid4(),
        "version": 1,
        "metadata": {
            "timestamp": stamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "bom-ref": "mojobpf-release-sbom@%s" % version,
                        "name": "mojobpf-release-sbom",
                        "version": version,
                    }
                ]
            },
            "component": {
                "bom-ref": purl,
                "type": "library",
                "name": name,
                "version": version,
                "purl": purl,
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "licenses": [{"expression": license_expression}],
            },
        },
        "components": [],
    }
    try:
        with open(out, "w", encoding="utf-8") as handle:
            json.dump(doc, handle, indent=2)
            handle.write("\n")
    except OSError as exc:
        print("cannot write SBOM: %s" % exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
