# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Extract the pinned library API rows for the coverage ledger.

Reads the independently packaged library API coverage
artifact plus the exact artifact revision it was read from,
and writes the pinned extract the ledger materializer
consumes: the artifact schema version, the provenance
header (repository, revision, path, artifact bytes hash),
and every function row, sorted by ID. The materializer
validates the extract; this tool only filters and stamps,
so validation stays in exactly one layer.

The extract is a hash-recorded derivative, not a second
authority: the ledger header binds it to the artifact
revision and bytes, and regeneration starts from the
artifact, never from a worktree copy.
"""

import argparse
import hashlib
import json
import math
import os
import re
import secrets
import sys

EXTRACT_SCHEMA_VERSION = 1

COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")

SOURCE_LICENSE = "Apache-2.0 WITH LLVM-exception"


class _StrictError(ValueError):
    """Strict-parse failure with its final message attached."""


def _parse_json_strict(text, path):
    """Parse JSON text, refusing ambiguity and odd constants."""

    def _refuse_dups(pairs):
        seen = set()
        document = {}
        for key, value in pairs:
            if key in seen:
                raise _StrictError(
                    f"{path} has a duplicate key {key!r}"
                )
            seen.add(key)
            document[key] = value
        return document

    def _refuse_constant(token):
        raise _StrictError(
            f"{path} uses non-standard constant {token}"
        )

    def _refuse_nonfinite(text_value):
        value = float(text_value)
        if not math.isfinite(value):
            raise _StrictError(
                f"{path} uses non-finite number {text_value}"
            )
        return value

    try:
        return json.loads(
            text,
            object_pairs_hook=_refuse_dups,
            parse_constant=_refuse_constant,
            parse_float=_refuse_nonfinite,
        )
    except _StrictError:
        raise
    except ValueError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}")


def _load_json_strict(path):
    """Load JSON, refusing duplicate keys and non-standard constants.

    Mirrors the materializer's loader: ambiguous source bytes
    must fail here instead of being silently normalized into
    the extract.
    """
    with open(path, "rb") as handle:
        raw = handle.read()
    try:
        text = raw.decode("utf-8")
    except ValueError as exc:
        raise ValueError(f"{path} is not valid UTF-8: {exc}")
    return _parse_json_strict(text, path)


def dump_extract(extract):
    """Serialize an extract to its canonical committed bytes."""
    return (
        json.dumps(extract, indent=2, sort_keys=True, allow_nan=False)
        + "\n"
    )


def _atomic_write_text(path, text, _opener=open):
    """Write text atomically: temp file plus rename.

    Mirrors the materializer's writer: exclusive creation
    under an unguessable temp name, and cleanup that only
    ever unlinks the temp path.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    tmp = os.path.join(
        directory,
        ".%s.%s.tmp" % (os.path.basename(path), secrets.token_hex(8)),
    )
    try:
        handle = _opener(tmp, "x", encoding="utf-8")
    except FileExistsError:
        # Exclusive creation refused: the path belongs to
        # someone else, so there is nothing of ours to clean.
        raise
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        with handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def extract_api_rows(artifact, *, repo, rev, path, artifact_sha256):
    """Filter function rows and stamp the provenance header."""
    if not isinstance(artifact, dict):
        raise ValueError("artifact must be an object")
    version = artifact.get("schema_version")
    if type(version) is not int or version != EXTRACT_SCHEMA_VERSION:
        raise ValueError(
            "API coverage schema_version %r is not supported "
            "(this extractor reads %d)"
            % (version, EXTRACT_SCHEMA_VERSION)
        )
    for key, value in (
        ("repo", repo),
        ("rev", rev),
        ("path", path),
        ("artifact_sha256", artifact_sha256),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"provenance {key!r} must be non-blank")
    if not COMMIT_PATTERN.fullmatch(rev):
        raise ValueError(
            "provenance revision %r is not a full commit ID "
            "(mutable refs cannot pin bytes)" % rev
        )
    raw_rows = artifact.get("rows", [])
    if not isinstance(raw_rows, list):
        raise ValueError("artifact rows must be a list")
    for row in raw_rows:
        if not isinstance(row, dict):
            raise ValueError("artifact row must be an object")
        ident = row.get("id", "")
        if not isinstance(ident, str) or not ident.strip():
            raise ValueError("artifact row is missing its id")
    rows = sorted(
        (
            row
            for row in raw_rows
            if row.get("id", "").startswith("function:")
        ),
        key=lambda row: row["id"],
    )
    return {
        "schema_version": EXTRACT_SCHEMA_VERSION,
        "license": SOURCE_LICENSE,
        "api_provenance": {
            "repo": repo,
            "rev": rev,
            "path": path,
            "artifact_sha256": artifact_sha256,
        },
        "rows": rows,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Extract pinned library API rows."
    )
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--rev", required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    # Read once: the stamped digest and the parsed document
    # must describe the same bytes.
    with open(args.artifact, "rb") as handle:
        artifact_bytes = handle.read()
    try:
        text = artifact_bytes.decode("utf-8")
    except ValueError as exc:
        print(
            f"error: {args.artifact} is not valid UTF-8: {exc}",
            file=sys.stderr,
        )
        return 1
    try:
        artifact = _parse_json_strict(text, args.artifact)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    try:
        extract = extract_api_rows(
            artifact,
            repo=args.repo,
            rev=args.rev,
            path=args.path,
            artifact_sha256=hashlib.sha256(artifact_bytes).hexdigest(),
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    # Serialize before opening the destination: a failure must
    # never truncate an existing output.
    try:
        out_text = dump_extract(extract)
    except ValueError as exc:
        print(f"error: cannot serialize extract: {exc}", file=sys.stderr)
        return 1
    try:
        _atomic_write_text(args.output, out_text)
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return 1
    print(
        "extracted %d function rows from %s"
        % (len(extract["rows"]), args.rev)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
