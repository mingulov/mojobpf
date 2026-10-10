# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Build-time generation of packaged adapter resources.

``compiler/`` is the authoritative adapter source; the wheel ships
byte-identical copies under ``src/mojobpf/resources/adapter/``.
This script derives those copies as a deterministic byte copy per
the ``[tool.mojobpf.adapter_generation]`` table in
``pyproject.toml``, and derives the standalone admission
descriptor (``admission.json``) from the authoritative capability
registry (``mojobpf.capabilities.SUPPORTED_PROFILES``) as
deterministic JSON. It is wired into the setuptools build (see
``setup.py``: the ``build_py`` and ``sdist`` commands regenerate
before packaging), so wheel AND sdist builds regenerate. The
committed copies stay for source-tree use and must equal generated
bytes (the mirror tests and ``--check`` enforce that).

Generation fails closed: missing inputs (the hook table, the
registry source, an authoritative ``compiler/`` file) fail before
any write with exit 2, and unwritable targets fail loudly with
exit 2 -- stale bytes are never silently kept. The sdist carries
the generator and the authoritative sources (see ``MANIFEST.in``),
so a wheel built from the sdist regenerates from them instead of
relying on a skip path. ``--check`` verifies a source checkout
without writing: drift reports exit 1, an unverifiable tree
reports exit 2.

Exit codes: 0 regenerated/up-to-date; 1 drift under ``--check``;
2 cannot run (missing hook table, unreadable registry, missing
sources, unwritable target).

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import asdict

try:
    import tomllib
except ImportError:  # pragma: no cover (requires-python >= 3.11)
    tomllib = None  # type: ignore[assignment]

HOOK_TABLE = ("tool", "mojobpf", "adapter_generation")

# Standalone admission descriptor: generated from the
# authoritative capability registry (never hand-edited) and
# shipped byte-identically in both lanes (``compiler/`` and the
# packaged ``resources/adapter/`` copy).
ADMISSION_FILENAME = "admission.json"
ADMISSION_SCHEMA_VERSION = 1
ADMISSION_GENERATED_FROM = "mojobpf.capabilities.SUPPORTED_PROFILES"
REGISTRY_SRC = os.path.join("src", "mojobpf", "capabilities.py")


def _repo_root(explicit: str | None) -> str:
    if explicit is not None:
        return os.path.abspath(explicit)
    here = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(here) == "tools":
        return os.path.dirname(here)
    return os.getcwd()


def load_table(root: str) -> tuple[str, str, tuple[str, ...]]:
    """Return ``(source_dir, target_dir, files)`` from the hook table."""
    if tomllib is None:
        raise RuntimeError("tomllib is required (Python 3.11+)")
    pyproject = os.path.join(root, "pyproject.toml")
    try:
        with open(pyproject, "rb") as handle:
            document = tomllib.load(handle)
    except OSError as exc:
        raise RuntimeError(
            "cannot read pyproject.toml: %s" % exc
        ) from None
    node: object = document
    for key in HOOK_TABLE:
        if not isinstance(node, dict) or key not in node:
            raise RuntimeError(
                "pyproject.toml lacks [%s]" % ".".join(HOOK_TABLE)
            )
        node = node[key]
    if not isinstance(node, dict):
        raise RuntimeError(
            "pyproject.toml [%s] must be a table"
            % ".".join(HOOK_TABLE)
        )
    source_dir = node.get("source_dir")
    target_dir = node.get("target_dir")
    files = node.get("files")
    if (
        not isinstance(source_dir, str)
        or not isinstance(target_dir, str)
        or not isinstance(files, list)
        or not files
        or not all(isinstance(entry, str) for entry in files)
    ):
        raise RuntimeError(
            "pyproject.toml [%s] must carry source_dir/target_dir "
            "strings and a non-empty files list" % ".".join(HOOK_TABLE)
        )
    return source_dir, target_dir, tuple(files)


def _sha12(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()[:12]


def render_admission(root: str) -> bytes:
    """Render the admission descriptor from the tree's registry.

    Imports ``mojobpf.capabilities`` from ``<root>/src`` (and
    only from there) and encodes ``SUPPORTED_PROFILES`` as
    canonical JSON: registry order, dataclass field order,
    ASCII, trailing newline. Raises ``RuntimeError`` on any
    failure: the descriptor is never guessed.
    """
    srcdir = os.path.abspath(os.path.join(root, "src"))
    want = os.path.realpath(os.path.join(root, REGISTRY_SRC))
    if not os.path.isfile(want):
        raise RuntimeError(
            "capability registry source is missing: %s" % REGISTRY_SRC
        )
    sys.path.insert(0, srcdir)
    try:
        try:
            import mojobpf.capabilities as registry
        except ImportError as exc:
            raise RuntimeError(
                "cannot import the capability registry: %s" % exc
            ) from None
    finally:
        try:
            sys.path.remove(srcdir)
        except ValueError:
            pass
    got = os.path.realpath(
        os.path.abspath(registry.__file__)
    )
    if got != want:
        raise RuntimeError(
            "refusing to generate from a non-tree registry: %s" % got
        )
    profiles = registry.SUPPORTED_PROFILES
    if not isinstance(profiles, dict) or not profiles:
        raise RuntimeError("capability registry names no profiles")
    encoded = {}
    for profile_id, profile in profiles.items():
        if not isinstance(profile_id, str) or not profile_id:
            raise RuntimeError(
                "capability registry carries a bad profile id"
            )
        if getattr(profile, "profile_id", None) != profile_id:
            raise RuntimeError(
                "capability registry drifts at %r" % (profile_id,)
            )
        try:
            fields = asdict(profile)
        except TypeError as exc:
            raise RuntimeError(
                "capability registry entry %r is misshapen: %s"
                % (profile_id, exc)
            ) from None
        encoded[profile_id] = fields
    document = {
        "schema_version": ADMISSION_SCHEMA_VERSION,
        "generated_from": ADMISSION_GENERATED_FROM,
        "profiles": encoded,
    }
    try:
        text = json.dumps(document, indent=2, ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            "capability registry is not JSON-encodable: %s" % exc
        ) from None
    return (text + "\n").encode("ascii")


def _read_optional(path: str) -> bytes | None:
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError:
        return None


def _check(
    root: str,
    source_dir: str,
    target_dir: str,
    files: tuple[str, ...],
    admission: bytes,
) -> int:
    """Verify derivation and mirrors without writing."""
    admission_path = os.path.join(root, source_dir, ADMISSION_FILENAME)
    committed = _read_optional(admission_path)
    drifted: list[str] = []
    if committed != admission:
        drifted.append("%s/%s" % (source_dir, ADMISSION_FILENAME))
        print(
            "adapter generation: %s/%s: drifted "
            "(registry %s, committed %s; regenerate)"
            % (
                source_dir,
                ADMISSION_FILENAME,
                _sha12(admission),
                _sha12(committed) if committed is not None else "missing",
            )
        )
    target_base = os.path.join(root, target_dir)
    jobs = [
        (name, os.path.join(root, source_dir, name)) for name in files
    ]
    for name, source_path in jobs:
        try:
            with open(source_path, "rb") as handle:
                want = handle.read()
        except OSError:
            print(
                "adapter generation: cannot verify: authoritative "
                "source unreadable: %s" % source_path
            )
            return 2
        got = _read_optional(os.path.join(target_base, name))
        if got == want:
            print(
                "adapter generation: %s: up-to-date (%s)"
                % (name, _sha12(want))
            )
            continue
        drifted.append(name)
        print(
            "adapter generation: %s: drifted "
            "(source %s, copy %s)"
            % (
                name,
                _sha12(want),
                _sha12(got) if got is not None else "missing",
            )
        )
    got = _read_optional(os.path.join(target_base, ADMISSION_FILENAME))
    if got == admission:
        print(
            "adapter generation: %s: up-to-date (%s)"
            % (ADMISSION_FILENAME, _sha12(admission))
        )
    else:
        drifted.append(ADMISSION_FILENAME)
        print(
            "adapter generation: %s: drifted "
            "(registry %s, copy %s)"
            % (
                ADMISSION_FILENAME,
                _sha12(admission),
                _sha12(got) if got is not None else "missing",
            )
        )
    if drifted:
        print(
            "adapter generation: drift: %s" % ", ".join(drifted)
        )
        return 1
    return 0


def generate(root: str, *, check: bool) -> int:
    """Regenerate (or, under ``check``, verify) the packaged copies."""
    try:
        source_dir, target_dir, files = load_table(root)
    except RuntimeError as exc:
        print("adapter generation: error: %s" % exc)
        return 2
    try:
        admission = render_admission(root)
    except RuntimeError as exc:
        print("adapter generation: error: %s" % exc)
        return 2
    sources = [
        (name, os.path.join(root, source_dir, name)) for name in files
    ]
    if check:
        return _check(root, source_dir, target_dir, files, admission)
    missing = [name for name, path in sources if not os.path.isfile(path)]
    if missing:
        print(
            "adapter generation: error: authoritative "
            "source(s) missing (%s); refusing to keep stale "
            "packaged copies" % ", ".join(missing)
        )
        return 2
    bodies: dict[str, bytes] = {}
    for name, source_path in sources:
        try:
            with open(source_path, "rb") as handle:
                bodies[name] = handle.read()
        except OSError as exc:
            print(
                "adapter generation: error: cannot read %s: %s"
                % (source_path, exc)
            )
            return 2
    bodies[ADMISSION_FILENAME] = admission
    source_base = os.path.join(root, source_dir)
    if not os.path.isdir(source_base):
        print(
            "adapter generation: error: authoritative source "
            "directory is missing: %s" % source_base
        )
        return 2
    admission_path = os.path.join(source_base, ADMISSION_FILENAME)
    if _read_optional(admission_path) != admission:
        try:
            with open(admission_path, "wb") as handle:
                handle.write(admission)
        except OSError as exc:
            print(
                "adapter generation: error: cannot write %s: %s"
                % (admission_path, exc)
            )
            return 2
        print(
            "adapter generation: %s/%s: regenerated (%s)"
            % (source_dir, ADMISSION_FILENAME, _sha12(admission))
        )
    else:
        print(
            "adapter generation: %s/%s: up-to-date (%s)"
            % (source_dir, ADMISSION_FILENAME, _sha12(admission))
        )
    target_base = os.path.join(root, target_dir)
    try:
        os.makedirs(target_base, exist_ok=True)
    except OSError as exc:
        print(
            "adapter generation: error: cannot create %s: %s"
            % (target_base, exc)
        )
        return 2
    for name in list(files) + [ADMISSION_FILENAME]:
        want = bodies[name]
        target_path = os.path.join(target_base, name)
        if _read_optional(target_path) == want:
            print(
                "adapter generation: %s: up-to-date (%s)"
                % (name, _sha12(want))
            )
            continue
        try:
            with open(target_path, "wb") as handle:
                handle.write(want)
        except OSError as exc:
            print(
                "adapter generation: error: cannot write %s: %s"
                % (target_path, exc)
            )
            return 2
        print(
            "adapter generation: %s: regenerated (%s)"
            % (name, _sha12(want))
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point; see the module docstring for exit codes."""
    args = list(sys.argv[1:] if argv is None else argv)
    root: str | None = None
    check = False
    positional: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--check":
            check = True
        elif arg == "--root":
            index += 1
            if index >= len(args):
                print("adapter generation: --root needs a directory")
                return 2
            root = args[index]
        elif arg in ("-h", "--help"):
            print(
                "usage: generate_adapter_resources.py "
                "[--root DIR] [--check]"
            )
            return 0
        elif arg.startswith("-"):
            print("adapter generation: unknown flag: %s" % arg)
            return 2
        else:
            positional.append(arg)
        index += 1
    if positional:
        print(
            "adapter generation: unexpected arguments: %s"
            % " ".join(positional)
        )
        return 2
    return generate(_repo_root(root), check=check)


if __name__ == "__main__":
    sys.exit(main())
