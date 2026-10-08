# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Single source of truth for tree-to-package mirror pairs.

``compiler/`` is the source of truth for the three adapter
scripts; ``src/mojobpf/resources/adapter/`` carries the
byte-identical distributed copies the wheel ships. Both the fast
mirror check (``tests/unit/test_mirror_sync.py``) and the wheel
contract (``tests/packaging/test_wheel_contents.py``) consume this
table, so a new, removed, or renamed mirrored file fails in one
place until the pin is reviewed.

Standard library only. Imported host-side (``sys.path``-relative
to this directory); never staged into a guest.
"""

import os


# Wheel path -> tree path for byte-identity checks.
SYNCED_FILES = (
    (
        "mojobpf/resources/adapter/adapter_service.py",
        "compiler/adapter_service.py",
    ),
    ("mojobpf/resources/adapter/audit.py", "compiler/audit.py"),
    (
        "mojobpf/resources/adapter/mojo_ir_adapter.py",
        "compiler/mojo_ir_adapter.py",
    ),
)


class MirrorDriftError(Exception):
    """One or more packaged copies drifted from ``compiler/``."""


def packaged_path(repo_root, shipped):
    """Tree path of the packaged copy of wheel entry ``shipped``."""
    return os.path.join(
        repo_root, "src", "mojobpf", shipped[len("mojobpf/"):]
    )


def check_tree_mirrors(repo_root):
    """Fail unless every packaged copy matches its ``compiler/`` source.

    Returns the checked pair count. A missing file fails the same
    way drift does: the mirror is either byte-identical or broken.
    """
    drifted = []
    for shipped, source in SYNCED_FILES:
        try:
            with open(
                os.path.join(repo_root, source), "rb"
            ) as handle:
                want = handle.read()
        except OSError as exc:
            drifted.append("%s (source unreadable: %s)" % (source, exc))
            continue
        try:
            with open(packaged_path(repo_root, shipped), "rb") as handle:
                got = handle.read()
        except OSError as exc:
            drifted.append("%s (copy unreadable: %s)" % (shipped, exc))
            continue
        if got != want:
            drifted.append(shipped)
    if drifted:
        raise MirrorDriftError(
            "packaged copies drifted from compiler/: %s"
            % ", ".join(drifted)
        )
    return len(SYNCED_FILES)
