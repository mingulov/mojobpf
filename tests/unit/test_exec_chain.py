# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the shared launcher exec-chain resolver.

Covers single-hop and two-hop launchers, scripts that run
directly, and every fail-closed shape (ambiguous, dangling,
cyclic, unknown-variable, over-depth, non-script, missing).
A parity battery asserts the harness resolver agrees with the
product's own resolver on every fixture, so the duplicates
cannot drift apart.

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3 tests/unit/test_exec_chain.py``).
"""

import os
import sys
import tempfile

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "harness"
    ),
)
sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

import exec_chain  # noqa: E402
from mojobpf.toolchain import (  # noqa: E402
    _follow_exec_target as _product_follow,
)


def _write(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o755)


def _fixture():
    root = tempfile.mkdtemp(prefix="exec-chain-test-")
    binary = os.path.join(root, "tool.bin")
    with open(binary, "wb") as handle:
        handle.write(b"\x7fELF" + b"\x00" * 60)
    script = os.path.join(root, "tool.sh")
    _write(script, "#!/bin/sh\necho tool\n")
    one = os.path.join(root, "one")
    _write(
        one,
        "#!/bin/sh\nTC=%s\nexec \"$TC/tool.bin\" \"$@\"\n" % root,
    )
    two = os.path.join(root, "two")
    _write(two, "#!/bin/sh\nexec \"%s\" \"$@\"\n" % one)
    ambiguous = os.path.join(root, "ambiguous")
    _write(
        ambiguous,
        "#!/bin/sh\nexec \"%s\" \"$@\"\nexec \"%s\" \"$@\"\n"
        % (binary, binary),
    )
    dangling = os.path.join(root, "dangling")
    _write(
        dangling,
        "#!/bin/sh\nexec \"%s\" \"$@\"\n"
        % os.path.join(root, "missing"),
    )
    unknown = os.path.join(root, "unknown")
    _write(unknown, "#!/bin/sh\nexec \"$NOWHERE/tool\" \"$@\"\n")
    cycle_a = os.path.join(root, "cycle-a")
    cycle_b = os.path.join(root, "cycle-b")
    _write(cycle_a, "#!/bin/sh\nexec \"%s\" \"$@\"\n" % cycle_b)
    _write(cycle_b, "#!/bin/sh\nexec \"%s\" \"$@\"\n" % cycle_a)
    deep_prev = binary
    for index in range(12):
        link = os.path.join(root, "deep-%02d" % index)
        _write(link, "#!/bin/sh\nexec \"%s\" \"$@\"\n" % deep_prev)
        deep_prev = link
    return {
        "binary": binary,
        "script": script,
        "one": one,
        "two": two,
        "ambiguous": ambiguous,
        "dangling": dangling,
        "unknown": unknown,
        "cycle": cycle_a,
        "deep": deep_prev,
        "missing": os.path.join(root, "missing"),
    }


def test_single_hop_launcher_resolves():
    fix = _fixture()
    assert exec_chain.follow_exec_target(fix["one"]) == os.path.realpath(
        fix["binary"]
    )


def test_two_hop_launcher_resolves():
    fix = _fixture()
    assert exec_chain.follow_exec_target(fix["two"]) == os.path.realpath(
        fix["binary"]
    )


def test_launcher_to_direct_script_resolves_script():
    root = tempfile.mkdtemp(prefix="exec-chain-direct-")
    target = os.path.join(root, "direct.sh")
    _write(target, "#!/bin/sh\necho direct\n")
    launcher = os.path.join(root, "launcher")
    _write(launcher, "#!/bin/sh\nexec \"%s\" \"$@\"\n" % target)
    assert exec_chain.follow_exec_target(launcher) == os.path.realpath(
        target
    )


def test_executed_image_has_no_chain():
    fix = _fixture()
    assert exec_chain.follow_exec_target(fix["binary"]) is None
    assert exec_chain.follow_exec_target(fix["script"]) is None


def test_ambiguous_launcher_fails_closed():
    fix = _fixture()
    assert exec_chain.follow_exec_target(fix["ambiguous"]) is None


def test_dangling_launcher_fails_closed():
    fix = _fixture()
    assert exec_chain.follow_exec_target(fix["dangling"]) is None


def test_unknown_variable_fails_closed():
    fix = _fixture()
    assert exec_chain.follow_exec_target(fix["unknown"]) is None


def test_cycle_fails_closed():
    fix = _fixture()
    assert exec_chain.follow_exec_target(fix["cycle"]) is None


def test_deep_chain_fails_closed():
    fix = _fixture()
    assert exec_chain.follow_exec_target(fix["deep"]) is None


def test_missing_entry_fails_closed():
    fix = _fixture()
    assert exec_chain.follow_exec_target(fix["missing"]) is None
    assert exec_chain.follow_exec_target(
        os.path.join(tempfile.mkdtemp(prefix="exec-chain-empty-"), "nope")
    ) is None


def test_product_resolver_parity():
    fix = _fixture()
    for name, path in sorted(fix.items()):
        assert exec_chain.follow_exec_target(path) == _product_follow(
            path
        ), name


def test_post_exec_assignment_does_not_shadow_the_target():
    # Assignments after the exec line never execute (the image is
    # already replaced), so neither resolver may read them: a
    # post-exec TARGET=decoy must not shadow the executed actual
    # image in either implementation.
    root = tempfile.mkdtemp(prefix="exec-chain-postexec-")
    actual = os.path.join(root, "actual.sh")
    decoy = os.path.join(root, "decoy.sh")
    _write(actual, "#!/bin/sh\necho actual\n")
    _write(decoy, "#!/bin/sh\necho decoy\n")
    launcher = os.path.join(root, "mojo")
    _write(
        launcher,
        "#!/bin/sh\nTARGET=%s\nexec \"$TARGET\" \"$@\"\nTARGET=%s\n"
        % (actual, decoy),
    )
    assert exec_chain.follow_exec_target(launcher) == os.path.realpath(
        actual
    )
    assert _product_follow(launcher) == os.path.realpath(actual)


def _direct_run():
    if not __debug__:
        print("REFUSED: must not run under python -O (asserts stripped)")
        return 2
    failures = 0
    names = sorted(
        name
        for name in globals()
        if name.startswith("test_") and callable(globals()[name])
    )
    for name in names:
        try:
            globals()[name]()
        except Exception:
            failures += 1
            print("FAIL %s" % name)
            import traceback

            traceback.print_exc()
        else:
            print("ok %s" % name)
    print("%d tests, %d failures" % (len(names), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_direct_run())
