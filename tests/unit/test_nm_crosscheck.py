# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the uprobe nm/readelf cross-check.

``crosscheck_nm_values`` (in the uprobe kernel suite) requires
both tools to name the same probe-symbol bytes. The positive
compiles two probe-named functions and resolves them end to
end; the negatives prove each refusal branch fires (missing
symbols, non-text symbols, address disagreement).

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3 tests/unit/test_nm_crosscheck.py``).
"""

import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "kernel"
    ),
)

import test_uprobe_register as uprobe  # noqa: E402

FUNCS_SOURCE = """\
int probe_target(int value) { return value + 1; }
int probe_never_called(int value) { return value + 2; }
int main(void) { return probe_target(41); }
"""

DATA_SOURCE = """\
int probe_target;
int probe_never_called;
int main(void) { return probe_target + probe_never_called; }
"""

HELLO_SOURCE = """\
int main(void) { return 0; }
"""


def _require_tools(*tools):
    for tool in tools:
        if shutil.which(tool) is None:
            raise AssertionError("%s not found on PATH" % tool)


def _compile(source, name):
    _require_tools("cc")
    root = tempfile.mkdtemp(prefix="nm-crosscheck-")
    src = os.path.join(root, name + ".c")
    out = os.path.join(root, name)
    with open(src, "w", encoding="utf-8") as handle:
        handle.write(source)
    proc = subprocess.run(
        ["cc", "-no-pie", "-fno-pie", "-O2", "-o", out, src],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return out


def _nm_values(path):
    _require_tools("nm")
    proc = subprocess.run(
        ["nm", path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    found = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in (
            "probe_target",
            "probe_never_called",
        ):
            found[parts[2]] = int(parts[0], 16)
    return found


def _assert_proof_failure(call, needle):
    try:
        call()
    except uprobe.ProofFailure as exc:
        assert needle in str(exc), str(exc)
        return
    raise AssertionError("expected ProofFailure %r" % needle)


def test_agreement_resolves_offsets():
    path = _compile(FUNCS_SOURCE, "funcs")
    offsets = uprobe.resolve_target_offsets(path)
    assert set(offsets) == {"probe_target", "probe_never_called"}
    assert offsets["probe_target"] != offsets["probe_never_called"]
    for offset in offsets.values():
        assert offset.startswith("0x"), offsets


def test_missing_symbols_refused():
    path = _compile(HELLO_SOURCE, "hello")
    _assert_proof_failure(
        lambda: uprobe.crosscheck_nm_values(
            path, {"probe_target": 1, "probe_never_called": 2}
        ),
        "nm is missing probe symbols",
    )


def test_non_text_symbols_refused():
    path = _compile(DATA_SOURCE, "data")
    found = _nm_values(path)
    assert set(found) == {"probe_target", "probe_never_called"}, found
    _assert_proof_failure(
        lambda: uprobe.crosscheck_nm_values(path, found),
        "as global text",
    )


def test_disagreement_refused():
    path = _compile(FUNCS_SOURCE, "funcs")
    found = _nm_values(path)
    assert set(found) == {"probe_target", "probe_never_called"}, found
    wrong = {name: value + 0x100 for name, value in found.items()}
    _assert_proof_failure(
        lambda: uprobe.crosscheck_nm_values(path, wrong),
        "nm/readelf disagree",
    )


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
