# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Live frontend oracle for ``modular.cfg`` import-path resolution.

Probes the pinned Mojo frontend's actual config-key resolution by
building a hello-world program under crafted ``MODULAR_HOME``
directories. Each case copies the installed ``modular.cfg``,
redirects only its cache directory into a temporary home, varies
the ``import_path`` key lines under test, and records whether the
real frontend resolves the standard library. The interesting
signal is the failure mode: a config the frontend reads as
selecting an empty directory fails with "unable to locate module
'std'", while a config selecting the installed library builds.
Every case also asserts the snapshot parser
(:func:`mojobpf.inputs.parse_cfg_import_path`) returns the same
selection, so the shared parse/rewrite rule is executable against
the frontend it must match -- in particular that
``import_path_alias`` is inert both alone and alongside the key.

Re-run from the repository root with the pinned toolchain on
``PATH`` (the project's Pixi environment provides it)::

    python3 -m pytest tests/unit/test_frontend_cfg_oracle.py -q

or directly as ``python3
tests/unit/test_frontend_cfg_oracle.py``. Without a ``mojo``
binary on ``PATH`` the test prints a skip notice and passes; with
a ``mojo`` whose version differs from the pinned one it fails so
the rule is re-validated before any re-pin. Hermetic: all homes,
sources, caches and outputs live under temporary directories
(removed afterwards), stdin is closed, each probe has a timeout,
and the install is only read. Takes about ten seconds.

Known frontend quirk, deliberately not probed here: a bare
``import_path`` line without ``=`` hangs the pinned frontend
instead of failing (it reads its config, then never schedules
work; killed by timeout). The snapshot parser treats such a
line as selecting nothing and stages it verbatim, so a build
through it stalls loudly at consumption rather than consuming
unattributed bytes. Manual repro: copy the installed config,
replace its ``import_path`` line with a bare ``import_path``
word, point ``MODULAR_HOME`` at the copy, and run ``mojo build``
on any hello-world program with stdin closed.
"""

import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

from mojobpf import inputs as inputs_module  # noqa: E402

PINNED_MOJO_VERSION = "1.1.0"
STD_MISSING_MARKER = "unable to locate module 'std'"
PROBE_TIMEOUT_S = 120
HELLO_SOURCE = 'def main():\n    print("hi")\n'


def _pinned_mojo():
    """Return the ``mojo`` binary on ``PATH``, if any."""
    return shutil.which("mojo")


def _check_pinned_version(mojo):
    # The asserted rule was observed against exactly this
    # frontend; a different version must re-validate, not
    # silently inherit the expectations.
    proc = subprocess.run(
        [mojo, "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )
    version = proc.stdout.decode("utf-8", "replace")
    assert PINNED_MOJO_VERSION in version, (
        "frontend oracle pinned to Mojo %s, found: %r; "
        "re-validate the selection rule before re-pinning"
        % (PINNED_MOJO_VERSION, version.strip())
    )


def _installed_cfg(env_root):
    path = os.path.join(env_root, "share", "max", "modular.cfg")
    with open(path, "rb") as handle:
        return handle.read()


def _is_import_path_line(line):
    key, sep, _value = line.strip().partition("=")
    return bool(sep) and key.strip().lower() == "import_path"


def _drop_key(lines):
    return [line for line in lines if not _is_import_path_line(line)]


def _set_key(lines, value, spell="import_path"):
    return [
        ("%s = %s" % (spell, value))
        if _is_import_path_line(line)
        else line
        for line in lines
    ]


def _run_probe(mojo, env_root, cfg_bytes, source):
    """Build ``source`` under a home carrying ``cfg_bytes``.

    Returns ``(exit_code, stderr, built)``. The home, cache and
    output all live under one temporary directory; the child
    environment is exactly the crafted home plus the install it
    reads, with stdin closed.
    """
    home = tempfile.mkdtemp(prefix="frontend-oracle-")
    try:
        with open(os.path.join(home, "modular.cfg"), "wb") as handle:
            handle.write(cfg_bytes)
        src_path = os.path.join(home, "hello.mojo")
        with open(src_path, "w", encoding="utf-8") as handle:
            handle.write(source)
        out_path = os.path.join(home, "hello-out")
        env = {
            "PATH": os.path.join(env_root, "bin")
            + ":/usr/bin:/bin",
            "MODULAR_HOME": home,
            "CONDA_PREFIX": env_root,
            "HOME": home,
        }
        try:
            proc = subprocess.run(
                [mojo, "build", src_path, "-o", out_path],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                timeout=PROBE_TIMEOUT_S,
                cwd=home,
            )
        except subprocess.TimeoutExpired:
            raise AssertionError(
                "mojo probe hung for %ds; refusing to stall "
                "the suite" % PROBE_TIMEOUT_S
            )
        stderr = proc.stderr.decode("utf-8", "replace")
        return proc.returncode, stderr, os.path.exists(out_path)
    finally:
        shutil.rmtree(home, ignore_errors=True)


def _cases(good, bad):
    """Yield ``(name, lines, ending, expect_ok, expect_sel)``.

    ``lines`` transforms the installed config lines (cache
    directory already redirected); ``expect_sel`` is the
    snapshot parser's required selection (``"good"``,
    ``"bad"`` or ``None``) and ``expect_ok`` the frontend's
    required build outcome.
    """
    return [
        ("baseline", lambda ls: ls, "\n", True, "good"),
        (
            "import-path-empty-dir",
            lambda ls: _set_key(ls, bad),
            "\n",
            False,
            "bad",
        ),
        ("no-key", _drop_key, "\n", False, None),
        (
            "alias-only",
            lambda ls: _drop_key(ls)
            + ["import_path_alias = " + good],
            "\n",
            False,
            None,
        ),
        (
            "key-bad-alias-good",
            lambda ls: _set_key(ls, bad)
            + ["import_path_alias = " + good],
            "\n",
            False,
            "bad",
        ),
        (
            "key-good-alias-bad",
            lambda ls: _set_key(ls, good)
            + ["import_path_alias = " + bad],
            "\n",
            True,
            "good",
        ),
        (
            "upper-key",
            lambda ls: _set_key(ls, good, "IMPORT_PATH"),
            "\n",
            True,
            "good",
        ),
        (
            "mixed-case-key",
            lambda ls: _set_key(ls, good, "Import_Path"),
            "\n",
            True,
            "good",
        ),
        (
            "cr-key",
            lambda ls: _set_key(ls, good),
            "\r",
            True,
            "good",
        ),
        (
            "crlf-key",
            lambda ls: _set_key(ls, good),
            "\r\n",
            True,
            "good",
        ),
        (
            "cr-alias-only",
            lambda ls: _drop_key(ls)
            + ["import_path_alias = " + good],
            "\r",
            False,
            None,
        ),
        (
            "empty-value",
            lambda ls: _set_key(ls, ""),
            "\n",
            False,
            None,
        ),
        (
            "last-good",
            lambda ls: _set_key(ls, bad)
            + ["import_path = " + good],
            "\n",
            True,
            "good",
        ),
        (
            "last-bad",
            lambda ls: _set_key(ls, good)
            + ["import_path = " + bad],
            "\n",
            False,
            "bad",
        ),
        (
            "last-empty-clears",
            lambda ls: _set_key(ls, good) + ["import_path = "],
            "\n",
            False,
            None,
        ),
        (
            "spaced-key",
            lambda ls: [
                ("  import_path   =   " + good + "   ")
                if _is_import_path_line(line)
                else line
                for line in ls
            ],
            "\n",
            True,
            "good",
        ),
        (
            "prefix-key",
            lambda ls: _drop_key(ls)
            + ["my_import_path = " + good],
            "\n",
            False,
            None,
        ),
        (
            "suffix-key",
            lambda ls: _drop_key(ls)
            + ["import_pathx = " + good],
            "\n",
            False,
            None,
        ),
    ]


def test_frontend_cfg_import_path_rule():
    # Live oracle: the pinned frontend resolves exactly the last
    # case-insensitive ``import_path`` line (CR, LF and CRLF all
    # split lines) and ignores ``import_path_alias`` and every
    # other spelling; an empty final value clears the selection
    # and no selection fails loudly. The snapshot parser must
    # agree on every crafted config.
    mojo = _pinned_mojo()
    if mojo is None:
        print("skip: no mojo binary on PATH for frontend oracle")
        return
    _check_pinned_version(mojo)
    env_root = os.path.dirname(os.path.dirname(mojo))
    installed = _installed_cfg(env_root).decode("utf-8")
    good = inputs_module.parse_cfg_import_path(
        installed.encode("utf-8")
    )
    assert good is not None and os.path.isdir(good), (
        "installed modular.cfg selects no usable library: %r" % good
    )
    bad = tempfile.mkdtemp(prefix="frontend-oracle-badlib-")
    try:
        for name, lines_fn, ending, expect_ok, expect_sel in _cases(
            good, bad
        ):
            scratch = tempfile.mkdtemp(prefix="frontend-oracle-")
            try:
                lines = [
                    (
                        "cache_dir = "
                        + os.path.join(scratch, "cache")
                    )
                    if line.strip().startswith("cache_dir")
                    else line
                    for line in installed.split("\n")
                ]
                text = ending.join(lines_fn(lines))
                if not text.endswith(ending):
                    text += ending
                cfg_bytes = text.encode("utf-8")
                wanted = {"good": good, "bad": bad, None: None}[
                    expect_sel
                ]
                parsed = inputs_module.parse_cfg_import_path(
                    cfg_bytes
                )
                assert parsed == wanted, (name, parsed, wanted)
                exit_code, stderr, built = _run_probe(
                    mojo, env_root, cfg_bytes, HELLO_SOURCE
                )
                if expect_ok:
                    assert exit_code == 0 and built, (
                        name,
                        exit_code,
                        stderr[-500:],
                    )
                    assert STD_MISSING_MARKER not in stderr, name
                else:
                    assert exit_code != 0, (name, exit_code)
                    assert STD_MISSING_MARKER in stderr, (
                        name,
                        exit_code,
                        stderr[-500:],
                    )
                    assert not built, name
            finally:
                shutil.rmtree(scratch, ignore_errors=True)
    finally:
        shutil.rmtree(bad, ignore_errors=True)


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
