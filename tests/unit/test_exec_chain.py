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

from contextlib import contextmanager
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
from mojobpf import execution as execution_module  # noqa: E402
from mojobpf.toolchain import (  # noqa: E402
    _follow_exec_target as _product_follow,
)


def _write(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o755)


@contextmanager
def _fixture():
    with tempfile.TemporaryDirectory(prefix="exec-chain-test-") as root:
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
        yield {
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
    with _fixture() as fix:
        assert exec_chain.follow_exec_target(fix["one"]) == os.path.realpath(
            fix["binary"]
        )


def test_two_hop_launcher_resolves():
    with _fixture() as fix:
        assert exec_chain.follow_exec_target(fix["two"]) == os.path.realpath(
            fix["binary"]
        )


def test_launcher_to_direct_script_resolves_script():
    with tempfile.TemporaryDirectory(prefix="exec-chain-direct-") as root:
        target = os.path.join(root, "direct.sh")
        _write(target, "#!/bin/sh\necho direct\n")
        launcher = os.path.join(root, "launcher")
        _write(launcher, "#!/bin/sh\nexec \"%s\" \"$@\"\n" % target)
        assert exec_chain.follow_exec_target(launcher) == os.path.realpath(
            target
        )


def test_executed_image_has_no_chain():
    with _fixture() as fix:
        assert exec_chain.follow_exec_target(fix["binary"]) is None
        assert exec_chain.follow_exec_target(fix["script"]) is None


def test_ambiguous_launcher_fails_closed():
    with _fixture() as fix:
        assert exec_chain.follow_exec_target(fix["ambiguous"]) is None


def test_dangling_launcher_fails_closed():
    with _fixture() as fix:
        assert exec_chain.follow_exec_target(fix["dangling"]) is None


def test_unknown_variable_fails_closed():
    with _fixture() as fix:
        assert exec_chain.follow_exec_target(fix["unknown"]) is None


def test_cycle_fails_closed():
    with _fixture() as fix:
        assert exec_chain.follow_exec_target(fix["cycle"]) is None


def test_deep_chain_fails_closed():
    with _fixture() as fix:
        assert exec_chain.follow_exec_target(fix["deep"]) is None


def test_missing_entry_fails_closed():
    with _fixture() as fix:
        assert exec_chain.follow_exec_target(fix["missing"]) is None
        with tempfile.TemporaryDirectory(prefix="exec-chain-empty-") as empty:
            assert exec_chain.follow_exec_target(
                os.path.join(empty, "nope")
            ) is None


def test_product_resolver_parity():
    with _fixture() as fix:
        for name, path in sorted(fix.items()):
            assert exec_chain.follow_exec_target(path) == _product_follow(
                path
            ), name


def test_post_exec_assignment_does_not_shadow_the_target():
    # Assignments after the exec line never execute (the image is
    # already replaced), so neither resolver may read them: a
    # post-exec TARGET=decoy must not shadow the executed actual
    # image in either implementation.
    with tempfile.TemporaryDirectory(prefix="exec-chain-postexec-") as root:
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


def test_capture_records_every_hop():
    with _fixture() as fix:
        captured = execution_module.capture_chain(fix["two"])
        assert captured.form == execution_module.FORM_EXEC_LAUNCHER
        assert [hop.realpath for hop in captured.hops] == [
            os.path.realpath(fix["two"]),
            os.path.realpath(fix["one"]),
            os.path.realpath(fix["binary"]),
        ]
        assert captured.image.realpath == os.path.realpath(fix["binary"])
        assert captured.image.sha256 == captured.hops[-1].sha256
        for hop in captured.hops:
            assert len(hop.sha256) == 64, hop
            assert hop.ino > 0, hop


def test_capture_classifies_direct_forms():
    with _fixture() as fix:
        binary = execution_module.capture_chain(fix["binary"])
        assert binary.form == execution_module.FORM_BINARY
        assert binary.hops == ()
        assert binary.interpreter is None
        script = execution_module.capture_chain(fix["script"])
        assert script.form == execution_module.FORM_DIRECT_SCRIPT
        assert script.hops == ()
        assert script.interpreter == "/bin/sh", script


def test_capture_classifies_console_scripts():
    with tempfile.TemporaryDirectory(prefix="exec-chain-console-") as root:
        entry = os.path.join(root, "tool")
        _write(
            entry,
            "#!%s\nprint('hi')\n" % os.path.join(root, "python3"),
        )
        captured = execution_module.capture_chain(entry)
        assert captured.form == execution_module.FORM_CONSOLE_SCRIPT
        assert captured.hops == ()
        assert captured.image.realpath == os.path.realpath(entry)


def test_capture_rejects_path_resolved_interpreters():
    with tempfile.TemporaryDirectory(prefix="exec-chain-env-") as root:
        entry = os.path.join(root, "tool")
        _write(entry, "#!/usr/bin/env python3\nprint('hi')\n")
        captured = execution_module.capture_chain(entry)
        assert captured.form == execution_module.FORM_UNKNOWN
        assert "PATH" in captured.note, captured


def test_capture_rejects_unresolvable_continuations():
    with _fixture() as fix:
        for name in ("ambiguous", "dangling", "unknown", "cycle", "deep"):
            captured = execution_module.capture_chain(fix[name])
            assert captured.form == execution_module.FORM_UNKNOWN, name
            assert captured.note, name


def test_capture_rejects_conditional_wrappers():
    # A launcher whose assignments run through a conditional is
    # rejected: resolving it would mean guessing which branch
    # the shell takes.
    with tempfile.TemporaryDirectory(prefix="exec-chain-conditional-") as root:
        binary = os.path.join(root, "tool.bin")
        with open(binary, "wb") as handle:
            handle.write(b"\x7fELF" + b"\x00" * 60)
        other = os.path.join(root, "other.bin")
        with open(other, "wb") as handle:
            handle.write(b"\x7fELF" + b"\x00" * 60)
        wrapper = os.path.join(root, "wrapper")
        _write(
            wrapper,
            "#!/bin/sh\nTARGET=%s\nif true; then TARGET=%s; fi\n"
            "exec \"$TARGET\" \"$@\"\n" % (binary, other),
        )
        captured = execution_module.capture_chain(wrapper)
        assert captured.form == execution_module.FORM_UNKNOWN, captured
        assert "unsupported shell logic" in captured.note, captured


def test_capture_rejects_command_lines_in_launchers():
    # Any non-assignment line (command invocation, export, set)
    # in a launcher-shaped script is unsupported, never skipped.
    with tempfile.TemporaryDirectory(prefix="exec-chain-cmdline-") as root:
        binary = os.path.join(root, "tool.bin")
        with open(binary, "wb") as handle:
            handle.write(b"\x7fELF" + b"\x00" * 60)
        for extra in (
            "echo selecting the image\n",
            "export TARGET=%s\n" % binary,
            "set -e\n",
            "TARGET=`which tool`\n",
            "TARGET=$(which tool)\n",
        ):
            wrapper = os.path.join(
                root, "wrapper-%d" % abs(hash(extra))
            )
            _write(
                wrapper,
                "#!/bin/sh\nTARGET=%s\n%sexec \"$TARGET\" \"$@\"\n"
                % (binary, extra),
            )
            captured = execution_module.capture_chain(wrapper)
            assert captured.form == execution_module.FORM_UNKNOWN, (
                extra,
                captured,
            )
            assert "unsupported shell logic" in captured.note, (
                extra,
                captured,
            )


def test_capture_rejects_env_prefix_commands():
    # VAR=ok /path/cmd is a COMMAND whose executable the shell
    # runs, never a bare assignment: a launcher carrying one is
    # rejected, with the uncaptured executable named in the
    # note. Covers single and multiple prefixes, empty and
    # quoted values, and prefixes on the exec line itself.
    with tempfile.TemporaryDirectory(prefix="exec-chain-envprefix-") as root:
        binary = os.path.join(root, "tool.bin")
        with open(binary, "wb") as handle:
            handle.write(b"\x7fELF" + b"\x00" * 60)
        prog = os.path.join(root, "prog")
        _write(prog, "#!/bin/sh\necho marker\n")
        for extra in (
            "VAR=ok %s\n" % prog,
            "A=1 B=2 %s --flag\n" % prog,
            "VAR= %s\n" % prog,
            "VAR=\"a b\" %s\n" % prog,
        ):
            wrapper = os.path.join(
                root, "wrapper-%d" % abs(hash(extra))
            )
            _write(
                wrapper,
                "#!/bin/sh\nTARGET=%s\n%sexec \"$TARGET\" \"$@\"\n"
                % (binary, extra),
            )
            captured = execution_module.capture_chain(wrapper)
            assert captured.form == execution_module.FORM_UNKNOWN, (
                extra,
                captured,
            )
            assert "unsupported shell logic" in captured.note, (
                extra,
                captured,
            )
            assert prog in captured.note, (extra, captured)
        for line in (
            "exec VAR=ok \"%s\" \"$@\"\n" % binary,
            "exec A=1 B=2 \"%s\" \"$@\"\n" % binary,
            "exec VAR=ok\n",
        ):
            wrapper = os.path.join(
                root, "exec-%d" % abs(hash(line))
            )
            _write(wrapper, "#!/bin/sh\n%s" % line)
            captured = execution_module.capture_chain(wrapper)
            assert captured.form == execution_module.FORM_UNKNOWN, (
                line,
                captured,
            )


def test_bare_assignments_with_quotes_and_comments_still_admit():
    # Quoted values with spaces are still one word, and a
    # trailing comment does not make a second one: such lines
    # are bare assignments, and the launcher still resolves.
    with tempfile.TemporaryDirectory(prefix="exec-chain-assign-") as root:
        binary = os.path.join(root, "tool.bin")
        with open(binary, "wb") as handle:
            handle.write(b"\x7fELF" + b"\x00" * 60)
        wrapper = os.path.join(root, "wrapper")
        _write(
            wrapper,
            "#!/bin/sh\nLABEL=\"a b\" # gentle comment\nTARGET=%s\n"
            "exec \"$TARGET\" \"$@\"\n" % binary,
        )
        captured = execution_module.capture_chain(wrapper)
        assert captured.form == execution_module.FORM_EXEC_LAUNCHER, captured
        assert captured.image.realpath == os.path.realpath(binary), captured


def test_capture_rejects_pipelined_exec():
    # An exec line with pipeline/background/redirection operators
    # does not replace the shell image plainly; it is rejected.
    with tempfile.TemporaryDirectory(prefix="exec-chain-pipe-") as root:
        binary = os.path.join(root, "tool.bin")
        with open(binary, "wb") as handle:
            handle.write(b"\x7fELF" + b"\x00" * 60)
        for line in (
            "exec \"%s\" \"$@\" | cat\n" % binary,
            "exec \"%s\" \"$@\" &\n" % binary,
        ):
            wrapper = os.path.join(
                root, "wrapper-%d" % abs(hash(line))
            )
            _write(wrapper, "#!/bin/sh\n%s" % line)
            captured = execution_module.capture_chain(wrapper)
            assert captured.form == execution_module.FORM_UNKNOWN, (
                line,
                captured,
            )


def test_capture_rejects_expansion_variants_in_launchers():
    # The exact TRIGGER counterexample plus every expansion
    # spelling: backticks, $(...), $((...)), $[...], ${...}
    # side-effect forms and plain $refs in values are all
    # launcher-unknown. Arithmetic/command/process expansion
    # in any accepted position is forbidden, so no variant
    # admits with uncaptured behavior.
    with tempfile.TemporaryDirectory(prefix="exec-chain-expansion-") as root:
        binary = os.path.join(root, "tool.bin")
        with open(binary, "wb") as handle:
            handle.write(b"\x7fELF" + b"\x00" * 60)
        trigger = "array[$(/usr/bin/printf UNCAPTURED_COMMAND >&2)]"
        assignment_variants = [
            "A=$%s" % trigger,
            "A=$[1+1]",
            "A=$((1+1))",
            "A=$(/bin/echo hi)",
            "A=`/bin/echo hi`",
            "B=$A/z",
            "A=${A:-y}",
            "A=~/x",
            "A={a,b}",
            "A=a\\b",
        ]
        for variant in assignment_variants:
            wrapper = os.path.join(
                root, "wrapper-%d" % abs(hash(variant))
            )
            _write(
                wrapper,
                "#!/bin/sh\nA=x\n%s\nexec \"%s\" \"$@\"\n"
                % (variant, binary),
            )
            captured = execution_module.capture_chain(wrapper)
            assert captured.form == execution_module.FORM_UNKNOWN, (
                variant,
                captured,
            )
            assert "unsupported shell logic" in captured.note, (
                variant,
                captured,
            )
        exec_variants = [
            "exec \"%s\" $[1+1]" % binary,
            "exec \"%s\" $((1+1))" % binary,
            "exec \"%s\" $(/bin/echo hi)" % binary,
            "exec \"%s\" `/bin/echo hi`" % binary,
            "exec \"%s\" ${A:-y}" % binary,
            "exec \"%s\" ${A:=y}" % binary,
            "exec \"%s\" $1" % binary,
            "exec \"%s\" $$" % binary,
            "exec \"%s\" $@" % binary,
            "exec \"%s\" '$@'" % binary,
            "exec \"%s\" <(/bin/echo hi)" % binary,
            "exec ${A:-\"%s\"}" % binary,
            "exec $P\"x\"/tool",
            "exec '$P'/tool",
            "exec -c \"%s\"" % binary,
            "exec -a myname \"%s\"" % binary,
            "exec \"-c\" \"%s\"" % binary,
            "exec \"%s\" *" % binary,
            "exec \"%s\" ~/x" % binary,
            "exec \"%s\" # hi" % binary,
            "exec \"%s\" a!b" % binary,
            "exec \"%s\" {a,b}" % binary,
        ]
        for variant in exec_variants:
            wrapper = os.path.join(
                root, "exec-%d" % abs(hash(variant))
            )
            _write(wrapper, "#!/bin/sh\nP=/bin\n%s\n" % variant)
            captured = execution_module.capture_chain(wrapper)
            assert captured.form == execution_module.FORM_UNKNOWN, (
                variant,
                captured,
            )
            assert "unsupported shell logic" in captured.note, (
                variant,
                captured,
            )


def test_capture_rejects_relative_exec_targets():
    # A relative target (or a bare name) resolves against the
    # runtime working directory or PATH, so the shell selects
    # its image from where the spawn runs rather than from the
    # captured chain: rejected, never resolved against the
    # admission-time directory.
    with tempfile.TemporaryDirectory(prefix="exec-chain-relative-") as root:
        for variant in (
            "exec bin/tool",
            "exec tool",
            "exec\tbin/tool",
        ):
            wrapper = os.path.join(
                root, "wrapper-%d" % abs(hash(variant))
            )
            _write(wrapper, "#!/bin/sh\n%s\n" % variant)
            captured = execution_module.capture_chain(wrapper)
            assert captured.form == execution_module.FORM_UNKNOWN, (
                variant,
                captured,
            )
            assert "relative exec target" in captured.note, (
                variant,
                captured,
            )


def test_capture_rejects_trailing_backslash_lines():
    # A trailing backslash joins the next physical line in the
    # shell (even inside a comment) but parses separately
    # here, so the joined meaning is never guessed.
    with tempfile.TemporaryDirectory(prefix="exec-chain-continuation-") as root:
        binary = os.path.join(root, "tool.bin")
        with open(binary, "wb") as handle:
            handle.write(b"\x7fELF" + b"\x00" * 60)
        for variant in (
            "# a comment\\\n",
            "A=foo\\\n",
            "exec \"%s\" \\\n" % binary,
        ):
            wrapper = os.path.join(
                root, "wrapper-%d" % abs(hash(variant))
            )
            _write(
                wrapper,
                "#!/bin/sh\n%sexec \"%s\"\n" % (variant, binary),
            )
            captured = execution_module.capture_chain(wrapper)
            assert captured.form == execution_module.FORM_UNKNOWN, (
                variant,
                captured,
            )


def test_exact_launcher_grammar_still_admits_documented_forms():
    # Literal assignments (quoted values, glob characters that
    # stay literal on an assignment's right-hand side),
    # $NAME/${NAME} targets, literal args and "$@" passthrough
    # still resolve; a tab separates exec exactly like a space.
    with tempfile.TemporaryDirectory(prefix="exec-chain-grammar-") as root:
        binary = os.path.join(root, "tool.bin")
        with open(binary, "wb") as handle:
            handle.write(b"\x7fELF" + b"\x00" * 60)
        launchers = [
            "TC=%s\nexec \"$TC/tool.bin\" \"$@\"\n" % root,
            "TC=%s\nexec $TC/tool.bin\n" % root,
            "TC=%s\nexec ${TC}/tool.bin\n" % root,
            "exec \"%s\" --flag A=b\n" % binary,
            "exec\t\"%s\"\n" % binary,
            "LABEL=\"a b\"\nTC=%s\nexec \"$TC/tool.bin\" \"$@\"\n" % root,
            "A=/tmp/*\nTC=%s\nexec \"$TC/tool.bin\"\n" % root,
            "# leading comment\n\nTC=%s\n\nexec \"$TC/tool.bin\"\n" % root,
        ]
        for text in launchers:
            wrapper = os.path.join(
                root, "launcher-%d" % abs(hash(text))
            )
            _write(wrapper, "#!/bin/sh\n%s" % text)
            captured = execution_module.capture_chain(wrapper)
            assert captured.form == execution_module.FORM_EXEC_LAUNCHER, (
                text,
                captured,
            )
            assert captured.image.realpath == os.path.realpath(binary), (
                text,
                captured,
            )


def test_module_path_probe_reports_stdlib_names():
    # The isolated probe also reports the interpreter's own
    # standard-library inventory, which admission uses to
    # refuse declared roots shadowing it.
    interpreter = execution_module.identify_file(sys.executable)
    _roots, stdlib_names = execution_module._dump_interpreter_sys_path(
        interpreter, (), 60
    )
    if stdlib_names is None:
        print("skip: interpreter predates sys.stdlib_module_names")
        return
    for name in ("json", "os", "sys"):
        assert name in stdlib_names, stdlib_names


def test_direct_script_with_logic_still_runs_directly():
    # Scripts without an exec line run under their pinned
    # interpreter and may carry arbitrary logic; only
    # launcher-shaped scripts face the shell-logic restriction.
    with tempfile.TemporaryDirectory(prefix="exec-chain-direct-logic-") as root:
        script = os.path.join(root, "tool.sh")
        _write(
            script,
            "#!/bin/sh\nif true; then echo yes; fi\nexport A=b\n",
        )
        captured = execution_module.capture_chain(script)
        assert captured.form == execution_module.FORM_DIRECT_SCRIPT
        assert captured.interpreter == "/bin/sh", captured


def test_module_path_probe_executes_no_startup_code():
    # The interpreter module-path probe runs under -S: a
    # sitecustomize.py on the admitted module path leaves no
    # marker, while the admitted root is still reported.
    with tempfile.TemporaryDirectory(prefix="exec-chain-probe-") as root:
        evil = os.path.join(root, "evil")
        os.makedirs(evil)
        marker = os.path.join(root, "EXECUTED.marker")
        with open(os.path.join(evil, "sitecustomize.py"), "w") as handle:
            handle.write("open(%r, 'w').write('startup')\n" % marker)
        interpreter = execution_module.identify_file(sys.executable)
        roots, _stdlib_names = execution_module._dump_interpreter_sys_path(
            interpreter, (evil,), 60
        )
        assert evil in roots, roots
        assert not os.path.exists(marker), "probe executed startup code"


def test_module_path_probe_isolates_stdlib_imports():
    # The probe's own json import must resolve to the real
    # standard library, never to a declared-but-unverified root:
    # a json.py on the declared root leaves no marker, while
    # the declared root still heads the reported order.
    with tempfile.TemporaryDirectory(prefix="exec-chain-json-") as root:
        evil = os.path.join(root, "evil")
        os.makedirs(evil)
        marker = os.path.join(root, "EXECUTED.marker")
        with open(os.path.join(evil, "json.py"), "w") as handle:
            handle.write(
                "open(%r, 'w').write('shadow')\n"
                "raise RuntimeError('shadow')\n" % marker
            )
        interpreter = execution_module.identify_file(sys.executable)
        roots, _stdlib_names = execution_module._dump_interpreter_sys_path(
            interpreter, (evil,), 60
        )
        assert roots[0] == evil, roots
        assert not os.path.exists(marker), (
            "probe imported from an unverified root"
        )


def test_capture_image_agrees_with_follow():
    # Wherever the legacy resolver finds an image, the capture
    # names the same one; wherever it fails closed, the capture
    # is either a directly run form or unknown.
    with _fixture() as fix:
        for name, path in sorted(fix.items()):
            if name == "missing":
                continue
            followed = exec_chain.follow_exec_target(path)
            captured = execution_module.capture_chain(path)
            if followed is None:
                assert captured.form in (
                    execution_module.FORM_BINARY,
                    execution_module.FORM_DIRECT_SCRIPT,
                    execution_module.FORM_CONSOLE_SCRIPT,
                    execution_module.FORM_UNKNOWN,
                ), name
            else:
                assert captured.form == (
                    execution_module.FORM_EXEC_LAUNCHER
                ), name
                assert captured.image.realpath == followed, name


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
