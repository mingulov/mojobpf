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
import dataclasses
import importlib.machinery
import os
import shutil
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


def test_oversized_hop_fails_closed_like_product():
    # A hop past the 64KiB analysis window refuses in both
    # resolvers: the harness must never truncate and analyze a
    # prefix (a late exec line flips the form).
    with tempfile.TemporaryDirectory(prefix="exec-chain-huge-") as root:
        binary = os.path.join(root, "tool.bin")
        with open(binary, "wb") as handle:
            handle.write(b"\x7fELF" + b"\x00" * 60)
        hop = os.path.join(root, "hop")
        padding = "# pad\n" * 12000
        with open(hop, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\n%s\nexec \"%s\" \"$@\"\n" % (padding, binary))
        os.chmod(hop, 0o755)
        assert os.path.getsize(hop) > 65536, os.path.getsize(hop)
        launcher = os.path.join(root, "launcher")
        _write(launcher, "#!/bin/sh\nexec \"%s\" \"$@\"\n" % hop)
        assert exec_chain.follow_exec_target(launcher) is None
        captured = execution_module.capture_chain(launcher)
        assert captured.form == execution_module.FORM_UNKNOWN, captured


def test_exact_window_hop_resolves_in_both():
    # Boundary pin: a hop of exactly 64KiB still resolves in
    # both the harness and the product (no off-by-one refusal).
    with tempfile.TemporaryDirectory(prefix="exec-chain-edge-") as root:
        binary = os.path.join(root, "tool.bin")
        with open(binary, "wb") as handle:
            handle.write(b"\x7fELF" + b"\x00" * 60)
        hop = os.path.join(root, "hop")
        tail = "exec \"%s\" \"$@\"\n" % binary
        head = "#!/bin/sh\n"
        padding = "#" * (65536 - len(head) - len(tail) - 1) + "\n"
        with open(hop, "w", encoding="utf-8") as handle:
            handle.write(head + padding + tail)
        os.chmod(hop, 0o755)
        assert os.path.getsize(hop) == 65536, os.path.getsize(hop)
        launcher = os.path.join(root, "launcher")
        _write(launcher, "#!/bin/sh\nexec \"%s\" \"$@\"\n" % hop)
        assert exec_chain.follow_exec_target(launcher) == os.path.realpath(
            binary
        )
        captured = execution_module.capture_chain(launcher)
        assert captured.form == (
            execution_module.FORM_EXEC_LAUNCHER
        ), captured


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


def test_oversized_launcher_fails_closed_not_direct():
    # A launcher whose single exec line lies beyond the
    # analysis window must classify unknown (refused), never
    # direct-script: the kernel executes the late line that a
    # truncated read misses, so truncation must fail closed.
    with _fixture() as fix:
        target = fix["binary"]
        limit = execution_module._EXEC_SCRIPT_LIMIT
        launcher = os.path.join(os.path.dirname(target), "late-exec")
        _write(
            launcher,
            "#!/bin/sh\n"
            + "# padding\n" * (limit // 10 + 8)
            + "exec \"%s\" \"$@\"\n" % target,
        )
        assert os.path.getsize(launcher) > limit + 2
        captured = execution_module.capture_chain(launcher)
        assert captured.form == execution_module.FORM_UNKNOWN, captured


def test_window_boundary_launcher_still_admits():
    # A launcher that exactly fills the analysis window is
    # fully visible, so it still resolves (no over-refusal).
    with _fixture() as fix:
        target = fix["binary"]
        limit = execution_module._EXEC_SCRIPT_LIMIT
        exec_line = "exec \"%s\" \"$@\"\n" % target
        pad_len = limit + 2 - len("#!/bin/sh\n") - 1 - len(exec_line)
        assert pad_len > 0
        launcher = os.path.join(os.path.dirname(target), "edge-exec")
        _write(
            launcher,
            "#!/bin/sh\n" + "#" * pad_len + "\n" + exec_line,
        )
        assert os.path.getsize(launcher) == limit + 2
        captured = execution_module.capture_chain(launcher)
        assert captured.form == execution_module.FORM_EXEC_LAUNCHER, captured


def _startup_console_admission(parent, startup_files):
    """Build a console-script admission tree; return (request, pins).

    ``startup_files`` maps root-relative paths to byte payloads
    (parent dirs are created). The pinned module itself is
    always clean; only the listed startup spellings vary.
    """
    bindir = os.path.join(parent, "bin")
    root = os.path.join(parent, "root")
    os.makedirs(bindir)
    os.makedirs(root)
    entry = os.path.join(bindir, "tool")
    _write(entry, "#!%s\nprint('hi')\n" % sys.executable)
    mod_path = os.path.join(root, "pkgmod.py")
    with open(mod_path, "w", encoding="utf-8") as handle:
        handle.write("VALUE = 1\n")
    for relpath, payload in startup_files.items():
        full = os.path.join(root, relpath)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as handle:
            handle.write(payload)
    request = execution_module.ExecutionRequest(
        name="tool", argv0=entry, allow_path_lookup=False
    )
    pins = execution_module.ExecutionPins(
        entry_sha256=execution_module.sha256_file(entry),
        interpreter_sha256=execution_module.sha256_file(
            sys.executable
        ),
        interpreter_pin_present=True,
        modules=(("pkgmod", execution_module.sha256_file(mod_path)),),
        python_path=(root,),
    )
    return request, pins


def _startup_payload(parent, spelling):
    """Honest payload per spelling: importable where feasible."""
    if spelling.endswith(".pyc"):
        import py_compile
        src = os.path.join(parent, "site_src.py")
        with open(src, "w", encoding="utf-8") as handle:
            handle.write("VALUE = 2\n")
        compiled = os.path.join(parent, "site_compiled.pyc")
        py_compile.compile(src, cfile=compiled, doraise=True)
        with open(compiled, "rb") as handle:
            return handle.read()
    if spelling.endswith(".py"):
        return b"VALUE = 3\n"
    # Extension spellings: FileFinder resolves these by name
    # (see test_startup_spellings_are_finder_importable), so
    # placeholder bytes exercise the same guard path a hostile
    # build would trip; compiling a hostile .so adds no further
    # refusal signal.
    return b"placeholder-bytes"


def _startup_spellings():
    import importlib.machinery
    spellings = []
    for name in ("sitecustomize", "usercustomize"):
        spellings.append("%s.py" % name)
        spellings.append("%s.pyc" % name)
        spellings.append(os.path.join(name, "__init__.py"))
        spellings.append(os.path.join(name, "__init__.pyc"))
        for ext in importlib.machinery.EXTENSION_SUFFIXES:
            spellings.append("%s%s" % (name, ext))
            spellings.append(
                os.path.join(name, "__init__%s" % ext)
            )
    return spellings


def test_console_root_startup_spellings_refused():
    for spelling in _startup_spellings():
        with tempfile.TemporaryDirectory(
            prefix="exec-chain-startup-"
        ) as parent:
            payload = _startup_payload(parent, spelling)
            request, pins = _startup_console_admission(
                parent, {spelling: payload}
            )
            try:
                execution_module.admit_execution(request, pins)
            except execution_module.AdmissionError as exc:
                assert exc.reason == (
                    execution_module.REASON_MODULE_MISMATCH
                ), (spelling, exc)
                assert "startup" in str(exc), (spelling, exc)
            else:
                raise AssertionError(
                    "admitted root carrying %s" % spelling
                )


def test_startup_spellings_are_finder_importable():
    # Every refused spelling genuinely resolves through the
    # interpreter's FileFinder: the guard refuses real import
    # paths, not phantoms.
    import importlib.machinery
    hook = importlib.machinery.FileFinder.path_hook(
        (
            importlib.machinery.ExtensionFileLoader,
            importlib.machinery.EXTENSION_SUFFIXES,
        ),
        (
            importlib.machinery.SourceFileLoader,
            importlib.machinery.SOURCE_SUFFIXES,
        ),
        (
            importlib.machinery.SourcelessFileLoader,
            importlib.machinery.BYTECODE_SUFFIXES,
        ),
    )
    for spelling in _startup_spellings():
        with tempfile.TemporaryDirectory(
            prefix="exec-chain-startup-truth-"
        ) as parent:
            root = os.path.join(parent, "root")
            os.makedirs(root)
            payload = _startup_payload(parent, spelling)
            full = os.path.join(root, spelling)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as handle:
                handle.write(payload)
            name = spelling.split(os.path.sep)[0].split(".")[0]
            spec = hook(root).find_spec(name)
            assert spec is not None, spelling
            assert os.path.realpath(spec.origin) == os.path.realpath(
                full
            ), (spelling, spec.origin)


def test_console_root_clean_admits():
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-startup-clean-"
    ) as parent:
        request, pins = _startup_console_admission(parent, {})
        admitted = execution_module.admit_execution(request, pins)
        assert admitted.form == (
            execution_module.FORM_CONSOLE_SCRIPT
        ), admitted


def test_spawn_rescan_refuses_startup_planted_after_admission():
    # A startup file planted on an admitted root after admission
    # refuses at spawn time: the run records spawn failure and
    # the planted bytes never execute.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-rescan-"
    ) as parent:
        request, pins = _startup_console_admission(parent, {})
        admitted = execution_module.admit_execution(request, pins)
        root = pins.python_path[0]
        marker = os.path.join(parent, "RESCAN.marker")
        with open(
            os.path.join(root, "sitecustomize.py"), "w",
            encoding="utf-8",
        ) as handle:
            handle.write("open(%r, 'w').write('x')\n" % marker)
        record = execution_module.run_admitted(admitted, ())
        assert record.status == (
            execution_module.STATUS_SPAWN_FAILED
        ), record
        assert "sitecustomize.py" in record.log_excerpt, record
        assert not os.path.exists(marker), "planted bytes executed"


def test_spawn_rescan_ignores_inert_files():
    # Only startup spellings trip the spawn-time rescan: an
    # inert file planted after admission still spawns cleanly.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-rescan-clean-"
    ) as parent:
        request, pins = _startup_console_admission(parent, {})
        admitted = execution_module.admit_execution(request, pins)
        root = pins.python_path[0]
        with open(
            os.path.join(root, "notes.txt"), "w", encoding="utf-8"
        ) as handle:
            handle.write("notes\n")
        record = execution_module.run_admitted(admitted, ())
        assert record.status == "ok", record
        assert record.exit_code == 0, record


def test_console_root_namespace_startup_dir_admits():
    # Boundary pin: a bare sitecustomize/ directory with no
    # __init__ is a namespace package, which executes nothing on
    # import -- only executable spellings refuse.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-startup-ns-"
    ) as parent:
        request, pins = _startup_console_admission(
            parent, {
                os.path.join("sitecustomize", "notes.txt"): b"notes",
                os.path.join("usercustomize", "notes.txt"): b"notes",
            },
        )
        admitted = execution_module.admit_execution(request, pins)
        assert admitted.form == (
            execution_module.FORM_CONSOLE_SCRIPT
        ), admitted


def test_sha256_file_refuses_fifo_without_hanging():
    # A FIFO swapped in for a hashed path must refuse promptly,
    # never block on open: admission hashes untrusted paths.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-hash-fifo-"
    ) as parent:
        fifo = os.path.join(parent, "input")
        os.mkfifo(fifo)
        try:
            execution_module.sha256_file(fifo)
        except execution_module.NonRegularFileError:
            pass
        else:
            raise AssertionError("FIFO hashed instead of refused")


def test_sha256_file_hashes_regular_and_symlinked_files():
    # The bounded hash keeps its contract: regular files hash to
    # the streaming SHA-256, and a symlink to a regular file (the
    # admission layer binds link identity separately) still hashes.
    import hashlib

    with tempfile.TemporaryDirectory(
        prefix="exec-chain-hash-regular-"
    ) as parent:
        target = os.path.join(parent, "target.bin")
        payload = os.urandom(200000)
        with open(target, "wb") as handle:
            handle.write(payload)
        expected = hashlib.sha256(payload).hexdigest()
        assert (
            execution_module.sha256_file(target) == expected
        )
        link = os.path.join(parent, "link.bin")
        os.symlink(target, link)
        assert (
            execution_module.sha256_file(link) == expected
        )


def _hop_chain(parent, hop_shebang=None, hop_body=None):
    # Two-hop launcher: entry --exec--> hop1 --exec--> /bin/true.
    # hop1 runs through a test-owned interpreter copy so a swap
    # between admission and spawn is observable.
    interp = os.path.join(parent, "interp")
    shutil.copy("/bin/sh", interp)
    hop1 = os.path.join(parent, "hop1")
    _write(
        hop1,
        "#!%s\n%s\n" % (hop_shebang or interp, hop_body or "exec /bin/true"),
    )
    entry = os.path.join(parent, "entry")
    _write(entry, "#!/bin/sh\nexec \"%s\" \"$@\"\n" % hop1)
    request = execution_module.ExecutionRequest(
        name="hop",
        argv0=entry,
        allow_path_lookup=False,
        forms=(execution_module.FORM_EXEC_LAUNCHER,),
    )
    pins = execution_module.ExecutionPins(
        exec_sha256=execution_module.sha256_file("/bin/true"),
        exec_pin_present=True,
    )
    return request, pins, interp


def test_hop_interpreter_swap_refuses_spawn():
    # Swapping a hop script's interpreter after admission must
    # refuse the spawn: the swapped bytes must never execute.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-hop-interp-"
    ) as parent:
        request, pins, interp = _hop_chain(parent)
        admitted = execution_module.admit_execution(request, pins)
        assert admitted.form == (
            execution_module.FORM_EXEC_LAUNCHER
        ), admitted
        shutil.copy("/bin/false", interp)
        record = execution_module.run_admitted(admitted, ())
        assert record.status == (
            execution_module.STATUS_SPAWN_FAILED
        ), record
        assert "drifted since admission" in (
            record.log_excerpt
        ), record


def test_hop_interpreter_symlink_repoint_refuses_spawn():
    # Same-realpath dedup must not drop a distinct interpreter
    # path: a hop interpreter admitted through a symlink is
    # watched by path, so repointing the link after admission
    # refuses the spawn (round-5 MAJOR-1).
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-hop-link-"
    ) as parent:
        link = os.path.join(parent, "linksh")
        os.symlink("/bin/sh", link)
        hop1 = os.path.join(parent, "hop1")
        _write(hop1, "#!%s\nexec /bin/true\n" % link)
        entry = os.path.join(parent, "entry")
        _write(entry, "#!/bin/sh\nexec \"%s\" \"$@\"\n" % hop1)
        request = execution_module.ExecutionRequest(
            name="hop",
            argv0=entry,
            allow_path_lookup=False,
            forms=(execution_module.FORM_EXEC_LAUNCHER,),
        )
        pins = execution_module.ExecutionPins(
            exec_sha256=execution_module.sha256_file("/bin/true"),
            exec_pin_present=True,
        )
        admitted = execution_module.admit_execution(request, pins)
        marker = os.path.join(parent, "EVIL.marker")
        evil = os.path.join(parent, "evil")
        _write(evil, "#!/bin/sh\ntouch \"%s\"\n" % marker)
        os.remove(link)
        os.symlink(evil, link)
        record = execution_module.run_admitted(admitted, ())
        assert record.status == (
            execution_module.STATUS_SPAWN_FAILED
        ), record
        assert not os.path.exists(marker), "repointed bytes executed"


def test_hop_chain_without_swap_verifies_cleanly():
    # Static half of the split control (owner ruling
    # 2026-11-21): the shell spawn cannot execute under lane
    # supervision (a successful exec escapes the guard's hooks
    # by design, so no guarded shell-spawn reformulation
    # exists). The same two-hop chain admits, captures both
    # hops plus image and interpreter, and passes the real
    # verify_spawn -- the exact pre-spawn check run_admitted
    # runs. The runtime half below proves spawn mechanics
    # through a Python entry; together they keep the
    # swap-refusal tests non-vacuous.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-hop-clean-"
    ) as parent:
        request, pins, _interp = _hop_chain(parent)
        admitted = execution_module.admit_execution(request, pins)
        assert admitted.form == (
            execution_module.FORM_EXEC_LAUNCHER
        ), admitted
        hop1 = os.path.join(parent, "hop1")
        assert [hop.path for hop in admitted.hops] == [
            request.argv0, hop1, admitted.image.path,
        ], admitted.hops
        assert admitted.image.sha256 == pins.exec_sha256, admitted
        assert admitted.interpreter is not None, admitted
        assert len(admitted.hop_interpreters) == len(
            admitted.hops
        ), admitted
        execution_module.verify_spawn(admitted)
        # Vacuity guard: the same verification refuses once a
        # hop drifts, so the clean pass above is meaningful.
        _write(hop1, "#!/bin/sh\nexec /bin/false\n")
        try:
            execution_module.verify_spawn(admitted)
        except execution_module.AdmissionError as exc:
            assert exc.reason == (
                execution_module.REASON_SPAWN_REFUSED
            ), exc
            assert "drifted since admission" in exc.detail, exc
        else:
            raise AssertionError("drifted hop verified clean")


def _python_hop_chain(parent):
    # Two-hop Python chain: entry --execv--> hop1 --execv-->
    # final, exiting 42. Owned fixtures under private scratch;
    # os.execv lines are not exec spellings, so the entry
    # admits as a console script and the guard injects its
    # prelude at the entry spawn. Post-exec hops run
    # test-owned bytes (the guard cannot supervise past an
    # exec by design); chain integrity for shell launchers
    # is covered by the static half above.
    final = os.path.join(parent, "final_hop.py")
    _write(final, "#!%s\nraise SystemExit(42)\n" % sys.executable)
    hop1 = os.path.join(parent, "hop1.py")
    _write(
        hop1,
        "#!%s\nimport os\nos.execv(%r, [%r])\n"
        % (sys.executable, final, final),
    )
    entry = os.path.join(parent, "entry.py")
    _write(
        entry,
        "#!%s\nimport os\nos.execv(%r, [%r])\n"
        % (sys.executable, hop1, hop1),
    )
    request = execution_module.ExecutionRequest(
        name="hop-py",
        argv0=entry,
        allow_path_lookup=False,
        forms=(execution_module.FORM_CONSOLE_SCRIPT,),
    )
    pins = execution_module.ExecutionPins(
        entry_sha256=execution_module.sha256_file(entry),
        interpreter_sha256=execution_module.sha256_file(
            sys.executable
        ),
        interpreter_pin_present=True,
    )
    return request, pins


def test_python_hop_chain_without_swap_spawns_cleanly():
    # Runtime half of the split control: a clean two-hop
    # chain spawns through real os.execv transitions with
    # its exit code propagated. Exit 42 (not 0) proves the
    # exact final bytes ran to completion; a nonzero exit
    # is a step failure, so the status is failed (the
    # control proves transitions plus propagation).
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-hop-py-"
    ) as parent:
        request, pins = _python_hop_chain(parent)
        admitted = execution_module.admit_execution(request, pins)
        assert admitted.form == (
            execution_module.FORM_CONSOLE_SCRIPT
        ), admitted
        record = execution_module.run_admitted(admitted, ())
        assert record.status == (
            execution_module.STATUS_FAILED
        ), record
        assert record.exit_code == 42, record


def test_hop_with_env_interpreter_refuses_admission():
    # A hop naming a PATH-resolved interpreter is ambient-
    # dependent: refused at admission, like the entry rule.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-hop-env-"
    ) as parent:
        request, pins, _interp = _hop_chain(
            parent, hop_shebang="/usr/bin/env sh"
        )
        try:
            execution_module.admit_execution(request, pins)
        except execution_module.AdmissionError as exc:
            assert exc.reason == (
                execution_module.REASON_LAUNCHER_UNKNOWN
            ), exc
        else:
            raise AssertionError("env hop interpreter admitted")


def test_hop_with_dangling_interpreter_refuses_admission():
    # A hop naming an interpreter that cannot be identified
    # refuses at admission: there is no pin to bind it later.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-hop-dangling-"
    ) as parent:
        request, pins, _interp = _hop_chain(
            parent,
            hop_shebang=os.path.join(parent, "no-such-interp"),
        )
        try:
            execution_module.admit_execution(request, pins)
        except execution_module.AdmissionError as exc:
            assert exc.reason == (
                execution_module.REASON_UNREADABLE
            ), exc
        else:
            raise AssertionError("dangling hop interpreter admitted")


def test_image_interpreter_swap_refuses_spawn():
    # The terminus image may itself be a script: its
    # interpreter binds exactly like a hop interpreter.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-image-interp-"
    ) as parent:
        interp = os.path.join(parent, "interp")
        shutil.copy("/bin/sh", interp)
        final = os.path.join(parent, "final.sh")
        _write(final, "#!%s\nexit 0\n" % interp)
        entry = os.path.join(parent, "entry")
        _write(entry, "#!/bin/sh\nexec \"%s\" \"$@\"\n" % final)
        request = execution_module.ExecutionRequest(
            name="hop",
            argv0=entry,
            allow_path_lookup=False,
            forms=(execution_module.FORM_EXEC_LAUNCHER,),
        )
        pins = execution_module.ExecutionPins(
            exec_sha256=execution_module.sha256_file(final),
            exec_pin_present=True,
        )
        admitted = execution_module.admit_execution(request, pins)
        assert admitted.form == (
            execution_module.FORM_EXEC_LAUNCHER
        ), admitted
        shutil.copy("/bin/false", interp)
        record = execution_module.run_admitted(admitted, ())
        assert record.status == (
            execution_module.STATUS_SPAWN_FAILED
        ), record


def test_identify_file_nul_byte_refuses_admission_error():
    # An embedded NUL refuses as AdmissionError, not a raw
    # ValueError from lstat: hostile bytes fail closed.
    try:
        execution_module.identify_file(
            os.path.join("nope", "x\x00y")
        )
    except execution_module.AdmissionError as exc:
        assert exc.reason in (
            execution_module.REASON_NOT_FOUND,
            execution_module.REASON_UNREADABLE,
        ), exc
    else:
        raise AssertionError("NUL path identified")


def _startup_console_admission_unpinned_modules(parent):
    # Console admission with no pinned modules: python_path
    # roots are still validated, never passed through blind.
    request, pins = _startup_console_admission(parent, {})
    return request, dataclasses.replace(pins, modules=())


def test_admission_nul_root_refuses_admission_error():
    # A root with an embedded NUL refuses, not ValueError.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-nul-root-"
    ) as parent:
        request, pins = _startup_console_admission_unpinned_modules(
            parent
        )
        bad = dataclasses.replace(
            pins,
            python_path=(pins.python_path[0] + "\x00",),
        )
        try:
            execution_module.admit_execution(request, bad)
        except execution_module.AdmissionError as exc:
            assert exc.reason == (
                execution_module.REASON_MODULE_NOT_FOUND
            ), exc
        else:
            raise AssertionError("NUL root admitted")


def test_admission_relative_root_refuses_admission_error():
    # A relative root would resolve against the spawner's
    # cwd: refused instead of passed to the spawn env.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-rel-root-"
    ) as parent:
        request, pins = _startup_console_admission_unpinned_modules(
            parent
        )
        bad = dataclasses.replace(
            pins,
            python_path=("definitely/missing/relroot",),
        )
        try:
            execution_module.admit_execution(request, bad)
        except execution_module.AdmissionError as exc:
            assert exc.reason == (
                execution_module.REASON_MODULE_NOT_FOUND
            ), exc
        else:
            raise AssertionError("relative root admitted")


def test_admission_missing_root_refuses_admission_error():
    # A missing absolute root cannot be scanned or hashed:
    # refused instead of passed to the spawn env.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-missing-root-"
    ) as parent:
        request, pins = _startup_console_admission_unpinned_modules(
            parent
        )
        bad = dataclasses.replace(
            pins,
            python_path=(os.path.join(parent, "no-such-root"),),
        )
        try:
            execution_module.admit_execution(request, bad)
        except execution_module.AdmissionError as exc:
            assert exc.reason == (
                execution_module.REASON_MODULE_NOT_FOUND
            ), exc
        else:
            raise AssertionError("missing root admitted")


def test_admission_ignores_pyd_sibling():
    # A ``stem.pyd`` beside the pinned module can never be
    # selected on Linux (FileFinder has no .pyd suffix here),
    # so it admits instead of refusing as a shadow.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-pyd-sibling-"
    ) as parent:
        request, pins = _startup_console_admission(
            parent, {"pkgmod.pyd": b"not-an-extension"}
        )
        admitted = execution_module.admit_execution(request, pins)
        assert admitted.form == (
            execution_module.FORM_CONSOLE_SCRIPT
        ), admitted


def test_admission_ignores_uppercase_so_sibling():
    # Posix matching is case-sensitive: ``stem.SO`` never
    # selects, so it admits instead of refusing as a shadow.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-upper-so-"
    ) as parent:
        request, pins = _startup_console_admission(
            parent, {"pkgmod.SO": b"not-an-extension"}
        )
        admitted = execution_module.admit_execution(request, pins)
        assert admitted.form == (
            execution_module.FORM_CONSOLE_SCRIPT
        ), admitted


def test_admission_ignores_pyd_stdlib_shadow():
    # A stdlib-named ``.pyd`` is equally unselectable here.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-pyd-stdlib-"
    ) as parent:
        request, pins = _startup_console_admission(
            parent, {"json.pyd": b"not-an-extension"}
        )
        admitted = execution_module.admit_execution(request, pins)
        assert admitted.form == (
            execution_module.FORM_CONSOLE_SCRIPT
        ), admitted


def test_admission_refuses_bogus_tag_so_sibling():
    # Any ``stem.<tag>.so`` still refuses: tags vary across
    # interpreter versions the pin may name, so only exact
    # platform truth (.so case, no .pyd) is trusted, never a
    # tag allowlist that could rot.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-bogus-tag-"
    ) as parent:
        request, pins = _startup_console_admission(
            parent, {"pkgmod.bar.so": b"not-an-extension"}
        )
        try:
            execution_module.admit_execution(request, pins)
        except execution_module.AdmissionError as exc:
            assert exc.reason == (
                execution_module.REASON_MODULE_MISMATCH
            ), exc
        else:
            raise AssertionError("bogus-tag .so shadow admitted")


def test_admission_refuses_real_extension_sibling():
    # A true extension suffix beside the pinned source still
    # refuses: the tightening only drops spellings the file
    # finder can never select.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-real-ext-"
    ) as parent:
        request, pins = _startup_console_admission(
            parent,
            {
                "pkgmod"
                + importlib.machinery.EXTENSION_SUFFIXES[0]: (
                    b"not-an-extension"
                )
            },
        )
        try:
            execution_module.admit_execution(request, pins)
        except execution_module.AdmissionError as exc:
            assert exc.reason == (
                execution_module.REASON_MODULE_MISMATCH
            ), exc
        else:
            raise AssertionError("real extension shadow admitted")


def test_admission_ignores_pyd_startup_spelling():
    # ``sitecustomize.pyd`` can never be startup-imported on
    # Linux, so it admits instead of refusing as a startup
    # shadow.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-pyd-startup-"
    ) as parent:
        request, pins = _startup_console_admission(
            parent, {"sitecustomize.pyd": b"not-an-extension"}
        )
        admitted = execution_module.admit_execution(request, pins)
        assert admitted.form == (
            execution_module.FORM_CONSOLE_SCRIPT
        ), admitted


def test_admission_ignores_uppercase_so_startup_spelling():
    # ``sitecustomize.SO`` never selects on posix either.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-upper-startup-"
    ) as parent:
        request, pins = _startup_console_admission(
            parent, {"sitecustomize.SO": b"not-an-extension"}
        )
        admitted = execution_module.admit_execution(request, pins)
        assert admitted.form == (
            execution_module.FORM_CONSOLE_SCRIPT
        ), admitted


def test_record_import_stems_ignores_unselectable_suffixes():
    # RECORD entries the file finder can never select on
    # Linux (``.pyd``, upper-case ``.SO``/``.PY``/``.PYC``)
    # contribute no import stems; real spellings still do.
    record = (
        "a.pyd,,\n"
        "b.SO,,\n"
        "c.so,,\n"
        "d.py,,\n"
        "e.pyc,,\n"
        "f.PY,,\n"
        "g.PYC,,\n"
        "h.Py,,\n"
    )
    assert execution_module._record_import_stems(record) == [
        "c.so",
        "d",
        "e",
    ]


def test_local_shadow_ignores_unselectable_suffix_spellings():
    # Twin of the RECORD-stems suffix rule: ``.PY``/``.PYC``
    # entries never win import selection, so same-root
    # beaters beside them refuse nothing; real ``.py``/``.pyc``
    # spellings still refuse.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-local-shadow-case-"
    ) as dist_root:
        for name in (
            "w.pyc",
            "w.py",
            "x.PY",
            "x.cpython-311-x86_64-linux-gnu.so",
            "y.cpython-311-x86_64-linux-gnu.so",
            "y.py",
            "z.PYC",
            "z.py",
        ):
            with open(os.path.join(dist_root, name), "wb") as handle:
                handle.write(b"probe")
        execution_module._reject_dependency_local_shadow(
            "probe", "x.PY,,\n", dist_root, []
        )
        execution_module._reject_dependency_local_shadow(
            "probe", "z.PYC,,\n", dist_root, []
        )
        for rel in ("y.py,,\n", "w.pyc,,\n"):
            try:
                execution_module._reject_dependency_local_shadow(
                    "probe", rel, dist_root, []
                )
            except execution_module.AdmissionError as exc:
                assert exc.reason == (
                    execution_module.REASON_MODULE_MISMATCH
                ), exc
            else:
                raise AssertionError(
                    "same-root beater admitted for %r" % rel
                )


def test_admission_nonstring_root_refuses_admission_error():
    # A non-string root (hostile lock) refuses, not TypeError.
    with tempfile.TemporaryDirectory(
        prefix="exec-chain-nonstr-root-"
    ) as parent:
        request, pins = _startup_console_admission_unpinned_modules(
            parent
        )
        bad = dataclasses.replace(pins, python_path=(5,))
        try:
            execution_module.admit_execution(request, bad)
        except execution_module.AdmissionError as exc:
            assert exc.reason == (
                execution_module.REASON_MODULE_NOT_FOUND
            ), exc
        else:
            raise AssertionError("non-string root admitted")


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
