# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Host-side unit tests for the B1 tool-admission helper.

Pin loading, staging admission and prologue rendering are
covered through this helper by the five packaging consumer
suites (migrated verbatim); these tests pin the new
harness-flag builders and the missing-tool classification.
"""

import json
import os
import shlex
import shutil
import sys
import tempfile

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)))
)

import tool_admission


def _direct_pins():
    return {
        "path": "/usr/bin/bpftool",
        "sha256": "1" * 64,
        "exec_path": None,
        "exec_link": None,
        "exec_sha256": None,
        "chain": [],
        "version": "bpftool v7.6.0",
    }


def _launcher_pins():
    pins = _direct_pins()
    pins["exec_path"] = "/usr/lib/bpftool-image"
    pins["exec_link"] = "/usr/bin/bpftool-link"
    pins["exec_sha256"] = "2" * 64
    pins["chain"] = [
        {
            "path": "/usr/bin/bpftool-link",
            "realpath": "/usr/lib/bpftool-image",
            "sha256": "3" * 64,
        }
    ]
    return pins


def test_harness_argv_direct_entry_omits_exec_flag():
    argv = tool_admission.harness_argv(
        _direct_pins(), pin_path="/sys/fs/bpf/p/prog",
        owned_root="/sys/fs/bpf", ownership_token="tok",
    )
    assert argv == [
        "--pin-path", "/sys/fs/bpf/p/prog",
        "--owned-root", "/sys/fs/bpf",
        "--ownership-token", "tok",
        "--bpftool", "/usr/bin/bpftool",
        "--bpftool-sha256", "1" * 64,
        "--bpftool-version", "bpftool v7.6.0",
    ]


def test_harness_argv_launcher_carries_exec_hash_verbatim():
    argv = tool_admission.harness_argv(
        _launcher_pins(), pin_path="/sys/fs/bpf/p/prog",
        owned_root="/sys/fs/bpf", ownership_token="tok",
    )
    assert "--bpftool-exec-sha256" in argv
    pos = argv.index("--bpftool-exec-sha256")
    assert argv[pos + 1] == "2" * 64
    # Exec flag sits between the entry hash and the version.
    assert argv.index("--bpftool-sha256") < pos
    assert pos < argv.index("--bpftool-version")


def test_render_harness_flags_quotes_but_keeps_vars_live():
    fragment = tool_admission.render_harness_flags(
        _direct_pins(), pin_path="$pin", owned_root="/sys/fs/bpf",
        ownership_token="xdp-$tag",
    )
    # Shell variables stay double-quoted (expand per case).
    assert '--pin-path "$pin"' in fragment
    assert '--ownership-token "xdp-$tag"' in fragment
    assert "--bpftool-sha256 %s" % ("1" * 64) in fragment


def test_render_harness_flags_refuses_quote_dollar_mix():
    try:
        tool_admission.render_harness_flags(
            _direct_pins(), pin_path='a$"b', owned_root="/sys/fs/bpf",
            ownership_token="tok",
        )
    except tool_admission.ToolAdmissionError as exc:
        assert "both $ and quote" in str(exc), exc
    else:
        raise AssertionError("half-quoted value admitted")


def test_render_harness_flags_quote_pins_metadata_literally():
    pins = _direct_pins()
    pins["path"] = "/opt/$weird/bpftool"
    fragment = tool_admission.render_harness_flags(
        pins, pin_path="$pin", owned_root="/sys/fs/bpf",
        ownership_token="xdp-$tag",
    )
    assert "--bpftool '/opt/$weird/bpftool'" in fragment


def test_render_harness_flags_quote_literal_templates_safely():
    for literal in ('a"b', "abc\\", "a b", "plain", "xdp-`id`", "we`ird"):
        fragment = tool_admission.render_harness_flags(
            _direct_pins(), pin_path="$pin",
            owned_root="/sys/fs/bpf", ownership_token=literal,
        )
        assert ("--ownership-token %s" % shlex.quote(literal)) in fragment


def test_render_harness_flags_refuse_template_substitution():
    for bad in (
        "xdp-$(touch /tmp/pwned)",
        "xdp-${tag}",
        "xdp-$$",
        "xdp-$tag-`id`",
        "xdp-$",
    ):
        try:
            tool_admission.render_harness_flags(
                _direct_pins(), pin_path="$pin",
                owned_root="/sys/fs/bpf", ownership_token=bad,
            )
        except tool_admission.ToolAdmissionError:
            continue
        raise AssertionError(
            "substitution syntax admitted: %r" % bad
        )


def test_render_prologue_propagates_granted_lease():
    saved = os.environ.get("MOJOBPF_TARGET_LEASE")
    try:
        os.environ["MOJOBPF_TARGET_LEASE"] = "1"
        prologue = tool_admission.render_prologue(_direct_pins())
    finally:
        if saved is None:
            os.environ.pop("MOJOBPF_TARGET_LEASE", None)
        else:
            os.environ["MOJOBPF_TARGET_LEASE"] = saved
    assert "export MOJOBPF_TARGET_LEASE=1" in prologue.splitlines(), (
        prologue
    )


def test_render_prologue_never_synthesizes_lease():
    for value in (None, "0", "", "yes"):
        saved = os.environ.get("MOJOBPF_TARGET_LEASE")
        try:
            if value is None:
                os.environ.pop("MOJOBPF_TARGET_LEASE", None)
            else:
                os.environ["MOJOBPF_TARGET_LEASE"] = value
            prologue = tool_admission.render_prologue(_direct_pins())
        finally:
            if saved is None:
                os.environ.pop("MOJOBPF_TARGET_LEASE", None)
            else:
                os.environ["MOJOBPF_TARGET_LEASE"] = saved
        assert "MOJOBPF_TARGET_LEASE" not in prologue, (value, prologue)


def test_render_prologue_mounts_bpffs_idempotently():
    prologue = tool_admission.render_prologue(_direct_pins())
    assert "mkdir -p /sys/fs/bpf 2>/dev/null || true" in (
        prologue.splitlines()
    )
    assert "mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true" in (
        prologue.splitlines()
    )


def test_stage_missing_path_is_tool_missing_admission():
    assert issubclass(
        tool_admission.ToolMissingError,
        tool_admission.ToolAdmissionError,
    )
    workdir = tempfile.mkdtemp(prefix="tool-admission-missing-")
    saved = os.environ.get(tool_admission.BPFTOOL_PINS_ENV)
    try:
        document = {
            "bpftool": {
                "exec_sha256": None,
                "sha256": "1" * 64,
                "version": "bpftool v7.6.0",
            },
            "generated_by": "host fixture (independent record)",
            "schema_version": 1,
            "status": "reviewed",
        }
        pins_path = os.path.join(workdir, "pins.json")
        with open(pins_path, "w", encoding="utf-8") as handle:
            json.dump(document, handle)
        os.environ[tool_admission.BPFTOOL_PINS_ENV] = pins_path
        emptydir = os.path.join(workdir, "empty-path")
        os.mkdir(emptydir)
        try:
            tool_admission.stage_tool_pins({"PATH": emptydir})
        except tool_admission.ToolMissingError as exc:
            assert "staging PATH" in str(exc), exc
        else:
            raise AssertionError("missing bpftool admitted")
    finally:
        if saved is None:
            os.environ.pop(tool_admission.BPFTOOL_PINS_ENV, None)
        else:
            os.environ[tool_admission.BPFTOOL_PINS_ENV] = saved
        shutil.rmtree(workdir, ignore_errors=True)
