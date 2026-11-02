# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Pin/ownership pairing controls for the B1-migrated suites.

The harness ownership validator admits a pin path only beneath
``<owned-root>/<token>``; a token that is not the pin dir's name
refuses every invocation at setup, before any oracle runs. This
control extracts each migrated suite's authored (pin, token) pair
and runs it through the real validator, so a future divergence
fails here instead of inside a guest.
"""
import ast
import os
import re
import sys

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(
    0, os.path.join(REPO_ROOT, "tests", "harness")
)

from bpf_test_run import validate_owned_pin  # noqa: E402

SUITES = [
    "tests/kernel/test_mojo_xdp.py",
    "tests/kernel/test_packet_sdk.py",
    "tests/kernel/test_parse_checksum_sdk.py",
    "tests/kernel/test_map_roundtrip.py",
    "tests/kernel/test_subprog_calls.py",
    "tests/kernel/test_array_maps.py",
    "tests/kernel/test_xdp_accounting.py",
    "tests/kernel/test_hash_maps.py",
    "tests/kernel/test_cleanup.py",
    "tests/kernel/test_arch_portability.py",
    "tests/verifier/test_subset_kernel.py",
]

VAR_VALUES = {"tag": "probe", "i": "1"}
VAR_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")


def _substitute(template, relpath):
    def _one(match):
        name = match.group(1)
        assert name in VAR_VALUES, (
            "%s: unhandled template variable $%s" % (relpath, name)
        )
        return VAR_VALUES[name]

    return VAR_RE.sub(_one, template)


def _flag_kwargs(relpath):
    """The suite's render_harness_flags keyword arguments."""
    with open(os.path.join(REPO_ROOT, relpath), encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else None
        if name != "render_harness_flags":
            continue
        kwargs = {}
        for keyword in node.keywords:
            assert isinstance(keyword.value, ast.Constant), (
                "%s: render_harness_flags %s must be a string "
                "constant" % (relpath, keyword.arg)
            )
            kwargs[keyword.arg] = keyword.value.value
        found.append(kwargs)
    assert len(found) == 1, (
        "%s: expected one render_harness_flags call, found %d"
        % (relpath, len(found))
    )
    return found[0]


def _guest_script(relpath):
    """The suite's raw guest template (placeholders intact)."""
    import importlib.util

    path = os.path.join(REPO_ROOT, relpath)
    stem = os.path.splitext(os.path.basename(path))[0]
    spec = importlib.util.spec_from_file_location(stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if stem == "test_cleanup":
        return module.REPEAT_GUEST_SCRIPT
    return module.GUEST_SCRIPT


def test_pin_dir_and_token_pair_and_validate():
    for relpath in SUITES:
        kwargs = _flag_kwargs(relpath)
        assert kwargs["pin_path"] == "$pin", (
            "%s: harness pin must be the shell $pin" % relpath
        )
        script = _guest_script(relpath)
        flags_at = script.find("{harness_flags}")
        assert flags_at >= 0, "%s: no {harness_flags}" % relpath
        assert script.find("{harness_flags}", flags_at + 1) < 0, (
            "%s: several harness invocations need per-site pairing"
            % relpath
        )
        pin_at = script.rfind('pin="/sys/fs/bpf/', 0, flags_at)
        assert pin_at >= 0, (
            "%s: no pin dir above the harness invocation" % relpath
        )
        pin_end = script.find('"', pin_at + len('pin="'))
        pin_template = script[pin_at + len('pin="'):pin_end]
        token_template = kwargs["ownership_token"]
        assert pin_template == "/sys/fs/bpf/" + token_template + "/prog", (
            "%s: pin %r is not beneath its ownership token %r"
            % (relpath, pin_template, token_template)
        )
        pin = _substitute(pin_template, relpath)
        token = _substitute(token_template, relpath)
        assert "$" not in pin and "$" not in token, (
            "%s: unsubstituted template variable" % relpath
        )
        note = validate_owned_pin(pin, kwargs["owned_root"], token)
        assert note is None, "%s: %s" % (relpath, note)
