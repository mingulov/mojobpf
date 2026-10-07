# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Unit tests for the helper capability/license registry.

Pins the registry version and table (seven profile helpers plus
the GPL-only witness), the lookup behavior over hostile input,
and the cross-layer agreement: the registry's admitted IDs equal
the target profile's helper IDs and the audit's lowered callee
IDs, while the witness is admitted nowhere.

Deterministic on any host: only the standard library plus pytest's
plain function collection.

Runnable under pytest (``python3 -m pytest tests/unit`` from the
repository root) or directly (``python3
tests/unit/test_helpers.py``).
"""

import importlib.util
import os
import re
import sys

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"
    ),
)

from mojobpf import helpers as helpers_module  # noqa: E402
from mojobpf.helpers import (  # noqa: E402
    HELPER_CAPABILITIES,
    HELPER_REGISTRY_VERSION,
    lookup_helper,
    profile_helper_ids,
)
from mojobpf import inspect as inspect_module  # noqa: E402
from mojobpf.manifest import lookup_profile  # noqa: E402

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
AUDIT_PATH = os.path.join(REPO_ROOT, "compiler", "audit.py")

# The full pinned table: (helper ID, kernel symbol, GPL-only, profiles).
PINNED_TABLE = (
    (1, "bpf_map_lookup_elem", False, ("linux-bpfel-v3",)),
    (2, "bpf_map_update_elem", False, ("linux-bpfel-v3",)),
    (3, "bpf_map_delete_elem", False, ("linux-bpfel-v3",)),
    (5, "bpf_ktime_get_ns", False, ("linux-bpfel-v3",)),
    (8, "bpf_get_smp_processor_id", False, ("linux-bpfel-v3",)),
    (14, "bpf_get_current_pid_tgid", False, ("linux-bpfel-v3",)),
    (35, "bpf_get_current_task", True, ()),
    (130, "bpf_ringbuf_output", False, ("linux-bpfel-v3",)),
)

PINNED_PROFILE_IDS = (1, 2, 3, 5, 8, 14, 130)


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_registry_version_pinned():
    assert HELPER_REGISTRY_VERSION == 1, HELPER_REGISTRY_VERSION


def test_registry_table_pinned():
    observed = tuple(
        (
            entry.helper_id,
            entry.kernel_name,
            entry.gpl_only,
            entry.profiles,
        )
        for entry in HELPER_CAPABILITIES
    )
    assert observed == PINNED_TABLE, observed


def test_registry_sorted_unique():
    ids = [entry.helper_id for entry in HELPER_CAPABILITIES]
    assert ids == sorted(ids), ids
    assert len(set(ids)) == len(ids), ids
    names = [entry.kernel_name for entry in HELPER_CAPABILITIES]
    assert len(set(names)) == len(names), names
    for entry in HELPER_CAPABILITIES:
        assert isinstance(entry.helper_id, int), entry
        assert isinstance(entry.gpl_only, bool), entry
        assert entry.summary, entry
        assert entry.kernel_name.startswith("bpf_"), entry


def test_registry_lookup():
    for helper_id, name, gpl_only, profiles in PINNED_TABLE:
        entry = lookup_helper(helper_id)
        assert entry is not None, helper_id
        assert entry.helper_id == helper_id
        assert entry.kernel_name == name
        assert entry.gpl_only is gpl_only
        assert entry.profiles == profiles


def test_registry_lookup_unknown_is_none():
    for unknown in (0, 4, 6, 7, 99, 1000, -1, "1", "35", None):
        assert lookup_helper(unknown) is None, unknown
    assert lookup_helper([35]) is None
    assert lookup_helper({"id": 35}) is None


def test_registry_witness_admitted_nowhere():
    witness = lookup_helper(35)
    assert witness is not None
    assert witness.gpl_only is True
    assert witness.profiles == ()
    for profile_id in ("linux-bpfel-v3", "no-such-profile"):
        assert 35 not in profile_helper_ids(profile_id), profile_id


def test_registry_profile_ids():
    assert profile_helper_ids("linux-bpfel-v3") == PINNED_PROFILE_IDS
    assert profile_helper_ids("no-such-profile") == ()


def test_registry_matches_manifest_profile():
    profile = lookup_profile("linux-bpfel-v3")
    assert profile.helper_ids == PINNED_PROFILE_IDS, profile.helper_ids
    assert profile_helper_ids(profile.profile_id) == profile.helper_ids


def test_registry_matches_audit_callees():
    audit = _load_module("audit_registry_check", AUDIT_PATH)
    lowered = set()
    for _name, callee in sorted(audit.LOWERED_CALLEE.items()):
        match = re.fullmatch(r"inttoptr \(i64 (\d+) to ptr\)", callee)
        assert match is not None, callee
        lowered.add(int(match.group(1)))
    assert lowered == set(PINNED_PROFILE_IDS), lowered
    assert 35 not in lowered, "the audit must still refuse the witness"


APACHE = "Apache-2.0 WITH LLVM-exception"
PROFILE = "linux-bpfel-v3"


def _expect_preflight_error(helper_ids, kernel_license):
    try:
        inspect_module.preflight_helper_licenses(
            helper_ids, kernel_license, PROFILE
        )
    except Exception as exc:  # noqa: BLE001 - assert the carried code
        assert exc.diagnostic.code == "MBPF709", exc.diagnostic
        assert exc.diagnostic.stage == "inspect.license", exc.diagnostic
        return exc
    raise AssertionError(
        "expected MBPF709 for %r under %r" % (helper_ids, kernel_license)
    )


def test_preflight_profile_helpers_pass():
    inspect_module.preflight_helper_licenses((), APACHE, PROFILE)
    inspect_module.preflight_helper_licenses(
        list(PINNED_PROFILE_IDS), APACHE, PROFILE
    )
    inspect_module.preflight_helper_licenses(
        list(PINNED_PROFILE_IDS), APACHE, lookup_profile(PROFILE)
    )


def test_preflight_witness_under_apache_fails():
    exc = _expect_preflight_error((35,), APACHE)
    explanation = exc.diagnostic.explanation
    assert "35" in explanation, explanation
    assert "bpf_get_current_task" in explanation, explanation
    assert repr(APACHE) in explanation, explanation
    assert PROFILE in explanation, explanation
    assert (
        exc.diagnostic.remedy == "restrict the program to non-GPL facilities"
    ), exc.diagnostic.remedy


def test_preflight_witness_mixed_with_profile_helpers():
    exc = _expect_preflight_error((1, 35, 130), APACHE)
    assert "bpf_get_current_task" in exc.diagnostic.explanation


def test_preflight_witness_first_offender_wins():
    exc = _expect_preflight_error((35, 35), APACHE)
    assert "helper 35" in exc.diagnostic.explanation


def test_preflight_skips_unrecorded_ids():
    # Availability is requires_gpl's verdict (MBPF706), not the
    # preflight's: unrecorded IDs pass through silently here.
    inspect_module.preflight_helper_licenses((7,), APACHE, PROFILE)
    inspect_module.preflight_helper_licenses((99,), APACHE, PROFILE)
    try:
        inspect_module.requires_gpl((7,), ("xdp",), (), PROFILE)
    except Exception as exc:  # noqa: BLE001 - assert the carried code
        assert exc.diagnostic.code == "MBPF706", exc.diagnostic
    else:
        raise AssertionError("expected MBPF706 for helper 7")


def test_preflight_gpl_recognized_declaration_passes():
    # Recognition passes the preflight; the pair gate still refuses
    # the unmapped GPL pair (the documented layering).
    inspect_module.preflight_helper_licenses((35,), "GPL", PROFILE)
    try:
        inspect_module.validate_declaration_pair(APACHE, "GPL")
    except Exception as exc:  # noqa: BLE001 - assert the carried code
        assert exc.diagnostic.code == "MBPF704", exc.diagnostic
    else:
        raise AssertionError("expected MBPF704 for the GPL pair")


def test_preflight_requires_string_declaration():
    try:
        inspect_module.preflight_helper_licenses((1,), None, PROFILE)
    except TypeError:
        pass
    else:
        raise AssertionError("expected TypeError for non-string license")


def test_preflight_unknown_profile():
    try:
        inspect_module.preflight_helper_licenses((1,), APACHE, "no-profile")
    except Exception as exc:  # noqa: BLE001 - assert the carried code
        assert exc.diagnostic.code == "MBPF101", exc.diagnostic
    else:
        raise AssertionError("expected MBPF101 for unknown profile")


def test_requires_gpl_witness_established():
    check = inspect_module.requires_gpl
    assert check((35,), ("tracepoint",), (), PROFILE) is True
    assert check((1, 35), ("xdp",), (), PROFILE) is True
    assert check((1, 2, 14), ("tracepoint",), (), PROFILE) is False


def _direct_names():
    return sorted(
        name
        for name in globals()
        if name.startswith("test_") and callable(globals()[name])
    )


def _direct_run():
    failures = 0
    for name in _direct_names():
        try:
            globals()[name]()
        except Exception:
            failures += 1
            print("FAIL %s" % name)
            import traceback

            traceback.print_exc()
        else:
            print("ok %s" % name)
    print("%d tests, %d failures" % (len(_direct_names()), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(_direct_run())
