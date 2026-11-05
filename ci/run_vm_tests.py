# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Two-lane VM matrix runner for the kernel proof suites.

Runs every guest-backed suite (the kernel suites including the
tracepoint/event/lifecycle tracing proofs, the verifier kernel
and license suites, the external-consumer suite, and the
cleanup suite) in each lane pinned by ``ci/kernels.lock.json``
with the same committed source tree, and reports one board. The tree must be committed first:
a dirty tree is refused up front so both lanes provably test the
same bits. A lane whose cached kernel image is absent fails the run;
lanes are never silently skipped.

Each suite boots its own disposable guests through ``vng`` (software
emulation, as pinned); the host itself only compiles. Lane selection
reaches the suites through ``MOJOBPF_VNG_RELEASE``; every suite
defaults to the primary lane when the variable is unset, so
standalone runs are unchanged.

Usage::

    python3 ci/run_vm_tests.py [--lock ci/kernels.lock.json]
        [--lane v6.12-tcg] [--suite kernel-xdp] [--out-dir DIR]
        [--timeout SECS] [--consumer-path DIR]

The ``packaging-*`` consumer suites build with an independently
installed toolchain that must resolve outside the checkout;
``--consumer-path`` prepends directories to PATH for those suites
only (every other suite uses the ambient toolchain). Without it
each consumer suite fails on its own isolation gate -- never
skipped, never faked.

Exit codes: 0 when every selected suite passed in every selected
lane; 1 when any suite failed or reported an environment failure;
2 for setup problems (dirty tree, runner/QEMU mismatch, consumer
PATH shadowing the locked runner, missing lane cache, bad
lockfile). Skips never occur: an unrun lane or suite is a
failure, not a pass.

Suites report through the structured result protocol, not line
scraping: each suite seals a ``test-contracts-v1`` run plan,
emits one case result per case, and ends with a terminal
``suite-result-v1`` record (single-line ``MOJOBPF_*`` JSON
documents on stdout). The matrix re-parses and re-aggregates
these records against its own pins -- the expected case IDs per
suite (``SUITE_CASES``), the matrix commit, the suite file
bytes, and the lane target manifest -- and judges the suite by
the recomputed verdict. ``PASS``/``FAIL``/``ENVIRONMENT
FAILURE`` lines remain in the logs as human evidence only. A
suite with a missing, duplicated, truncated or non-verifying
terminal record fails; a forged PASS without records fails; the
suite exit must agree with its own verdict (0/PASS, 1/FAIL,
2-or-3/INCOMPLETE), and a suite that dies by signal or times
out keeps its signed exit and fails. Timeout is its own
fail-closed outcome, never a pass and never envfail.

The runner, its launcher and its emulator are admitted through
``execution-contract-v1`` before any suite starts: the ``vng``
entry, its ``exec`` chain, the console-script interpreter, the
runner package modules, the ``virtme-run`` launcher ``vng``
invokes through a shell plus its ``virtme.*`` implementation,
and the QEMU image are all hash-checked against the lock, and
the lock's distribution bindings are enforced. Suites run with
a farm-first ``PATH`` plus stripped import-path, loader and
shell-startup variables so ambient shadows can never substitute
the admitted chain.

Standard library plus the first-party ``mojobpf`` package.
"""

import argparse
import atexit
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_LOCK = os.path.join(REPO_ROOT, "ci", "kernels.lock.json")

sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from mojobpf import execution as execution_mod  # noqa: E402
from mojobpf import validation as validation_mod  # noqa: E402
from mojobpf.validation.aggregate import (  # noqa: E402
    verify_suite_result,
)

# (suite id, path relative to the checkout, guest timeout seconds).
SUITES = (
    ("kernel-xdp", "tests/kernel/test_mojo_xdp.py", 1500),
    ("kernel-map", "tests/kernel/test_map_roundtrip.py", 1500),
    ("kernel-packet", "tests/kernel/test_packet_sdk.py", 1500),
    ("kernel-parse", "tests/kernel/test_parse_checksum_sdk.py", 1500),
    ("kernel-array", "tests/kernel/test_array_maps.py", 1500),
    ("kernel-percpu", "tests/kernel/test_percpu_maps.py", 1500),
    ("kernel-accounting", "tests/kernel/test_xdp_accounting.py", 1500),
    ("kernel-generalized", "tests/kernel/test_generalized_arrays.py", 1500),
    ("kernel-mojopercpu", "tests/kernel/test_mojo_percpu.py", 1500),
    ("kernel-tracepoint", "tests/kernel/test_tracepoint_counter.py", 1500),
    ("kernel-events", "tests/kernel/test_tracepoint_events.py", 1500),
    ("kernel-tracing-lifecycle", "tests/kernel/test_tracing_lifecycle.py", 1800),
    ("verifier-subset", "tests/verifier/test_subset_kernel.py", 1500),
    ("verifier-licenses", "tests/verifier/test_helper_licenses.py", 1500),
    ("packaging-consumer", "tests/packaging/test_external_consumer.py", 2400),
    ("packaging-hash-consumer", "tests/packaging/test_hash_consumer.py", 2400),
    ("packaging-reserve-consumer",
     "tests/packaging/test_reserve_consumer.py", 2400),
    ("packaging-subprog-consumer",
     "tests/packaging/test_subprog_consumer.py", 2400),
    ("packaging-uprobe-consumer",
     "tests/packaging/test_uprobe_consumer.py", 2400),
    ("kernel-core-layouts", "tests/kernel/test_core_layouts.py", 1800),
    ("kernel-hash", "tests/kernel/test_hash_maps.py", 1800),
    ("kernel-ringbuf", "tests/kernel/test_ringbuf_reserve.py", 1800),
    ("kernel-subprog", "tests/kernel/test_subprog_calls.py", 1800),
    ("kernel-uprobe", "tests/kernel/test_uprobe_register.py", 1800),
    ("kernel-cleanup", "tests/kernel/test_cleanup.py", 1800),
    ("kernel-joint", "tests/kernel/test_joint_stack.py", 1500),
    ("kernel-net", "tests/kernel/test_net_classifier.py", 1500),
    ("kernel-lru", "tests/kernel/test_lru_maps.py", 1800),
)

# Pinned plan case IDs per suite (the matrix's independent
# expectation: a plan omitting or adding IDs is rejected).
# Board suites append their assertive board phase as "board".
# A sync test pins these against the suite sources; changing
# a suite's tests without updating the pin fails loudly.
SUITE_CASES = {
    "kernel-xdp": (
        "test_base_packet_actions test_fixture_bytes test_guest_provenance  "
        "test_mutation_changes_behavior test_stale_object_fails"
    ).split(),
    "kernel-map": (
        "test_guest_provenance test_map_roundtrip_42  "
        "test_mutation_changes_value test_oob_rejected_by_verifier  "
        "test_stale_object_fails test_unchecked_rejected_by_verifier"
    ).split(),
    "kernel-packet": (
        "test_boundary_frames test_cursor_actions test_fixed_byte_actions  "
        "test_frame_bytes test_guard_paths test_guest_provenance  "
        "test_half_actions test_negatives_rejected_by_verifier  "
        "test_scalar_endian_actions test_scalar_guard_edge_actions  "
        "test_short_guard_actions test_var_offset_actions  "
        "test_word_actions"
    ).split(),
    "kernel-parse": (
        "test_checksum_actions test_checksum_exactness test_eth_actions  "
        "test_frame_bytes test_guard_paths test_guest_provenance  "
        "test_trunc_actions test_vlan_actions"
    ).split(),
    "kernel-array": (
        "test_delete_refused_and_entry_survives  "
        "test_exact_counts_after_quiescence test_first_and_last_key  "
        "test_guest_provenance test_invalid_keys_refused  "
        "test_invalid_sizes_refused test_lifecycle_init_run_observe  "
        "test_oob_rejected_by_verifier test_unchecked_rejected_by_verifier"
    ).split(),
    "kernel-percpu": (
        "test_bad_key_and_delete_refused  "
        "test_broadcast_update_replaces_all_cpus  "
        "test_decode_bpftool_dump_shape  "
        "test_decode_padded_values_skips_padding  "
        "test_decode_unpadded_values test_dumps_stable_after_quiescence  "
        "test_expected_buffer_round_trip test_first_to_last_key_walk  "
        "test_guest_cpu_facts_agree test_guest_provenance_and_cleanup  "
        "test_invalid_sizes_refused test_map_identity_per_kind  "
        "test_parse_possible_list_forms test_percpu_stride_padding  "
        "test_u32_padding_exact test_u64_exact_per_cpu_values  "
        "test_u64_exact_totals_and_byte_sums"
    ).split(),
    "kernel-accounting": (
        "test_c_reference_matches_oracle test_classifier_matches_oracle  "
        "test_combined_matches_oracle test_corpus_byte_total  "
        "test_counter_accumulates_exactly  "
        "test_counter_divergence_pinned_to_drops test_guest_provenance  "
        "test_mutants_detected_in_guest  "
        "test_relocation_mutant_rejected_by_loader test_sidecarless_loads"
    ).split(),
    "kernel-generalized": (
        "test_delete_refused_four_entries test_delete_refused_one_entry  "
        "test_delete_refused_three_entries test_delete_refused_two_entries  "
        "test_first_last_walk_four_entries  "
        "test_first_last_walk_three_entries  "
        "test_first_last_walk_two_entries  "
        "test_guest_provenance_and_cleanup  "
        "test_invalid_keys_sizes_four_entries  "
        "test_invalid_keys_sizes_three_entries  "
        "test_invalid_keys_sizes_two_entries  "
        "test_rmw_exact_counts_four_entries  "
        "test_rmw_exact_counts_three_entries  "
        "test_rmw_exact_counts_two_entries test_rmw_lifecycle_four_entries  "
        "test_rmw_lifecycle_three_entries test_rmw_lifecycle_two_entries"
    ).split(),
    "kernel-mojopercpu": (
        "test_combined_counts_both_paths test_cpu_facts_agree  "
        "test_decode_bpftool_dump_shape test_decode_values_exact  "
        "test_delete_refused_four_entries test_delete_refused_one_entry  "
        "test_delete_refused_three_entries test_delete_refused_two_entries  "
        "test_guest_provenance_and_cleanup test_parse_possible_list_forms  "
        "test_percpu_stride_padding test_rmw_exact_counts_four_entries  "
        "test_rmw_exact_counts_one_entry  "
        "test_rmw_exact_counts_three_entries  "
        "test_rmw_exact_counts_two_entries test_rmw_lifecycle_four_entries  "
        "test_rmw_lifecycle_one_entry test_rmw_lifecycle_three_entries  "
        "test_rmw_lifecycle_two_entries"
    ).split(),
    "kernel-tracepoint": (
        "test_exact_count test_excluded_phase_zero  "
        "test_guest_provenance  "
        "test_missing_tracepoint_unavailability  "
        "test_tgid_mutant_mismatch_and_stale_base  "
        "test_wrong_filter_mismatch board"
    ).split(),
    "kernel-events": (
        "test_control_pattern_reproduced  "
        "test_crash_keeps_position_no_kernel_loss  "
        "test_healthy_exact_accounting test_saturation_explicit_loss  "
        "test_tgid_mutant_zeroes_and_stale_reloads  "
        "test_v2_decoder_rejects_live_records board"
    ).split(),
    "kernel-tracing-lifecycle": (
        "test_attach_failures_classified test_failsafe_arena_lane_verdict  "
        "test_failsafe_event_preflight test_failsafe_map_preflight  "
        "test_failsafe_negative_controls test_guest_provenance  "
        "test_holder_interruption test_matrix_timeout_reaps_detached_guest  "
        "test_midrun_oracle_rejects_completed_workload  "
        "test_process_exit_exact test_repeated_runs_cleanup  "
        "test_runner_cancels_owned_group_on_timeout  "
        "test_workload_interruption board"
    ).split(),
    "verifier-subset": (
        "test_call_inline test_casts test_checked_arith  "
        "test_guest_provenance test_loop_pressure test_loop_sum  "
        "test_oob_store_rejected_by_verifier test_stack_array"
    ).split(),
    "verifier-licenses": (
        "test_counter_gate_verdict test_declaration_never_rewritten  "
        "test_fixture_build_portable test_guest_provenance  "
        "test_kernel_rejects_gpl_only_helper  "
        "test_matrix_timeout_reaps_detached_guest  "
        "test_registry_names_witness_gpl_only  "
        "test_runner_cancels_owned_group_on_timeout  "
        "test_witness_gate_verdict board"
    ).split(),
    "packaging-consumer": (
        "test_build_fails_without_installed_package  "
        "test_consumer_admission_probes_the_captured_image  "
        "test_consumer_admission_refuses_swap_after_capture  "
        "test_consumer_admission_refuses_swap_before_capture  "
        "test_consumer_admission_rejects_replacement  "
        "test_consumer_admission_rejects_unapproved_chain  "
        "test_consumer_admission_rejects_unresolvable_chain  "
        "test_consumer_admission_spawns_only_through_the_contract  "
        "test_consumer_admits_independent_prefix  "
        "test_consumer_bootstrap_without_independent_pins  "
        "test_consumer_builds_through_admitted_prefix  "
        "test_consumer_builds_with_installed_tool  "
        "test_consumer_exact_kernel_result test_consumer_guest_provenance  "
        "test_consumer_has_no_copy_no_path_back  "
        "test_consumer_imports_only_the_sdk_surface  "
        "test_consumer_independent_pins_require_reviewed_status  "
        "test_consumer_lock_declares_trust  "
        "test_consumer_lockfile_schema_for_build  "
        "test_consumer_object_compiled_from_own_source  "
        "test_consumer_prefix_replaces_ambient_probe  "
        "test_consumer_probe_refuses_swap_before_probe  "
        "test_consumer_self_pin_is_not_a_trust_root  "
        "test_consumer_standard_runner_passes  "
        "test_consumer_toolchain_resolved_path_only  "
        "test_guest_harness_case_carries_admission  "
        "test_guest_prologue_rejects_post_staging_chain_symlink_retarget  "
        "test_guest_prologue_rejects_post_staging_image_replacement  "
        "test_guest_prologue_rejects_post_staging_middle_replacement  "
        "test_guest_script_binds_bpftool_to_reviewed_pins  "
        "test_stage_bpftool_pins_admit_reviewed_tool  "
        "test_stage_bpftool_pins_from_shared_rootfs  "
        "test_stage_bpftool_pins_refuse_without_reviewed_pins  "
        "test_stage_bpftool_pins_reject_replacement  "
        "test_stage_bpftool_pins_reject_unresolvable_launcher  "
        "test_stage_bpftool_pins_require_reviewed_status"
    ).split(),
    "packaging-hash-consumer": (
        "test_build_fails_without_installed_package  "
        "test_consumer_admission_probes_the_captured_image  "
        "test_consumer_admission_refuses_swap_after_capture  "
        "test_consumer_admission_refuses_swap_before_capture  "
        "test_consumer_admission_rejects_replacement  "
        "test_consumer_admission_rejects_unapproved_chain  "
        "test_consumer_admission_rejects_unresolvable_chain  "
        "test_consumer_admission_spawns_only_through_the_contract  "
        "test_consumer_admits_independent_prefix  "
        "test_consumer_bootstrap_without_independent_pins  "
        "test_consumer_builds_through_admitted_prefix  "
        "test_consumer_builds_with_installed_tool  "
        "test_consumer_exact_kernel_result test_consumer_guest_provenance  "
        "test_consumer_has_no_copy_no_path_back  "
        "test_consumer_imports_only_the_sdk_surface  "
        "test_consumer_independent_pins_require_reviewed_status  "
        "test_consumer_lock_declares_trust  "
        "test_consumer_lockfile_schema_for_build  "
        "test_consumer_object_compiled_from_own_source  "
        "test_consumer_prefix_replaces_ambient_probe  "
        "test_consumer_probe_refuses_swap_before_probe  "
        "test_consumer_self_pin_is_not_a_trust_root  "
        "test_consumer_standard_runner_passes  "
        "test_consumer_toolchain_resolved_path_only  "
        "test_guest_harness_case_carries_admission  "
        "test_guest_prologue_rejects_post_staging_chain_symlink_retarget  "
        "test_guest_prologue_rejects_post_staging_image_replacement  "
        "test_guest_prologue_rejects_post_staging_middle_replacement  "
        "test_guest_script_binds_bpftool_to_reviewed_pins  "
        "test_stage_bpftool_pins_admit_reviewed_tool  "
        "test_stage_bpftool_pins_from_shared_rootfs  "
        "test_stage_bpftool_pins_refuse_without_reviewed_pins  "
        "test_stage_bpftool_pins_reject_replacement  "
        "test_stage_bpftool_pins_reject_unresolvable_launcher  "
        "test_stage_bpftool_pins_require_reviewed_status"
    ).split(),
    "packaging-reserve-consumer": (
        "test_build_fails_without_installed_package  "
        "test_consumer_admission_probes_the_captured_image  "
        "test_consumer_admission_refuses_swap_after_capture  "
        "test_consumer_admission_refuses_swap_before_capture  "
        "test_consumer_admission_rejects_replacement  "
        "test_consumer_admission_rejects_unapproved_chain  "
        "test_consumer_admission_rejects_unresolvable_chain  "
        "test_consumer_admission_spawns_only_through_the_contract  "
        "test_consumer_admits_independent_prefix  "
        "test_consumer_bootstrap_without_independent_pins  "
        "test_consumer_builds_through_admitted_prefix  "
        "test_consumer_builds_with_installed_tool  "
        "test_consumer_guest_provenance  "
        "test_consumer_has_no_copy_no_path_back  "
        "test_consumer_imports_only_the_sdk_surface  "
        "test_consumer_independent_pins_require_reviewed_status  "
        "test_consumer_kernel_run_exact test_consumer_lock_declares_trust  "
        "test_consumer_lockfile_schema_for_build  "
        "test_consumer_object_compiled_from_own_source  "
        "test_consumer_prefix_replaces_ambient_probe  "
        "test_consumer_probe_refuses_swap_before_probe  "
        "test_consumer_self_pin_is_not_a_trust_root  "
        "test_consumer_toolchain_resolved_path_only  "
        "test_guest_prologue_rejects_post_staging_chain_symlink_retarget  "
        "test_guest_prologue_rejects_post_staging_image_replacement  "
        "test_guest_prologue_rejects_post_staging_middle_replacement  "
        "test_guest_script_binds_bpftool_to_reviewed_pins  "
        "test_stage_bpftool_pins_admit_reviewed_tool  "
        "test_stage_bpftool_pins_refuse_without_reviewed_pins  "
        "test_stage_bpftool_pins_reject_replacement  "
        "test_stage_bpftool_pins_reject_unresolvable_launcher  "
        "test_stage_bpftool_pins_require_reviewed_status"
    ).split(),
    "packaging-subprog-consumer": (
        "test_build_fails_without_installed_package  "
        "test_consumer_admission_probes_the_captured_image  "
        "test_consumer_admission_refuses_swap_after_capture  "
        "test_consumer_admission_refuses_swap_before_capture  "
        "test_consumer_admission_rejects_replacement  "
        "test_consumer_admission_rejects_unapproved_chain  "
        "test_consumer_admission_rejects_unresolvable_chain  "
        "test_consumer_admission_spawns_only_through_the_contract  "
        "test_consumer_admits_independent_prefix  "
        "test_consumer_bootstrap_without_independent_pins  "
        "test_consumer_builds_through_admitted_prefix  "
        "test_consumer_builds_with_installed_tool  "
        "test_consumer_exact_kernel_result test_consumer_guest_provenance  "
        "test_consumer_has_no_copy_no_path_back  "
        "test_consumer_imports_only_the_sdk_surface  "
        "test_consumer_independent_pins_require_reviewed_status  "
        "test_consumer_lock_declares_trust  "
        "test_consumer_lockfile_schema_for_build  "
        "test_consumer_object_compiled_from_own_source  "
        "test_consumer_prefix_replaces_ambient_probe  "
        "test_consumer_probe_refuses_swap_before_probe  "
        "test_consumer_self_pin_is_not_a_trust_root  "
        "test_consumer_standard_runner_passes  "
        "test_consumer_toolchain_resolved_path_only  "
        "test_guest_harness_case_carries_admission  "
        "test_guest_prologue_rejects_post_staging_chain_symlink_retarget  "
        "test_guest_prologue_rejects_post_staging_image_replacement  "
        "test_guest_prologue_rejects_post_staging_middle_replacement  "
        "test_guest_script_binds_bpftool_to_reviewed_pins  "
        "test_stage_bpftool_pins_admit_reviewed_tool  "
        "test_stage_bpftool_pins_from_shared_rootfs  "
        "test_stage_bpftool_pins_refuse_without_reviewed_pins  "
        "test_stage_bpftool_pins_reject_replacement  "
        "test_stage_bpftool_pins_reject_unresolvable_launcher  "
        "test_stage_bpftool_pins_require_reviewed_status"
    ).split(),
    "packaging-uprobe-consumer": (
        "test_build_fails_without_installed_package  "
        "test_consumer_admission_probes_the_captured_image  "
        "test_consumer_admission_refuses_swap_after_capture  "
        "test_consumer_admission_refuses_swap_before_capture  "
        "test_consumer_admission_rejects_replacement  "
        "test_consumer_admission_rejects_unapproved_chain  "
        "test_consumer_admission_rejects_unresolvable_chain  "
        "test_consumer_admission_spawns_only_through_the_contract  "
        "test_consumer_admits_independent_prefix  "
        "test_consumer_bootstrap_without_independent_pins  "
        "test_consumer_builds_through_admitted_prefix  "
        "test_consumer_builds_with_installed_tool  "
        "test_consumer_exact_kernel_result test_consumer_guest_provenance  "
        "test_consumer_has_no_copy_no_path_back  "
        "test_consumer_imports_only_the_sdk_surface  "
        "test_consumer_independent_pins_require_reviewed_status  "
        "test_consumer_lock_declares_trust  "
        "test_consumer_lockfile_schema_for_build  "
        "test_consumer_object_compiled_from_own_source  "
        "test_consumer_prefix_replaces_ambient_probe  "
        "test_consumer_probe_refuses_swap_before_probe  "
        "test_consumer_self_pin_is_not_a_trust_root  "
        "test_consumer_toolchain_resolved_path_only  "
        "test_guest_prologue_rejects_post_staging_chain_symlink_retarget  "
        "test_guest_prologue_rejects_post_staging_image_replacement  "
        "test_guest_prologue_rejects_post_staging_middle_replacement  "
        "test_guest_script_binds_bpftool_to_reviewed_pins  "
        "test_stage_bpftool_pins_admit_reviewed_tool  "
        "test_stage_bpftool_pins_refuse_without_reviewed_pins  "
        "test_stage_bpftool_pins_reject_replacement  "
        "test_stage_bpftool_pins_reject_unresolvable_launcher  "
        "test_stage_bpftool_pins_require_reviewed_status"
    ).split(),
    "kernel-core-layouts": (
        "test_absent_target_btf_fails_explicitly  "
        "test_case_exit_check_refuses_nonzero test_case_exits_zero  "
        "test_cleanup_ok test_exists_bit_matches_lane_layout  "
        "test_guest_provenance test_lane_layout_facts  "
        "test_layout_fixture_gates_refuse_drift  "
        "test_layout_fixtures_self_consistent  "
        "test_layout_oracle_matches_lane test_load_pins_program_and_map  "
        "test_malformed_and_missing_type_fail_explicitly  "
        "test_missing_field_fails_explicitly  "
        "test_pin_phrase_wired_both_sides test_prefill_markers_present  "
        "test_reader_relocations test_relocated_read_matches_lane_marker  "
        "test_tag_record_refuses_reserved_keys"
    ).split(),
    "kernel-hash": (
        "test_budget_and_sizes_refused test_decode_bpftool_hash_dump_shape  "
        "test_exact_counts_after_quiescence test_guest_provenance  "
        "test_iteration_set_and_bytes test_kernel_delete_removes_entries  "
        "test_key_value_byte_helpers test_license_gate_agrees  "
        "test_lifecycle_init_run_observe test_miss_path_inserts_nothing  "
        "test_oob_rejected_by_verifier  "
        "test_residue_checks_refuse_blind_spots  "
        "test_scoped_update_after_insert  "
        "test_unchecked_rejected_by_verifier  "
        "test_userspace_delete_lifecycle  "
        "test_walk_chain_refuses_broken_chains"
    ).split(),
    "kernel-ringbuf": (
        "test_adversarial_interleavings_rejected  "
        "test_discard_publishes_nothing test_license_gate_and_preflight  "
        "test_no_residue test_saturation_null_reserve_accounting  "
        "test_submit_publishes_exactly_once board"
    ).split(),
    "kernel-subprog": (
        "test_base_packet_actions test_entry_first_matches_base  "
        "test_fd_lifecycle_and_residue test_fixture_bytes  "
        "test_guest_provenance test_kernel_rejects_callee_null_load  "
        "test_license_gate_agrees test_mutation_changes_behavior  "
        "test_object_hashes test_stale_object_fails  "
        "test_verifier_log_shows_subprogram"
    ).split(),
    "kernel-uprobe": (
        "test_bad_offset_refused test_holder_refuses_non_test_binary  "
        "test_inverted_counts_mismatches test_license_gate_and_preflight  "
        "test_match_exact_with_oracle test_mismatch_zero_with_oracle  "
        "test_never_called_zero test_no_residue  "
        "test_offsets_resolve_to_text test_reload_live_state  "
        "test_unavailability_reported test_verifier_rejects_oob_context  "
        "test_vlog_captured"
    ).split(),
    "kernel-cleanup": (
        "test_harness_timeout test_interrupt_sigterm_reaps  "
        "test_killed_child_no_hang test_missing_btf_unavailable  "
        "test_owned_runner_classification  "
        "test_repeated_load_unload_no_leak  "
        "test_reproducible_manifest_build test_reproducible_two_paths  "
        "test_unprivileged_load_unavailable  "
        "test_unsupported_prog_type_unavailable  "
        "test_verify_load_unload_pass test_verify_loader_classification  "
        "test_verify_verifier_classification"
    ).split(),
    "kernel-joint": (
        "test_guest_provenance test_joint_baseline_42  "
        "test_joint_cross_check_42 test_joint_driver_mutant_43  "
        "test_joint_driver_reports_42 test_joint_driver_stale_fails_43  "
        "test_joint_mutation_changes_value test_joint_stale_object_fails"
    ).split(),
    "kernel-net": (
        "test_guest_provenance test_tc_baseline_verdicts  "
        "test_tc_mutation_flips_verdicts test_tc_stale_object_fails "
        "test_socket_exec_runs test_socket_attach_verdicts "
        "test_socket_attach_mutation_flips test_tc_store_packet_out "
        "test_tc_load_map_readback test_parse_attach_sample "
        "test_parse_store_sample test_parse_map_sample"
    ).split(),
    "kernel-lru": (
        "test_decode_bpftool_lru_dump_shape  "
        "test_eviction_evicts_lru_entry  "
        "test_exact_counts_after_quiescence test_guest_provenance  "
        "test_iteration_set_and_bytes test_kernel_delete_removes_entries  "
        "test_key_value_byte_helpers test_license_gate_agrees  "
        "test_lifecycle_init_run_observe test_miss_path_inserts_nothing  "
        "test_oob_rejected_by_verifier  "
        "test_residue_checks_refuse_blind_spots  "
        "test_scoped_update_after_insert test_sizes_refused  "
        "test_unchecked_rejected_by_verifier  "
        "test_userspace_delete_lifecycle  "
        "test_walk_chain_refuses_broken_chains"
    ).split(),
}

# Pinned per-case obligations per suite (the matrix's independent
# expectation: every plan case must be required, denials must
# match these (denies, wire stage) pins exactly, and every other
# case must be positive). A sync test pins these against each
# suite's CASE_DENIALS; a plan that weakens a case to optional
# or flips an expectation is rejected, never re-aggregated into
# a pass.
SUITE_DENIALS = {
    "kernel-xdp": {
        "test_stale_object_fails": (
            "test_mutation_changes_behavior", "RUNTIME"
        ),
    },
    "kernel-map": {
        "test_oob_rejected_by_verifier": (
            "test_map_roundtrip_42", "VERIFY"
        ),
        "test_unchecked_rejected_by_verifier": (
            "test_map_roundtrip_42", "VERIFY"
        ),
    },
    "kernel-packet": {
        "test_negatives_rejected_by_verifier": (
            "test_fixed_byte_actions", "VERIFY"
        ),
    },
    "kernel-parse": {},
    "kernel-array": {
        "test_oob_rejected_by_verifier": (
            "test_lifecycle_init_run_observe", "VERIFY"
        ),
        "test_unchecked_rejected_by_verifier": (
            "test_lifecycle_init_run_observe", "VERIFY"
        ),
    },
    "kernel-percpu": {},
    "kernel-accounting": {
        "test_mutants_detected_in_guest": (
            "test_classifier_matches_oracle", "RUNTIME"
        ),
    },
    "kernel-generalized": {},
    "kernel-mojopercpu": {},
    "kernel-tracepoint": {},
    "kernel-events": {},
    "kernel-tracing-lifecycle": {},
    "verifier-subset": {
        "test_oob_store_rejected_by_verifier": (
            "test_call_inline", "VERIFY"
        ),
    },
    "verifier-licenses": {},
    "packaging-consumer": {},
    "packaging-hash-consumer": {},
    "packaging-reserve-consumer": {},
    "packaging-subprog-consumer": {},
    "packaging-uprobe-consumer": {},
    "kernel-core-layouts": {},
    "kernel-hash": {
        "test_oob_rejected_by_verifier": (
            "test_lifecycle_init_run_observe", "VERIFY"
        ),
        "test_unchecked_rejected_by_verifier": (
            "test_lifecycle_init_run_observe", "VERIFY"
        ),
    },
    "kernel-ringbuf": {},
    "kernel-subprog": {
        "test_stale_object_fails": (
            "test_mutation_changes_behavior", "RUNTIME"
        ),
    },
    "kernel-uprobe": {},
    "kernel-cleanup": {
        "test_verify_loader_classification": (
            "test_verify_load_unload_pass", "LOAD"
        ),
        "test_verify_verifier_classification": (
            "test_verify_load_unload_pass", "VERIFY"
        ),
    },
    "kernel-joint": {},
    "kernel-net": {},
    "kernel-lru": {
        "test_oob_rejected_by_verifier": (
            "test_lifecycle_init_run_observe", "VERIFY"
        ),
        "test_unchecked_rejected_by_verifier": (
            "test_lifecycle_init_run_observe", "VERIFY"
        ),
    },
}

# Suites whose assertive board phase runs as an extra case.
BOARD_CASES = {
    "kernel-events": "board",
    "kernel-ringbuf": "board",
    "kernel-tracepoint": "board",
    "kernel-tracing-lifecycle": "board",
    "verifier-licenses": "board",
}

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_SETUP = 2


class SetupFailure(Exception):
    """The matrix cannot run honestly (exit 2)."""


def sha256_file(path):
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_head():
    try:
        completed = subprocess.run(
            ["git", "-C", REPO_ROOT, "rev-parse", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SetupFailure("cannot read git HEAD: %s" % exc)
    if completed.returncode != 0:
        raise SetupFailure("cannot read git HEAD: %s" % completed.stderr)
    return completed.stdout.strip()


def git_clean():
    try:
        completed = subprocess.run(
            ["git", "-C", REPO_ROOT, "status", "--short"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SetupFailure("cannot inspect the worktree: %s" % exc)
    if completed.returncode != 0:
        raise SetupFailure("cannot inspect the worktree: %s" % completed.stderr)
    return completed.stdout.strip()


def load_lock(path):
    if not os.path.isfile(path):
        raise SetupFailure("lockfile not found: %s" % path)
    try:
        with open(path, encoding="utf-8") as handle:
            lock = json.load(handle)
    except (OSError, ValueError) as exc:
        raise SetupFailure("lockfile %s is unreadable: %s" % (path, exc))
    if lock.get("schema_version") != 1:
        raise SetupFailure("lockfile schema_version must be 1")
    runner = lock.get("runner")
    if not isinstance(runner, dict) or runner.get("name") != "vng":
        raise SetupFailure("lockfile runner must name vng")
    for key in ("version", "sha256", "qemu"):
        if not runner.get(key):
            raise SetupFailure("lockfile runner lacks %s" % key)
    _validate_runner_pins(runner)
    _validate_distribution(lock.get("distribution"))
    lanes = lock.get("lanes")
    if not isinstance(lanes, list) or len(lanes) < 2:
        raise SetupFailure("lockfile must pin at least two lanes")
    seen_ids = set()
    for lane in lanes:
        for key in (
            "id",
            "release",
            "accelerator",
            "kernel_release",
            "kernel_debs",
            "vng_argv_prefix",
        ):
            if key not in lane:
                raise SetupFailure(
                    "lane %r lacks %s" % (lane.get("id"), key)
                )
        if lane["id"] in seen_ids:
            raise SetupFailure(
                "duplicate lane id %r" % lane["id"]
            )
        seen_ids.add(lane["id"])
        if not lane["kernel_debs"]:
            raise SetupFailure(
                "lane %r pins no kernel debs" % lane["id"]
            )
        for deb in lane["kernel_debs"]:
            if not isinstance(deb, dict) or (
                not deb.get("file") or not deb.get("sha256")
            ):
                raise SetupFailure(
                    "lane %r carries a deb without file+sha256"
                    % lane["id"]
                )
        if lane["vng_argv_prefix"][:3] != ["vng", "--run", lane["release"]]:
            raise SetupFailure(
                "lane %r argv prefix does not match its release"
                % lane.get("id")
            )
        tcg_flag = "--disable-kvm" in lane["vng_argv_prefix"]
        if tcg_flag != (lane["accelerator"] == "tcg"):
            raise SetupFailure(
                "lane %r accelerator %r disagrees with its argv "
                "prefix" % (lane["id"], lane["accelerator"])
            )
        if lane.get("arch", "x86_64") not in ("x86_64", "amd64"):
            raise SetupFailure(
                "lane %r arch %r is not supported by the "
                "matrix runner (x86-64 lanes only)"
                % (lane["id"], lane.get("arch"))
            )
        if lane["accelerator"] not in ("tcg", "kvm", "hvf", "hyperv"):
            raise SetupFailure(
                "lane %r accelerator %r is not a known "
                "execution mode" % (lane["id"], lane["accelerator"])
            )
    return lock


def _validate_runner_pins(runner):
    """Validate the lock's optional execution pins when present.

    Locks pre-dating ``execution-contract-v1`` stay loadable (lane
    tools read them), but admission refuses to qualify guests from
    them until they are re-pinned.
    """
    for key in (
        "exec_sha256",
        "qemu_sha256",
        "qemu_exec_sha256",
        "virtme_run_exec_sha256",
    ):
        if key in runner and not (
            runner[key] is None or isinstance(runner[key], str)
        ):
            raise SetupFailure(
                "lockfile runner %s must be a hash string or null" % key
            )
    if "virtme_run_sha256" in runner and not isinstance(
        runner["virtme_run_sha256"], str
    ):
        raise SetupFailure(
            "lockfile runner virtme_run_sha256 must be a hash string"
        )
    if "qemu_binary" in runner and not isinstance(
        runner["qemu_binary"], str
    ):
        raise SetupFailure("lockfile runner qemu_binary must be a string")
    interpreter = runner.get("interpreter")
    if interpreter is not None:
        if not isinstance(interpreter, dict) or not isinstance(
            interpreter.get("sha256"), str
        ):
            raise SetupFailure(
                "lockfile runner interpreter must carry a sha256 string"
            )
    package = runner.get("package")
    if package is not None:
        if not isinstance(package, dict) or not isinstance(
            package.get("modules"), dict
        ):
            raise SetupFailure(
                "lockfile runner package must carry a modules table"
            )
        for dotted, digest in package["modules"].items():
            if not isinstance(dotted, str) or not isinstance(digest, str):
                raise SetupFailure(
                    "lockfile runner package modules must map names "
                    "to hash strings"
                )
    virtme_package = runner.get("virtme_package")
    if virtme_package is not None:
        if not isinstance(virtme_package, dict) or not isinstance(
            virtme_package.get("modules"), dict
        ):
            raise SetupFailure(
                "lockfile runner virtme_package must carry a modules table"
            )
        for dotted, digest in virtme_package["modules"].items():
            if not isinstance(dotted, str) or not isinstance(digest, str):
                raise SetupFailure(
                    "lockfile runner virtme_package modules must map "
                    "names to hash strings"
                )
    python_path = runner.get("python_path", [])
    if not isinstance(python_path, list) or not all(
        isinstance(entry, str) for entry in python_path
    ):
        raise SetupFailure(
            "lockfile runner python_path must be a list of strings"
        )


def _validate_distribution(distribution):
    """Validate the lock's distribution record shape when present.

    Digest/existence enforcement happens at admission; load time
    only rejects malformed shapes so lane tools keep reading
    legacy locks without the record.
    """
    if distribution is None:
        return
    if not isinstance(distribution, dict):
        raise SetupFailure("lockfile distribution must be a mapping")
    runner_dist = distribution.get("runner")
    if runner_dist is not None:
        if not isinstance(runner_dist, dict):
            raise SetupFailure(
                "lockfile distribution runner must be a mapping"
            )
        dependencies = runner_dist.get("dependencies", [])
        if not isinstance(dependencies, list):
            raise SetupFailure(
                "lockfile distribution dependencies must be a list"
            )
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                raise SetupFailure(
                    "lockfile distribution dependency must be a mapping"
                )
            for key in ("name", "version", "metadata_sha256"):
                if not isinstance(dependency.get(key), str):
                    raise SetupFailure(
                        "lockfile distribution dependency lacks a %s "
                        "string" % key
                    )
    emulator = distribution.get("emulator")
    if emulator is not None:
        if not isinstance(emulator, dict):
            raise SetupFailure(
                "lockfile distribution emulator must be a mapping"
            )
        if "qemu_version" in emulator and not isinstance(
            emulator["qemu_version"], str
        ):
            raise SetupFailure(
                "lockfile distribution emulator qemu_version must be "
                "a string"
            )


def qemu_binary_for_lock(lock):
    """Return the QEMU binary name driving this lock's lanes.

    An explicit ``runner.qemu_binary`` wins; otherwise the lanes'
    ``arch`` decides (``arm64``/``aarch64`` selects the AArch64
    system emulator, anything else the x86-64 one). A mixed-arch
    lock without an explicit binary fails closed.
    """
    explicit = lock["runner"].get("qemu_binary")
    if explicit:
        return explicit
    archs = set(
        lane.get("arch", "x86_64") for lane in lock["lanes"]
    )
    if len(archs) > 1:
        raise SetupFailure(
            "mixed-arch lock needs an explicit runner.qemu_binary"
        )
    if archs <= {"arm64", "aarch64"}:
        return "qemu-system-aarch64"
    return "qemu-system-x86_64"


def check_qemu(lock, lock_path="", timeout=60):
    """Admit the locked QEMU emulator; return its record.

    The lock pins the emulator next to the runner because both
    shape guest behavior. The image is hash-checked before its
    version probe runs, so a same-version unrelated binary is
    refused without executing; an unpinned or drifting QEMU fails
    the run up front instead of qualifying unknown emulation.
    """
    binary = qemu_binary_for_lock(lock)
    try:
        _binary, pins = execution_mod.qemu_pins(lock["runner"])
    except ValueError as exc:
        raise SetupFailure("lockfile %s" % (exc,))
    try:
        admitted = execution_mod.admit_execution(
            execution_mod.ExecutionRequest(
                name=binary,
                argv0=binary,
                version_argv=("--version",),
                probe_version=True,
                trust_root=("lock:%s" % lock_path) if lock_path else "",
            ),
            pins,
            probe_timeout=timeout,
        )
    except execution_mod.AdmissionError as exc:
        raise SetupFailure("emulator admission refused: %s" % (exc,))
    except UnicodeDecodeError as exc:
        raise SetupFailure(
            "%s version probe printed undecodable output: %s"
            % (binary, exc)
        )
    return {
        "binary": binary,
        "path": admitted.image.realpath,
        "version": admitted.version,
        "sha256": admitted.image.sha256,
        "execution": admitted,
    }


def check_virtme_run(lock, lock_path="", timeout=60):
    """Admit the locked virtme-run launcher; return its record.

    ``vng`` invokes this bare name through a shell, so the
    launcher and its ``virtme.*`` implementation are admitted
    exactly like the runner itself (entry, ``exec`` chain, shared
    interpreter, package modules) before the launcher probe runs.
    ``virtme-run`` has no ``--version``; the ``--help`` probe line
    is record-only (usage wrapping varies with output width), so
    identity rests on the entry/interpreter/module hashes.
    """
    try:
        name, pins = execution_mod.virtme_run_pins(lock["runner"])
    except ValueError as exc:
        raise SetupFailure("lockfile %s" % (exc,))
    try:
        admitted = execution_mod.admit_execution(
            execution_mod.ExecutionRequest(
                name=name,
                argv0=name,
                version_argv=("--help",),
                probe_version=True,
                trust_root=("lock:%s" % lock_path) if lock_path else "",
            ),
            pins,
            probe_timeout=timeout,
        )
    except execution_mod.AdmissionError as exc:
        raise SetupFailure("launcher admission refused: %s" % (exc,))
    except UnicodeDecodeError as exc:
        raise SetupFailure(
            "virtme-run probe printed undecodable output: %s" % (exc,)
        )
    return {
        "binary": name,
        "path": admitted.entry.realpath,
        "version": admitted.version,
        "sha256": admitted.entry.sha256,
        "execution": admitted,
    }


def check_runner(lock, lock_path="", farm_parent=None, timeout=60):
    """Admit the locked runner plus its launcher and emulator.

    The ``vng`` entry, its ``exec`` chain, the console-script
    interpreter and the runner package modules are hash-checked
    against the lock, then the lock's distribution bindings are
    enforced, and only then does any version probe run: the
    ``virtme-run`` launcher follows through
    :func:`check_virtme_run` and the emulator through
    :func:`check_qemu`. Returns the runner record with the
    ``execution``/``virtme_run_execution``/``qemu_execution``
    admissions and a ``farm`` directory forcing admitted
    ``vng``/``virtme-run``/QEMU resolution for every suite. The
    caller owns farm cleanup.
    """
    expected = lock["runner"]
    try:
        pins = execution_mod.runner_pins(expected)
    except ValueError as exc:
        raise SetupFailure("lockfile runner is malformed: %s" % (exc,))
    trust_root = ("lock:%s" % lock_path) if lock_path else ""
    try:
        static_admitted = execution_mod.admit_execution(
            execution_mod.ExecutionRequest(
                name="vng",
                argv0="vng",
                version_argv=("--version",),
                probe_version=False,
                trust_root=trust_root,
            ),
            pins,
            probe_timeout=timeout,
        )
    except execution_mod.AdmissionError as exc:
        raise SetupFailure("runner admission refused: %s" % (exc,))
    # Distribution bindings BEFORE any entry probe: the probes
    # execute distribution code (vng imports its dependencies at
    # startup), so unverified content must never reach them. The
    # emulator claim is checked against the lock's pinned version
    # here; the observed version is checked again after the
    # emulator probe below.
    try:
        execution_mod.verify_runner_dependencies(
            lock.get("distribution"), static_admitted
        )
        expected_qemu = expected.get("qemu")
        if expected_qemu is not None:
            execution_mod.verify_emulator_claim(
                lock.get("distribution"), expected_qemu
            )
    except ValueError as exc:
        raise SetupFailure(
            "lockfile distribution is malformed: %s" % (exc,)
        )
    except execution_mod.AdmissionError as exc:
        raise SetupFailure("runner distribution refused: %s" % (exc,))
    try:
        admitted = execution_mod.admit_execution(
            execution_mod.ExecutionRequest(
                name="vng",
                argv0="vng",
                version_argv=("--version",),
                probe_version=True,
                trust_root=trust_root,
            ),
            pins,
            probe_timeout=timeout,
        )
    except execution_mod.AdmissionError as exc:
        raise SetupFailure("runner admission refused: %s" % (exc,))
    except UnicodeDecodeError as exc:
        raise SetupFailure(
            "vng version probe printed undecodable output: %s" % (exc,)
        )
    qemu = check_qemu(lock, lock_path=lock_path, timeout=timeout)
    launcher = check_virtme_run(
        lock, lock_path=lock_path, timeout=timeout
    )
    # Post-probe half: the emulator claim against the OBSERVED
    # version (dependencies were already enforced pre-probe and
    # are re-checked here for a single final verdict).
    try:
        execution_mod.verify_runner_distribution(
            lock.get("distribution"), admitted, qemu["version"]
        )
    except ValueError as exc:
        raise SetupFailure(
            "lockfile distribution is malformed: %s" % (exc,)
        )
    except execution_mod.AdmissionError as exc:
        raise SetupFailure("runner distribution refused: %s" % (exc,))
    try:
        farm = execution_mod.build_path_farm(
            {
                "vng": admitted.entry.realpath,
                launcher["binary"]: launcher["execution"].entry.realpath,
                qemu["binary"]: qemu["execution"].image.realpath,
            },
            parent=farm_parent,
        )
    except (ValueError, OSError) as exc:
        raise SetupFailure(
            "cannot stage the admitted PATH farm: %s" % (exc,)
        )
    image = admitted.image
    return {
        "path": admitted.entry.path,
        "realpath": admitted.entry.realpath,
        "version": admitted.version,
        "sha256": admitted.entry.sha256,
        "exec_path": (
            image.realpath if image.realpath != admitted.entry.realpath
            else None
        ),
        "exec_sha256": (
            image.sha256 if image.realpath != admitted.entry.realpath
            else None
        ),
        "qemu_binary": qemu["binary"],
        "qemu_path": qemu["path"],
        "qemu_version": qemu["version"],
        "qemu_sha256": qemu["sha256"],
        "virtme_run_path": launcher["path"],
        "virtme_run_version": launcher["version"],
        "virtme_run_sha256": launcher["sha256"],
        "farm": farm,
        "digest": admitted.digest,
        "execution": admitted,
        "virtme_run_execution": launcher["execution"],
        "qemu_execution": qemu["execution"],
    }


def runner_report(runner):
    """Return the JSON-safe runner attestation for the report."""
    report = {
        key: value
        for key, value in runner.items()
        if key
        not in ("execution", "virtme_run_execution", "qemu_execution")
    }
    report["admission"] = execution_mod.summarize(runner["execution"])
    report["virtme_run_admission"] = execution_mod.summarize(
        runner["virtme_run_execution"]
    )
    report["qemu_admission"] = execution_mod.summarize(
        runner["qemu_execution"]
    )
    return report


def check_consumer_vng_shadow(consumer_path, runner_realpath):
    """Reject a consumer PATH that shadows the locked vng.

    Consumer suites resolve their guest runner PATH-only after
    the matrix prepends ``consumer_path``; a vng binary there
    would run guests under an unrecorded runner. The vng
    resolving under the augmented PATH must be the validated
    one (or absent, in which case the suite fails on its own
    isolation gate).
    """
    if not consumer_path:
        return
    augmented = os.pathsep.join(
        list(consumer_path) + [os.environ.get("PATH", "")]
    )
    shadow = shutil.which("vng", path=augmented)
    if shadow is not None and (
        os.path.realpath(shadow) != runner_realpath
    ):
        raise SetupFailure(
            "consumer path shadows the locked vng: %s "
            "resolves to %s, want %s"
            % (shadow, os.path.realpath(shadow), runner_realpath)
        )


def check_consumer_qemu_shadow(
    consumer_path, qemu_binary, qemu_realpath
):
    """Reject a consumer PATH that shadows the locked QEMU.

    vng resolves its emulator PATH-only (``shutil.which`` on
    the locked ``qemu-system-{arch}`` binary) after the matrix
    prepends ``consumer_path``; a QEMU binary there would run
    guests under an unrecorded emulator. The QEMU resolving
    under the augmented PATH must be the validated one (or
    absent, in which case the suite fails on its own
    isolation gate).
    """
    if not consumer_path:
        return
    augmented = os.pathsep.join(
        list(consumer_path) + [os.environ.get("PATH", "")]
    )
    shadow = shutil.which(qemu_binary, path=augmented)
    if shadow is not None and (
        os.path.realpath(shadow) != qemu_realpath
    ):
        raise SetupFailure(
            "consumer path shadows the locked %s: %s "
            "resolves to %s, want %s"
            % (
                qemu_binary, shadow,
                os.path.realpath(shadow), qemu_realpath,
            )
        )


def check_consumer_virtme_run_shadow(
    consumer_path, virtme_run_realpath
):
    """Reject a consumer PATH that shadows the locked virtme-run.

    ``vng`` invokes the bare ``virtme-run`` name through a shell
    under the augmented PATH; a launcher there would run guests
    under an unrecorded implementation. The ``virtme-run``
    resolving under the augmented PATH must be the validated one
    (or absent, in which case the suite fails on its own
    isolation gate).
    """
    if not consumer_path:
        return
    augmented = os.pathsep.join(
        list(consumer_path) + [os.environ.get("PATH", "")]
    )
    shadow = shutil.which("virtme-run", path=augmented)
    if shadow is not None and (
        os.path.realpath(shadow) != virtme_run_realpath
    ):
        raise SetupFailure(
            "consumer path shadows the locked virtme-run: %s "
            "resolves to %s, want %s"
            % (shadow, os.path.realpath(shadow), virtme_run_realpath)
        )


def check_lane_cache(lane):
    """Fail when the lane's kernel image is not cached and pinned."""
    cache = os.path.join(
        os.path.expanduser("~"), ".cache", "virtme-ng", lane["release"]
    )
    if not os.path.isdir(cache):
        raise SetupFailure(
            "lane %s cache is absent (%s); fetch it with "
            "`vng --run %s --disable-kvm --exec true` and re-run"
            % (lane["id"], cache, lane["release"])
        )
    found = []
    for root, _dirs, files in os.walk(cache):
        for name in files:
            if name.endswith(".deb"):
                found.append(os.path.join(root, name))
    problems = []
    for deb in lane["kernel_debs"]:
        matches = [
            path
            for path in found
            if os.path.basename(path) == deb["file"]
        ]
        if not matches:
            problems.append("missing %s" % deb["file"])
            continue
        if len(matches) > 1:
            problems.append(
                "ambiguous %s (%d copies; refusing to pick)"
                % (deb["file"], len(matches))
            )
            continue
        digest = sha256_file(matches[0])
        if digest != deb["sha256"]:
            problems.append(
                "%s hash mismatch (cache %s)" % (deb["file"], digest)
            )
    if problems:
        raise SetupFailure(
            "lane %s cache mismatch: %s" % (lane["id"], "; ".join(problems))
        )
    return {"cache": cache, "debs": sorted(os.path.basename(p) for p in found)}


# Structured result protocol (F-049): lane targets and suite
# acceptance. The matrix authors the lane target manifest from
# lock data, passes it (with the commit identity) to every
# suite through the environment, and requires each suite to
# embed it verbatim in its run plan. Suite output is judged by
# re-aggregating the emitted plan, results and terminal record
# against the matrix pins -- never by scraping PASS/FAIL lines.

PLAN_TOOL = "run_vm_tests"

LINE_PLAN = "MOJOBPF_RUN_PLAN "
LINE_RESULT = "MOJOBPF_CASE_RESULT "
LINE_SUITE = "MOJOBPF_SUITE_RESULT "

ENV_TARGET_MANIFEST = "MOJOBPF_TARGET_MANIFEST"
ENV_PLAN_COMMIT = "MOJOBPF_PLAN_COMMIT"
ENV_PLAN_TOOL = "MOJOBPF_PLAN_TOOL"

ZERO_SHA256 = "0" * 64
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def lane_target_manifest(lane):
    """Build the lane-declared target manifest for a lock lane.

    The manifest binds suite results to the lane the matrix
    selected. Every field states either a lock-pinned fact or
    an explicit unknown; nothing is borrowed from the build
    host and nothing is guessed about the guest:

    * kernel.release: the lane's locked ``kernel_release``
      (exact; the suites additionally check the booted kernel
      against it).
    * kernel.source_commit / kernel.config_sha256 /
      btf.vmlinux_sha256: zero hashes. The kernel build is
      unattested in A06 scope; attesting the staged and booted
      kernel bytes is verify/guest scope, and per-lane BTF
      recording rides with the deferred cross-lane CO-RE
      equality. Zero here means "unattested", documented, not
      a measurement.
    * image.digest: ``vng:<release>:<accelerator>`` (the
      selected runner and mode); image.packages: unprobed
      (guest packages are never inventoried from the host).
    * cpu.architecture / byte_order: derived from the lane arch
      (x86_64 only; anything else fails closed below).
      cpu.page_size 4096 is the x86-64 architectural base page;
      cpu.cpus 1 is the declared floor, not a measurement
      (guest probing replaces both in guest scope).
    * execution_mode: tcg, or hardware-vm for kvm-class
      accelerators.
    * instruction_profile ``v3``: the lane demonstrably
      executes the program v3 objects; per-run ISA probing is
      guest scope.
    * jit.state ``unknown``; every other unprobed string list
      carries ``["unprobed"]`` (explicit and greppable, never a
      fabricated value); unprobed maps stay empty.
    * build_host: the matrix host role that builds the suite
      objects (``mojobpf-matrix/<arch>``), with unprobed flags
      (suites use varying build commands).

    Unknown lane arch or accelerator fails closed with
    :class:`SetupFailure`: the matrix cannot honestly declare
    a target it does not understand. Returns the validated
    manifest mapping with its fingerprint.
    """
    lane_id = lane.get("id", "?")
    arch = lane.get("arch", "x86_64")
    if arch in ("x86_64", "amd64"):
        architecture = "x86-64"
        byte_order = "le"
        page_size = 4096
        cpus = 1
    else:
        raise SetupFailure(
            "lane %r arch %r needs a probed target (guest "
            "scope); the matrix declares x86-64 lanes only"
            % (lane_id, arch)
        )
    accelerator = lane.get("accelerator", "tcg")
    if accelerator == "tcg":
        execution_mode = "tcg"
    elif accelerator in ("kvm", "hvf", "hyperv"):
        execution_mode = "hardware-vm"
    else:
        raise SetupFailure(
            "lane %r accelerator %r is not a known execution "
            "mode" % (lane_id, accelerator)
        )
    body = {
        "schema_version": 1,
        "kernel": {
            "source_commit": "0" * 40,
            "release": lane["kernel_release"],
            "build_id": "unprobed",
            "config_sha256": ZERO_SHA256,
        },
        "btf": {"vmlinux_sha256": ZERO_SHA256, "modules": []},
        "image": {
            "digest": "vng:%s:%s" % (
                lane["release"], accelerator
            ),
            "packages": {},
        },
        "cpu": {
            "architecture": architecture,
            "model": "unprobed",
            "features": ["unprobed"],
            "page_size": page_size,
            "cpus": cpus,
        },
        "execution_mode": execution_mode,
        "byte_order": byte_order,
        "instruction_profile": "v3",
        "jit": {"state": "unknown", "hardening": ["unprobed"]},
        "boot": {
            "parameters": ["unprobed"],
            "lsms": ["unprobed"],
            "lockdown": "unknown",
        },
        "privileges": {
            "capabilities": ["unprobed"],
            "token": "unprobed",
            "delegation": "unprobed",
            "rlimits": {},
        },
        "mounts": {
            "tracefs": "unprobed",
            "bpffs": "unprobed",
            "cgroup": "unprobed",
            "namespaces": ["unprobed"],
        },
        "build_host": {
            "identity": "mojobpf-matrix/%s" % architecture,
            "flags": ["unprobed"],
        },
    }
    body["fingerprint"] = (
        validation_mod.TargetManifest.fingerprint_of(body)
    )
    return validation_mod.TargetManifest.from_dict(body).to_dict()


def _extract_protocol_lines(output):
    """Split suite output into (plan, result, suite) JSON payloads."""
    plans, results, suites = [], [], []
    for line in output.splitlines():
        if line.startswith(LINE_PLAN):
            plans.append(line[len(LINE_PLAN):])
        elif line.startswith(LINE_RESULT):
            results.append(line[len(LINE_RESULT):])
        elif line.startswith(LINE_SUITE):
            suites.append(line[len(LINE_SUITE):])
    return plans, results, suites


def _short_reasons(reasons, limit=3, width=400):
    """Summarize aggregation reasons for a one-line note."""
    text = "; ".join(reasons[:limit])
    if len(reasons) > limit:
        text += " (+%d more)" % (len(reasons) - limit,)
    if len(text) > width:
        text = text[:width] + "..."
    return text or "no reason recorded"


def accept_suite_output(suite_id, expected_cases, output, exit_code,
                        commit, target_manifest, suite_sha256,
                        expected_denials=None):
    """Judge suite output by its terminal record.

    Re-parses the emitted run plan, case results and terminal
    suite record and re-aggregates them against the matrix pins:
    the expected case IDs and per-case obligations (every case
    required, denials matching ``expected_denials`` exactly,
    every other case positive), the matrix commit, the executed
    suite file bytes, and the lane target manifest. Returns
    ``(outcome, note, detail)`` with outcome ``pass``, ``fail``
    or ``envfail`` and a detail mapping carrying the recomputed
    verdict, run ID, plan hash and reasons. Every rejection
    fails closed: a missing, duplicated, truncated or
    non-verifying terminal record is ``fail``, never ``pass``
    and never ``envfail``; the exit code must agree with the
    verdict or the suite fails.
    """
    detail = {
        "verdict": "NO_TERMINAL",
        "run_id": None,
        "plan_hash": None,
        "reasons": [],
    }
    plans, result_lines, suite_lines = _extract_protocol_lines(output)
    if len(plans) != 1:
        return (
            "fail",
            "want exactly one run plan, saw %d" % len(plans),
            detail,
        )
    if not result_lines:
        return ("fail", "no case results emitted", detail)
    if len(suite_lines) != 1:
        return (
            "fail",
            "want exactly one terminal suite record, saw %d"
            % len(suite_lines),
            detail,
        )
    try:
        plan_doc = json.loads(plans[0])
    except ValueError as exc:
        return ("fail", "malformed run plan: %s" % exc, detail)
    try:
        plan = validation_mod.RunPlan.from_dict(plan_doc)
    except validation_mod.ContractError as exc:
        return (
            "fail",
            "run plan rejected (%s): %s"
            % (exc.code, exc.diagnostic.explanation),
            detail,
        )
    detail["plan_hash"] = plan.plan_hash
    got = set(case.case_id for case in plan.cases)
    want = set(expected_cases)
    if got != want:
        return (
            "fail",
            "plan case IDs drift: missing %s, extra %s"
            % (sorted(want - got), sorted(got - want)),
            detail,
        )
    # Per-case obligations: membership alone would let a
    # resealed plan weaken a mandatory case to optional or flip
    # a denial to a positive expectation and still pass. Every
    # plan case must be required, each pinned denial must carry
    # its pinned (denies, wire stage) expectation, and every
    # other case must be positive.
    denials = dict(expected_denials or {})
    for plan_case in plan.cases:
        if not plan_case.required:
            return (
                "fail",
                "plan weakens coverage: case %s is optional, "
                "mandatory cases cannot be narrowed"
                % plan_case.case_id,
                detail,
            )
        pinned = denials.get(plan_case.case_id)
        if pinned is None:
            if plan_case.expectation != "positive":
                return (
                    "fail",
                    "plan obligation drift: case %s must be "
                    "positive, got %s"
                    % (plan_case.case_id, plan_case.expectation),
                    detail,
                )
            if dict(plan_case.expected) != {
                "outcome": "PASS", "failure_stage": None
            }:
                return (
                    "fail",
                    "plan obligation drift: case %s carries a "
                    "non-positive expectation %r"
                    % (
                        plan_case.case_id,
                        dict(plan_case.expected),
                    ),
                    detail,
                )
            continue
        denies, stage = pinned
        if (
            plan_case.expectation != "denial"
            or plan_case.denies != denies
            or dict(plan_case.expected) != {
                "outcome": "FAIL", "failure_stage": stage
            }
        ):
            return (
                "fail",
                "plan obligation drift: denial %s must deny %s "
                "at %s, got %s/%s %r"
                % (
                    plan_case.case_id,
                    denies,
                    stage,
                    plan_case.expectation,
                    plan_case.denies,
                    dict(plan_case.expected),
                ),
                detail,
            )
    revisions = plan.revisions
    if (
        revisions["repository_commit"] != commit
        or revisions["package"] != "mojobpf@" + commit
        or revisions["tool"] != PLAN_TOOL
    ):
        return (
            "fail",
            "plan revisions %r do not match the matrix run"
            % (dict(revisions),),
            detail,
        )
    if len(plan.targets) != 1 or (
            plan.targets[0].to_dict() != target_manifest):
        return (
            "fail",
            "plan target is not the matrix lane target",
            detail,
        )
    results = []
    for index, line in enumerate(result_lines):
        try:
            doc = json.loads(line)
        except ValueError as exc:
            return (
                "fail",
                "malformed case result #%d: %s" % (index, exc),
                detail,
            )
        try:
            results.append(
                validation_mod.CaseResult.from_dict(doc)
            )
        except validation_mod.ContractError as exc:
            return (
                "fail",
                "case result #%d rejected (%s): %s"
                % (index, exc.code, exc.diagnostic.explanation),
                detail,
            )
    for result in results:
        consumer = result.identities["consumer"]
        if (
            consumer["name"],
            consumer["version"],
            consumer["artifact_sha256"],
        ) != (suite_id, commit, suite_sha256):
            return (
                "fail",
                "case %s consumer is not this suite's executed "
                "bytes" % result.case_id,
                detail,
            )
    try:
        suite_doc = json.loads(suite_lines[0])
    except ValueError as exc:
        return (
            "fail",
            "malformed terminal suite record: %s" % exc,
            detail,
        )
    try:
        suite = validation_mod.SuiteResult.from_dict(suite_doc)
    except validation_mod.ContractError as exc:
        return (
            "fail",
            "terminal suite record rejected (%s): %s"
            % (exc.code, exc.diagnostic.explanation),
            detail,
        )
    try:
        decision = validation_mod.aggregate(plan, results)
    except validation_mod.ContractError as exc:
        return (
            "fail",
            "aggregation refused (%s): %s"
            % (exc.code, exc.diagnostic.explanation),
            detail,
        )
    try:
        verify_suite_result(suite, plan, results)
    except validation_mod.ContractError as exc:
        return (
            "fail",
            "terminal record disagrees with recomputation "
            "(%s): %s" % (exc.code, exc.diagnostic.explanation),
            detail,
        )
    detail["verdict"] = decision.verdict
    detail["run_id"] = decision.suite.run_id
    detail["reasons"] = list(decision.reasons)
    # No-op workload rule: a PASS must pin the durable sources
    # it depended on (board cases excepted: they verify the
    # transcript itself, which the evidence binds), must not
    # pin missing inputs (zeros mean declared-but-lost), and
    # must carry nonzero-byte evidence. An empty object or
    # corpus class is honest for cases that consume none
    # (host-only checks); an empty or missing source class on
    # a non-board PASS is a workload that proves nothing. A
    # satisfied denial backs the verdict exactly like a PASS,
    # so the same rule binds it: an evidence-free denial over
    # missing inputs proves nothing either. Unsatisfied,
    # unrun, and infrastructure records never reach this rule
    # (they cannot support a PASS verdict on their own).
    board_case = BOARD_CASES.get(suite_id)
    for result in decision.accepted:
        if result.outcome == "PASS":
            pass
        elif (
            result.expected.get("outcome") == "FAIL"
            and dict(result.observed) == dict(result.expected)
        ):
            pass
        else:
            continue
        identities = result.identities
        proven = (
            "PASS" if result.outcome == "PASS"
            else "satisfied denial"
        )
        if result.case_id != board_case and identities[
                "source_sha256"] in (ZERO_SHA256, EMPTY_SHA256):
            return (
                "fail",
                "no-op workload: case %s %s pins no sources"
                % (result.case_id, proven),
                detail,
            )
        if identities["object_sha256"] == ZERO_SHA256:
            return (
                "fail",
                "no-op workload: case %s %s pins missing "
                "object inputs" % (result.case_id, proven),
                detail,
            )
        if identities["workload"]["corpus_sha256"] == ZERO_SHA256:
            return (
                "fail",
                "no-op workload: case %s %s pins missing "
                "corpus inputs" % (result.case_id, proven),
                detail,
            )
        if not any(
                item["bytes"] >= 1 for item in result.evidence
        ):
            return (
                "fail",
                "no-op workload: case %s %s carries no "
                "nonzero-byte evidence" % (result.case_id, proven),
                detail,
            )
    if decision.verdict == "PASS":
        if exit_code == 0:
            return ("pass", "", detail)
        return (
            "fail",
            "exit %s disagrees with the PASS verdict" % exit_code,
            detail,
        )
    if decision.verdict == "FAIL":
        return (
            "fail",
            "verdict FAIL: %s"
            % _short_reasons(list(decision.reasons)),
            detail,
        )
    if exit_code in (2, 3):
        return (
            "envfail",
            "verdict INCOMPLETE: %s"
            % _short_reasons(list(decision.reasons)),
            detail,
        )
    return (
        "fail",
        "exit %s disagrees with the INCOMPLETE verdict" % exit_code,
        detail,
    )


def _pid_still_present(entry):
    """Return True when ``/proc/<entry>`` still exists.

    True means the pid is alive; False is returned only when
    the stat proves it vanished (``FileNotFoundError``). Any
    other metadata failure propagates: a denied or unreadable
    directory is scan uncertainty, never evidence of
    absence. (``os.path.isdir`` must not be used here: it
    swallows metadata errors into False, which would read a
    concealed live child as vanished.)
    """
    try:
        os.stat("/proc/%s" % entry)
    except FileNotFoundError:
        return False
    return True


def _scan_processes():
    """Snapshot the process table into ``{pid: (ppid, pgid, state)}``.

    Best-effort: processes that exit mid-scan are skipped.
    Returns None when the scan is untrustworthy -- denied
    enumeration, or any entry whose stat cannot be read or
    parsed while the pid is still present (or whose presence
    cannot even be determined) -- so a failed stat read on a
    potentially-owned pid never reads as an empty table.
    """
    table = {}
    try:
        entries = [entry for entry in os.listdir("/proc") if entry.isdigit()]
    except OSError:
        return None
    for entry in entries:
        try:
            pid = int(entry)
            # errors="replace": a foreign comm may hold
            # non-UTF-8 bytes; the numeric tail still parses,
            # so membership stays attributable instead of
            # crashing the scan.
            with open("/proc/%s/stat" % entry, encoding="utf-8",
                      errors="replace") as handle:
                text = handle.read()
            fields = text.rsplit(")", 1)
            if len(fields) != 2:
                raise ValueError("truncated stat for %s" % entry)
            rest = fields[1].split()
            if len(rest) < 3:
                raise ValueError("truncated stat for %s" % entry)
            ppid = int(rest[1])
            pgid = int(rest[2])
        except (OSError, ValueError):
            # A pid that vanished mid-scan is skipped; a pid
            # that is still present but unreadable -- or whose
            # presence check itself fails -- makes the whole
            # snapshot untrustworthy, so the scan is refused
            # instead of silently dropping the entry.
            try:
                present = _pid_still_present(entry)
            except OSError:
                return None
            if present:
                return None
            continue
        table[pid] = (ppid, pgid, rest[0])
    return table


def _owned_descendants(root, table):
    """Return the pids whose parent chain reaches ``root``.

    Only parent links from a ``_scan_processes`` snapshot are
    followed, so foreign processes are never collected -- but
    orphans already reparented past ``root`` are invisible too,
    which is why the tree kill snapshots before signalling and
    remembers every owned group it saw.
    """
    children = {}
    for pid, (ppid, _pgid, _state) in table.items():
        children.setdefault(ppid, []).append(pid)
    owned = []
    stack = list(children.get(root, []))
    while stack:
        pid = stack.pop()
        owned.append(pid)
        stack.extend(children.get(pid, []))
    return owned


def _signal_live_owned(pgid, table, seen_groups):
    """SIGKILL the living owned tree once; extend the seen groups.

    Only owned pids are signalled: living descendants of the
    suite child plus groups observed holding an owned member --
    never a bare pid used as a group id. Only groups that still
    show a living member are signalled, so dead groups are left
    alone once empty. Returns the living owned pids plus the
    groups that still hold a living member.
    """
    descendants = _owned_descendants(pgid, table)
    for pid in descendants:
        seen_groups.add(table[pid][1])
    live_owned = [
        pid for pid in descendants
        if table[pid][2] not in ("Z", "X")
    ]
    live_groups = set()
    for _ppid, member_pgid, state in table.values():
        if member_pgid in seen_groups and state not in ("Z", "X"):
            live_groups.add(member_pgid)
    for group in sorted(live_groups):
        try:
            os.killpg(group, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    for pid in live_owned:
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    return live_owned, live_groups


def _suite_residue_entries(table, seen_groups):
    """Format living members of owned groups as residue entries."""
    entries = []
    for pid in sorted(table):
        _ppid, pgid, state = table[pid]
        if state in ("Z", "X"):
            continue
        if pgid in seen_groups:
            entries.append(
                "pid %d (pgid %d, state %s)" % (pid, pgid, state)
            )
    return entries


def _kill_suite_tree(pgid):
    """SIGKILL the suite tree; wait for every owned group to empty.

    Suites boot guests as session leaders (their own process
    group), so killing only the suite group would orphan them.
    The owned tree is snapshotted BEFORE signalling -- dead
    parents reparent their orphans and the chain is lost
    afterwards -- and every group that ever held an owned member
    stays a kill candidate while it shows a living member, which
    also reaps already-reparented stragglers that kept their
    group. Zombies count as gone and the wait is best-effort:
    whatever remains, the timeout verdict below stands. Without
    ``/proc`` the snapshot is empty and only the suite group is
    killed, as before.

    Returns the residue: ``pid ... (pgid ..., state ...)``
    entries for owned strays still living after the deadline,
    ``[]`` when the tree reaped cleanly. The timeout record
    carries the entries as evidence; a SIGKILL-immune straggler
    is reported, never silently dropped, and an unreadable
    process table reports the kill unverified, never clean.
    """
    seen_groups = {pgid}
    deadline = time.monotonic() + 30
    first = True
    while time.monotonic() < deadline:
        table = _scan_processes()
        if table is None:
            if first and not os.path.isdir("/proc"):
                # No snapshot (no /proc): fall back to the suite
                # group alone, as before. The kill is
                # unverifiable, so the residue says so honestly.
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                return ["pgid %d kill unverified (no /proc)" % pgid]
            first = False
            # Unreadable table, owned tree possibly alive: keep
            # signalling every owned group seen so far and wait
            # for a trustworthy snapshot. Emptiness can never be
            # verified over read errors, so this path never
            # returns clean.
            for group in sorted(seen_groups):
                try:
                    os.killpg(group, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            time.sleep(0.2)
            continue
        if not table and first:
            # No snapshot (no /proc): fall back to the suite
            # group alone, as before. The kill is unverifiable,
            # so the residue says so honestly.
            try:
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            return ["pgid %d kill unverified (no /proc)" % pgid]
        first = False
        live_owned, live_groups = _signal_live_owned(
            pgid, table, seen_groups
        )
        if not live_owned and not live_groups:
            return []
        time.sleep(0.2)
    final = _scan_processes()
    if final is None:
        return [
            "pgid %d kill unverified (process table unreadable)"
            % pgid
        ]
    return _suite_residue_entries(final, seen_groups)


def run_suite(suite_id, relpath, lane, out_dir, timeout, commit,
              consumer_path, farm=None):
    """Run one suite in one lane; return its result record.

    The suite runs as a session leader, so a timeout kills the
    whole owned suite tree (the suite group plus any detached
    guest groups the suite booted), never just the suite child.
    An interruption reaps the owned suite tree and propagates.

    When ``farm`` (an admitted ``vng``/``virtme-run``/QEMU
    ``PATH`` farm) is given, it heads the suite's ``PATH`` so
    guests the suite boots resolve exactly the admitted chain;
    ambient import-path, loader and shell-startup variables are
    always stripped (in-tree suites self-insert their import
    paths and never need them).

    The lane target manifest and the plan identity travel to
    the suite through the environment; the suite embeds them
    verbatim in its run plan. The incoming target lease (when
    an external disposable-target approval granted one)
    propagates the same way, verbatim and never synthesized:
    an absent or "0" lease stays unleased and the execution
    paths refuse. The verdict comes from
    :func:`accept_suite_output` (re-aggregated terminal
    record); the ``PASS``/``FAIL``/``ENVIRONMENT FAILURE``
    counters below stay as human evidence only. A timeout (or
    any signal death) keeps its signed exit code and fails;
    the timeout verdict additionally carries the tree-kill
    residue as evidence.
    """
    path = os.path.join(REPO_ROOT, relpath)
    record = {
        "suite": suite_id,
        "lane": lane["id"],
        "release": lane["release"],
        "commit": commit,
        "path": relpath,
        "exit_code": None,
        "outcome": "fail",
        "passes": 0,
        "failures": 0,
        "envfailures": 0,
        "timed_out": False,
        "elapsed_secs": None,
        "log": None,
        "verdict": "NO_TERMINAL",
        "kill_residue": [],
    }
    if not os.path.isfile(path):
        record["note"] = "suite file missing: %s" % relpath
        return record
    try:
        expected_cases = SUITE_CASES[suite_id]
    except KeyError:
        record["note"] = (
            "suite %r has no pinned case list" % suite_id
        )
        return record
    try:
        target_manifest = lane_target_manifest(lane)
    except SetupFailure as exc:
        record["note"] = "cannot declare the lane target: %s" % exc
        return record
    try:
        suite_sha256 = sha256_file(path)
    except OSError as exc:
        record["note"] = "cannot hash the suite file: %s" % exc
        return record
    env = dict(os.environ)
    env["MOJOBPF_VNG_RELEASE"] = lane["release"]
    # The matrix never synthesizes a target lease: the
    # incoming environment propagates verbatim, so an absent
    # or "0" lease stays unleased and the execution paths
    # refuse. Only an external disposable-target approval
    # (MOJOBPF_TARGET_LEASE=1 in the matrix's own
    # environment) admits guest boots and in-target loads
    # below this point.
    env[ENV_TARGET_MANIFEST] = json.dumps(
        target_manifest, sort_keys=True
    )
    env[ENV_PLAN_COMMIT] = commit
    env[ENV_PLAN_TOOL] = PLAN_TOOL
    env["LC_ALL"] = "C"
    env.pop("PYTHONOPTIMIZE", None)
    stripped = [
        name for name in execution_mod.SPAWN_ENV_UNSET if name in env
    ]
    for name in stripped:
        env.pop(name, None)
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONSAFEPATH"] = "1"
    path_parts = []
    if farm:
        path_parts.append(farm)
    if suite_id.startswith("packaging-") and consumer_path:
        path_parts.extend(consumer_path)
    path_parts.append(env.get("PATH", ""))
    env["PATH"] = os.pathsep.join(path_parts)
    log_path = os.path.join(
        out_dir, "%s.%s.log" % (lane["id"], suite_id)
    )
    record["log"] = log_path
    record["farm"] = farm
    record["env_stripped"] = stripped
    start = time.monotonic()
    proc = subprocess.Popen(
        [sys.executable, path],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            residue = _kill_suite_tree(proc.pid)
            try:
                stdout, stderr = proc.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
            output = (
                "MATRIX TIMEOUT after %ds\n%s\n%s"
                % (timeout, stdout or "", stderr or "")
            )
            record["timed_out"] = True
            # The signed exit survives: a killed suite reports
            # its signal (typically -9), never a silent None.
            record["exit_code"] = proc.returncode
            record["kill_residue"] = residue
        else:
            output = (stdout or "") + (stderr or "")
            record["exit_code"] = proc.returncode
    except KeyboardInterrupt:
        # An operator abort lands here from any communicate call
        # above: reap the owned suite tree (suites run as session
        # leaders in their own groups, so the terminal interrupt
        # never reaches them), then propagate.
        _kill_suite_tree(proc.pid)
        raise
    record["elapsed_secs"] = round(time.monotonic() - start, 1)
    with open(log_path, "w", encoding="utf-8") as handle:
        handle.write(
            "matrix: suite=%s lane=%s release=%s commit=%s\n"
            % (suite_id, lane["id"], lane["release"], commit)
        )
        handle.write(
            "matrix: farm=%s env_stripped=%s\n"
            % (farm, ",".join(stripped) if stripped else "none")
        )
        handle.write(output)
        if not output.endswith("\n"):
            handle.write("\n")
    for line in output.splitlines():
        # Human evidence only: the verdict below never reads
        # these counters.
        if line.startswith("PASS "):
            record["passes"] += 1
        elif line.startswith("FAIL "):
            record["failures"] += 1
        elif "ENVIRONMENT FAILURE" in line:
            record["envfailures"] += 1
    if record["timed_out"]:
        # A timed-out suite's partial output is unsealed (its
        # terminal record never completed), so it is never
        # parsed: timeout stays its own fail-closed outcome.
        record["outcome"] = "timeout"
        record["note"] = (
            "suite timed out after %ds (exit %s)%s"
            % (
                timeout,
                record["exit_code"],
                (
                    "; kill residue: %s"
                    % ", ".join(record["kill_residue"])
                ) if record["kill_residue"] else "",
            )
        )
        return record
    outcome, note, detail = accept_suite_output(
        suite_id,
        expected_cases,
        output,
        record["exit_code"],
        commit,
        target_manifest,
        suite_sha256,
        SUITE_DENIALS.get(suite_id, {}),
    )
    record["outcome"] = outcome
    record["verdict"] = detail["verdict"]
    record["run_id"] = detail["run_id"]
    record["plan_hash"] = detail["plan_hash"]
    if note:
        record["note"] = note
    return record


def build_parser():
    parser = argparse.ArgumentParser(
        description="Run the kernel proof suites in every pinned VM lane."
    )
    parser.add_argument("--lock", default=DEFAULT_LOCK)
    parser.add_argument(
        "--lane",
        action="append",
        default=[],
        help="lane id to run (default: every pinned lane)",
    )
    parser.add_argument(
        "--suite",
        action="append",
        default=[],
        help="suite id to run (default: every suite)",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        help="directory for per-suite logs and the report",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="per-suite timeout override in seconds",
    )
    parser.add_argument(
        "--consumer-path",
        action="append",
        default=[],
        help="directory prepended to PATH for the consumer suite only "
        "(independent toolchain outside the checkout)",
    )
    return parser


def _remove_farm(farm_dir):
    """Best-effort removal of an admitted PATH farm."""
    shutil.rmtree(farm_dir, ignore_errors=True)


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        lock = load_lock(args.lock)
        commit = git_head()
        dirt = git_clean()
        if dirt:
            raise SetupFailure(
                "worktree is dirty; commit first so every lane "
                "tests the same bits:\n%s" % dirt
            )
        runner = check_runner(lock, lock_path=args.lock)
        atexit.register(_remove_farm, runner["farm"])
        lanes = lock["lanes"]
        if args.lane:
            wanted = set(args.lane)
            lanes = [lane for lane in lanes if lane["id"] in wanted]
            missing = wanted - {lane["id"] for lane in lanes}
            if missing:
                raise SetupFailure(
                    "unknown lane(s): %s" % ", ".join(sorted(missing))
                )
        suites = SUITES
        if args.suite:
            wanted = set(args.suite)
            suites = [item for item in SUITES if item[0] in wanted]
            missing = wanted - {item[0] for item in suites}
            if missing:
                raise SetupFailure(
                    "unknown suite(s): %s" % ", ".join(sorted(missing))
                )
        caches = {}
        for lane in lanes:
            caches[lane["id"]] = check_lane_cache(lane)
        for entry in args.consumer_path:
            if not os.path.isdir(entry):
                raise SetupFailure(
                    "consumer path is not a directory: %s" % entry
                )
        check_consumer_vng_shadow(
            args.consumer_path, runner["realpath"]
        )
        check_consumer_qemu_shadow(
            args.consumer_path,
            runner["qemu_binary"],
            runner["qemu_path"],
        )
        check_consumer_virtme_run_shadow(
            args.consumer_path,
            runner["virtme_run_path"],
        )
    except SetupFailure as exc:
        sys.stderr.write("run_vm_tests: %s\n" % exc)
        return EXIT_SETUP

    if args.out_dir:
        out_dir = args.out_dir
        os.makedirs(out_dir, exist_ok=True)
    else:
        out_dir = tempfile.mkdtemp(prefix="mojobpf-matrix-")
    started = time.time()
    print("matrix: commit %s" % commit)
    print("matrix: runner %s (%s)" % (runner["version"], runner["realpath"]))
    print("matrix: runner digest %s" % runner["digest"])
    print("matrix: farm %s" % runner["farm"])
    print(
        "matrix: qemu %s (%s)"
        % (runner["qemu_version"], runner["qemu_path"])
    )
    print(
        "matrix: virtme-run %s (%s)"
        % (runner["virtme_run_version"], runner["virtme_run_path"])
    )
    print(
        "matrix: lanes %s"
        % ", ".join(
            "%s/%s" % (lane["id"], lane["kernel_release"]) for lane in lanes
        )
    )
    print("matrix: logs at %s" % out_dir)
    sys.stdout.flush()

    results = []
    for lane in lanes:
        for suite_id, relpath, suite_timeout in suites:
            timeout = args.timeout or suite_timeout
            print(
                "matrix: lane=%s suite=%s timeout=%ds ..."
                % (lane["id"], suite_id, timeout)
            )
            sys.stdout.flush()
            record = run_suite(
                suite_id,
                relpath,
                lane,
                out_dir,
                timeout,
                commit,
                args.consumer_path,
                runner["farm"],
            )
            mid_commit = git_head()
            mid_dirt = git_clean()
            if mid_commit != commit or mid_dirt:
                record["outcome"] = "fail"
                record["note"] = (
                    "tree changed mid-run (commit %s, dirt %r); "
                    "same-bits guarantee broken" % (mid_commit, mid_dirt)
                )
            results.append(record)
            print(
                "matrix: lane=%s suite=%s outcome=%s "
                "(exit=%s passes=%d failures=%d envfailures=%d %.1fs)"
                % (
                    lane["id"],
                    suite_id,
                    record["outcome"],
                    record["exit_code"],
                    record["passes"],
                    record["failures"],
                    record["envfailures"],
                    record["elapsed_secs"] or 0,
                )
            )
            sys.stdout.flush()

    report = {
        "tool": "run_vm_tests",
        "commit": commit,
        "python": {
            "executable": sys.executable,
            "version": sys.version.split()[0],
        },
        "consumer_path": list(args.consumer_path),
        "runner": runner_report(runner),
        "lanes": [
            {
                "id": lane["id"],
                "release": lane["release"],
                "accelerator": lane["accelerator"],
                "kernel_release": lane["kernel_release"],
                "cache": caches[lane["id"]],
            }
            for lane in lanes
        ],
        "results": results,
        "elapsed_secs": round(time.time() - started, 1),
    }
    report_path = os.path.join(out_dir, "matrix-report.json")
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")

    print("matrix board (commit %s):" % commit)
    for lane in lanes:
        row = []
        for suite_id, _relpath, _timeout in suites:
            match = [
                item
                for item in results
                if item["lane"] == lane["id"] and item["suite"] == suite_id
            ][0]
            row.append("%s=%s" % (suite_id, match["outcome"]))
        print("  %s: %s" % (lane["id"], " ".join(row)))
    print("matrix report: %s" % report_path)
    bad = [item for item in results if item["outcome"] != "pass"]
    if bad:
        print(
            "matrix: %d/%d lane-suites failed (%s)"
            % (
                len(bad),
                len(results),
                ", ".join(
                    "%s/%s=%s"
                    % (item["lane"], item["suite"], item["outcome"])
                    for item in bad
                ),
            )
        )
        return EXIT_FAILURE
    print("matrix: %d/%d lane-suites passed" % (len(results), len(results)))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
