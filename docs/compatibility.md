<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF compatibility (0.3.0a1)

What this release is proven with, what it is proven to refuse,
and what it does not claim. Supported here means observed in
the release test runs, not merely untested; every row cites its
proof.

## Supported profiles

Eight target profiles exist: `linux-bpfel-v3` (little-endian BPF,
CPU v3, XDP programs plus the `syscalls:sys_enter_getpid`
tracepoint counter and event programs, `core_supported =
false`, `subprog_supported = false`), `linux-bpfel-v3-core`
(everything the base profile admits, plus the 4096-byte opaque
core map value and validated CO-RE relocation records,
`core_supported = true`), `linux-bpfel-v3-hash` (everything the
base profile admits, plus hash maps with `u32` keys and `u64`
values in 1-4 entries, `core_supported = false`),
`linux-bpfel-v3-lru` (everything the base profile admits, plus
LRU hash maps with `u32` keys and `u64` values in 1-4 entries,
reusing the lookup/update/delete helpers, `core_supported =
false`), `linux-bpfel-v3-net` (everything the base profile
admits, plus the socket-filter and TC classifier pairs and the
two skb helpers 9 and 26, `core_supported = false`),
`linux-bpfel-v3-reserve` (everything the base profile admits,
plus explicit ring-buffer reservations through helpers 131,
132, and 133, `core_supported = false`),
`linux-bpfel-v3-subprog` (everything the base profile admits,
plus one static subprogram call on a classifier program,
`subprog_supported = true`), and `linux-bpfel-v3-uprobe`
(everything the base profile admits, plus one controlled uprobe
register counter on a suite-owned test executable,
`core_supported = false`, `subprog_supported = false`). A
manifest requesting CO-RE under the base profile fails
(`tests/unit/test_manifest.py::test_core_request_outside_profile_fails`),
a manifest requesting hash maps under the base profile fails
(`tests/unit/test_manifest.py::test_hash_map_type_refused`),
a manifest requesting LRU maps under the base profile fails
(`tests/unit/test_manifest.py::test_lru_map_type_refused`),
socket/TC pairs under the base profile fail
(`tests/unit/test_manifest.py::test_net_pairs_refused_under_base_profile`),
a reservation object inspected under the base profile reports
its reservation helpers as outside the profile
(`tests/elf/test_reserve_struct.py::test_reserve_inspect_profile_gating`),
a subprogram object inspected under the base profile reports
its `.text` section and its static call as outside the profile
(`tests/elf/test_subprog_struct.py::test_decision_profile_gating`),
a uprobe object inspected under the base profile reports its
`uprobe` section as outside the profile
(`tests/elf/test_uprobe_struct.py::test_uprobe_profile_gating`),
a net object inspected under the base profile reports its
socket/TC sections as outside the profile
(`tests/elf/test_net_struct.py::test_net_profile_gating`),
and all eight records pin the exact map types, sizes, value
vocabulary, and helper IDs
(`tests/unit/test_manifest.py::test_profile_registry_holds_supported_profiles`,
`tests/unit/test_manifest.py::test_core_profile_extends_base_with_core_vocabulary`,
`tests/unit/test_manifest.py::test_hash_profile_extends_base_with_hash_vocabulary`,
`tests/unit/test_manifest.py::test_lru_profile_extends_base_with_lru_vocabulary`,
`tests/unit/test_manifest.py::test_net_profile_extends_base_with_net_pairs`,
`tests/unit/test_manifest.py::test_reserve_profile_extends_base_with_reserve_helpers`,
`tests/unit/test_manifest.py::test_subprog_profile_extends_base_with_subprog_flag`,
`tests/unit/test_manifest.py::test_uprobe_profile_extends_base_with_uprobe_pair`).

| Role | Proven identity |
|---|---|
| Build/test host | x86-64 Linux; other operating systems are refused with a clear error (`tests/unit/test_build_commands.py::test_cli_refuses_unsupported_platform`) |
| Python driver | 3.11 or later (3.14.8 in the current lock); standard library only |
| Mojo compiler | 1.1.0 (`8189361e`) |
| Frontend target | canonical `--target-cpu znver4` plus the frozen feature set (`FRONTEND_TARGET_FLAGS` in `src/mojobpf/build.py`); qualifying captures reproduced byte-identical under the pinned environment, other hosts unproven |
| BPF backend | LLVM `llc` 22.1.8, triple `bpfel`, CPU `v3` |
| Loader/observer | `bpftool` 7.6.0 with libbpf 1.6, unmodified |
| Guest runner | virtme-ng 1.41, QEMU 10.2.2, software emulation (TCG) |
| Guest kernels | 6.12.0-061200-generic and 6.6.0-060600-generic (Ubuntu mainline builds, pinned by hash in `ci/kernels.lock.json`), plus 7.0.14-070014-generic for the joint suite only |

Full binary hashes live in `toolchains.lock.json` (host tools)
and `ci/kernels.lock.json` (guest runner plus both kernel
lanes). The release matrix runs every release-scope
guest-backed suite (the 28 wired suites) in both lanes on the
same committed bits
(`ci/run_vm_tests.py`, `tests/kernel/test_cleanup.py` for the
lane-identity assertions); the portability suite runs as its
own lane (next section), never in the matrix.

Every behavior section below outside the named portability
lanes was observed on the current tested combination (LLVM
22.1.8, bpftool 7.6.0 with libbpf 1.6, QEMU 10.2.2) in both
lanes of the alpha matrix; see
[evidence-0.3.0a1.md](evidence-0.3.0a1.md) for the anchor
board.

Other Mojo, LLVM, `bpftool`, runner, kernel, or host
combinations are unproven, not supported. Other host
architectures need their own runs. Two combinations beyond
the release pins have their own observed runs (next
section); everything else stays unproven.

## Architecture and compiler lanes

Two portability lanes ran beyond the release pins. Each is
pinned in its own lockfile and proven by named suites; neither
changes the supported release pins above.

### AArch64 guest lane (tested)

The same applicable objects run on an AArch64 Linux kernel: a
TCG-emulated `aarch64` guest under `qemu-system-aarch64` 10.2.1
running the same `6.12.0-061200-generic` kernel build as the
primary x86-64 lane (the `arm64` mainline debs), with an Ubuntu
resolute `arm64` cloud-image root and the guest observer
(`bpftool` v7.7.0 with libbpf 1.7, pinned for this lane in its
own lockfile) provisioned per boot. The lockfile's runner
entry was since re-pinned to 10.2.2 without a lane re-run;
that combination is untested. The lane is pinned in
`ci/kernels.arm64.lock.json` (kernel debs, rootfs image hash,
provisioning recipe, runner argv).

`tests/kernel/test_arch_portability.py` proves, on that guest,
exact parity with the x86-64 lanes: the architecture-neutral
XDP classifier and its mutation on three fixtures first, then
the 41-to-42 round trip, a delete probe, boundary-constant
endian words plus a ones-complement checksum window, one
per-CPU entry read through raw `bpf()` against the `bpftool`
dump oracle, an exact-count tracepoint run, and a healthy
event drain decoded by the product decoder. Together the cases
exercise every helper the subset admits (IDs 1, 2, 3, 5, 8,
14, 130) and the three lane-proven map kinds (`ARRAY`,
`PERCPU_ARRAY`, `RINGBUF`) on the AArch64 kernel, with the
counter and emitter objects byte-identical to the qualified
bytes the tracing suites pin. Hash maps, ring-buffer
reservations, and controlled uprobes are proven on the x86-64
lanes only and are not claimed on AArch64 (uprobe register
extraction is architecture-specific by design: x86-64 only).
The suite also passes natively
in both x86-64 lanes, so the comparison is the same test on
three lanes, not three tests.

Where the kernel interface differs by architecture the suite
selects explicitly: the raw `bpf()` reader uses syscall 321 on
x86-64 and 280 on AArch64 and refuses anything else, and the
raw-syscall C holders build with the matching compiler
(`cc` natively, `aarch64-linux-gnu-gcc` for the lane). The
older per-CPU suites keep their hardcoded x86-64 syscall
number, so they stay x86-64-only; the portability suite is
their cross-architecture vehicle.

Correctness only: the lane makes no performance claim, and
emulation timing is never quoted as one.

`bpfeb` (big-endian BPF) is explicitly not covered by this
lane: AArch64 testing validates little-endian `bpfel` objects
on an AArch64 kernel, and big-endian support is a separate
project.

### Mojo 1.0.0 investigational combo (tested, not supported)

Exactly one second Mojo/LLVM combination ran as a
compatibility lane: Mojo 1.0.0 (`ed45d567`) with bundled LLVM
`24.0.0git` at `21b0fc84` (2026-07-31), in a separate
investigational workspace outside the release environment.
The combination is pinned in
`ci/toolchains.investigational.lock.json` (conda package
hashes, binary hash, both LLVM identity routes). It is
investigational: tested and recorded, explicitly not
supported, and the release pins are unchanged. Promoting any
second combination needs its own maintainer decision.

The observed verdict: Mojo-independent suites run identically
(`tests/unit`: 311 passed), and the 1.0.0 frontend compiles
SDK-free kernel sources to byte-identical IR and objects as
1.1.0, proven in-guest by `tests/kernel/test_mojo_xdp.py`
(5/5 on the x86-64 v6.12 lane). But the packaged SDK surface
does not parse under 1.0.0: it uses the 1.1
decorator-argument spelling `@inline(.always)` in every
module, which the older parser rejects, so every
SDK-importing external source fails at the frontend
(95 files: 80 tests + 15 examples; 96 counting the
SDK's own self-import). That count is a source
inventory, not 95 individually observed
compilations: every SDK module uses the spelling,
so any SDK import transitively fails at parse.
Build-driver paths additionally refuse the unpinned compiler
at the toolchain gate (`MBPF102`) exactly as designed.

## Kernel-version boundary: `loop-sum` on 6.6

The bounded-loop subset case `loop-sum` verifies and runs on
6.12 but is rejected by the 6.6 verifier with the kernel's own
reason (`back-edge from insn 18 to 19`). Both verdicts are
pinned exactly: the suite passes on 6.12 only when test-run
actions match the oracle, and passes on 6.6 only when the
verifier rejects with that exact log line; any other behavior
on either lane fails loudly
(`tests/verifier/test_subset_kernel.py::test_loop_sum`,
`docs/supported-subset.md` case table, both matrix lanes).

This is a genuine kernel-version boundary the two-lane matrix
exists to find — not a skipped lane. Programs whose loops the
6.6 verifier rejects must be reshaped; the remaining subset
cases behave identically on both lanes.

## Measured tracing limitations

Tracing is partially claimed in this release: exactly the
tracepoint counter and the fixed-record event emitter below are
proven, and the bounds in this section were measured in the
guest lanes rather than asserted. Everything else under tracing
stays out (see the unsupported list).

* Supported event: only `syscalls:sys_enter_getpid`, spelled
  `tracepoint/syscalls/sys_enter_getpid` in the manifest. Attaching
  to a missing event reports an explicit environment-capability
  failure instead of passing, and every attach failure shape (bad
  pin, missing event, type mismatch, duplicate) classifies with no
  residue
  (`tests/kernel/test_tracepoint_counter.py::test_missing_tracepoint_unavailability`,
  `tests/kernel/test_tracing_lifecycle.py::test_attach_failures_classified`).
* Filtering semantics: the program compares the low 32 bits of the
  helper-14 word (the TID, never the TGID) against the filter entry;
  both sides observe the initial PID namespace. With the filter set
  to the monitored thread, exactly N=10000 monitored `getpid` calls
  count 10000 while two excluded threads issuing 1000 calls each
  count 0; with the monitored thread idle the excluded phase
  observes 0; a filter naming TID 2147483647 (which no thread
  holds) observes 0 as a controlled mismatch; and a TGID-confused
  mutant observes 0 while the reloaded base still observes N
  (`tests/kernel/test_tracepoint_counter.py::test_exact_count`,
  `tests/kernel/test_tracepoint_counter.py::test_excluded_phase_zero`,
  `tests/kernel/test_tracepoint_counter.py::test_wrong_filter_mismatch`,
  `tests/kernel/test_tracepoint_counter.py::test_tgid_mutant_mismatch_and_stale_base`).
* Record ABI: one 32-byte little-endian record per matching call
  (version 1, size 32, TGID, TID, CPU, per-run sequence, monotonic
  nanoseconds; every byte initialized), decoded by an independent
  tool-side decoder that is total over hostile bytes (see the
  record table in `docs/sdk.md`,
  `tests/elf/test_event_struct.py::test_event_record_layout_proof`,
  `tests/unit/test_event_decoder.py::test_fuzz_never_crashes_and_classifies`).
* Loss accounting: the producer advances its attempt sequence on
  every attempted output including failures, so attempted equals
  successful plus failed and drained records equal successful, with
  the missing attempts established via the producer counters as a
  trailing tail: the drained records form the exact successful
  prefix with zero interior gaps. A healthy consumer drains the
  full workload with zero loss and contiguous sequences; a stopped
  consumer on the one-page ring observes nonzero explicit loss with
  the drained records forming the exact successful prefix; and
  SIGKILLing the consumer between completed drain batches loses no
  kernel records, and the restarted consumer resumes with 2500
  contiguous records, failed=0, at byte offset 80000
  (`tests/kernel/test_tracepoint_events.py::test_healthy_exact_accounting`,
  `tests/kernel/test_tracepoint_events.py::test_saturation_explicit_loss`,
  `tests/kernel/test_tracepoint_events.py::test_crash_keeps_position_no_kernel_loss`).
* Lifecycle and licensing: process exit and mid-run interruption
  keep owned links, pins, FDs, mounts, and child processes clean
  across repeated runs; unsupported map types and trace events are
  refused by a fail-safe preflight with clear diagnostics, never a
  crash or a fake pass; helper license restrictions are enforced by
  a preflight diagnostic that agrees with the kernel verifier; and
  no artifact's license declaration is ever rewritten to gain helper
  access
  (`tests/kernel/test_tracing_lifecycle.py::test_process_exit_exact`,
  `tests/kernel/test_tracing_lifecycle.py::test_repeated_runs_cleanup`,
  `tests/kernel/test_tracing_lifecycle.py::test_failsafe_map_preflight`,
  `tests/kernel/test_tracing_lifecycle.py::test_failsafe_event_preflight`,
  `tests/verifier/test_helper_licenses.py::test_kernel_rejects_gpl_only_helper`,
  `tests/verifier/test_helper_licenses.py::test_declaration_never_rewritten`).

## Measured CO-RE limitations

CO-RE is narrowly claimed in this release: exactly one
relocated field read (`task_struct.pid`) plus one optional-field
existence check (`task_struct.scx`), admitted only under the
`linux-bpfel-v3-core` profile. The inspection parses and
validates the relocation record content (an unsupported kind,
zero records, or a corrupt header each fail with their own
diagnostic), and identical object bytes load on both lanes with
the loader resolving each lane's offsets
(`tests/core/test_core_object.py::test_core_profile_verdicts`,
`tests/core/test_core_object.py::test_core_btfext_negatives_refused`,
`tests/kernel/test_core_layouts.py::test_relocated_read_matches_lane_marker`,
`tests/kernel/test_core_layouts.py::test_exists_bit_matches_lane_layout`).
Everything else under CO-RE stays out (see the unsupported list).

## Measured hash-map behavior

Hash maps are claimed narrowly in this release: `u32` keys and
`u64` values in 1-4 entries, admitted only under the
`linux-bpfel-v3-hash` profile, with the existing lookup, update
(`BPF_ANY` only), and delete helpers. On both x86-64 lanes the
four-entry round trip initializes keys 0-3 to 41 and observes
exactly 42 after one run and exact quiesced counts after
repeated runs; absent keys miss without inserting anything; a
userspace insert followed by a run increments exactly the
inserted key; the delete probe observes success and every entry
is gone; arbitrary keys (including `0xDEADBEEF`) round-trip
with exact little-endian bytes and a get-next-key walk plus a
JSON dump observe exactly the inserted set (hash order is
unspecified, so iteration order is never claimed); the fifth
insert into a 4-entry map fails; and short keys and values are
refused
(`tests/kernel/test_hash_maps.py::test_lifecycle_init_run_observe`,
`tests/kernel/test_hash_maps.py::test_exact_counts_after_quiescence`,
`tests/kernel/test_hash_maps.py::test_miss_path_inserts_nothing`,
`tests/kernel/test_hash_maps.py::test_scoped_update_after_insert`,
`tests/kernel/test_hash_maps.py::test_kernel_delete_removes_entries`,
`tests/kernel/test_hash_maps.py::test_userspace_delete_lifecycle`,
`tests/kernel/test_hash_maps.py::test_iteration_set_and_bytes`,
`tests/kernel/test_hash_maps.py::test_budget_and_sizes_refused`).
Out-of-bounds and unchecked hash programs are rejected by the
kernel verifier at load
(`tests/kernel/test_hash_maps.py::test_oob_rejected_by_verifier`,
`tests/kernel/test_hash_maps.py::test_unchecked_rejected_by_verifier`),
and an independent consumer builds its own hash tally through
the installed package and observes 41 to 42 to 43 in the kernel
(`tests/packaging/test_hash_consumer.py::test_consumer_exact_kernel_result`).
Everything else under hash maps stays out (see the unsupported
list): other key/value widths, other entry counts, `BPF_NOEXIST`
/ `BPF_EXIST` spellings, and from-program iteration.

## Measured uprobe behavior

Controlled uprobes are claimed narrowly in this release: one
uprobe program per build, attached at load time to one symbol of
a suite-owned test executable, reading exactly the pinned x86-64
first-argument register (`pt_regs` word 14, `rdi`), admitted
only under the `linux-bpfel-v3-uprobe` profile, with the
existing lookup and update (`BPF_ANY` only) helpers and a
two-entry array map. On both x86-64 lanes, with the expected
argument 41: 1000 calls carrying 41 are counted exactly 1000
with every oracle word equal to 41; 500 calls carrying 43 leave
the counter at 0 with every oracle word equal to 43; the
inverted mutant counts exactly the 500 mismatching calls; the
reloaded base object counts exactly 1000 again; and a probe
attached to the never-called symbol observes 0 while the
workload's 1000 calls proceed normally
(`tests/kernel/test_uprobe_register.py::test_match_exact_with_oracle`,
`tests/kernel/test_uprobe_register.py::test_mismatch_zero_with_oracle`,
`tests/kernel/test_uprobe_register.py::test_inverted_counts_mismatches`,
`tests/kernel/test_uprobe_register.py::test_reload_live_state`,
`tests/kernel/test_uprobe_register.py::test_never_called_zero`).
A guest without the tracefs uprobe interface reports an explicit
environment-capability failure instead of passing
(`tests/kernel/test_uprobe_register.py::test_unavailability_reported`),
an out-of-range probe offset fails the perf open loudly
(`tests/kernel/test_uprobe_register.py::test_bad_offset_refused`),
and an out-of-bounds context mutant that clears host inspection
is rejected by the kernel verifier at load
(`tests/kernel/test_uprobe_register.py::test_verifier_rejects_oob_context`),
while the loader refuses any non-test-binary target before
touching tracefs
(`tests/kernel/test_uprobe_register.py::test_holder_refuses_non_test_binary`).
An independent consumer builds its own uprobe tally through the
installed package and observes 200/0/0 with oracle agreement in
the kernel
(`tests/packaging/test_uprobe_consumer.py::test_consumer_exact_kernel_result`).
Everything else under uprobes stays out: other registers, other
widths, second reads, context writes, AArch64 extraction,
multi-probe graphs, mixed uprobe/XDP builds, and system-binary
targets.

## Measured networking behavior

Socket-filter and TC classifier programs are claimed narrowly
in this release: the `("socket", "socket")` and `("tc",
"classifier")` pairs admitted only under the
`linux-bpfel-v3-net` profile, with the skb helpers 26
(`skb_load_bytes`) and 9 (`skb_store_bytes`) in their
audited shapes (one skb helper call plus its initialized key
slot; the buffer must be an initialized keyslot and the call
spelling must match genuine Mojo emission). On both x86-64
lanes, over a five-frame corpus keyed on byte 14 (42
matches, 43 does not, plus a short frame): the socket legs
attach live to `AF_PACKET` and observe exactly the manifest
arrival per frame (verdict 64 arrives with exact byte
counts, verdict 0 does not), while the rebuilt inverted-bit
mutant flips exactly the long frames' arrivals; the TC legs
observe exactly the manifest verdicts (0/2 per frame)
through test-run, the rebuilt mutant changes the observed
verdicts, and a stale object fails
(`tests/kernel/test_net_classifier.py::test_socket_attach_verdicts`,
`tests/kernel/test_net_classifier.py::test_socket_attach_mutation_flips`,
`tests/kernel/test_net_classifier.py::test_tc_baseline_verdicts`,
`tests/kernel/test_net_classifier.py::test_tc_mutation_flips_verdicts`,
`tests/kernel/test_net_classifier.py::test_tc_stale_object_fails`).
The TC store leg observes the stored packet bytes out, and
the loadmap leg reads a map value back through skb-load plus
update
(`tests/kernel/test_net_classifier.py::test_tc_store_packet_out`,
`tests/kernel/test_net_classifier.py::test_tc_load_map_readback`).
Socket verdicts require the real attach: test-run shows the
L3 view, so verdict legs never run detached. Everything else
under networking stays out: tcx programs, other sections,
other helpers on these pairs, attach beyond the proven
socket legs, and XDP attach.

## Measured LRU behavior

LRU hash maps are claimed narrowly in this release: `u32`
keys and `u64` values in 1-4 entries, admitted only under
the `linux-bpfel-v3-lru` profile, with the existing lookup,
update (`BPF_ANY` only), and delete helpers. On both x86-64
lanes the one-entry lifecycle shapes initialize key 0 to 41
and observe exactly 42 after one run with exact quiesced
counts after repeated runs; absent keys miss without
inserting anything; a userspace insert followed by a run
increments exactly the inserted key; the delete probe
observes success and every entry is gone; a get-next-key
walk plus a JSON dump observe exactly the inserted set
(hash order is unspecified, so iteration order is never
claimed); oversize keys/values and entry counts are refused;
and a pigeonhole leg over-fills a small map and proves the
kernel evicted (the last key stays present, at most 4 entries
survive, and at least one early key misses — eviction
occurred, but no victim identity is asserted, so recency
ordering itself is not proven)
(`tests/kernel/test_lru_maps.py::test_lifecycle_init_run_observe`,
`tests/kernel/test_lru_maps.py::test_exact_counts_after_quiescence`,
`tests/kernel/test_lru_maps.py::test_miss_path_inserts_nothing`,
`tests/kernel/test_lru_maps.py::test_scoped_update_after_insert`,
`tests/kernel/test_lru_maps.py::test_kernel_delete_removes_entries`,
`tests/kernel/test_lru_maps.py::test_userspace_delete_lifecycle`,
`tests/kernel/test_lru_maps.py::test_iteration_set_and_bytes`,
`tests/kernel/test_lru_maps.py::test_sizes_refused`,
`tests/kernel/test_lru_maps.py::test_eviction_evicts_lru_entry`).
Out-of-bounds and unchecked LRU programs are rejected by the
kernel verifier at load
(`tests/kernel/test_lru_maps.py::test_oob_rejected_by_verifier`,
`tests/kernel/test_lru_maps.py::test_unchecked_rejected_by_verifier`).
The iteration leg pins its map operations to one CPU to
control 6.6 per-CPU free-list stranding, a kernel-allocator
placement variance a C control shows identically. Everything
else under LRU stays out (see the unsupported list): other
key/value widths, other entry counts, `BPF_NOEXIST` /
`BPF_EXIST` spellings, and from-program iteration.

## Proven refusals

* Entry counts outside 1–4, map kinds outside `ARRAY` /
  `PERCPU_ARRAY` / `RINGBUF` (plus `HASH` under the hash
  capability profile only, plus `LRU_HASH` under the LRU
  capability profile only), ring sizes outside 4096/131072,
  key/value vocabulary on ring buffers, and key widths outside
  the declared dense coverage fail manifest validation with
  `MBPF205`
  (`tests/unit/test_manifest.py::test_ringbuf_unqualified_size_refused`,
  `tests/unit/test_manifest.py::test_ringbuf_key_vocabulary_refused`,
  `tests/unit/test_manifest.py::test_hash_map_type_refused`,
  `tests/unit/test_manifest.py::test_hash_profile_refuses_non_hash_kinds`,
  `tests/unit/test_manifest.py::test_hash_profile_refuses_bad_key_value_sizes`,
  `tests/unit/test_manifest.py::test_lru_map_type_refused`,
  `tests/unit/test_manifest.py::test_lru_profile_refuses_non_lru_kinds`,
  `tests/unit/test_manifest.py::test_lru_profile_refuses_bad_key_value_sizes`).
* A five-pair program over dense keys 0–4 passes the IR audit
  under its generic N-pair rule but is refused at build time
  with `MBPF107`: no manifest can declare 5 entries and the
  shape has no qualified add-immediate multiset
  (`tests/compile/test_build_pipeline.py::test_five_pair_program_refused_at_build_time`).
* From-program key iteration has no spelling: the kernel
  offers no `map_get_next_key`-style helper and the
  callback-based `for_each_map_elem` helper is outside the
  subset's scope, so both spellings are refused at the audit
  with `MBPF303` and lowered helper ID 4 is refused at
  inspection with `MBPF407`
  (`tests/elf/test_map_contract.py::test_nextkey_attempt_refused`,
  `tests/elf/test_artifact_contract.py::test_helper4_patched_canonical_object`).
* Nonzero update flags (`BPF_NOEXIST`/`BPF_EXIST`), mixed map
  operations in one program, helpers outside each shape's
  audited set (1–3 for XDP, plus 14 for the tracepoint
  counter, plus 5, 8, and 130 for the event program, plus
  131–133 instead of 130 for the reservation program with
  exactly one reserve and one terminus, plus 9 and 26 on the
  net pairs only), and malformed
  reservation shapes (second reserve, second terminus, mixed
  terminus, use after the terminus, wrong store coverage) are
  refused with named diagnostics
  (`tests/elf/test_map_contract.py`,
  `tests/elf/test_artifact_contract.py`,
  `tests/compile/test_subset_rejection.py::test_fixture_rejections`).
* Socket/TC shapes outside the net profile (wrong section,
  wrong entry symbol, skb bodies under another entry, skb
  calls with uninitialized or missing keyslots, malformed skb
  call shapes) are refused at the manifest or the audit with
  named codes (`MBPF205`/`MBPF302`/`MBPF303` family)
  (`tests/unit/test_manifest.py::test_net_wrong_section_refused`,
  `tests/compile/test_subset_rejection.py::test_fixture_rejections`,
  `tests/ir/test_audit.py::test_skb_call_shapes_reject`,
  `tests/ir/test_audit.py::test_skb_body_under_xdp_rejected`,
  `tests/ir/test_audit.py::test_skb_load_missing_decl_rejected`),
  and net objects under profiles without the net capability
  are refused at inspection (`MBPF406`)
  (`tests/elf/test_net_struct.py::test_net_profile_gating`).
* BPF-to-BPF calls outside the single proven shape (more than
  one callee, any other arity or type, recursion, indirect
  calls, calls inside the callee, extra attribute sets,
  map/helper calls alongside the callee, or calls outside XDP
  classifiers) are refused at the audit with named codes
  (`MBPF302`/`MBPF303`/`MBPF306`/`MBPF307`/`MBPF309`/`MBPF312`/`MBPF313`/`MBPF314`/`MBPF316`),
  and call programs under profiles without the subprogram
  capability are refused at inspection (`MBPF406`/`MBPF407`)
  (`tests/compile/test_subset_rejection.py::test_fixture_rejections`,
  `tests/elf/test_subprog_struct.py::test_decision_profile_gating`,
  `docs/supported-subset.md`, subprogram section).
* Context reads outside the single pinned x86-64 uprobe word
  (another word, another width, a second read, a missing read,
  a key-order violation, or a context write), uprobe bodies
  under another entry symbol, and multi-probe or mixed
  uprobe/XDP builds are refused with named codes
  (`MBPF302`/`MBPF307`/`MBPF211`/`MBPF317`), and uprobe objects
  under profiles without the uprobe capability are refused at
  inspection (`MBPF406`)
  (`tests/compile/test_subset_rejection.py::test_fixture_rejections`,
  `tests/unit/test_manifest.py::test_two_uprobe_programs_refused`,
  `tests/unit/test_manifest.py::test_uprobe_plus_xdp_program_refused`,
  `tests/elf/test_uprobe_struct.py::test_uprobe_profile_gating`,
  `docs/supported-subset.md`, uprobe section).
* Unoptimized (`-O0`), debug (`-g`), and foreign-target
  builds are refused at the audit or the frontend, never
  silently rebuilt (`docs/supported-subset.md`, optimization
  section).
* Unsupported platforms fail before anything compiles
  (`tests/unit/test_build_commands.py::test_cli_refuses_unsupported_platform`).

## Explicitly unsupported

* CO-RE beyond the proven slice: other types, fields, and
  relocation kinds are refused at the audit, the inspection, or
  the loader (see the measured limitations above). BTF outside
  the core profile covers map metadata only, and a manifest
  requesting CO-RE under the base profile fails.
* Tracing beyond the proven counter, event, reservation, and
  uprobe programs: only the exact
  `tracepoint/syscalls/sys_enter_getpid` counter, emitter, and
  reservation shapes plus the single pinned-register uprobe
  shape validate (see the measured limitations above). Other
  events, other filters, context reads outside the pinned
  uprobe word, and per-CPU counting are refused or unclaimed.
* Multi-program objects, other map kinds and sizes (LPM
  tries included), other helpers, and other ELFs as inputs:
  outside the surface.
* tcx programs, XDP attach (objects load and run under
  test-run only), and attach beyond the proven socket legs:
  outside the surface.
* Kernel 7.x beyond the joint-only lane: no full matrix ran
  there, so no 7.x claim extends past the joint cells (see
  the pair matrix).
* Content-derived variable packet offsets, variable-length
  checksum windows, stacked VLAN tags, and deeper header
  chains: unproven (see the
  [architecture non-claims](architecture.md#explicit-non-claims)).
* KVM acceleration: the release runs pin software emulation
  for every lane. `verify --kernel` accepts `--accelerator
  kvm`, but no release proof ran under KVM.

## Audit boundaries

The IR audit's guarantees cover the instruction shapes the
qualified frontend emits, and two boundaries bind every claim
above: the pointer-store check skips stores it cannot parse
(constant-expression operands fail open), and comparison
predicates are untainted by design. Both are disclosed with
their rationale in the
[architecture non-claims](architecture.md#explicit-non-claims).
