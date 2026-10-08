<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF compatibility (0.2.0)

What this release is proven with, what it is proven to refuse,
and what it does not claim. Supported here means observed in
the release test runs, not merely untested; every row cites its
proof.

## Supported profiles

Four target profiles exist: `linux-bpfel-v3` (little-endian BPF,
CPU v3, XDP programs plus the `syscalls:sys_enter_getpid`
tracepoint counter and event programs, `core_supported =
false`), `linux-bpfel-v3-core` (everything the base profile
admits, plus the 4096-byte opaque core map value and validated
CO-RE relocation records, `core_supported = true`),
`linux-bpfel-v3-hash` (everything the base profile admits, plus
hash maps with `u32` keys and `u64` values in 1-4 entries,
`core_supported = false`), and `linux-bpfel-v3-reserve`
(everything the base profile admits, plus explicit ring-buffer
reservations through helpers 131, 132, and 133,
`core_supported = false`). A manifest requesting CO-RE under the
base profile fails
(`tests/unit/test_manifest.py::test_core_request_outside_profile_fails`),
a manifest requesting hash maps under the base profile fails
(`tests/unit/test_manifest.py::test_hash_map_type_refused`),
a reservation object inspected under the base profile reports
its reservation helpers as outside the profile
(`tests/elf/test_reserve_struct.py::test_reserve_inspect_profile_gating`),
and all four records pin the exact map types, sizes, value
vocabulary, and helper IDs
(`tests/unit/test_manifest.py::test_profile_registry_holds_supported_profiles`,
`tests/unit/test_manifest.py::test_core_profile_extends_base_with_core_vocabulary`,
`tests/unit/test_manifest.py::test_hash_profile_extends_base_with_hash_vocabulary`,
`tests/unit/test_manifest.py::test_reserve_profile_extends_base_with_reserve_helpers`).

| Role | Proven identity |
|---|---|
| Build/test host | x86-64 Linux; other operating systems are refused with a clear error (`tests/unit/test_build_commands.py::test_cli_refuses_unsupported_platform`) |
| Python driver | 3.11 or later (release runs used 3.14.4); standard library only |
| Mojo compiler | 1.1.0 (`8189361e`) |
| BPF backend | LLVM `llc` 21.1.8, triple `bpfel`, CPU `v3` |
| Loader/observer | `bpftool` 7.7.0 with libbpf 1.7, unmodified |
| Guest runner | virtme-ng 1.41, QEMU 10.2.1, software emulation (TCG) |
| Guest kernels | 6.12.0-061200-generic and 6.6.0-060600-generic (Ubuntu mainline builds, pinned by hash in `ci/kernels.lock.json`) |

Full binary hashes live in `toolchains.lock.json` (host tools)
and `ci/kernels.lock.json` (guest runner plus both kernel
lanes). The release matrix runs every guest-backed suite in
both lanes on the same committed bits
(`ci/run_vm_tests.py`, `tests/kernel/test_cleanup.py` for the
lane-identity assertions).

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
(`bpftool` v7.7.0 with libbpf 1.7, the same versions the x86-64
lanes use) provisioned per boot. The lane is pinned in
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
bytes the tracing suites pin. Hash maps and ring-buffer
reservations are proven on the x86-64 lanes only and are not
claimed on AArch64. The suite also passes natively
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

## Proven refusals

* Entry counts outside 1–4, map kinds outside `ARRAY` /
  `PERCPU_ARRAY` / `RINGBUF` (plus `HASH` under the hash
  capability profile only), ring sizes outside 4096/131072,
  key/value vocabulary on ring buffers, and key widths outside
  the declared dense coverage fail manifest validation with
  `MBPF205`
  (`tests/unit/test_manifest.py::test_ringbuf_unqualified_size_refused`,
  `tests/unit/test_manifest.py::test_ringbuf_key_vocabulary_refused`,
  `tests/unit/test_manifest.py::test_hash_map_type_refused`,
  `tests/unit/test_manifest.py::test_hash_profile_refuses_non_hash_kinds`,
  `tests/unit/test_manifest.py::test_hash_profile_refuses_bad_key_value_sizes`).
* A five-pair program over dense keys 0–4 passes the IR audit
  under its generic N-pair rule but is refused at build time
  with `MBPF107`: no manifest can declare 5 entries and the
  shape has no qualified add-immediate multiset
  (`tests/compile/test_build_pipeline.py::test_five_pair_program_refused_at_build_time`).
* From-program key iteration has no spelling: the kernel
  offers no such helper, so both spellings are refused at the
  audit with `MBPF303` and lowered helper ID 4 is refused at
  inspection with `MBPF407`
  (`tests/elf/test_map_contract.py::test_nextkey_attempt_refused`,
  `tests/elf/test_artifact_contract.py::test_helper4_patched_canonical_object`).
* Nonzero update flags (`BPF_NOEXIST`/`BPF_EXIST`), mixed map
  operations in one program, helpers outside each shape's
  audited set (1–3 for XDP, plus 14 for the tracepoint
  counter, plus 5, 8, and 130 for the event program, plus
  131–133 instead of 130 for the reservation program with
  exactly one reserve and one terminus), and malformed
  reservation shapes (second reserve, second terminus, mixed
  terminus, use after the terminus, wrong store coverage) are
  refused with named diagnostics
  (`tests/elf/test_map_contract.py`,
  `tests/elf/test_artifact_contract.py`,
  `tests/compile/test_subset_rejection.py::test_fixture_rejections`).
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
* Tracing beyond the proven counter, event, and reservation
  programs: only the exact
  `tracepoint/syscalls/sys_enter_getpid` counter, emitter, and
  reservation shapes validate (see the measured limitations
  above). Other events, other filters, context payload reads,
  and per-CPU counting are refused or unclaimed.
* Multi-program objects, other map kinds and sizes, other
  helpers, and other ELFs as inputs: outside the surface.
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
