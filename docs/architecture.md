<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF architecture

MojoBPF compiles Mojo-authored Linux eBPF programs into conventional
`EM_BPF` ELF objects loadable by unmodified libbpf/bpftool. This document
describes the validated pipeline, the exact supported subset, the pinned
toolchain it was proven with, and what is explicitly not claimed. Every
support claim below names a test file a reader can run; anything without
such a pointer is unproven.

## Pipeline

```text
Mojo source
  -> Mojo frontend IR (`mojo build --emit llvm`)
  -> exact-match adapter (`compiler/mojo_ir_adapter.py`)
  -> BPF backend (`llc -mtriple=bpfel -mcpu=v3 -filetype=obj`)
  -> standard ELF object
  -> unmodified libbpf/bpftool
  -> Linux kernel (load, verify, test-run)
```

The kernel-side algorithm always originates in Mojo source. The adapter
retargets module metadata (the target triple, the data layout, the
section attribution — `xdp` for the XDP entrypoint, the tracepoint
event section for the tracepoint entrypoint — the entrypoint
codegen attributes, and appended license/map/BTF metadata blocks)
and performs exactly two further helper-related edits: it replaces
the callee operand of each admitted helper pseudo-call with the
standard helper-call encoding (`@__mojobpf_lookup_v1` becomes
`inttoptr (i64 1 to ptr)`, `@__mojobpf_update_v1` becomes
`inttoptr (i64 2 to ptr)`, `@__mojobpf_delete_elem_v1` becomes
`inttoptr (i64 3 to ptr)`, `@__mojobpf_get_pid_tgid_v1`
becomes `inttoptr (i64 14 to ptr)`,
`@__mojobpf_ktime_get_ns_v1` becomes `inttoptr (i64 5 to ptr)`,
`@__mojobpf_get_smp_processor_id_v1` becomes
`inttoptr (i64 8 to ptr)`, and `@__mojobpf_ringbuf_output_v1`
becomes `inttoptr (i64 130 to ptr)`, preserving type, arguments,
result, and position), and it removes the now-unreferenced
reserved helper declarations (exactly one per used helper).
Every other body line in the adapted IR is byte-identical to the
frontend output, except on the core shape, whose relocation call
sites expand to loads plus the `llvm.bpf.passthrough` intrinsic;
the raw file is preserved next to the adapted
file so reviewers can diff them
(`tests/ir/test_adapter_validation.py::test_map_adapt_lowers_only_callees`,
`tests/ir/test_helper_lowering.py::test_delete_lowers_to_helper_3`,
`tests/ir/test_adapter_validation.py::test_tracepoint_adapt_lowers_only_callees`,
`tests/ir/test_helper_lowering.py::test_event_lowered_callee_lines`,
`compiler/audit.py` `LOWERED_CALLEE`). There is no
source-to-C translation, no hidden C kernel code, and no runtime stub.

Concretely, from the repository root with the project Mojo environment
active:

```bash
mojo build --emit llvm -o out/xdp_pass.ll examples/xdp_pass/xdp_pass.mojo
python3 compiler/mojo_ir_adapter.py --input out/xdp_pass.ll \
    --output out/xdp_pass.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/xdp_pass.bpf.ll \
    -o out/xdp_pass.bpf.o
```

## Validated subset

The supported shape is deliberately tiny. All of the following were
demonstrated in a Linux guest; each bullet names its proof.

- A single entrypoint per program — `i32 @xdp_entry(ptr)` for XDP
  programs, `i32 @trace_entry(ptr)` for the tracepoint counter
  and the tracepoint event program, `i32 @uprobe_entry(ptr)`
  for the uprobe register counter, `i32 @socket_entry(ptr)` for
  the socket-filter classifier, and `i32 @tc_entry(ptr)` for the
  TC classifier — taking the kernel context
  pointer with no hidden parameters and no ordinary runtime
  calls, plus, in the subprogram shape only, exactly one
  `i64 (i64)` callee under a plain C-identifier name: the probe
  exports contain no call or invoke instructions and the module
  declares no external functions; the kernel programs' only
  calls are the reviewed shapes below, and the entry symbol
  always matches the body shape
  (`tests/compile/test_probe_export.py`,
  `tests/ir/test_probe_abi.py`,
  `tests/ir/test_adapter_validation.py::test_tracepoint_shape_validates`).
- Integer-only program bodies using fixed-width scalars and pointers;
  no globals, no intrinsics, no unwinding, no floating-point or
  unsupported vector types, no address spaces, and no external
  declarations besides the reserved helper declarations (exactly
  one per used helper: lookup, update, delete, current-PID/TID,
  clock, CPU, ring-buffer output, reserve, submit, discard)
  (`tests/ir/test_adapter_validation.py`,
  `tests/ir/test_audit.py`).
- Calls restricted to the reviewed exact shapes: the tied
  register-reinterpretation cast, the map address load, the key
  scratch-slot preparations (key-0, key-1, and the keyed slots
  for wider counts, all inline assembly), the optional per-CPU
  kind tags (which emit no code), the value scratch-slot
  preparation, and — for the event program only — the
  ring-buffer map address load, the ring-size tag, and the event
  scratch buffer with its per-field views, plus the
  lookup/update/delete/PID-TID/clock/CPU/output/reserve/
  submit/discard helper invocations as ordinary direct calls to
  reserved declarations, lowered by the adapter to the standard
  helper-call encoding so argument registers, the result
  register, and the caller-saved clobbers come from backend call
  lowering, plus — for the subprogram shape only — tail calls
  from the entrypoint body to the one callee, which pass through
  to the backend unlowered. The audit admits nine frozen count
  vectors (the packet classifier, the single-pair map round
  trip, the combined packet workload, the tracepoint counter,
  the tracepoint event emitter, the two reservation emitters,
  the core relocation probe, and the uprobe register counter,
  whose pinned context-word read is pinned alongside its
  vector), plus the classifier-plus-subprogram shape, which
  reuses the classifier vector with callee/call-site structure,
  plus bounded count
  families: N read-modify-write pairs over dense keys 0 to N-1, N
  deletions over dense keys 0 to N-1 (never mixed with pairs in
  one program), and per-CPU twins of the pair, delete, and
  combined shapes; anything else is rejected with a named
  diagnostic (`compiler/audit.py` `_check_counts`,
  `tests/ir/test_adapter_validation.py`,
  `tests/compile/test_subset_rejection.py`,
  `tests/ir/test_audit.py`).
- A packet classifier with an explicit bounds check: frames of at
  least 15 bytes with bit 0 of byte 14 set return `XDP_DROP` (1),
  everything else returns `XDP_PASS` (2). Both actions were observed
  in the kernel via test-run, a one-line source mutation swapped the
  observed behavior, and the stale object failed the new expectation
  (`tests/kernel/test_mojo_xdp.py`,
  `examples/xdp_pass/README.md`).
- A TC classifier with the same shape: frames of at least 15 bytes
  with bit 0 of byte 14 set return `TC_ACT_SHOT` (2), everything
  else returns `TC_ACT_OK` (0). Both verdicts were observed in the
  kernel via test-run over a pinned frame corpus, the inverted-bit
  mutant flipped every verdict, and the stale object failed the new
  expectation (`tests/kernel/test_net_classifier.py`,
  `examples/tc_classifier/README.md`).
- One subprogram decision: the classifier rule above with the bit
  test computed in a single `(i64) -> i64` callee reached
  through one static call. Both definition orders build and
  execute with input-dependent boards through the call on both
  x86 lanes, the call-free inverted mutant shows a different
  board, and the verifier log shows the subprogram (`func#0` /
  `func#1` with caller/callee frames)
  (`tests/kernel/test_subprog_calls.py`,
  `tests/elf/test_subprog_struct.py`,
  `examples/subprog_call/README.md`).
- One helper-based map round trip: a one-entry `ARRAY` map with u32
  key and u64 value, initialized to 41 from userspace, checked lookup
  (null-tested before dereference) plus update through helpers 1 and
  2, with the final value 42 read back independently. The plus-two
  mutation observes 43; the stale object still observes 42 and fails
  the new expectation (`tests/kernel/test_map_roundtrip.py`).
- One TID-filtered tracepoint counter: on `syscalls:sys_enter_getpid`
  the program compares the low 32 bits of the helper-14 word (the
  TID, never the TGID) against the filter in entry 0 of a
  two-entry `ARRAY` map and counts matches in entry 1, reading no
  tracepoint context payload. Userspace initializes the filter and
  the zero counter; a raw-syscall workload then observes exactly N
  counts for the monitored thread, zero for excluded threads, and a
  controlled mismatch under a wrong filter or a TGID-confused
  mutant (`tests/kernel/test_tracepoint_counter.py`,
  `tests/elf/test_tracepoint_struct.py`,
  `examples/tracepoint_counter/README.md`).
- One TID-filtered tracepoint event program: on
  `syscalls:sys_enter_getpid` the program emits one 32-byte
  fixed record (version, size, TGID, TID, CPU, per-run
  sequence, monotonic clock) per matching call through the
  copy-output helper into a ring-buffer map, advancing the
  attempt sequence on every attempt including failures and
  exactly one of the success/failure counters per attempt.
  The layout is proven byte-exact four ways, the independent
  decoder is total over hostile bytes, and the kernel proves
  exact healthy accounting, saturation loss on a stopped
  consumer, consumer restart across SIGKILL, TGID and version
  mutants, and a C control producer
  (`tests/kernel/test_tracepoint_events.py`,
  `tests/elf/test_event_struct.py`,
  `tests/unit/test_event_decoder.py`,
  `examples/tracepoint_events/README.md`).
- One TID-filtered tracepoint reservation program: on
  `syscalls:sys_enter_getpid` the program emits one 32-byte
  fixed record per matching call through an explicit
  ring-buffer reservation (reserve, stamp the record into the
  reservation, submit exactly once; discard releases
  unpublished), advancing the attempt sequence on every
  attempt including null reservations and exactly one of the
  released-or-success/failed counters per attempt. The
  encoder's seven reservation-relative stores cover all 32
  record bytes before the single terminus, the map BTF is
  byte-identical to the copy-output pair, and the kernel
  proves exactly-once submit publication, discard silence,
  null-reserve saturation accounting, and verifier rejection
  of the four adversarial interleavings
  (`tests/kernel/test_ringbuf_reserve.py`,
  `tests/elf/test_reserve_struct.py`,
  `examples/ringbuf_reserve/README.md`).
- One controlled uprobe register counter: on a uprobe attached
  to one symbol of a suite-owned test executable the program
  reads the probed call's first argument from the pinned x86-64
  register word (`pt_regs` word 14, `rdi`), compares it against
  the expected value in entry 0 of a two-entry `ARRAY` map, and
  counts matches in entry 1, reading no other context. Userspace
  initializes the filter and the zero counter; a workload whose
  every call reports its argument over an oracle channel then
  observes exactly N counts for matching calls, zero for
  mismatching calls and for a probe on a never-called symbol,
  and the inverted mutant counts exactly the mismatches
  (`tests/kernel/test_uprobe_register.py`,
  `tests/elf/test_uprobe_struct.py`,
  `examples/uprobe_counter/README.md`).
- Standard object layout: `EM_BPF` relocatable, exactly one
  executable section holding exactly one function (two sections,
  `.text` plus the entry section, in the subprogram shape, with
  one static call and one `R_BPF_64_32` relocation against the
  callee), exact license bytes, map relocations against `.maps`,
  and map BTF parsed independently and cross-checked against
  `bpftool btf dump` (`tests/elf/test_minimal_object.py`,
  `tests/elf/test_map_btf.py`,
  `tests/elf/test_subprog_struct.py`).
- Layered rejection: a missing map reference is rejected by the
  adapter at compile time; an out-of-bounds value access and an
  unchecked null dereference both compile and are then rejected by
  the kernel verifier with its own logged reason
  (`tests/elf/test_map_btf.py`, `tests/kernel/test_map_roundtrip.py`).
- A generalized map SDK slice: `ARRAY`, `PERCPU_ARRAY`,
  `HASH`, `LRU_HASH`, and `PERCPU_HASH` maps with u32 keys and
  u64 values in
  one- to four-entry sizes, named update flags (`BPF_ANY`
  lowers; `BPF_NOEXIST`/`BPF_EXIST` are refused with a named
  diagnostic), documented mutation semantics, layout/BTF
  proofs per shape at all 40 shapes, and kernel proofs per
  operation and kind at the measured counts for the array,
  per-CPU, and hash kinds: read-modify-write lifecycle (41 to
  42) and exact counts per entry, deletion refused with
  `-EINVAL` per key on the preallocated kinds and succeeding
  per key on hash maps, userspace key iteration (a get-next-key
  walk visits
  keys 0 to N-1 and reports end-of-map `-ENOENT` on the
  preallocated kinds, and visits exactly the inserted set on
  hash maps with unspecified order; the kernel offers no
  `map_get_next_key`-style from-program helper — the
  callback-based `for_each_map_elem` helper is outside this
  SDK's scope — so from-program attempts are refused at the
  audit and programs walk entries with open-coded lookups),
  first/last keys, invalid sizes, and out-of-range keys, with
  layout/BTF mismatch rejected by the loader rather than
  misdecoded. Hash kernel behavior ran at 4 entries (suite)
  plus an independent 2-entry read-modify-write consumer
  proof; the 1-entry hash shape is a load/unload proof
  (LRU kernel behavior is proven by `tests/kernel/test_lru_maps.py`:
  lifecycle, exact counts, miss path, delete, iteration,
  eviction, size refusals, and verifier negatives; the LRU slice
  here covers the host pipeline: profile, kind tag, map/BTF
  emission, and reconciliation). (Per-CPU-hash kernel behavior
  is proven by `tests/kernel/test_percpu_hash_maps.py`: lifecycle,
  exact counts, miss path, delete, iteration, the full-map
  `E2BIG` refusal, CPU isolation, size refusals, and verifier
  negatives; the per-CPU-hash slice here covers the host
  pipeline: profile, kind tag, map/BTF emission, and
  reconciliation).
  (`src/mojobpf/resources/sdk/mojobpf/maps.mojo`,
  `tests/compile/maps_*.mojo`, `tests/compile/percpu_*.mojo`,
  `tests/compile/hash_*.mojo`, `tests/compile/maps_hash_*.mojo`,
  `tests/compile/lru_*.mojo`, `tests/compile/maps_lru_*.mojo`,
  `tests/compile/percpuhash_*.mojo`,
  `tests/compile/maps_percpuhash_*.mojo`,
  `tests/elf/test_map_contract.py`,
  `tests/elf/test_generalized_maps.py`,
  `tests/kernel/test_array_maps.py`,
  `tests/kernel/test_generalized_arrays.py`,
  `tests/kernel/test_mojo_percpu.py`,
  `tests/kernel/test_hash_maps.py`).
- A per-CPU program vocabulary: Mojo-authored per-CPU programs
  whose kind tags select the per-CPU map description at build
  time (the tags emit no code, so array and per-CPU objects share
  their instruction bytes), the per-CPU kind and entry count
  reconciled against the manifest at build time, and
  Mojo-driven per-CPU events observed with exact totals through
  raw syscalls with a `bpftool` JSON cross-check
  (`src/mojobpf/resources/sdk/mojobpf/maps.mojo`,
  `tests/elf/test_generalized_maps.py`,
  `tests/kernel/test_mojo_percpu.py`).
- A two-entry workload vocabulary for the combined packet
  program and its per-CPU twin: per-entry invocation and byte
  accounting with oracle-predicted actions, totals, and map
  values — the array program over the 68-frame corpus, the
  per-CPU twin over a 2-frame drop-plus-pass corpus — the map
  block and BTF pinned structurally and accepted by unmodified
  `bpftool`
  (`examples/packet_counter/`,
  `tests/elf/test_combined_struct.py`,
  `tests/elf/test_generalized_maps.py`,
  `tests/kernel/test_xdp_accounting.py`,
  `tests/kernel/test_mojo_percpu.py`).
- Independent per-CPU decoding: possible-CPU-count handling with
  8-byte value-stride padding, proven against live kernel
  `percpu_array` maps (u64 and padded u32) through raw syscalls with
  a `bpftool` JSON cross-check, exact totals after quiescence, key
  iteration to end-of-map, and kernel refusals for invalid sizes,
  out-of-range keys, and deletion
  (`tests/kernel/test_percpu_maps.py`).
- A bounds-checked packet-access SDK slice: a context handle for the
  packet metadata words, start-based and address-based length guards
  that fail closed to `XDP_DROP`, byte/half/word loads assembled
  alignment-safely, and a cursor with header-sized advance. Six
  shapes (fixed-offset byte, variable-offset with runtime bound,
  2-byte, 4-byte, short-packet guard, cursor) each execute in the
  kernel with oracle-predicted actions on crafted frames; short
  frames take the guard path. Every positive shape's IR carries a
  guard covering each packet load, and the unguarded negative
  fixture compiles but is rejected by the kernel verifier at load
  (`src/mojobpf/resources/sdk/mojobpf/packet.mojo`,
  `tests/compile/packet_*.mojo`,
  `tests/elf/test_packet_struct.py`,
  `tests/kernel/test_packet_sdk.py`).
- A parsing and checksum SDK slice: Ethernet field accessors with an
  optional single 802.1Q tag (network-order loads, tag dispatch over
  fixed offsets by value, two-tier truncation guards) plus
  incremental ones-complement checksum accumulation with carry fold
  and complement over explicitly unrolled bounded windows. Four
  shapes (EtherType dispatch, VLAN match, truncated-header guards,
  checksum window) each execute in the kernel with oracle-predicted
  actions on crafted frames; computed checksums match an independent
  model exactly across distinct digests and truncated frames take the
  guard paths. Every positive shape's IR carries guards covering each
  packet load and the checksum object carries the genuine
  fold-and-complement arithmetic
  (`src/mojobpf/resources/sdk/mojobpf/parse.mojo`,
  `src/mojobpf/resources/sdk/mojobpf/checksum.mojo`,
  `tests/compile/parse_*.mojo`,
  `tests/compile/checksum_*.mojo`,
  `tests/elf/test_parse_struct.py`,
  `tests/kernel/test_parse_checksum_sdk.py`).
- Scalar boundary behavior in the kernel: an endian shape asserting
  boundary words in both byte orders, a guard-edge shape pinning the
  need-equals-length edge down to one-byte frames, and boundary
  frames on the older shapes, all executing with oracle-predicted
  actions; short frames take the guard paths. The unmasked
  last-byte shape compiles and passes the IR audit but is rejected
  by the kernel verifier with its predicted log line
  (`tests/compile/scalar_*.mojo`,
  `tests/kernel/test_packet_sdk.py`).
- A differential scalar proof with ABI layout records: the SDK
  integer, endian, checksum, and guard helpers execute on the host
  over exhaustive and boundary inputs and agree line by line with
  an independent integer model built from distinct primitives; SDK
  value-type sizes, alignments, and offsets agree across
  Mojo-reported, independent-C, and LLVM BPF-target legs; every
  classifier's packet-rooted loads are single bytes with no
  packed-struct cast; and one coherence record ties source
  behavior to layouts and decoder assumptions
  (`tests/differential/test_scalars.py`,
  `tests/reference_c/sdk_layouts.c`,
  `tests/elf/abi_layouts.json`,
  `tests/elf/test_layouts.py`).
- Three Mojo demo programs with in-kernel accounting proofs: an
  SDK-built packet classifier returning the specified action on
  every frame of a 68-frame corpus (33 fixed frames pinned to 16
  drops, 17 passes, and 9,590 bytes, plus 32 seeded frames and 3
  minimized regressions), an invocation counter accumulating
  exactly one per frame from a nonzero userspace initialization
  with per-frame map reads, a combined packet counter returning
  the specified action while accumulating exactly one per frame
  into entry 0 and the frame length into entry 1 from nonzero
  userspace initializations, and an independent C reference
  workload matching the oracle on actions and both map entries;
  the split counter's constant-pass divergence is pinned to occur
  exactly on oracle-drop frames
  (`examples/packet_classifier/`, `examples/xdp_counter/`,
  `examples/packet_counter/`,
  `tests/reference_c/xdp_counter_ref.bpf.c`,
  `tests/kernel/test_xdp_accounting.py`).
- A host differential proof over the packet corpus: a native Mojo
  probe built on the genuine SDK loads agrees action by action,
  count by count, and byte by byte with an independent oracle
  built from distinct primitives, over the fixed, seeded
  (deterministically generated, hash-pinned), and minimized
  frames; the minimizer reproduces the committed regressions
  byte-identically, and the C reference's helpers, actions,
  relocations, and BTF are pinned structurally
  (`tests/differential/packets_probe.mojo`,
  `tests/differential/test_packets.py`).
- Mutation sensitivity with sidecar-less loads: an inverted
  classifier bit test fails the differential suite with exactly
  the predicted mismatch count and passes on revert, and fails
  in-guest with precisely the flipped values; a removed map
  relocation fails the structural relocation check (while map BTF
  still dumps) and fails to load in-guest, and passes on revert;
  the combined bit mutant flips actions exactly and the combined
  byte-sum mutant observes the wrong sum in-guest while the build
  driver refuses to publish it; and each final Mojo object loads,
  runs, and unloads from a directory containing only itself
  through direct unmodified `bpftool`
  (`tests/elf/test_mutations.py`,
  `tests/elf/test_combined_struct.py`,
  `tests/compile/test_build_pipeline.py`,
  `tests/kernel/test_xdp_accounting.py`).

## Toolchain pins

The proofs above were validated on tested combinations; the table
below names the current pins. Behavior proofs not yet
re-qualified on the current combination are not claimed for it:
only the tracepoint-counter and generalized-array guest proofs
are re-qualified on LLVM 22.1.8
(`tests/kernel/test_tracepoint_counter.py`,
`tests/kernel/test_generalized_arrays.py`); every other
guest-behavior proof above was validated on the previous tested
combination (LLVM 21.1.8, bpftool 7.7.0 with libbpf 1.7, QEMU
10.2.1) and awaits re-qualification. Other combinations are
unproven, not supported. Full binary paths and hashes are
recorded in `toolchains.lock.json`; rerun
`tests/probes/toolchain_inventory.py` to re-probe any machine.

| Role | Pinned identity |
| --- | --- |
| Mojo compiler | 1.1.0 (`8189361e`), pixi-pinned from the Modular channel |
| BPF backend | LLVM `llc` 22.1.8, triple `bpfel-unknown-none`, cpu `v3` |
| Loader/observer | bpftool 7.6.0 with libbpf 1.6, unmodified |
| Guest kernel | 6.12.0-061200-generic under virtme-ng 1.41, QEMU 10.2.2, software emulation |
| Host drivers | Python 3.14, pixi-managed Mojo environment, standard library only |
| C reference | Clang 22.1.8 builds the independent C controls and fixtures in `tests/reference_c/` (XDP controls, ring-buffer controls, license witness pair, map references) |

The adapter fails closed on frontend drift outside its validated
shapes: IR that falls outside the known shapes (one entrypoint
definition, plus the one subprogram definition in the subprogram
shape) is rejected loudly until the new shape is reviewed
(`tests/ir/test_adapter_validation.py`). In-shape body mutations
are accepted by design (the behavior proofs rely on them); any
other frontend drift is caught by the six hash pins checked in
`tests/probes/run_feasibility.py`. Broader transforms, including
programmatically constructed map globals and BTF, must move to LLVM
APIs; the exact-match adapter is deliberately limited to the known
shapes.

## Failure layers

Each layer is a distinct, tested outcome:

| Layer | Signal | Demonstrated by |
| --- | --- | --- |
| Source rejection | the Mojo frontend exits nonzero | `tests/compile/test_probe_export.py` (invalid-source fixture rejected, no IR emitted) |
| Compile-time rejection | the adapter exits 1 with no output | `tests/elf/test_map_btf.py` (missing-map fixture), `tests/elf/test_map_contract.py` (flags/key/delete/iteration negatives) |
| Backend failure | `llc` exits nonzero | fails its build suite as a named proof failure (`tests/elf/test_minimal_object.py`, `tests/elf/test_map_btf.py`, `tests/probes/run_feasibility.py`) |
| Loader failure | libbpf/bpftool cannot load the object | `tests/harness/bpf_test_run.py` reports `loader` |
| Verifier rejection | the kernel refuses the program at load | `tests/kernel/test_map_roundtrip.py` (out-of-bounds, unchecked), `tests/kernel/test_packet_sdk.py` (unguarded packet load, last-byte address), `tests/kernel/test_array_maps.py` (out-of-bounds, unchecked) |
| Environment failure | missing tool, denied permission, no guest | every suite exits 2 with `ENVIRONMENT FAILURE`, never a pass |
| Runtime mismatch | test-run returns an unexpected action | `tests/kernel/test_mojo_xdp.py` (stale-object cases) |

Build, check, and inspect steps stay unprivileged. Privileged
load/test-run steps run only inside a disposable guest; nothing in
this repository loads programs on the build host.

## Reproduction

`tests/probes/run_feasibility.py` replays the whole proof from a
clean state: it clones the repository at its current commit into a
new temporary directory, runs a fresh `pixi install` there, executes
all four proof suites inside that directory, rebuilds both canonical
objects, and compares six hashes (raw IR, adapted IR, and object for
each program) against pinned values. Any suite failure or hash
mismatch fails loudly. A full run boots two guests and takes tens of
minutes.

## Explicit non-claims

The following were demonstrated absent or have not been probed; none
of them is implied by the results above:

- Native BPF emission from Mojo: unavailable with the pinned
  compiler. An explicit `--target-triple bpfel-unknown-none` fails at
  target registration (`No available targets are compatible with
  triple`), and the supported-target list contains no BPF entry.
  Re-probe with `mojo build --print-supported-targets` if the
  compiler changes.
- Compiler, backend, and host coverage beyond the observed
  lanes: unproven. One AArch64 guest lane and one second Mojo
  combination (1.0.0, investigational) have their own runs and
  verdicts (see the compatibility documentation); every other
  Mojo/LLVM combination, every `llc` backend version but
  22.1.8, every host architecture but x86-64, and big-endian
  BPF still need theirs. The two x86-64 guest kernels, 6.12.0
  and 6.6.0, are the qualification lanes pinned in
  `ci/kernels.lock.json` and driven by `ci/run_vm_tests.py`,
  with the 6.6 loop-shape verifier boundary pinned per lane
  (see the compatibility documentation). A full-matrix-green
  verdict on the LLVM 22.1.8 toolchain is not claimed here;
  each proof above names the suite that demonstrates it.
- CO-RE beyond the proven slice, and multi-program objects:
  unproven. BTF covers map metadata only, with no function
  records and no `.BTF.ext`, except on the CO-RE probe object
  (core profile only), which carries the accessed kernel-type
  records, one function record for its entry, and a `.BTF.ext`
  holding exactly the two pinned relocation records
  (`tests/core/test_core_object.py`; see the compatibility
  documentation). Multiple entrypoints in one object stay out;
  the one exception is the proven single-subprogram call shape
  (one program with one static callee, not two programs). Tracing
  beyond the exact `syscalls:sys_enter_getpid` counter and
  event programs plus the single pinned-register uprobe program
  is unproven: other events, other filters, context reads
  outside the pinned uprobe word, and per-CPU counting are
  refused or unclaimed
  (`tests/kernel/test_tracepoint_counter.py`,
  `tests/kernel/test_tracepoint_events.py`,
  `tests/kernel/test_uprobe_register.py`).
- Map kinds and shapes beyond the proven matrix:
  map-in-map and `PROG_ARRAY` declarations are refused by the
  build driver, as are hash, LRU, and per-CPU-hash shapes
  outside the qualified form (`u32` keys with `u64` values
  under the hash, LRU, and per-CPU-hash profiles), entry
  counts outside 1 to 4, ring sizes
  outside the two qualified sizes, and key literals outside the
  declared dense coverage.
  Programs mixing map operations (pairs
  with deletions in one program) match no count family and are
  refused, as is any from-program key-iteration spelling: the
  kernel offers no `map_get_next_key`-style helper, and the
  callback-based `for_each_map_elem` helper is outside this
  SDK's scope. Ring-buffer reserve/submit/discard spellings
  outside the qualified reservation shape (one reserve, seven
  record stores, one terminus) are likewise refused
  (`tests/unit/test_manifest.py`,
  `tests/elf/test_generalized_maps.py`,
  `tests/compile/test_build_pipeline.py`,
  `tests/elf/test_map_contract.py`,
  `tests/compile/test_subset_rejection.py`).
- General cross-call liveness beyond the combined, tracepoint,
  event, reservation, and uprobe shapes: the audit still
  rejects any value kept live across a helper call in
  classifier and map programs, and admits cross-call values
  only inside the combined count vector, whose action selector
  and frame length necessarily cross calls, plus the tracepoint
  counter, whose filter value and PID/TID result necessarily
  meet at their comparison, plus the event emitter, whose
  filter, helper results, and sequence necessarily meet after
  their producing calls, plus the reservation emitter for the
  same structural reason, plus the uprobe counter, whose
  filter value and extracted register value necessarily meet
  at their comparison. Static
  subprogram calls are not helper calls: values may cross them
  and the backend spills around the real call (see the subset
  document's subprogram section). Admitting more
  needs re-qualification, not just a wider gate
  (`tests/compile/test_subset_rejection.py`,
  `tests/ir/test_audit.py`).
- Constant-expression store operands: the `MBPF316` pointer-store
  check skips stores it cannot parse instead of refusing them, so
  its guarantee covers only the instruction shapes the qualified
  frontend emits. Hand-written IR with constant-folded store
  operands is outside the qualified boundary; rejecting such
  operands at an earlier check is recorded future hardening
  (`compiler/audit.py`).
- Taint-blind comparison predicates: the `MBPF316` pointer-store
  check treats `icmp`/`fcmp` results as untainted by design (a
  comparison yields a one-bit predicate rather than an address,
  which the null-check pattern relies on), so bit-by-bit
  exfiltration through comparison predicates is outside the
  rule. This is an accepted analysis limitation, not a proven
  absence (`compiler/audit.py`).
- The stack-slot and int-to-pointer cast assembly spellings are
  version-specific workarounds for the Mojo-1.1.0/LLVM-21
  lifetime-marker skew; they must be revisited if a future Mojo
  emits backend-compatible IR for those constructs.
- Content-derived variable packet offsets (loading one packet byte
  to compute a second packet address) are outside the supported
  subset: the verifier cannot connect a separately computed guard
  to the access, and every qualified count vector spends all of
  its address reinterpretations already. Supported variable
  offsets derive from context words such as the packet length
  (`tests/compile/packet_var_offset.mojo`).
- Variable-length checksum windows, stacked VLAN tags, and deeper
  header chains: unproven. The checksum proof covers explicitly
  unrolled fixed windows only, and tag support covers at most one
  802.1Q tag; length-driven or multi-header parses need their own
  proofs.
- The unmasked last-byte packet edge (computing length-minus-one as
  a packet address) is unrepresentable in the current pipeline: the
  backend rewrites the address into packet-end arithmetic, which
  the kernel verifier prohibits. Supported length-derived offsets
  stay masked (`tests/compile/scalar_addr_edge.mojo`).
- Partial combined forms that match no qualified count vector:
  content actions with a single read-modify-write pair, and
  single-pair programs whose merged returns or lengths cross a
  helper call, stay refused with named diagnostics; only the full
  combined vector (content action plus both counters) is admitted.
  The split demos stay as subset documentation for the shapes they
  prove (`tests/compile/counter_content_attempt.mojo`,
  `tests/compile/counter_length_attempt.mojo`,
  `tests/compile/counter_bytesum_attempt.mojo`,
  `examples/packet_classifier/`, `examples/xdp_counter/`).

## Licensing and provenance

First-party material uses `Apache-2.0 WITH LLVM-exception` (see
`LICENSE` and `THIRD_PARTY_NOTICES.md`). The toolchain license, the
dependency licenses, the BPF source grants, and the ELF kernel
license string are distinct: the map helpers used here are not
GPL-restricted, and the license declaration in the object must always
describe the program accurately rather than unlock kernel APIs.
Generated artifacts carry no new license grants; provenance
(source hashes, tool identities, commands) is recorded alongside
every proof run.
