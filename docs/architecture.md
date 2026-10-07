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
retargets module metadata only: the target triple, the data layout, the
`xdp` section attribution, the entrypoint codegen attributes, and appended
license/map/BTF metadata blocks. Every body instruction in the adapted IR
is byte-identical to the frontend output; the raw file is preserved next
to the adapted file so reviewers can diff them. There is no
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

- A single entrypoint, `i32 @xdp_entry(ptr)`, taking the kernel context
  pointer with no hidden parameters and no ordinary runtime calls: the
  probe exports contain no call or invoke instructions and the module
  declares no external functions; the kernel programs' only calls are
  the reviewed shapes below
  (`tests/compile/test_probe_export.py`,
  `tests/ir/test_probe_abi.py`).
- Integer-only program bodies using fixed-width scalars and pointers;
  no globals, no intrinsics, no unwinding, no floating-point or
  unsupported vector types, no address spaces, and no external
  declarations besides the two reserved helper declarations
  (`tests/ir/test_adapter_validation.py`,
  `tests/ir/test_audit.py`).
- Calls restricted to six reviewed exact shapes: one tied
  register-reinterpretation cast, the map address load, the key
  and value scratch-slot preparations (all inline assembly), and the
  lookup/update helper invocations as ordinary direct calls to
  reserved declarations, lowered by the adapter to the standard
  helper-call encoding so argument registers, the result register,
  and the caller-saved clobbers come from backend call lowering.
  Exactly two shape-count combinations validate: the packet
  classifier and the map round trip; anything else is rejected with
  a named diagnostic (`tests/ir/test_adapter_validation.py`,
  `tests/compile/test_subset_rejection.py`).
- A packet classifier with an explicit bounds check: frames of at
  least 15 bytes with bit 0 of byte 14 set return `XDP_DROP` (1),
  everything else returns `XDP_PASS` (2). Both actions were observed
  in the kernel via test-run, a one-line source mutation swapped the
  observed behavior, and the stale object failed the new expectation
  (`tests/kernel/test_mojo_xdp.py`,
  `examples/xdp_pass/README.md`).
- One helper-based map round trip: a one-entry `ARRAY` map with u32
  key and u64 value, initialized to 41 from userspace, checked lookup
  (null-tested before dereference) plus update through helpers 1 and
  2, with the final value 42 read back independently. The plus-two
  mutation observes 43; the stale object still observes 42 and fails
  the new expectation (`tests/kernel/test_map_roundtrip.py`).
- Standard object layout: `EM_BPF` relocatable, exactly one
  executable section holding exactly one function, exact license
  bytes, map relocations against `.maps`, and map BTF parsed
  independently and cross-checked against `bpftool btf dump`
  (`tests/elf/test_minimal_object.py`, `tests/elf/test_map_btf.py`).
- Layered rejection: a missing map reference is rejected by the
  adapter at compile time; an out-of-bounds value access and an
  unchecked null dereference both compile and are then rejected by
  the kernel verifier with its own logged reason
  (`tests/elf/test_map_btf.py`, `tests/kernel/test_map_roundtrip.py`).
- An array map SDK slice: the one-entry `ARRAY` vocabulary with named
  update flags (`BPF_ANY` lowers; `BPF_NOEXIST`/`BPF_EXIST` are
  refused with a named diagnostic), documented mutation semantics,
  and kernel proofs for lifecycle (41 to 42), exact counts and byte
  sums over repeated runs, first/last/invalid keys, invalid sizes,
  and refused deletion, with layout/BTF mismatch rejected by the
  loader rather than misdecoded
  (`src/mojobpf/resources/sdk/mojobpf/maps.mojo`,
  `tests/compile/maps_*.mojo`,
  `tests/elf/test_map_contract.py`,
  `tests/kernel/test_array_maps.py`).
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

## Toolchain pins

The proofs above were validated with exactly this combination; other
combinations are unproven, not supported. Full binary paths and hashes
are recorded in `toolchains.lock.json`; rerun
`tests/probes/toolchain_inventory.py` to re-probe any machine.

| Role | Pinned identity |
| --- | --- |
| Mojo compiler | 1.1.0 (`8189361e`), pixi-pinned from the Modular channel |
| BPF backend | LLVM `llc` 21.1.8, triple `bpfel-unknown-none`, cpu `v3` |
| Loader/observer | bpftool 7.7.0 with libbpf 1.7, unmodified |
| Guest kernel | 6.12.0-061200-generic under virtme-ng 1.41, QEMU 10.2.1, software emulation |
| Host drivers | Python 3.14, pixi-managed Mojo environment, standard library only |
| C reference | Clang 21.1.8 builds the independent `XDP_PASS` control only |

The adapter fails closed on frontend drift outside its validated
shapes: IR that falls outside the two known single-entrypoint shapes
is rejected loudly until the new shape is reviewed
(`tests/ir/test_adapter_validation.py`). In-shape body mutations are
accepted by design (the behavior proofs rely on them); any other
frontend drift is caught by the six hash pins checked in
`tests/probes/run_feasibility.py`. Broader transforms, including
programmatically constructed map globals and BTF, must move to LLVM
APIs; the exact-match adapter is limited to the two known
single-entrypoint shapes.

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
- Any second compiler, backend, guest kernel, or host architecture
  version: unproven. AArch64, other LLVM releases, and other Mojo
  releases need their own runs.
- CO-RE, tracing programs, and multi-program objects: unproven.
  BTF covers map metadata only; no function records and no
  `.BTF.ext` are emitted.
- Map kinds and shapes beyond the one-entry array: hash, LRU,
  map-in-map, and `PROG_ARRAY` declarations are refused by the build
  driver; multi-entry arrays and Mojo-authored per-CPU programs are
  unrepresentable in the current pipeline; delete and key-iteration
  helpers are unqualified. The per-CPU proofs cover decoding and
  kernel semantics only, not Mojo-authored per-CPU programs
  (`tests/unit/test_manifest.py`, `tests/elf/test_map_contract.py`,
  `tests/kernel/test_percpu_maps.py`).
- General cross-call liveness beyond the audited subset: the audit
  conservatively rejects any value kept live across a helper call,
  including cases ordinary call lowering would handle correctly.
  Admitting those needs re-qualification, not just a wider gate.
- The stack-slot and int-to-pointer cast assembly spellings are
  version-specific workarounds for the Mojo-1.1.0/LLVM-21
  lifetime-marker skew; they must be revisited if a future Mojo
  emits backend-compatible IR for those constructs.
- Content-derived variable packet offsets (loading one packet byte
  to compute a second packet address) are outside the supported
  subset: with one address reinterpretation per program, the
  verifier cannot connect a separately computed guard to the
  access. Supported variable offsets derive from context words
  such as the packet length (`tests/compile/packet_var_offset.mojo`).
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
