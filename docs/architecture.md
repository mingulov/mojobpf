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
| Compile-time rejection | the adapter exits 1 with no output | `tests/elf/test_map_btf.py` (missing-map fixture) |
| Backend failure | `llc` exits nonzero | fails its build suite as a named proof failure (`tests/elf/test_minimal_object.py`, `tests/elf/test_map_btf.py`, `tests/probes/run_feasibility.py`) |
| Loader failure | libbpf/bpftool cannot load the object | `tests/harness/bpf_test_run.py` reports `loader` |
| Verifier rejection | the kernel refuses the program at load | `tests/kernel/test_map_roundtrip.py` (out-of-bounds, unchecked) |
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
- CO-RE, tracing programs, hash maps, larger maps, and multi-program
  objects: unproven. BTF covers map metadata only; no function
  records and no `.BTF.ext` are emitted.
- General cross-call liveness beyond the audited subset: the audit
  conservatively rejects any value kept live across a helper call,
  including cases ordinary call lowering would handle correctly.
  Admitting those needs re-qualification, not just a wider gate.
- The stack-slot and int-to-pointer cast assembly spellings are
  version-specific workarounds for the Mojo-1.1.0/LLVM-21
  lifetime-marker skew; they must be revisited if a future Mojo
  emits backend-compatible IR for those constructs.

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
