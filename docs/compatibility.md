<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF compatibility (0.1.0)

What this release is proven with, what it is proven to refuse,
and what it does not claim. Supported here means observed in
the release test runs, not merely untested; every row cites its
proof.

## Supported profiles

One target profile exists: `linux-bpfel-v3` (little-endian BPF,
CPU v3, XDP programs plus the `syscalls:sys_enter_getpid`
tracepoint counter and event programs). The profile record
carries `core_supported = false`
(`tests/unit/test_manifest.py::test_core_request_outside_profile_fails`)
and pins the exact map types, sizes, and helper IDs
(`tests/unit/test_manifest.py::test_profile_registry_holds_exactly_one_supported_profile`).

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
combinations are unproven, not supported. AArch64 and other
host architectures need their own runs.

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

## Proven refusals

* Entry counts outside 1–4, map kinds outside `ARRAY` /
  `PERCPU_ARRAY` / `RINGBUF`, ring sizes outside 4096/131072,
  key/value vocabulary on ring buffers, and key widths outside
  the declared dense coverage fail manifest validation with
  `MBPF205`
  (`tests/unit/test_manifest.py::test_ringbuf_unqualified_size_refused`,
  `tests/unit/test_manifest.py::test_ringbuf_key_vocabulary_refused`,
  `tests/unit/test_manifest.py::test_hash_map_type_refused`).
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
  counter, plus 5, 8, and 130 for the event program), and
  ring-buffer reserve/submit/discard spellings are refused
  with named diagnostics
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

* CO-RE: no function records and no `.BTF.ext` are emitted;
  BTF covers map metadata only. A manifest requesting CO-RE
  fails.
* Tracing and other program types beyond the proven counter
  and event programs: only the exact
  `tracepoint/syscalls/sys_enter_getpid` shapes validate.
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
