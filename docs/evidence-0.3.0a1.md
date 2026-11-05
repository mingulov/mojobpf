<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 0.3.0a1 evidence summary

The alpha regression anchor: every suite below ran green on
the release tree, except the four compiler-lane reds that
reproduce identically on the pristine pre-alpha base and are
recorded as known-red with their reproduction. The two-lane
matrix ran on commit
`15be770c4398b7759dd1df71c0c401257a79b19a` with a clean tree
(the runner refuses dirty trees and re-checks the commit
mid-run); this document, `checksums-0.3.0a1.md`,
`release-notes-0.3.0a1.md`, `pair-matrix-0.3.0a1.md`,
`api-coverage-submission-0.3.0a1.md`, and the quickstart
transcription landed afterwards in the release commit as
docs-only additions: no suite executes them and no product
code reads them (the only direct doc reads target `sdk.md`
and `supported-subset.md`, untouched by that delta). The
source-archive tests enumerate `docs/` by design — the
member inventory pins the five new files and the
markdown-link check resolves their links — and the review
fixes below touched product and test code with their own
re-proofs, amending this board.

Release commit: the commit carrying this document (the
docs-only amendment of the matrix commit described above).
Matrix commit: `15be770c4398b7759dd1df71c0c401257a79b19a`.

## Anchor board

| Suite | Command | Result |
|---|---|---|
| Unit | `python3 -m pytest tests/unit -q` | exit 0 — 24 modules, 1506/1506 nodes |
| Compiler | per-module `python3 -m pytest <file> -q` (57 modules) | exit 2 — 53 green, 4 known-red (pre-existing, see below) |
| VM matrix, 6.12 lane | `python3 ci/run_vm_tests.py --lock ci/kernels.lock.json --lane v6.12-tcg --out-dir matrix-out --consumer-path <independent-toolchain>` (plus the lease/lib env below) | 28/28 lane-suites pass, 530 `PASS` lines |
| VM matrix, 6.6 lane | (same run, `--lane v6.6-tcg`) | 28/28 lane-suites pass, 530 `PASS` lines |
| Joint-only, 7.x lane | (same runner, `--lane v7.0.14-tcg`, kernel-joint suite only) | 8/8 pass |

Matrix total: 56/56 lane-suites pass, 1060 `PASS`
lines, 0 failures, 0 environment failures. Per-suite passes
per lane (identical on both lanes): kernel-xdp 5, kernel-map
6, kernel-packet 13, kernel-parse 8, kernel-array 9,
kernel-percpu 17, kernel-accounting 20, kernel-generalized
17, kernel-mojopercpu 19, kernel-tracepoint 13, kernel-events
13, kernel-tracing-lifecycle 27, verifier-subset 16,
verifier-licenses 19, packaging-consumer 37,
packaging-hash-consumer 37, packaging-reserve-consumer 34,
packaging-subprog-consumer 37, packaging-uprobe-consumer 34,
kernel-core-layouts 18, kernel-hash 16, kernel-ringbuf 13,
kernel-subprog 11, kernel-uprobe 26, kernel-cleanup 28,
kernel-joint 8, kernel-net 12, kernel-lru 17.

## The four compiler-lane reds (known-red, pre-existing)

Each red below reproduces identically on the pristine
pre-alpha base (the joint-proof tip, before any alpha
branch commit) in a clean worktree under lane-exact flags,
so none is an alpha regression and no alpha commit can green
them. Fixing them is out of alpha scope.

1. `compiler/tests/test_parsed_lowering.py`: 122 passed, 4
   errors from 126 nodes under lane flags. The 4 nodes need
   the `subtests` fixture from the pytest-subtests plugin;
   the lane runs with plugin autoload disabled, so they
   error. Standalone (autoload on): 126/126 pass. Harness
   interaction, predates the alpha branch.
2. `compiler/tests/test_target_model.py::test_scalar_native_controls_match_independent_c_and_oracle`:
   fails on the matrix commit and on the base.
3. `tests/unit/test_guest_proc.py`: 3 failures
   (`test_migrated_suite_preserves_failed_attempt_without_rerun`,
   `test_tracepoint_main_finalizes_cached_assertion_failure`,
   `test_tracepoint_main_finalizes_cached_lease_refusal`) on
   the matrix commit and on the base.
4. `tests/unit/test_verify.py::test_kernels_lock_schema`:
   fails on the matrix commit and on the base.

## Toolchain the anchor ran

* Host Python: 3.14.8 (`/usr/bin/python3`), pytest 8.4.2,
  standard library only plus the test runner.
* Mojo 1.1.0 (`8189361e`): the checkout-pinned environment
  for host and kernel lanes, and an independently installed
  toolchain outside the checkout (PATH-only, no
  checkout-derived paths) for every consumer suite.
* LLVM `llc` 22.1.8 (host `/usr/bin/llc`). Every object in
  every lane was built on the host; guests only load, run,
  and observe.
* `bpftool` v7.6.0 with libbpf 1.6, unmodified, staged into
  each guest (owner-endorsed pins).
* Guest runner: virtme-ng 1.41, QEMU 10.2.2, software
  emulation (TCG) on every lane.
* Guest lanes (pinned by hash in `ci/kernels.lock.json`):
  6.12.0-061200-generic and 6.6.0-060600-generic (Ubuntu
  mainline builds) for the full matrix;
  7.0.14-070014-generic for the joint-only lane.
* Joint library: libbpf-mojo
  `cc4b03d8eec3a16a336f261801deeaf6b4fdbc2f` (15 commits
  past tag `v0.2.2`), read-only; see
  [pair-matrix-0.3.0a1.md](pair-matrix-0.3.0a1.md).

Guest suites additionally require
`MOJOBPF_TARGET_LEASE=1`, the consumer suites require
`MOJOBPF_CONSUMER_GUEST_LEASE=1` with `--consumer-path`
pointing at the independent toolchain, and the joint suite
requires `MOJOBPF_LIBBPF_MOJO_SRC` (checkout) and
`MOJOBPF_LIBBPF_MOJO_LIB` (built `libbpf_mojo.so`); every
variable is required explicitly, never defaulted, and a
missing lease or variable fails loudly as an environment
failure, never a skip.

## Key release proofs (all observed in the anchor)

* Breadth 1, networking: socket-filter verdicts from live
  `AF_PACKET` attach (127 pass / 5 drop / 5 drop on three
  fixtures, mutants flip exactly), TC classifier verdicts
  through test-run, TC packet-store bytes observed out, and
  map readback through skb-load plus update — 12/12 in both
  lanes on the same bits.
* Breadth 2, LRU: one-entry lifecycle shapes, exact counts
  after quiescence, miss/delete/iteration semantics, and a
  pigeonhole eviction leg proving the kernel evicts rather
  than refusing inserts (last key present, bounded occupancy,
  early miss; no victim identity asserted) — 17/17 in
  both lanes on the same bits (the iteration leg pins its
  map operations to one CPU to control 6.6 per-CPU
  free-list stranding, a kernel-allocator placement
  variance a C control shows identically).
* Breadth 3, skb helpers: helpers 9 and 26 audited to
  genuine emission spellings with initialized keyslots,
  proven through the breadth-1 legs above.
* Joint stack: userspace initializes map key 0 to 41
  through libbpf-mojo (`Object` open/load,
  `lookup_u64`/`update_u64`, `test_run`), the kernel
  observes and increments to 42, and mutants/stale legs
  fail exactly — 8/8 in all three lanes (6.12, 6.6, 7.x).
* External consumers: five independent consumers (base,
  hash, reserve, subprog, uprobe) build their own sources
  through the installed tool only and observe exact kernel
  results in both lanes (37/37/34/37/34).
* Registry revision 2: 47 records proven by this anchor
  flip to IMPLEMENTED/tested through the curated flip
  table; `validate --sources --flips` passes byte-identical
  against freshly downloaded pinned upstream sources, and
  the rev1→rev2 diff touches exactly those 47 records plus
  the revision metadata.
* Cleanup and reproducibility: 28 cleanup `PASS` lines from
  13 test methods in both lanes (repeat load/unload leaves
  guest listings byte-identical; two-path builds produce
  identical objects); the wheel rebuilds contents-identical
  (`diff -r` clean; see
  [checksums](checksums-0.3.0a1.md)).
* Quickstart: the documented fresh-environment run built
  the counter (object `b2679151…`, byte-identical to the
  0.2.0 quickstart object), inspected clean, and passed
  `verify --kernel` (guest load plus unload, no attach).

## Rerunning

From a clean checkout of the tree carrying this document
with the toolchain above on `PATH`:

```bash
python3 -m pytest tests/unit -q
python3 ci/test_lanes.py --lane compiler
# or per module, serially: python3 -m pytest <file> -q -p no:cacheprovider
# for each of the 57 files owned by the compiler lane (see OWNERS in
# ci/test_lanes.py); the lane runner does exactly this.
MOJOBPF_TARGET_LEASE=1 \
MOJOBPF_CONSUMER_GUEST_LEASE=1 \
MOJOBPF_LIBBPF_MOJO_SRC=<checkout> \
MOJOBPF_LIBBPF_MOJO_LIB=<libbpf_mojo.so> \
python3 ci/run_vm_tests.py --lock ci/kernels.lock.json \
    --lane v6.12-tcg --out-dir matrix-out \
    --consumer-path <independent-toolchain>
```

Repeat the matrix invocation with `--lane v6.6-tcg`, and
once more with `--lane v7.0.14-tcg` for the joint-only
lane. Guest-backed suites take tens of minutes under
software emulation. A missing tool, lease, guest image, or
lane fails its run loudly; nothing passes by skipping.
