<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Supported language subset

MojoBPF kernel programs are written in a restricted subset of Mojo.
This document lists exactly what is proven to work, what is proven
to be rejected (with the rejecting layer and its evidence for each
case), and the optimization settings the proof covers. Every claim
names the tests that demonstrate it; the case table at the end is
generated from those tests, so the document cannot drift from them.
Anything without such a pointer is unproven, however plausible.

The qualified toolchain is recorded in `toolchains.lock.json`; the
programs below were proven with the pinned Mojo frontend, the
pinned LLVM backend, and the guest kernels the suites boot.

## Rejection layers

A program passes through four gates before it runs in the kernel,
and each negative below names the first gate that refuses it:

* **source**: the Mojo frontend itself rejects the program (a
  compile error; no IR exists). Some shapes are not expressible at
  all, such as runtime-sized stack allocations.
* **preflight**: the IR audit (`compiler/audit.py`) rejects the
  frontend's IR with a stable `MBPF3xx` diagnostic at stage
  `adapter.audit` before any lowering happens.
* **backend**: the BPF backend refuses to emit an object (for
  example, a frame that exceeds the kernel stack budget).
* **kernel**: the kernel verifier rejects the loaded object (for
  example, a write past the end of a map value). Only the
  verifier knows map value sizes, so these cases pass every
  earlier gate by design.

The suites keep one test path per layer and never conflate them:
preflight negatives assert audit codes on the host, while kernel
negatives assert verifier log lines from a disposable guest.

## Proven positives

Each positive is a Mojo program under `tests/compile/subset/` that
validates under the frozen audit and executes in the guest with
oracle-predicted behavior on crafted frames, including short frames
that must take the guard path and fail closed.

* Bounded loops (`loop-sum`, `loop-pressure`). A constant-trip
  `for` loop over packet bytes and a runtime-bounded `while` loop
  carrying 40 64-bit accumulators both verify and run. The heavier
  loop spills to a measured frame that stays within the 512-byte
  budget, proving the boundary is real rather than a blanket ban.
* Small helper inlining (`call-inline`). A plain helper with no
  inline attribute is folded into the caller by the frontend: the
  emitted IR holds a single definition with exactly the one
  address-reinterpretation call, and the program classifies packets
  in the guest.
* Initialized stack arrays (`stack-array`). A four-byte fixed array
  filled from packet bytes promotes to SSA values with no stack
  allocation left in the IR, and the program classifies packets in
  the guest.
* Casts (`casts`). Explicit narrowing (`u32` to `u8`) and widening
  (`u8` to `u64`) reconstruct a packet word that the program
  compares in the guest.
* Checked arithmetic (`checked-arith`). A narrow multiply whose
  wrapped result is detected against a widened multiply, plus a
  headroom check on a `u32` word, both demonstrated on frames that
  trip each check independently and together.

## Precise negatives

Each negative names the first layer that refuses it and the exact
evidence the test asserts.

* Excessive stack (`deep-stack`, backend). Eighty carried 64-bit
  accumulators pass the audit as ordinary SSA values, then the
  backend refuses to emit an object: `llc` exits 1 naming the BPF
  stack limit. The build driver surfaces this as `MBPF106` at
  `build.backend` (`test_backend_failure_surfaced_explicitly`).
* Dynamic stack (`dynamic-stack`, source). A runtime-sized stack
  allocation is not expressible: the frontend rejects the parameter
  list. IR carrying a dynamic allocation would be refused by the
  preflight audit with `MBPF310`, pinned by the existing
  `dynamic_alloca.ll` fixture in the same test.
* Unoptimized stack (`unoptimized-stack`, preflight). The stack
  array fixture compiled with `-O0` keeps its allocations, and the
  audit refuses them with `MBPF310` (`test_no_optimization_rejected_explicitly`).
* Escaping pointers (`escape-value`, preflight; `ptr-store`,
  preflight; `ptr-erase`, source). A packet pointer passed as a
  map update value is refused with `MBPF314`, which requires the
  prepared value slot. A lookup-derived value stored into map
  memory or into the update value buffer — directly or laundered
  through arithmetic or casts — is refused with `MBPF316`, as is
  any pointer-typed value reaching a store; write map values only
  through the reviewed round-trip pattern. This guarantee covers
  the instruction shapes the qualified frontend emits; a store
  whose operands the audit cannot parse (constant-expression
  operands) is skipped by the check rather than refused, so
  hand-written IR outside the qualified shapes is not covered.
  Reinterpreting a pointer as an integer is rejected by the
  frontend's type check.
* Out-of-bounds map store (`oob-store`, kernel). A write past the
  end of the 8-byte map value passes the audit (only the verifier
  knows the value size) and is refused at load. This pins the
  store path; the map round-trip suite pins the load path with its
  own out-of-bounds read.
* Unsupported helpers (`bad-helper`, preflight). A helper invoked
  through `call` inline assembly instead of the reserved call form
  is refused with `MBPF306`. Only the reviewed helpers behind the
  SDK wrappers can be reached.

## Optimization settings

The driver invokes the frontend with fixed release flags (`mojo
build --emit llvm`, the compiler default) and the backend with
fixed flags (`llc -mtriple=bpfel -mcpu=v3 -filetype=obj`). There
is no optimization knob on that route, so no setting can be
silently changed. Proven by `test_release_settings_identical`,
`test_no_optimization_rejected_explicitly`,
`test_debug_info_rejected_explicitly`,
`test_target_override_rejected_explicitly`,
`test_driver_pins_release_invocation`,
`test_backend_flags_load_bearing`, and
`test_backend_failure_surfaced_explicitly`:

* Supported: the default flags, byte-identical to explicit `-O1`,
  `-O2` and `-O3` on the qualified frontend; every output validates
  with its expected mode.
* Rejected by the preflight audit: `-O0` and `--no-optimization`
  (`MBPF310`), and any `-g` debug level (`MBPF302`, debug metadata
  changes the entrypoint header).
* Rejected by the frontend: `--target-triple` overrides (the host
  compiler has no such target info).
* Pinned by the driver: the recorded frontend command carries no
  optimization, debug or target spelling, and the recorded backend
  command spells exactly the pinned triple, CPU and file type with
  no `-O` or `-mllvm` widening. The backend flags are load-bearing
  (an `llc -O0` object differs), so the pin matters.

## Tracing shapes

Two tracing shapes are proven alongside the packet subset above:
a TID-filtered counter and a fixed-record event emitter, both on
the exact `syscalls:sys_enter_getpid` event with no context
payload reads. Their sources, manifests, and measured behavior
live in `examples/tracepoint_counter/README.md` and
`examples/tracepoint_events/README.md`; the compatibility
document's measured tracing limitations bind every claim, and the
unsupported list there names what stays out.

## Subprogram calls

Exactly one BPF-to-BPF call shape is proven, on XDP classifier
programs only: a single static callee with the fixed
one-argument scalar signature `(i64) -> i64`, spelled in Mojo as
one `@export` + `@no_inline` C-ABI function taking and returning
a 64-bit integer, called from the entrypoint (the frontend emits
the `tail call`; either definition order validates). The callee
body is pure scalar computation: no calls of its own (no
recursion, no helper calls, no calls back into the entrypoint),
no loads, and no stores. The backend lowers the static call
itself; the object carries the callee in `.text` plus one
`R_BPF_64_32` relocation per call site, and the kernel verifies
the subprogram (`func#0`/`func#1` with caller/callee frames in
the verifier log).

Everything else refuses at the preflight audit before the
backend runs: a recursive callee (`MBPF312`), an indirect call
in the callee (`MBPF306`), a call back into the entrypoint
(`MBPF312`), a second callee (`MBPF302`), any other arity,
width, or argument type (`MBPF302` at the definition, `MBPF314`
at the call site), a missing `tail` marker (`MBPF306`), a call
to an undefined name (`MBPF303`), a defined-but-uncalled callee
(`MBPF307`), a callee under `trace_entry` (`MBPF302`), and map
or helper calls alongside the callee (`MBPF307`, or `MBPF313`
where the second attribute set renumbers the helper
declarations). Under any profile without the subprogram
capability the object is refused at the pre-publication
inspection gate (`MBPF406` for `.text`, `MBPF407` for the static
call), so a call program can never reach the kernel through a
profile that does not admit the shape.

Proven by the IR audit suite (both definition orders, SSA
scoping, and the refusal matrix), the corpus refusal suite (the
`subprog_*.ll` fixtures in
`tests/compile/test_subset_rejection.py::test_fixture_rejections`
plus genuine compiled attempts), the driver pipeline suite
(both orders end to end, base-profile refusal), the subprogram
ELF structure suite (object pins plus the inspection gate), and
the subprogram kernel suite (input-dependent boards through the
call on both x86 lanes, the call-free mutant board, the
verifier-log subprogram markers, FD lifecycle, and residue).
The public example with its rule, fixtures, and mutant lives in
`examples/subprog_call/README.md`.

## Controlled uprobes

One uprobe program per build may attach at load time to one
symbol of a suite-owned test executable, exporting
`uprobe_entry` under the `("uprobe", "uprobe")` pair of the
uprobe capability profile. The program reads exactly the pinned
x86-64 first-argument register (`pt_regs` word 14, `rdi` at byte
112) through the entry context, compares it against the expected
value in entry 0 of a two-entry array map, and counts matches in
entry 1 with the existing lookup/update helpers and no
helper-ID call. The audit admits exactly the uprobe count
vector plus the single pinned address computation and its one
`i64` load; another word, another width, a second read, a
missing read, a context write, or a uprobe body under another
entry symbol is refused, as are multi-probe graphs and mixed
uprobe/XDP builds at manifest validation. Register extraction
is architecture-specific and explicit: x86-64 is proven,
AArch64 extraction is not claimed, and a tracepoint is never
presented as a portable uprobe. The object carries no attach
target and verifies only under the uprobe profile; system-binary
targets are refused by the loader before tracefs is touched.
The slice is proven by the uprobe corpus fixtures (exact codes),
the genuine register-attempt refusals, the uprobe structure
suite (calls, pinned first load, immediates, BTF, profile
gating), the uprobe kernel suite (input-dependent boards with
oracle agreement, mismatch and never-called negatives,
unavailability and bad-offset reports, verifier rejection of
the out-of-bounds context mutant, residue), and the uprobe
external-consumer proof (third-party build plus exact kernel
result through the installed package); see
`examples/uprobe_counter/README.md`.

## Socket and TC classifiers

The net capability profile admits the base pairs plus
`("socket", "socket")` and `("tc", "classifier")`, exporting
`socket_entry` for socket-filter programs and `tc_entry` for TC
classifier programs. Both entries export the mapless classifier
shape (one packet reinterpretation, plain loads, no helpers or
maps, reading the `__sk_buff` data/data_end words through the
entry context) and the mapless skb shape (one `skb_load_bytes`
or `skb_store_bytes` helper call plus its key slot). Any other
body under a socket or TC entry (map, combined, delete, core,
subprogram, tracepoint, or uprobe) is refused by the
entry/family rule; the subprogram shape stays pinned to XDP.
Each object is a mapless relocatable with exactly one
executable section (`socket` / `classifier`), one global entry
function, the exact license bytes, no code relocations, and no
map or BTF sections, and verifies only under the net profile;
the TC classifier carries no calls while the socket classifier
and the TC store fixture each carry their one helper call. The
slice is proven by the audit corpus fixtures (exact codes), the
net structure suite (sections, entry symbols, license, layout,
calls, profile gating), and the socket/tc example CLI builds;
see `examples/socket_classifier/README.md` and
`examples/tc_classifier/README.md`. The TC rule is proven
in-guest by the kernel-net suite (exact verdicts over the frame
corpus, inverted mutant flipped, stale object fails); the
socket example reads through the `skb_load_bytes` helper
because the socket-filter verifier rejects direct context
reads, and its in-guest execution proof arrives with the
kernel-net skb legs.

## Not claimed

The following are explicitly outside the proven subset: programs
whose frames exceed the kernel stack budget, runtime-sized stack,
unoptimized or debug builds, foreign target triples, helpers
outside the reviewed SDK wrappers, map types beyond the proven
matrix (arrays and per-CPU arrays with u32 keys, u64 values, and
1 to 4 entries, hash maps with u32 keys and u64 values in 1 to
4 entries under the hash profile, LRU hash maps with u32 keys
and u64 values in 1 to 4 entries under the LRU profile, plus
ring buffers in the two qualified sizes),
programs mixing map operations, from-program key iteration (the
kernel offers no `map_get_next_key`-style helper and
`for_each_map_elem` is outside the subset's scope; refused at
the audit), malformed
ring-buffer reservations (a second reserve, a second terminus, a
mixed terminus, or any use after the terminus; refused at the
audit), BPF-to-BPF calls outside the single proven shape (more
than one callee, any other arity or type, recursion, indirect
calls, calls inside the callee, or calls outside XDP
classifiers; refused at the audit), context reads outside the
single pinned uprobe word, multi-probe graphs, mixed uprobe/XDP
builds, AArch64 register extraction, system-binary uprobe
targets (see `examples/uprobe_counter/README.md`),
content-derived packet offsets, CO-RE behavior beyond the
proven slice (one relocated field read plus one existence
check; see `docs/compatibility.md`), and
any tracing behavior beyond the exact `syscalls:sys_enter_getpid`
TID-filtered counter, fixed-record event emitter, explicit
reservation emitter, and single pinned-register uprobe counter
(see `examples/tracepoint_counter/README.md`,
`examples/tracepoint_events/README.md`,
`examples/ringbuf_reserve/README.md`, and
`examples/uprobe_counter/README.md`). Some of these are
refused with the named diagnostics above; the rest are simply
unproven, and the suites assert refusals rather than guessing.

## Case table

The table below is generated from the linked tests by
`tests/verifier/test_subset_doc.py`. Do not edit it by hand:
refresh it with `python3 tests/verifier/test_subset_doc.py
--refresh` after any intentional change, and commit the document
together with the change.

<!-- SUBSET-TABLE-BEGIN -->
| case | result | layer | evidence | fixture | tests |
| --- | --- | --- | --- | --- | --- |
| loop-sum | accept | kernel | v6.12: test-run actions match the oracle; v6.6 verifier rejects the back edge (pinned log line) | subset_loop_sum.mojo (aee324cb) | tests/compile/subset/test_subset_audit.py::test_positive_programs_validate (136e3d41)<br>tests/verifier/test_subset_kernel.py::test_loop_sum (34af05e8) |
| call-inline | accept | kernel | plain helper inlined; test-run actions match | subset_call_inline.mojo (243fb782) | tests/compile/subset/test_subset_audit.py::test_positive_shapes (136e3d41)<br>tests/verifier/test_subset_kernel.py::test_call_inline (34af05e8) |
| stack-array | accept | kernel | initialized array promotes (no alloca); actions match | subset_stack_array.mojo (0af7cfb9) | tests/compile/subset/test_subset_audit.py::test_positive_shapes (136e3d41)<br>tests/verifier/test_subset_kernel.py::test_stack_array (34af05e8) |
| casts | accept | kernel | narrow/widen round trip; test-run actions match | subset_casts.mojo (5016d187) | tests/compile/subset/test_subset_audit.py::test_positive_programs_validate (136e3d41)<br>tests/verifier/test_subset_kernel.py::test_casts (34af05e8) |
| checked-arith | accept | kernel | wrap and headroom checks; test-run actions match | subset_checked_arith.mojo (7988c341) | tests/compile/subset/test_subset_audit.py::test_positive_programs_validate (136e3d41)<br>tests/verifier/test_subset_kernel.py::test_checked_arith (34af05e8) |
| loop-pressure | accept | kernel | frame spills within the 512-byte budget; total exact | subset_loop_pressure.mojo (da66630c) | tests/compile/subset/test_subset_audit.py::test_loop_pressure_frame_within_budget (136e3d41)<br>tests/verifier/test_subset_kernel.py::test_loop_pressure (34af05e8) |
| deep-stack | reject | backend | llc exits 1: BPF stack limit is exceeded, no object | subset_deep_stack.mojo (e59da606) | tests/compile/subset/test_subset_audit.py::test_deep_stack_refused_by_backend (136e3d41)<br>tests/ir/test_optimization_invariants.py::test_backend_failure_surfaced_explicitly (0a826266) |
| dynamic-stack | reject | source | frontend: cannot use a dynamic value in a parameter list | (inline source in test) | tests/compile/subset/test_subset_audit.py::test_dynamic_stack_rejected_at_source (136e3d41) |
| unoptimized-stack | reject | preflight | MBPF310: unoptimized IR keeps stack allocations | (subset_stack_array.mojo compiled with -O0; bytes pinned by the stack-array row) | tests/ir/test_optimization_invariants.py::test_no_optimization_rejected_explicitly (0a826266) |
| escape-value | reject | preflight | MBPF314: value must come from the prepared value slot | subset_escape_value.mojo (f50a0816) | tests/compile/subset/test_subset_audit.py::test_preflight_negatives_rejected (136e3d41) |
| ptr-store | reject | preflight | MBPF316: no lookup-derived or pointer-typed stored value | (synthetic IR: ptr_store_map_mem.ll and ptr_store_update_buf.ll in tests/compile/unsupported/) | tests/compile/test_subset_rejection.py::test_fixture_rejections (219e5e82) |
| bad-helper | reject | preflight | MBPF306: helper calls never use inline assembly | subset_bad_helper.mojo (02d336fb) | tests/compile/subset/test_subset_audit.py::test_preflight_negatives_rejected (136e3d41) |
| ptr-erase | reject | source | frontend: rebind input type '!kgen.pointer<none>' does not match result type '!kgen.scalar<si64>' | (inline source in test) | tests/compile/subset/test_subset_audit.py::test_ptr_erase_rejected_at_source (136e3d41) |
| oob-store | reject | kernel | verifier: invalid access to map value, value_size=8 off=8 size=8 | subset_oob_store.mojo (6c86f3da) | tests/verifier/test_subset_kernel.py::test_oob_store_rejected_by_verifier (34af05e8) |
<!-- SUBSET-TABLE-END -->
