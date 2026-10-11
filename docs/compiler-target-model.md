<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Candidate compiler target model

The internal C++ reader can check genuine Mojo 1.1.0 output against
`mojo-1.1.0-x86_64-bpfel-v3-minimal-v1`. This is source admission on an
x86-64 build host for a little-endian BPF v3 candidate. It does not emit a
qualified BPF object, replace the installed build driver, or establish
kernel/verifier/runtime compatibility.

Build with CMake 3.20+, C++17 and the exact LLVM 21.1.8 development package.
Python 3.11+ and pytest are required for tests; genuine captures and native
controls also need the admitted Mojo 1.1.0 compiler environment and Clang
21.1.8. The frozen executable, stdlib and dynamic closure identities are
listed in [the test case ledger](../compiler/tests/target_model_cases.json).
The capture harness checks those identities before invoking the producer.
Its configuration hash is part of this candidate's admitted environment;
a different installation/configuration needs a new reviewed identity
binding. No installation is changed by these tests.

```sh
cmake -S compiler -B build/compiler -DLLVM_DIR=/usr/lib/llvm-21/lib/cmake/llvm
cmake --build build/compiler --parallel 2
build/compiler/mojobpf-lower --mode check-target --input program.ll \
  --spec program-spec.json --report build/check.json
ctest --test-dir build/compiler --output-on-failure
```

Raw IR cannot authenticate its producer. The C++ report contains typed
semantic facts and explicitly says `producer_authenticated=false`.
Capture evidence binds the producer, input source/imports, invocation and
IR bytes separately. Native execution proves scalar/layout observations
on the build host. Independent LLVM verification proves reader/IR
validity. Kernel admission and behavior are still required boundaries.

## Strict request and output contract

The specification must contain exactly these fields. The entry name is
supplied by the caller, rather than recognized as an algorithm identity.

```json
{"schema_version":1,"model_id":"mojo-1.1.0-x86_64-bpfel-v3-minimal-v1","profile_id":"linux-bpfel-v3","entry":"xdp_entry","program_type":"xdp","section":"xdp","kernel_license":"Apache-2.0 WITH LLVM-exception","map":null}
```

For the one-entry array, `map` is exactly
`{"symbol":"mojobpf_map0","type":2,"key_bits":32,"value_bits":64,"max_entries":1,"flags":0}`.
Other fields, versions, types, map contracts, program types, target models
and license declarations are rejected. This candidate does not broaden
the capabilities associated with the existing profile identifier.

Default invocation retains parse/verify/write round trip:
`mojobpf-lower --input INPUT --output OUTPUT [--emit llvm|bitcode]`.
`check-target` requires a specification and report, rejects `--output`,
and neither rewrites nor emits IR. `lower` recognizes the eventual
interface but fails explicitly because lowering is not implemented.

Exit 0 means the requested internal operation completed. Exit 2 means
an unusable invocation or specification; exit 4 means a parse, LLVM
verification, target, audit or write failure. Reports use schema 1,
bind the captured input and specification digests, enumerate measured target facts and named
proof obligations, and contain transformations and six-field diagnostics.
They always report `runtime_qualified=false`. Callers require both a
consistent exit/status and a valid report; absent/malformed reports and
contradictory status cannot confer acceptance.

Inputs are captured before output opening. Output/report paths cannot
alias input/specification paths or each other, including symlinks and hard
links. Specification/usage failures preserve existing sentinels. A typed
analysis failure may write a failure report; it never writes success.
Owned report/output staging removes partial files on a write failure.
Round-trip output retains its documented non-atomic replacement behavior.
These internal paths must belong to the caller's staging directory.

LLVM can verify a version-3 module during debug-info upgrade, before the
reader returns. That verifier failure terminates with an `MBPF106` failure
report and exit 4; no partially parsed module is reused. Other LLVM reader
internal failures have a distinct `MBPF319` explanation. Target checks
also reject reader diagnostics that discard invalid debug metadata, so
stripping an unsupported graph cannot confer admission. Default round trip
retains LLVM's existing debug-upgrade behavior.

The C++ source factory verifies the module, revalidates the strict request,
remeasures target facts and compares the complete caller-supplied fact
record before constructing a `ValidatedProgram`. Its recognized bindings
have const accessors. Before reusing a source proof,
`requireUnchangedSource()` repeats verification and source admission and
checks an LLVM-bitcode snapshot digest. Changed source, unsupported
attributes, invalid IR or exhausted analysis budgets cannot reuse old
bindings. The caller owns the module and must keep it alive throughout
that use; this contract does not protect a destroyed module or arbitrary
C++ memory misuse.

## Measured obligations

Every row has positive and negative executable controls in
[test_target_model.py](../compiler/tests/test_target_model.py) and
[test_parsed_audit.py](../compiler/tests/test_parsed_audit.py). The case
ledger records independent expected results. A listed obligation is a
requirement; documentation alone is not proof that an execution passed.

| Obligation | Admitted host check | Rejection boundary |
| --- | --- | --- |
| `producer_reader` | Producer executable/closure checked before capture; `.ll` and native `.bc` independently parsed/verified and compared by measured properties | Wrong identity, unsupported reader syntax/attributes, malformed bitcode, invalid CFG |
| `integer_semantics` | Native Mojo/C controls establish `Int`/`UInt` = 64 and signed/unsigned 8/16/32/64-bit widths, high bits, limits, narrowing/extension and wrapping u64 addition | Floating point, i128 arithmetic, poison/undef, unchecked divide/remainder or shifts, unproved integer flags, surviving runtime vectors |
| `endian_pointer_index` | BPF `TargetMachine` supplies its layout; compare used types' store/allocation sizes and ABI/preferred alignments; AS0 pointer/index/alignment = 64/64/64 bits | Big endian, narrow pointers/indices, non-integral/used other address spaces, address-space casts |
| `gep_alignment` | Compute constant offsets with both `DataLayout`s; prove declared alignment from the pointer root and accumulated offset; context offsets 0/4, packet byte 14, u32/u64 and byte accesses | Dynamic/different offsets, alignment exceeding the root/offset guarantee, volatile/atomic accesses |
| `struct_entry_abi` | Native prefix bytes and C layout agree with both LLVM layouts: size 8, ABI alignment 4, offsets 0/4; entry is exported C `i32(ptr)` | Aggregate/hidden ABI, varargs, alternate convention, extra function roots |
| `attributes` | Enumerate attributes; preserve `noundef`; admit only observed `znver4` CPU/features for future explicit transition to v3 | Unknown enum/string, memory-effect or ABI claims; no generic deletion |
| `pointer_provenance` | Explicit u32 extension and instruction-free tied register cast; bounds/null edges dominate dereference; ordinary payload loads break address taint | Forged casts/map roots, unchecked lookup, pointer escapes, address observations, scalar/Boolean/PHI/select/aggregate laundering into payload |
| `scratch_contracts` | Exact inline-asm types, constraints, dialect and side-effect flags; one shared key `[r10-4,r10)` and value `[r10-16,r10-8)`; preparation identity and freshness on every predecessor | Changed primitive, clobber/overlap/unknown alias, re-preparation including equal literals, escape, user/dynamic stack |
| `calls_runtime` | Complete module inventory; one requested entry and exact lookup/update declarations; source operations retained | Allocation/init/TLS/constructors, unwind/errors, recursion, indirect calls, unknown helpers/intrinsics or unreachable baggage |
| `debug_metadata` | Preserve only observed Debug Info Version flag 3; inventory function definitions/declarations and instruction attachments; no source-line or CO-RE claim | Unknown flags, function/instruction attachments, forged global/license/map payloads or input DI graph |
| `target_transition` | Source checks are non-mutating; no optimization pipeline or target transition occurs here | Unknown target choice, removal of side effects/error paths or unrecorded rewriting |

The two-u32 layout is the **accessed prefix**, not the full Linux `xdp_md`
size. Both LLVM layouts report preferred alignment 8 in addition to ABI
alignment 4. Host equality does not prove the BPF register path retains
verifier-visible packet pointer state. Backend inspection and real guest
verification/execution must complete that obligation before emission is
qualified. Valid scalar integer aliases are accepted regardless of Mojo's
one-lane SIMD implementation. A surviving LLVM vector, including one lane,
requires a separate scalarization proof and is refused in this candidate.

The packet bound is an explicit u32-to-u64 extension plus a nonnegative
constant at most `2^31-1`. Its result stays below `2^63`, proving the retained
`nuw`/`nsw` addition and `samesign` comparison flags in that domain.
An `inbounds` packet GEP must itself follow the proved range edge, before
any byte load. Other integer poison-generating flags and extra GEP wrap
flags require their own proof and are refused. Narrowing an address cannot
create a new packet-pointer proof.

Memory alignment is a separate obligation from an access fitting inside
its cell. The shared value and non-null u64 lookup roots guarantee eight
bytes; an accumulated offset of one or two cannot support an `align 4`
i32 load/store, while offset four can. Byte accesses retain their one-byte
guarantee. Context/key roots guarantee four bytes and packet roots one.
The audit rejects an excessive source assertion rather than rewriting it.

## Shared cell and pointer analyses

Key freshness is finite CFG dataflow over preparation identity, literal
and cell validity. Joins retain only facts proved by every predecessor.
Stores use LLVM's actual byte footprint and resolved offsets; GEP, freeze,
PHI/select and aggregate insertion/extraction preserve aliases. Unknown
destinations/writers invalidate the key cell. Cycles are outside this
no-loop slice. Resource exhaustion produces `MBPF320`, never acceptance.

The analysis-only `mojobpf-audit-driver` resolves explicit test-owned
bindings to actual LLVM values and invokes the same production analyses.
It prints `whole_program_admitted=false`, cannot transform/emit IR, and
does not admit other program families. The source recognizer constructs
its own bindings by typed primitive/call inspection. Those are separate
tests, so a faulty recognizer cannot certify the analysis fixtures.

The original key corpus remains unchanged. Its two deliberately invalid
dominance/use-before-definition fixtures fail LLVM verification first.
The i96 boundary store has a 12-byte footprint ending at the key boundary,
so key analysis proves disjointness; emission still refuses its width and
value-cell range. A four-byte `{i16,i16}` value store is now provably
disjoint by typed layout analysis, refining the old unknown-width refusal;
aggregate-over-key and 16-byte overlap cases still fail freshness. Scalar
memory loads produce ordinary data. Address-derived comparison bits stay
tainted through casts and joins and cannot become stored payload, including
the legacy predicate-store fixture that formerly accepted them.
The shared pointer analysis also follows tainted branch outcomes into PHI
edge selection. Distinct incoming values selected by an address predicate
remain tainted, just as an explicit select does. Traversals stop at the
join and all traversal/edge/value work uses the finite budget. A guard
that permits an entire join through one outcome does not select its
payload; ordinary loaded-data stores remain valid. Equal-value PHI
inputs do not materialize the predicate.
If both outcomes can reach unequal PHI inputs, equal structural reachability
sets do not prove that the selection is independent. The audit conservatively
retains taint, including paths with reversed literal or scalar branches.
It does not fold branches to infer independence.
The ledger records the exact first whole-source boundary separately from
each core result. A legacy fixture's unreachable block or unreserved
helper does not stand in for exercising its key or pointer invariant.

Whole-source admission tracks context/packet addresses, map references,
nullable/non-null lookup values and scratch cells. Scratch addresses feed
only bounded loads/stores and reserved helper operands. Update consumes
eight initialized value bytes with flags zero. Equal literals do not
erase key preparation identities. There is no algorithm-name or operation
count vector, and no legacy register-pressure exemption is inherited.

See [diagnostics](diagnostics.md) for the new target/resource diagnostics.
