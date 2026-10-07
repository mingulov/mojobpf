<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF SDK reference (surface 1.0)

The `mojobpf` Mojo package is the only importable surface a kernel
program may use. It ships five modules under the packaged SDK
directory (resolved through the installed tool, never the caller's
working directory):

| Module | Contents |
|---|---|
| `mojobpf.packet` | XDP context handle, length guards, byte/half/word loads, cursor |
| `mojobpf.parse` | Ethernet field accessors with one optional VLAN tag |
| `mojobpf.checksum` | Incremental ones-complement checksum arithmetic |
| `mojobpf.helpers` | Map lookup/update/delete wrappers plus the nullable result type |
| `mojobpf.maps` | Array and per-CPU array map handles, key/value slots, constants |

Every name below is pinned: the export list, the signatures, and
this document's test citations are checked mechanically
(`tests/unit/test_sdk_surface.py::test_export_list_matches_tree`,
`tests/unit/test_sdk_surface.py::test_sdk_doc_citations_resolve`).
A claim without a citation is not a claim.

## Version and compatibility

The SDK surface version is `1.0`
(`tests/unit/test_sdk_surface.py::test_sdk_version_pinned`).
Within one major version only additive changes are allowed: new
modules or new names may appear, but removing or renaming a module
or name, or changing a pinned signature, requires a major-version
bump. The frozen v1.0 baseline enforces this
(`tests/packaging/test_sdk_compat.py::test_additive_only_within_major`).

Every build stamps the tool and SDK versions into its provenance
and evidence sidecar, and both versions join the cache key, so
objects built under different versions never share a cache entry
(`tests/unit/test_build_commands.py::test_build_stamps_tool_and_sdk_versions`,
`tests/unit/test_artifact_publication.py::test_schemas_valid_and_conform`).

## Import rules

These are the only accepted import shapes (verified against the
Mojo 1.1.0 frontend; `as` aliases are transparent):

```mojo
from mojobpf.packet import XDP_PASS, load_u8
from mojobpf import packet
import mojobpf.packet
import mojobpf.packet as pkt
```

The frontend rejects anything else at the source layer: an unknown
module (`unable to locate module`), an unknown name (`module
... does not contain ...`, including any leading-underscore name,
which is reserved for internals and never exported), a name from
the wrong module, and paths deeper than `mojobpf.<module>`
(`... is a module, not a package`)
(`tests/packaging/test_sdk_compat.py::test_frontend_import_negatives`,
`tests/unit/test_sdk_surface.py::test_import_checker_truth_table`).
Every in-tree program stays within the pinned surface
(`tests/unit/test_sdk_surface.py::test_in_tree_sources_within_surface`).

## `mojobpf.packet`

Bounds-checked packet access. Guard discipline: every packet load
is dominated by a length guard, and a tripped guard returns
`GUARD_ACTION`, which is `XDP_DROP` (fail closed). The guard
values and the fail-closed rule are pinned against the ABI record
(`tests/elf/test_layouts.py::test_sdk_constants_match_record`).

* `XDP_DROP` (`1`), `XDP_PASS` (`2`): the two return actions.
  Both are observed in the kernel on crafted frames
  (`tests/kernel/test_packet_sdk.py::test_fixed_byte_actions`).
* `XdpCtx` / `XdpCtx.from_ctx(ctx)`: the three context words
  (`data`, `data_end`, `data_meta`) loaded from the kernel
  context. The loader is checked against an independent model
  (`tests/differential/test_scalars.py::test_context_loader`).
* `packet_short(ctx, need)`: true when fewer than `need` packet
  bytes are available. Guard arithmetic matches the oracle
  (`tests/differential/test_scalars.py::test_length_guard_arithmetic`,
  `tests/differential/test_scalars.py::test_length_and_address_values`),
  and short frames take the guard path in the kernel
  (`tests/kernel/test_packet_sdk.py::test_short_guard_actions`,
  `tests/kernel/test_packet_sdk.py::test_guard_paths`).
* `packet_len(ctx)`: `data_end` minus `data`, in bytes. A
  length-derived offset (`length mod 64`) classifies in the kernel
  (`tests/kernel/test_packet_sdk.py::test_var_offset_actions`).
* `packet_addr(ctx, off)` / `addr_short(addr, ctx, size)`: byte
  address of offset `off`, and the check that `size` bytes there
  stay in the packet. The address form matches the oracle
  (`tests/differential/test_scalars.py::test_address_guard_arithmetic`)
  and guards a variable offset in the kernel
  (`tests/kernel/test_packet_sdk.py::test_var_offset_actions`).
* `packet_base(addr)`: reinterprets a guarded address as a byte
  pointer. Call exactly once per program, on the guarded address:
  the verifier ties the checked range to one address computation,
  so the guarded and loaded values must be the same computation.
  The tied empty template emits no instructions of its own
  (packet objects carry no call instructions:
  `tests/elf/test_packet_struct.py::test_no_runtime_calls`), and
  content-derived addressing (a second pre-load feeding the
  address) is refused before the kernel
  (`tests/compile/test_subset_rejection.py::test_genuine_content_combination_refused`).
* `load_u8(base, off)`, `load_u16_le(base, off)`,
  `load_u32_le(base, off)`: alignment-safe little-endian loads;
  the caller must have guarded. Byte identity, exhaustive endian
  pairs, and boundary words match the oracle
  (`tests/differential/test_scalars.py::test_byte_load_identity`,
  `tests/differential/test_scalars.py::test_exhaustive_endian_pairs`,
  `tests/differential/test_scalars.py::test_boundary_words`),
  and each width classifies in the kernel
  (`tests/kernel/test_packet_sdk.py::test_fixed_byte_actions`,
  `tests/kernel/test_packet_sdk.py::test_half_actions`,
  `tests/kernel/test_packet_sdk.py::test_word_actions`).
* `Cursor(base, off)` / `advance(step)` / `u8()` / `u8_at(k)`:
  packet base plus a guarded offset; constant steps fold away.
  The cursor shape classifies in the kernel
  (`tests/kernel/test_packet_sdk.py::test_cursor_actions`).

Verifier notes: no packet dereference in any fixture is
unguarded (`tests/elf/test_packet_struct.py::test_guarded_loads`,
`tests/elf/test_packet_struct.py::test_variable_offset_guard`),
boundary frames take specified paths
(`tests/kernel/test_packet_sdk.py::test_boundary_frames`), and the
deliberately unguarded fixture keeps its loads visible so the
verifier (not the compiler) is what rejects it
(`tests/elf/test_packet_struct.py::test_unguarded_has_loads_but_no_guard`,
`tests/kernel/test_packet_sdk.py::test_negatives_rejected_by_verifier`).

## `mojobpf.parse`

Ethernet header fields in network (big-endian) order over a
guarded base. Untagged callers guard 14 bytes, tagged callers 18;
offsets stay constant so the single-reinterpretation shape holds.

* `load_u16_be(base, off)`: one 16-bit network-order field
  (little-endian load plus a swap). Endian pairs match the oracle
  (`tests/differential/test_scalars.py::test_exhaustive_endian_pairs`)
  and the accessor reads IPv4 EtherTypes in the kernel
  (`tests/kernel/test_parse_checksum_sdk.py::test_eth_actions`).
* `outer_ethertype(base)`: the bytes-12-13 field (EtherType, or
  the tag protocol on a tagged frame; caller guards 14)
  (`tests/kernel/test_parse_checksum_sdk.py::test_eth_actions`,
  `tests/kernel/test_parse_checksum_sdk.py::test_trunc_actions`).
* `vlan_tci(base)`: the tag-control field at bytes 14-15 (caller
  guards 16). `vlan_id(tci)`: its low 12 bits. A tagged frame
  with VLAN identifier 7 classifies in the kernel
  (`tests/kernel/test_parse_checksum_sdk.py::test_vlan_actions`),
  and VLAN fields match the oracle
  (`tests/differential/test_scalars.py::test_vlan_fields`).
* `inner_ethertype(base)`: the inner EtherType at bytes 16-17
  (caller guards 18)
  (`tests/kernel/test_parse_checksum_sdk.py::test_vlan_actions`).
* `is_vlan_tag(field12)`: true when the bytes-12-13 field is
  `0x8100`. Tag dispatch by value (never content-derived
  addressing) is proven on untagged, tagged, and truncated frames
  (`tests/kernel/test_parse_checksum_sdk.py::test_trunc_actions`).

Verifier notes: parse objects reuse the single-reinterpretation
shape with no call instructions
(`tests/elf/test_parse_struct.py::test_no_runtime_calls`), every
dereference is guarded
(`tests/elf/test_parse_struct.py::test_guarded_loads`), and the
two-tier (14/18-byte) guard is structural
(`tests/elf/test_parse_struct.py::test_two_tier_guard`).
Truncated frames prove the guard paths by taking them
(`tests/kernel/test_parse_checksum_sdk.py::test_guard_paths`).

## `mojobpf.checksum`

Incremental 16-bit ones-complement arithmetic over network-order
words. The module touches no packet bytes itself: callers load
each word big-endian and accumulate with explicit unrolled calls
over a bounded window. There are no loops, so after inlining the
verifier sees straight-line arithmetic on values the caller's
length guard already covered. Callers must not mix byte orders
within one digest.

* `cksum_add(sum, word)`: adds one network-order word to a
  32-bit running sum. Accumulation matches the oracle
  (`tests/differential/test_scalars.py::test_checksum_accumulate`).
* `cksum_fold(sum)`: folds every carry bit into 16 bits in two
  stages. The fold matches the oracle's carry loop
  (`tests/differential/test_scalars.py::test_checksum_fold_and_finalize`).
* `cksum_finalize(sum)`: fold plus complement, the transmitted
  checksum
  (`tests/differential/test_scalars.py::test_checksum_fold_and_finalize`).

Checksum windows classify in the kernel with exact digests
(`tests/kernel/test_parse_checksum_sdk.py::test_checksum_actions`,
`tests/kernel/test_parse_checksum_sdk.py::test_checksum_exactness`),
and the arithmetic is present in the object as plain integer
operations (`tests/elf/test_parse_struct.py::test_checksum_arithmetic_present`).

## `mojobpf.helpers`

One wrapper per supported kernel helper, issued as an ordinary
typed call to a reserved compiler-recognized declaration. The
adapter replaces only the callee operand with the standard helper
encoding, so argument registers, the result register, and the
caller-saved clobbers come from ordinary backend call lowering
(`tests/ir/test_helper_lowering.py::test_mir_call_model`,
`tests/ir/test_helper_lowering.py::test_backend_conformance_bytes`).
Every wrapper is force-inlined: kernel programs contain only the
intended helper invocations.

* `bpf_map_lookup(map_addr, key) -> LookupResult` (helper 1) and
  `bpf_map_update(map_addr, key, value, flags) -> Int64`
  (helper 2). The lowered callees and the final `call 1` / `call 2`
  bytes are exact
  (`tests/ir/test_helper_lowering.py::test_lowered_callee_lines`,
  `tests/elf/test_map_btf.py::test_helper_calls_present`), and the
  round trip computes 41 to 42 in the kernel
  (`tests/kernel/test_map_roundtrip.py::test_map_roundtrip_42`).
* `bpf_map_delete(map_addr, key) -> Int64` (helper 3). Deletion
  lowers to helper 3
  (`tests/ir/test_helper_lowering.py::test_delete_lowers_to_helper_3`);
  on arrays and per-CPU arrays (preallocated entries) it always
  fails with `-EINVAL` in the kernel while entries survive
  (`tests/kernel/test_array_maps.py::test_delete_refused_and_entry_survives`,
  `tests/kernel/test_generalized_arrays.py::test_delete_refused_four_entries`,
  `tests/kernel/test_mojo_percpu.py::test_delete_refused_four_entries`).
* `LookupResult` / `is_null()` / `unsafe_value_ptr()`: the lookup
  result is a nullable address as a plain integer (`0` is null).
  Callers must branch on `is_null` before converting; the kernel
  verifier rejects any use that skips the check
  (`tests/kernel/test_map_roundtrip.py::test_unchecked_rejected_by_verifier`,
  `tests/kernel/test_array_maps.py::test_unchecked_rejected_by_verifier`).
* `BPF_FUNC_map_lookup_elem` (`1`), `BPF_FUNC_map_update_elem`
  (`2`), `BPF_FUNC_map_delete_elem` (`3`): the helper IDs the
  wrappers lower to. They are pinned conveniences; the emitted
  IDs are what the lowering proofs check.

Map programs must keep nothing live across a helper call: a value
defined before a call and used after it is rejected
(`tests/compile/test_subset_rejection.py::test_genuine_liveness_violation_rejected`).
Only the combined workload's action selector and frame length may
cross calls, admitted by the combined count vector alone
(`tests/ir/test_audit.py::test_combined_count_vector_exact`).

## `mojobpf.maps`

Array and per-CPU array maps with `u32` keys and `u64` values in
1-4 entries, declared in loader-compatible form with map BTF. The
key/value widths and counts are pinned against the ABI record
(`tests/elf/test_layouts.py::test_sdk_constants_match_record`),
and the emitted map type, dimensions, and relocations are exact
per shape (`tests/elf/test_generalized_maps.py::test_btf_dims_per_shape`,
`tests/elf/test_generalized_maps.py::test_map_section_and_relocations_per_shape`,
`tests/elf/test_generalized_maps.py::test_bpftool_accepts_btf_per_shape`).

* `MapHandle.load()` / `PercpuHandle.load()`: the map address
  from its metadata section. The per-CPU load adds a kind tag
  that emits no code, so array and per-CPU objects share shapes
  and differ in exactly one BTF word
  (`tests/elf/test_generalized_maps.py::test_kind_is_one_btf_word`).
  Exactly one map symbol is declared
  (`tests/elf/test_map_contract.py::test_single_map_symbol_and_shared_declaration`),
  and mixing tagged with untagged loads in one program is refused
  (`tests/elf/test_generalized_maps.py::test_mixed_kind_refused`).
* `key_slot()` / `key_slot1()` / `key_slot2()` / `key_slot3()`:
  key scratch slots holding keys 0-3; a program's slots must
  cover exactly its map's entries. Dense keys validate, sparse
  and out-of-range keys are refused before the kernel
  (`tests/ir/test_audit.py::test_keyslotN_dense_keys_validate`,
  `tests/ir/test_audit.py::test_keyslotN_sparse_rejected`,
  `tests/elf/test_generalized_maps.py::test_oob_key_refused`,
  `tests/elf/test_map_contract.py::test_nonzero_key_refused`).
* `value_slot()`: the value scratch slot the program stores
  through. Slots compile to the audited stack immediates
  (`tests/ir/test_helper_lowering.py::test_stack_immediates_are_slots_and_increment`).
* `BPF_ANY` (`0`): the only lowering update flag (unconditional
  replace); the named spelling lowers to the canonical shape
  (`tests/elf/test_map_contract.py::test_named_spelling_matches_canonical`).
  `BPF_NOEXIST` and `BPF_EXIST` name refused spellings: any
  nonzero flags value is rejected, never rewritten
  (`tests/elf/test_map_contract.py::test_update_noexist_refused`,
  `tests/elf/test_map_contract.py::test_update_exist_refused`).
* `MAP_TYPE_ARRAY` (`2`), `MAP_TYPE_PERCPU_ARRAY` (`6`),
  `MAP_KEY_SIZE` (`4`), `MAP_VALUE_SIZE` (`8`),
  `MAP_MAX_ENTRIES` (`1`), `MAP_MAX_ENTRIES_COMBINED` (`2`),
  `MAP_MAX_ENTRIES_N3` (`3`), `MAP_MAX_ENTRIES_N4` (`4`):
  declarative mirrors of the emitted map description; the
  emitted values are what the BTF proofs check.

Behavior per operation, kind, and count is proven in the kernel:
read-modify-write lifecycles (41 to 42) with exact per-entry
counts
(`tests/kernel/test_generalized_arrays.py::test_rmw_lifecycle_four_entries`,
`tests/kernel/test_generalized_arrays.py::test_rmw_exact_counts_four_entries`,
`tests/kernel/test_mojo_percpu.py::test_rmw_exact_counts_four_entries`),
exact quiesced counts
(`tests/kernel/test_array_maps.py::test_exact_counts_after_quiescence`),
and first/last/invalid-key behavior per count with userspace
key walks
(`tests/kernel/test_generalized_arrays.py::test_first_last_walk_four_entries`,
`tests/kernel/test_array_maps.py::test_first_and_last_key`).

There is deliberately no key-iteration wrapper: the kernel offers
no from-program map-iteration helper, so from-program attempts
are refused
(`tests/elf/test_map_contract.py::test_nextkey_attempt_refused`,
`tests/elf/test_map_contract.py::test_getnext_attempt_refused`,
`tests/ir/test_helper_lowering.py::test_from_bpf_getnext_refused`)
and programs walk entries with open-coded lookups. Out-of-bounds
value access is rejected by the kernel verifier at load, never
misdecoded
(`tests/kernel/test_array_maps.py::test_oob_rejected_by_verifier`).

## Explicit non-claims

* No CO-RE: the profile records `core_supported = false`, and a
  manifest requesting it fails
  (`tests/unit/test_manifest.py::test_core_request_outside_profile_fails`).
* Tracing, other program types, and other helpers are outside the
  surface: only XDP programs and helpers 1-3 validate, and
  unknown inputs fail closed
  (`tests/unit/test_artifact_publication.py::test_requires_gpl_unknown_inputs`,
  `tests/elf/test_map_contract.py::test_no_foreign_helper_or_map_kind_emitted`).
* Only `ARRAY` and `PERCPU_ARRAY` maps with `u32` keys, `u64`
  values, and 1-4 entries exist; hash, LRU, and other shapes are
  refused at manifest validation
  (`tests/unit/test_manifest.py::test_hash_map_type_refused`,
  `tests/unit/test_manifest.py::test_lru_map_type_refused`).
* Only `BPF_ANY` updates lower; `BPF_NOEXIST`/`BPF_EXIST`
  spellings are refused, and there is no from-program iteration
  spelling (see the maps section for all four refusal proofs).
* Floating-point, multi-lane vectors, indirect calls, unwinding,
  allocation, and runtime calls have no SDK spelling and are
  rejected as a corpus with named codes
  (`tests/compile/test_subset_rejection.py::test_fixture_rejections`).
* A clean inspection report describes bytes only; it never claims
  the kernel will accept an object. Kernel acceptance is proven
  only by the in-kernel suites above, and the unsupported-shape
  negatives name the kernel verifier as their rejecting layer.
* The SDK carries no compiler: Mojo and LLVM are external
  dependencies (see the installation documentation). The wheel
  ships no compiler binaries
  (`tests/packaging/test_wheel_contents.py::test_no_bundled_compiler`).
