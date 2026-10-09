<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF artifact format (0.2.0)

What `mojobpf build` emits: a standard BPF ELF object plus a
JSON evidence sidecar. Both layouts below are transcribed from
the [quickstart](quickstart.md) counter build
(`counter.bpf.o`, 1896 bytes); the stated invariants are
pinned by the cited tests.

## The object: standard BPF ELF

```text
counter.bpf.o: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), not stripped
```

The object is a conventional `EM_BPF` relocatable loadable by
unmodified `bpftool`/libbpf — no custom loader, no sidecar
required at load time. Final objects load, run, and unload
from a directory containing only themselves
(`tests/elf/test_mutations.py::test_standalone_object_without_sidecars`
for the host half — stock inspection, verification, and
`bpftool btf dump` on a lone object —
`tests/kernel/test_xdp_accounting.py` for the in-guest half).

Sections of the quickstart counter, as reported by `mojobpf
inspect` on the actual bytes:

```text
object build/counter.bpf.o (profile linux-bpfel-v3): ok
observation: sections in order: , .strtab, .text, .BTF, .rel.BTF, xdp, .relxdp, license, .maps, .eh_frame, .rel.eh_frame, .symtab
observation section:license: license payload: b'Apache-2.0 WITH LLVM-exception\x00'
observation: empty executable sections: .text
observation: defined functions: xdp_entry
observation: map metadata: .maps present: True, .BTF present: True
observation: helper IDs observed: 1, 2
observation: call instructions: 2
```

The pinned invariants:

* exactly one executable section holding exactly one
  function (`xdp_entry`), with exact license bytes
  (`tests/elf/test_minimal_object.py`);
* map relocations against `.maps` (`.maps` itself is 32 zero
  bytes; kind and count live in BTF), with one code
  relocation per map-address load
  (`tests/elf/test_generalized_maps.py::test_map_section_and_relocations_per_shape`);
* map BTF describing the declared map, parsed independently
  and cross-checked against unmodified `bpftool btf dump`
  (`tests/elf/test_map_btf.py`).

The counter's BTF, as dumped by unmodified `bpftool 7.7.0`
from the built object:

```text
[1] PTR '(anon)' type_id=3
[2] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED
[3] ARRAY '(anon)' type_id=2 index_type_id=4 nr_elems=2
[4] INT '__ARRAY_SIZE_TYPE__' size=4 bits_offset=0 nr_bits=32 encoding=(none)
[5] PTR '(anon)' type_id=6
[6] ARRAY '(anon)' type_id=2 index_type_id=4 nr_elems=4
[7] PTR '(anon)' type_id=8
[8] ARRAY '(anon)' type_id=2 index_type_id=4 nr_elems=8
[9] PTR '(anon)' type_id=10
[10] ARRAY '(anon)' type_id=2 index_type_id=4 nr_elems=1
[11] STRUCT 'mojobpf_map_def' size=32 vlen=4
	'type' type_id=1 bits_offset=0
	'key_size' type_id=5 bits_offset=64
	'value_size' type_id=7 bits_offset=128
	'max_entries' type_id=9 bits_offset=192
[12] VAR 'mojobpf_map0' type_id=11, linkage=global
[13] DATASEC '.maps' size=0 vlen=1
	type_id=12 offset=0 size=32 (VAR 'mojobpf_map0')
```

The four array bounds read `(type 2, key_size 4, value_size
8, max_entries 1)`: a one-entry `ARRAY` map with `u32` keys
and `u64` values. On this object BTF covers map metadata only;
no function records and no `.BTF.ext` are emitted (only the
core-profile CO-RE probe object carries relocation records;
see [compatibility](compatibility.md)).

The `license` section carries the validated kernel
declaration verbatim, NUL-terminated; the tool derives it
from the manifest without substitution and never rewrites it
to gain API access (see [licensing](licensing.md)).

## The sidecar: versioned build evidence

Each object ships with `<artifact>.evidence.json`, schema
version 4 (`schemas/evidence.schema.json`). The quickstart
sidecar's top level:

```text
schema_version = 4
tool_version = 0.2.0
sdk_version = 1.1
profile_id = linux-bpfel-v3
source_license = Apache-2.0 WITH LLVM-exception
kernel_license = Apache-2.0 WITH LLVM-exception
license_mapping_version = 1
success = True
transforms = ["mojo-frontend", "ir-adapter", "llc-backend"]
```

`inputs` seals everything the build consumed: the source
files with SHA-256, the SDK files with SHA-256, the adapter
scripts with SHA-256, the compiler identities, the flag
sets, the manifest, and the tool/SDK versions. `commands`
records every stage (`build.frontend`, `build.adapter`,
`build.backend`) with argv, exit code, and status. `outputs`
seals the emitted object by SHA-256. The sidecar carries no
absolute paths: rebuilding the same sources in another
directory under the same environment yields identical
objects and identical sidecars
(`tests/kernel/test_cleanup.py::test_reproducible_two_paths`).
Across different environments only the environment seal
differs — a SHA-256 of `PATH`, never the path itself — as
observed when the quickstart counter was built from two
separate virtual environments (same object
`b2679151…`, sidecars differing only in that seal).

The tool and SDK versions join the cache key (key version
6), so objects built under different versions never share a
cache entry
(`tests/unit/test_build_commands.py::test_build_stamps_tool_and_sdk_versions`,
`tests/unit/test_artifact_publication.py::test_schemas_valid_and_conform`).

## Publication: owned directories, atomic generations

`mojobpf.evidence.publish_artifacts` publishes one staged file
set all-or-nothing into an owned, identity-pinned output
directory:

* the output directory must be a real directory owned by the
  current user — a symlink is refused before anything is
  written, under every spelling (`link`, `link/`, `link/.`),
  and an optional run-ownership token claims the directory
  for one run so same-user runs cannot publish into each
  other's directories
  (`tests/unit/test_artifact_publication.py`
  `::test_publish_rejects_symlinked_out_dir`,
  `::test_publish_rejects_symlinked_out_dir_spellings`,
  `::test_publish_requires_owned_out_dir`,
  `::test_publish_ownership_token_claim_and_enforce`,
  `::test_publish_ownership_token_malformed_and_spoofed`);
* the directory is pinned by an open descriptor and held under
  an exclusive lock for the whole call, so concurrent
  publishers serialize into whole generations instead of
  interleaving
  (`::test_publish_holds_exclusive_lock`,
  `::test_publish_concurrent_no_mixed_generation`);
* predecessors are classified without following links, read
  back through `O_NOFOLLOW` opens, and re-verified immediately
  before the rename; a file-to-symlink swap between the check
  and the backup read, or a predecessor change between backup
  and replace, aborts the call with the backup restored
  (`::test_publish_backup_swap_rejected`,
  `::test_publish_backup_swap_keeps_rollback_honest`,
  `::test_publish_predecessor_change_before_replace_rejected`);
  a symlink swapped in after the final recheck is removed by
  the rename rather than followed, and the installed file's
  identity is re-verified against the staged temporary before
  hashing, so a swapped result is refused instead of reported
  (`::test_publish_final_window_symlink_never_followed`,
  `::test_publish_swapped_result_rejected`);
* the pinned directory identity is re-verified around every
  step: an output-directory swap is detected, nothing new is
  reported, the original directory is rolled back through the
  pinned descriptor, and the swapped-in path is never mutated
  (`::test_publish_out_dir_swap_mid_flight_detected`,
  `::test_publish_out_dir_symlink_swap_mid_flight_detected`,
  `::test_publish_reswap_during_rollback_still_rolls_back`);
* on any failure the call raises `MBPF106` at stage
  `evidence.publish` instead of returning artifacts; when a
  predecessor cannot be restored, or a new file cannot be
  removed, the error reports the incomplete rollback and the
  retained recovery backups
  (`::test_publish_mid_failure_rolls_back`,
  `::test_publish_incomplete_rollback_reports_backups`,
  `::test_publish_swap_rollback_failure_recorded`,
  `::test_publish_failed_new_file_unlink_recorded`,
  `::test_publish_interrupted_new_file_unlink_incomplete`,
  `::test_publish_swapped_new_file_unlink_recorded`).

Interruptions (`KeyboardInterrupt`, `SystemExit`) run the same
rollback and propagate as themselves carrying a
`PublicationRecovery` account. Names starting with `.` are never
results: crash leftovers use that namespace and are safe to
delete. Unrelated files in the output directory are never
touched.

## Sidecar binding and qualification

The loader never reads sidecars, so consistency between objects
and provenance is enforced at qualification time, not load time.
`mojobpf.evidence.qualify_artifacts` is the qualification
aggregator: it takes published sidecar bytes plus the live object
bytes and either returns a `QualificationReport` binding the two
or fails closed with `MBPF710` at stage `evidence.verify`:

* every sidecar must parse as duplicate-free JSON, carry
  exactly the version-4 evidence fields with no unknown
  entries, record a successful build, name the artifact it
  is qualified under, and agree with itself: the top-level
  `profile_id`/`tool_version`/`sdk_version` must equal the
  corresponding recorded inputs;
* every `outputs[]` entry must be a bound object of that
  artifact — `<artifact>.bpf.o`, or
  `<artifact>.<entry>.bpf.o` with a non-empty entry — and the
  claimed object set must match the live bytes exactly: no
  missing bytes, no unbound bytes, no object claimed by two
  sidecars;
* each live object's SHA-256 and size are compared against its
  record; the report binds every accepted object to its
  sidecar bytes, to the recorded input set (the cache key over
  the sidecar's inputs), and — when the caller supplies one —
  to the run-plan digest (validated for shape, recorded, never
  recomputed). Optional expectations turn recording into
  comparison: `expected_inputs` must match every sidecar's
  recorded inputs, and `expected_run_plan` bytes must hash to
  the supplied run-plan digest.

The unit negatives pin each rule
(`tests/unit/test_artifact_publication.py::test_qualify_accepts_bound_sidecar`
through `::test_qualify_rejects_unhashable_command_status`,
including `::test_qualify_rejects_contradictory_provenance`,
`::test_qualify_expected_inputs_compared`, and
`::test_qualify_expected_run_plan_compared`); the
contract suite proves the same checks against genuine builds
(`tests/elf/test_artifact_contract.py::test_qualification_binds_real_build`,
`::test_qualification_rejects_real_tamper`,
`::test_qualification_aggregates_two_artifacts`).

## Trust limit: unsigned local provenance

Stated plainly: the sidecar plus qualification detect accident
and drift — a detached, truncated, or edited sidecar, an
object that no longer matches its record, an input set that
changed between runs. They do not authenticate objects or
provenance against a coordinated malicious rewriting of both
together: anyone able to rewrite the object bytes can rewrite
the adjacent sidecar to match, and the qualification would
still pass. Treat published artifacts as local build records
with exact bindings, not as signed releases. No signature
service and no mandatory custom loader are introduced here;
both would be separately scoped work.

## Original-spec equivalence record

The original design (§7.1) sketches a per-artifact directory
`build/<artifact>/` holding `program.bpf.o`, `artifact.json`,
`provenance.json`, and `diagnostics.json`, with one manifest
building one object (§8.2), and requires either the sketched
interfaces or a documented equivalent (§4.4). The
implementation's equivalent, recorded here:

| sketched shape | actual equivalent |
|---|---|
| `build/<artifact>/` directory | the caller's flat output directory; artifact and entry names join each file name instead of a per-artifact directory |
| `program.bpf.o` | `<artifact>.bpf.o` for one program; `<artifact>.<entry>.bpf.o` per entry for several (`mojobpf.evidence.layout_names`) |
| `artifact.json` | the build result's artifact records (`role`/`name`/`sha256`/`size`), returned in-process rather than written as a separate file, plus the `outputs[]` seal inside the sidecar |
| `provenance.json` | `<artifact>.evidence.json`: input hashes per cache class, output hashes, transforms, licenses, normalized commands, environment |
| `diagnostics.json` | diagnostics stay in the build result and logs — they are run-specific and path-laden by design, and stable provenance must not embed them; failures surface through result records and CLI exits |
| one manifest builds one object | one manifest builds one object per program entry; each program reconciles independently |

The `.bpf.o must load without the JSON sidecars` clause holds
unchanged (see the object section above). Objects and the
sidecar publish through one transaction that is atomic on the
error path only: a failure that raises through the publisher
rolls back to the previous generation (or reports the
incomplete rollback), so a failed build never *reports* a
half-written generation as success. A process killed between
renames runs no handler and can leave a mixed generation plus
recovery backups behind; the next successful publication
replaces them wholesale. Later multi-object linking across
separately built objects is future work outside this contract
— not a reason to reshape the current layout.

## Machine-readable schemas

`schemas/` holds the versioned contracts: the manifest, the
diagnostics, the evidence sidecar, and the published
artifact. Builders and checkers validate against them;
unknown fields fail closed rather than being ignored.
