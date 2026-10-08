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
(`tests/elf/test_mutations.py`,
`tests/kernel/test_xdp_accounting.py`).

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
4), so objects built under different versions never share a
cache entry
(`tests/unit/test_build_commands.py::test_build_stamps_tool_and_sdk_versions`,
`tests/unit/test_artifact_publication.py::test_schemas_valid_and_conform`).

## Machine-readable schemas

`schemas/` holds the versioned contracts: the manifest, the
diagnostics, the evidence sidecar, and the published
artifact. Builders and checkers validate against them;
unknown fields fail closed rather than being ignored.
