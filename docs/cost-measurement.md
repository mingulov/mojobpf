<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Object-cost measurements

The source checkout includes a Python collector for static BPF object measurements. It supports ELF64 little-endian relocatable BPF objects and accounts for one catalog-selected entry at a time. It reads captured inputs without compiling, executing or loading them.

From the repository root with Python 3.11 or newer:

```sh
PYTHONPATH=src python3 tests/codegen_cost/collect.py object --help
```

For a prepared case catalog, object and provenance file, use:

```sh
PYTHONPATH=src python3 tests/codegen_cost/collect.py object \
  --cases path/to/cases.json \
  --case your.case.identifier \
  --object path/to/program.o \
  --provenance path/to/provenance.json \
  --out path/to/new-measurement
```

The output directory must not exist and its parent must already exist. The case identifier must match a row in the supplied catalog, including its explicit section and function selection, profile, required metrics and captured semantic contract. Supplied provenance must contain a matching `profile`; declared object hashes must also match. These identity checks do not establish production provenance admission.

The [included catalog](../tests/codegen_cost/cases.json) contains one ready synthetic accounting control and pending C, Mojo and Rust comparison cases. Pending rows are an inventory of work still required, not runnable qualified baselines. Real producer provenance admission is not implemented: real objects may yield incomplete inspection reports and exit 3. Do not relabel a real object as synthetic to obtain a complete result.

## What is measured

| Metric | Meaning |
| --- | --- |
| ELF bytes | The complete captured file size, including headers and padding |
| Section file and logical bytes | Stored section payload versus declared logical size; an uninitialized section contributes no file payload |
| Executable bytes | File-backed executable section payload, counted once |
| Reachable slots and bytes | Static union reachable from the selected entry; slots are eight bytes, and a wide immediate uses two slots |
| Reachable subprograms and call depth | Statically resolved direct-call structure; shared callees are not recounted for every call |
| BTF, BTF extension, debug and relocation bytes | Separate stored section categories; compressed debug bytes remain compressed size |

Reachability is not a count of executed instructions. Unsupported control flow, recursion or unresolved function boundaries prevents a complete object measurement. Stack usage, verifier statistics, translated/JIT size, runtime duration, decompressed debug size and duplicate-body cost remain explicitly unavailable.

## Outputs and exit status

A successful capture retains `cases.json`, `object.o` and `provenance.json` in the new directory. A completed inspection writes `report.json` and `report-identity.json`; the identity hashes the canonical report content. An incomplete inspection also writes `attempt.json`. Earlier input or publication failures may leave only an attempt record or a structured stderr error. Preserve each attempt under a separate output directory.

| Exit | Meaning |
| --- | --- |
| 0 | All required measurements in the supported object-only scope are complete |
| 2 | Invalid usage, catalog or report shape, including an existing output directory |
| 3 | Required input, measurement or admission support is unavailable |
| 4 | Object, evidence identity or publication failure |

`complete: true` establishes only the report's fixed object-measurement scope. It does not establish kernel behavior, target support, a performance comparison or a size budget. The reserved `--target`, `--binding` and `--evidence-root` options must occur together and currently refuse actual target-bound export with exit 3. No validated production baseline or numeric budget is supplied yet.

Input work limits are parser bounds, not optimization budgets: objects are limited to 32 MiB and catalog/provenance documents to 4 MiB each. Captured evidence is rechecked against its declared identity before publication. See the [collector source](../tests/codegen_cost/collect.py) for the complete internal report and catalog validation rules.
