<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->
# MojoBPF diagnostics

Every failure the toolchain reports comes out as a stable diagnostic
record with six fields: a frozen machine-readable `code`, the raising
`stage`, a `severity`, a plain-language `explanation`, an optional
`location`, and an optional `remedy`. Codes keep their meaning once
issued; new failures receive new codes. The machine-readable shape is
pinned by `schemas/diagnostics.schema.json`, and every code's exact
rendering plus its neighboring-valid control is pinned by
`tests/compile/test_diagnostic_catalog.py`.

## Reading a diagnostic

The CLI prints one line per diagnostic on stderr:

```
CODE (stage/severity): explanation; location: ...; remedy: ...
```

The `location` and `remedy` parts appear only when the raising layer
knows them. A failing `mojobpf build` exits nonzero (4 for compile
failures, 2 for usage errors such as an unreadable manifest, 3 when
the toolchain itself is unusable) and never leaves a stale object
behind.

Program findings point at the offending source. Audit refusals
(`MBPF3xx`) reached through `mojobpf build` carry
`file:line: excerpt`:

```
location: /tmp/.../proj/prog.mojo:18:     ]()
```

Whole-program shape findings, which name no single line, point at the
entry definition instead. Frontend failures (`MBPF106` at
`build.frontend`) carry the Mojo compiler's own `file:line:col`
error line. Backend failures (`MBPF106` at `build.backend`) carry
the backend's first error line; the backend preserves no source
locations, so those stay at the tool level.

## Example transcript: audit failure

The transcript below is the actual output of the installed CLI
building a program that calls a helper through inline assembly
instead of the SDK wrapper (`mojobpf` 0.2.0 installed from the
wheel into a clean virtualenv; paths shortened to the project):

```
$ mojobpf build --manifest proj/mojobpf.toml --out-dir out \
    --lockfile proj/toolchains.lock.json
MBPF306 (adapter.audit/error): helper invocations must use the reserved call form, never inline assembly: '%11 = call i64 asm sideeffect "call 9", "={r0}"()'; location: /tmp/.../proj/prog.mojo:18:     ](); remedy: use the SDK helper wrappers unchanged
$ echo $?
4
```

Reading it: the audit (`adapter.audit`) refused the program because
the helper call at `prog.mojo` line 18 uses raw inline assembly
(the excerpt shows the closing line of the offending expression).
The fix is the remedy: call the SDK helper wrapper unchanged. Nothing
was emitted; the exit status is 4.

A frontend failure looks like this (same setup, syntactically
invalid source):

```
$ mojobpf build --manifest proj/mojobpf.toml --out-dir out \
    --lockfile proj/toolchains.lock.json
MBPF106 (build.frontend/error): frontend step exited 1: .../bin/mojo build --emit llvm -o /tmp/.../xdp_entry.raw.ll /tmp/.../proj/prog.mojo; location: /tmp/.../proj/prog.mojo:7:12: error: expected argument name; remedy: fix the reported error; the log excerpt names it
$ echo $?
4
```

Here the location is the Mojo frontend's own error: file, line 7,
column 12. The full tool log stays in the work directory under
`--save-temps`; the diagnostic always carries the first error line.

## How source lines are found

The audit works on LLVM IR, where findings are IR line numbers. After
an adapter failure, and only then, the driver re-emits the failed
program's source with line tables (`-g1`, recorded under the
`build.diagnose` stage) and maps the finding to the author's line.
The mapping is verified before use:

- the re-emitted IR must match the audited IR line for line once
  debug attachments are stripped (a shifted or reordered re-emit
  stands the mapping down);
- the reported path is always the file just built: the frontend
  replays cached line tables for byte-identical sources, so a stale
  path is remapped only after its content verifies byte-identical;
- inlined SDK frames resolve to the outermost call site, the
  author's own line;
- findings without a mappable line fall back to the entry definition
  line when it resolves;
- `MBPF301` is never rewritten: it reports an adapter-internal
  failure, never a program finding, so a source line would
  misdirect.

Anything unverifiable keeps the original diagnostic untouched. Valid
builds never run the re-emit, so valid programs produce
byte-identical objects with or without this machinery.

Two honest limits follow from the same rule. Synthesized globals
(`MBPF309`, for example from exception plumbing) carry no debug
location, and line tables can reorder code on such shapes, so those
findings keep their IR line. The audit's direct consumers (the
adapter service CLI, `tests/compile/unsupported/*.ll` probes) see IR
line locations by design: IR line numbers are that layer's accurate
addresses.

## Catalog

### Toolchain, profile, and build steps (MBPF1xx)

| Code | Stage | Severity | Meaning | Location |
| ---- | ----- | -------- | ------- | -------- |
| MBPF101 | profile.resolve | error | Unknown target profile | Manifest path |
| MBPF102 | toolchain.match | error | Installed tool differs from the lockfile pin | Lockfile path and tool |
| MBPF103 | toolchain.discovery | error | Required tool missing from PATH and search paths | `tool:<name>` |
| MBPF104 | toolchain.match | error | Lockfile missing or unreadable | Lockfile path |
| MBPF105 | toolchain.match | note | No lockfile: version validation skipped | None |
| MBPF106 | build.frontend / build.backend | error | Build step failed (nonzero exit, tool crash, error marker, missing output) | Tool's first error line, else the expected output path |
| MBPF107 | build.backend | error | Built map object leaves the qualified shape (spill gate) | Built object path |

### Manifest and driver gates (MBPF2xx)

| Code | Stage | Severity | Meaning | Location |
| ---- | ----- | -------- | ------- | -------- |
| MBPF201 | manifest.parse | error | Unknown `schema_version` | Manifest path |
| MBPF202 | manifest.parse | error | Unknown manifest field | Manifest path and field |
| MBPF203 | manifest.parse | error | Duplicate program entry name | Manifest path and entry |
| MBPF204 | manifest.parse | error | Duplicate map name | Manifest path and map |
| MBPF205 | manifest.parse | error | Map spec outside the profile vocabulary | Manifest path and map |
| MBPF206 | manifest.parse | error | Section/program-type pair conflict | Manifest path and program |
| MBPF207 | manifest.parse | error | Program source escapes the project directory | Manifest path and source |
| MBPF208 | manifest.parse | error | Program source file missing | Manifest path and source |
| MBPF209 | manifest.parse | error | Manifest unreadable or malformed | Manifest path |
| MBPF210 | manifest.parse | error | Invalid program or map name | Manifest path and name |
| MBPF211 | manifest.parse | error | Capability outside the selected profile | Manifest path |
| MBPF212 | build.adapter | error | Malformed adapter response (fail closed) | Response path |
| MBPF213 | build.setup | error | Program entry is not a supported root | Manifest path and entry |
| MBPF214 | build.setup | error | Map name is not a supported map | Manifest path and map |
| MBPF215 | build.setup | error | Manifest declares more maps than the pair form admits | Manifest path |
| MBPF216 | build.backend | error | Built object disagrees with the manifest (entry counts, maps, license section) | Built object path |
| MBPF217 | build.setup | error | Program entry disagrees with its section/program-type pair | Manifest path and entry |

### Audit (MBPF3xx)

All at stage `adapter.audit`, severity `error`. Through `mojobpf
build`, every code below carries a source `file:line: excerpt`
except `MBPF301` (no location by design) and `MBPF309` (IR line: the
frontend preserves no location for synthesized globals).
Direct-audit consumers see IR `line N` locations.

| Code | Meaning |
| ---- | ------- |
| MBPF301 | Lowering altered body lines beyond the admitted shapes (adapter-internal; report as a bug) |
| MBPF302 | Entrypoint header unexpected, missing, or duplicated |
| MBPF303 | Unreserved external call or declaration, or classifier shape-count mismatch |
| MBPF304 | Unwinding, TLS, constructor, or intrinsic machinery |
| MBPF305 | Floating-point or unsupported vector operation |
| MBPF306 | Helper invocation outside the reserved call form |
| MBPF307 | Map program outside the admitted count families |
| MBPF308 | SSA value used across a call (single-lane pressure) |
| MBPF309 | Module defines globals or unexpected symbols |
| MBPF310 | Stack allocation outside the promoted shapes |
| MBPF311 | Poison/undef, address-space, or pointer-integer operand |
| MBPF312 | Entrypoint calls itself |
| MBPF313 | Reserved helper declaration deviates |
| MBPF314 | Helper operand outside its prepared slot |
| MBPF315 | SSA value used but never defined |
| MBPF316 | Lookup-derived value stored into map memory |
| MBPF317 | Tracepoint program reads the context pointer |

### Object inspection (MBPF4xx)

All at stage `inspect.object`, severity `error`. Locations name the
object path, or the offending section.

| Code | Meaning |
| ---- | ------- |
| MBPF401 | Object missing, unreadable, or not an ELF object |
| MBPF402 | Malformed ELF headers, sections, or tables |
| MBPF403 | License section missing or malformed |
| MBPF404 | Unknown undefined symbols |
| MBPF405 | Map metadata inconsistent |
| MBPF406 | Section or machine outside the profile |
| MBPF407 | Unsupported feature (helper id, map use, relocation) |

### License and provenance (MBPF7xx)

All at stage `inspect.license`, severity `error`, except `MBPF708`
(`evidence.capture`).

| Code | Meaning | Location |
| ---- | ----- | -------- |
| MBPF701 | Malformed SPDX expression | None |
| MBPF702 | Program grant differs from the declared source license | Program source |
| MBPF703 | Unsupported mixed-license arrangement | Offending file |
| MBPF704 | Declaration pair has no mapping | None |
| MBPF705 | Object license bytes mismatch the declaration | `section:license` |
| MBPF706 | Helper licensing requirements cannot be established | None |
| MBPF707 | Program source lacks a license grant | Program source |
| MBPF708 | Provenance input unreadable (evidence capture) | Input path |
| MBPF709 | GPL-only helper under a non-GPL declaration | None |

## Further reading

- `docs/supported-subset.md` documents the accepted program shapes
  the `MBPF3xx` codes guard.
- `docs/licensing.md` documents the license behavior behind the
  `MBPF7xx` codes.
- `tests/compile/test_diagnostic_catalog.py` pins each code's exact
  rendering with a positive and a neighboring-valid control;
  `tests/packaging/test_installed_diagnostics.py` proves the
  installed wheel surfaces the same diagnostics as the checkout
  driver.
