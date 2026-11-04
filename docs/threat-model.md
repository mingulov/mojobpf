# MojoBPF host threat model

This document states what the MojoBPF build driver trusts, what it
refuses, and where the residual risks are. Each of the four pages
covers one trust boundary; the arbitration table at the end records
the scope decision for every hardening item.

## Page 1: Environment

Boundary: the driver reads ambient environment once, passes a derived
environment to child tools, and records a stable environment into
build evidence (sidecars, cache keys).

Attacker capability: hostile values in ambient variables (injection,
loader hijack, secret exfiltration through persisted evidence).

Rules:

- Spawn environments are utility-filtered. Children are the user's own
  tools (same trust domain as the driver), so values pass through, but
  only allowlisted names and prefixes reach the child: loader and
  interpreter-hijack names are stripped first, then ambient is filtered
  to the allowlist, then the hardening overlay is applied. Explicit
  `env_extra` entries are code-specified and bypass the allowlist.
- Recorded environments are hash-only. Every recorded value is stored
  as `sha256:…`; no ambient value is persisted verbatim. Names matching
  `*KEY*`, `*TOKEN*`, `*SECRET*` (case-insensitive substring) are
  dropped from evidence entirely — not hashed, since low-entropy
  secrets are crackable from hashes.
- The drop rule is evidence-only and fail-closed: an exotic legitimate
  name containing one of those substrings loses its evidence record
  (weaker cache key for that variable) but is never leaked and still
  spawns normally.

## Page 2: Spawn

Boundary: tool admission (hash pins) → process spawn → output capture →
signal/reap. The window between identity verification and `exec`, the
child's output volume, and the signals sent at timeout are all hostile.

Attacker capability: a racing writer swapping binaries mid-spawn; a
chatty or malicious child exhausting memory; pid/pgid reuse turning a
kill into a signal against an unrelated process.

Rules:

- Only the allowlisted `Popen` keyword set reaches the spawn call; shell
  execution, alternate executables, pre-exec hooks, and fd passing are
  refused at the boundary.
- The exec'd image is held open from admission and executed through the
  held file description, so no path re-resolution happens between
  verification and `exec`. Chain scripts passed as arguments are
  re-statted immediately pre-spawn.
- Child output is spooled with a per-stream cap and a truncation note;
  verdict/marker scans see the full stream while only the capped head
  is stored.
- Direct children are signalled through retained pidfds, never numeric
  pids. Group sweeps run only while an unreaped direct child still pins
  the group; once the child is reaped the sweep is a no-op.

## Page 3: Filesystem input

Boundary: untrusted path arguments (`--object`, `--manifest`,
`--lockfile`, manifest-referenced sources, staged trees, publish
sources) → driver reads, hashes, copies.

Attacker capability: huge files exhausting memory; FIFOs and devices
blocking reads forever; symlinks redirecting reads, hashes, and
artifact installs outside the intended roots.

Rules:

- Every untrusted read goes through a capped regular-file reader:
  non-blocking `O_NOFOLLOW` open, `S_ISREG` required, pre- and
  post-read size bounds, identity re-check. Anything else (symlink,
  FIFO, device, directory, over-limit) is refused with the limit named,
  before blocking.
- Hashing is streamed with a running total cap; digests of capped
  inputs are byte-identical to whole-read digests of the same bytes.
- Manifest sources, staged captures, and lockfile-referenced files must
  resolve (realpath) under their pinned root; lexical containment is
  not sufficient.
- Artifact publish admits staged sources with the same `lstat` +
  `O_NOFOLLOW` + regular-file discipline as the already-hardened
  destination side.

## Page 4: Lock and pin

Boundary: lockfiles qualify tool bytes for execution; pin paths scope
guest `bpftool` load/unlink operations.

Attacker capability: unpinned bytes executed as trusted tools; pin-path
traversal escaping the bpffs scope for load or `rm -f`.

Rules:

- Outside explicit discovery mode (lockfile omitted, non-qualifying,
  nonzero exit), every executed tool byte range carries a hash pin:
  tools, adapter, runner, QEMU, guest bpftool. A lockfile that fails to
  pin a component it should qualify refuses the operation; warnings
  never substitute for refusal.
- Pin paths are normalized before the prefix check: the pin must equal
  its own `normpath`, contain no `.`/`..` segments, and sit under the
  bpffs prefix. Charset gates are not traversal gates.

## Scope arbitration

| Item | Disposition |
|---|---|
| Env redaction (hash all but allowlisted) | Accept: hash everything recorded; verbatim-name mechanism exists, initially empty |
| Drop `*KEY*/*TOKEN*/*SECRET*` | Accept per text; PASSWORD/CREDENTIAL extension accepted with the same rule |
| Sweep existing bundles | Accept: scan committed bundles/fixtures for secret patterns, record result |
| Size-capped regular-file reads | Accept with the per-kind cap table in Appendix A |
| Streamed hashing | Accept; byte-identical digests required |
| Capped child-output spool | Accept: verify transcript + admitted runs (build/native/controller already capped) |
| Lock hashes outside discovery | Accept: adapter fail-closed (MBPF104); all other lanes already enforce |
| Re-hash / fd-exec at spawn | Refine: held-fd exec for the image (closes the race); chain scripts re-statted pre-spawn (narrows it) |
| Spawn-env allowlist | Accept with the name/prefix table in Appendix B; explicit extras bypass |
| popen kwargs allowlist | Accept: 7 names; fd-exec kwargs stay internal |
| pidfd kill | Refine: pidfd for direct children in all lanes; group sweep only while a child pins the group |
| Realpath containment | Accept: manifest sources, staged captures, distribution file |
| O_NOFOLLOW publish source | Accept: mirror the destination-side discipline |
| Guest pin `..` rejection | Accept on the verify path (normalization + prefix); map-pin constants are a residual (see below) |

## Residual register

- Same-inode content rewrite between verification and use is unfixable
  without immutable files; fd-exec closes path races, not content races.
- Chain scripts passed as argv are re-statted, not fd-held; the residual
  window is microseconds and is logged, not silent.
- In-lane adapter-service reads are stage-internal and out of scope.
- Suite-authored map-pin constants are safe by construction today; if
  pin tags ever become external input, traversal validation reopens.
- Descendant-group sweeps remain numeric but time- and membership-
  bounded as stated above; full subreaper adoption is future work.

## Appendix A: read caps

| Input kind | Cap |
|---|---|
| BPF objects (`--object`, verify inputs) | 16 MiB |
| Manifests | 1 MiB |
| Lockfiles (toolchain, kernels) | 1 MiB |
| Mojo sources and imports | 8 MiB |
| IR documents | 32 MiB |
| External-party JSON files (auditor grants) | 1 MiB |
| Distribution METADATA/RECORD | 1 MiB |

Over-cap reads are refused with the byte limit named in the
diagnostic. FIFOs and other non-regular files swapped in for a
regular file are refused without blocking. Adapter subprocess
responses arrive over stdout and are bounded by the capture spool,
not by this table.

## Appendix B: spawn environment

Ambient names reaching children: `PATH`, `HOME`, `TMPDIR`,
`MODULAR_HOME`, `LANG`, `TZ`, `PYTHONHASHSEED`, the `LC_*` prefix,
and the `MOJO_*`, `MODULAR_*`, `LLVM_*`, `MOJOBPF_*` prefixes.
Loader and interpreter-hijack names are stripped first; the
`PYTHONNOUSERSITE`/`PYTHONDONTWRITEBYTECODE`/`PYTHONSAFEPATH`
overlay is applied after; explicit caller-supplied entries bypass
the allowlist.
