# MojoBPF maintenance policy (v1.0 line)

This policy takes effect with the v1.0 readiness decision.
It governs the maintained line starting at the anchor commit;
the 0.2.0 release documents stay untouched as release
snapshots.

## Scope

The v1.0 line covers the eight target profiles
(`linux-bpfel-v3`, `-core`, `-hash`, `-lru`, `-net`, `-reserve`,
`-subprog`, `-uprobe`), the ten supported helpers, the four map
families,
and the tracepoint, ring-buffer, and uprobe observers exactly
as `docs/compatibility.md` claims them. Everything that page
lists as a non-claim (AArch64 support beyond the portability
lane, uprobe outside x86-64, subprogram calls outside XDP,
CO-RE beyond the relocation probe, TCG timing as a performance
result) stays a non-claim until its own gate passes.

## Pin discipline

Toolchain, kernel-lane, and lock updates require a full anchor
re-proof (fast suites, all five x86 KVM matrix lanes, the three
portability lanes, feasibility, quickstart, revision equality)
before promotion. Investigational lanes and pins never leak
into the release pins or the release documentation.

## Compatibility

The SDK surface is additive-only across minor versions; every
addition carries its surface-minor pin and a compat-suite
control. Audit codes (`MBPF3xx`) and inspection codes
(`MBPF40x`) are stable identifiers: existing codes keep their
meaning, and the diagnostic catalog grows by addition. The
`docs/supported-subset.md` table is regenerated from the tree
(`tests/verifier/test_subset_doc.py --refresh`) whenever a
covered file changes.

## Re-proof cadence

Every product commit re-runs the fast suites
(unit, IR, compile, core, ELF, verifier, differential,
packaging). Releases re-run the full anchor plus the five
external-consumer suites on all five lanes. A dirty tree never
anchors: the matrix and feasibility gates refuse it.

## Residuals

The deferred hygiene items stay tracked, not silent: guest
transcript archiving (in-memory stage logs are kept, not
bundled), fork-during-cleanup containment (needs cgroup or
freeze support), and PID-reuse identity (start-time identity
later). None affects a claimed behavior; each needs its own
proof before it closes.

## End of life and security

Privileged tests run only in disposable virtme-ng guests; the
project never loads or attaches BPF on a development host.
Helper access is never gained by changing an ELF license
declaration. Versions pin their toolchain and lane locks; a
lock update is a new release candidate, re-anchored in full.
