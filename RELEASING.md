<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Releasing MojoBPF

Cutting a release from candidate to published artifacts. Owner
commands (push, tag, publish) run only on explicit owner
direction; everything else below is executor work.

## 1. Candidate and version

The candidate is a clean tree at the qualified commit. Bump the
version in exactly three sites (single-source refactors are out
of scope for a cut):

* `pyproject.toml` (`version =`),
* `src/mojobpf/__init__.py` (`__version__`),
* `pixi.toml` (`version =`).

then update the version-coupled tests and transcripts in the
same commit: `tests/unit/test_sdk_surface.py`,
`tests/packaging/test_installed_build.py` (2 asserts), the five
consumer `tool_version` asserts, wheel/sdist pins if membership
changes (with a payload-diff note), and every `1.0.x` transcript
in `docs/quickstart.md` / `docs/install.md` (wheel filename,
installed version, `doctor` line). `pixi.lock` carries no
package version.

## 2. Gates

The candidate ships only with these receipts on it:

* Host lanes green via the pixi tasks on the candidate tree:
  `pixi run test-unit`, `test-compiler`, `test-package`,
  `test-smoke` (run lanes through the tasks, never the runner
  directly: the tasks provision the toolchain environment).
* Guest board green: `ci/run_vm_tests.py` per-lane runs plus
  the scoped `--merge` (`--expect-lanes` + `--expect-suites`),
  exit 0, on a clean tree.
* Evidence doc (`docs/evidence-<ver>.md`) with the board tally,
  toolchain versions, kernels, merged-report hash, and a rerun
  recipe; scope/claim sentences need their wording approvals.

## 3. Clean-clone build

From a clean clone (not the working checkout), in this order
(artifact builds pollute the tree with `src/*.egg-info`, which
breaks a later packaging run — tests first, artifacts after):

1. `pixi install` (reproduces the pinned toolchain
   hash-identically), then the package lane against the clone.
2. `pip wheel . --no-deps --no-build-isolation -w dist` with
   `setuptools==80.10.2` as the build backend (the `WHEEL` and
   `METADATA` checksum rows name it; the release workflow pins
   it by hash),
   `python3 setup.py -q sdist`, and the lowering build
   (`cmake -S compiler -B build/lower -DCMAKE_BUILD_TYPE=Release
   -DBUILD_TESTING=OFF && cmake --build build/lower -j$(nproc)`).
3. Fresh-venv offline wheel install, all examples via the CLI
   route plus `inspect` each (with `--profile` where the
   manifest names one), and the quickstart verbatim including
   the guest leg (`verify --kernel` on TCG + KVM, packet
   counting). The lockfile recipe must pin `bpftool` (spelling
   `version`); `MODULAR_HOME` must be exported.
4. Record the transcript, timings, container hashes, and the
   extracted-contents identity proof (`diff -r` across two
   wheel builds) in the release receipt.

## 4. Checksums

Regenerate the checksums record for the candidate artifacts:
per-file SHA-256 contents table of the wheel plus container
hashes. Label honestly: wheel containers vary per build
(zip metadata); only extracted contents are pinned. The
wheel-content diff vs the checksums table must be empty.

## 5. Tag

The owner creates the signed tag at the final candidate.
Signing uses SSH (`gpg.format=ssh`) with the owner's key,
configured once per checkout (values below are the 1.0.1
cut's):

```bash
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519.pub
git config gpg.ssh.allowedSignersFile ~/.config/mojobpf/allowed_signers
git tag -s v<ver> -m "MojoBPF <ver>"
git verify-tag v<ver>
```

Anyone can check a tag against the committed
`docs/allowed_signers` (principal `denis@mingulov.com`,
ED25519 key `SHA256:4SdMsG72+xOBHpyoHX9GDELA30Q9ulAlcRhBlDv/djo`):

```bash
git -c gpg.ssh.allowedSignersFile=docs/allowed_signers verify-tag v<ver>
```

Tags are never moved. A wrong tag is superseded by a new
patch release, never re-pointed.

## 6. Publish (owner)

1. Push `main`, then the tag (no force-push; existing tags
   untouched).
2. The tag-triggered workflow (`.github/workflows/release.yml`)
   rebuilds from the tag, proves the sdist rebuilds the
   same wheel, compares extracted contents against the
   recorded local build, and opens a DRAFT release with
   wheel + sdist + SBOMs + SHA256SUMS + checksums record +
   evidence record + attestation. The attestation covers
   `dist/*` only; the two attached docs records ride outside
   the SLSA subject set (their hashes are pinned inside the
   attested `SHA256SUMS`).
   Publish itself is a human click after the checks below.
3. Verify from a second machine/account view: download per
   the README, verify checksums/signature, build
   `xdp_counter`, compare its sha256 with the release notes.
4. Post the announcement only after the assets verify.

PyPI upload happens only on a separate explicit owner
decision (owner credentials).

## 7. Post-publish verification

The oracle from a clean environment: obtain per README,
verify checksums/signature, build `xdp_counter`, sha256
matches the release notes. Provenance attestation (if any)
proves origin only; qualification is checked against the
board cells in the evidence record.

## 8. Yank and errata

* A broken artifact is yanked (PyPI) or deleted (GitHub
  patch assets) with a dated errata note appended to the
  release notes (never rewritten history); the tag stays.
* A wrong claim is corrected by a new patch release with
  corrected notes; the old notes gain an errata pointer.
* A compromised signing key is revoked out-of-band; all
  assets signed with it are re-verified or yanked, and the
  runbook records the new key before the next cut.

## Historical tags

Observed 2026-11-24: the remote carries only `v1.0.0`
(at cdc9619, matching local). Local-only tags: `v0.1.0`,
`v0.2.0`, `v0.3.0a1`, `v1.0.0-rc1`, `v1.0.0-rc2`,
`g4-matrix-a6e640a`. Owner decision at publish time: push
them so their trees stay obtainable, or mark those releases
unobtainable-history in their notes. Never re-point a
published tag to new bits.
