# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

# Capability coverage ledger

`capabilities/coverage-ledger.json` is the generated join of the
capability inventory, the target matrix, and the library API
coverage artifact. Each cell is one capability record x required
target x path (producer or consumer), evaluated to a status:

- `QUALIFIED`: the record is implemented and tested, carries
  evidence references, has no blocker, and (for consumer cells)
  the joined library row is required without a blocker, has
  all raw/forwarding/typed layers present, and passes all six
  evidence layers with every layer naming a matrix-admitted
  profile for that target (source-contract profiles never
  satisfy the runtime layer).
- `OPEN`: outstanding work, including targets blocked on
  missing execution. Blocked cells carry the excuse rationale;
  they are counted, never dropped.
- `NOT_APPLICABLE`: matrix exclusions citing sources only.
  A joined library row marked excluded aborts generation:
  admitted rows cannot be excluded under the pinned API
  contract.

The ledger header records SHA-256 hashes of all three inputs
plus the API artifact provenance (repository, revision, path).

## Regenerating

Regeneration runs from a checkout of the release tag with the
libbpf-mojo repository alongside it. The source distribution
carries the ledger, the matrix, the pinned API row extract,
the schema, and the materializer, but not the registry
(inventory-owned input) nor the independently packaged
library artifact, so both must come from their checkouts.
Prerequisite: Python 3 with `jsonschema` importable
(`python3 -c "import jsonschema"` must succeed; install the
system package or run `pip install jsonschema`):

```sh
set -euo pipefail
REV=$(python3 -c "import json; print(json.load(open('capabilities/coverage-ledger.json'))['inputs']['api_provenance']['rev'])")
API=$(mktemp /tmp/api-coverage.XXXXXX.json)
EXT=$(mktemp /tmp/api-rows.XXXXXX.json)
OUT=$(mktemp /tmp/ledger-regen.XXXXXX.json)
git -C ../libbpf-mojo rev-parse "$REV^{commit}"
git -C ../libbpf-mojo show "$REV:docs/api-coverage.json" > "$API"
python3 tools/validation/extract_api_rows.py \
  --artifact "$API" \
  --repo https://github.com/mingulov/libbpf-mojo \
  --rev "$REV" \
  --path docs/api-coverage.json \
  --output "$EXT"
cmp capabilities/api-rows.json "$EXT"
python3 tools/validation/materialize_coverage.py \
  --registry capabilities/registry.json \
  --matrix capabilities/target-matrix.json \
  --api-coverage capabilities/api-rows.json \
  --schema schemas/coverage-ledger.schema.json \
  --output "$OUT"
cmp capabilities/coverage-ledger.json "$OUT"
```

Read the API bytes from the header's pinned commit, never
from a worktree file: that keeps the procedure independent
of dirty checkouts. The pinned extract
(`capabilities/api-rows.json`) is a hash-recorded
derivative of that artifact revision carrying exactly the
rows the join consumes. Binding is layered: the ledger
header records the canonical-content hashes of its three
inputs plus the artifact revision and artifact bytes hash;
the offline suite additionally requires the committed
ledger and extract files to be byte-identical to fresh
canonical serialization; and this ritual byte-compares
both files against regeneration from the pinned commit.
Any substitution — content, revision, or formatting —
breaks one of the comparisons. Writing outputs aside
keeps the committed references available for comparison.

Generation is deterministic and fail-closed: unowned
records, unknown owners, surfaces, states, or row values,
duplicate identities, missing matrix excuses, unjustified
exclusions, and broken consumer joins each fail with an
error instead of emitting a misleading ledger.

## Known limitations

- Qualification evidence binds kernels and suites, not target
  profiles directly; per-target evidence gating awaits the
  kernel-cohort work that defines effective configurations.
- Only `function:` library rows join consumer cells; other API
  row kinds have no join rule yet.
- No record currently requires cost cases, and lifecycle
  obligations are not yet enumerated; both fields stay empty
  until their owning work defines them.
- Binding cells to implementation and qualification work
  leaves happens at dispatch time; the ledger carries the
  package and test-case join keys.
