<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Disposable target controller

`python -m mojobpf.target_controller` runs one externally admitted lane in a dedicated Linux process. It performs main, intentional interruption, and fresh recovery attempts in that order. The controller consumes approval and lease records; it cannot issue either record or declare a target READY.

The implementation has deterministic tests that assemble observed fixture bytes through the real controller and the unchanged bootstrap assessor. The process guardian also has bounded, unprivileged local process controls. Guest boot, BPF behavior and target compatibility remain **NOT_RUN** for this controller. Fixture READY results are fixture evidence only.

## Invocation and prior authority

Use Python 3.11 or newer from the separately approved installed runtime. Supply the exact private cache path admitted in the proposal:

```sh
python3 -I -B -X pycache_prefix=/srv/controller-run/tmp/controller-cache \
  -m mojobpf.target_controller \
  --proposal /srv/controller-inputs/proposal.json \
  --approval /srv/controller-inputs/approval.json \
  --approval-sha256 APPROVAL_FILE_SHA256 \
  --lease /srv/controller-inputs/lease.json \
  --lease-sha256 LEASE_FILE_SHA256 \
  --lane approved-lane
```

The paths and hash labels are placeholders for externally prepared, independently pinned inputs. This example grants no target permission. Add `--validate-only` for read-only input validation: its result is NOT_RUN and it creates no lock, cache, output or process. `--cancel-fd N` accepts a cancellation byte or EOF on a dispatcher-owned descriptor; the controller sets close-on-exec and never passes it to the runner.

Executable proposals require the exact tuple `(2, controller-launch-v2, controller-result-v2, controller-result-v2-plus-v1)` for `schema_version`, `contract`, `controller_contract`, and `acceptance_rule`. All remaining launch fields are closed: `owner`, `host_boot_id`, `execution_mode`, `vm_concurrency`, `limits`, `paths`, `inputs`, `lanes`, `nice_policy`, and `hard_death_policy`. Concurrency is one; nice policy is `controller-once-inherited`, and hard-death policy is `quarantine`. A v2 x86-64 profile uses `expected.byte_order = "le"`, carried unchanged into projection. Legacy launch-v1 requires its historical `"little"` spelling and remains validate-only. Mixed versions or spellings refuse; the controller never upgrades inputs or rewrites their digests.

Approval-v1 binds the exact proposal file and every input reference. Lease-v1 independently binds approval, proposal, controller distribution, owner, host boot, run, lane, permitted roots, limits, a precreated lock pathname/device/inode/owner/mode, and sufficient expiry. Neither contains a future result hash. Each input reference contains an absolute normalized `path`, `file_sha256`, and nullable `canonical_sha256`; the byte pin comes from the trusted producer or dispatcher, not from the input's own asserted hash. Execution summaries must round-trip the installed public execution contract and pass `verify_spawn()`. Historical versions are observations, never new runtime probes.

`paths` names `output_root`, `tmp_root`, `farm`, `controller_output`, `lease_journal`, `controller_pycache`, and `final_path`. The controller-only directory lies beneath output_root and is disjoint from guest exports. Every lane names `run_id`, exact `expected` identities and three closed `invocations` with `phase`, `attempt_id`, `argv`, `cwd`, `env_overrides`, `start_new_session`, `timeout_seconds`, and `output_path`. Attempts use distinct guest export, temporary and cache roots. Only exact admitted `PATH`, `TMPDIR`, and `PYTHONPYCACHEPREFIX` overrides are accepted. Injection variables and arbitrary overrides refuse. The final PATH and farm inventory are independently checked.

The precreated lock is controller-owned, single-link regular data with mode 0600. Nonblocking exclusive flock remains held through terminal recording and checked release. Any preexisting controller history or lease journal refuses automatic reuse even after a crashed controller's flock disappears. Another run requires separate recovery and admission authority.

## Complete distribution closure

The separately pinned `controller-distribution-v2` supplement has exactly `schema_version`, `contract`, `producer`, `coverage`, `files`, `roles`, and `inventories`. Its canonical pin hashes the entire object. `producer` contains exactly `wheel_path`, `sources`, `wheel_members`, `installed_generated`, `install_scheme`, and `runtime_layout`; it binds the approved wheel, source copies, installed members, generated install files, and observed controller/runner Python layouts.

Each file row contains exactly `path`, `realpath`, `kind`, `mode`, `dev`, `ino`, `uid`, `gid`, `nlink`, `size`, `mtime_ns`, `ctime_ns`, `sha256`, and `link_target`. Kinds are `regular`, `directory`, or `symlink`; regular files have a nonzero SHA-256 and null link_target, links have null SHA-256 and exact link text, and directories have both null. Full metadata, content, modes, component links and declared final targets are checked through retained directory descriptors. Complete directory inventories use `{path, entries}` with sorted unique direct basenames, including empty directories.

Coverage requires the wheel producer directory, installed prefix, exact farm, historical rootfs and payload roots, and mechanically derived controller/runner stdlib and site-packages roots plus the QEMU module and data roots. Runtime root rows use `{path, purpose}` with `python-stdlib`, `python-site-packages`, `qemu-modules`, or `qemu-data`; unexplained auxiliary roots refuse. Each complete root includes all descendants and exact inventories. Specifically enumerated shared files outside those roots cannot hide an import/search directory. Necessary ancestor or target directories outside every complete root compare device/inode/uid/gid/mode exactly; their size/link-count/time fields remain recorded observations because owned directory creation can change them. This exception never applies to complete-root directories, files, links, guest exports or controller evidence.

The ten exact role sets are `controller`, `runtime`, `original_closure`, `supplemental_closure`, `rootfs`, `payload`, `input_sidecars`, `kernel_packages`, `kernel_images`, and `farm`. Overlapping paths must agree in every identity and content field. Role coverage cannot authorize an extra historical entry. Original and supplemental runtime manifests retain their `digest_of(files)` recipes; rootfs retains `digest_of(entries)`. Payload retains its exact eight-file `digest_of(files)` and the two independently pinned excluded input sidecars stay outside that digest. Recovery hashes its object without the embedded sha256 field. Package record bytes remain pinned separately from the ordered package-list digest used by lane inputs. Standalone payload/package records must equal their immutable parent observations.

Wheel inspection maps every archive member exactly to source and installed bytes. The only source exceptions are generated METADATA, WHEEL, entry_points.txt, top_level.txt and archive RECORD; archive RECORD is not authority for the rewritten installed RECORD. Generated installed files are closed to RECORD, INSTALLER, optional REQUESTED/direct_url.json and declared entrypoint scripts. All five shipped public schemas map to their exact data destinations. Extra, omitted, duplicate, relocated, stale-bytecode, encrypted, special or native archive members refuse. The actual in-process module, distribution location, import paths, mapped native files and both Python layouts must match the admitted closure; a descriptor claim alone is insufficient.

| Bound | Limit |
| --- | --- |
| Ordinary JSON, sidecars and guest marker/diagnostic files | 4 MiB each |
| Distribution / rootfs provenance JSON | 32 MiB / 16 MiB |
| Large JSON structure | 32 container levels, 2,000,000 value/key nodes |
| Closure files / inventory directories / inventory edges | 65,536 / 16,384 / 65,536 |
| Role references / runtime roots | 131,072 / 256 |
| Producer sources / wheel members / generated files | 8,192 / 8,192 / 256 |
| Wheel compressed / expanded / individual member | 64 MiB / 256 MiB / 32 MiB |
| Runtime regular file / unique aggregate content | 4 GiB / 16 GiB |
| Each stdout/stderr stream | 64 MiB |
| Full lane guardian prefix / records / record / receipt | 64 MiB / 65,536 / 16 MiB / 4,096 bytes |

No limit failure is truncation-as-success. Complete closure checks run before each exact spawn. These checks rely on trusted nonconcurrent writers; they are not a filesystem sandbox or proof against a malicious same-inode writer.

## Ownership, deadlines and evidence

The dedicated single-thread guardian is the sole Linux subreaper and waiter. It requires waitable SIGCHLD semantics and uses `WNOWAIT` plus Linux `__WALL` before its own reap. It acquires runner and descendant pidfds, brackets raw stat/fdinfo/parent observations, continuously discovers children only beneath proven owned processes, and identifies QEMU by its admitted executable bytes. It never globally scans processes or signals a numeric PID, process group, session, name or command line. Session changes cannot escape retained ownership.

The controller increases its own nice value by ten once and records readback; all attempts inherit it. Each attempt has a 900-second budget, with 300 seconds from spawn to startup evidence and to the interruption marker. Marker acceptance rechecks the exact positive, target and guest bytes and requires the same retained live QEMU. Cancellation and late markers stop progress. Streams use owned regular files rather than pipes. Overflow preserves the complete original file, records the limit failure and triggers cleanup.

Cleanup has one 30-second monotonic deadline, including guardian release and controller persistence/readback. CLEAN requires all retained pidfds exited, no unresolved live identity and a final kernel ECHILD while the dedicated controller owns no unrelated work. An observed descendant reaped by its live parent truthfully retains a null wait status; runner and controller-reaped children retain signed observed statuses. Normal runner return drains residual descendants. Intentional interruption signals the retained runner first and preserves -9 before fresh recovery can begin. There is no complete historical fork census claim.

Each completed epoch persists a separate immutable full-prefix JSONL snapshot and guardian receipt. Later snapshots contain all earlier bytes unchanged. The controller journal binds run/lane/lease/proposal/distribution, attempt-open sequence and completion pair/range. A synchronous write-all/fsync/checked-close/directory-sync/readback/replay barrier must finish within the original deadline before another prepare is permitted. Missing, failed, late or uncertain acknowledgement permanently refuses advancement; visible candidate records never recover that authority. The controller rechecks externalized physical facts, input bindings and projections from fixed owned bytes before writing the terminal sidecar.

Controller-only artifacts use exclusive creation and no-follow, single-link regular files. The sidecar references the final controller journal; that journal binds attempts and earlier artifacts without the future sidecar hash. A subsequent lease hint can reference both. This graph is acyclic. Raw stat/fdinfo/mount observations, guest observations, held-pin marker, commands, diagnostics, stream bytes and incomplete captures remain evidence. Files and temporary directories are retained for review; no recursive deletion or automatic restart occurs.

An ordinary failed but fully cleaned lane may be RELEASABLE with causally NOT_RUN successors and null successor cleanup. Ownership, API, admission, persistence or cleanup uncertainty remains quarantined. Main/fresh guest cleanup and pin/unmount observations must be actually captured. Interruption derives guest destruction only from complete retained QEMU/tree drain, with null guest_unmount. Reused numeric PIDs within an attempt prevent the unchanged v1 projection; reused boot/session/process identities across attempts prevent recovery success.

## Result inspection and dispatcher completion

The [v2 result schema](../ci/targets/controller-result-v2.schema.json) adds required nullable `completion_journal` and `completion_receipt` references to every non-null cleanup. CLEAN requires both. References are closed `{path, sha256}` records beneath the admitted controller directory. The [original v1 schema](../ci/targets/controller-result.schema.json) retains its original bytes and semantics. `validate_result(record)` checks shape only, using the standard library with embedded contracts; installed operation needs no checkout schema or jsonschema dependency.

`inspect_result_bundle(issued_launch_v2, pinned_result)` reads fixed artifacts, validates input and transition bindings, replays every committed epoch and compares signed waits, retained identities/parents, raw observations and conditional projections. It returns integrity with `release_authority = False`. `project_attempt` returns an existing validated per-phase v1 map reference. Neither constructs release authority or READY.

`validate_result_bundle` requires the exact issued launch-v2 object and a **trusted dispatcher-supplied** `DispatcherCompletionObservation`. The observation contains run_id, lane_id, lease_id, proposal_sha256, approval_sha256, lease_sha256, controller_distribution_sha256, public `ProcessIdentity`, exact boolean normal_exit and final_readback_acknowledged, exact integer exit_code, and two `BytePin(path, sha256)` values for independently retained absolute result/journal paths and file-byte hashes. The dispatcher supplies it only after observing normal termination of that exact retained controller and the successful final checked readback return. No sidecar field, generated hash, copied pair or replay result constructs this observation. It is a caller provenance precondition, not cryptographic attestation against a dishonest caller.

For a dispatcher that already holds those trusted observations:

```python
from pathlib import Path
from mojobpf.target_controller import read_approved_document, validate_result_bundle

result = read_approved_document(Path(completed_controller.result.path),
                                completed_controller.result.sha256)
eligibility = validate_result_bundle(issued_launch_v2, result,
                                     completed_controller=completed_controller)
```

Missing, abnormal, unacknowledged or mismatched observations refuse. Exit 0 must match successful lane semantics; exit 3 must match recorded terminal failure. All started epochs must have caller-committed CLEAN evidence and the non-quarantine rules must hold. The returned lease eligibility still reports assessment NOT_RUN: READY additionally requires the separately pinned unchanged bootstrap assessor and agreeing complete v1 projection.

CLI stdout emits the terminal sidecar only after successful final readback and checked handle releases; successful lanes exit 0 and recorded failures exit 3. Typed refusal reports code/detail/errno on stderr and exits 3 without completion acknowledgement. A dispatcher must distinguish recorded completion from refusal and independently read/pin the stored result and journal. Abrupt termination, an ACTIVE/QUARANTINED history or a visible RELEASABLE hint after a failed final release never authorizes reuse. Filesystem calls have checks before/after and bounded reads; there is no hard real-time cancellation guarantee for a blocking local syscall. General crash cleanup requires separately reviewed recovery authority.
