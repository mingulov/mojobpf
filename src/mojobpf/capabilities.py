# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""One production source for target-profile and helper admission.

This module owns the admission boundary: the target-profile
registry (which program/section pairs, map vocabulary, entry
counts, helper IDs, BTF scope and entry ABI each named profile
admits) and the per-profile helper views derived from it.
Production code consults this module -- never a per-layer
re-pinning of the same literals -- so one registry entry plus its
tests is the whole admission change.

Helper views and migration note: :func:`helpers_for_profile`
returns ALL helper IDs admitted by a profile (the profile's own
``helper_ids``, cross-checked against the helper registry); it
fails closed with ``MBPF101`` for unknown profiles and for
profile/registry drift. :func:`introduced_helper_ids` is the
distinct introducing-only view: the IDs a profile introduces over
its base set, which is empty for capability profiles that admit
helpers purely through inheritance (core, hash, subprog, uprobe).
The older spelling ``mojobpf.helpers.profile_helper_ids`` is that
same introducing-only view under a misleading "admitted" name;
new code must call :func:`helpers_for_profile` for admission and
:func:`introduced_helper_ids` when it truly means "introduced".
``mojobpf.manifest`` re-exports the profile registry names so
existing importers keep working.

Admission is membership only: a helper ID listed here may still
need GPL coverage, which the license gates in
:mod:`mojobpf.inspect` decide from the helper registry's
``gpl_only`` flags.

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from .diagnostics import (
    STAGE_PROFILE_RESOLVE,
    Diagnostic,
    MojobpfError,
    SEVERITY_ERROR,
)
from .helpers import lookup_helper, profile_helper_ids


class ProfileError(MojobpfError):
    """A target profile is unknown or unusable."""


@dataclass(frozen=True)
class TargetProfile:
    """Validated capability subset behind one target-profile identifier.

    ``allowed_pairs`` holds the accepted ``(program_type, section)``
    combinations. ``allowed_map_types``, ``allowed_key_types`` and
    ``allowed_value_types`` hold the accepted map vocabulary.
    ``allowed_max_entries`` holds the accepted ``max_entries`` values
    for keyed maps. ``allowed_ringbuf_sizes`` holds the accepted
    ``max_entries`` values (ring sizes in bytes) for ring-buffer
    maps, which carry no key/value vocabulary. ``helper_ids`` holds
    the accepted helper IDs. ``btf_scope`` is ``"map-only"`` while
    only map BTF is validated and ``"map-and-core"`` once CO-RE
    relocation records are validated as well. ``entry_return`` and
    ``entry_parameters`` describe the validated entrypoint ABI.
    ``core_supported`` records whether CO-RE relocations are validated.
    ``subprog_supported`` records whether one static subprogram call
    (the single-callee ``(i64) -> i64`` shape) is validated.
    """

    profile_id: str
    byte_order: str
    cpu: str
    allowed_pairs: tuple[tuple[str, str], ...]
    allowed_map_types: tuple[str, ...]
    allowed_key_types: tuple[str, ...]
    allowed_value_types: tuple[str, ...]
    allowed_max_entries: tuple[int, ...]
    allowed_ringbuf_sizes: tuple[int, ...]
    helper_ids: tuple[int, ...]
    btf_scope: str
    entry_return: str
    entry_parameters: tuple[str, ...]
    core_supported: bool
    subprog_supported: bool


SUPPORTED_PROFILES: dict[str, TargetProfile] = {
    "linux-bpfel-v3": TargetProfile(
        profile_id="linux-bpfel-v3",
        byte_order="little",
        cpu="v3",
        allowed_pairs=(
            ("xdp", "xdp"),
            ("tracepoint", "tracepoint/syscalls/sys_enter_getpid"),
        ),
        allowed_map_types=("array", "percpu_array", "ringbuf"),
        allowed_key_types=("u32",),
        allowed_value_types=("u64",),
        allowed_max_entries=(1, 2, 3, 4),
        allowed_ringbuf_sizes=(4096, 131072),
        helper_ids=(1, 2, 3, 5, 8, 14, 130),
        btf_scope="map-only",
        entry_return="i32",
        entry_parameters=("ptr",),
        core_supported=False,
        subprog_supported=False,
    ),
    # CO-RE capability profile: everything the base profile
    # admits, plus the 4096-byte opaque core map value and
    # validated CO-RE relocation records. No helper, map kind,
    # or program type beyond the base set: the minimal slice
    # relocates one field read and one existence check through
    # the existing lookup helper only.
    "linux-bpfel-v3-core": TargetProfile(
        profile_id="linux-bpfel-v3-core",
        byte_order="little",
        cpu="v3",
        allowed_pairs=(
            ("xdp", "xdp"),
            ("tracepoint", "tracepoint/syscalls/sys_enter_getpid"),
        ),
        allowed_map_types=("array", "percpu_array", "ringbuf"),
        allowed_key_types=("u32",),
        allowed_value_types=("u64", "bytes4096"),
        allowed_max_entries=(1, 2, 3, 4),
        allowed_ringbuf_sizes=(4096, 131072),
        helper_ids=(1, 2, 3, 5, 8, 14, 130),
        btf_scope="map-and-core",
        entry_return="i32",
        entry_parameters=("ptr",),
        core_supported=True,
        subprog_supported=False,
    ),
    # Hash capability profile: everything the base profile
    # admits, plus hash maps with u32 keys and u64 values in
    # one- to four-entry sizes. No helper, key/value width,
    # entry count, or program type beyond the base set: the
    # hash slice reuses the existing lookup/update/delete
    # helpers and the dense key coverage, only the emitted map
    # kind differs.
    "linux-bpfel-v3-hash": TargetProfile(
        profile_id="linux-bpfel-v3-hash",
        byte_order="little",
        cpu="v3",
        allowed_pairs=(
            ("xdp", "xdp"),
            ("tracepoint", "tracepoint/syscalls/sys_enter_getpid"),
        ),
        allowed_map_types=("array", "percpu_array", "ringbuf", "hash"),
        allowed_key_types=("u32",),
        allowed_value_types=("u64",),
        allowed_max_entries=(1, 2, 3, 4),
        allowed_ringbuf_sizes=(4096, 131072),
        helper_ids=(1, 2, 3, 5, 8, 14, 130),
        btf_scope="map-only",
        entry_return="i32",
        entry_parameters=("ptr",),
        core_supported=False,
        subprog_supported=False,
    ),
    # Reservation capability profile: everything the base
    # profile admits, plus explicit ring-buffer reservations
    # (helpers 131, 132, 133). No map kind, key/value width,
    # entry count, or program type beyond the base set: the
    # reservation slice reuses the event pair (a four-entry
    # array plus its ring-buffer companion) and the 32-byte
    # record, only the publication path differs (reserve one
    # record and terminate it exactly once instead of
    # copy-output).
    "linux-bpfel-v3-reserve": TargetProfile(
        profile_id="linux-bpfel-v3-reserve",
        byte_order="little",
        cpu="v3",
        allowed_pairs=(
            ("xdp", "xdp"),
            ("tracepoint", "tracepoint/syscalls/sys_enter_getpid"),
        ),
        allowed_map_types=("array", "percpu_array", "ringbuf"),
        allowed_key_types=("u32",),
        allowed_value_types=("u64",),
        allowed_max_entries=(1, 2, 3, 4),
        allowed_ringbuf_sizes=(4096, 131072),
        helper_ids=(1, 2, 3, 5, 8, 14, 130, 131, 132, 133),
        btf_scope="map-only",
        entry_return="i32",
        entry_parameters=("ptr",),
        core_supported=False,
        subprog_supported=False,
    ),
    # Subprogram capability profile: everything the base profile
    # admits, plus one static subprogram call (the single-callee
    # ``(i64) -> i64`` shape on a classifier program). No helper,
    # map kind, key/value width, entry count, or program type
    # beyond the base set: the call shape uses no helpers and no
    # maps, only the callee in ``.text`` plus the static call
    # sites in the entry section.
    "linux-bpfel-v3-subprog": TargetProfile(
        profile_id="linux-bpfel-v3-subprog",
        byte_order="little",
        cpu="v3",
        allowed_pairs=(
            ("xdp", "xdp"),
            ("tracepoint", "tracepoint/syscalls/sys_enter_getpid"),
        ),
        allowed_map_types=("array", "percpu_array", "ringbuf"),
        allowed_key_types=("u32",),
        allowed_value_types=("u64",),
        allowed_max_entries=(1, 2, 3, 4),
        allowed_ringbuf_sizes=(4096, 131072),
        helper_ids=(1, 2, 3, 5, 8, 14, 130),
        btf_scope="map-only",
        entry_return="i32",
        entry_parameters=("ptr",),
        core_supported=False,
        subprog_supported=True,
    ),
    # Uprobe capability profile: everything the base profile
    # admits, plus one controlled uprobe register counter (the
    # ``("uprobe", "uprobe")`` pair). No helper, map kind,
    # key/value width, or entry count beyond the base set: the
    # counter reuses the existing lookup/update helpers and a
    # two-entry array map (expected argument plus count), only
    # the program type and the pinned x86-64 register read are
    # new. The object carries no attach target: the section is
    # the bare ``uprobe`` name, and the suite-owned loader
    # chooses the suite-owned test executable at attach time.
    # One build holds at most one uprobe program (see the
    # single-probe rule in parse_manifest): multi-probe graphs
    # are unproven and refused.
    "linux-bpfel-v3-uprobe": TargetProfile(
        profile_id="linux-bpfel-v3-uprobe",
        byte_order="little",
        cpu="v3",
        allowed_pairs=(
            ("xdp", "xdp"),
            ("tracepoint", "tracepoint/syscalls/sys_enter_getpid"),
            ("uprobe", "uprobe"),
        ),
        allowed_map_types=("array", "percpu_array", "ringbuf"),
        allowed_key_types=("u32",),
        allowed_value_types=("u64",),
        allowed_max_entries=(1, 2, 3, 4),
        allowed_ringbuf_sizes=(4096, 131072),
        helper_ids=(1, 2, 3, 5, 8, 14, 130),
        btf_scope="map-only",
        entry_return="i32",
        entry_parameters=("ptr",),
        core_supported=False,
        subprog_supported=False,
    ),
}

SUPPORTED_PROFILE_IDS = tuple(SUPPORTED_PROFILES)


def profile_digest(profile: TargetProfile) -> str:
    """Return the identity hash of a resolved target profile.

    The digest covers the complete profile record (capability sets,
    entry ABI, CO-RE support), canonically encoded, so two registry
    implementations under one identifier never share an identity.
    Builds seal this digest and provenance records it; any drift
    invalidates the capture and the cache key.
    """
    if not isinstance(profile, TargetProfile):
        raise TypeError("profile_digest requires a TargetProfile")
    text = json.dumps(
        asdict(profile),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def lookup_profile(profile_id: str) -> TargetProfile:
    """Return the registered profile, or raise ``MBPF101`` if unknown."""
    try:
        return SUPPORTED_PROFILES[profile_id]
    except KeyError:
        raise ProfileError(
            Diagnostic(
                code="MBPF101",
                stage=STAGE_PROFILE_RESOLVE,
                severity=SEVERITY_ERROR,
                explanation="unsupported target profile: %r" % (profile_id,),
                location="target.profile",
                remedy="use one of: %s" % ", ".join(SUPPORTED_PROFILE_IDS),
            )
        ) from None


def helpers_for_profile(profile_id: str) -> tuple[int, ...]:
    """Return ALL helper IDs admitted by ``profile_id``, ascending.

    This is the truthful admission view: the profile's complete
    admitted set, including helpers inherited from the base
    profile (so the uprobe profile reports its seven base
    helpers, not an empty tuple). Every returned ID is
    cross-checked against the helper registry; an admitted but
    unrecorded ID, or an unsorted/duplicated profile list, fails
    closed with ``MBPF101`` instead of reporting a set the two
    sources disagree on. Unknown profiles raise ``MBPF101`` like
    :func:`lookup_profile`.

    Admission is membership only; license coverage stays with the
    license gates.
    """
    profile = lookup_profile(profile_id)
    admitted = tuple(profile.helper_ids)
    if tuple(sorted(set(admitted))) != admitted:
        raise ProfileError(
            Diagnostic(
                code="MBPF101",
                stage=STAGE_PROFILE_RESOLVE,
                severity=SEVERITY_ERROR,
                explanation=(
                    "target profile %r lists helpers %r, not an "
                    "ascending unique set" % (profile_id, admitted)
                ),
                location="target.profile",
                remedy="report the profile registry drift",
            )
        )
    for helper_id in admitted:
        if lookup_helper(helper_id) is None:
            raise ProfileError(
                Diagnostic(
                    code="MBPF101",
                    stage=STAGE_PROFILE_RESOLVE,
                    severity=SEVERITY_ERROR,
                    explanation=(
                        "target profile %r admits unrecorded helper %r; "
                        "the profile registry and the helper registry "
                        "disagree" % (profile_id, helper_id)
                    ),
                    location="target.profile",
                    remedy="report the profile/helper registry drift",
                )
            )
    return admitted


def introduced_helper_ids(profile_id: str) -> tuple[int, ...]:
    """Return the helper IDs INTRODUCED by ``profile_id``, ascending.

    The introducing-only view: the IDs whose registry entry names
    this profile, excluding helpers the profile admits through
    inheritance. Capability profiles that introduce no helpers
    (core, hash, subprog, uprobe) report ``()`` here while still
    admitting the base set -- see :func:`helpers_for_profile` for
    admission.

    Migration: this is the distinct name for the view the older
    ``mojobpf.helpers.profile_helper_ids`` spelling returns; new
    code needing "introduced" must call this function, and new
    code needing "admitted" must call
    :func:`helpers_for_profile`.
    """
    return profile_helper_ids(profile_id)
