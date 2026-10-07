# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Helper capability and license registry.

This module is the single home of per-helper facts: the kernel
helper ID, the kernel's own symbol spelling (as it appears in
verifier logs), a one-line summary, the kernel's GPL-only flag,
and the target profiles whose validated subset admits the helper.
The license gate (:mod:`mojobpf.inspect`) and the helper-license
tests read these facts; nothing here rewrites a license
declaration.

Two helper classes live here side by side:

* profile helpers (IDs 1, 2, 3, 5, 8, 14, 130): admitted by the
  ``linux-bpfel-v3`` profile, none GPL-only, so they load under
  the project's non-GPL kernel declaration;
* the restriction witness (ID 35, ``bpf_get_current_task``):
  recorded as GPL-only and admitted by no profile, so the
  preflight diagnostic and the kernel rejection test have a
  concrete GPL-restricted helper to agree on.

Recording the witness is not subset widening: the profile's
admitted IDs are unchanged, the compiler audit still refuses the
witness spelling, and inspection still reports it as outside the
profile. The registry only makes the restriction explicit so the
preflight can name it instead of failing closed on an unknown ID.

The ``gpl_only`` flags record the kernel's per-helper GPL
restriction as observed through load behavior on the pinned
kernels: the seven profile helpers load under the non-GPL project
declaration, while the witness is rejected with the kernel's
GPL-restriction message (see the helper-license kernel suite).
Kernel symbol spellings match the verifier log form
(``bpf_get_current_task#35``).

Standard library only.
"""

from __future__ import annotations

from dataclasses import dataclass

# Version of the table below. A new or changed entry needs a
# reviewed registry update together with its audit, profile, and
# test coverage; the version bump marks that the table moved.
HELPER_REGISTRY_VERSION = 1


@dataclass(frozen=True)
class HelperCapability:
    """One recorded helper: identity, restriction, and admission.

    ``helper_id`` is the kernel helper number. ``kernel_name`` is
    the kernel's own symbol spelling. ``summary`` is one line of
    plain description. ``gpl_only`` records the kernel's GPL-only
    flag for the helper. ``profiles`` holds the target-profile
    identifiers whose validated subset admits the helper (empty
    for helpers no profile admits).
    """

    helper_id: int
    kernel_name: str
    summary: str
    gpl_only: bool
    profiles: tuple[str, ...]


HELPER_CAPABILITIES: tuple[HelperCapability, ...] = (
    HelperCapability(
        helper_id=1,
        kernel_name="bpf_map_lookup_elem",
        summary="look up an element by key in a map",
        gpl_only=False,
        profiles=("linux-bpfel-v3",),
    ),
    HelperCapability(
        helper_id=2,
        kernel_name="bpf_map_update_elem",
        summary="create or update an element in a map",
        gpl_only=False,
        profiles=("linux-bpfel-v3",),
    ),
    HelperCapability(
        helper_id=3,
        kernel_name="bpf_map_delete_elem",
        summary="delete an element from a map",
        gpl_only=False,
        profiles=("linux-bpfel-v3",),
    ),
    HelperCapability(
        helper_id=5,
        kernel_name="bpf_ktime_get_ns",
        summary="read the monotonic clock in nanoseconds",
        gpl_only=False,
        profiles=("linux-bpfel-v3",),
    ),
    HelperCapability(
        helper_id=8,
        kernel_name="bpf_get_smp_processor_id",
        summary="read the current CPU number",
        gpl_only=False,
        profiles=("linux-bpfel-v3",),
    ),
    HelperCapability(
        helper_id=14,
        kernel_name="bpf_get_current_pid_tgid",
        summary="read the current thread-group and thread IDs",
        gpl_only=False,
        profiles=("linux-bpfel-v3",),
    ),
    HelperCapability(
        helper_id=35,
        kernel_name="bpf_get_current_task",
        summary="read the current task struct (GPL-only witness)",
        gpl_only=True,
        profiles=(),
    ),
    HelperCapability(
        helper_id=130,
        kernel_name="bpf_ringbuf_output",
        summary="copy one record into a ring-buffer map",
        gpl_only=False,
        profiles=("linux-bpfel-v3",),
    ),
)

_BY_ID: dict[int, HelperCapability] = {
    entry.helper_id: entry for entry in HELPER_CAPABILITIES
}


def lookup_helper(helper_id: object) -> HelperCapability | None:
    """Return the registry entry for ``helper_id``, or None.

    Total over hostile input: unhashable or unrecorded IDs return
    None instead of raising, so callers fail closed with their own
    diagnostic.
    """
    try:
        return _BY_ID.get(helper_id)  # type: ignore[arg-type]
    except TypeError:
        return None


def profile_helper_ids(profile_id: str) -> tuple[int, ...]:
    """Return the admitted helper IDs for ``profile_id``, ascending."""
    return tuple(
        sorted(
            entry.helper_id
            for entry in HELPER_CAPABILITIES
            if profile_id in entry.profiles
        )
    )
