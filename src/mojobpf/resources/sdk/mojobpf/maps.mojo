# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Array, per-CPU array, hash, and LRU hash map definitions.
#
# The supported maps hold u32 keys and u64 values, declared in the
# standard loader-compatible form with map BTF: arrays, per-CPU
# arrays, hash maps, and LRU hash maps with the manifest-declared
# entry counts (1, 2, 3, or 4).
# The map address is loaded from the map metadata section by
# `MapHandle.load` (arrays), `PercpuHandle.load` (per-CPU
# arrays, which additionally tags the program as per-CPU so the
# pipeline emits the per-CPU map description),
# `HashHandle.load` (hash maps, which tags the program as hash
# so the pipeline emits the hash map description), or
# `LruHandle.load` (LRU hash maps, which tags the program as LRU
# so the pipeline emits the LRU map description). Key and value
# scratch slots live in fixed stack slots prepared by `key_slot`,
# `key_slot1`, `key_slot2`, `key_slot3`, and `value_slot`. All
# four key preparations share one stack cell: each stores its own
# key (0, 1, 2, and 3 respectively), and each stays live only
# until the next key preparation overwrites the cell, so every
# helper call consumes a freshly prepared key on a straight-line
# fallthrough. The value slot is left for the program to store
# through. Every item is force-inlined, so kernel programs built
# on this module contain only the intended map reference and slot
# shapes.
#
# Mutation semantics (array and per-CPU array):
#
# * Lookup takes a key slot holding a valid key and returns a
#   nullable result: branch on `is_null` before converting with
#   `unsafe_value_ptr`. The kernel rejects any use that skips the
#   check, even though an in-range lookup never misses.
# * Update takes key and value slots plus flags. Only `BPF_ANY` (0,
#   unconditional replace) lowers; `BPF_NOEXIST` and `BPF_EXIST` are
#   named here so call sites spell their intent, and the compile
#   pipeline refuses them until their behavior is qualified.
# * Each key preparation stores its own key into the shared cell:
#   `key_slot` stores 0, `key_slot1` stores 1, `key_slot2`
#   stores 2, `key_slot3` stores 3. Only the latest preparation
#   is live: a program prepares each key immediately before the
#   helper call that consumes it, with no other key preparation
#   between them. A program's key preparations must cover exactly
#   its map's entries (keys 0 through N-1 for an N-entry map);
#   any other key is refused before the kernel sees it.
# * The delete spelling lives in `helpers.mojo`. Both map kinds
#   preallocate their entries, so deletion always fails in the
#   kernel (`-EINVAL`). There is no from-program iteration
#   spelling: programs walk entries with open-coded lookup
#   sequences, and userspace walks live maps with the `bpf()`
#   get-next-key command. Out-of-range access from userspace fails
#   in the kernel instead of misdecoding.
#
# Mutation semantics (hash maps):
#
# * Lookup takes a key slot and returns a nullable result with
#   the same null-check discipline. Absent keys miss (null);
#   present keys hit. A program that skips the check is rejected
#   by the kernel verifier.
# * Update takes key and value slots plus flags. Only `BPF_ANY`
#   (0) lowers; it creates the entry when the key is absent and
#   replaces the value when it is present. `BPF_NOEXIST` and
#   `BPF_EXIST` stay refused spellings here too.
# * A program's key slots cover exactly keys 0 through N-1 for
#   an N-entry map, as with the preallocated kinds; userspace
#   may additionally use any other u32 key up to the entry
#   budget, and iteration order over those keys is unspecified.
# * Delete removes the entry and reports success (`0`); deleting
#   an absent key fails. There is no from-program iteration
#   spelling: userspace walks live maps with the `bpf()`
#   get-next-key command.
#
# Mutation semantics (LRU hash maps):
#
# * Lookup, update, and delete follow the hash discipline above:
#   absent keys miss, `BPF_ANY` creates-or-replaces, delete
#   removes and reports success. The one difference is the full
#   map: where a hash update fails, an LRU update evicts the
#   least-recently-used entry and inserts the new key.
#
# Vocabulary outside this module (other map types, key/value widths,
# other entry counts, helpers) is refused by the build driver and
# the IR audit with named diagnostics; nothing silently falls back.

from std.sys import inlined_assembly

comptime MAP_TYPE_ARRAY = 2
comptime MAP_TYPE_HASH = 1
comptime MAP_TYPE_LRU_HASH = 9
comptime MAP_TYPE_PERCPU_ARRAY = 6
comptime MAP_KEY_SIZE = 4
comptime MAP_VALUE_SIZE = 8
comptime MAP_MAX_ENTRIES = 1
comptime MAP_MAX_ENTRIES_COMBINED = 2
comptime MAP_MAX_ENTRIES_N3 = 3
comptime MAP_MAX_ENTRIES_N4 = 4

# Update flags. Only BPF_ANY (unconditional replace) lowers to the
# kernel helper; the other two name refused spellings (the pipeline
# rejects any nonzero flags value rather than changing it).
comptime BPF_ANY = 0
comptime BPF_NOEXIST = 1
comptime BPF_EXIST = 2


@fieldwise_init
struct MapHandle(ImplicitlyCopyable):
    """Address of the single map, loaded from its metadata section."""

    var addr: Int64

    @staticmethod
    @inline(.always)
    def load() -> Self:
        var addr = inlined_assembly[
            "r0 = mojobpf_map0 ll",
            Int64,
            constraints="={r0}",
            has_side_effect=True,
        ]()
        return Self(addr)


@fieldwise_init
struct PercpuHandle(ImplicitlyCopyable):
    """Address of the single per-CPU map, loaded from its metadata section.

    The map-address load is the same audited shape as
    `MapHandle.load`; the additional kind tag marks the program as
    per-CPU so the pipeline emits the per-CPU map description. The
    tag ties the loaded address to its result through an empty
    template, so the backend emits nothing for it; its value is
    always the map address, and it is the value helper calls take
    as their map operand. Every per-CPU handle load tags exactly
    once; mixing tagged and untagged loads in one program is
    refused.
    """

    var addr: Int64

    @staticmethod
    @inline(.always)
    def load() -> Self:
        var addr = inlined_assembly[
            "r0 = mojobpf_map0 ll",
            Int64,
            constraints="={r0}",
            has_side_effect=True,
        ]()
        var tagged = inlined_assembly[
            "",
            Int64,
            constraints="=r,0",
            has_side_effect=False,
        ](addr)
        return Self(tagged)


@fieldwise_init
struct HashHandle(ImplicitlyCopyable):
    """Address of the single hash map, loaded from its metadata section.

    The map-address load is the same audited shape as
    `MapHandle.load`; the additional kind tag marks the program as
    hash so the pipeline emits the hash map description. The tag
    ties the loaded address to its result through an empty
    template, so the backend emits nothing for it; its value is
    always the map address, and it is the value helper calls take
    as their map operand. Every hash handle load tags exactly
    once; mixing tagged and untagged loads, or hash tags with
    per-CPU tags, in one program is refused.
    """

    var addr: Int64

    @staticmethod
    @inline(.always)
    def load() -> Self:
        var addr = inlined_assembly[
            "r0 = mojobpf_map0 ll",
            Int64,
            constraints="={r0}",
            has_side_effect=True,
        ]()
        var tagged = inlined_assembly[
            "",
            Int64,
            constraints="=r,0",
            has_side_effect=True,
        ](addr)
        return Self(tagged)


@fieldwise_init
struct LruHandle(ImplicitlyCopyable):
    """Address of the single LRU hash map, loaded from its metadata section.

    The map-address load is the same audited shape as
    `MapHandle.load`; the additional kind tag marks the program as
    LRU so the pipeline emits the LRU map description. The tag
    ties the loaded address to its result through an empty
    template with a memory clobber, so the backend emits nothing
    for it while the audit tells it apart from the per-CPU tag
    (no side effect) and the hash tag (no clobber); its value is
    always the map address, and it is the value helper calls take
    as their map operand. Every LRU handle load tags exactly
    once; mixing tagged and untagged loads, or LRU tags with
    per-CPU or hash tags, in one program is refused.
    """

    var addr: Int64

    @staticmethod
    @inline(.always)
    def load() -> Self:
        var addr = inlined_assembly[
            "r0 = mojobpf_map0 ll",
            Int64,
            constraints="={r0}",
            has_side_effect=True,
        ]()
        var tagged = inlined_assembly[
            "",
            Int64,
            constraints="=r,0,~{memory}",
            has_side_effect=True,
        ](addr)
        return Self(tagged)


@inline(.always)
def key_slot() -> MutPointer[UInt32, MutAnyOrigin]:
    """Prepare the key scratch slot holding key 0."""
    return inlined_assembly[
        "r0 = r10\nr0 += -4\n*(u32 *)(r0 + 0) = r1",
        MutPointer[UInt32, MutAnyOrigin],
        constraints="={r0},{r1},~{memory}",
        has_side_effect=True,
    ](UInt32(0))


@inline(.always)
def key_slot1() -> MutPointer[UInt32, MutAnyOrigin]:
    """Prepare the key scratch slot holding key 1.

    The identical audited stack template as `key_slot`, holding the
    second entry of a multi-entry map.
    """
    return inlined_assembly[
        "r0 = r10\nr0 += -4\n*(u32 *)(r0 + 0) = r1",
        MutPointer[UInt32, MutAnyOrigin],
        constraints="={r0},{r1},~{memory}",
        has_side_effect=True,
    ](UInt32(1))


@inline(.always)
def key_slot2() -> MutPointer[UInt32, MutAnyOrigin]:
    """Prepare the key scratch slot holding key 2.

    The identical audited stack template as `key_slot`, holding the
    third entry of a multi-entry map.
    """
    return inlined_assembly[
        "r0 = r10\nr0 += -4\n*(u32 *)(r0 + 0) = r1",
        MutPointer[UInt32, MutAnyOrigin],
        constraints="={r0},{r1},~{memory}",
        has_side_effect=True,
    ](UInt32(2))


@inline(.always)
def key_slot3() -> MutPointer[UInt32, MutAnyOrigin]:
    """Prepare the key scratch slot holding key 3.

    The identical audited stack template as `key_slot`, holding the
    fourth entry of a multi-entry map.
    """
    return inlined_assembly[
        "r0 = r10\nr0 += -4\n*(u32 *)(r0 + 0) = r1",
        MutPointer[UInt32, MutAnyOrigin],
        constraints="={r0},{r1},~{memory}",
        has_side_effect=True,
    ](UInt32(3))


@inline(.always)
def value_slot() -> MutPointer[UInt64, MutAnyOrigin]:
    """Reserve the value scratch slot (program stores through it)."""
    return inlined_assembly[
        "r0 = r10\nr0 += -16",
        MutPointer[UInt64, MutAnyOrigin],
        constraints="={r0}",
        has_side_effect=True,
    ]()
