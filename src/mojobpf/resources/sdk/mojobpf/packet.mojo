# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Bounds-checked packet access helpers.
#
# This module is the packet slice of the MojoBPF SDK: a context handle
# for the kernel packet metadata, explicit length guards, and
# byte/half/word loads plus a cursor that keep the kernel verifier's
# packet-range tracking. Every item is force-inlined, so kernel
# programs built on this module contain only the intended context
# loads, one address reinterpretation, and plain loads.
#
# Guard discipline (frozen for reuse by later SDK slices): every packet
# load is dominated by a length guard, and a tripped guard returns
# GUARD_ACTION, which is XDP_DROP (fail closed). There are two guard
# forms. The start-based form checks `need` bytes from the packet
# start: `if packet_short(ctx, need): return Int32(GUARD_ACTION)`.
# The address-based form checks `size` bytes at a computed address:
# `var addr = packet_addr(ctx, off)` then `if addr_short(addr, ctx,
# size): return Int32(GUARD_ACTION)`.
#
# The verifier ties a checked range to one address computation: the
# guarded address value and the loaded address value must be the same
# computation, not two equal-looking ones. So `packet_base` is called
# exactly once per program, on the guarded address, and variable
# offsets must derive from context words (packet length), never from
# a second packet pre-load: a pre-load would need its own
# reinterpretation, and the checked and accessed computations would
# then be visibly different values the verifier cannot connect.
# Constant offsets and cursor steps fold to plain constant
# addressing, which the verifier tracks against the start-based
# guard. Multi-byte loads assemble bytes explicitly, so they are
# safe at any alignment.
#
# The module uses no main function, printing, heap allocation, Python
# interop, exceptions, or runtime init.

from std.sys import inlined_assembly

comptime XDP_DROP = 1
comptime XDP_PASS = 2
comptime GUARD_ACTION = XDP_DROP


@fieldwise_init
struct XdpCtx(ImplicitlyCopyable):
    """Packet bounds loaded from the kernel context words."""

    var data: UInt32
    var data_end: UInt32
    var data_meta: UInt32

    @staticmethod
    @inline(.always)
    def from_ctx(ctx: MutPointer[UInt8, MutAnyOrigin]) -> Self:
        """Load the three context words (data, data_end, data_meta)."""
        var words = ctx.unsafe_bitcast[UInt32]()
        return Self(
            words[unsafe_offset=0],
            words[unsafe_offset=1],
            words[unsafe_offset=2],
        )


@inline(.always)
def packet_short(ctx: XdpCtx, need: UInt64) -> Bool:
    """True when fewer than `need` packet bytes are available."""
    # Addition form, matching the C reference and the
    # differential oracle (`(base + need) mod 2**64 > end`):
    # needs are compiled-in small constants and packet
    # addresses derive from u32 context words, so the addition
    # never wraps in practice; the kernel verifier
    # independently bounds packet access. A subtraction form
    # would fail open when base > end (routine for
    # `addr_short` on short packets), so any guard-arithmetic
    # change needs a designed cross-language update, not a
    # local rewrite.
    return UInt64(ctx.data) + need > UInt64(ctx.data_end)


@inline(.always)
def packet_len(ctx: XdpCtx) -> UInt64:
    """Packet length in bytes (data_end minus data)."""
    return UInt64(ctx.data_end) - UInt64(ctx.data)


@inline(.always)
def packet_addr(ctx: XdpCtx, off: UInt64) -> UInt64:
    """Byte address of packet offset `off` (guard before use)."""
    return UInt64(ctx.data) + off


@inline(.always)
def addr_short(addr: UInt64, ctx: XdpCtx, size: UInt64) -> Bool:
    """True when `size` bytes at `addr` run past the packet end."""
    # Addition form, as in `packet_short` above.
    return addr + size > UInt64(ctx.data_end)


@inline(.always)
def packet_base(addr: UInt64) -> MutPointer[UInt8, MutAnyOrigin]:
    """Reinterpret a guarded packet address as a byte pointer.

    Call exactly once per program, on an address a guard above has
    already checked. The empty assembly template with tied
    constraints (=r,0) is a pure register copy: it emits no
    instructions of its own and keeps the verifier-visible address
    computation (one shared value feeding the guard and the loads)
    intact.
    """
    return inlined_assembly[
        "",
        MutPointer[UInt8, MutAnyOrigin],
        constraints="=r,0",
        has_side_effect=False,
    ](Int(addr))


@inline(.always)
def load_u8(base: MutPointer[UInt8, MutAnyOrigin], off: Int) -> UInt8:
    """Load one packet byte at `off` (caller must have guarded)."""
    return base[unsafe_offset=off]


@inline(.always)
def load_u16_le(base: MutPointer[UInt8, MutAnyOrigin], off: Int) -> UInt16:
    """Load two bytes little-endian (alignment-safe)."""
    var lo = UInt16(base[unsafe_offset=off])
    var hi = UInt16(base[unsafe_offset=off + 1])
    return lo | (hi << 8)


@inline(.always)
def load_u32_le(base: MutPointer[UInt8, MutAnyOrigin], off: Int) -> UInt32:
    """Load four bytes little-endian (alignment-safe)."""
    var b0 = UInt32(base[unsafe_offset=off])
    var b1 = UInt32(base[unsafe_offset=off + 1])
    var b2 = UInt32(base[unsafe_offset=off + 2])
    var b3 = UInt32(base[unsafe_offset=off + 3])
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)


@fieldwise_init
struct Cursor[O: MutOrigin, //](ImplicitlyCopyable):
    """Packet base plus a guarded offset."""

    var base: MutPointer[UInt8, Self.O]
    var off: Int

    @inline(.always)
    def advance(self, step: Int) -> Self:
        """Cursor `step` bytes further (constant steps fold away)."""
        return Self(self.base, self.off + step)

    @inline(.always)
    def u8(self) -> UInt8:
        """Load the byte under the cursor (caller must have guarded)."""
        return self.base[unsafe_offset=self.off]

    @inline(.always)
    def u8_at(self, k: Int) -> UInt8:
        """Load the byte `k` past the cursor (caller must have guarded)."""
        return self.base[unsafe_offset=self.off + k]
