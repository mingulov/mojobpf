# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Incremental 16-bit ones-complement checksum arithmetic.
#
# This module is the checksum slice of the MojoBPF SDK: an
# accumulator over network-order 16-bit words plus the carry fold
# and final complement. It performs pure integer arithmetic and
# touches no packet bytes itself; callers load each word (big-endian,
# for example with the parsing slice) and accumulate with explicit
# unrolled calls over a bounded window. There are no loops of any
# kind here, bounded or otherwise, so after inlining the verifier
# sees straight-line arithmetic on values the caller's length guard
# already covered.
#
# Endianness matters: the running sum must accumulate network-order
# words. Summing little-endian words converges to a different value,
# so callers must not mix orders within one digest.
#
# The accumulator is 32 bits wide and the fold runs two stages, which
# carries any 32-bit sum (not only the small windows below) down to
# 16 bits: the first stage adds the high half into the low half and
# the second stage absorbs the remaining carry, if any. Finalizing
# complements the folded sum, which is the transmitted checksum.
#
# The module uses no main function, printing, heap allocation, Python
# interop, exceptions, or runtime init.


@inline(.always)
def cksum_add(sum: UInt32, word: UInt16) -> UInt32:
    """Add one network-order word to a running 32-bit sum."""
    return sum + UInt32(word)


@inline(.always)
def cksum_fold(sum: UInt32) -> UInt16:
    """Fold every carry bit into a 16-bit ones-complement sum."""
    var folded = (sum & 0xFFFF) + (sum >> 16)
    folded = folded + (folded >> 16)
    return UInt16(folded & 0xFFFF)


@inline(.always)
def cksum_finalize(sum: UInt32) -> UInt16:
    """Fold and complement: the checksum of the accumulated words."""
    return ~cksum_fold(sum)
