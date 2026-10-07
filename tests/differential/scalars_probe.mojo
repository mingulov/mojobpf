# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Host-side differential probe for the SDK scalar functions.
#
# This program runs on the build host (plain `mojo build`, native
# target), never in the kernel: it executes the genuine SDK integer,
# endian, checksum, and guard helpers over boundary inputs and
# prints one tagged result line per case. The Python differential
# suite enumerates the same cases and predicts every line with
# mechanically distinct primitives (`int.from_bytes`, carry loops,
# explicit wrap masks), so a shared misunderstanding cannot hide.
# In-kernel behavior of the same helpers is proven separately by
# the kernel suites; this probe covers the exhaustive and
# overflow-boundary inputs no packet run can enumerate.
#
# The probe uses heap scratch buffers for its inputs. That is
# ordinary host-side test glue, not kernel code: nothing here is
# subject to the kernel subset, and nothing here loads into BPF.
#
# Output protocol: every line starts with a tag. The two exhaustive
# loops print bare values in fixed nested order (outer index first);
# every other section echoes its inputs before the value. Booleans
# print as True/False, integers as unsigned decimals.

from std.memory import Layout, alloc
from mojobpf.checksum import cksum_add, cksum_finalize, cksum_fold
from mojobpf.packet import (
    XdpCtx,
    addr_short,
    load_u8,
    load_u16_le,
    load_u32_le,
    packet_addr,
    packet_base,
    packet_len,
    packet_short,
)
from mojobpf.parse import is_vlan_tag, load_u16_be, vlan_id


def main():
    var buf = alloc(Layout[UInt8](count=16))
    var raw = buf^.unsafe_leak()
    var base = packet_base(UInt64(Int(raw)))

    # Exhaustive single bytes through the byte load.
    for b in range(256):
        raw.unsafe_offset(0).unsafe_write(UInt8(b))
        print("U8", load_u8(base, 0))

    # Exhaustive byte pairs through both endian loads.
    for lo in range(256):
        for hi in range(256):
            raw.unsafe_offset(0).unsafe_write(UInt8(lo))
            raw.unsafe_offset(1).unsafe_write(UInt8(hi))
            print("LE16", load_u16_le(base, 0))
            print("BE16", load_u16_be(base, 0))

    # Boundary words through the four-byte load.
    var words32: List[UInt32] = [
        0x00000000,
        0x00000001,
        0x000000FF,
        0x00000100,
        0x0000FF00,
        0x00FF0000,
        0x00FF00FF,
        0x12345678,
        0x78563412,
        0x7FFFFFFF,
        0x80000000,
        0x80000001,
        0xFFFFFFFE,
        0xFFFFFFFF,
    ]
    for v in words32:
        var b0 = UInt8(v & 0xFF)
        var b1 = UInt8((v >> 8) & 0xFF)
        var b2 = UInt8((v >> 16) & 0xFF)
        var b3 = UInt8((v >> 24) & 0xFF)
        raw.unsafe_offset(0).unsafe_write(b0)
        raw.unsafe_offset(1).unsafe_write(b1)
        raw.unsafe_offset(2).unsafe_write(b2)
        raw.unsafe_offset(3).unsafe_write(b3)
        print("LE32", b0, b1, b2, b3, load_u32_le(base, 0))

    # Boundary tag-control fields through the VLAN identifier mask.
    var tcis: List[UInt16] = [
        0x0000,
        0x0001,
        0x0FFF,
        0x1000,
        0x1FFF,
        0x8100,
        0x8107,
        0x8FFF,
        0xFFFF,
    ]
    for tci in tcis:
        print("VLID", tci, vlan_id(tci))

    # Tag-protocol neighbors through the tag predicate.
    var fields: List[UInt16] = [0x0000, 0x0800, 0x80FF, 0x8100, 0x8101, 0xFFFF]
    for field in fields:
        print("ISVL", field, is_vlan_tag(field))

    # Boundary sums and words through the checksum accumulator.
    var sums: List[UInt32] = [
        0x00000000,
        0x00000001,
        0x0000FFFE,
        0x0000FFFF,
        0x00010000,
        0x0001FFFE,
        0xFFFFFFFE,
        0xFFFFFFFF,
    ]
    var words: List[UInt16] = [0x0000, 0x0001, 0xFFFF]
    for s in sums:
        for w in words:
            print("ADD", s, w, cksum_add(s, w))

    # Boundary sums through the carry fold and the final complement.
    var folds: List[UInt32] = [
        0x00000000,
        0x00000001,
        0x000000FF,
        0x0000FFFF,
        0x00010000,
        0x00010001,
        0x0001FFFE,
        0x0001FFFF,
        0x00020000,
        0xFFFEFFFF,
        0xFFFFFFFE,
        0xFFFFFFFF,
    ]
    for s in folds:
        print("FOLD", s, cksum_fold(s))
    for s in folds:
        print("FIN", s, cksum_finalize(s))

    # Whole four-word windows accumulated then finalized.
    var windows: List[UInt16] = [
        0x0000, 0x0000, 0x0000, 0x0000,
        0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        0x8000, 0x8000, 0x0000, 0x0000,
        0x1234, 0x5678, 0x9ABC, 0xDEF0,
    ]
    for wi in range(4):
        var w0 = windows[wi * 4]
        var w1 = windows[wi * 4 + 1]
        var w2 = windows[wi * 4 + 2]
        var w3 = windows[wi * 4 + 3]
        var acc = cksum_add(UInt32(0), w0)
        acc = cksum_add(acc, w1)
        acc = cksum_add(acc, w2)
        acc = cksum_add(acc, w3)
        print("WIN", w0, w1, w2, w3, cksum_finalize(acc))

    # Synthetic length contexts through the start-based guard,
    # including 64-bit wrap boundaries the packet runs cannot reach.
    var gdata: List[UInt32] = [
        0, 0, 0, 0, 0, 100, 100, 5, 5, 5,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0xFFFFFFFF,
        0, 0, 0, 12345, 12345, 10,
    ]
    var gend: List[UInt32] = [
        0, 0, 1, 1, 1, 160, 160, 5, 6, 6,
        0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 1, 13345, 13345, 5,
    ]
    var gneed: List[UInt64] = [
        0, 1, 0, 1, 2, 60, 61, 0, 1, 2,
        0, 1, 1, 18446744073709551615, 18446744073709551615,
        0xFFFFFFFF, 0x100000000, 18446744073709551615, 1000, 1001, 0,
    ]
    for i in range(len(gdata)):
        var ctx = XdpCtx(gdata[i], gend[i], UInt32(0))
        print("GSH", gdata[i], gend[i], gneed[i], packet_short(ctx, gneed[i]))

    # Synthetic addresses through the address-based guard.
    var adata: List[UInt64] = [
        0, 0, 10, 10, 10, 100, 100,
        0xFFFFFFFF, 18446744073709551615, 0, 0, 18446744073709551614,
    ]
    var aend: List[UInt32] = [
        0, 0, 10, 11, 11, 160, 160,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    ]
    var asize: List[UInt64] = [
        0, 1, 0, 1, 2, 60, 61,
        1, 1, 0xFFFFFFFF, 0x100000000, 1,
    ]
    for i in range(len(adata)):
        var ctx = XdpCtx(UInt32(0), aend[i], UInt32(0))
        print(
            "ASH",
            adata[i],
            aend[i],
            asize[i],
            addr_short(adata[i], ctx, asize[i]),
        )

    # Synthetic contexts through the length and address arithmetic.
    var pdata: List[UInt32] = [0, 0, 100, 160, 10, 0xFFFFFFFF, 0xFFFFFFFF, 0, 5, 12345]
    var pend: List[UInt32] = [0, 1, 160, 100, 5, 0xFFFFFFFF, 0, 0xFFFFFFFF, 5, 13345]
    for i in range(len(pdata)):
        var ctx = XdpCtx(pdata[i], pend[i], UInt32(0))
        print("PLEN", pdata[i], pend[i], packet_len(ctx))
    var qdata: List[UInt32] = [0, 100, 100, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0, 12345]
    var qoff: List[UInt64] = [0, 60, 0, 0, 1, 18446744073709551615, 18446744073709551615, 18446744073709539270]
    for i in range(len(qdata)):
        var ctx = XdpCtx(qdata[i], UInt32(0), UInt32(0))
        print("PADDR", qdata[i], qoff[i], packet_addr(ctx, qoff[i]))

    # Context words through the context loader over fixed patterns.
    for b in range(12):
        raw.unsafe_offset(b).unsafe_write(UInt8(b))
    var pat = XdpCtx.from_ctx(base)
    print("FCTX", pat.data, pat.data_end, pat.data_meta)
    raw.unsafe_offset(0).unsafe_write(UInt8(1))
    raw.unsafe_offset(1).unsafe_write(UInt8(0))
    raw.unsafe_offset(2).unsafe_write(UInt8(0))
    raw.unsafe_offset(3).unsafe_write(UInt8(0))
    raw.unsafe_offset(4).unsafe_write(UInt8(0))
    raw.unsafe_offset(5).unsafe_write(UInt8(0))
    raw.unsafe_offset(6).unsafe_write(UInt8(0))
    raw.unsafe_offset(7).unsafe_write(UInt8(0))
    raw.unsafe_offset(8).unsafe_write(UInt8(0xFF))
    raw.unsafe_offset(9).unsafe_write(UInt8(0xFF))
    raw.unsafe_offset(10).unsafe_write(UInt8(0xFF))
    raw.unsafe_offset(11).unsafe_write(UInt8(0xFF))
    var pat2 = XdpCtx.from_ctx(base)
    print("FCTX", pat2.data, pat2.data_end, pat2.data_meta)
