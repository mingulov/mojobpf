# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Mutant of the Jcc fixture: the zeros-expectation changes
# 755497 -> 755496 (single digit). Zeros now score 755497,
# matching neither gate, so the mutant returns ABORTED (0)
# where the base returns PASS (2).
# compare gates over packet bytes 14..51 (u64 12, s64 5, u32 4,
# K-form 6), each adding a power-of-two weight on its true arm.
# The score is a bitmask: every arm combination yields a unique
# sum, so the exact-equality gate proves EVERY arm executed:
# zeros must score exactly 755497 (PASS), the mixed packet
# exactly 293078 (DROP); any other score returns ABORTED.
#
# Gate map (bytes, zeros arm -> mixed arm):
# g1 eq-u64 (14,15): T -> F (+1); g2 ne-u64 (16,17): F -> T (+2);
# g3 ugt (18,19): F -> T (+4); g4 uge (20,21): T -> F (+8);
# g5 ult (22,23): F -> T (+16); g6 ule (24,25): T -> F (+32);
# g7 sgt (26,27, -1 biased): F -> T (+64);
# g8 slt (28,29, -1 biased): F -> T (+128);
# g9 sge (30,31, -1 biased): T -> F (+256);
# g10 sle (32,33, -1 biased): T -> F (+512);
# g11 eq-u32 (34,35): T -> F (+1024);
# g12 ult-u32 (36,37): F -> T (+2048);
# g13 ugt-u32-K10 (38): F -> T (+4096);
# g14 eq-u64-K7 (40): F -> T (+8192);
# g15 ugt-u64-K100 (42): F -> T (+16384);
# g16 slt-s64-K0 (44, -1 biased): T -> F (+32768);
# g17 eq-u64 (46,47): T -> F (+65536);
# g18 ne-u64-K9 (48): T -> F (+131072);
# g19 ne-u64 (49,50): F -> T (+262144);
# g20 ne-u32-K5 (51): T -> F (+524288).
# Zeros: 231209+524288 = 755497.
# Mixed: 30934+262144 = 293078.

from mojobpf.packet import (
    XDP_DROP,
    XDP_PASS,
    XdpCtx,
    load_u8,
    packet_addr,
    packet_base,
    packet_short,
)


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 52):
        return Int32(XDP_PASS)
    var base = packet_base(packet_addr(pkt, 0))
    var score = UInt64(0)
    var a = UInt64(load_u8(base, 14))
    var b = UInt64(load_u8(base, 15))
    if a == b:
        score += 1
    var c = UInt64(load_u8(base, 16))
    var d = UInt64(load_u8(base, 17))
    if c != d:
        score += 2
    var e = UInt64(load_u8(base, 18))
    var f = UInt64(load_u8(base, 19))
    if e > f:
        score += 4
    var g = UInt64(load_u8(base, 20))
    var h = UInt64(load_u8(base, 21))
    if g >= h:
        score += 8
    var i = UInt64(load_u8(base, 22))
    var j = UInt64(load_u8(base, 23))
    if i < j:
        score += 16
    var k = UInt64(load_u8(base, 24))
    var l = UInt64(load_u8(base, 25))
    if k <= l:
        score += 32
    var m = Int64(load_u8(base, 26)) - Int64(1)
    var n = Int64(load_u8(base, 27)) - Int64(1)
    if m > n:
        score += 64
    var o = Int64(load_u8(base, 28)) - Int64(1)
    var p = Int64(load_u8(base, 29)) - Int64(1)
    if o < p:
        score += 128
    var q = Int64(load_u8(base, 30)) - Int64(1)
    var r = Int64(load_u8(base, 31)) - Int64(1)
    if q >= r:
        score += 256
    var s = Int64(load_u8(base, 32)) - Int64(1)
    var t = Int64(load_u8(base, 33)) - Int64(1)
    if s <= t:
        score += 512
    var u = UInt32(load_u8(base, 34))
    var v = UInt32(load_u8(base, 35))
    if u == v:
        score += 1024
    var w = UInt32(load_u8(base, 36))
    var x = UInt32(load_u8(base, 37))
    if w < x:
        score += 2048
    var y = UInt32(load_u8(base, 38))
    if y > UInt32(10):
        score += 4096
    var z = UInt64(load_u8(base, 40))
    if z == UInt64(7):
        score += 8192
    var aa = UInt64(load_u8(base, 42))
    if aa > UInt64(100):
        score += 16384
    var ab = Int64(load_u8(base, 44)) - Int64(1)
    if ab < Int64(0):
        score += 32768
    var ac = UInt64(load_u8(base, 46))
    var ad = UInt64(load_u8(base, 47))
    if ac == ad:
        score += 65536
    var ae = UInt64(load_u8(base, 48))
    if ae != UInt64(9):
        score += 131072
    var af = UInt64(load_u8(base, 49))
    var ag = UInt64(load_u8(base, 50))
    if af != ag:
        score += 262144
    var ah = UInt32(load_u8(base, 51))
    if ah != UInt32(5):
        score += 524288
    if score == UInt64(755496):
        return Int32(XDP_PASS)
    if score == UInt64(293078):
        return Int32(XDP_DROP)
    return Int32(0)
