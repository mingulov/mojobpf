# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/alu/alu32 qualification fixture: 32-bit add/sub/mul/div/mod/
# and/or/xor/neg/lsh/rsh/arsh over packet bytes, plus u16/u8
# division legs, no maps. Every op works on loaded bytes so nothing
# folds: `s` xors (not ors) with 15 because r is in [0,6] and r|15
# would be the constant 15, killing the div/mod/mul chain; `v`
# keeps u alive through two shifts. On the zero packet the chain
# evaluates to a=0, c=0, x0=7, x=240, y=15, m=255, n=248, k=240,
# p=100, d=100, q=2, r=2, s=29, t=237, u=1896, v=63, w16=0, w8=0,
# ng=-63, ar=2 and the gate (3 + 2 + 0 + 0 = 5) stays shut:
# XDP_PASS (2). The parsed lowering must admit it under cpu=v3
# (checked 32/16/8-bit division). The mutant changes +18 to +28.

from std.sys import inlined_assembly


@fieldwise_init
struct XdpMd(ImplicitlyCopyable):
    var data: UInt32
    var data_end: UInt32


@export
def xdp_entry(ctx: MutPointer[XdpMd, MutAnyOrigin]) abi("C") -> Int32:
    var words = ctx.unsafe_bitcast[UInt32]()
    var data = words[unsafe_offset=0]
    var data_end = words[unsafe_offset=1]
    if UInt64(data) + 24 > UInt64(data_end):
        return Int32(2)
    var pkt = inlined_assembly[
        "", MutPointer[UInt8, MutAnyOrigin], constraints="=r,0", has_side_effect=False
    ](Int(data))
    var a = UInt32(pkt[unsafe_offset=14]) | (UInt32(pkt[unsafe_offset=15]) << 16)
    var c = UInt32(pkt[unsafe_offset=15]) | (UInt32(pkt[unsafe_offset=14]) << 16)
    var x0 = a | 7
    var x = x0 ^ 247
    var y = c ^ 15
    var m = x | y
    var n = m ^ (a + 7)
    var k = n & 243
    var p = a * c + 100
    var d = p - UInt32(pkt[unsafe_offset=16])
    var q = d // 42
    var r = q % 7
    var s = ((r ^ 15) | 16) & 255
    var t = (s ^ k) & m
    var u = t << 3
    var v = (u >> 5) + ((u >> 1) & 7)
    var w16 = (UInt16(pkt[unsafe_offset=17]) + UInt16(pkt[unsafe_offset=18])) // 42
    var w8 = (UInt8(pkt[unsafe_offset=19]) + UInt8(pkt[unsafe_offset=20])) % 7
    var ng = Int32(0) - Int32(v)
    var ar = (ng >> 2) + 28
    var gate = (k >> 6) + UInt32(ar) + UInt32(w16) + UInt32(w8)
    if gate > 10:
        return Int32(1)
    return Int32(2)
