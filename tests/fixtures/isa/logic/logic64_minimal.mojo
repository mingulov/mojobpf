# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/alu/logic64 qualification fixture: 64-bit or/xor/and/lsh/
# rsh/arsh over two packet bytes, no maps. The lanes start WIDE
# (low byte plus the other byte shifted to bits 32-39, so high bits
# are genuinely unknown): a middle chain over narrow values would be
# narrowed to 32-bit selection by the backend, and saturating `| 255`
# on a byte is constant and would collapse the chain. On the zero
# packet all wide bits are clear and the chain evaluates to x0=7,
# x=240, y=15, m=255, n=248, k=240, k2=240, s=480, t=30, u=510,
# sv=410, ar=102 and the gate (102 + 240 - 335 = 7) stays shut:
# XDP_PASS (2). The parsed lowering must admit it under cpu=v3.
# The k2 mask (0x1000000F3) keeps bit 32 live to the gate so the
# middle logic selects 64-bit forms instead of narrowing.

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
    if UInt64(data) + 16 > UInt64(data_end):
        return Int32(2)
    var pkt = inlined_assembly[
        "", MutPointer[UInt8, MutAnyOrigin], constraints="=r,0", has_side_effect=False
    ](Int(data))
    var a = UInt64(pkt[unsafe_offset=14]) | (UInt64(pkt[unsafe_offset=15]) << 32)
    var c = UInt64(pkt[unsafe_offset=15]) | (UInt64(pkt[unsafe_offset=14]) << 32)
    var x0 = a | 7
    var x = x0 ^ 247
    var y = c ^ 15
    var m = x | y
    var n = m ^ (a + 7)
    var k = n & 243
    var k2 = n & 4294967539
    var s = k2 << 1
    var t = x >> 3
    var u = s + t
    var sv = Int64(u) - 100
    var ar = sv >> 2
    var gate = ar + Int64(k) - 335
    if gate > 10:
        return Int32(1)
    return Int32(2)
