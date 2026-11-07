# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/alu/logic64 single-constant mutant: the s shift count 1
# becomes 5, so the chain evaluates to s=7680, u=7710, sv=7610,
# ar=1902 and the gate (1902 + 240 - 335 = 1807) opens: XDP_DROP
# (1). Every other byte matches logic64_minimal.mojo.

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
    var s = k2 << 5
    var t = x >> 3
    var u = s + t
    var sv = Int64(u) - 100
    var ar = sv >> 2
    var gate = ar + Int64(k) - 335
    if gate > 10:
        return Int32(1)
    return Int32(2)
