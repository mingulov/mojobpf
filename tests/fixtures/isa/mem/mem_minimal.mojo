# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/mem/load-store qualification fixture: packet byte loads,
# u16 arithmetic legs, a sign-extension leg, a wide ld_imm64 mask,
# and an @export helper call forcing r10 spills, no maps. The mask
# input ((a << 32) | b) stays wide so range analysis cannot narrow
# the constant (a narrow input would fold the mask to 32 bits and
# lose the ld_imm64 pair). On the zero packet the chain evaluates
# to a=b=c=d=e=0, h=h2=h3=0, s=0, t=0, v = (0 + 100) // 42 + 7 = 9
# and the gate (9 + 0 = 9) stays shut: XDP_PASS (2). The parsed
# lowering must admit it under cpu=v3 with the
# linux-bpfel-v3-subprog profile. The mutant changes +7 to +17.

from std.sys import inlined_assembly


@fieldwise_init
struct XdpMd(ImplicitlyCopyable):
    var data: UInt32
    var data_end: UInt32


@export
@inline(.never)
def helper(n: UInt64) abi("C") -> UInt64:
    return (n // 42) + 7


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
    var a = UInt64(pkt[unsafe_offset=14])
    var b = UInt64(pkt[unsafe_offset=15])
    var c = UInt64(pkt[unsafe_offset=16])
    var d = UInt64(pkt[unsafe_offset=17])
    var e = UInt64(pkt[unsafe_offset=18])
    var h = (UInt16(pkt[unsafe_offset=19]) + UInt16(pkt[unsafe_offset=20])) // 42
    var s = Int64(Int8(pkt[unsafe_offset=21]))
    var h2 = (UInt16(pkt[unsafe_offset=22]) + UInt16(pkt[unsafe_offset=23])) // 7
    var h3 = h + h2
    var t = ((a << 32) | b) & 0x123456789ABCDEF
    var v = helper(a + 100)
    var gate = v + b + c + d + e + UInt64(h) + UInt64(h2) + UInt64(h3) + UInt64(s) + t
    if gate > 10:
        return Int32(1)
    return Int32(2)
