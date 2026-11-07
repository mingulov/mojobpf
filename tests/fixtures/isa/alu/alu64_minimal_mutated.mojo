# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/alu/arith64 single-constant mutant: the +50 seed becomes
# +500, so the chain evaluates to q=11, t=5 and the gate
# (5 + 11 + 0 + 7 = 23) opens: XDP_DROP (1). Every other byte
# matches alu64_minimal.mojo.

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
    if UInt64(data) + 15 > UInt64(data_end):
        return Int32(2)
    var pkt = inlined_assembly[
        "", MutPointer[UInt8, MutAnyOrigin], constraints="=r,0", has_side_effect=False
    ](Int(data))
    var a = UInt64(pkt[unsafe_offset=14])
    var m = a * 3
    var d = (a + 500) - m
    var q = d / 42
    var r = d % 5
    var n = UInt64(0) - q
    var t = n % 7
    var gate64 = t + q + r + 7
    if gate64 > 10:
        return Int32(1)
    return Int32(2)
