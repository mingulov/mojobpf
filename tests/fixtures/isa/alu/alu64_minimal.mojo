# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/alu/arith64 qualification fixture: 64-bit mul/sub/udiv/
# urem/neg/add over a packet byte, no maps. Every op takes a
# packet-derived operand so no step folds away: on the zero packet
# the chain evaluates to m=0, d=50, q=1, r=0, n=-1, t=1 and the
# gate (1 + 1 + 0 + 7 = 9) stays shut: XDP_PASS (2). The parsed
# lowering must admit it under cpu=v3.

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
    var d = (a + 50) - m
    var q = d / 42
    var r = d % 5
    var n = UInt64(0) - q
    var t = n % 7
    var gate64 = t + q + r + 7
    if gate64 > 10:
        return Int32(1)
    return Int32(2)
