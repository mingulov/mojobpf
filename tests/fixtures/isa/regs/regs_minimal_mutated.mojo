# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/registers/v3 qualification fixture: entry computes 7 values
# from packet bytes, calls an @export helper (r1 argument, r0
# return), and sums everything into the gate. Six values stay live
# across the call, forcing r6-r9 callee-saved moves plus r10 frame
# spills. The helper needs @export (plain dso_local symbol) and
# @inline(.never) (a real call); mangled or inlined helpers would
# not exercise the call roles. On the zero packet v = (0 + 100) //
# 42 + 7 = 9 and the gate (9 + 0 = 9) stays shut: XDP_PASS (2).
# The parsed lowering must admit it under cpu=v3 with the
# linux-bpfel-v3-subprog profile. The mutant changes +7 to +17.

from std.sys import inlined_assembly


@fieldwise_init
struct XdpMd(ImplicitlyCopyable):
    var data: UInt32
    var data_end: UInt32


@export
@inline(.never)
def helper(n: UInt64) abi("C") -> UInt64:
    return (n // 42) + 17


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
    var f = UInt64(pkt[unsafe_offset=19])
    var g = UInt64(pkt[unsafe_offset=20])
    var v = helper(a + 100)
    var gate = v + b + c + d + e + f + g
    if gate > 10:
        return Int32(1)
    return Int32(2)
