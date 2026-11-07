# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/alu/arith64 qualification fixture: 64-bit add/sub/mul/udiv/
# urem/neg over a packet byte, no maps. The parsed lowering must
# admit it under cpu=v3. On the zero packet the chain evaluates to
# q=2, r=1 and the gate (3 + 7 = 10) stays shut: XDP_PASS (2).

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
    var eth_last = pkt[unsafe_offset=14]
    var wide = UInt64(eth_last) + 50
    wide = wide - 7
    wide = wide * 2
    var q = wide / 42
    var r = wide % 5
    var n = UInt64(0) - q
    var gate: Int32 = Int32(n + q + q + r) + 7
    if gate > 10:
        return Int32(1)
    return Int32(2)
