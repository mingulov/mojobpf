# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# F-ISA/alu/arith64 single-constant mutant: the +50 seed becomes
# +500, so the chain evaluates to q=23, r=1 and the gate (24 + 7)
# opens: XDP_DROP (1). Every other byte matches alu64_minimal.mojo.

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
    var wide = UInt64(eth_last) + 500
    wide = wide - 7
    wide = wide * 2
    var q = wide / 42
    var r = wide % 5
    var n = UInt64(0) - q
    var gate: Int32 = Int32(n + q + q + r) + 7
    if gate > 10:
        return Int32(1)
    return Int32(2)
