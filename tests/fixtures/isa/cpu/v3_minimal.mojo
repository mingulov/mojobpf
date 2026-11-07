# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Minimal v3 CPU-qualification fixture: 32-bit compare/branch on a
# packet byte plus 64-bit arithmetic, no maps. check-target must
# admit it under cpu=v3 and report the resolved isa_cpu facts.
# On the zero packet the gate stays shut and one execution observes
# XDP_PASS (2).

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
    var acc: Int64 = 41
    acc = acc + 1
    var gate: Int32 = Int32(eth_last) + 7
    if gate > 10:
        return Int32(1)
    return Int32(acc - 40)
