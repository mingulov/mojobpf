# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Single-constant mutant of v3_minimal.mojo: the packet-byte bias 17
# opens the gate, so one execution observes XDP_DROP (1) instead of
# XDP_PASS (2). The stale-object leg runs base.bpf.o against the
# mutant expectation.

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
    var gate: Int32 = Int32(eth_last) + 17
    if gate > 10:
        return Int32(1)
    return Int32(acc - 40)
