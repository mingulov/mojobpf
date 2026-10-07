# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# case: bad-helper
# Negative: unqualified helper invoked through inline assembly.
from std.sys import inlined_assembly
from mojobpf.packet import GUARD_ACTION, XDP_DROP, XDP_PASS, XdpCtx, packet_short


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var pkt = XdpCtx.from_ctx(ctx)
    if packet_short(pkt, 15):
        return Int32(GUARD_ACTION)
    var now = inlined_assembly[
        "call 9",
        Int64,
        constraints="={r0}",
        has_side_effect=True,
    ]()
    if now == 0:
        return Int32(XDP_DROP)
    return Int32(XDP_PASS)
