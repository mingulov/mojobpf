# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Mutated XDP classifier: drops when bit 0 of byte 14 is CLEAR.
#
# This file is byte-identical to xdp_pass.mojo except for the bit-test
# comparison below (`== 1` became `== 0`). It exists so behavior tests can
# prove that a source change alters rebuilt kernel behavior: with this
# mutation, the drop fixture passes and the pass fixture drops, while the
# object built from the unmutated source fails the new expectations.

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
    # Reinterpret the loaded data address as a byte pointer. The empty
    # assembly template with register-only constraints is a pure register
    # reinterpretation: it emits no instructions of its own and keeps the
    # verifier-visible packet-pointer arithmetic (base plus constant offset)
    # intact for the bounds-checked load below.
    var pkt = inlined_assembly[
        "", MutPointer[UInt8, MutAnyOrigin], constraints="=r,0", has_side_effect=False
    ](Int(data))
    var eth_last = pkt[unsafe_offset=14]
    if (eth_last & 1) == 0:
        return Int32(1)
    return Int32(2)
