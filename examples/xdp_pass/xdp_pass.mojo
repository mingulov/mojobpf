# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# XDP packet classifier written in Mojo.
#
# Behavior: drop the packet (return 1, XDP_DROP) when the frame holds at
# least 15 bytes and bit 0 of byte 14 is set; pass it (return 2, XDP_PASS)
# otherwise. Short frames take the pass path through the explicit bounds
# check. The context argument is the kernel XDP metadata (data and data_end
# packet offsets as two little-endian u32 words); the program reads both
# words and one packet byte, then returns the action code.
#
# The module uses no main function, printing, heap allocation, Python
# interop, exceptions, or runtime init. It exposes exactly one C-ABI entry
# point returning a 32-bit action code for a context pointer.

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
        "", MutPointer[UInt8, MutAnyOrigin], constraints="=r,r", has_side_effect=False
    ](Int(data))
    var eth_last = pkt[unsafe_offset=14]
    if (eth_last & 1) == 1:
        return Int32(1)
    return Int32(2)
