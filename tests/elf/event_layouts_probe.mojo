# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Layout probe for the SDK event record struct.
#
# Built for the host (never for BPF) and run by the event
# structure suite. Prints the struct's size, alignment, and a
# byte-by-byte dump of a known value; the suite compares all
# three against the C reference struct, the ABI record, and the
# encoder's IR store offsets. Any hidden padding, reordered
# field, or byte-order surprise fails that suite.

from std.sys.info import align_of, size_of

from mojobpf.events import EventRecord


def main():
    var rec = EventRecord(
        UInt16(1),
        UInt16(32),
        UInt32(0x11111111),
        UInt32(0x22222222),
        UInt32(0x33333333),
        UInt64(0x4444444444444444),
        UInt64(0x5555555555555555),
    )
    print("SIZE event_record", size_of[EventRecord]())
    print("ALIGN event_record", align_of[EventRecord]())
    var ptr = Pointer(to=rec).unsafe_bitcast[UInt8]()
    var line = String("EDUMP event_record")
    for i in range(32):
        line += " " + String(Int(ptr[unsafe_offset=i]))
    print(line)
