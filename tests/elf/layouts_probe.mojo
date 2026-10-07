# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Host-side layout probe for the SDK value types.
#
# This program runs on the build host (plain `mojo build`, native
# target), never in the kernel: it prints the compiler-reported
# sizes and alignments of the SDK integer, packet-handle, and
# cursor types, plus byte dumps of known struct values. The ABI
# layout suite compares these facts against the independent C
# layout fixture and the LLVM type layouts. The dumps pin field
# order, offsets, and byte order: every dumped byte is predicted,
# so hidden padding or a reordered field fails the suite.
#
# Like the differential probe, this is host-side test glue using
# heap scratch buffers, not kernel code.

from std.memory import Layout, alloc
from std.sys.info import align_of, size_of
from mojobpf.events import EventRecord
from mojobpf.packet import Cursor, XdpCtx, packet_base


def main():
    print("SIZE u8", size_of[UInt8]())
    print("SIZE u16", size_of[UInt16]())
    print("SIZE u32", size_of[UInt32]())
    print("SIZE u64", size_of[UInt64]())
    print("SIZE i32", size_of[Int32]())
    print("SIZE i64", size_of[Int64]())
    print("SIZE int", size_of[Int]())
    print("ALIGN u8", align_of[UInt8]())
    print("ALIGN u16", align_of[UInt16]())
    print("ALIGN u32", align_of[UInt32]())
    print("ALIGN u64", align_of[UInt64]())
    print("ALIGN i32", align_of[Int32]())
    print("ALIGN i64", align_of[Int64]())
    print("ALIGN int", align_of[Int]())
    print("SIZE xdp_ctx", size_of[XdpCtx]())
    print("ALIGN xdp_ctx", align_of[XdpCtx]())
    print("SIZE cursor", size_of[Cursor[O = MutAnyOrigin]]())
    print("ALIGN cursor", align_of[Cursor[O = MutAnyOrigin]]())
    print("SIZE event_record", size_of[EventRecord]())
    print("ALIGN event_record", align_of[EventRecord]())

    var slot = alloc(Layout[XdpCtx](count=1))
    var ptr = slot^.unsafe_leak()
    ptr.unsafe_write(
        XdpCtx(UInt32(0x04030201), UInt32(0x08070605), UInt32(0x0C0B0A09))
    )
    var bytes = ptr.unsafe_bitcast[UInt8]()
    print("XDUMP", end="")
    for i in range(size_of[XdpCtx]()):
        print("", bytes.unsafe_offset(i).unsafe_load(), end="")
    print("")

    var buf = alloc(Layout[UInt8](count=8))
    var raw = buf^.unsafe_leak()
    var cursor = Cursor(packet_base(UInt64(Int(raw))), 0x0807060504030201)
    var cslot = alloc(Layout[Cursor[O = MutAnyOrigin]](count=1))
    var cptr = cslot^.unsafe_leak()
    cptr.unsafe_write(cursor)
    var cbytes = cptr.unsafe_bitcast[UInt8]()
    print("CDUMP", end="")
    for i in range(size_of[Cursor[O = MutAnyOrigin]]()):
        print("", cbytes.unsafe_offset(i).unsafe_load(), end="")
    print("")
    print("CADDR", Int(raw))
