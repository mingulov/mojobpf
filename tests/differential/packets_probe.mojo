# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Host-side differential probe for the packet corpus.
#
# This program runs on the build host (plain `mojo build`, native
# target), never in the kernel: for each frame file named on its
# command line it loads the bytes into a heap scratch buffer,
# applies the genuine packet SDK loads plus the classifier rule,
# and prints one FRAME line with the action and the running
# invocation count and byte total. The Python differential suite
# predicts every line with mechanically distinct primitives (length
# comparison, modulo instead of masking, big-integer accumulation),
# so a shared misunderstanding cannot hide. In-kernel behavior of
# the same rule is proven separately by the kernel accounting
# suite; this probe covers the full corpus plus the seeded and
# minimized frames no single guest run enumerates cheaply.
#
# The probe uses heap scratch buffers for its inputs. That is
# ordinary host-side test glue, not kernel code: nothing here is
# subject to the kernel subset, and nothing here loads into BPF.
#
# Output protocol: one line per frame,
# `FRAME <name> <action> <count> <cumbytes>`, where count and
# cumbytes are the running totals after this frame. Any usage or
# read error raises, so the suite sees a nonzero exit, never a
# silent shortfall.

from std.memory import Layout, alloc
from std.pathlib import Path
from std.sys import argv

from mojobpf.packet import (
    XdpCtx,
    load_u8,
    packet_base,
    packet_len,
    packet_short,
)


def frame_action(path: String) raises -> Int:
    var data = Path(path).read_bytes()
    var length = len(data)
    var ctx = XdpCtx(UInt32(0), UInt32(length), UInt32(0))
    if packet_short(ctx, 15):
        return 2
    var buf = alloc(Layout[UInt8](count=length))
    var raw = buf^.unsafe_leak()
    for i in range(length):
        raw.unsafe_offset(i).unsafe_write(data[i])
    var base = packet_base(UInt64(Int(raw)))
    var eth_last = load_u8(base, 14)
    if (eth_last & 1) == 1:
        return 1
    return 2


def main() raises:
    var args = argv()
    if len(args) < 2:
        raise Error("usage: packets_probe <frame> [<frame> ...]")
    var count = 0
    var cumbytes = 0
    for i in range(1, len(args)):
        var path = args[i]
        var action = frame_action(path)
        count += 1
        cumbytes += len(Path(path).read_bytes())
        print("FRAME", path, action, count, cumbytes)
