# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Joint-stack driver: drive a MojoBPF-built object via libbpf-mojo.

Usage: joint_driver <object.o> <libbpf_mojo.so> <map-name> <prog-name>
       <data.bin>

Opens the ELF bytes through the independent libbpf-mojo consumer
(explicit library path: the guest runs privileged, so ``open`` would
refuse EPERM), loads it, initializes key 0 to 41 from userspace,
executes one kernel test-run, and reads key 0 back. Prints one JSON
line: {"retval", "before", "after", "lib_path"}. Any loader, map, or
test-run failure exits nonzero with the library error on stderr.

Built host-side by tests/kernel/test_joint_stack.py with the pinned
Mojo against the read-only libbpf-mojo sources; runs in the disposable
joint-lane guest. The staged ``libbpf_mojo.so`` bytes are hashed by
the suite's staged-hashes line (attested), not self-reported here.
"""
from std.pathlib import Path
from std.sys import argv
from libbpf_mojo.object import Object
from libbpf_mojo.maps import lookup_u64, update_u64
from libbpf_mojo.program import test_run


def main() raises:
    var args = argv()
    if len(args) != 6:
        raise Error(
            "usage: joint_driver"
            " <object.o> <lib.so> <map> <prog> <data.bin>"
        )
    var elf = Path(args[1]).read_bytes()
    var packet = Path(args[5]).read_bytes()
    var obj = Object.open_with_lib(Span(elf), args[2])
    obj.load()
    var view = obj.map(args[3])
    update_u64(view, UInt32(0), UInt64(41))
    var before = lookup_u64(view, UInt32(0))
    var prog = obj.program(args[4])
    var context = List[UInt8]()
    var packet_out = List[UInt8](length=128, fill=0)
    var context_out = List[UInt8]()
    var result = test_run(
        prog,
        Span(packet),
        Span(context),
        Span(packet_out),
        Span(context_out),
        UInt64(1),
    )
    var after = lookup_u64(view, UInt32(0))
    var retval = result.retval
    view.close()
    prog.close()
    obj.close()
    print(
        '{"retval": '
        + String(retval)
        + ', "before": '
        + String(before)
        + ', "after": '
        + String(after)
        + ', "lib_path": "'
        + args[2]
        + '"}'
    )
