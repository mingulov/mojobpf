# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Native layout/arithmetic control; this program never executes in BPF.

from std.memory import Layout, alloc, dealloc
from std.sys.info import align_of, size_of


@fieldwise_init
struct ContextPrefix(ImplicitlyCopyable):
    var data: UInt32
    var data_end: UInt32


@export
def scalar_wrap(value: UInt64) abi("C") -> UInt64:
    return value + 1


@export
def scalar_narrow(value: UInt64) abi("C") -> UInt8:
    return UInt8(value)


@export
def scalar_zero_extend(value: UInt8) abi("C") -> UInt64:
    return UInt64(value)


@export
def scalar_sign_extend(value: Int8) abi("C") -> UInt64:
    return UInt64(Int64(value))


def run_native_control():
    print("WIDTHS", size_of[Int]() * 8, size_of[UInt]() * 8,
          size_of[Int8]() * 8, size_of[UInt8]() * 8,
          size_of[Int16]() * 8, size_of[UInt16]() * 8,
          size_of[Int32]() * 8, size_of[UInt32]() * 8,
          size_of[Int64]() * 8, size_of[UInt64]() * 8)
    var allocation = alloc(Layout[ContextPrefix](count=1))
    var ptr = allocation.unsafe_ptr()
    ptr.unsafe_write(ContextPrefix(0x04030201, 0x08070605))
    var bytes = ptr.unsafe_bitcast[UInt8]()
    print("PREFIX", size_of[ContextPrefix](), align_of[ContextPrefix](),
          0, size_of[UInt32](), end="")
    for i in range(size_of[ContextPrefix]()):
        print("", bytes.unsafe_offset(i).unsafe_load(), end="")
    print("")
    dealloc(allocation^)
    var maximum = UInt64(0xFFFFFFFFFFFFFFFF)
    print("CASTS", scalar_narrow(maximum), UInt16(maximum), UInt32(maximum),
          maximum, Int8(-128), Int16(-32768), Int32(-2147483648),
          Int64(-9223372036854775808))
    print("WRAP", scalar_wrap(maximum), scalar_wrap(0),
          scalar_wrap(0x8000000000000000), scalar_wrap(maximum - 1))
    print("EXTEND", scalar_zero_extend(255), scalar_sign_extend(-1))
    print("NARROW", scalar_narrow(0), scalar_narrow(0x8000000000000000),
          scalar_narrow(maximum))
    print("EXTEND_BOUNDARY", scalar_zero_extend(0), scalar_zero_extend(128),
          scalar_zero_extend(255), scalar_sign_extend(0),
          scalar_sign_extend(127), scalar_sign_extend(-128))
