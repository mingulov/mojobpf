<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# TC classifier example

`tc.mojo` is a Mojo-authored TC classifier program. It reads the
kernel TC context (`struct __sk_buff` `data`/`data_end` words),
guards the load with an explicit 15-byte length check, and returns
an action code:

| input                                   | result           |
| --------------------------------------- | ---------------- |
| frame >= 15 bytes, bit 0 of byte 14 set | `2` (`TC_ACT_SHOT`) |
| anything else (clear bit, short frame)  | `0` (`TC_ACT_OK`)   |

The bounds check is explicit: frames shorter than 15 bytes return `0`
without touching packet bytes. Short frames are ordinary traffic
under this rule, so the short-input action passes, mirroring the
packet classifier's documented short-input convention rather than
the SDK's fail-closed guard idiom.

## Build

From the repository root, with the project Mojo environment active so
that `mojo` resolves:

```bash
mkdir -p out
mojo build --emit llvm \
    --target-cpu znver4 \
    --target-features +adx,+aes,+avx,+avx2,+avx512bf16,+avx512bitalg,+avx512bw,+avx512cd,+avx512dq,+avx512f,+avx512ifma,+avx512vbmi,+avx512vbmi2,+avx512vl,+avx512vnni,+avx512vpopcntdq,+bmi,+bmi2,+clflushopt,+clwb,+clzero,+crc32,+cx16,+cx8,+f16c,+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,+mmx,+movbe,+mwaitx,+pclmul,+pku,+popcnt,+prfchw,+rdpid,+rdpru,+rdrnd,+rdseed,+sahf,+sha,+shstk,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+sse4a,+ssse3,+vaes,+vpclmulqdq,+wbnoinvd,+x87,+xsave,+xsavec,+xsaveopt,+xsaves \
    -I src/mojobpf/resources/sdk \
    -o out/tc.ll examples/tc_classifier/tc.mojo
python3 compiler/mojo_ir_adapter.py --input out/tc.ll \
    --output out/tc.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/tc.bpf.ll \
    -o out/tc.bpf.o
```

The `--target-cpu`/`--target-features` pair pins the frontend to
the frozen producer shape the exact-match adapter expects (the
same flags the `mojobpf build` route passes); without it the
frontend emits the build machine's CPU and the adapter refuses
the IR.

The adapter only retargets module metadata (triple, data layout, the
`classifier` section, the license note, entrypoint codegen
attributes); every body instruction in the adapted IR is byte-identical
to the frontend output. The resulting object loads with unmodified
libbpf/bpftool.
