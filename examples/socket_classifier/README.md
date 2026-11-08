<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Socket classifier example

`socket.mojo` is a Mojo-authored socket-filter program. Classic
socket filters cannot read the kernel socket-filter context
(`struct __sk_buff` `data`/`data_end` words) directly — the
verifier rejects those context offsets for this program type —
so the program reads the packet through the `skb_load_bytes`
helper into an initialized key slot and returns a verdict:

| input                                   | result   |
| --------------------------------------- | -------- |
| frame >= 15 bytes, bit 0 of byte 14 set | `0`      |
| anything else (clear bit, short frame)  | `64`     |

Short frames take the pass path through the helper status:
`skb_load_bytes` fails closed on overrun, and the program
returns `64` on any nonzero status. Short frames are ordinary
traffic under this rule, so the short-input action passes,
mirroring the packet classifier's documented short-input
convention rather than the SDK's fail-closed guard idiom.

## Build

From the repository root, with the project Mojo environment active so
that `mojo` resolves:

```bash
mkdir -p out
mojo build --emit llvm \
    --target-cpu znver4 \
    --target-features +adx,+aes,+avx,+avx2,+avx512bf16,+avx512bitalg,+avx512bw,+avx512cd,+avx512dq,+avx512f,+avx512ifma,+avx512vbmi,+avx512vbmi2,+avx512vl,+avx512vnni,+avx512vpopcntdq,+bmi,+bmi2,+clflushopt,+clwb,+clzero,+crc32,+cx16,+cx8,+f16c,+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,+mmx,+movbe,+mwaitx,+pclmul,+pku,+popcnt,+prfchw,+rdpid,+rdpru,+rdrnd,+rdseed,+sahf,+sha,+shstk,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+sse4a,+ssse3,+vaes,+vpclmulqdq,+wbnoinvd,+x87,+xsave,+xsavec,+xsaveopt,+xsaves \
    -I src/mojobpf/resources/sdk \
    -o out/socket.ll examples/socket_classifier/socket.mojo
python3 compiler/mojo_ir_adapter.py --input out/socket.ll \
    --output out/socket.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/socket.bpf.ll \
    -o out/socket.bpf.o
```

The `--target-cpu`/`--target-features` pair pins the frontend to
the frozen producer shape the exact-match adapter expects (the
same flags the `mojobpf build` route passes); without it the
frontend emits the build machine's CPU and the adapter refuses
the IR.

The adapter substitutes the one helper call with its kernel
helper ID and retargets module metadata (triple, data layout,
the `socket` section, the license note, entrypoint codegen
attributes); every other body instruction in the adapted IR is
byte-identical to the frontend output. The resulting object is
a standard BPF relocatable.
