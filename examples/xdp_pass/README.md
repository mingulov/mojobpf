<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# XDP classifier example

`xdp_pass.mojo` is a Mojo-authored XDP program. It reads the kernel XDP
context (packet `data`/`data_end` offsets) and returns an action code:

| input                                   | result              |
| --------------------------------------- | ------------------- |
| frame >= 15 bytes, bit 0 of byte 14 set | `1` (`XDP_DROP`)    |
| anything else (clear bit, short frame)  | `2` (`XDP_PASS`)    |

The bounds check is explicit: frames shorter than 15 bytes return `2`
without touching packet bytes. `xdp_pass_mutated.mojo` is identical except
that the bit test is inverted (drops when the bit is clear), so the two
fixtures below swap their expected actions; it exists for behavior-change
proofs.

## Build

From the repository root, with the project Mojo environment active so that
`mojo` resolves:

```bash
mkdir -p out
mojo build --emit llvm \
    --target-cpu znver4 \
    --target-features +adx,+aes,+avx,+avx2,+avx512bf16,+avx512bitalg,+avx512bw,+avx512cd,+avx512dq,+avx512f,+avx512ifma,+avx512vbmi,+avx512vbmi2,+avx512vl,+avx512vnni,+avx512vpopcntdq,+bmi,+bmi2,+clflushopt,+clwb,+clzero,+crc32,+cx16,+cx8,+f16c,+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,+mmx,+movbe,+mwaitx,+pclmul,+pku,+popcnt,+prfchw,+rdpid,+rdpru,+rdrnd,+rdseed,+sahf,+sha,+shstk,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+sse4a,+ssse3,+vaes,+vpclmulqdq,+wbnoinvd,+x87,+xsave,+xsavec,+xsaveopt,+xsaves \
    -o out/xdp_pass.ll examples/xdp_pass/xdp_pass.mojo
python3 compiler/mojo_ir_adapter.py --input out/xdp_pass.ll \
    --output out/xdp_pass.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/xdp_pass.bpf.ll \
    -o out/xdp_pass.bpf.o
```

The `--target-cpu`/`--target-features` pair pins the frontend to
the frozen producer shape the exact-match adapter expects (the
same flags the `mojobpf build` route passes); without it the
frontend emits the build machine's CPU and the adapter refuses
the IR.

The adapter only retargets module metadata (triple, data layout, the `xdp`
section, the license note, entrypoint codegen attributes); every body
instruction in the adapted IR is byte-identical to the frontend output.
The resulting object loads with unmodified libbpf/bpftool.

## Fixtures

| file            | bytes | byte 14 | base action | mutated action |
| --------------- | ----- | ------- | ----------- | -------------- |
| `pkt_drop.bin`  | 60    | `0x01`  | `1`         | `2`            |
| `pkt_pass.bin`  | 60    | `0x00`  | `2`         | `1`            |
| `pkt_short.bin` | 10    | n/a     | `2`         | `2`            |

All other bytes are zero. Feed a fixture to the kernel test-run entry with
`--data-in`; never rely on the harness default input for this program.
