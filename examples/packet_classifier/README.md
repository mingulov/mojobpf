<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Packet classifier example

`classifier.mojo` is a Mojo-authored XDP program built on the packet
SDK. It reads the kernel XDP context (packet `data`/`data_end`
offsets), guards the load with an explicit 15-byte length check, and
returns an action code:

| input                                   | result              |
| --------------------------------------- | ------------------- |
| frame >= 15 bytes, bit 0 of byte 14 set | `1` (`XDP_DROP`)    |
| anything else (clear bit, short frame)  | `2` (`XDP_PASS`)    |

The bounds check is explicit: frames shorter than 15 bytes return `2`
without touching packet bytes. Short frames are ordinary traffic
under this rule, so the short-input action is `XDP_PASS`, not the
SDK's fail-closed guard idiom. `classifier_mutated.mojo` is identical
except that the bit test is inverted (drops when the bit is clear), so
the corpus expectations below flip on every frame of at least 15
bytes; it exists for behavior-change proofs.

## Build

From the repository root, with the project Mojo environment active so
that `mojo` resolves:

```bash
mkdir -p out
mojo build --emit llvm \
    --target-cpu znver4 \
    --target-features +adx,+aes,+avx,+avx2,+avx512bf16,+avx512bitalg,+avx512bw,+avx512cd,+avx512dq,+avx512f,+avx512ifma,+avx512vbmi,+avx512vbmi2,+avx512vl,+avx512vnni,+avx512vpopcntdq,+bmi,+bmi2,+clflushopt,+clwb,+clzero,+crc32,+cx16,+cx8,+f16c,+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,+mmx,+movbe,+mwaitx,+pclmul,+pku,+popcnt,+prfchw,+rdpid,+rdpru,+rdrnd,+rdseed,+sahf,+sha,+shstk,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+sse4a,+ssse3,+vaes,+vpclmulqdq,+wbnoinvd,+x87,+xsave,+xsavec,+xsaveopt,+xsaves \
    -I src/mojobpf/resources/sdk \
    -o out/classifier.ll examples/packet_classifier/classifier.mojo
python3 compiler/mojo_ir_adapter.py --input out/classifier.ll \
    --output out/classifier.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/classifier.bpf.ll \
    -o out/classifier.bpf.o
```

The `--target-cpu`/`--target-features` pair pins the frontend to
the frozen producer shape the exact-match adapter expects (the
same flags the `mojobpf build` route passes); without it the
frontend emits the build machine's CPU and the adapter refuses
the IR.

The adapter only retargets module metadata (triple, data layout, the
`xdp` section, the license note, entrypoint codegen attributes); every
body instruction in the adapted IR is byte-identical to the frontend
output. The resulting object loads with unmodified libbpf/bpftool.

## Corpus

`corpus/` holds the 33-frame packet corpus the differential and
kernel suites run: lengths 14, 15, 18, 30, 64, 127, 128, 512 and 1500
bytes, a fixed Ethernet header (locally-administered unicast
addresses, IPv4 ethertype), byte 14 varied across 0, 1, 2 and 255 for
every length above 14, and the 14-byte header-only frame once. All
other payload bytes are zero. `corpus/manifest.json` records the rule,
the header, and the independent expected action plus the SHA-256 of
every frame: 33 invocations, 16 drops, 17 passes, 9,590 bytes total.
