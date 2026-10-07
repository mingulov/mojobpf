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
mojo build --emit llvm -I src/mojobpf/resources/sdk \
    -o out/classifier.ll examples/packet_classifier/classifier.mojo
python3 compiler/mojo_ir_adapter.py --input out/classifier.ll \
    --output out/classifier.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/classifier.bpf.ll \
    -o out/classifier.bpf.o
```

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
