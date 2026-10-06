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
mojo build --emit llvm -o out/xdp_pass.ll examples/xdp_pass/xdp_pass.mojo
python3 compiler/mojo_ir_adapter.py --input out/xdp_pass.ll \
    --output out/xdp_pass.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/xdp_pass.bpf.ll \
    -o out/xdp_pass.bpf.o
```

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
