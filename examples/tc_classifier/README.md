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
mojo build --emit llvm -I src/mojobpf/resources/sdk \
    -o out/tc.ll examples/tc_classifier/tc.mojo
python3 compiler/mojo_ir_adapter.py --input out/tc.ll \
    --output out/tc.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/tc.bpf.ll \
    -o out/tc.bpf.o
```

The adapter only retargets module metadata (triple, data layout, the
`classifier` section, the license note, entrypoint codegen
attributes); every body instruction in the adapted IR is byte-identical
to the frontend output. The resulting object loads with unmodified
libbpf/bpftool.
