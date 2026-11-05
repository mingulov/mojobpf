<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Socket classifier example

`socket.mojo` is a Mojo-authored socket-filter program. It reads the
kernel socket-filter context (`struct __sk_buff` `data`/`data_end`
words), guards the load with an explicit 15-byte length check, and
returns a verdict:

| input                                   | result   |
| --------------------------------------- | -------- |
| frame >= 15 bytes, bit 0 of byte 14 set | `0`      |
| anything else (clear bit, short frame)  | `64`     |

The bounds check is explicit: frames shorter than 15 bytes return `64`
without touching packet bytes. Short frames are ordinary traffic
under this rule, so the short-input action passes, mirroring the
packet classifier's documented short-input convention rather than
the SDK's fail-closed guard idiom.

## Build

From the repository root, with the project Mojo environment active so
that `mojo` resolves:

```bash
mojo build --emit llvm -I src/mojobpf/resources/sdk \
    -o out/socket.ll examples/socket_classifier/socket.mojo
python3 compiler/mojo_ir_adapter.py --input out/socket.ll \
    --output out/socket.bpf.ll
llc -mtriple=bpfel -mcpu=v3 -filetype=obj out/socket.bpf.ll \
    -o out/socket.bpf.o
```

The adapter only retargets module metadata (triple, data layout, the
`socket` section, the license note, entrypoint codegen attributes);
every body instruction in the adapted IR is byte-identical to the
frontend output. The resulting object is a standard BPF relocatable.

Note: the socket-filter verifier rejects direct context reads, so
this direct-reads revision builds and verifies structurally but is
not the executed form. The executed socket classifier reads the
packet through the `skb_load_bytes` helper instead; that revision
is proven in-guest separately. The TC classifier in this
repository demonstrates the same byte-14 rule end to end with
direct reads, which its program type admits.
