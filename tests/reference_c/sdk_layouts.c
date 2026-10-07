// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
/* Independent layout oracle for the SDK value types.
 *
 * This program mirrors the SDK integer, packet-handle, and cursor
 * value types as plain C declarations and prints their sizes,
 * alignments, and field offsets. It is an independent control: it
 * shares no code with the Mojo SDK, is built with the system C
 * compiler for the host, and its output is compared line by line
 * against Mojo-reported layouts and LLVM type layouts by the ABI
 * layout suite. Any divergence fails that suite.
 *
 * The structs below mirror the SDK source field by field (three
 * 32-bit context words; a byte pointer plus a 64-bit offset). The
 * SDK never casts packet bytes to a struct; the layout suite proves
 * that separately from the classifier IR, where every packet-rooted
 * load is a single byte.
 *
 * Output protocol: `SIZE <name> <bytes>`, `ALIGN <name> <bytes>`,
 * `OFF <struct.field> <bytes>`, one fact per line.
 */

#include <stddef.h>
#include <stdint.h>
#ifndef BPF_TYPE_EMIT
#include <stdio.h>
#endif

struct mojo_xdp_ctx {
    uint32_t data;
    uint32_t data_end;
    uint32_t data_meta;
};

struct mojo_cursor {
    uint8_t *base;
    int64_t off;
};

#define EMIT_SIZE(name, type) \
    printf("SIZE " name " %zu\n", sizeof(type))
#define EMIT_ALIGN(name, type) \
    printf("ALIGN " name " %zu\n", _Alignof(type))
#define EMIT_OFF(sname, stype, field) \
    printf("OFF " sname "." #field " %zu\n", offsetof(stype, field))

#ifndef BPF_TYPE_EMIT
int main(void) {
    EMIT_SIZE("u8", uint8_t);
    EMIT_SIZE("u16", uint16_t);
    EMIT_SIZE("u32", uint32_t);
    EMIT_SIZE("u64", uint64_t);
    EMIT_SIZE("i32", int32_t);
    EMIT_SIZE("i64", int64_t);
    EMIT_SIZE("int", long);
    EMIT_ALIGN("u8", uint8_t);
    EMIT_ALIGN("u16", uint16_t);
    EMIT_ALIGN("u32", uint32_t);
    EMIT_ALIGN("u64", uint64_t);
    EMIT_ALIGN("i32", int32_t);
    EMIT_ALIGN("i64", int64_t);
    EMIT_ALIGN("int", long);
    EMIT_SIZE("xdp_ctx", struct mojo_xdp_ctx);
    EMIT_ALIGN("xdp_ctx", struct mojo_xdp_ctx);
    EMIT_OFF("xdp_ctx", struct mojo_xdp_ctx, data);
    EMIT_OFF("xdp_ctx", struct mojo_xdp_ctx, data_end);
    EMIT_OFF("xdp_ctx", struct mojo_xdp_ctx, data_meta);
    EMIT_SIZE("cursor", struct mojo_cursor);
    EMIT_ALIGN("cursor", struct mojo_cursor);
    EMIT_OFF("cursor", struct mojo_cursor, base);
    EMIT_OFF("cursor", struct mojo_cursor, off);
    return 0;
}
#else
/* Type-only translation unit for the BPF-target layout leg: these
 * definitions force clang to emit the struct type records without
 * any libc dependency the BPF target cannot provide. */
struct mojo_xdp_ctx bpf_emit_ctx;
struct mojo_cursor bpf_emit_cursor;
#endif
