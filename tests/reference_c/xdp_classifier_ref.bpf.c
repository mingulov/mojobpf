/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Independent exact classifier workload. No generated Mojo implementation. */
typedef unsigned int u32;
typedef unsigned char u8;
struct xdp_prefix { u32 data; u32 data_end; };
#define SEC(name) __attribute__((section(name), used))

SEC("xdp") int xdp_classifier_ref(struct xdp_prefix *ctx)
{
    u8 *data = (u8 *)(unsigned long)ctx->data;
    u8 *end = (u8 *)(unsigned long)ctx->data_end;
    if (data + 15 <= end && data[14] % 2 == 1)
        return 1;
    return 2;
}
char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
