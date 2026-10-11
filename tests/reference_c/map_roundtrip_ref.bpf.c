/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Independent one-entry array workload, including its checked lookup. */
typedef unsigned int u32;
typedef unsigned long long u64;
#define SEC(name) __attribute__((section(name), used))
struct array_map {
    int (*type)[2];
    int (*max_entries)[1];
    u32 *key;
    u64 *value;
} mojobpf_map0 SEC(".maps");
static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, u64) = (void *)2;

SEC("xdp") int map_roundtrip_ref(void *ctx)
{
    u32 key = 0;
    u64 *found = lookup(&mojobpf_map0, &key);
    if (found) {
        u64 next = *found + 1;
        key = 0;
        update(&mojobpf_map0, &key, &next, 0);
    }
    return 2;
}
char _license[] SEC("license") = "Apache-2.0 WITH LLVM-exception";
