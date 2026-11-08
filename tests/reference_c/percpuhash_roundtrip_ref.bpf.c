/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Independent one-entry per-CPU-hash workload, including its checked lookup.
 * Mirrors tests/compile/percpuhash_rmw1.mojo exactly: look up key 0; on a
 * hit read the calling CPU's value, add one, and write the sum back
 * through the update helper with BPF_ANY; report XDP_PASS either way.
 * The D3 control leg loads this object beside the Mojo object, drives
 * both identically, and asserts identical map bytes through bpftool.
 */
typedef unsigned int u32;
typedef unsigned long long u64;
#define SEC(name) __attribute__((section(name), used))
struct percpu_hash_map {
    int (*type)[5];
    int (*max_entries)[1];
    u32 *key;
    u64 *value;
} mojobpf_map0 SEC(".maps");
static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, u64) = (void *)2;

SEC("xdp") int percpuhash_roundtrip_ref(void *ctx)
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
