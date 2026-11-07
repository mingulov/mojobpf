// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Reference control for F-ISA/mem/load-store qualification: mirrors
// tests/fixtures/isa/mem/mem_minimal.mojo arithmetic on a raw byte
// array. On the 60-byte zero packet the chain evaluates to
// a=b=c=d=e=0, h=h2=h3=0, s=0, t=0, v = (0 + 100) / 42 + 7 = 9 and
// the gate (9) stays shut: XDP_PASS (2). Build and run:
//   cc -O1 -o /tmp/mem_ref mem_ref.bpf.c && /tmp/mem_ref
// The mutant (+17 instead of +7) must print XDP_DROP instead.

#include <stdint.h>
#include <stdio.h>

static uint64_t helper(uint64_t n) { return (n / 42) + 7; }

static int xdp_entry(const uint8_t *pkt) {
    uint64_t a = pkt[14];
    uint64_t b = pkt[15];
    uint64_t c = pkt[16];
    uint64_t d = pkt[17];
    uint64_t e = pkt[18];
    uint16_t h = (uint16_t)((uint16_t)pkt[19] + (uint16_t)pkt[20]) / 42;
    int64_t s = (int8_t)pkt[21];
    uint16_t h2 =
        (uint16_t)((uint16_t)pkt[22] + (uint16_t)pkt[23]) / 7;
    uint16_t h3 = h + h2;
    uint64_t t = ((a << 32) | b) & 0x123456789ABCDEFULL;
    uint64_t v = helper(a + 100);
    uint64_t gate = v + b + c + d + e + (uint64_t)h + (uint64_t)h2 +
                    (uint64_t)h3 + (uint64_t)s + t;
    return gate > 10 ? 1 : 2;
}

int main(void) {
    static uint8_t pkt[60];
    int rc = xdp_entry(pkt);
    printf("verdict=%s(%d)\n", rc == 2 ? "XDP_PASS" : "XDP_DROP", rc);
    // The zero packet must shut the gate.
    return rc == 2 ? 0 : 1;
}
