// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Independent native oracle. It is never linked into a MojoBPF output.
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct context_prefix { uint32_t data, data_end; };

int main(void) {
  printf("WIDTHS %zu %zu %zu %zu %zu %zu %zu %zu %zu %zu\n",
         sizeof(intptr_t) * CHAR_BIT, sizeof(uintptr_t) * CHAR_BIT,
         sizeof(int8_t) * CHAR_BIT, sizeof(uint8_t) * CHAR_BIT,
         sizeof(int16_t) * CHAR_BIT, sizeof(uint16_t) * CHAR_BIT,
         sizeof(int32_t) * CHAR_BIT, sizeof(uint32_t) * CHAR_BIT,
         sizeof(int64_t) * CHAR_BIT, sizeof(uint64_t) * CHAR_BIT);
  struct context_prefix prefix = {UINT32_C(0x04030201), UINT32_C(0x08070605)};
  printf("PREFIX %zu %zu %zu %zu", sizeof(prefix), _Alignof(struct context_prefix),
         offsetof(struct context_prefix, data), offsetof(struct context_prefix, data_end));
  const uint8_t *bytes = (const uint8_t *)&prefix;
  for (size_t i = 0; i < sizeof(prefix); ++i) printf(" %u", bytes[i]);
  printf("\nCASTS %u %u %" PRIu32 " %" PRIu64 " %d %d %" PRId32 " %" PRId64 "\n",
         (uint8_t)UINT64_MAX, (uint16_t)UINT64_MAX, (uint32_t)UINT64_MAX,
         UINT64_MAX, INT8_MIN, INT16_MIN, INT32_MIN, INT64_MIN);
  printf("WRAP %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
         UINT64_MAX + UINT64_C(1), UINT64_C(0) + UINT64_C(1),
         UINT64_C(0x8000000000000000) + UINT64_C(1), UINT64_MAX - UINT64_C(1) + UINT64_C(1));
  printf("EXTEND %" PRIu64 " %" PRIu64 "\n", (uint64_t)(uint8_t)255, (uint64_t)(int64_t)(int8_t)-1);
  printf("NARROW %u %u %u\n", (uint8_t)UINT64_C(0),
         (uint8_t)UINT64_C(0x8000000000000000), (uint8_t)UINT64_MAX);
  printf("EXTEND_BOUNDARY %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
         (uint64_t)(uint8_t)0, (uint64_t)(uint8_t)128, (uint64_t)(uint8_t)255,
         (uint64_t)(int64_t)(int8_t)0, (uint64_t)(int64_t)(int8_t)INT8_MAX,
         (uint64_t)(int64_t)(int8_t)INT8_MIN);
  return 0;
}
