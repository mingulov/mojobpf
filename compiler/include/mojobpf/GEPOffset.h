// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#ifndef MOJOBPF_GEPOFFSET_H
#define MOJOBPF_GEPOFFSET_H
#include "llvm/ADT/APInt.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Instructions.h"
#include <algorithm>

namespace mojobpf {
// True when an inbounds GEP's index scaling overflows the recorded
// offset. accumulateConstantOffset reduces mod 2^N, so a wrapping
// index (4 * 4611686018427387907 = 2^64 + 12 records 12 for an i32
// step) would present a small proved offset for an out-of-range
// address, while inbounds poison makes the address meaningless.
// Recompute wide -- the width covers every index bit plus scaling
// headroom (each term is below 2^(W+64) and terms are far fewer
// than 2^64, so the wide sum cannot wrap) -- and require agreement
// with the recorded offset. Non-constant indices also report true
// (fail closed); callers reject those separately with their own
// diagnostic.
inline bool InboundsScalingOverflows(const llvm::DataLayout &DL,
                                     const llvm::GetElementPtrInst *GEP,
                                     const llvm::APInt &Recorded) {
  unsigned Need = DL.getIndexSizeInBits(0);
  for (const llvm::Value *Idx : GEP->indices())
    if (const auto *IT = llvm::dyn_cast<llvm::IntegerType>(Idx->getType()))
      Need = std::max(Need, IT->getBitWidth() + 128);
  llvm::APInt Wide(Need, 0);
  if (!GEP->accumulateConstantOffset(DL, Wide))
    return true;
  return Wide != Recorded.sext(Need);
}
} // namespace mojobpf
#endif
