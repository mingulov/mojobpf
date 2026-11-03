// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#ifndef MOJOBPF_GEPOFFSET_H
#define MOJOBPF_GEPOFFSET_H
#include "llvm/ADT/APInt.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/Instructions.h"
#include <algorithm>

namespace mojobpf {
// True when an inbounds GEP's index scaling overflows the recorded
// offset. accumulateConstantOffset reduces mod 2^N, so a wrapping
// index (4 * 4611686018427387907 = 2^64 + 12 records 12 for an i32
// step) would present a small proved offset for an out-of-range
// address, while inbounds poison makes the address meaningless.
// This walks the indices explicitly in controlled wide arithmetic
// (a wide accumulateConstantOffset call is NOT used: the header
// permits wider APInts but the implementation asserts exact index
// width). The width covers every index bit plus scaling headroom:
// each term is below 2^(W+64) and terms are far fewer than 2^64,
// so the wide sum cannot wrap, and any disagreement with the
// recorded offset is a genuine overflow. Struct steps bounds-check
// their field index; sequential steps multiply the sign-extended
// index by the element stride, mirroring the upstream walk.
// Non-constant indices, scalable steps, and out-of-range struct
// fields report true (fail closed); callers reject those separately
// with their own diagnostic where applicable.
inline bool InboundsScalingOverflows(const llvm::DataLayout &DL,
                                     const llvm::GetElementPtrInst *GEP,
                                     const llvm::APInt &Recorded) {
  unsigned Need = DL.getIndexSizeInBits(0);
  for (const llvm::Value *Idx : GEP->indices())
    if (const auto *IT = llvm::dyn_cast<llvm::IntegerType>(Idx->getType()))
      Need = std::max(Need, IT->getBitWidth() + 128);
  llvm::APInt Wide(Need, 0);
  for (auto GTI = llvm::gep_type_begin(GEP), GTE = llvm::gep_type_end(GEP);
       GTI != GTE; ++GTI) {
    const auto *ConstOffset =
        llvm::dyn_cast<llvm::ConstantInt>(GTI.getOperand());
    if (!ConstOffset || !ConstOffset->getType()->isIntegerTy())
      return true;
    if (ConstOffset->isZero())
      continue;
    if (GTI.getIndexedType()->isScalableTy())
      return true;
    if (llvm::StructType *STy = GTI.getStructTypeOrNull()) {
      if (ConstOffset->getValue().uge(STy->getNumElements()))
        return true;
      Wide += llvm::APInt(
          Need, DL.getStructLayout(STy)->getElementOffset(
                    (unsigned)ConstOffset->getZExtValue()));
    } else {
      Wide += ConstOffset->getValue().sext(Need) *
              llvm::APInt(Need, GTI.getSequentialElementStride(DL));
    }
  }
  return Wide != Recorded.sext(Need);
}
} // namespace mojobpf
#endif
