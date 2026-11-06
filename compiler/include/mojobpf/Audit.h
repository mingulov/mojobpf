// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#ifndef MOJOBPF_AUDIT_H
#define MOJOBPF_AUDIT_H

#include "mojobpf/TargetModel.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/ValueHandle.h"
#include <vector>

namespace mojobpf {
enum class CellKind { Key, Value, Disjoint };
struct ScratchCell {
  CellKind Kind;
  int64_t Offset;
  uint64_t Size;
  bool Preparation = false;
  uint32_t Literal = 0;
};

struct ScratchBindings {
  llvm::DenseMap<const llvm::Value *, ScratchCell> Cells;
  llvm::DenseSet<const llvm::CallBase *> InertCalls;
  unsigned AnalysisBudget = DefaultAnalysisBudget;
};

struct KeyUse {
  const llvm::CallBase *Call;
  const llvm::Value *Buffer;
  const llvm::Instruction *Preparation;
  uint32_t ExpectedLiteral;
};

enum class PrimitiveKind { Key, Value, Map, Reinterpret };
struct PrimitiveBinding {
  const llvm::CallInst *Call;
  PrimitiveKind Kind;
  uint32_t Literal = 0;
};

class ValidatedProgram {
  llvm::Module *BoundModule;
  llvm::Function *BoundEntry;
  llvm::Function *BoundCallee = nullptr;
  LoweringSpec BoundSpec;
  TargetFacts BoundFacts;
  std::string SourceDigest;
  std::string LoweringDigest;
  // WeakVH does not follow RAUW and becomes null on deletion. Comparing a
  // fresh live inventory never dereferences an old cached instruction.
  std::vector<llvm::WeakVH> ValueIdentities;
  enum class Phase { Source, Primitives, Complete } State = Phase::Source;
  llvm::json::Array Transformations;
  std::vector<PrimitiveBinding> Primitives;
  std::vector<const llvm::CallInst *> Helpers;
  ScratchBindings Scratch;
  std::vector<KeyUse> KeyUses;
  bool PermissiveAudit = false;
  llvm::json::Array Unproved;
  size_t UnprovedTotal = 0;
  ValidatedProgram(llvm::Module &Module, llvm::Function &Entry, const LoweringSpec &Spec);
  friend llvm::Expected<ValidatedProgram>
  auditSource(llvm::Module &, const LoweringSpec &, const TargetFacts &, bool);
  friend llvm::Error lowerPrimitivesAndHelpers(ValidatedProgram &);
  friend llvm::Error emitMapMetadata(ValidatedProgram &);
  void sealLoweringSnapshot();
  llvm::Error requirePendingLowering() const;

public:
  ValidatedProgram(ValidatedProgram &&) = default;
  ValidatedProgram(const ValidatedProgram &) = delete;
  ValidatedProgram &operator=(ValidatedProgram &&) = default;
  const llvm::Module &module() const { return *BoundModule; }
  const llvm::Function &entry() const { return *BoundEntry; }
  const std::vector<PrimitiveBinding> &primitives() const { return Primitives; }
  const std::vector<const llvm::CallInst *> &helpers() const { return Helpers; }
  const ScratchBindings &scratch() const { return Scratch; }
  const std::vector<KeyUse> &keyUses() const { return KeyUses; }
  const llvm::json::Array &transformations() const { return Transformations; }
  bool permissive() const { return PermissiveAudit; }
  const llvm::json::Array &unproved() const { return Unproved; }
  size_t unprovedTotal() const { return UnprovedTotal; }
  // The caller retains the module's lifetime. Recheck before using a source
  // proof; a changed module requires a new complete audit.
  llvm::Error requireUnchangedSource() const;
};

llvm::Expected<ValidatedProgram> auditSource(llvm::Module &Module,
                                            const LoweringSpec &Spec,
                                            const TargetFacts &Facts,
                                            bool Permissive = false);
llvm::Error auditKeyFreshness(const llvm::Function &Function,
                              const ScratchBindings &Bindings,
                              llvm::ArrayRef<KeyUse> Uses);
llvm::Error auditPointerStores(const llvm::Function &Function,
                               llvm::ArrayRef<const llvm::Value *> AddressRoots,
                               unsigned AnalysisBudget = DefaultAnalysisBudget);
llvm::Error auditLowered(const llvm::Module &Module, const LoweringSpec &Spec,
                         const TargetFacts &Facts, bool Permissive = false);
} // namespace mojobpf
#endif
