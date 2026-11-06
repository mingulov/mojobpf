// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "mojobpf/Lowering.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/ModuleSlotTracker.h"
#include "llvm/IR/Verifier.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;
namespace mojobpf {
Error lowerPrimitivesAndHelpers(ValidatedProgram &P) {
  if (P.State != ValidatedProgram::Phase::Source)
    return compilerError("MBPF319", "adapter.lower", "source proof was already consumed");
  if (auto E = P.requireUnchangedSource()) return E;
  Module &M = *P.BoundModule;
  Function &F = *P.BoundEntry;
  // All collision checks precede any change, including local SSA names.
  for (StringRef Name : {"_license", "llvm.used", "llvm.compiler.used", "mojobpf_map0"})
    if (M.getNamedValue(Name))
      return compilerError("MBPF309", "adapter.lower", "generated symbol collision", Name);
  std::string MapTypeName = "mojobpf.array.map";
  if (P.BoundSpec.Map && P.BoundSpec.Map->Type == 1) MapTypeName = "mojobpf.hash.map";
  else if (P.BoundSpec.Map && P.BoundSpec.Map->Type == 9) MapTypeName = "mojobpf.lru.map";
  else if (P.BoundSpec.Map && P.BoundSpec.Map->Type == 6) MapTypeName = "mojobpf.percpu.map";
  if (StructType::getTypeByName(M.getContext(), MapTypeName))
    return compilerError("MBPF309", "adapter.lower", "generated map type collision");

  ModuleSlotTracker Slots(&M);
  Slots.incorporateFunction(F);
  DenseMap<const Value *, std::string> Original;
  auto Name = [&](const Value &V) {
    std::string S;
    raw_string_ostream OS(S);
    V.printAsOperand(OS, false, Slots);
    return S;
  };
  auto Remember = [&](const Value &V) { Original[&V] = Name(V); };
  for (Argument &A : F.args()) Remember(A);
  unsigned Ordinal = 0;
  DenseMap<const Instruction *, unsigned> Ordinals;
  for (BasicBlock &BB : F) {
    Remember(BB);
    for (Instruction &I : BB) {
      Ordinals[&I] = Ordinal++;
      if (!I.getType()->isVoidTy()) Remember(I);
    }
  }
  unsigned Index = 0;
  for (Argument &A : F.args()) if (!A.hasName()) A.setName("mojobpf.arg." + Twine(Index++));
  Index = 0;
  for (BasicBlock &BB : F) {
    if (!BB.hasName()) BB.setName("mojobpf.block." + Twine(Index++));
    for (Instruction &I : BB)
      if (!I.getType()->isVoidTy() && !I.hasName())
        I.setName("mojobpf.source." + Twine(Ordinals.lookup(&I)));
  }
  DenseMap<const Value *, Value *> Rewrites;
  M.setTargetTriple(Triple(P.BoundFacts.TargetTriple));
  M.setDataLayout(P.BoundFacts.TargetLayout);
  F.setSection(P.BoundSpec.Section);
  F.removeFnAttr("target-cpu");
  F.removeFnAttr("target-features");
  F.addFnAttr("target-cpu", "v3");
  F.addFnAttr("target-features", "");
  for (BasicBlock &BB : F) for (Instruction &I : BB)
    if (auto *Call = dyn_cast<CallInst>(&I)) {
      Call->removeFnAttr("target-cpu");
      Call->removeFnAttr("target-features");
    }
  if (P.BoundCallee) {
    // The backend lowers the static call itself: the callee keeps
    // its body, name and noinline marker and only retargets, with
    // no section of its own.
    Function &G = *P.BoundCallee;
    G.removeFnAttr("target-cpu");
    G.removeFnAttr("target-features");
    G.addFnAttr("target-cpu", "v3");
    G.addFnAttr("target-features", "");
    P.Transformations.push_back(json::Object{{"kind", "subprog"},
        {"callee", G.getName().str()}, {"target", G.getName().str()}});
  }
  auto *LicenseBytes = ConstantDataArray::getString(M.getContext(), P.BoundSpec.KernelLicense, true);
  auto *License = new GlobalVariable(M, LicenseBytes->getType(), false,
      GlobalValue::ExternalLinkage, LicenseBytes, "_license");
  License->setDSOLocal(true);
  License->setSection("license");
  License->setAlignment(Align(1));
  // Lane-A order and list: license, entry, map. llvm.compiler.used
  // (not llvm.used) so section flags and EI_OSABI match the
  // qualified emission exactly.
  SmallVector<GlobalValue *, 3> Retained{License, &F};
  GlobalVariable *Map = nullptr;
  if (P.BoundSpec.Map) {
    auto *Ptr = PointerType::getUnqual(M.getContext());
    auto *T = StructType::create(M.getContext(), {Ptr, Ptr, Ptr, Ptr}, MapTypeName);
    Map = new GlobalVariable(M, T, false, GlobalValue::ExternalLinkage,
                             ConstantAggregateZero::get(T), P.BoundSpec.Map->Symbol);
    Map->setSection(".maps");
    Map->setAlignment(M.getDataLayout().getABITypeAlign(T));
    Retained.push_back(Map);
  }
  appendToCompilerUsed(M, Retained);
  bool HasKey = false, HasValue = false;
  for (const PrimitiveBinding &B : P.Primitives) {
    HasKey |= B.Kind == PrimitiveKind::Key;
    HasValue |= B.Kind == PrimitiveKind::Value;
  }
  IRBuilder<> EntryBuilder(&*F.getEntryBlock().getFirstInsertionPt());
  AllocaInst *KeyCell = nullptr, *ValueCell = nullptr;
  if (HasKey) {
    KeyCell = EntryBuilder.CreateAlloca(EntryBuilder.getInt32Ty(), nullptr, "mojobpf.key");
    KeyCell->setAlignment(Align(4));
  }
  if (HasValue) {
    ValueCell = EntryBuilder.CreateAlloca(EntryBuilder.getInt64Ty(), nullptr, "mojobpf.value");
    ValueCell->setAlignment(Align(8));
  }
  SmallVector<Instruction *, 16> Erase;
  for (const PrimitiveBinding &B : P.Primitives) {
    auto *Call = const_cast<CallInst *>(B.Call);
    if (B.Kind == PrimitiveKind::Reinterpret) continue;
    IRBuilder<> Builder(Call);
    Value *Replacement;
    std::string Kind;
    if (B.Kind == PrimitiveKind::Key) {
      auto *Store = Builder.CreateStore(Builder.getInt32(B.Literal), KeyCell);
      Store->setAlignment(Align(4));
      Replacement = KeyCell;
      Kind = "key";
    } else if (B.Kind == PrimitiveKind::Value) {
      Replacement = ValueCell;
      Kind = "value";
    } else if (B.Kind == PrimitiveKind::HashTag || B.Kind == PrimitiveKind::LruTag ||
               B.Kind == PrimitiveKind::PercpuTag) {
      // Transparent copy of the map address, like the map
      // primitive itself; recorded under its own kind so the
      // evidence names what the source spelled.
      Replacement = ConstantExpr::getPtrToInt(Map, Builder.getInt64Ty());
      Kind = "tag";
    } else {
      Replacement = ConstantExpr::getPtrToInt(Map, Builder.getInt64Ty());
      Kind = "map";
    }
    P.Transformations.push_back(json::Object{{"kind", Kind}, {"source", Original.lookup(Call)},
        {"source_ordinal", int64_t(Ordinals.lookup(Call))}, {"target", Name(*Replacement)},
        {"literal", int64_t(B.Literal)}});
    Rewrites[Call] = Replacement;
    Call->replaceAllUsesWith(Replacement);
    Erase.push_back(Call);
  }
  for (const CallInst *ConstCall : P.Helpers) {
    auto *Call = const_cast<CallInst *>(ConstCall);
    StringRef Callee = Call->getCalledFunction()->getName();
    unsigned ID = Callee == "__mojobpf_lookup_v1" ? 1 : Callee == "__mojobpf_update_v1" ? 2 : 3;
    auto *Numeric = ConstantExpr::getIntToPtr(ConstantInt::get(Type::getInt64Ty(M.getContext()), ID),
                                             PointerType::getUnqual(M.getContext()));
    P.Transformations.push_back(json::Object{{"kind", "helper"}, {"source", Original.lookup(Call)},
        {"source_ordinal", int64_t(Ordinals.lookup(Call))}, {"callee", Callee.str()}, {"helper_id", int64_t(ID)}});
    Call->setCalledOperand(Numeric);
  }
  for (const auto &Row : Original) {
    const Value *Target = Rewrites.count(Row.first) ? Rewrites.lookup(Row.first) : Row.first;
    std::string Role = Row.first == &F.getEntryBlock() ? "entry-block" :
        isa<BasicBlock>(Row.first) ? "block" : isa<Argument>(Row.first) ? "argument" : "instruction";
    P.Transformations.push_back(json::Object{{"kind", "value-map"}, {"source", Row.second},
        {"target", Name(*Target)}, {"value_kind", Role}});
  }
  for (Instruction *I : Erase) I->eraseFromParent();
  for (auto I = M.begin(), E = M.end(); I != E;) {
    Function &Decl = *I++;
    if (&Decl == &F || &Decl == P.BoundCallee) continue;
    if (!Decl.use_empty())
      return compilerError("MBPF313", "adapter.lower", "reserved declaration retains unexpected uses", Decl.getName());
    Decl.eraseFromParent();
  }
  P.Transformations.push_back(json::Object{{"kind", "target"}, {"triple", P.BoundFacts.TargetTriple},
      {"layout", P.BoundFacts.TargetLayout}, {"cpu", "v3"}, {"section", P.BoundSpec.Section}});
  P.Primitives.clear();
  P.Helpers.clear();
  P.Scratch.Cells.clear();
  P.Scratch.InertCalls.clear();
  P.KeyUses.clear();
  if (verifyModule(M, &errs()))
    return compilerError("MBPF106", "adapter.verify", "lowered primitive module failed LLVM verification");
  P.State = ValidatedProgram::Phase::Primitives;
  P.sealLoweringSnapshot();
  return Error::success();
}
} // namespace mojobpf
