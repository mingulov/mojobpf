// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "mojobpf/Audit.h"
#include "mojobpf/GEPOffset.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/ScopeExit.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include <algorithm>
#include <optional>

using namespace llvm;
namespace mojobpf {
Error auditMapMetadata(const Module &, const LoweringSpec &, bool);
Error auditLoweredCore(const Module &, const LoweringSpec &, const TargetFacts &, bool);
namespace {
std::string location(const Value &V) {
  std::string Text;
  raw_string_ostream OS(Text);
  V.printAsOperand(OS, false);
  if (auto *I = dyn_cast<Instruction>(&V))
    OS << " in " << I->getFunction()->getName();
  return Text;
}
Error failure(StringRef Code, StringRef Explanation, const Value *V = nullptr) {
  return compilerError(Code, Code == "MBPF320" ? "adapter.resource" :
                       Code == "MBPF319" ? "adapter.target" : "adapter.audit",
                       Explanation, V ? location(*V) : "module");
}

struct Budget {
  unsigned Remaining;
  bool Exhausted = false;
  bool spend() {
    if (!Remaining) { Exhausted = true; return false; }
    --Remaining;
    return true;
  }
};

Expected<SmallVector<const BasicBlock *, 16>> orderedBlocks(const Function &F, Budget &B) {
  if (F.empty()) return failure("MBPF319", "analysis requires a defined function");
  SmallPtrSet<const BasicBlock *, 32> Reachable;
  SmallVector<const BasicBlock *, 16> Pending{&F.getEntryBlock()};
  while (!Pending.empty()) {
    if (!B.spend()) return failure("MBPF320", "CFG analysis budget exhausted");
    const BasicBlock *BB = Pending.pop_back_val();
    if (!Reachable.insert(BB).second) continue;
    if (Reachable.size() > MaxBlocks) return failure("MBPF320", "CFG block limit exhausted");
    for (const BasicBlock *Successor : successors(BB)) Pending.push_back(Successor);
  }
  DenseMap<const BasicBlock *, unsigned> Predecessors;
  SmallVector<const BasicBlock *, 16> Ready, Order;
  for (const BasicBlock &BB : F) {
    if (!Reachable.contains(&BB)) continue;
    unsigned Count = 0;
    for (const BasicBlock *Pred : predecessors(&BB)) if (Reachable.contains(Pred)) ++Count;
    Predecessors[&BB] = Count;
    if (!Count) Ready.push_back(&BB);
  }
  while (!Ready.empty()) {
    if (!B.spend()) return failure("MBPF320", "CFG ordering budget exhausted");
    const BasicBlock *BB = Ready.pop_back_val();
    Order.push_back(BB);
    for (const BasicBlock *Successor : successors(BB))
      if (--Predecessors[Successor] == 0) Ready.push_back(Successor);
  }
  if (Order.size() != Reachable.size())
    return failure("MBPF319", "cyclic CFG is outside the admitted no-loop slice");
  return Order;
}

struct CellAddress {
  const Value *Arena = nullptr; // null is the shared source r10 frame.
  int64_t Offset = 0;
  bool operator==(const CellAddress &Other) const {
    return Arena == Other.Arena && Offset == Other.Offset;
  }
};

class CellResolver {
  const ScratchBindings &Bindings;
  const DataLayout &DL;
  Budget &Work;
  SmallPtrSet<const Value *, 32> Active;
  DenseMap<const Value *, std::optional<CellAddress>> Cache;
  unsigned FieldDepth = 0;

  std::optional<CellAddress> join(std::optional<CellAddress> Left,
                                   std::optional<CellAddress> Right) {
    if (Left && Right && *Left == *Right) return Left;
    return std::nullopt;
  }
  std::optional<CellAddress> field(const Value *V, ArrayRef<unsigned> Indices) {
    if (!Work.spend()) return std::nullopt;
    if (FieldDepth >= 256) { Work.Exhausted = true; return std::nullopt; }
    ++FieldDepth;
    auto Scope = make_scope_exit([&] { --FieldDepth; });
    if (Indices.empty()) return resolve(V);
    if (auto *Insert = dyn_cast<InsertValueInst>(V)) {
      auto Written = Insert->getIndices();
      if (Indices == Written) return resolve(Insert->getInsertedValueOperand());
      if (Indices.size() > Written.size() && Indices.take_front(Written.size()) == Written)
        return field(Insert->getInsertedValueOperand(), Indices.drop_front(Written.size()));
      return field(Insert->getAggregateOperand(), Indices);
    }
    if (auto *C = dyn_cast<Constant>(V)) {
      if (Constant *Element = C->getAggregateElement(Indices.front()))
        return field(Element, Indices.drop_front());
    }
    if (auto *Select = dyn_cast<SelectInst>(V))
      return join(field(Select->getTrueValue(), Indices), field(Select->getFalseValue(), Indices));
    if (auto *Phi = dyn_cast<PHINode>(V)) {
      std::optional<CellAddress> Result;
      bool First = true;
      for (const Value *Incoming : Phi->incoming_values()) {
        auto Next = field(Incoming, Indices);
        Result = First ? Next : join(Result, Next);
        First = false;
      }
      return Result;
    }
    return std::nullopt;
  }

public:
  CellResolver(const ScratchBindings &Bindings, const DataLayout &DL, Budget &Work)
      : Bindings(Bindings), DL(DL), Work(Work) {}
  std::optional<CellAddress> resolve(const Value *V) {
    if (!Work.spend()) return std::nullopt;
    if (auto Found = Bindings.Cells.find(V); Found != Bindings.Cells.end()) {
      const ScratchCell &Cell = Found->second;
      return CellAddress{Cell.Kind == CellKind::Disjoint ? V : nullptr, Cell.Offset};
    }
    if (auto Found = Cache.find(V); Found != Cache.end()) return Found->second;
    if (Active.size() >= 256) { Work.Exhausted = true; return std::nullopt; }
    if (!Active.insert(V).second) return std::nullopt;
    std::optional<CellAddress> Result;
    if (const auto *GEP = dyn_cast<GEPOperator>(V)) {
      auto Base = resolve(GEP->getPointerOperand());
      APInt Offset(64, 0);
      if (Base && GEP->getPointerAddressSpace() == 0 && GEP->accumulateConstantOffset(DL, Offset)) {
        int64_t Total;
        if (!AddOverflow(Base->Offset, Offset.getSExtValue(), Total)) {
          Base->Offset = Total;
          Result = Base;
        }
      }
    } else if (const auto *Freeze = dyn_cast<FreezeInst>(V)) {
      Result = resolve(Freeze->getOperand(0));
    } else if (const auto *Cast = dyn_cast<CastInst>(V)) {
      if (isa<BitCastInst>(Cast) || isa<PtrToIntInst>(Cast) || isa<IntToPtrInst>(Cast))
        Result = resolve(Cast->getOperand(0));
    } else if (const auto *Expression = dyn_cast<ConstantExpr>(V)) {
      if (Expression->isCast()) Result = resolve(Expression->getOperand(0));
    } else if (const auto *Select = dyn_cast<SelectInst>(V)) {
      Result = join(resolve(Select->getTrueValue()), resolve(Select->getFalseValue()));
    } else if (const auto *Phi = dyn_cast<PHINode>(V)) {
      bool First = true;
      for (const Value *Incoming : Phi->incoming_values()) {
        auto Next = resolve(Incoming);
        Result = First ? Next : join(Result, Next);
        First = false;
      }
    } else if (const auto *Extract = dyn_cast<ExtractValueInst>(V)) {
      Result = field(Extract->getAggregateOperand(), Extract->getIndices());
    }
    Active.erase(V);
    Cache[V] = Result;
    return Result;
  }
};

std::optional<uint64_t> storeFootprint(const StoreInst &Store, const DataLayout &DL) {
  Type *T = Store.getValueOperand()->getType();
  if (!T->isSized()) return std::nullopt;
  TypeSize Size = DL.getTypeStoreSize(T);
  if (Size.isScalable()) return std::nullopt;
  return Size.getFixedValue();
}
bool overlapsKey(const std::optional<CellAddress> &Address,
                 const std::optional<uint64_t> &Size) {
  if (!Address || !Size || *Size > uint64_t(INT64_MAX)) return true;
  if (Address->Arena) return false;
  int64_t End;
  if (AddOverflow(Address->Offset, int64_t(*Size), End)) return true;
  return Address->Offset < 0 && End > -4;
}

struct KeyState {
  const Instruction *Preparation = nullptr;
  uint32_t Literal = 0;
  bool Valid = false;
  bool operator==(const KeyState &Other) const {
    return Valid == Other.Valid && (!Valid || (Preparation == Other.Preparation && Literal == Other.Literal));
  }
};

enum class Kind { Scalar, Context, DataWord, EndWord, PacketAddress, EndAddress,
                  PacketBound, PacketPointer, MapReference, LookupAddress,
                  LookupPointer, KeyPointer, ValuePointer, Control, Escaped };
struct Provenance {
  Kind Category = Kind::Scalar;
  const Value *Origin = nullptr;
  int64_t Offset = 0;
};
std::optional<Align> memoryAlignment(const Provenance &Address) {
  unsigned Root;
  switch (Address.Category) {
  case Kind::Context: case Kind::KeyPointer: Root = 4; break;
  case Kind::ValuePointer: case Kind::LookupPointer: Root = 8; break;
  case Kind::PacketPointer: Root = 1; break;
  default: return std::nullopt;
  }
  if (Address.Offset < 0) return std::nullopt;
  return commonAlignment(Align(Root), uint64_t(Address.Offset));
}
bool tainted(const Provenance &P) { return P.Category != Kind::Scalar; }
bool sameFact(const Provenance &A, const Provenance &B) {
  return A.Category == B.Category && A.Origin == B.Origin && A.Offset == B.Offset;
}

bool scalar(Type *T) {
  if (auto *I = dyn_cast<IntegerType>(T)) {
    auto Bits = I->getBitWidth();
    return Bits == 1 || Bits == 8 || Bits == 16 || Bits == 32 || Bits == 64;
  }
  return false;
}
bool constant(const Value *V, uint64_t Number) {
  const auto *C = dyn_cast<ConstantInt>(V);
  return C && C->getValue() == Number;
}
bool prototype(const FunctionType *T, Type *Result, ArrayRef<Type *> Arguments) {
  return T->getReturnType() == Result && !T->isVarArg() && T->params() == Arguments;
}
std::optional<PrimitiveKind> primitive(const CallInst &Call) {
  const auto *Asm = dyn_cast<InlineAsm>(Call.getCalledOperand());
  if (!Asm || Call.hasOperandBundles() || Call.getCallingConv() != CallingConv::C ||
      Call.isMustTailCall() || Asm->getDialect() != InlineAsm::AD_ATT ||
      Asm->isAlignStack() || Asm->canThrow()) return std::nullopt;
  auto &C = Call.getContext();
  Type *Ptr = PointerType::getUnqual(C), *I32 = Type::getInt32Ty(C), *I64 = Type::getInt64Ty(C);
  StringRef Text = Asm->getAsmString(), Constraints = Asm->getConstraintString();
  if (Text == "r0 = r10\nr0 += -4\n*(u32 *)(r0 + 0) = r1" &&
      Constraints == "={r0},{r1},~{memory}" && Asm->hasSideEffects() &&
      prototype(Asm->getFunctionType(), Ptr, {I32})) return PrimitiveKind::Key;
  if (Text == "r0 = r10\nr0 += -16" && Constraints == "={r0}" &&
      Asm->hasSideEffects() && prototype(Asm->getFunctionType(), Ptr, {})) return PrimitiveKind::Value;
  if (Text == "r0 = mojobpf_map0 ll" && Constraints == "={r0}" &&
      Asm->hasSideEffects() && prototype(Asm->getFunctionType(), I64, {})) return PrimitiveKind::Map;
  if (Text.empty() && Constraints == "=r,0" && !Asm->hasSideEffects() &&
      prototype(Asm->getFunctionType(), Ptr, {I64})) return PrimitiveKind::Reinterpret;
  return std::nullopt;
}

Error inspectConstants(const Value *V, SmallPtrSetImpl<const Value *> &Seen, Budget &B) {
  if (!B.spend()) return failure("MBPF320", "constant/operand traversal budget exhausted");
  if (!Seen.insert(V).second) return Error::success();
  if (isa<UndefValue>(V) || isa<PoisonValue>(V))
    return failure("MBPF311", "undef/poison cannot enter the admitted program", V);
  if (auto *C = dyn_cast<Constant>(V))
    for (const Use &U : C->operands())
      if (auto E = inspectConstants(U.get(), Seen, B)) return E;
  return Error::success();
}

bool edgeDominates(const Function &F, const Value *Condition, unsigned Successor,
                   const Instruction &Use, const DominatorTree &DT) {
  for (const User *U : Condition->users()) {
    auto *Branch = dyn_cast<BranchInst>(U);
    if (Branch && Branch->isConditional() && Branch->getFunction() == &F &&
        Branch->getCondition() == Condition &&
        DT.dominates(BasicBlockEdge(Branch->getParent(), Branch->getSuccessor(Successor)), Use.getParent()))
      return true;
  }
  return false;
}

bool checkedLookup(const CallInst &Lookup, const Instruction &Use, const DominatorTree &DT) {
  for (const User *U : Lookup.users()) {
    auto *Compare = dyn_cast<ICmpInst>(U);
    if (!Compare || Compare->getOperand(0) != &Lookup || !constant(Compare->getOperand(1), 0)) continue;
    if (Compare->getPredicate() == ICmpInst::ICMP_EQ && edgeDominates(*Lookup.getFunction(), Compare, 1, Use, DT)) return true;
    if (Compare->getPredicate() == ICmpInst::ICMP_NE && edgeDominates(*Lookup.getFunction(), Compare, 0, Use, DT)) return true;
  }
  return false;
}
std::string sourceDigest(const Module &M) {
  SmallVector<char, 0> Bytes;
  raw_svector_ostream OS(Bytes);
  WriteBitcodeToFile(M, OS);
  return toHex(SHA256::hash(arrayRefFromStringRef(StringRef(Bytes.data(), Bytes.size()))), true);
}
} // namespace

Error auditKeyFreshness(const Function &F, const ScratchBindings &Bindings, ArrayRef<KeyUse> Uses) {
  Budget Work{Bindings.AnalysisBudget};
  auto Ordered = orderedBlocks(F, Work);
  if (!Ordered) return Ordered.takeError();
  const DataLayout &DL = F.getParent()->getDataLayout();
  CellResolver Resolver(Bindings, DL, Work);
  DominatorTree DT(const_cast<Function &>(F));
  DenseMap<const Instruction *, const KeyUse *> Consumers;
  for (const KeyUse &Use : Uses) {
    if (!Work.spend()) return failure("MBPF320", "key binding budget exhausted");
    auto Preparation = Bindings.Cells.find(Use.Preparation);
    if (!Use.Call || Use.Call->getFunction() != &F || !Use.Preparation ||
        Use.Preparation->getFunction() != &F || Preparation == Bindings.Cells.end() ||
        !Preparation->second.Preparation || Preparation->second.Kind != CellKind::Key ||
        !Consumers.try_emplace(Use.Call, &Use).second)
      return failure("MBPF318", "key-use binding does not name a unique preparation/consumer");
  }
  DenseMap<const BasicBlock *, KeyState> Outputs;
  for (const BasicBlock *BB : *Ordered) {
    KeyState State;
    bool First = true;
    for (const BasicBlock *Pred : predecessors(BB)) {
      auto Found = Outputs.find(Pred);
      if (Found == Outputs.end()) continue;
      if (First) State = Found->second;
      else if (!(State == Found->second)) State.Valid = false;
      First = false;
    }
    for (const Instruction &I : *BB) {
      if (!Work.spend()) return failure("MBPF320", "key instruction budget exhausted");
      if (auto Found = Bindings.Cells.find(&I); Found != Bindings.Cells.end() && Found->second.Preparation) {
        State = KeyState{&I, Found->second.Literal, true};
      }
      if (const auto *S = dyn_cast<StoreInst>(&I)) {
        auto Address = Resolver.resolve(S->getPointerOperand());
        if (Work.Exhausted) return failure("MBPF320", "scratch alias analysis budget exhausted", &I);
        if (overlapsKey(Address, storeFootprint(*S, DL))) State.Valid = false;
      }
      if (auto Found = Consumers.find(&I); Found != Consumers.end()) {
        const KeyUse &Use = *Found->second;
        auto Address = Resolver.resolve(Use.Buffer);
        if (Work.Exhausted) return failure("MBPF320", "key alias analysis budget exhausted", &I);
        if (!State.Valid || State.Preparation != Use.Preparation || State.Literal != Use.ExpectedLiteral ||
            !Address || Address->Arena || Address->Offset != -4 || !DT.dominates(Use.Preparation, Use.Call))
          return failure("MBPF318", "cannot prove the consumer reads its exact preparation identity/literal from the shared key cell", &I);
      }
      if (const auto *Call = dyn_cast<CallBase>(&I)) {
        auto Cell = Bindings.Cells.find(Call);
        bool Preparation = Cell != Bindings.Cells.end() && Cell->second.Preparation;
        if (!Preparation && !Consumers.contains(&I) && !Bindings.InertCalls.contains(Call) && Call->mayWriteToMemory())
          State.Valid = false;
      }
    }
    Outputs[BB] = State;
  }
  if (Work.Exhausted) return failure("MBPF320", "scratch analysis budget exhausted");
  return Error::success();
}

ValidatedProgram::ValidatedProgram(Module &M, Function &F, const LoweringSpec &Spec)
    : BoundModule(&M), BoundEntry(&F), BoundSpec(Spec) {}

namespace {
// Called only after complete bounded admission. Every cached primitive,
// helper, scratch root, inert call, key consumer/buffer/preparation and entry
// is a member of this finite module inventory. Deletion-aware handles also
// distinguish a deleted value whose storage address was subsequently reused.
std::vector<WeakVH> liveIdentities(Module &M) {
  std::vector<WeakVH> Values;
  for (GlobalVariable &G : M.globals()) Values.emplace_back(&G);
  for (Function &F : M) {
    Values.emplace_back(&F);
    for (Argument &A : F.args()) Values.emplace_back(&A);
    for (BasicBlock &BB : F) {
      Values.emplace_back(&BB);
      for (Instruction &I : BB) Values.emplace_back(&I);
    }
  }
  return Values;
}
bool sameIdentities(const std::vector<WeakVH> &Old, const std::vector<WeakVH> &Live) {
  if (Old.size() != Live.size()) return false;
  for (unsigned Index = 0; Index < Old.size(); ++Index)
    if (!static_cast<Value *>(Old[Index]) ||
        static_cast<Value *>(Old[Index]) != static_cast<Value *>(Live[Index])) return false;
  return true;
}
} // namespace

Error ValidatedProgram::requireUnchangedSource() const {
  if (State != Phase::Source)
    return failure("MBPF319", "source proof was consumed by a lowering transition");
  // Re-audit before serialization: a valid but unsupported mutation cannot
  // use the snapshot mechanism to widen the source model. No proof is reused
  // for a verifier-invalid or resource-exhausting module.
  std::string VerifierText;
  raw_string_ostream Verifier(VerifierText);
  if (verifyModule(*BoundModule, &Verifier))
    return compilerError("MBPF106", "adapter.verify", "source proof requires LLVM verification: " + VerifierText);
  auto Facts = inspectTargetModel(*BoundModule, BoundSpec);
  if (!Facts) return Facts.takeError();
  auto Current = auditSource(*BoundModule, BoundSpec, *Facts);
  if (!Current) return Current.takeError();
  if (Current->SourceDigest != SourceDigest || !sameIdentities(ValueIdentities, Current->ValueIdentities))
    return failure("MBPF319", "audited source module changed after construction; its bindings are stale");
  return Error::success();
}

void ValidatedProgram::sealLoweringSnapshot() {
  LoweringDigest = sourceDigest(*BoundModule);
  ValueIdentities = liveIdentities(*BoundModule);
}
Error ValidatedProgram::requirePendingLowering() const {
  if (State != Phase::Primitives)
    return failure("MBPF319", "metadata requires the exact pending primitive transition");
  // Check actual forms, verification and finite bounds before serializing a
  // caller-mutated module. The snapshot is a freshness check, not admission.
  if (auto E = auditLoweredCore(*BoundModule, BoundSpec, BoundFacts, false)) return E;
  if (sourceDigest(*BoundModule) != LoweringDigest ||
      !sameIdentities(ValueIdentities, liveIdentities(*BoundModule)))
    return failure("MBPF319", "lowered module changed between primitive and metadata transitions");
  return Error::success();
}

Error auditPointerStores(const Function &F, ArrayRef<const Value *> AddressRoots,
                         unsigned AnalysisBudget) {
  Budget Work{AnalysisBudget};
  DenseSet<const Value *> Tainted;
  SmallVector<const Value *, 32> Pending;
  auto Add = [&](const Value *V) { if (Tainted.insert(V).second) Pending.push_back(V); };
  for (const Value *V : AddressRoots) {
    if (!Work.spend()) return failure("MBPF320", "pointer root budget exhausted");
    Add(V);
  }
  for (const Argument &A : F.args()) if (A.getType()->isPointerTy()) Add(&A);
  SmallPtrSet<const Value *, 32> Seen;
  SmallVector<const Value *, 32> Constants;
  SmallVector<const PHINode *, 16> Phis;
  for (const BasicBlock &BB : F) for (const Instruction &I : BB) {
    if (!Work.spend()) return failure("MBPF320", "pointer-store instruction budget exhausted");
    if (I.getType()->isPointerTy()) Add(&I);
    if (const auto *Phi = dyn_cast<PHINode>(&I)) Phis.push_back(Phi);
    for (const Use &U : I.operands()) if (isa<Constant>(U.get())) Constants.push_back(U.get());
  }
  while (!Constants.empty()) {
    if (!Work.spend()) return failure("MBPF320", "pointer constant budget exhausted");
    const Value *V = Constants.pop_back_val();
    if (!Seen.insert(V).second) continue;
    if (V->getType()->isPointerTy()) Add(V);
    for (const Use &U : cast<Constant>(V)->operands()) if (isa<Constant>(U.get())) Constants.push_back(U.get());
  }
  auto TaintSelections = [&](const BranchInst &Branch) -> Error {
    // A PHI selects by its incoming edge. Compare the edges reachable from
    // each branch outcome, stopping at the join; reachability after the PHI
    // cannot justify its current selection. Cache one traversal per join.
    DenseMap<const BasicBlock *, DenseMap<const BasicBlock *, unsigned>> Joins;
    for (const PHINode *Phi : Phis) {
      if (!Work.spend()) return failure("MBPF320", "pointer control-selection budget exhausted");
      if (Phi->getNumIncomingValues() < 2) continue;
      bool SameValue = true;
      for (const Value *Incoming : Phi->incoming_values()) {
        if (!Work.spend()) return failure("MBPF320", "pointer PHI-value budget exhausted");
        SameValue &= Incoming == Phi->getIncomingValue(0);
      }
      if (SameValue) continue;
      const BasicBlock *Join = Phi->getParent();
      auto Found = Joins.find(Join);
      if (Found == Joins.end()) {
        DenseMap<const BasicBlock *, unsigned> Reachable;
        for (unsigned Edge = 0; Edge != 2; ++Edge) {
          if (Branch.getSuccessor(Edge) == Join)
            Reachable[Branch.getParent()] |= 1u << Edge;
          SmallPtrSet<const BasicBlock *, 32> Visited;
          SmallVector<const BasicBlock *, 16> Frontier{Branch.getSuccessor(Edge)};
          while (!Frontier.empty()) {
            if (!Work.spend()) return failure("MBPF320", "pointer control-reachability budget exhausted");
            const BasicBlock *BB = Frontier.pop_back_val();
            if (BB == Join || !Visited.insert(BB).second) continue;
            Reachable[BB] |= 1u << Edge;
            for (const BasicBlock *Successor : successors(BB)) {
              if (!Work.spend()) return failure("MBPF320", "pointer control-edge budget exhausted");
              Frontier.push_back(Successor);
            }
          }
        }
        Found = Joins.try_emplace(Join, std::move(Reachable)).first;
      }
      for (unsigned Left = 0; Left < Phi->getNumIncomingValues(); ++Left)
        for (unsigned Right = Left + 1; Right < Phi->getNumIncomingValues(); ++Right) {
          if (!Work.spend()) return failure("MBPF320", "pointer PHI-selection budget exhausted");
          unsigned L = Found->second.lookup(Phi->getIncomingBlock(Left));
          unsigned R = Found->second.lookup(Phi->getIncomingBlock(Right));
          // A one-outcome guard does not select the join's payload. When
          // both outcomes can reach unequal values, even identical possible
          // edge sets do not prove independence from the address predicate.
          if (L && R && (L | R) == 3 &&
              Phi->getIncomingValue(Left) != Phi->getIncomingValue(Right))
            Add(Phi);
        }
    }
    return Error::success();
  };
  // Each value is enqueued once. Explicit SSA joins and PHI edge selection
  // retain address taint. A scalar load reads payload, not its address.
  while (!Pending.empty()) {
    if (!Work.spend()) return failure("MBPF320", "pointer taint budget exhausted");
    const Value *V = Pending.pop_back_val();
    if (!V->hasUseList()) continue; // Untracked uses iterate empty (LLVM 21 did the same).
    for (const User *U : V->users()) {
      if (!Work.spend()) return failure("MBPF320", "pointer use budget exhausted");
      if (auto *Store = dyn_cast<StoreInst>(U)) {
        if (Store->getFunction() == &F && Store->getValueOperand() == V)
          return failure("MBPF316", "pointer/address-derived value or control predicate cannot become stored payload", Store);
        continue;
      }
      if (const auto *Branch = dyn_cast<BranchInst>(U)) {
        if (Branch->getFunction() == &F && Branch->isConditional() && Branch->getCondition() == V)
          if (auto E = TaintSelections(*Branch)) return E;
        continue;
      }
      if (auto *I = dyn_cast<Instruction>(U)) {
        if (I->getFunction() != &F || isa<LoadInst>(I) || isa<CallBase>(I) || I->getType()->isVoidTy()) continue;
        Add(I);
      } else if (isa<ConstantExpr>(U) || isa<ConstantAggregate>(U)) {
        Add(U);
      }
    }
  }
  return Error::success();
}

Expected<ValidatedProgram> auditSource(Module &M, const LoweringSpec &Spec, const TargetFacts &Facts) {
  std::string VerifierText;
  raw_string_ostream Verifier(VerifierText);
  if (verifyModule(M, &Verifier))
    return compilerError("MBPF106", "adapter.verify", "source factory requires LLVM verification: " + VerifierText);
  auto Measured = inspectTargetModel(M, Spec);
  if (!Measured) return Measured.takeError();
  if (Facts.InputTriple != Measured->InputTriple || Facts.InputLayout != Measured->InputLayout ||
      Facts.TargetTriple != Measured->TargetTriple || Facts.TargetLayout != Measured->TargetLayout ||
      Facts.Measured != Measured->Measured || Facts.ProofObligations != Measured->ProofObligations)
    return failure("MBPF319", "caller target facts differ from the model measured for this exact module/request");
  if (!M.getModuleInlineAsm().empty()) return failure("MBPF304", "module assembly is outside the candidate subset");
  if (!M.global_empty() || !M.alias_empty() || !M.ifunc_empty())
    return failure("MBPF309", "input globals/aliases/ifuncs are outside the candidate subset");
  auto *Entry = M.getFunction(Spec.Entry);
  if (!Entry || Entry->isDeclaration()) return failure("MBPF302", "requested entry is absent");
  ValidatedProgram Program(M, *Entry, Spec);
  Program.BoundFacts = Facts;
  auto &C = M.getContext();
  Type *I64 = Type::getInt64Ty(C), *Ptr = PointerType::getUnqual(C);
  for (Function &F : M) {
    if (F.hasMetadata()) return failure("MBPF319", "input function metadata is outside the candidate subset", &F);
    if (&F == Entry) continue;
    if (!F.isDeclaration()) return failure("MBPF309", "extra function definition is outside the single-root slice", &F);
    if (F.isIntrinsic()) return failure("MBPF304", "intrinsic/runtime machinery is outside the candidate subset", &F);
    bool Lookup = F.getName() == "__mojobpf_lookup_v1", Update = F.getName() == "__mojobpf_update_v1";
    if (!Lookup && !Update) return failure("MBPF303", "unreserved declaration", &F);
    if (!Spec.Map || F.getCallingConv() != CallingConv::C ||
        !prototype(F.getFunctionType(), I64, Lookup ? ArrayRef<Type *>({I64, Ptr}) : ArrayRef<Type *>({I64, Ptr, Ptr, I64})))
      return failure("MBPF313", "reserved helper prototype or map contract differs", &F);
  }
  for (const NamedMDNode &N : M.named_metadata()) {
    if (N.getName() != "llvm.module.flags" || N.getNumOperands() != 1)
      return failure("MBPF319", "unknown named metadata or input debug graph");
    const MDNode *Flag = N.getOperand(0);
    if (Flag->getNumOperands() != 3) return failure("MBPF319", "unexpected module flag structure");
    auto *Behavior = mdconst::dyn_extract<ConstantInt>(Flag->getOperand(0));
    auto *Name = dyn_cast<MDString>(Flag->getOperand(1));
    auto *Value = mdconst::dyn_extract<ConstantInt>(Flag->getOperand(2));
    if (!Behavior || !Behavior->getType()->isIntegerTy(32) || Behavior->getZExtValue() != 2 ||
        !Name || Name->getString() != "Debug Info Version" || !Value ||
        !Value->getType()->isIntegerTy(32) || Value->getZExtValue() != 3)
      return failure("MBPF319", "input module flag is outside Debug Info Version 3");
  }
  if (Entry->hasPersonalityFn() || Entry->hasPrefixData() || Entry->hasPrologueData() ||
      Entry->hasGC() || !Entry->getSection().empty() || Entry->getComdat())
    return failure("MBPF304", "entry has unexpected runtime or target-specific properties", Entry);
  Budget Work{DefaultAnalysisBudget};
  auto Ordered = orderedBlocks(*Entry, Work);
  if (!Ordered) return Ordered.takeError();
  if (Ordered->size() != Entry->size()) return failure("MBPF304", "unreachable input baggage is outside the slice");
  DominatorTree DT(*Entry);
  SmallPtrSet<const Value *, 32> SeenConstants;
  for (BasicBlock &BB : *Entry) for (Instruction &I : BB) {
    if (I.hasMetadata()) return failure("MBPF319", "input instruction metadata is outside the candidate subset", &I);
    for (const Use &U : I.operands()) if (auto E = inspectConstants(U.get(), SeenConstants, Work)) return std::move(E);
    if (isa<AllocaInst>(I)) return failure("MBPF310", "user stack allocations are outside the shared-cell slice", &I);
    if (isa<InvokeInst>(I) || isa<LandingPadInst>(I) || isa<ResumeInst>(I) || isa<CallBrInst>(I))
      return failure("MBPF304", "unwind/exception/callbr machinery is outside the slice", &I);
    if (auto *Call = dyn_cast<CallInst>(&I)) {
      if (isa<InlineAsm>(Call->getCalledOperand())) {
        auto Kind = primitive(*Call);
        if (!Kind) return failure("MBPF306", "inline assembly is not an exact reserved primitive", &I);
        PrimitiveBinding Binding{Call, *Kind, 0};
        if (*Kind == PrimitiveKind::Key) {
          if (!Spec.Map || !constant(Call->getArgOperand(0), 0)) return failure("MBPF314", "only array key preparation literal zero is admitted", &I);
          Program.Scratch.Cells[Call] = ScratchCell{CellKind::Key, -4, 4, true, 0};
        } else if (*Kind == PrimitiveKind::Value) {
          if (!Spec.Map) return failure("MBPF314", "value scratch requires the exact array map", &I);
          Program.Scratch.Cells[Call] = ScratchCell{CellKind::Value, -16, 8, false, 0};
          Program.Scratch.InertCalls.insert(Call);
        } else {
          if (*Kind == PrimitiveKind::Map && !Spec.Map) return failure("MBPF314", "map address requires the exact array map", &I);
          Program.Scratch.InertCalls.insert(Call);
        }
        Program.Primitives.push_back(Binding);
      } else {
        auto *Callee = Call->getCalledFunction();
        if (Callee == Entry) return failure("MBPF312", "entry recursion is outside the slice", &I);
        if (!Callee) return failure("MBPF303", "indirect user call is outside the slice", &I);
        if (Callee->isIntrinsic()) return failure("MBPF304", "runtime intrinsic call is outside the slice", &I);
        if (Callee->getName() != "__mojobpf_lookup_v1" && Callee->getName() != "__mojobpf_update_v1")
          return failure("MBPF303", "unreserved runtime/helper call", &I);
        if (Call->getFunctionType() != Callee->getFunctionType() || Call->getCallingConv() != CallingConv::C ||
            Call->hasOperandBundles() || Call->isMustTailCall())
          return failure("MBPF313", "reserved call ABI deviates", &I);
        Program.Helpers.push_back(Call);
        Program.Scratch.InertCalls.insert(Call);
      }
    } else if (isa<CallBase>(I)) {
      return failure("MBPF306", "unsupported call instruction form", &I);
    }
  }
  for (const CallInst *Call : Program.Helpers) {
    const Value *Buffer = Call->getArgOperand(1);
    auto Bound = Program.Scratch.Cells.find(Buffer);
    if (Bound == Program.Scratch.Cells.end() || Bound->second.Kind != CellKind::Key || !Bound->second.Preparation)
      return failure("MBPF314", "helper key operand is not its recognized preparation", Call);
    Program.KeyUses.push_back(KeyUse{Call, Buffer, cast<Instruction>(Buffer), Bound->second.Literal});
  }
  // A non-null map result is a separate allocation, not an unknown alias of
  // the shared r10 cells. Bind this fact before checking intervening stores.
  for (const auto &P : Program.Primitives) {
    if (P.Kind != PrimitiveKind::Reinterpret) continue;
    auto *Lookup = dyn_cast<CallInst>(P.Call->getArgOperand(0));
    if (Lookup && is_contained(Program.Helpers, Lookup) &&
        Lookup->getCalledFunction()->getName() == "__mojobpf_lookup_v1" &&
        checkedLookup(*Lookup, *P.Call, DT))
      Program.Scratch.Cells[P.Call] = ScratchCell{CellKind::Disjoint, 0, 8};
  }
  SmallVector<const Value *, 16> AddressRoots;
  for (const auto &P : Program.Primitives) AddressRoots.push_back(P.Call);
  for (const CallInst *Call : Program.Helpers)
    if (Call->getCalledFunction()->getName() == "__mojobpf_lookup_v1") AddressRoots.push_back(Call);
  if (auto E = auditPointerStores(*Entry, AddressRoots)) return std::move(E);
  if (auto E = auditKeyFreshness(*Entry, Program.Scratch, Program.KeyUses)) return std::move(E);

  DenseMap<const Value *, Provenance> Proven;
  Proven[Entry->getArg(0)] = {Kind::Context, Entry->getArg(0), 0};
  auto Get = [&](const Value *V) -> Provenance {
    auto Found = Proven.find(V);
    if (Found != Proven.end()) return Found->second;
    if (V->getType()->isPointerTy() || isa<ConstantExpr>(V)) return {Kind::Escaped, V, 0};
    return {};
  };
  auto PacketRangeDominates = [&](const Provenance &Address, const Instruction &Use, uint64_t End, bool &FoundEdge) {
    FoundEdge = false;
    for (const auto &Known : Proven) {
      if (Known.second.Category != Kind::Control || Known.second.Origin != Address.Origin) continue;
      auto *Comparison = dyn_cast<ICmpInst>(Known.first);
      if (!Comparison) continue;
      unsigned GoodEdge = Comparison->getPredicate() == ICmpInst::ICMP_UGT ? 1 : 0;
      if (!edgeDominates(*Entry, Comparison, GoodEdge, Use, DT)) continue;
      FoundEdge = true;
      if (Known.second.Offset >= 0 && End <= static_cast<uint64_t>(Known.second.Offset)) return true;
    }
    return false;
  };
  DenseMap<const CallInst *, PrimitiveKind> PrimitiveKinds;
  for (const auto &P : Program.Primitives) PrimitiveKinds[P.Call] = P.Kind;
  DenseMap<const BasicBlock *, unsigned> ValueInitialized;
  for (const BasicBlock *ConstBB : *Ordered) {
    auto *BB = const_cast<BasicBlock *>(ConstBB);
    unsigned Initialized = 0xFF;
    bool HasPredecessor = false;
    for (const BasicBlock *Pred : predecessors(BB)) {
      Initialized &= ValueInitialized.lookup(Pred);
      HasPredecessor = true;
    }
    if (!HasPredecessor) Initialized = 0;
    for (Instruction &I : *BB) {
      if (!Work.spend()) return failure("MBPF320", "provenance analysis budget exhausted", &I);
      Provenance Result;
      if (auto *Call = dyn_cast<CallInst>(&I)) {
        if (auto Found = PrimitiveKinds.find(Call); Found != PrimitiveKinds.end()) {
          switch (Found->second) {
          case PrimitiveKind::Key: Result = {Kind::KeyPointer, Call, 0}; break;
          case PrimitiveKind::Value: Result = {Kind::ValuePointer, Call, 0}; break;
          case PrimitiveKind::Map: Result = {Kind::MapReference, Call, 0}; break;
          case PrimitiveKind::Reinterpret: {
            Provenance Input = Get(Call->getArgOperand(0));
            if (Input.Category == Kind::PacketAddress && Input.Offset == 0)
              Result = {Kind::PacketPointer, Input.Origin, 0};
            else if (Input.Category == Kind::LookupAddress && checkedLookup(*cast<CallInst>(Input.Origin), I, DT)) {
              Result = {Kind::LookupPointer, Input.Origin, 0};
            } else return failure("MBPF314", "tied cast is not a packet address or a dominating non-null lookup", &I);
            break;
          }
          }
        } else {
          bool Lookup = Call->getCalledFunction()->getName() == "__mojobpf_lookup_v1";
          if (Get(Call->getArgOperand(0)).Category != Kind::MapReference ||
              Get(Call->getArgOperand(1)).Category != Kind::KeyPointer)
            return failure("MBPF314", "helper map/key provenance differs", &I);
          if (!Lookup && (Get(Call->getArgOperand(2)).Category != Kind::ValuePointer ||
                          Get(Call->getArgOperand(2)).Offset != 0 || Initialized != 0xFF ||
                          !constant(Call->getArgOperand(3), 0)))
            return failure("MBPF314", "update value is not a fully initialized eight-byte cell or flags are not zero", &I);
          Result = Lookup ? Provenance{Kind::LookupAddress, Call, 0} : Provenance{};
        }
      } else if (auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
        if (GEP->hasNoUnsignedWrap() || (GEP->hasNoUnsignedSignedWrap() && !GEP->isInBounds()))
          return failure("MBPF319", "GEP wrap flags are outside the recorded inbounds proof", &I);
        Provenance Base = Get(GEP->getPointerOperand());
        APInt Offset(64, 0);
        int64_t Total;
        if (!GEP->accumulateConstantOffset(M.getDataLayout(), Offset) || AddOverflow(Base.Offset, Offset.getSExtValue(), Total))
          return failure("MBPF317", "unproved pointer offset", &I);
        int64_t BaseInput = Base.Offset;
        Base.Offset = Total;
        if (GEP->isInBounds() && InboundsScalingOverflows(M.getDataLayout(), GEP, Offset))
          return failure("MBPF317", "inbounds GEP index scaling overflows the recorded offset", &I);
        if (Base.Category == Kind::Context) {
          if (Total != 0 && Total != 4) return failure("MBPF317", "context access leaves the two-u32 prefix", &I);
        } else if (Base.Category == Kind::PacketPointer) {
          if (Total < 0) return failure("MBPF317", "packet offset is outside the proved byte access", &I);
          bool FoundEdge = false;
          // An inbounds GEP asserts BOTH its base address and
          // its endpoint (LangRef getelementptr inbounds): each
          // must sit inside a dominating proved range. Absent
          // dominance stays MBPF314; an exceeded range is
          // MBPF317, mirroring the load rule below.
          if (GEP->isInBounds()) {
            if (BaseInput < 0)
              return failure("MBPF317", "inbounds packet base is outside the proved byte access", &I);
            if (!PacketRangeDominates(Base, I, static_cast<uint64_t>(BaseInput), FoundEdge))
              return FoundEdge
                  ? failure("MBPF317", "inbounds packet base exceeds the proved packet range", &I)
                  : failure("MBPF314", "inbounds packet base lacks a dominating proved range edge", &I);
            if (!PacketRangeDominates(Base, I, static_cast<uint64_t>(Total), FoundEdge))
              return FoundEdge
                  ? failure("MBPF317", "inbounds packet address exceeds the proved packet range", &I)
                  : failure("MBPF314", "inbounds packet address lacks a dominating proved range edge", &I);
          }
        } else if (Base.Category == Kind::KeyPointer || Base.Category == Kind::ValuePointer || Base.Category == Kind::LookupPointer) {
          int64_t Extent = Base.Category == Kind::KeyPointer ? 4 : 8;
          if (Total < 0 || Total >= Extent) return failure("MBPF314", "scratch/map pointer leaves its bounded cell", &I);
        } else return failure("MBPF311", "GEP has unproved pointer provenance", &I);
        Result = Base;
      } else if (auto *Load = dyn_cast<LoadInst>(&I)) {
        Provenance Address = Get(Load->getPointerOperand());
        if (Address.Category == Kind::Context) {
          if (!Load->getType()->isIntegerTy(32) || (Address.Offset != 0 && Address.Offset != 4))
            return failure("MBPF317", "context loads must read the two aligned u32 address words", &I);
          Result = {Address.Offset == 0 ? Kind::DataWord : Kind::EndWord, Entry->getArg(0), 0};
        } else if (Address.Category == Kind::PacketPointer) {
          if (!Load->getType()->isIntegerTy(8) || Address.Offset < 0)
            return failure("MBPF317", "packet load exceeds the admitted byte access", &I);
          bool FoundEdge = false;
          uint64_t End = static_cast<uint64_t>(Address.Offset) + 1;
          if (!PacketRangeDominates(Address, I, End, FoundEdge))
            return FoundEdge
                ? failure("MBPF317", "packet load exceeds the proved packet range", &I)
                : failure("MBPF314", "packet byte load lacks a dominating proved range edge", &I);
        } else if (Address.Category == Kind::LookupPointer || Address.Category == Kind::ValuePointer || Address.Category == Kind::KeyPointer) {
          unsigned Bytes = Load->getType()->isIntegerTy(64) ? 8 : Load->getType()->isIntegerTy(32) ? 4 : Load->getType()->isIntegerTy(8) ? 1 : 0;
          unsigned Extent = Address.Category == Kind::KeyPointer ? 4 : 8;
          if (!Bytes || Address.Offset < 0 || uint64_t(Address.Offset) + Bytes > Extent)
            return failure("MBPF314", "load exceeds its proved cell", &I);
          if (Address.Category == Kind::ValuePointer && Initialized != 0xFF)
            return failure("MBPF314", "scratch load is not fully initialized", &I);
        } else return failure("MBPF311", "load pointer provenance is unproved", &I);
        auto Guaranteed = memoryAlignment(Address);
        if (!Guaranteed || Load->getAlign() > *Guaranteed)
          return failure("MBPF319", "load alignment exceeds its root and accumulated-offset guarantee", &I);
      } else if (auto *Store = dyn_cast<StoreInst>(&I)) {
        Provenance Stored = Get(Store->getValueOperand()), Address = Get(Store->getPointerOperand());
        if (tainted(Stored) || Store->getValueOperand()->getType()->isPointerTy())
          return failure("MBPF316", "pointer/address-derived value or control predicate cannot become stored payload", &I);
        unsigned Bytes = unsigned(M.getDataLayout().getTypeStoreSize(Store->getValueOperand()->getType()).getFixedValue());
        unsigned Extent = Address.Category == Kind::KeyPointer ? 4 : 8;
        if ((Address.Category != Kind::ValuePointer && Address.Category != Kind::LookupPointer && Address.Category != Kind::KeyPointer) ||
            Address.Offset < 0 || uint64_t(Address.Offset) + Bytes > Extent || !scalar(Store->getValueOperand()->getType()))
          return failure("MBPF314", "store exceeds or escapes its proved scratch/map cell", &I);
        auto Guaranteed = memoryAlignment(Address);
        if (!Guaranteed || Store->getAlign() > *Guaranteed)
          return failure("MBPF319", "store alignment exceeds its root and accumulated-offset guarantee", &I);
        if (Address.Category == Kind::ValuePointer)
          for (unsigned Byte = unsigned(Address.Offset); Byte < unsigned(Address.Offset) + Bytes; ++Byte) Initialized |= 1u << Byte;
      } else if (auto *Cast = dyn_cast<CastInst>(&I)) {
        if (isa<PtrToIntInst>(Cast) || isa<IntToPtrInst>(Cast) || isa<AddrSpaceCastInst>(Cast))
          return failure("MBPF311", "ordinary pointer/integer/address-space casts are outside the proof", &I);
        if (!scalar(Cast->getType()) || !scalar(Cast->getOperand(0)->getType()))
          return failure("MBPF305", "cast is outside the scalar model", &I);
        if (Cast->hasPoisonGeneratingFlags())
          return failure("MBPF319", "integer cast flags have no proved defined domain", &I);
        Provenance Input = Get(Cast->getOperand(0));
        if (Input.Category == Kind::DataWord || Input.Category == Kind::EndWord) {
          if (!isa<ZExtInst>(Cast) || !Cast->getType()->isIntegerTy(64)) return failure("MBPF311", "context address word requires its explicit u32-to-u64 extension", &I);
          Result = {Input.Category == Kind::DataWord ? Kind::PacketAddress : Kind::EndAddress, Input.Origin, 0};
        } else if (tainted(Input)) {
          return failure("MBPF311", "integer cast transforms address/control outside its explicit extension proof", &I);
        }
      } else if (auto *Binary = dyn_cast<BinaryOperator>(&I)) {
        if (Binary->getOpcode() == Instruction::UDiv || Binary->getOpcode() == Instruction::SDiv ||
            Binary->getOpcode() == Instruction::URem || Binary->getOpcode() == Instruction::SRem)
          return failure("MBPF319", "unchecked division/remainder/trap semantics are outside the model", &I);
        auto Left = Get(Binary->getOperand(0)), Right = Get(Binary->getOperand(1));
        bool DefinedPacketAdd = false;
        if (Left.Category == Kind::PacketAddress && Binary->getOpcode() == Instruction::Add &&
            Binary->getType()->isIntegerTy(64) && isa<ConstantInt>(Binary->getOperand(1))) {
          const auto &Offset = cast<ConstantInt>(Binary->getOperand(1))->getValue();
          if (Offset.isNegative() || Offset.getActiveBits() > 31) return failure("MBPF319", "packet bound addition domain is unproved", &I);
          // zext(u32) + [0, 2^31-1] is strictly below 2^63, so the
          // observed nuw/nsw flags are defined for every admitted input.
          DefinedPacketAdd = true;
          Result = {Kind::PacketBound, Left.Origin, int64_t(Offset.getZExtValue())};
        } else if (tainted(Left) || tainted(Right)) {
          Result = {Kind::Escaped, &I, 0};
        }
        if (Binary->hasPoisonGeneratingFlags() && !DefinedPacketAdd)
          return failure("MBPF319", "integer overflow/exact flag has no proved defined domain", &I);
        if (Binary->isShift()) {
          const auto *Shift = dyn_cast<ConstantInt>(Binary->getOperand(1));
          if (!Shift || Shift->getValue().uge(Binary->getType()->getIntegerBitWidth()))
            return failure("MBPF319", "shift count has no proved defined domain", &I);
        }
      } else if (auto *Compare = dyn_cast<ICmpInst>(&I)) {
        auto Left = Get(Compare->getOperand(0)), Right = Get(Compare->getOperand(1));
        bool DefinedPacketCompare = Left.Category == Kind::PacketBound && Right.Category == Kind::EndAddress &&
            Left.Origin == Right.Origin &&
            (Compare->getPredicate() == ICmpInst::ICMP_UGT || Compare->getPredicate() == ICmpInst::ICMP_ULE);
        if (Compare->hasSameSign() && !DefinedPacketCompare)
          return failure("MBPF319", "comparison samesign flag has no proved defined domain", &I);
        if (Left.Category == Kind::LookupAddress && constant(Compare->getOperand(1), 0) &&
            (Compare->getPredicate() == ICmpInst::ICMP_EQ || Compare->getPredicate() == ICmpInst::ICMP_NE)) {
          Result = {Kind::Control, Left.Origin, 0};
        } else if (DefinedPacketCompare) {
          Result = {Kind::Control, Left.Origin, Left.Offset};
        } else if (tainted(Left) || tainted(Right)) return failure("MBPF311", "unrecognized address observation/comparison", &I);
      } else if (auto *Select = dyn_cast<SelectInst>(&I)) {
        auto Condition = Get(Select->getCondition()), True = Get(Select->getTrueValue()), False = Get(Select->getFalseValue());
        if (tainted(Condition) || tainted(True) || tainted(False)) Result = {Kind::Escaped, &I, 0};
      } else if (auto *Phi = dyn_cast<PHINode>(&I)) {
        for (const Value *Incoming : Phi->incoming_values()) if (tainted(Get(Incoming))) Result = {Kind::Escaped, &I, 0};
      } else if (auto *Branch = dyn_cast<BranchInst>(&I)) {
        if (Branch->isConditional()) {
          auto Condition = Get(Branch->getCondition());
          if (Condition.Category != Kind::Scalar && Condition.Category != Kind::Control)
            return failure("MBPF311", "branch condition is laundered address data", &I);
        }
      } else if (auto *Return = dyn_cast<ReturnInst>(&I)) {
        if (!Return->getReturnValue() || tainted(Get(Return->getReturnValue())))
          return failure("MBPF311", "entry return leaks address/control data", &I);
      } else {
        return failure("MBPF319", "instruction is outside the finite source subset", &I);
      }
      Proven[&I] = Result;
    }
    ValueInitialized[BB] = Initialized;
  }
  // References have only the narrow consumers whose semantics were proved.
  for (const auto &Known : Proven) {
    auto P = Known.second;
    if (P.Category == Kind::Scalar || P.Category == Kind::Control) continue;
    if (P.Category == Kind::Escaped) return failure("MBPF311", "address is laundered outside the proved uses", Known.first);
    for (const User *U : Known.first->users()) {
      auto *I = dyn_cast<Instruction>(U);
      if (!I) return failure("MBPF311", "address escapes into a non-instruction user", Known.first);
      if (P.Category == Kind::MapReference) {
        auto *Call = dyn_cast<CallInst>(I);
        if (!Call || Call->getCalledFunction() == nullptr || Call->getArgOperand(0) != Known.first)
          return failure("MBPF314", "map reference escapes its reserved helper operand", I);
      }
      if ((P.Category == Kind::KeyPointer || P.Category == Kind::ValuePointer) &&
          !isa<GetElementPtrInst>(I) && !isa<LoadInst>(I) && !isa<StoreInst>(I) && !isa<CallInst>(I))
        return failure("MBPF311", "scratch address has an observable/escaping use", I);
    }
  }
  Program.SourceDigest = sourceDigest(M);
  Program.ValueIdentities = liveIdentities(M);
  return Program;
}

Error auditLoweredCore(const Module &M, const LoweringSpec &Spec,
                       const TargetFacts &Facts, bool Complete) {
  std::string VerifierText;
  raw_string_ostream Verifier(VerifierText);
  if (verifyModule(M, &Verifier))
    return compilerError("MBPF106", "adapter.verify", "lowered module failed LLVM verification: " + VerifierText);
  unsigned Count = 0, Blocks = 0;
  for (const Function &F : M) for (const BasicBlock &BB : F) {
    if (++Blocks > MaxBlocks) return failure("MBPF320", "lowered CFG block limit exhausted");
    for (const Instruction &I : BB)
      if (++Count > MaxInstructions + 2) return failure("MBPF320", "lowered instruction limit exhausted", &I);
  }
  if (!M.getModuleInlineAsm().empty() || !M.alias_empty() || !M.ifunc_empty() || M.size() != 1)
    return failure("MBPF304", "lowered module contains assembly, aliases or extra functions");
  auto *F = M.getFunction(Spec.Entry);
  if (!F || F->isDeclaration() || F->getSection() != Spec.Section || F->hasMetadata() ||
      F->hasPersonalityFn() || F->hasPrefixData() || F->hasPrologueData() || F->hasGC() || F->getComdat())
    return failure("MBPF319", "lowered entry properties differ from the finite target transition");
  if (M.getTargetTriple().str() != "bpfel-unknown-none" || Facts.TargetTriple != M.getTargetTriple().str() ||
      M.getDataLayoutStr() != Facts.TargetLayout)
    return failure("MBPF319", "lowered triple/layout differs from the measured target");
  for (unsigned Slot : F->getAttributes().indexes()) for (Attribute A : F->getAttributes().getAttributes(Slot)) {
    bool Allowed = A.isEnumAttribute() && A.getKindAsEnum() == Attribute::NoUndef && Slot != AttributeList::FunctionIndex;
    if (A.isStringAttribute() && Slot == AttributeList::FunctionIndex)
      Allowed = (A.getKindAsString() == "target-cpu" && A.getValueAsString() == "v3") ||
                (A.getKindAsString() == "target-features" && A.getValueAsString().empty());
    if (!Allowed) return failure("MBPF319", "unexpected lowered function attribute", F);
  }
  if (F->getFnAttribute("target-cpu").getValueAsString() != "v3" ||
      !F->hasFnAttribute("target-features") || !F->getFnAttribute("target-features").getValueAsString().empty())
    return failure("MBPF319", "lowered target attributes are missing or differ", F);
  const auto *License = M.getGlobalVariable("_license"), *Used = M.getGlobalVariable("llvm.used");
  const auto *Map = Spec.Map ? M.getGlobalVariable(Spec.Map->Symbol) : nullptr;
  if (M.global_size() != (Spec.Map ? 3 : 2) || !License || !Used || (Spec.Map && !Map))
    return failure("MBPF309", "lowered globals differ from the generated set");
  auto PlainGlobal = [](const GlobalVariable &G) {
    return G.hasExternalLinkage() && !G.isConstant() && !G.isThreadLocal() && !G.getAddressSpace() &&
           !G.isExternallyInitialized() && !G.hasComdat() && !G.hasDLLImportStorageClass() &&
           !G.hasDLLExportStorageClass() && G.getVisibility() == GlobalValue::DefaultVisibility &&
           G.getUnnamedAddr() == GlobalValue::UnnamedAddr::None;
  };
  const auto *Bytes = dyn_cast_or_null<ConstantDataArray>(License->getInitializer());
  if (!PlainGlobal(*License) || License->getSection() != "license" || License->getAlign() != Align(1) ||
      License->hasMetadata() || !License->getValueType()->isArrayTy() || !Bytes ||
      !Bytes->isString() || Bytes->getAsString() != Spec.KernelLicense + std::string(1, '\0'))
    return failure("MBPF319", "lowered license bytes or properties differ");
  auto *Retained = dyn_cast_or_null<ConstantArray>(Used->getInitializer());
  if (!Used->hasAppendingLinkage() || Used->getSection() != "llvm.metadata" || Used->hasMetadata() ||
      Used->isConstant() || Used->isThreadLocal() || Used->getAddressSpace() || !Retained ||
      Retained->getNumOperands() != (Spec.Map ? 3 : 2))
    return failure("MBPF309", "required llvm.used retention differs");
  SmallPtrSet<const Value *, 4> Retention;
  for (const Use &U : Retained->operands()) Retention.insert(U.get());
  if (Retention.size() != Retained->getNumOperands() || !Retention.contains(F) || !Retention.contains(License) ||
      (Map && !Retention.contains(Map))) return failure("MBPF309", "required entry/globals are not retained exactly");
  if (Map) {
    auto *T = dyn_cast<StructType>(Map->getValueType());
    if (!PlainGlobal(*Map) || Map->getSection() != ".maps" || Map->getAlign() != Align(8) ||
        !isa_and_nonnull<ConstantAggregateZero>(Map->getInitializer()) || !T || T->isPacked() ||
        T->getNumElements() != 4 || M.getDataLayout().getTypeAllocSize(T).getFixedValue() != 32 ||
        M.getDataLayout().getABITypeAlign(T) != Align(8))
      return failure("MBPF314", "generated map global layout differs");
    for (unsigned Index = 0; Index < 4; ++Index)
      if (!T->getElementType(Index)->isPointerTy() || cast<PointerType>(T->getElementType(Index))->getAddressSpace() ||
          M.getDataLayout().getStructLayout(T)->getElementOffset(Index) != Index * 8)
        return failure("MBPF314", "generated map fields differ");
  }
  if (auto E = auditMapMetadata(M, Spec, Complete)) return E;

  // Projection is derived from this module, never from the original source.
  // Only the exact generated forms below can be removed/reified. Every other
  // instruction, operand, CFG edge and memory effect enters the source audit.
  auto Projection = CloneModule(M);
  Function &Entry = *Projection->getFunction(Spec.Entry);
  Entry.setSection("");
  Entry.removeFnAttr("target-cpu");
  Entry.removeFnAttr("target-features");
  Projection->setTargetTriple(Triple("x86_64-unknown-linux-gnu"));
  AllocaInst *KeyCell = nullptr, *ValueCell = nullptr;
  for (BasicBlock &BB : Entry) for (Instruction &I : BB) {
    if (I.hasMetadata()) return failure("MBPF319", "unexpected lowered instruction metadata", &I);
    if (auto *A = dyn_cast<AllocaInst>(&I)) {
      if (&BB != &Entry.getEntryBlock() || !A->isStaticAlloca() || !constant(A->getArraySize(), 1) ||
          A->getAddressSpace() || A->isUsedWithInAlloca() || A->isSwiftError())
        return failure("MBPF310", "generated cell is not a fixed entry alloca", &I);
      AllocaInst **Cell;
      if (A->getAllocatedType()->isIntegerTy(32) && A->getAlign() == Align(4)) Cell = &KeyCell;
      else if (A->getAllocatedType()->isIntegerTy(64) && A->getAlign() == Align(8)) Cell = &ValueCell;
      else return failure("MBPF310", "generated cell type/alignment differs", &I);
      if (*Cell || !Spec.Map || A->use_empty()) return failure("MBPF310", "duplicate, unused or unrequested scratch cell", &I);
      *Cell = A;
    }
  }
  auto &C = Projection->getContext();
  Type *I32 = Type::getInt32Ty(C), *I64 = Type::getInt64Ty(C), *Ptr = PointerType::getUnqual(C);
  auto *KeyAsm = InlineAsm::get(FunctionType::get(Ptr, {I32}, false),
      "r0 = r10\nr0 += -4\n*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}", true);
  auto *ValueAsm = InlineAsm::get(FunctionType::get(Ptr, false), "r0 = r10\nr0 += -16", "={r0}", true);
  auto *MapAsm = InlineAsm::get(FunctionType::get(I64, false), "r0 = mojobpf_map0 ll", "={r0}", true);
  CallInst *ReifiedValue = nullptr;
  if (ValueCell) {
    ReifiedValue = CallInst::Create(ValueAsm->getFunctionType(), ValueAsm, {}, "", ValueCell->getIterator());
    ValueCell->replaceAllUsesWith(ReifiedValue);
    ValueCell->eraseFromParent();
  }
  Budget Work{DefaultAnalysisBudget};
  auto Ordered = orderedBlocks(Entry, Work);
  if (!Ordered) return Ordered.takeError();
  DenseMap<const BasicBlock *, CallInst *> CurrentPreparations;
  SmallVector<Instruction *, 16> Erase;
  for (const BasicBlock *ConstBB : *Ordered) {
    auto *BB = const_cast<BasicBlock *>(ConstBB);
    CallInst *Preparation = nullptr;
    bool First = true;
    for (const BasicBlock *Pred : predecessors(BB)) {
      if (!Work.spend()) return failure("MBPF320", "lowered key edge budget exhausted");
      CallInst *Incoming = CurrentPreparations.lookup(Pred);
      if (First) Preparation = Incoming;
      else if (Preparation != Incoming) Preparation = nullptr;
      First = false;
    }
    for (auto It = BB->begin(); It != BB->end();) {
      Instruction &I = *It++;
      if (!Work.spend()) return failure("MBPF320", "lowered projection budget exhausted", &I);
      if (&I == KeyCell || &I == ReifiedValue) continue;
      if (auto *Store = dyn_cast<StoreInst>(&I)) {
        if (KeyCell && Store->getPointerOperand() == KeyCell && Store->getValueOperand()->getType() == I32 &&
            constant(Store->getValueOperand(), 0) && Store->getAlign() == Align(4) && !Store->isVolatile() && !Store->isAtomic()) {
          Preparation = CallInst::Create(KeyAsm->getFunctionType(), KeyAsm, {Store->getValueOperand()}, "", Store->getIterator());
          Erase.push_back(Store);
          continue;
        }
      }
      for (Use &U : I.operands()) if (KeyCell && U.get() == KeyCell) {
        if (!Preparation) return failure("MBPF318", "lowered key use lacks one dominating preparation identity", &I);
        U.set(Preparation);
      }
      auto *Call = dyn_cast<CallInst>(&I);
      if (!Call) continue;
      if (auto *Asm = dyn_cast<InlineAsm>(Call->getCalledOperand())) {
        auto Kind = primitive(*Call);
        if (!Kind || *Kind != PrimitiveKind::Reinterpret)
          return failure("MBPF306", "lowered asm is not the proved tied reinterpretation", &I);
        continue;
      }
      auto *Callee = dyn_cast<ConstantExpr>(Call->getCalledOperand());
      auto *ID = Callee && Callee->getOpcode() == Instruction::IntToPtr ? dyn_cast<ConstantInt>(Callee->getOperand(0)) : nullptr;
      if (!ID || !ID->getType()->isIntegerTy(64) || (!ID->equalsInt(1) && !ID->equalsInt(2)) || !Spec.Map)
        return failure("MBPF313", "lowered callee is not helper 1/2 at the validated interface", &I);
      bool Lookup = ID->equalsInt(1);
      auto *Expected = FunctionType::get(I64, Lookup ? ArrayRef<Type *>({I64, Ptr}) : ArrayRef<Type *>({I64, Ptr, Ptr, I64}), false);
      if (Call->getFunctionType() != Expected || Call->getCallingConv() != CallingConv::C ||
          Call->hasOperandBundles() || Call->isMustTailCall()) return failure("MBPF313", "numeric helper call ABI differs", &I);
      for (unsigned Slot : Call->getAttributes().indexes()) for (Attribute A : Call->getAttributes().getAttributes(Slot))
        if (!A.isEnumAttribute() || A.getKindAsEnum() != Attribute::NoUndef || Slot == AttributeList::FunctionIndex)
          return failure("MBPF319", "unexpected numeric helper call attribute", &I);
      auto *MapRef = dyn_cast<ConstantExpr>(Call->getArgOperand(0));
      if (!MapRef || MapRef->getOpcode() != Instruction::PtrToInt || MapRef->getType() != I64 ||
          MapRef->getOperand(0) != Projection->getGlobalVariable(Spec.Map->Symbol))
        return failure("MBPF314", "map conversion is outside the named helper interface", &I);
      auto *Reference = CallInst::Create(MapAsm->getFunctionType(), MapAsm, {}, "", Call->getIterator());
      Call->setArgOperand(0, Reference);
      auto Decl = Projection->getOrInsertFunction(Lookup ? "__mojobpf_lookup_v1" : "__mojobpf_update_v1", Expected);
      Call->setCalledOperand(Decl.getCallee());
    }
    CurrentPreparations[BB] = Preparation;
  }
  for (Instruction *I : Erase) I->eraseFromParent();
  if (KeyCell) {
    if (!KeyCell->use_empty()) return failure("MBPF311", "unmatched lowered key cell use");
    KeyCell->eraseFromParent();
  }
  // Any surviving global/constant expression use is unexpected. Only the
  // checked used-list and map-interface conversions may refer to globals.
  auto *ProjectionUsed = Projection->getGlobalVariable("llvm.used");
  ProjectionUsed->eraseFromParent();
  for (auto I = Projection->global_begin(), E = Projection->global_end(); I != E;) {
    GlobalVariable &G = *I++;
    G.removeDeadConstantUsers();
    if (!G.use_empty()) return failure("MBPF311", "generated global has an escaping or unmatched use", &G);
    G.eraseFromParent();
  }
  for (auto I = Projection->named_metadata_begin(), E = Projection->named_metadata_end(); I != E;) {
    NamedMDNode &N = *I++;
    if (N.getName() != "llvm.module.flags") N.eraseFromParent();
  }
  auto Measured = inspectTargetModel(*Projection, Spec);
  if (!Measured) return Measured.takeError();
  if (Measured->TargetLayout != M.getDataLayoutStr())
    return failure("MBPF319", "actual backend target layout differs from the selected machine");
  auto Source = auditSource(*Projection, Spec, *Measured);
  if (!Source) return Source.takeError();
  return Error::success();
}

Error auditLowered(const Module &M, const LoweringSpec &Spec, const TargetFacts &Facts) {
  return auditLoweredCore(M, Spec, Facts, true);
}
} // namespace mojobpf
