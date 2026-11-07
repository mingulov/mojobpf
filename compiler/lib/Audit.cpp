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
#include "llvm/IR/DebugInfoMetadata.h"
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
#include <utility>

using namespace llvm;
namespace mojobpf {
Error auditMapMetadata(const Module &, const LoweringSpec &, bool);
Error auditLoweredCore(const Module &, const LoweringSpec &, const TargetFacts &, bool, bool Permissive = false);
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

// F-ISA/alu/arith64: the only admitted division/remainder shape is a
// 64-bit unsigned operation with a nonzero constant divisor (the
// divisor is provably nonzero, so the operation cannot trap). Every
// other shape is refused under MBPF319: non-64-bit forms name the
// deferred slice they belong to; all other shapes keep the
// established unchecked explanation. Admission is about the IR
// shape, not the selected encoding: the backend emits K-form when
// the divisor fits the 32-bit immediate field and otherwise
// materializes larger divisors in a register (X-form) or reduces
// powers of two to shifts/masks. Shared by the entry and subprogram
// audits so the two sites cannot diverge. Returns the refusal
// explanation, or nullopt when the operation is admitted (or is not
// div/rem).
std::optional<std::string> checkedDivRefusal(const BinaryOperator &Binary) {
  unsigned Opcode = Binary.getOpcode();
  if (Opcode != Instruction::UDiv && Opcode != Instruction::SDiv &&
      Opcode != Instruction::URem && Opcode != Instruction::SRem)
    return std::nullopt;
  if (!Binary.getType()->isIntegerTy(64))
    return "division/remainder outside the 64-bit arithmetic slice is deferred to the 32-bit stage";
  if (Opcode == Instruction::SDiv || Opcode == Instruction::SRem)
    return "unchecked division/remainder/trap semantics are outside the model";
  const auto *Divisor = dyn_cast<ConstantInt>(Binary.getOperand(1));
  if (!Divisor || Divisor->isZero())
    return "unchecked division/remainder/trap semantics are outside the model";
  return std::nullopt;
}

// Permissive proof: the enumerated downgrade sites record the
// unproved property and continue with the lattice's natural
// (conservative) value instead of refusing. The strict proof is
// unchanged: every site still refuses when Permissive is false.
struct UnprovedSink {
  bool Permissive = false;
  json::Array Recorded;
  size_t Total = 0;
  static constexpr size_t Cap = 8;
  void record(StringRef Code, StringRef Explanation, const Value *V) {
    ++Total;
    if (Recorded.size() >= Cap) return;
    CompilerError Entry(Code, Code == "MBPF320" ? "adapter.resource" :
                        Code == "MBPF319" ? "adapter.target" : "adapter.audit",
                        Explanation, V ? location(*V) : "module",
                        "use the documented candidate subset");
    Entry.Severity = "warning";
    Recorded.push_back(Entry.diagnostic());
  }
};

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
                  LookupPointer, KeyPointer, ValuePointer, Control, Escaped,
                  RingbufReference, EventRecord, ReservationAddress,
                  ReservationPointer };
struct Provenance {
  Kind Category = Kind::Scalar;
  const Value *Origin = nullptr;
  int64_t Offset = 0;
};
std::optional<Align> memoryAlignment(const Provenance &Address, unsigned ContextRoot = 4) {
  unsigned Root;
  switch (Address.Category) {
  case Kind::Context: Root = ContextRoot; break;
  case Kind::KeyPointer: Root = 4; break;
  case Kind::ValuePointer: case Kind::LookupPointer:
  case Kind::ReservationPointer: Root = 8; break;
  case Kind::EventRecord: Root = 8; break;
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
  // The hash kind tag wraps a map address (i64 in and out, empty
  // template, sideeffect marker). The percpu spell stays
  // unrecognized until its kind flips (a later T4a-3 commit).
  if (Text.empty() && Constraints == "=r,0" && Asm->hasSideEffects() &&
      prototype(Asm->getFunctionType(), I64, {I64})) return PrimitiveKind::HashTag;
  // The LRU kind tag wraps a map address the same way, with a
  // memory clobber the hash shape never carries.
  if (Text.empty() && Constraints == "=r,0,~{memory}" && Asm->hasSideEffects() &&
      prototype(Asm->getFunctionType(), I64, {I64})) return PrimitiveKind::LruTag;
  // The percpu kind tag wraps a map address with no sideeffect
  // marker. The return type keeps it disjoint from Reinterpret
  // (i64 out here, pointer out there).
  if (Text.empty() && Constraints == "=r,0" && !Asm->hasSideEffects() &&
      prototype(Asm->getFunctionType(), I64, {I64})) return PrimitiveKind::PercpuTag;
  // The ring-buffer companion address (second map, mojobpf_map1;
  // the memory clobber keeps it disjoint from the keyed map).
  if (Text == "r0 = mojobpf_map1 ll" && Constraints == "={r0},~{memory}" &&
      Asm->hasSideEffects() && prototype(Asm->getFunctionType(), I64, {})) return PrimitiveKind::RingbufMap;
  // The ring-size tag ties the ring-buffer address to the
  // audited size literal (two inputs, empty template, no
  // sideeffect marker). The literal is checked at the walk
  // site against the qualified ring-buffer sizes.
  if (Text.empty() && Constraints == "=r,0,r" && !Asm->hasSideEffects() &&
      prototype(Asm->getFunctionType(), I64, {I64, I64})) return PrimitiveKind::RingSizeTag;
  // The event record views: r10-relative slot preparations at
  // the seven record field offsets (the -64 base twice: the
  // output data operand and the version field). The memory
  // clobber keeps them disjoint from the value slot.
  if (Constraints == "={r0},~{memory}" && Asm->hasSideEffects() &&
      prototype(Asm->getFunctionType(), Ptr, {})) {
    for (StringRef Spelling : {"r0 = r10\nr0 += -64", "r0 = r10\nr0 += -62",
                               "r0 = r10\nr0 += -60", "r0 = r10\nr0 += -56",
                               "r0 = r10\nr0 += -52", "r0 = r10\nr0 += -48",
                               "r0 = r10\nr0 += -40"})
      if (Text == Spelling) return PrimitiveKind::EventSlot;
  }
  return std::nullopt;
}

// Record-field offset of an event-slot view (0..24 into the
// 32-byte record); nullopt unless the call is exactly one.
std::optional<uint32_t> eventSlotOffset(const CallInst &Call) {
  const auto *Asm = dyn_cast<InlineAsm>(Call.getCalledOperand());
  if (!Asm) return std::nullopt;
  StringRef Text = Asm->getAsmString();
  for (auto [Spelling, Offset] : {std::pair<StringRef, uint32_t>{"r0 = r10\nr0 += -64", 0},
                                  {"r0 = r10\nr0 += -62", 2},
                                  {"r0 = r10\nr0 += -60", 4},
                                  {"r0 = r10\nr0 += -56", 8},
                                  {"r0 = r10\nr0 += -52", 12},
                                  {"r0 = r10\nr0 += -48", 16},
                                  {"r0 = r10\nr0 += -40", 24}})
    if (Text == Spelling) return Offset;
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
    // A single boolean negation of the null check guards the
    // flipped edge (the inverted reserve null check).
    for (const User *W : Compare->users()) {
      auto *Xor = dyn_cast<BinaryOperator>(W);
      if (!Xor || Xor->getOpcode() != Instruction::Xor || !Xor->getType()->isIntegerTy(1)) continue;
      const Value *Other = Xor->getOperand(0) == Compare ? Xor->getOperand(1) :
          Xor->getOperand(1) == Compare ? Xor->getOperand(0) : nullptr;
      auto *One = dyn_cast_or_null<ConstantInt>(Other);
      if (!Other || !One || !One->isOne()) continue;
      if (Compare->getPredicate() == ICmpInst::ICMP_EQ && edgeDominates(*Lookup.getFunction(), Xor, 0, Use, DT)) return true;
      if (Compare->getPredicate() == ICmpInst::ICMP_NE && edgeDominates(*Lookup.getFunction(), Xor, 1, Use, DT)) return true;
    }
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
  // The resolver accumulates offsets into 64-bit APInts, which the
  // accumulator requires to match the index width exactly. Standalone
  // drivers reach this entry without the admission layout guard, so
  // enforce it here; auditSource callers already satisfy it.
  if (DL.getIndexSizeInBits(0) != 64)
    return failure("MBPF319", "key analysis requires 64-bit AS0 GEP index width");
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
  // Re-verification follows the same downgrade decisions; the
  // obligations were recorded once at construction.
  auto Current = auditSource(*BoundModule, BoundSpec, *Facts, PermissiveAudit);
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
  // The transition re-audit follows the construction downgrade decisions.
  if (auto E = auditLoweredCore(*BoundModule, BoundSpec, BoundFacts, false, PermissiveAudit)) return E;
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

Expected<ValidatedProgram> auditSource(Module &M, const LoweringSpec &Spec, const TargetFacts &Facts, bool Permissive) {
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
  Program.PermissiveAudit = Permissive;
  UnprovedSink Sink{Permissive};
  auto Downgrade = [&](StringRef Code, StringRef Explanation, const Value *V) -> Error {
    if (!Sink.Permissive) return failure(Code, Explanation, V);
    Sink.record(Code, Explanation, V);
    return Error::success();
  };
  auto &C = M.getContext();
  Type *I32 = Type::getInt32Ty(C), *I64 = Type::getInt64Ty(C), *Ptr = PointerType::getUnqual(C);
  for (Function &F : M) {
    if (F.hasMetadata()) return failure("MBPF319", "input function metadata is outside the candidate subset", &F);
    if (&F == Entry) continue;
    if (!F.isDeclaration()) {
      // At most one extra definition: the admitted (i64)->i64
      // subprogram, and only under the subprog profile.
      if (Spec.ProfileID != "linux-bpfel-v3-subprog" || Program.BoundCallee)
        return failure("MBPF309", "extra function definition is outside the admitted entry-plus-one-callee slice", &F);
      StringRef Name = F.getName();
      if (Name == Spec.Entry || Name.starts_with("__mojobpf_") || Name.starts_with("llvm."))
        return failure("MBPF303", "subprogram name is reserved", &F);
      if (Name.empty() || !(isAlpha(Name.front()) || Name.front() == '_') ||
          !all_of(Name, [](char C) { return isAlnum(C) || C == '_'; }))
        return failure("MBPF302", "subprogram name is not a plain C identifier", &F);
      if (F.getLinkage() != GlobalValue::ExternalLinkage || !F.isDSOLocal() ||
          !prototype(F.getFunctionType(), I64, {I64}) || F.getCallingConv() != CallingConv::C ||
          F.hasPersonalityFn() || F.hasPrefixData() || F.hasPrologueData() ||
          F.hasGC() || !F.getSection().empty() || F.getComdat())
        return failure("MBPF302", "subprogram is not a dso_local C-ABI (i64)->i64 definition", &F);
      if (!F.hasFnAttribute(Attribute::NoInline))
        return failure("MBPF302", "subprogram must carry the noinline marker", &F);
      Program.BoundCallee = &F;
      continue;
    }
    if (F.isIntrinsic()) return failure("MBPF304", "intrinsic/runtime machinery is outside the candidate subset", &F);
    bool Lookup = F.getName() == "__mojobpf_lookup_v1", Update = F.getName() == "__mojobpf_update_v1",
         Delete = F.getName() == "__mojobpf_delete_elem_v1", Pid = F.getName() == "__mojobpf_get_pid_tgid_v1",
         Cpu = F.getName() == "__mojobpf_get_smp_processor_id_v1", Ktime = F.getName() == "__mojobpf_ktime_get_ns_v1",
         Output = F.getName() == "__mojobpf_ringbuf_output_v1",
         Reserve = F.getName() == "__mojobpf_ringbuf_reserve_v1",
         Submit = F.getName() == "__mojobpf_ringbuf_submit_v1",
         Discard = F.getName() == "__mojobpf_ringbuf_discard_v1",
         CoreRead = F.getName() == "__mojobpf_core_read_task_pid_v1",
         CoreExists = F.getName() == "__mojobpf_core_exists_task_scx_v1",
         SkbLoad = F.getName() == "__mojobpf_skb_load_bytes_v1",
         SkbStore = F.getName() == "__mojobpf_skb_store_bytes_v1";
    if (!Lookup && !Update && !Delete && !Pid && !Cpu && !Ktime && !Output && !Reserve && !Submit && !Discard &&
        !CoreRead && !CoreExists && !SkbLoad && !SkbStore)
      return failure("MBPF303", "unreserved declaration", &F);
    bool Proto;
    if (Update) Proto = prototype(F.getFunctionType(), I64, {I64, Ptr, Ptr, I64});
    else if (Output) Proto = prototype(F.getFunctionType(), I64, {I64, Ptr, I64, I64});
    else if (Reserve) Proto = prototype(F.getFunctionType(), I64, {I64, I64, I64});
    else if (Submit || Discard) Proto = prototype(F.getFunctionType(), I64, {Ptr, I64});
    else if (Pid || Cpu || Ktime) Proto = prototype(F.getFunctionType(), I64, {});
    else if (CoreRead) Proto = prototype(F.getFunctionType(), I32, {Ptr});
    else if (CoreExists) Proto = prototype(F.getFunctionType(), I32, {});
    else if (SkbLoad) Proto = prototype(F.getFunctionType(), I64, {Ptr, I32, Ptr, I32});
    else if (SkbStore) Proto = prototype(F.getFunctionType(), I64, {Ptr, I32, Ptr, I32, I64});
    else Proto = prototype(F.getFunctionType(), I64, {I64, Ptr});
    // The packet helpers are the only mapless declarations (the
    // socket load and the TC store carry no map contract); every
    // other helper still needs its map.
    bool NeedsMap = !SkbLoad && !SkbStore;
    if ((NeedsMap && !Spec.Map) || F.getCallingConv() != CallingConv::C || !Proto)
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
  if (Entry->hasFnAttribute(Attribute::NoInline))
    return failure("MBPF302", "entrypoint must reference the plain attribute set", Entry);
  Budget Work{DefaultAnalysisBudget};
  auto Ordered = orderedBlocks(*Entry, Work);
  if (!Ordered) return Ordered.takeError();
  if (Ordered->size() != Entry->size()) return failure("MBPF304", "unreachable input baggage is outside the slice");
  DominatorTree DT(*Entry);
  SmallPtrSet<const Value *, 32> SeenConstants;
  unsigned SubprogCalls = 0;
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
          // Dense keys 0..N-1 share one key cell (sequential
          // reuse: each preparation stores its literal before
          // its helper call). Density is verified after the
          // walk, once the pair/delete counts are known.
          const auto *Literal = dyn_cast<ConstantInt>(Call->getArgOperand(0));
          if (!Literal)
            return failure("MBPF314", "key preparation literal is not a constant", &I);
          if (Spec.Map && Literal->getValue().uge(Spec.Map->MaxEntries))
            return failure("MBPF314", "array key preparation literal is outside the dense map entries", &I);
          // Mapless programs use the key cell as the packet
          // buffer (any u32 initializer: the load overwrites
          // it, the store payload is the program's own byte);
          // the skb vector arms pin the per-shape multiset.
          Binding.Literal = (uint32_t)Literal->getZExtValue();
          Program.Scratch.Cells[Call] = ScratchCell{CellKind::Key, -4, 4, true, Binding.Literal};
        } else if (*Kind == PrimitiveKind::Value) {
          if (!Spec.Map) return failure("MBPF314", "value scratch requires the exact array map", &I);
          Program.Scratch.Cells[Call] = ScratchCell{CellKind::Value, -16, 8, false, 0};
          Program.Scratch.InertCalls.insert(Call);
        } else if (*Kind == PrimitiveKind::RingbufMap) {
          // The ring-buffer companion address carries no
          // contract of its own (the spec maps only the
          // keyed state map); the size tag and the output
          // arm reconcile it at their walk sites.
          Program.Scratch.InertCalls.insert(Call);
        } else if (*Kind == PrimitiveKind::RingSizeTag) {
          // The tag claims a ring-buffer operand of a
          // qualified size; the operand check recomputes
          // the primitive directly, and the literal must
          // be a qualified ring-buffer size (the lowering
          // stamps it into the companion debuginfo).
          const auto *Input = dyn_cast<CallInst>(Call->getArgOperand(0));
          auto InputKind = Input ? primitive(*Input) : std::nullopt;
          if (!InputKind || *InputKind != PrimitiveKind::RingbufMap)
            return failure("MBPF314", "ring-size tag operand is not the ring-buffer address", &I);
          const auto *Size = dyn_cast<ConstantInt>(Call->getArgOperand(1));
          if (!Size || (Size->getZExtValue() != 4096 && Size->getZExtValue() != 131072))
            return failure("MBPF314", "ring-size tag literal is outside the qualified ring-buffer sizes", &I);
          Binding.Literal = (uint32_t)Size->getZExtValue();
          Program.Scratch.InertCalls.insert(Call);
        } else if (*Kind == PrimitiveKind::EventSlot) {
          // A record field view: a shared-frame cell at its
          // exact r10 offset (never a key preparation), so
          // key freshness resolves its stores as
          // non-overlapping. The binding literal is the
          // record-relative field offset for the lowering.
          auto Offset = eventSlotOffset(*Call);
          if (!Offset)
            return failure("MBPF306", "event-slot view is outside the record field offsets", &I);
          Program.Scratch.Cells[Call] = ScratchCell{CellKind::Event, int64_t(*Offset) - 64, 8, false, 0};
          Binding.Literal = *Offset;
          Program.Scratch.InertCalls.insert(Call);
        } else if (*Kind == PrimitiveKind::HashTag) {
          // The tag claims a hash map operand; the contract must
          // agree (an array program against a hash map, or vice
          // versa, is a cross-kind confusion, never a lowering).
          // The operand check recomputes the primitive directly,
          // so it holds regardless of walk order.
          if (!Spec.Map || Spec.Map->Type != 1)
            return failure("MBPF314", "hash tag needs the exact hash map contract", &I);
          const auto *Input = dyn_cast<CallInst>(Call->getArgOperand(0));
          auto InputKind = Input ? primitive(*Input) : std::nullopt;
          if (!InputKind || *InputKind != PrimitiveKind::Map)
            return failure("MBPF314", "hash tag operand is not the map address", &I);
          // No literal: only Key bindings carry one (multiplicity
          // checks filter on Key), like the Map primitive.
          Program.Scratch.InertCalls.insert(Call);
        } else if (*Kind == PrimitiveKind::LruTag) {
          // The tag claims an LRU map operand; the contract must
          // agree (a cross-kind confusion is never a lowering).
          // The operand check recomputes the primitive directly,
          // so it holds regardless of walk order.
          if (!Spec.Map || Spec.Map->Type != 9)
            return failure("MBPF314", "lru tag needs the exact lru map contract", &I);
          const auto *Input = dyn_cast<CallInst>(Call->getArgOperand(0));
          auto InputKind = Input ? primitive(*Input) : std::nullopt;
          if (!InputKind || *InputKind != PrimitiveKind::Map)
            return failure("MBPF314", "lru tag operand is not the map address", &I);
          // No literal: only Key bindings carry one (multiplicity
          // checks filter on Key), like the Map primitive.
          Program.Scratch.InertCalls.insert(Call);
        } else if (*Kind == PrimitiveKind::PercpuTag) {
          // The tag claims a percpu map operand; the contract
          // must agree (a cross-kind confusion is never a
          // lowering). The operand check recomputes the
          // primitive directly, so it holds regardless of walk
          // order.
          if (!Spec.Map || Spec.Map->Type != 6)
            return failure("MBPF314", "percpu tag needs the exact percpu map contract", &I);
          const auto *Input = dyn_cast<CallInst>(Call->getArgOperand(0));
          auto InputKind = Input ? primitive(*Input) : std::nullopt;
          if (!InputKind || *InputKind != PrimitiveKind::Map)
            return failure("MBPF314", "percpu tag operand is not the map address", &I);
          // No literal: only Key bindings carry one (multiplicity
          // checks filter on Key), like the Map primitive.
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
        if (Callee == Program.BoundCallee) {
          if (!Call->isTailCall() || Call->isMustTailCall() ||
              Call->getFunctionType() != Callee->getFunctionType() ||
              Call->getCallingConv() != CallingConv::C ||
              Call->hasOperandBundles() || Call->getAttributes().getNumAttrSets() != 0)
            return failure("MBPF306", "subprogram call is not the exact tail-call form", &I);
          ++SubprogCalls;
          continue;
        }
        if (Callee->getName() != "__mojobpf_lookup_v1" && Callee->getName() != "__mojobpf_update_v1" &&
            Callee->getName() != "__mojobpf_delete_elem_v1" && Callee->getName() != "__mojobpf_get_pid_tgid_v1" &&
            Callee->getName() != "__mojobpf_get_smp_processor_id_v1" && Callee->getName() != "__mojobpf_ktime_get_ns_v1" &&
            Callee->getName() != "__mojobpf_ringbuf_output_v1" && Callee->getName() != "__mojobpf_ringbuf_reserve_v1" &&
            Callee->getName() != "__mojobpf_ringbuf_submit_v1" && Callee->getName() != "__mojobpf_ringbuf_discard_v1" &&
            Callee->getName() != "__mojobpf_core_read_task_pid_v1" &&
            Callee->getName() != "__mojobpf_core_exists_task_scx_v1" &&
            Callee->getName() != "__mojobpf_skb_load_bytes_v1" &&
            Callee->getName() != "__mojobpf_skb_store_bytes_v1")
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
  if (Program.BoundCallee && !SubprogCalls)
    return failure("MBPF307", "subprogram is defined but never called", Program.BoundCallee);
  if (Program.BoundCallee) {
    // The subprogram is pure scalar computation: integer
    // arithmetic, compares, selection and direct control flow.
    // No calls, no memory operations, nothing else.
    Function &G = *Program.BoundCallee;
    for (BasicBlock &BB : G) for (Instruction &I : BB) {
      if (!Work.spend()) return failure("MBPF320", "subprogram analysis budget exhausted", &I);
      if (I.hasMetadata()) return failure("MBPF319", "input instruction metadata is outside the candidate subset", &I);
      for (const Use &U : I.operands()) if (auto E = inspectConstants(U.get(), SeenConstants, Work)) return std::move(E);
      if (auto *Call = dyn_cast<CallInst>(&I)) {
        auto *Target = Call->getCalledFunction();
        if (Target == &G) return failure("MBPF312", "subprogram must not call itself", &I);
        if (Target == Entry) return failure("MBPF312", "subprogram must not call back into the entrypoint", &I);
        if (Target && Target->isIntrinsic())
          return failure("MBPF304", "intrinsic call is not in the audited subset", &I);
        return failure("MBPF303", "subprogram body admits no calls", &I);
      }
      if (isa<CallBase>(I)) return failure("MBPF306", "unsupported call instruction form", &I);
      if (isa<LoadInst>(I))
        return failure("MBPF303", "subprogram body is pure scalar computation and must not load", &I);
      if (isa<StoreInst>(I))
        return failure("MBPF316", "subprogram body is pure scalar computation and must not store", &I);
      if (isa<AllocaInst>(I)) return failure("MBPF310", "user stack allocations are outside the shared-cell slice", &I);
      if (isa<InvokeInst>(I) || isa<LandingPadInst>(I) || isa<ResumeInst>(I) || isa<CallBrInst>(I))
        return failure("MBPF304", "unwind/exception/callbr machinery is outside the slice", &I);
      if (isa<FenceInst>(I) || isa<AtomicCmpXchgInst>(I) || isa<AtomicRMWInst>(I) || isa<VAArgInst>(I))
        return failure("MBPF304", "atomic or varargs machinery is outside the slice", &I);
      if (isa<FCmpInst>(I) || I.getOpcode() == Instruction::FNeg)
        return failure("MBPF305", "floating-point operation is outside the integer model", &I);
      if (isa<ShuffleVectorInst>(I) || isa<ExtractElementInst>(I) || isa<InsertElementInst>(I))
        return failure("MBPF305", "vector operation is outside the integer model", &I);
      if (auto *Binary = dyn_cast<BinaryOperator>(&I)) {
        if (auto Refusal = checkedDivRefusal(*Binary))
          return failure("MBPF319", *Refusal, &I);
        if (!Binary->getType()->isIntegerTy() ||
            !Binary->getOperand(0)->getType()->isIntegerTy() ||
            !Binary->getOperand(1)->getType()->isIntegerTy())
          return failure("MBPF305", "subprogram arithmetic is outside the integer model", &I);
        if (Binary->hasPoisonGeneratingFlags())
          return failure("MBPF319", "integer overflow/exact flag has no proved defined domain", &I);
        if (Binary->isShift()) {
          const auto *Shift = dyn_cast<ConstantInt>(Binary->getOperand(1));
          if (!Shift || Shift->getValue().uge(Binary->getType()->getIntegerBitWidth()))
            return failure("MBPF319", "shift count has no proved defined domain", &I);
        }
        continue;
      }
      if (auto *Compare = dyn_cast<ICmpInst>(&I)) {
        if (!Compare->getOperand(0)->getType()->isIntegerTy() ||
            !Compare->getOperand(1)->getType()->isIntegerTy())
          return failure("MBPF305", "subprogram compare is outside the integer model", &I);
        if (Compare->hasSameSign())
          return failure("MBPF319", "comparison samesign flag has no proved defined domain", &I);
        continue;
      }
      if (auto *Cast = dyn_cast<CastInst>(&I)) {
        if (isa<PtrToIntInst>(Cast) || isa<IntToPtrInst>(Cast) || isa<AddrSpaceCastInst>(Cast))
          return failure("MBPF311", "ordinary pointer/integer/address-space casts are outside the proof", &I);
        if (!scalar(Cast->getType()) || !scalar(Cast->getOperand(0)->getType()))
          return failure("MBPF305", "cast is outside the scalar model", &I);
        if (Cast->hasPoisonGeneratingFlags())
          return failure("MBPF319", "integer cast flags have no proved defined domain", &I);
        continue;
      }
      if (auto *Select = dyn_cast<SelectInst>(&I)) {
        if (!Select->getType()->isIntegerTy() ||
            !Select->getTrueValue()->getType()->isIntegerTy() ||
            !Select->getFalseValue()->getType()->isIntegerTy())
          return failure("MBPF305", "subprogram selection is outside the integer model", &I);
        continue;
      }
      if (auto *Phi = dyn_cast<PHINode>(&I)) {
        if (!Phi->getType()->isIntegerTy())
          return failure("MBPF305", "subprogram phi is outside the integer model", &I);
        continue;
      }
      if (isa<BranchInst>(I) || isa<ReturnInst>(I)) continue;
      return failure("MBPF319", "instruction is outside the admitted pure-scalar vocabulary", &I);
    }
  }
  for (const CallInst *Call : Program.Helpers) {
    StringRef HelperName = Call->getCalledFunction()->getName();
    if (HelperName == "__mojobpf_get_pid_tgid_v1" || HelperName == "__mojobpf_get_smp_processor_id_v1" ||
        HelperName == "__mojobpf_ktime_get_ns_v1" || HelperName == "__mojobpf_ringbuf_output_v1" ||
        HelperName == "__mojobpf_ringbuf_reserve_v1" || HelperName == "__mojobpf_ringbuf_submit_v1" ||
        HelperName == "__mojobpf_ringbuf_discard_v1")
      continue;
    if (HelperName == "__mojobpf_core_exists_task_scx_v1") {
      // The existence check rides the core map contract
      // (the 4096-byte slot the probe reads).
      if (!Spec.Map || Spec.Map->ValueBits != 32768)
        return failure("MBPF313", "relocation helper requires the core map contract", Call);
      continue;
    }
    if (HelperName == "__mojobpf_core_read_task_pid_v1") {
      if (!Spec.Map || Spec.Map->ValueBits != 32768)
        return failure("MBPF313", "relocation helper requires the core map contract", Call);
      // The relocation read takes the checked map value
      // pointer: its operand is the tied reinterpretation
      // of a null-checked lookup, never an arbitrary
      // pointer.
      const auto *Pointer = dyn_cast<CallInst>(Call->getArgOperand(0));
      const CallInst *Lookup = Pointer ? dyn_cast<CallInst>(Pointer->getArgOperand(0)) : nullptr;
      bool Tied = false;
      for (const auto &P : Program.Primitives)
        if (P.Call == Pointer && P.Kind == PrimitiveKind::Reinterpret) Tied = true;
      if (!Pointer || !Lookup || !Tied || !is_contained(Program.Helpers, Lookup) ||
          Lookup->getCalledFunction()->getName() != "__mojobpf_lookup_v1" ||
          !checkedLookup(*Lookup, *Call, DT))
        return failure("MBPF314", "relocation read operand is not its checked map value pointer", Call);
      continue;
    }
    if (HelperName == "__mojobpf_skb_load_bytes_v1" || HelperName == "__mojobpf_skb_store_bytes_v1") {
      // The packet buffer is the third operand (the
      // initialized key slot), not the second: the second is
      // the byte offset. Freshness governs the buffer like
      // any key preparation (the load overwrites it, the
      // store reads it).
      const Value *Buffer = Call->getArgOperand(2);
      auto Bound = Program.Scratch.Cells.find(Buffer);
      if (Bound == Program.Scratch.Cells.end() || Bound->second.Kind != CellKind::Key || !Bound->second.Preparation)
        return failure("MBPF314", "packet buffer operand is not its recognized preparation", Call);
      Program.KeyUses.push_back(KeyUse{Call, Buffer, cast<Instruction>(Buffer), Bound->second.Literal});
      continue;
    }
    const Value *Buffer = Call->getArgOperand(1);
    auto Bound = Program.Scratch.Cells.find(Buffer);
    if (Bound == Program.Scratch.Cells.end() || Bound->second.Kind != CellKind::Key || !Bound->second.Preparation)
      return failure("MBPF314", "helper key operand is not its recognized preparation", Call);
    Program.KeyUses.push_back(KeyUse{Call, Buffer, cast<Instruction>(Buffer), Bound->second.Literal});
  }
  // Dense keys mirror the source-audit rule: pairs carry two
  // preparations per key over 0..N-1 (N = lookup count),
  // deletions one per key (N = delete count). A mixed helper
  // program is outside both slices. Unused preparations fail
  // here too (any gap, surplus key, or wrong multiplicity).
  if (!Program.Helpers.empty()) {
    unsigned Lookups = 0, Updates = 0, Deletes = 0, Pids = 0, Cpus = 0, Ktimes = 0, Outputs = 0,
             Reserves = 0, Submits = 0, Discards = 0, CoreReads = 0, CoreExists = 0,
             SkbLoads = 0, SkbStores = 0;
    for (const CallInst *Call : Program.Helpers) {
      StringRef Name = Call->getCalledFunction()->getName();
      if (Name == "__mojobpf_lookup_v1") ++Lookups;
      else if (Name == "__mojobpf_update_v1") ++Updates;
      else if (Name == "__mojobpf_delete_elem_v1") ++Deletes;
      else if (Name == "__mojobpf_get_pid_tgid_v1") ++Pids;
      else if (Name == "__mojobpf_get_smp_processor_id_v1") ++Cpus;
      else if (Name == "__mojobpf_ktime_get_ns_v1") ++Ktimes;
      else if (Name == "__mojobpf_ringbuf_output_v1") ++Outputs;
      else if (Name == "__mojobpf_ringbuf_reserve_v1") ++Reserves;
      else if (Name == "__mojobpf_ringbuf_submit_v1") ++Submits;
      else if (Name == "__mojobpf_ringbuf_discard_v1") ++Discards;
      else if (Name == "__mojobpf_core_read_task_pid_v1") ++CoreReads;
      else if (Name == "__mojobpf_skb_load_bytes_v1") ++SkbLoads;
      else if (Name == "__mojobpf_skb_store_bytes_v1") ++SkbStores;
      else ++CoreExists;
    }
    if (Deletes > 0 && (Lookups > 0 || Updates > 0 || Pids > 0 || Cpus > 0 || Ktimes > 0 || Outputs > 0 ||
                        Reserves > 0 || Submits > 0 || Discards > 0 || CoreReads > 0 || CoreExists > 0 ||
                        SkbLoads > 0 || SkbStores > 0))
      return failure("MBPF303", "mixed lookup/update/delete helpers are outside the pairs/deletes slices", Program.Helpers.front());
    if (CoreReads > 0 || CoreExists > 0) {
      // The CO-RE probe is one lookup, one relocation
      // read, one existence check, and nothing else. The
      // probe reads a single key, so the density slice
      // below never runs for it; the vector pins here.
      if (CoreReads != 1 || CoreExists != 1 || Lookups != 1 || Updates != 0 || Deletes != 0 ||
          Pids != 0 || Cpus != 0 || Ktimes != 0 || Outputs != 0 || Reserves != 0 || Submits != 0 || Discards != 0 ||
          SkbLoads != 0 || SkbStores != 0)
        return failure("MBPF303", "helper counts are outside the relocation probe vector", Program.Helpers.front());
      std::vector<uint32_t> Keys;
      for (const auto &P : Program.Primitives)
        if (P.Kind == PrimitiveKind::Key) Keys.push_back(P.Literal);
      if (Keys != std::vector<uint32_t>({0}))
        return failure("MBPF314", "relocation probe prepares exactly key 0 once", Program.Helpers.front());
    }
    std::vector<uint32_t> Literals;
    for (const auto &P : Program.Primitives)
      if (P.Kind == PrimitiveKind::Key) Literals.push_back(P.Literal);
    std::sort(Literals.begin(), Literals.end());
    Literals.erase(std::unique(Literals.begin(), Literals.end()), Literals.end());
    // The helper-count vector, classified once. The arms
    // are mutually exclusive: the mixed-helper rule above
    // isolates deletes (every other arm needs a non-delete
    // helper), and every remaining arm pins distinct
    // counts, so these flags equal the chain below.
    bool DeleteArm = Deletes > 0;
    bool PairArm = Lookups > 0 && Lookups == Updates && Pids == 0 && Cpus == 0 && Ktimes == 0 && Outputs == 0 &&
             Reserves == 0 && Submits == 0 && Discards == 0 && CoreReads == 0 && CoreExists == 0 &&
             SkbLoads == 0 && SkbStores == 0;
    bool TracepointArm = Pids == 1 && Lookups == 2 && Updates == 1 && Cpus == 0 && Ktimes == 0 && Outputs == 0 &&
             Reserves == 0 && Submits == 0 && Discards == 0 && CoreReads == 0 && CoreExists == 0 &&
             SkbLoads == 0 && SkbStores == 0;
    bool EventArm = Pids == 2 && Lookups == 4 && Updates == 3 && Cpus == 1 && Ktimes == 1 && Outputs == 1 &&
             Reserves == 0 && Submits == 0 && Discards == 0 && CoreReads == 0 && CoreExists == 0 &&
             SkbLoads == 0 && SkbStores == 0;
    bool UprobeArm = Pids == 0 && Lookups == 2 && Updates == 1 && Cpus == 0 && Ktimes == 0 && Outputs == 0 &&
             Reserves == 0 && Submits == 0 && Discards == 0 && CoreReads == 0 && CoreExists == 0 &&
             SkbLoads == 0 && SkbStores == 0;
    bool ReserveArm = Pids == 2 && Lookups == 4 && Updates == 3 && Cpus == 1 && Ktimes == 1 && Outputs == 0 &&
             Reserves == 1 && ((Submits == 1 && Discards == 0) || (Submits == 0 && Discards == 1)) &&
             CoreReads == 0 && CoreExists == 0 && SkbLoads == 0 && SkbStores == 0;
    bool SocketArm = SkbLoads == 1 && SkbStores == 0 && Lookups == 0 && Updates == 0 && Pids == 0 && Cpus == 0 &&
             Ktimes == 0 && Outputs == 0 && Reserves == 0 && Submits == 0 && Discards == 0 &&
             CoreReads == 0 && CoreExists == 0 && !Spec.Map;
    bool StoreArm = SkbLoads == 0 && SkbStores == 1 && Lookups == 0 && Updates == 0 && Pids == 0 && Cpus == 0 &&
             Ktimes == 0 && Outputs == 0 && Reserves == 0 && Submits == 0 && Discards == 0 &&
             CoreReads == 0 && CoreExists == 0 && !Spec.Map;
    bool LoadmapArm = SkbLoads == 1 && SkbStores == 0 && Lookups == 0 && Updates == 1 && Pids == 0 && Cpus == 0 &&
             Ktimes == 0 && Outputs == 0 && Reserves == 0 && Submits == 0 && Discards == 0 &&
             CoreReads == 0 && CoreExists == 0 && Spec.Map && Spec.Map->Type == 2;
    // Entry/family agreement (mirror of the Lane-A entry
    // rule): each classified body exports its family's
    // entry symbol. This runs for classified programs even
    // when the density slice is skipped; unclassified
    // counts fall through to the MBPF303 below with
    // unchanged codes.
    if (DeleteArm || PairArm) {
      if (Spec.Entry != "xdp_entry")
        return failure("MBPF302", "map body must export xdp_entry", Program.Helpers.front());
    } else if (TracepointArm || EventArm || ReserveArm) {
      if (Spec.Entry != "trace_entry")
        return failure("MBPF302", "tracepoint/event/reserve body must export trace_entry", Program.Helpers.front());
    } else if (UprobeArm) {
      if (Spec.Entry != "uprobe_entry")
        return failure("MBPF302", "uprobe body must export uprobe_entry", Program.Helpers.front());
    } else if (StoreArm) {
      if (Spec.Entry != "tc_entry")
        return failure("MBPF302", "packet-store body must export tc_entry", Program.Helpers.front());
    } else if (SocketArm || LoadmapArm) {
      if (Spec.Entry != "socket_entry" && Spec.Entry != "tc_entry")
        return failure("MBPF302", "socket/loadmap body must export socket_entry or tc_entry", Program.Helpers.front());
    }
    // Single-key lookup/update programs predate the density
    // rule (multi-read register pressure): every preparation
    // stores the same literal, so no cross-key reuse hazard
    // exists; the preparation-operand check above and the
    // key-freshness check below already govern them. Only
    // multi-key programs, every delete program (which has
    // no pre-density coverage), every skb program, and
    // every fixed-vector program (the vector counts demand
    // the exact multiset whatever literals were prepared)
    // take the counts/density slice.
    if (Deletes > 0 || Literals.size() > 1 || SkbLoads > 0 || SkbStores > 0 ||
        TracepointArm || EventArm || UprobeArm || ReserveArm) {
      unsigned Entries = 0, PerKey = 0;
      bool TracepointVector = false, EventVector = false, UprobeVector = false, ReserveVector = false,
           SocketVector = false, StoreVector = false, LoadmapVector = false;
      if (DeleteArm) { Entries = Deletes; PerKey = 1; }
      else if (PairArm) { Entries = Lookups; PerKey = 2; }
      else if (TracepointArm) { Entries = 2; TracepointVector = true; }
      else if (EventArm) { Entries = 4; EventVector = true; }
      else if (UprobeArm) { Entries = 2; UprobeVector = true; }
      else if (ReserveArm) { Entries = 4; ReserveVector = true; }
      else if (SocketArm) { Entries = 1; SocketVector = true; }
      else if (StoreArm) { Entries = 1; StoreVector = true; }
      else if (LoadmapArm) { Entries = 2; LoadmapVector = true; }
      else
        return failure("MBPF303", "helper counts are outside the pairs/deletes slices", Program.Helpers.front());
      std::vector<uint32_t> All;
      for (const auto &P : Program.Primitives)
        if (P.Kind == PrimitiveKind::Key) All.push_back(P.Literal);
      std::vector<uint32_t> Want;
      if (TracepointVector) Want = {0, 1, 1};
      else if (EventVector) Want = {0, 1, 1, 2, 2, 3, 3};
      else if (UprobeVector) Want = {0, 1, 1};
      else if (ReserveVector) Want = {0, 1, 1, 2, 2, 3, 3};
      else if (SocketVector) Want = {0};
      else if (LoadmapVector) Want = {0, 1};
      else if (!StoreVector)
        for (uint32_t Key = 0; Key < Entries; ++Key)
          for (unsigned K = 0; K < PerKey; ++K) Want.push_back(Key);
      std::sort(All.begin(), All.end());
      if (StoreVector) {
        // The store payload is the program's own byte, never a
        // map key: exactly one preparation outside keys 0..1
        // (the keyslot-N class).
        if (All.size() != 1 || All[0] < 2)
          return failure("MBPF314", "packet store prepares exactly one payload slot outside the map keys", Program.Helpers.front());
      } else if (All != Want)
        return failure("MBPF314", "key preparation literals are not dense 0..N-1 for the helper counts", Program.Helpers.front());
      // Key/helper order agreement (mirror of the Lane-A
      // pair/key rules): the multiset above pins which keys
      // exist; this pins which call reads which key, in
      // walker (program) order. Single-literal programs
      // cannot violate it (every pair reads (0,0)), so the
      // gate above stays sound for the pairs arm.
      std::vector<uint32_t> ReadKeys, WrittenKeys;
      for (const auto &U : Program.KeyUses) {
        StringRef Name = U.Call->getCalledFunction()->getName();
        if (Name == "__mojobpf_lookup_v1") ReadKeys.push_back(U.ExpectedLiteral);
        else if (Name == "__mojobpf_update_v1") WrittenKeys.push_back(U.ExpectedLiteral);
      }
      if (TracepointVector || UprobeVector) {
        if (ReadKeys != std::vector<uint32_t>({0, 1}) || WrittenKeys != std::vector<uint32_t>({1}))
          return failure("MBPF314", "filter/count key order is not the (0,1,1) vector", Program.Helpers.front());
      } else if (EventVector || ReserveVector) {
        if (ReadKeys != std::vector<uint32_t>({0, 1, 2, 3}) || WrittenKeys != std::vector<uint32_t>({1, 2, 3}))
          return failure("MBPF314", "filter/pair key order is not the (0,1,2,3)/(1,2,3) vector", Program.Helpers.front());
      } else if (!StoreVector && !SocketVector && !LoadmapVector && Deletes == 0) {
        // Generic pairs (map and combined): the i-th lookup
        // and the i-th update reference one entry; either
        // entry order validates. Deletes carry one key each
        // (the multiset above decides them); the skb arms
        // pin single-key shapes (freshness governs the
        // loadmap buffer/key split).
        if (ReadKeys.size() != WrittenKeys.size())
          return failure("MBPF303", "lookup/update counts disagree outside the pairs slice", Program.Helpers.front());
        for (size_t K = 0; K < ReadKeys.size(); ++K)
          if (ReadKeys[K] != WrittenKeys[K])
            return failure("MBPF314", "lookup/update pair reads and writes different keys", Program.Helpers.front());
      }
      if (EventVector) {
        // The event record carries its eight field views (the
        // -64 base twice: the output data operand and the
        // version field); any other view multiset is a
        // different record layout, never this vector.
        std::vector<uint32_t> Views;
        for (const auto &P : Program.Primitives)
          if (P.Kind == PrimitiveKind::EventSlot) Views.push_back(P.Literal);
        std::sort(Views.begin(), Views.end());
        if (Views != std::vector<uint32_t>({0, 0, 2, 4, 8, 12, 16, 24}))
          return failure("MBPF314", "event record views are not the eight field views of the record layout", Program.Helpers.front());
        unsigned Tags = 0;
        for (const auto &P : Program.Primitives)
          if (P.Kind == PrimitiveKind::RingSizeTag) ++Tags;
        if (Tags != 1)
          return failure("MBPF314", "event vector carries exactly one ring-size tag", Program.Helpers.front());
      }
      if (ReserveVector) {
        // The reservation vector stamps the record into the
        // reservation (no scratch views); exactly one
        // ring-size tag qualifies the companion.
        for (const auto &P : Program.Primitives)
          if (P.Kind == PrimitiveKind::EventSlot)
            return failure("MBPF314", "reservation vector carries no scratch record views", Program.Helpers.front());
        unsigned Tags = 0;
        for (const auto &P : Program.Primitives)
          if (P.Kind == PrimitiveKind::RingSizeTag) ++Tags;
        if (Tags != 1)
          return failure("MBPF314", "reservation vector carries exactly one ring-size tag", Program.Helpers.front());
      }
      if (SocketVector || StoreVector || LoadmapVector) {
        // The skb vectors pin every Lane-A shape count at
        // zero except their own key/helper multiset: no kind
        // tags, no ring-buffer companion, no record views. (A
        // stray map or value cell in a mapless vector is
        // already refused by the Spec.Map arms above; the
        // loadmap cell multiplicity follows the map-slice
        // precedent of no Map/Value counting.)
        for (const auto &P : Program.Primitives)
          if (P.Kind == PrimitiveKind::HashTag || P.Kind == PrimitiveKind::LruTag ||
              P.Kind == PrimitiveKind::PercpuTag || P.Kind == PrimitiveKind::RingbufMap ||
              P.Kind == PrimitiveKind::RingSizeTag || P.Kind == PrimitiveKind::EventSlot)
            return failure("MBPF314", "skb vector carries no kind tags, ring-buffer companion, or record views", Program.Helpers.front());
      }
    }
  }
  if (Program.Helpers.empty())
    for (const auto &P : Program.Primitives) {
      // The packet reinterpretation is the classifier's own
      // cast (address to pointer); every other scratch
      // primitive without a consuming helper is outside
      // every vector.
      if (P.Kind == PrimitiveKind::Reinterpret) continue;
      return failure("MBPF303", "helper-less program carries scratch primitives outside every vector", P.Call);
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

  // The admitted context address words: the xdp two-u32 prefix or
  // the tc data/data_end words (struct __sk_buff u32 offsets 19/20).
  // Tracepoint programs leave the context unused (payload layouts
  // are a separate unimplemented capability): any context use
  // refuses below. Uprobe programs read exactly the pinned x86-64
  // first-argument register word (pt_regs word 14, rdi at byte
  // 112): one address computation off the entry parameter plus
  // one i64 load, enforced at the GEP/load arms and counted
  // below.
  int64_t ContextDataOffset = Spec.ProgramType == "tc" ? 76 : 0;
  bool TraceContext = Spec.ProgramType == "tracepoint";
  bool UprobeContext = Spec.ProgramType == "uprobe";
  unsigned PinnedRegisterReads = 0;
  // The single reservation call and its single terminus (either
  // flavor), when the vector carries them; the count arms pin
  // the multiplicity, the walker pins the operands and order.
  const CallInst *ReserveCall = nullptr, *TerminusCall = nullptr;
  for (const CallInst *Call : Program.Helpers) {
    StringRef Name = Call->getCalledFunction()->getName();
    if (Name == "__mojobpf_ringbuf_reserve_v1") ReserveCall = Call;
    else if (Name == "__mojobpf_ringbuf_submit_v1" || Name == "__mojobpf_ringbuf_discard_v1") TerminusCall = Call;
  }
  struct ReservationStore { int64_t Offset; unsigned Bytes; const Instruction *Where; };
  SmallVector<ReservationStore, 8> ReservationStores;
  SmallVector<const Instruction *, 8> ReservationLoads, ReservationGEPs;
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
  // Map-operand kind consistency: every helper's map operand
  // resolves through kind tags to the map address, and the
  // effective kind (tagged, or array when untagged) must equal
  // the spec map type. Unrecognized operands stay for the
  // provenance check in the walker, which fails them closed.
  if (Spec.Map) {
    for (const CallInst *Helper : Program.Helpers) {
      StringRef HelperName = Helper->getCalledFunction()->getName();
      if (HelperName == "__mojobpf_get_pid_tgid_v1" || HelperName == "__mojobpf_get_smp_processor_id_v1" ||
          HelperName == "__mojobpf_ktime_get_ns_v1" || HelperName == "__mojobpf_ringbuf_output_v1" ||
          HelperName == "__mojobpf_core_read_task_pid_v1" || HelperName == "__mojobpf_core_exists_task_scx_v1")
        continue;
      const Value *Operand = Helper->getArgOperand(0);
      unsigned Kind = 0;
      if (const auto *Call = dyn_cast<CallInst>(Operand)) {
        auto Found = PrimitiveKinds.find(Call);
        if (Found != PrimitiveKinds.end()) {
          if (Found->second == PrimitiveKind::HashTag) Kind = 1;
          else if (Found->second == PrimitiveKind::LruTag) Kind = 9;
          else if (Found->second == PrimitiveKind::PercpuTag) Kind = 6;
          else if (Found->second == PrimitiveKind::Map) Kind = 2;
        }
      }
      if (Kind != 0 && Kind != Spec.Map->Type)
        return failure("MBPF314", "helper map operand kind is not the spec map type", Helper);
    }
  }
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
          case PrimitiveKind::RingbufMap: Result = {Kind::RingbufReference, Call, 0}; break;
          case PrimitiveKind::RingSizeTag: {
            // Transparent copy of the ring-buffer address: the
            // tag marks the operand's size (reconciled with
            // the qualified sizes at admission) and carries
            // the companion's origin.
            Provenance Input = Get(Call->getArgOperand(0));
            if (Input.Category == Kind::RingbufReference)
              Result = {Kind::RingbufReference, Input.Origin, 0};
            break;
          }
          case PrimitiveKind::EventSlot: {
            auto Offset = eventSlotOffset(*Call);
            if (!Offset)
              return failure("MBPF306", "event-slot view is outside the record field offsets", &I);
            Result = {Kind::EventRecord, Call, int64_t(*Offset)};
            break;
          }
          case PrimitiveKind::HashTag:
          case PrimitiveKind::LruTag:
          case PrimitiveKind::PercpuTag: {
            // Transparent copy of the map address: the tag marks
            // the operand's kind (reconciled with the spec at the
            // walk site) and carries the map's origin. All kind
            // tags share this rule; kind identity is enforced at
            // the walk site, not here.
            Provenance Input = Get(Call->getArgOperand(0));
            if (Input.Category == Kind::MapReference)
              Result = {Kind::MapReference, Input.Origin, 0};
            break;
          }
          case PrimitiveKind::Reinterpret: {
            Provenance Input = Get(Call->getArgOperand(0));
            if (Input.Category == Kind::PacketAddress && Input.Offset == 0)
              Result = {Kind::PacketPointer, Input.Origin, 0};
            else if (Input.Category == Kind::LookupAddress && checkedLookup(*cast<CallInst>(Input.Origin), I, DT)) {
              Result = {Kind::LookupPointer, Input.Origin, 0};
            } else if (Input.Category == Kind::ReservationAddress && Input.Origin == ReserveCall &&
                       checkedLookup(*cast<CallInst>(Input.Origin), I, DT)) {
              // The record reinterpretation of the checked
              // single reservation result.
              Result = {Kind::ReservationPointer, Input.Origin, 0};
            } else {
              if (auto E = Downgrade("MBPF314", "tied cast is not a packet address or a dominating non-null lookup", &I))
                return std::move(E);
              if (Input.Category == Kind::LookupAddress)
                // Unchecked lookup result: assume the dominating
                // null check under this obligation (the kernel
                // verifier decides per release); the cell rules
                // admit the dereference like a checked one.
                Result = {Kind::LookupPointer, Input.Origin, 0};
              else {
                // A fresh unmatchable origin: no dominating edge can
                // ever match it, so every access through the
                // unproved pointer obligates at its own site.
                Result = {Kind::PacketPointer, &I, 0};
              }
            }
            break;
          }
          }
        } else if (Call->getCalledFunction() == Program.BoundCallee) {
          // The callee is pure scalar and opaque to the entry
          // proof: its result carries no provenance (fail-closed
          // for address roots, which require proved origins).
        } else {
          StringRef HelperName = Call->getCalledFunction()->getName();
          bool Lookup = HelperName == "__mojobpf_lookup_v1";
          bool Update = HelperName == "__mojobpf_update_v1";
          if (HelperName == "__mojobpf_get_pid_tgid_v1") {
            // The kernel PID/TGID word is pure data (no
            // address material): the result is Scalar.
            if (!Call->arg_empty())
              return failure("MBPF313", "PID/TID call carries operands", &I);
            Result = Provenance{};
          } else if (HelperName == "__mojobpf_get_smp_processor_id_v1") {
            // The CPU number is pure data: the result is
            // Scalar.
            if (!Call->arg_empty())
              return failure("MBPF313", "CPU call carries operands", &I);
            Result = Provenance{};
          } else if (HelperName == "__mojobpf_ktime_get_ns_v1") {
            // The monotonic clock is pure data: the result
            // is Scalar.
            if (!Call->arg_empty())
              return failure("MBPF313", "clock call carries operands", &I);
            Result = Provenance{};
          } else if (HelperName == "__mojobpf_core_read_task_pid_v1") {
            // The relocated pid word is pure data (no
            // address material): the result is Scalar. The
            // operand is the checked map value pointer
            // (pinned structurally before the walk); the
            // walk re-confirms the dereferenceable root.
            if (Call->arg_size() != 1)
              return failure("MBPF313", "relocation read carries no single pointer operand", &I);
            Provenance Pointer = Get(Call->getArgOperand(0));
            if (Pointer.Category != Kind::LookupPointer)
              return failure("MBPF314", "relocation read operand is not its checked map value pointer", &I);
            Result = Provenance{};
          } else if (HelperName == "__mojobpf_core_exists_task_scx_v1") {
            // The relocated existence bit is pure data:
            // the result is Scalar.
            if (!Call->arg_empty())
              return failure("MBPF313", "existence call carries operands", &I);
            Result = Provenance{};
          } else if (HelperName == "__mojobpf_ringbuf_output_v1") {
            // The copy-output call takes the size-tagged
            // ring-buffer address, the prepared record
            // base, the literal record size 32, and the
            // literal flags 0; the status result is Scalar.
            const auto *Tag = dyn_cast<CallInst>(Call->getArgOperand(0));
            auto TagKind = Tag ? PrimitiveKinds.find(Tag) : PrimitiveKinds.end();
            if (TagKind == PrimitiveKinds.end() || TagKind->second != PrimitiveKind::RingSizeTag ||
                Get(Call->getArgOperand(0)).Category != Kind::RingbufReference)
              return failure("MBPF314", "output map is not the size-tagged ring-buffer address", &I);
            Provenance Slot = Get(Call->getArgOperand(1));
            if (Slot.Category != Kind::EventRecord || Slot.Offset != 0)
              return failure("MBPF314", "output data is not the prepared event record base", &I);
            if (!constant(Call->getArgOperand(2), 32) || !constant(Call->getArgOperand(3), 0))
              return failure("MBPF314", "output size and flags are not the 32-byte record submission", &I);
            Result = Provenance{};
          } else if (HelperName == "__mojobpf_ringbuf_reserve_v1") {
            // The reservation call takes the size-tagged
            // ring-buffer address, the literal record size
            // 32, and the literal flags 0; the result is a
            // possibly-null record address (null-checked
            // like a lookup result before reinterpretation).
            const auto *Tag = dyn_cast<CallInst>(Call->getArgOperand(0));
            auto TagKind = Tag ? PrimitiveKinds.find(Tag) : PrimitiveKinds.end();
            if (TagKind == PrimitiveKinds.end() || TagKind->second != PrimitiveKind::RingSizeTag ||
                Get(Call->getArgOperand(0)).Category != Kind::RingbufReference)
              return failure("MBPF314", "reservation map is not the size-tagged ring-buffer address", &I);
            if (!constant(Call->getArgOperand(1), 32) || !constant(Call->getArgOperand(2), 0))
              return failure("MBPF314", "reservation size and flags are not the 32-byte record request", &I);
            Result = {Kind::ReservationAddress, Call, 0};
          } else if (HelperName == "__mojobpf_ringbuf_submit_v1" || HelperName == "__mojobpf_ringbuf_discard_v1") {
            // The terminus takes the record reinterpretation
            // of the single reservation result plus the
            // literal flags 0; the status result is Scalar.
            // Store completeness and before-terminus order
            // are pinned after the walk.
            Provenance Data = Get(Call->getArgOperand(0));
            if (Data.Category != Kind::ReservationPointer || Data.Offset != 0 || Data.Origin != ReserveCall)
              return failure("MBPF314", "terminus data is not the record reinterpretation of the reservation result", &I);
            if (!constant(Call->getArgOperand(1), 0))
              return failure("MBPF314", "terminus flags are not zero", &I);
            Result = Provenance{};
          } else if (HelperName == "__mojobpf_skb_load_bytes_v1" || HelperName == "__mojobpf_skb_store_bytes_v1") {
            // The packet call takes the entry context itself
            // (never a derived address), the byte offset and
            // length as scalar data (a literal or a computed
            // scalar, mirroring the source audit; the kernel
            // fails the call closed on overrun), the packet
            // buffer (the initialized key slot at offset 0),
            // and, for the store, the pinned zero flags; the
            // status result is Scalar.
            bool Store = HelperName == "__mojobpf_skb_store_bytes_v1";
            if (Call->arg_size() != (Store ? 5u : 4u))
              return failure("MBPF313", "packet call arity differs", &I);
            if (Call->getArgOperand(0) != Entry->getArg(0))
              return failure("MBPF314", "packet skb operand is not the entry context", &I);
            if (Get(Call->getArgOperand(1)).Category != Kind::Scalar ||
                Get(Call->getArgOperand(3)).Category != Kind::Scalar)
              return failure("MBPF314", "packet offset and length are scalar data", &I);
            Provenance Buffer = Get(Call->getArgOperand(2));
            if (Buffer.Category != Kind::KeyPointer || Buffer.Offset != 0)
              return failure("MBPF314", "packet buffer is not the initialized key slot", &I);
            if (Store && !constant(Call->getArgOperand(4), 0))
              return failure("MBPF314", "packet store flags are not zero", &I);
            Result = Provenance{};
          } else {
            if (Get(Call->getArgOperand(0)).Category != Kind::MapReference ||
                Get(Call->getArgOperand(1)).Category != Kind::KeyPointer)
              return failure("MBPF314", "helper map/key provenance differs", &I);
            // Delete takes (map, key) like lookup; only update
            // carries the value cell and flags operands.
            if (Update && (Get(Call->getArgOperand(2)).Category != Kind::ValuePointer ||
                           Get(Call->getArgOperand(2)).Offset != 0 || Initialized != 0xFF ||
                           !constant(Call->getArgOperand(3), 0)))
              return failure("MBPF314", "update value is not a fully initialized eight-byte cell or flags are not zero", &I);
            Result = Lookup ? Provenance{Kind::LookupAddress, Call, 0} : Provenance{};
          }
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
          if (TraceContext)
            return failure("MBPF317", "tracepoint programs must not read context payload fields", &I);
          if (UprobeContext) {
            // The pinned register word only: one inbounds i64
            // step of exactly index 14 off the entry parameter
            // (any other element type, index count, or base is
            // a different register and is refused).
            bool Pinned = GEP->isInBounds() && GEP->getSourceElementType()->isIntegerTy(64) &&
                GEP->getNumIndices() == 1 && GEP->getPointerOperand() == Entry->getArg(0);
            if (Pinned) {
              const auto *Index = dyn_cast<ConstantInt>(GEP->getOperand(1));
              Pinned = Index && Index->getValue() == 14 && Total == 112;
            }
            if (!Pinned)
              return failure("MBPF317", "uprobe programs must read exactly the pinned x86-64 first-argument register (context word 14, rdi at byte 112)", &I);
          } else if (Total != ContextDataOffset && Total != ContextDataOffset + 4)
            return failure("MBPF317", "context access leaves the admitted data/data_end words", &I);
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
            if (!PacketRangeDominates(Base, I, static_cast<uint64_t>(BaseInput), FoundEdge)) {
              auto [Code, Explanation] = FoundEdge
                  ? std::pair{"MBPF317", "inbounds packet base exceeds the proved packet range"}
                  : std::pair{"MBPF314", "inbounds packet base lacks a dominating proved range edge"};
              if (auto E = Downgrade(Code, Explanation, &I)) return std::move(E);
            }
            if (!PacketRangeDominates(Base, I, static_cast<uint64_t>(Total), FoundEdge)) {
              auto [Code, Explanation] = FoundEdge
                  ? std::pair{"MBPF317", "inbounds packet address exceeds the proved packet range"}
                  : std::pair{"MBPF314", "inbounds packet address lacks a dominating proved range edge"};
              if (auto E = Downgrade(Code, Explanation, &I)) return std::move(E);
            }
          }
        } else if (Base.Category == Kind::KeyPointer || Base.Category == Kind::ValuePointer || Base.Category == Kind::LookupPointer ||
                   Base.Category == Kind::ReservationPointer) {
          int64_t Extent = Base.Category == Kind::KeyPointer ? 4 : Base.Category == Kind::ReservationPointer ? 32 : 8;
          // Kernel-negative out-of-bounds address: refuse strict,
          // obligate+continue permissive (the kernel verifier
          // decides the access; every access re-obligates).
          if (Total < 0 || Total >= Extent)
            if (auto E = Downgrade("MBPF314", "scratch/map pointer leaves its bounded cell", &I)) return std::move(E);
          if (Base.Category == Kind::ReservationPointer) ReservationGEPs.push_back(&I);
        } else return failure("MBPF311", "GEP has unproved pointer provenance", &I);
        Result = Base;
      } else if (auto *Load = dyn_cast<LoadInst>(&I)) {
        Provenance Address = Get(Load->getPointerOperand());
        if (Address.Category == Kind::Context) {
          if (TraceContext)
            return failure("MBPF317", "tracepoint programs must not read context payload fields", &I);
          if (UprobeContext) {
            // The pinned register word loads exactly once as
            // i64; the loaded register value is ordinary scalar
            // data (it meets the filter value at the comparison
            // after their producing calls).
            if (!Load->getType()->isIntegerTy(64) || Address.Offset != 112)
              return failure("MBPF317", "uprobe programs must load the pinned x86-64 first-argument register exactly once as i64", &I);
            ++PinnedRegisterReads;
            Result = {Kind::Scalar, nullptr, 0};
          } else {
            if (!Load->getType()->isIntegerTy(32) ||
                (Address.Offset != ContextDataOffset && Address.Offset != ContextDataOffset + 4))
              return failure("MBPF317", "context loads must read the two aligned u32 address words", &I);
            Result = {Address.Offset == ContextDataOffset ? Kind::DataWord : Kind::EndWord, Entry->getArg(0), 0};
          }
        } else if (Address.Category == Kind::PacketPointer) {
          if (!Load->getType()->isIntegerTy(8) || Address.Offset < 0)
            return failure("MBPF317", "packet load exceeds the admitted byte access", &I);
          bool FoundEdge = false;
          uint64_t End = static_cast<uint64_t>(Address.Offset) + 1;
          if (!PacketRangeDominates(Address, I, End, FoundEdge)) {
            auto [Code, Explanation] = FoundEdge
                ? std::pair{"MBPF317", "packet load exceeds the proved packet range"}
                : std::pair{"MBPF314", "packet byte load lacks a dominating proved range edge"};
            if (auto E = Downgrade(Code, Explanation, &I)) return std::move(E);
          }
        } else if (Address.Category == Kind::LookupPointer || Address.Category == Kind::ValuePointer || Address.Category == Kind::KeyPointer) {
          unsigned Bytes = Load->getType()->isIntegerTy(64) ? 8 : Load->getType()->isIntegerTy(32) ? 4 : Load->getType()->isIntegerTy(8) ? 1 : 0;
          unsigned Extent = Address.Category == Kind::KeyPointer ? 4 : 8;
          if (!Bytes)
            return failure("MBPF314", "load width is outside the proved cell model", &I);
          // Kernel-negative out-of-bounds dereference: refuse
          // strict, obligate+continue permissive.
          if (Address.Offset < 0 || uint64_t(Address.Offset) + Bytes > Extent)
            if (auto E = Downgrade("MBPF314", "load exceeds its proved cell", &I)) return std::move(E);
          if (Address.Category == Kind::ValuePointer && Initialized != 0xFF)
            return failure("MBPF314", "scratch load is not fully initialized", &I);
        } else if (Address.Category == Kind::ReservationPointer) {
          // Record loads read stamped fields (the u16/u32/u64
          // field widths); the post-walk check pins
          // before-terminus order like the stores.
          unsigned Bytes = Load->getType()->isIntegerTy(64) ? 8 : Load->getType()->isIntegerTy(32) ? 4 :
              Load->getType()->isIntegerTy(16) ? 2 : Load->getType()->isIntegerTy(8) ? 1 : 0;
          if (!Bytes)
            return failure("MBPF314", "record load width is outside the proved field model", &I);
          if (Address.Offset < 0 || uint64_t(Address.Offset) + Bytes > 32)
            if (auto E = Downgrade("MBPF314", "record load exceeds its proved record", &I)) return std::move(E);
          ReservationLoads.push_back(&I);
        } else {
          if (auto E = Downgrade("MBPF311", "load pointer provenance is unproved", &I))
            return std::move(E);
          // Unproved provenance yields ordinary scalar data; the
          // alignment guarantee below cannot be evaluated for it.
          Proven[&I] = {};
          continue;
        }
        // The uprobe context is struct pt_regs (a u64-worded
        // 8-aligned kernel struct, the same program-type-gated
        // layout trust as the tc __sk_buff offsets); every other
        // context root stays 4-aligned.
        auto Guaranteed = memoryAlignment(Address, UprobeContext ? 8 : 4);
        if (!Guaranteed || Load->getAlign() > *Guaranteed)
          return failure("MBPF319", "load alignment exceeds its root and accumulated-offset guarantee", &I);
      } else if (auto *Store = dyn_cast<StoreInst>(&I)) {
        Provenance Stored = Get(Store->getValueOperand()), Address = Get(Store->getPointerOperand());
        if (tainted(Stored) || Store->getValueOperand()->getType()->isPointerTy())
          return failure("MBPF316", "pointer/address-derived value or control predicate cannot become stored payload", &I);
        unsigned Bytes = unsigned(M.getDataLayout().getTypeStoreSize(Store->getValueOperand()->getType()).getFixedValue());
        unsigned Extent = Address.Category == Kind::KeyPointer ? 4 : Address.Category == Kind::EventRecord ? 32 :
            Address.Category == Kind::ReservationPointer ? 32 : 8;
        // Unknown-provenance and non-scalar stores stay refused
        // (no observed kernel-negative shape needs them); only a
        // known cell with an out-of-bounds offset obligates.
        if ((Address.Category != Kind::ValuePointer && Address.Category != Kind::LookupPointer && Address.Category != Kind::KeyPointer &&
             Address.Category != Kind::EventRecord && Address.Category != Kind::ReservationPointer) ||
            !scalar(Store->getValueOperand()->getType()))
          return failure("MBPF314", "store exceeds or escapes its proved scratch/map cell", &I);
        if (Address.Category == Kind::ReservationPointer) {
          // One word store per record field, at its exact
          // offset and width; the post-walk check pins the
          // full seven-store covering multiset.
          bool Field = (Address.Offset == 0 && Bytes == 2) || (Address.Offset == 2 && Bytes == 2) ||
              (Address.Offset == 4 && Bytes == 4) || (Address.Offset == 8 && Bytes == 4) ||
              (Address.Offset == 12 && Bytes == 4) || (Address.Offset == 16 && Bytes == 8) ||
              (Address.Offset == 24 && Bytes == 8);
          if (!Field)
            return failure("MBPF314", "reservation store is outside the seven record field words", &I);
          ReservationStores.push_back({Address.Offset, Bytes, &I});
        }
        if (Address.Offset < 0 || uint64_t(Address.Offset) + Bytes > Extent)
          if (auto E = Downgrade("MBPF314", "store exceeds its proved scratch/map cell", &I)) return std::move(E);
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
        if (auto Refusal = checkedDivRefusal(*Binary))
          return failure("MBPF319", *Refusal, &I);
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
        } else if (Binary->getOpcode() == Instruction::Sub &&
                   Left.Category == Kind::EndAddress && Right.Category == Kind::PacketAddress &&
                   Left.Origin == Right.Origin && Binary->getType()->isIntegerTy(64)) {
          // Packet length: the difference of two same-origin
          // context addresses is slide-invariant (the ASLR slide
          // cancels even under wrap), so it is pure scalar data.
          Result = {Kind::Scalar, nullptr, 0};
        } else if (Binary->getOpcode() == Instruction::Xor && Binary->getType()->isIntegerTy(1) &&
                   ((Left.Category == Kind::Control && isa<ConstantInt>(Binary->getOperand(1))) ||
                    (Right.Category == Kind::Control && isa<ConstantInt>(Binary->getOperand(0))))) {
          // Boolean negation of a proved control predicate
          // (the inverted null check) is still control.
          Result = {Kind::Control, Left.Category == Kind::Control ? Left.Origin : Right.Origin, 0};
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
        if ((Left.Category == Kind::LookupAddress || Left.Category == Kind::ReservationAddress) &&
            constant(Compare->getOperand(1), 0) &&
            (Compare->getPredicate() == ICmpInst::ICMP_EQ || Compare->getPredicate() == ICmpInst::ICMP_NE)) {
          Result = {Kind::Control, Left.Origin, 0};
        } else if (DefinedPacketCompare) {
          Result = {Kind::Control, Left.Origin, Left.Offset};
        } else if (tainted(Left) || tainted(Right)) {
          if (auto E = Downgrade("MBPF311", "unrecognized address observation/comparison", &I))
            return std::move(E);
          Result = {Kind::Escaped, &I, 0};
        }
      } else if (auto *Select = dyn_cast<SelectInst>(&I)) {
        auto Condition = Get(Select->getCondition()), True = Get(Select->getTrueValue()), False = Get(Select->getFalseValue());
        if (tainted(Condition) || tainted(True) || tainted(False)) Result = {Kind::Escaped, &I, 0};
      } else if (auto *Phi = dyn_cast<PHINode>(&I)) {
        for (const Value *Incoming : Phi->incoming_values()) if (tainted(Get(Incoming))) Result = {Kind::Escaped, &I, 0};
      } else if (auto *Branch = dyn_cast<BranchInst>(&I)) {
        if (Branch->isConditional()) {
          auto Condition = Get(Branch->getCondition());
          if (Condition.Category != Kind::Scalar && Condition.Category != Kind::Control)
            if (auto E = Downgrade("MBPF311", "branch condition is laundered address data", Branch->getCondition()))
              return std::move(E);
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
  if (UprobeContext) {
    // The pinned register word reads exactly once: the entry
    // parameter feeds one address computation only, and the
    // pinned address loads once (the GEP/load arms above pin
    // the form; this pins the multiplicity).
    Argument *Ctx = Entry->getArg(0);
    if (!Ctx->hasOneUse() || !isa<GetElementPtrInst>(*Ctx->user_begin()))
      return failure("MBPF317", "uprobe programs must read exactly the pinned x86-64 first-argument register (context word 14): entry parameter feeds one address computation only", Entry);
    if (PinnedRegisterReads != 1)
      return failure("MBPF317", "uprobe programs must load the pinned x86-64 first-argument register exactly once as i64", Entry);
  }
  if (ReserveCall) {
    // The reservation stamps all seven record words exactly
    // once (no gaps, no overlap, no second covering), the
    // reservation result reinterprets exactly once, and every
    // reservation-relative store, load, and address
    // computation dominates the terminus (no use follows the
    // release).
    std::vector<std::pair<int64_t, unsigned>> Covered;
    for (const auto &S : ReservationStores) Covered.push_back({S.Offset, S.Bytes});
    std::sort(Covered.begin(), Covered.end());
    const std::vector<std::pair<int64_t, unsigned>> Want{
        {0, 2}, {2, 2}, {4, 4}, {8, 4}, {12, 4}, {16, 8}, {24, 8}};
    if (Covered != Want)
      return failure("MBPF314", "reservation stores are not the seven record field words covering the 32 record bytes", ReserveCall);
    unsigned Reinterps = 0;
    for (const auto &P : Program.Primitives) {
      if (P.Kind != PrimitiveKind::Reinterpret) continue;
      if (P.Call->getArgOperand(0) == ReserveCall) ++Reinterps;
    }
    if (Reinterps != 1)
      return failure("MBPF314", "reservation result needs exactly one record reinterpretation", ReserveCall);
    if (TerminusCall) {
      for (const auto &S : ReservationStores)
        if (!DT.dominates(S.Where, TerminusCall))
          return failure("MBPF314", "reservation store does not dominate the terminus", S.Where);
      for (const Instruction *Load : ReservationLoads)
        if (!DT.dominates(Load, TerminusCall))
          return failure("MBPF314", "reservation load does not dominate the terminus", Load);
      for (const Instruction *GEP : ReservationGEPs)
        if (!DT.dominates(GEP, TerminusCall))
          return failure("MBPF314", "reservation address does not dominate the terminus", GEP);
    }
  }
  // References have only the narrow consumers whose semantics were proved.
  for (const auto &Known : Proven) {
    auto P = Known.second;
    if (P.Category == Kind::Scalar || P.Category == Kind::Control) continue;
    if (P.Category == Kind::Escaped) {
      // Permissive mode passes silently: escaped intermediates
      // carry no assertion of their own, and every assertion
      // (memory access, control decision, comparison) records
      // at its own downgrade site above.
      if (Sink.Permissive) continue;
      return failure("MBPF311", "address is laundered outside the proved uses", Known.first);
    }
    for (const User *U : Known.first->users()) {
      auto *I = dyn_cast<Instruction>(U);
      if (!I) return failure("MBPF311", "address escapes into a non-instruction user", Known.first);
      if (P.Category == Kind::MapReference) {
        auto *Call = dyn_cast<CallInst>(I);
        bool TransparentTag = false;
        if (Call) {
          auto Tag = PrimitiveKinds.find(Call);
          TransparentTag = Tag != PrimitiveKinds.end() &&
              (Tag->second == PrimitiveKind::HashTag ||
               Tag->second == PrimitiveKind::LruTag ||
               Tag->second == PrimitiveKind::PercpuTag);
        }
        // A map reference flows only into a helper's map
        // operand (arg0) or a transparent kind tag (which the
        // walk site already reconciled with the spec contract).
        if (!Call || (Call->getCalledFunction() == nullptr && !TransparentTag) ||
            Call->getArgOperand(0) != Known.first)
          return failure("MBPF314", "map reference escapes its reserved helper operand", I);
      }
      if (P.Category == Kind::RingbufReference) {
        auto *Call = dyn_cast<CallInst>(I);
        bool TransparentTag = false;
        if (Call) {
          auto Tag = PrimitiveKinds.find(Call);
          TransparentTag = Tag != PrimitiveKinds.end() &&
              Tag->second == PrimitiveKind::RingSizeTag;
        }
        // A ring-buffer reference flows only into the
        // size tag or a helper's map operand (arg0); the
        // output arm admits the tagged address while the
        // keyed-helper arms refuse the untagged kind.
        if (!Call || (Call->getCalledFunction() == nullptr && !TransparentTag) ||
            Call->getArgOperand(0) != Known.first)
          return failure("MBPF314", "ring-buffer reference escapes its reserved helper operand", I);
      }
      if ((P.Category == Kind::KeyPointer || P.Category == Kind::ValuePointer || P.Category == Kind::EventRecord) &&
          !isa<GetElementPtrInst>(I) && !isa<LoadInst>(I) && !isa<StoreInst>(I) && !isa<CallInst>(I))
        return failure("MBPF311", "scratch address has an observable/escaping use", I);
    }
  }
  Program.Unproved = std::move(Sink.Recorded);
  Program.UnprovedTotal = Sink.Total;
  Program.SourceDigest = sourceDigest(M);
  Program.ValueIdentities = liveIdentities(M);
  return Program;
}

Error auditLoweredCore(const Module &M, const LoweringSpec &Spec,
                       const TargetFacts &Facts, bool Complete, bool Permissive) {
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
  if (!M.getModuleInlineAsm().empty() || !M.alias_empty() || !M.ifunc_empty() || M.size() < 1 || M.size() > 2)
    return failure("MBPF304", "lowered module contains assembly, aliases or extra functions");
  const Function *LoweredCallee = nullptr;
  for (const Function &F : M) {
    if (F.getName() == Spec.Entry) continue;
    if (F.getName() == "llvm.bpf.passthrough.i32.i32") {
      // The synthesized relocation runtime: an exact
      // i32(i32,i32) declaration with exactly the two
      // expansion uses, admitted only under the core map.
      // The name denotes a backend intrinsic, so the
      // declaration carries the canonical intrinsic
      // attributes (materialized identically at parse);
      // nothing else may.
      Type *I32Ty = Type::getInt32Ty(M.getContext());
      AttributeSet FnAttrs = F.getAttributes().getFnAttrs();
      bool CanonicalAttrs = FnAttrs.getNumAttributes() == 2 &&
          FnAttrs.hasAttribute(Attribute::NoUnwind) &&
          FnAttrs.getMemoryEffects() == MemoryEffects::none();
      for (unsigned Slot : F.getAttributes().indexes())
        if (Slot != AttributeList::FunctionIndex) CanonicalAttrs = false;
      if (!Spec.Map || Spec.Map->ValueBits != 32768 || !F.isDeclaration() ||
          F.getLinkage() != GlobalValue::ExternalLinkage || F.isDSOLocal() ||
          !prototype(F.getFunctionType(), I32Ty, {I32Ty, I32Ty}) ||
          F.getCallingConv() != CallingConv::C || F.hasPersonalityFn() ||
          F.hasPrefixData() || F.hasPrologueData() || F.hasGC() ||
          !F.getSection().empty() || F.getComdat() || F.hasMetadata() ||
          !CanonicalAttrs || !F.hasNUses(2))
        return failure("MBPF319", "lowered relocation runtime differs from the synthesized declaration", &F);
      for (const Use &U : F.uses())
        if (!isa<CallInst>(U.getUser()))
          return failure("MBPF319", "lowered relocation runtime use is not an expansion call", &F);
      continue;
    }
    if (F.isDeclaration() || LoweredCallee || Spec.ProfileID != "linux-bpfel-v3-subprog")
      return failure("MBPF304", "lowered module contains assembly, aliases or extra functions", &F);
    StringRef Name = F.getName();
    if (Name.starts_with("__mojobpf_") || Name.starts_with("llvm."))
      return failure("MBPF303", "lowered subprogram name is reserved", &F);
    if (Name.empty() || !(isAlpha(Name.front()) || Name.front() == '_') ||
        !all_of(Name, [](char C) { return isAlnum(C) || C == '_'; }))
      return failure("MBPF302", "lowered subprogram name is not a plain C identifier", &F);
    Type *I64Ty = Type::getInt64Ty(M.getContext());
    if (F.getLinkage() != GlobalValue::ExternalLinkage || !F.isDSOLocal() ||
        !prototype(F.getFunctionType(), I64Ty, {I64Ty}) ||
        F.getCallingConv() != CallingConv::C || F.hasPersonalityFn() ||
        F.hasPrefixData() || F.hasPrologueData() || F.hasGC() ||
        !F.getSection().empty() || F.getComdat() || F.hasMetadata())
      return failure("MBPF302", "lowered subprogram is not a dso_local C-ABI (i64)->i64 definition", &F);
    if (!F.hasFnAttribute(Attribute::NoInline))
      return failure("MBPF302", "lowered subprogram must carry the noinline marker", &F);
    for (unsigned Slot : F.getAttributes().indexes()) for (Attribute A : F.getAttributes().getAttributes(Slot)) {
      bool Allowed = (A.isEnumAttribute() && A.getKindAsEnum() == Attribute::NoUndef && Slot != AttributeList::FunctionIndex) ||
                     (A.isEnumAttribute() && A.getKindAsEnum() == Attribute::NoInline && Slot == AttributeList::FunctionIndex);
      if (A.isStringAttribute() && Slot == AttributeList::FunctionIndex)
        Allowed = (A.getKindAsString() == "target-cpu" && A.getValueAsString() == "v3") ||
                  (A.getKindAsString() == "target-features" && A.getValueAsString().empty());
      if (!Allowed) return failure("MBPF319", "unexpected lowered subprogram attribute", &F);
    }
    if (F.getFnAttribute("target-cpu").getValueAsString() != "v3" ||
        !F.hasFnAttribute("target-features") || !F.getFnAttribute("target-features").getValueAsString().empty())
      return failure("MBPF319", "lowered subprogram target attributes are missing or differ", &F);
    LoweredCallee = &F;
  }
  auto *F = M.getFunction(Spec.Entry);
  bool CoreMap = Spec.Map && Spec.Map->ValueBits == 32768;
  // The core entry carries its synthesized subprogram (names
  // the relocation section) once the metadata transition
  // runs; the graph audit pins the exact attachment. Before
  // that, and for every other shape, it carries no metadata.
  if (!F || F->isDeclaration() || F->getSection() != Spec.Section || (F->hasMetadata() && !(CoreMap && Complete)) ||
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
  const auto *License = M.getGlobalVariable("_license"), *Used = M.getGlobalVariable("llvm.compiler.used");
  const auto *Map = Spec.Map ? M.getGlobalVariable(Spec.Map->Symbol) : nullptr;
  const auto *Ringbuf = M.getGlobalVariable("mojobpf_map1");
  const auto *CoreRead = M.getGlobalVariable("llvm.task_struct:0:32$0:1");
  const auto *CoreExists = M.getGlobalVariable("llvm.task_struct:2:1$0:4");
  if (M.global_size() != 2 + (Map ? 1 : 0) + (Ringbuf ? 1 : 0) + (CoreMap ? 2 : 0) || !License || !Used ||
      (Spec.Map && !Map) || (CoreMap && (!CoreRead || !CoreExists)) ||
      (!CoreMap && (CoreRead || CoreExists)))
    return failure("MBPF309", "lowered globals differ from the generated set");
  auto PlainGlobal = [](const GlobalVariable &G) {
    return G.hasExternalLinkage() && !G.isConstant() && !G.isThreadLocal() && !G.getAddressSpace() &&
           !G.isExternallyInitialized() && !G.hasComdat() && !G.hasDLLImportStorageClass() &&
           !G.hasDLLExportStorageClass() && G.getVisibility() == GlobalValue::DefaultVisibility &&
           G.getUnnamedAddr() == GlobalValue::UnnamedAddr::None;
  };
  const auto *Bytes = dyn_cast_or_null<ConstantDataArray>(License->getInitializer());
  if (!PlainGlobal(*License) || !License->isDSOLocal() || License->getSection() != "license" || License->getAlign() != Align(1) ||
      License->hasMetadata() || !License->getValueType()->isArrayTy() || !Bytes ||
      !Bytes->isString() || Bytes->getAsString() != Spec.KernelLicense + std::string(1, '\0'))
    return failure("MBPF319", "lowered license bytes or properties differ");
  auto *Retained = dyn_cast_or_null<ConstantArray>(Used->getInitializer());
  if (!Used->hasAppendingLinkage() || Used->getSection() != "llvm.metadata" || Used->hasMetadata() ||
      Used->isConstant() || Used->isThreadLocal() || Used->getAddressSpace() || !Retained ||
      Retained->getNumOperands() != 2 + (Map ? 1 : 0) + (Ringbuf ? 1 : 0))
    return failure("MBPF309", "required llvm.compiler.used retention differs");
  SmallPtrSet<const Value *, 4> Retention;
  for (const Use &U : Retained->operands()) Retention.insert(U.get());
  if (Retention.size() != Retained->getNumOperands() || !Retention.contains(F) || !Retention.contains(License) ||
      (Map && !Retention.contains(Map)) || (Ringbuf && !Retention.contains(Ringbuf)))
    return failure("MBPF309", "required entry/globals are not retained exactly");
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
  if (Ringbuf) {
    auto *T = dyn_cast<StructType>(Ringbuf->getValueType());
    if (!PlainGlobal(*Ringbuf) || Ringbuf->getSection() != ".maps" || Ringbuf->getAlign() != Align(8) ||
        !isa_and_nonnull<ConstantAggregateZero>(Ringbuf->getInitializer()) || !T || T->isPacked() ||
        T->getNumElements() != 2 || M.getDataLayout().getTypeAllocSize(T).getFixedValue() != 16 ||
        M.getDataLayout().getABITypeAlign(T) != Align(8))
      return failure("MBPF314", "generated ring-buffer global layout differs");
    for (unsigned Index = 0; Index < 2; ++Index)
      if (!T->getElementType(Index)->isPointerTy() || cast<PointerType>(T->getElementType(Index))->getAddressSpace() ||
          M.getDataLayout().getStructLayout(T)->getElementOffset(Index) != Index * 8)
        return failure("MBPF314", "generated ring-buffer fields differ");
  }
  if (CoreMap) {
    // The relocation markers: bare external i32 globals. The
    // metadata transition adds exactly the
    // preserve-access-index attachment (whose target the graph
    // audit pins) and the btf_ama attribute group the backend
    // recognizes.
    unsigned PreserveKind = M.getMDKindID("llvm.preserve.access.index");
    for (const GlobalVariable *G : {CoreRead, CoreExists}) {
      SmallVector<std::pair<unsigned, MDNode *>, 2> Attachments;
      G->getAllMetadata(Attachments);
      if (!PlainGlobal(*G) || G->isDSOLocal() || !G->getSection().empty() || static_cast<bool>(G->getAlign()) ||
          G->hasInitializer() || !G->getValueType()->isIntegerTy(32))
        return failure("MBPF319", "lowered relocation marker differs from the synthesized global", G);
      bool Attached = Attachments.size() == 1 && Attachments[0].first == PreserveKind &&
          isa<DICompositeType>(Attachments[0].second) &&
          G->getAttributes().getNumAttributes() == 1 && G->getAttributes().hasAttribute("btf_ama");
      if (Complete && !Attached)
        return failure("MBPF319", "lowered relocation marker lacks its synthesized relocation attachments", G);
      if (!Complete && (!Attachments.empty() || G->getAttributes().getNumAttributes() != 0))
        return failure("MBPF319", "lowered relocation marker carries pre-metadata attachments", G);
    }
  }
  if (auto E = auditMapMetadata(M, Spec, Complete)) return E;

  // Projection is derived from this module, never from the original source.
  // Only the exact generated forms below can be removed/reified. Every other
  // instruction, operand, CFG edge and memory effect enters the source audit.
  auto Projection = CloneModule(M);
  Function &Entry = *Projection->getFunction(Spec.Entry);
  Entry.setSection("");
  // The synthesized entry subprogram (core only) leaves
  // with the metadata transition; the re-audit sees the
  // bare source shape.
  Entry.setSubprogram(nullptr);
  Entry.removeFnAttr("target-cpu");
  Entry.removeFnAttr("target-features");
  if (LoweredCallee) {
    Function &ProjectedCallee = *Projection->getFunction(LoweredCallee->getName());
    ProjectedCallee.removeFnAttr("target-cpu");
    ProjectedCallee.removeFnAttr("target-features");
  }
  Projection->setTargetTriple(Triple("x86_64-unknown-linux-gnu"));
  AllocaInst *KeyCell = nullptr, *ValueCell = nullptr, *RecordCell = nullptr;
  for (BasicBlock &BB : Entry) for (Instruction &I : BB) {
    if (I.hasMetadata()) return failure("MBPF319", "unexpected lowered instruction metadata", &I);
    if (auto *A = dyn_cast<AllocaInst>(&I)) {
      if (&BB != &Entry.getEntryBlock() || !A->isStaticAlloca() || !constant(A->getArraySize(), 1) ||
          A->getAddressSpace() || A->isUsedWithInAlloca() || A->isSwiftError())
        return failure("MBPF310", "generated cell is not a fixed entry alloca", &I);
      AllocaInst **Cell;
      if (A->getAllocatedType()->isIntegerTy(32) && A->getAlign() == Align(4)) Cell = &KeyCell;
      else if (A->getAllocatedType()->isIntegerTy(64) && A->getAlign() == Align(8)) Cell = &ValueCell;
      else if (auto *Array = dyn_cast<ArrayType>(A->getAllocatedType())) {
        if (Array->getNumElements() != 32 || !Array->getElementType()->isIntegerTy(8) ||
            A->getAlign() != Align(8))
          return failure("MBPF310", "generated cell type/alignment differs", &I);
        Cell = &RecordCell;
      }
      else return failure("MBPF310", "generated cell type/alignment differs", &I);
      // The mapless skb vectors reify exactly one used key
      // cell (the packet buffer); value and record cells
      // still need their map contract.
      if (*Cell || A->use_empty() || (!Spec.Map && Cell != &KeyCell))
        return failure("MBPF310", "duplicate, unused or unrequested scratch cell", &I);
      *Cell = A;
    }
  }
  auto &C = Projection->getContext();
  Type *I32 = Type::getInt32Ty(C), *I64 = Type::getInt64Ty(C), *Ptr = PointerType::getUnqual(C);
  auto *KeyAsm = InlineAsm::get(FunctionType::get(Ptr, {I32}, false),
      "r0 = r10\nr0 += -4\n*(u32 *)(r0 + 0) = r1", "={r0},{r1},~{memory}", true);
  auto *ValueAsm = InlineAsm::get(FunctionType::get(Ptr, false), "r0 = r10\nr0 += -16", "={r0}", true);
  auto *MapAsm = InlineAsm::get(FunctionType::get(I64, false), "r0 = mojobpf_map0 ll", "={r0}", true);
  auto *HashTagAsm = InlineAsm::get(FunctionType::get(I64, {I64}, false), "", "=r,0", true);
  auto *LruTagAsm = InlineAsm::get(FunctionType::get(I64, {I64}, false), "", "=r,0,~{memory}", true);
  auto *PercpuTagAsm = InlineAsm::get(FunctionType::get(I64, {I64}, false), "", "=r,0", false);
  CallInst *ReifiedValue = nullptr;
  if (ValueCell) {
    ReifiedValue = CallInst::Create(ValueAsm->getFunctionType(), ValueAsm, {}, "", ValueCell->getIterator());
    ValueCell->replaceAllUsesWith(ReifiedValue);
    ValueCell->eraseFromParent();
  }
  auto *RingbufMapAsm = InlineAsm::get(FunctionType::get(I64, false), "r0 = mojobpf_map1 ll", "={r0},~{memory}", true);
  Budget Work{DefaultAnalysisBudget};
  auto Ordered = orderedBlocks(Entry, Work);
  if (!Ordered) return Ordered.takeError();
  // The key-use calls a preparation store must dominate to
  // reify (finding F4): an ordinary store to the key slot
  // shares the preparation shape exactly, so shape alone
  // cannot reify it. Legitimate preparations dominate their
  // helper call (key freshness refuses impostors at the
  // source); anything else keeps its existing path into the
  // re-audit as an ordinary store.
  SmallVector<const CallInst *, 16> KeyUseCalls;
  if (KeyCell)
    for (const BasicBlock &BB : Entry)
      for (const Instruction &I : BB)
        if (const auto *Call = dyn_cast<CallInst>(&I))
          for (const Use &U : Call->operands())
            if (U.get() == KeyCell) { KeyUseCalls.push_back(Call); break; }
  DominatorTree ProjectDT(Entry);
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
        // Dense key stores reify with their literal (mirror of the
        // source key rule); the re-audit verifies density. Only a
        // store dominating a key-use call reifies (finding F4):
        // an ordinary store to the slot falls through to the
        // operand rewrite below and meets the re-audit as an
        // ordinary store.
        const auto *Stored = dyn_cast<ConstantInt>(Store->getValueOperand());
        bool PreparationShape = KeyCell && Store->getPointerOperand() == KeyCell &&
            Store->getValueOperand()->getType() == I32 && Stored &&
            (!Spec.Map || Stored->getValue().ult(Spec.Map->MaxEntries)) &&
            Store->getAlign() == Align(4) && !Store->isVolatile() && !Store->isAtomic();
        bool DominatesUse = false;
        if (PreparationShape)
          for (const CallInst *Use : KeyUseCalls)
            if (ProjectDT.dominates(Store, Use)) { DominatesUse = true; break; }
        if (PreparationShape && DominatesUse) {
          Preparation = CallInst::Create(KeyAsm->getFunctionType(), KeyAsm, {Store->getValueOperand()}, "", Store->getIterator());
          Erase.push_back(Store);
          continue;
        }
      }
      for (Use &U : I.operands()) if (KeyCell && U.get() == KeyCell) {
        if (!Preparation) return failure("MBPF318", "lowered key use lacks one dominating preparation identity", &I);
        U.set(Preparation);
      }
      if (auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
        // Record field pointers reify to their exact view
        // spelling (mirror of the source view rule); the
        // re-audit verifies the record layout. Every other
        // GEP keeps its existing path into the re-audit,
        // which proves or refuses it there.
        if (!RecordCell || GEP->getPointerOperand() != RecordCell)
          continue;
        if (!GEP->isInBounds() || GEP->getSourceElementType() != RecordCell->getAllocatedType() ||
            GEP->getNumIndices() != 2 || GEP->getAddressSpace())
          return failure("MBPF310", "record field pointer is outside the generated cell", &I);
        const auto *Zero = dyn_cast<ConstantInt>(GEP->getOperand(1));
        const auto *Off = dyn_cast<ConstantInt>(GEP->getOperand(2));
        if (!Zero || !Zero->isZero() || !Off)
          return failure("MBPF310", "record field pointer is outside the generated cell", &I);
        std::string Spelling;
        switch (Off->getZExtValue()) {
        case 0: Spelling = "r0 = r10\nr0 += -64"; break;
        case 2: Spelling = "r0 = r10\nr0 += -62"; break;
        case 4: Spelling = "r0 = r10\nr0 += -60"; break;
        case 8: Spelling = "r0 = r10\nr0 += -56"; break;
        case 12: Spelling = "r0 = r10\nr0 += -52"; break;
        case 16: Spelling = "r0 = r10\nr0 += -48"; break;
        case 24: Spelling = "r0 = r10\nr0 += -40"; break;
        default: return failure("MBPF314", "record field offset is outside the record layout", &I);
        }
        auto *ViewAsm = InlineAsm::get(FunctionType::get(Ptr, false), Spelling, "={r0},~{memory}", true);
        auto *View = CallInst::Create(ViewAsm->getFunctionType(), ViewAsm, {}, "", GEP->getIterator());
        GEP->replaceAllUsesWith(View);
        Erase.push_back(GEP);
        continue;
      }
      auto *Call = dyn_cast<CallInst>(&I);
      if (!Call) continue;
      if (Call->getCalledFunction() &&
          Call->getCalledFunction()->getName() == "llvm.bpf.passthrough.i32.i32") {
        // A relocation expansion reifies to its symbolic
        // call: the existence check threads the constant
        // through its own marker; the read threads the
        // checked value pointer through the relocated
        // offset (marker load, passthrough, extend,
        // indexed byte load). The reified call lands
        // before the expansion (already visited), so the
        // re-audit sees the source shape; the expansion
        // instructions leave through the erase list.
        if (Call->arg_size() != 2)
          return failure("MBPF313", "relocation expansion call is outside the synthesized shape", &I);
        const auto *One = dyn_cast<ConstantInt>(Call->getArgOperand(0));
        auto *Mark = dyn_cast<LoadInst>(Call->getArgOperand(1));
        const auto *Marker = Mark ? dyn_cast<GlobalVariable>(Mark->getPointerOperand()) : nullptr;
        bool IsRead = One && One->isZero() && Marker &&
            Marker->getName() == "llvm.task_struct:0:32$0:1";
        bool IsExists = One && One->equalsInt(1) && Marker &&
            Marker->getName() == "llvm.task_struct:2:1$0:4";
        if (!One || !Mark || !Marker || (!IsRead && !IsExists) || !Mark->hasOneUse() ||
            Mark->getAlign() != Align(4) || Mark->isVolatile() || !Mark->getType()->isIntegerTy(32))
          return failure("MBPF313", "relocation expansion marker is outside the synthesized shape", &I);
        if (IsExists) {
          auto Decl = Projection->getOrInsertFunction("__mojobpf_core_exists_task_scx_v1",
              FunctionType::get(I32, {}, false));
          auto *Back = CallInst::Create(Decl.getFunctionType(), Decl.getCallee(),
              {}, "", Call->getIterator());
          Call->replaceAllUsesWith(Back);
        } else {
          if (!Call->hasOneUse() || !isa<ZExtInst>(*Call->user_begin()))
            return failure("MBPF313", "relocation read expansion is outside the synthesized shape", &I);
          auto *Wide = cast<ZExtInst>(*Call->user_begin());
          if (!Wide->getType()->isIntegerTy(64) || !Wide->hasOneUse() ||
              !isa<GetElementPtrInst>(*Wide->user_begin()))
            return failure("MBPF313", "relocation read expansion is outside the synthesized shape", &I);
          auto *Slot = cast<GetElementPtrInst>(*Wide->user_begin());
          if (Slot->isInBounds() || Slot->getSourceElementType() != Type::getInt8Ty(C) ||
              Slot->getNumIndices() != 1 || Slot->getOperand(1) != Wide || !Slot->hasOneUse() ||
              !isa<LoadInst>(*Slot->user_begin()))
            return failure("MBPF313", "relocation read expansion is outside the synthesized shape", &I);
          auto *Word = cast<LoadInst>(*Slot->user_begin());
          if (!Word->getType()->isIntegerTy(32) || Word->getAlign() != Align(4) || Word->isVolatile())
            return failure("MBPF313", "relocation read expansion is outside the synthesized shape", &I);
          auto Decl = Projection->getOrInsertFunction("__mojobpf_core_read_task_pid_v1",
              FunctionType::get(I32, {Ptr}, false));
          auto *Back = CallInst::Create(Decl.getFunctionType(), Decl.getCallee(),
              {Slot->getPointerOperand()}, "", Call->getIterator());
          Word->replaceAllUsesWith(Back);
          Erase.push_back(Wide);
          Erase.push_back(Slot);
          Erase.push_back(Word);
        }
        Erase.push_back(Mark);
        Erase.push_back(Call);
        continue;
      }
      if (auto *Asm = dyn_cast<InlineAsm>(Call->getCalledOperand())) {
        auto Kind = primitive(*Call);
        if (!Kind || (*Kind != PrimitiveKind::Reinterpret && *Kind != PrimitiveKind::RingSizeTag))
          return failure("MBPF306", "lowered asm is not the proved tied reinterpretation", &I);
        if (*Kind == PrimitiveKind::RingSizeTag) {
          // The preserved size tag keeps its literal; its
          // companion operand reifies to the map load for
          // the re-audit.
          auto *MapOp = dyn_cast<ConstantExpr>(Call->getArgOperand(0));
          if (!MapOp || MapOp->getOpcode() != Instruction::PtrToInt || MapOp->getType() != I64 ||
              MapOp->getOperand(0) != Projection->getGlobalVariable("mojobpf_map1"))
            return failure("MBPF314", "preserved size tag operand is outside the companion interface", &I);
          auto *Reference = CallInst::Create(RingbufMapAsm->getFunctionType(), RingbufMapAsm, {}, "", Call->getIterator());
          Call->setArgOperand(0, Reference);
        }
        continue;
      }
      if (LoweredCallee && Call->getCalledFunction() &&
          Call->getCalledFunction()->getName() == LoweredCallee->getName())
        continue;
      auto *Callee = dyn_cast<ConstantExpr>(Call->getCalledOperand());
      auto *ID = Callee && Callee->getOpcode() == Instruction::IntToPtr ? dyn_cast<ConstantInt>(Callee->getOperand(0)) : nullptr;
      bool SkbLoad = ID && ID->equalsInt(26), SkbStore = ID && ID->equalsInt(9);
      if (!ID || !ID->getType()->isIntegerTy(64) ||
          (!ID->equalsInt(1) && !ID->equalsInt(2) && !ID->equalsInt(3) && !ID->equalsInt(5) &&
           !ID->equalsInt(8) && !ID->equalsInt(14) && !ID->equalsInt(130) && !ID->equalsInt(131) &&
           !ID->equalsInt(132) && !ID->equalsInt(133) && !SkbLoad && !SkbStore) ||
          (!Spec.Map && !SkbLoad && !SkbStore))
        return failure("MBPF313", "lowered callee is not helper 1/2/3/5/8/9/14/26/130/131/132/133 at the validated interface", &I);
      bool Lookup = ID->equalsInt(1), Delete = ID->equalsInt(3), Pid = ID->equalsInt(14),
           Ktime = ID->equalsInt(5), Cpu = ID->equalsInt(8), Output = ID->equalsInt(130),
           Reserve = ID->equalsInt(131), Submit = ID->equalsInt(132), Discard = ID->equalsInt(133);
      auto *Expected = FunctionType::get(I64, (Lookup || Delete) ? ArrayRef<Type *>({I64, Ptr}) :
          (Pid || Ktime || Cpu) ? ArrayRef<Type *>({}) :
          Reserve ? ArrayRef<Type *>({I64, I64, I64}) :
          (Submit || Discard) ? ArrayRef<Type *>({Ptr, I64}) :
          SkbLoad ? ArrayRef<Type *>({Ptr, I32, Ptr, I32}) :
          SkbStore ? ArrayRef<Type *>({Ptr, I32, Ptr, I32, I64}) :
          Output ? ArrayRef<Type *>({I64, Ptr, I64, I64}) : ArrayRef<Type *>({I64, Ptr, Ptr, I64}), false);
      if (Call->getFunctionType() != Expected || Call->getCallingConv() != CallingConv::C ||
          Call->hasOperandBundles() || Call->isMustTailCall()) return failure("MBPF313", "numeric helper call ABI differs", &I);
      for (unsigned Slot : Call->getAttributes().indexes()) for (Attribute A : Call->getAttributes().getAttributes(Slot))
        if (!A.isEnumAttribute() || A.getKindAsEnum() != Attribute::NoUndef || Slot == AttributeList::FunctionIndex)
          return failure("MBPF319", "unexpected numeric helper call attribute", &I);
      if (Pid || Ktime || Cpu) {
        // The data calls carry no map operand: only their
        // symbolic callee is restored for the re-audit.
        StringRef Name = Pid ? "__mojobpf_get_pid_tgid_v1" :
            Ktime ? "__mojobpf_ktime_get_ns_v1" : "__mojobpf_get_smp_processor_id_v1";
        auto Decl = Projection->getOrInsertFunction(Name, Expected);
        Call->setCalledOperand(Decl.getCallee());
      } else if (SkbLoad || SkbStore) {
        // The packet call keeps its context, window, and
        // buffer operands through lowering: only the
        // symbolic callee is restored; the re-audit proves
        // the operands and the vector.
        StringRef Name = SkbLoad ? "__mojobpf_skb_load_bytes_v1" : "__mojobpf_skb_store_bytes_v1";
        auto Decl = Projection->getOrInsertFunction(Name, Expected);
        Call->setCalledOperand(Decl.getCallee());
      } else if (Output) {
        // The output call keeps its size-tagged companion
        // and record operands through lowering: only the
        // symbolic callee is restored, after checking the
        // tag shape the re-audit proves.
        const auto *Tag = dyn_cast<CallInst>(Call->getArgOperand(0));
        auto TagKind = Tag ? primitive(*Tag) : std::nullopt;
        if (!TagKind || *TagKind != PrimitiveKind::RingSizeTag)
          return failure("MBPF314", "lowered output map is not the size-tagged ring-buffer address", &I);
        auto Decl = Projection->getOrInsertFunction("__mojobpf_ringbuf_output_v1", Expected);
        Call->setCalledOperand(Decl.getCallee());
      } else if (Reserve) {
        // The reservation call keeps its size-tagged
        // companion through lowering: only the symbolic
        // callee is restored, after checking the tag
        // shape the re-audit proves.
        const auto *Tag = dyn_cast<CallInst>(Call->getArgOperand(0));
        auto TagKind = Tag ? primitive(*Tag) : std::nullopt;
        if (!TagKind || *TagKind != PrimitiveKind::RingSizeTag)
          return failure("MBPF314", "lowered reservation map is not the size-tagged ring-buffer address", &I);
        auto Decl = Projection->getOrInsertFunction("__mojobpf_ringbuf_reserve_v1", Expected);
        Call->setCalledOperand(Decl.getCallee());
      } else if (Submit || Discard) {
        // The terminus keeps its reinterpreted record
        // operand through lowering: only the symbolic
        // callee is restored; the re-audit proves the
        // record reinterpretation and the store order.
        StringRef Name = Submit ? "__mojobpf_ringbuf_submit_v1" : "__mojobpf_ringbuf_discard_v1";
        auto Decl = Projection->getOrInsertFunction(Name, Expected);
        Call->setCalledOperand(Decl.getCallee());
      } else {
      auto *MapRef = dyn_cast<ConstantExpr>(Call->getArgOperand(0));
      if (!MapRef || MapRef->getOpcode() != Instruction::PtrToInt || MapRef->getType() != I64 ||
          MapRef->getOperand(0) != Projection->getGlobalVariable(Spec.Map->Symbol))
        return failure("MBPF314", "map conversion is outside the named helper interface", &I);
      auto *Reference = CallInst::Create(MapAsm->getFunctionType(), MapAsm, {}, "", Call->getIterator());
      Value *MapOperand = Reference;
      // A hash, LRU, or percpu map operand reifies with its
      // kind tag, mirroring the source shape the re-audit's
      // kind check requires.
      if (Spec.Map->Type == 1)
        MapOperand = CallInst::Create(HashTagAsm->getFunctionType(), HashTagAsm, {Reference}, "",
                                      Call->getIterator());
      else if (Spec.Map->Type == 9)
        MapOperand = CallInst::Create(LruTagAsm->getFunctionType(), LruTagAsm, {Reference}, "",
                                      Call->getIterator());
      else if (Spec.Map->Type == 6)
        MapOperand = CallInst::Create(PercpuTagAsm->getFunctionType(), PercpuTagAsm, {Reference}, "",
                                      Call->getIterator());
      Call->setArgOperand(0, MapOperand);
      auto Decl = Projection->getOrInsertFunction(Lookup ? "__mojobpf_lookup_v1" : Delete ? "__mojobpf_delete_elem_v1" : "__mojobpf_update_v1", Expected);
      Call->setCalledOperand(Decl.getCallee());
      }
    }
    CurrentPreparations[BB] = Preparation;
  }
  for (Instruction *I : Erase) I->eraseFromParent();
  if (auto *PT = Projection->getFunction("llvm.bpf.passthrough.i32.i32")) {
    // The relocation runtime served the reified expansions;
    // no use survives them.
    if (!PT->use_empty())
      return failure("MBPF311", "relocation runtime has an unmatched use", PT);
    PT->eraseFromParent();
  }
  if (KeyCell) {
    if (!KeyCell->use_empty()) return failure("MBPF311", "unmatched lowered key cell use");
    KeyCell->eraseFromParent();
  }
  if (RecordCell) {
    if (!RecordCell->use_empty()) return failure("MBPF311", "unmatched lowered record cell use");
    RecordCell->eraseFromParent();
  }
  // Any surviving global/constant expression use is unexpected. Only the
  // checked used-list and map-interface conversions may refer to globals.
  auto *ProjectionUsed = Projection->getGlobalVariable("llvm.compiler.used");
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
  // The projection re-audit follows the same downgrade decisions;
  // its own records are discarded (the source audit's stand) while
  // any non-downgraded violation still refuses.
  auto Source = auditSource(*Projection, Spec, *Measured, Permissive);
  if (!Source) return Source.takeError();
  return Error::success();
}

Error auditLowered(const Module &M, const LoweringSpec &Spec, const TargetFacts &Facts, bool Permissive) {
  return auditLoweredCore(M, Spec, Facts, true, Permissive);
}
} // namespace mojobpf
