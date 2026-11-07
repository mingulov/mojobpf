// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "mojobpf/TargetModel.h"
#include "mojobpf/GEPOffset.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/TargetParser/Triple.h"
#include <algorithm>
#include <memory>
#include <set>

using namespace llvm;
namespace mojobpf {
char CompilerError::ID;
CompilerError::CompilerError(StringRef Code, StringRef Stage, StringRef Explanation,
                             StringRef Location, StringRef Remedy)
    : Code(Code), Stage(Stage), Severity("error"), Explanation(Explanation),
      Location(Location), Remedy(Remedy) {}
void CompilerError::log(raw_ostream &OS) const {
  OS << Code << " (" << Stage << "/" << Severity << "): " << Explanation
     << "; location: " << Location << "; remedy: " << Remedy;
}
std::error_code CompilerError::convertToErrorCode() const {
  return inconvertibleErrorCode();
}
json::Object CompilerError::diagnostic() const {
  return json::Object{{"code", Code}, {"stage", Stage}, {"severity", Severity},
          {"explanation", Explanation}, {"location", Location}, {"remedy", Remedy}};
}
Error compilerError(StringRef Code, StringRef Stage, StringRef Explanation,
                    StringRef Location, StringRef Remedy) {
  return make_error<CompilerError>(Code, Stage, Explanation, Location, Remedy);
}
json::Array takeDiagnostics(Error ErrorValue) {
  json::Array Result;
  handleAllErrors(std::move(ErrorValue), [&](const CompilerError &E) {
    Result.push_back(E.diagnostic());
  }, [&](const ErrorInfoBase &E) {
    Result.push_back(CompilerError("MBPF319", "adapter.target", E.message(),
                                  "module", "retain the input and report this compiler failure").diagnostic());
  });
  return Result;
}
json::Object TargetFacts::json() const {
  json::Object Result = Measured;
  Result["input_triple"] = InputTriple;
  Result["target_triple"] = TargetTriple;
  Result["input_layout"] = InputLayout;
  Result["target_layout"] = TargetLayout;
  Result["producer_authenticated"] = false;
  return Result;
}

namespace {
constexpr StringLiteral ModelID = "mojo-1.1.0-x86_64-bpfel-v3-minimal-v1";
constexpr StringLiteral HostFeatures =
    "+adx,+aes,+avx,+avx2,+avx512bf16,+avx512bitalg,+avx512bw,+avx512cd,+avx512dq,+avx512f,+avx512ifma,+avx512vbmi,+avx512vbmi2,+avx512vl,+avx512vnni,+avx512vpopcntdq,+bmi,+bmi2,+clflushopt,+clwb,+clzero,+crc32,+cx16,+cx8,+f16c,+fma,+fsgsbase,+fxsr,+gfni,+invpcid,+lzcnt,+mmx,+movbe,+mwaitx,+pclmul,+pku,+popcnt,+prfchw,+rdpid,+rdpru,+rdrnd,+rdseed,+sahf,+sha,+shstk,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+sse4a,+ssse3,+vaes,+vpclmulqdq,+wbnoinvd,+x87,+xsave,+xsavec,+xsaveopt,+xsaves";

Error requestFailure(StringRef Explanation) {
  return compilerError("MBPF202", "adapter.request", Explanation, "spec",
                       "supply the complete version-1 lowering specification");
}
Error validateSpec(const LoweringSpec &Spec) {
  if (Spec.SchemaVersion != 1)
    return requestFailure("unsupported lowering specification version or type");
  bool Profile = Spec.ProfileID == "linux-bpfel-v3" || Spec.ProfileID == "linux-bpfel-v3-subprog" ||
      Spec.ProfileID == "linux-bpfel-v3-net" || Spec.ProfileID == "linux-bpfel-v3-hash" ||
      Spec.ProfileID == "linux-bpfel-v3-lru" || Spec.ProfileID == "linux-bpfel-v3-uprobe" ||
      Spec.ProfileID == "linux-bpfel-v3-reserve" || Spec.ProfileID == "linux-bpfel-v3-core";
  bool Contract = (Spec.ProgramType == "xdp" && Spec.Section == "xdp") ||
      (Spec.ProgramType == "tc" && Spec.Section == "classifier") ||
      (Spec.ProgramType == "uprobe" && Spec.Section == "uprobe") ||
      (Spec.ProgramType == "tracepoint" && Spec.Section == "tracepoint/syscalls/sys_enter_getpid");
  if (Spec.ModelID != ModelID || !Profile || !Contract ||
      Spec.KernelLicense != "Apache-2.0 WITH LLVM-exception")
    return requestFailure("unsupported model/profile/program/section/license contract");
  if (Spec.Entry.empty() || !(isAlpha(Spec.Entry.front()) || Spec.Entry.front() == '_') ||
      !all_of(Spec.Entry, [](char C) { return isAlnum(C) || C == '_'; }))
    return requestFailure("entry must be an ordinary LLVM/ELF identifier");
  if (Spec.Map) {
    const auto &Map = *Spec.Map;
    // The CO-RE probe reads a 4096-byte array slot (value
    // 32768 bits); every other single-map shape carries the
    // u64 value. The wide value is structurally core-only:
    // no other admitted program has it.
    bool CoreMap = Map.Symbol == "mojobpf_map0" && Map.Type == 2 && Map.KeyBits == 32 &&
        Map.ValueBits == 32768 && Map.MaxEntries == 1 && Map.Flags == 0;
    if (Map.Symbol != "mojobpf_map0" || (Map.Type != 2 && Map.Type != 1 && Map.Type != 9 && Map.Type != 6) || Map.KeyBits != 32 ||
        ((Map.ValueBits != 64 || Map.MaxEntries < 1) && !CoreMap) || Map.Flags != 0)
      return requestFailure("unsupported array/hash/lru/percpu map contract");
  }
  return Error::success();
}
Error exactFields(const json::Object &Object, ArrayRef<StringRef> Names) {
  if (Object.size() != Names.size())
    return requestFailure("missing or unknown lowering specification field");
  for (const auto &Field : Object)
    if (!is_contained(Names, Field.first.str()))
      return requestFailure("unknown lowering specification field");
  return Error::success();
}
Error targetFailure(StringRef Explanation, StringRef Location = "module") {
  return compilerError("MBPF319", "adapter.target", Explanation, Location);
}
Error numericFailure(StringRef Explanation) {
  return compilerError("MBPF305", "adapter.audit", Explanation);
}
std::string typeName(Type *T) {
  std::string Text;
  raw_string_ostream OS(Text);
  T->print(OS);
  return Text;
}
json::Object layoutFacts(const DataLayout &DL, Type *T) {
  return json::Object{{"store_size", int64_t(DL.getTypeStoreSize(T).getFixedValue())},
          {"alloc_size", int64_t(DL.getTypeAllocSize(T).getFixedValue())},
          {"abi_alignment", int64_t(DL.getABITypeAlign(T).value())},
          {"preferred_alignment", int64_t(DL.getPrefTypeAlign(T).value())}};
}
Error inspectAttributes(const AttributeList &Attributes, StringRef Owner,
                        json::Array &Observed) {
  for (unsigned Slot : Attributes.indexes()) {
    for (Attribute A : Attributes.getAttributes(Slot)) {
      bool Allowed = false;
      if (A.isStringAttribute() && Slot == AttributeList::FunctionIndex) {
        Allowed = (A.getKindAsString() == "target-cpu" && A.getValueAsString() == "znver4") ||
                  (A.getKindAsString() == "target-features" && A.getValueAsString() == HostFeatures);
      } else if (A.isEnumAttribute()) {
        // noinline survives the frontend only on the admitted
        // subprogram definition; auditSource pins that placement
        // (callee carries it, the entrypoint never does).
        Allowed = (A.getKindAsEnum() == Attribute::NoUndef && Slot != AttributeList::FunctionIndex) ||
                  (A.getKindAsEnum() == Attribute::NoInline && Slot == AttributeList::FunctionIndex);
      }
      if (!Allowed)
        return targetFailure("attribute is outside the frozen producer model: " + A.getAsString(), Owner);
      Observed.push_back(json::Object{{"owner", Owner.str()}, {"slot", int64_t(Slot)},
                                      {"attribute", A.getAsString()}});
    }
  }
  return Error::success();
}
} // namespace

Expected<LoweringSpec> readLoweringSpec(StringRef JSON) {
  auto Parsed = json::parse(JSON);
  if (!Parsed) {
    consumeError(Parsed.takeError());
    return requestFailure("malformed lowering specification JSON");
  }
  auto *Object = Parsed->getAsObject();
  if (!Object)
    return requestFailure("lowering specification must be an object");
  if (auto E = exactFields(*Object, {"schema_version", "model_id", "profile_id", "entry", "program_type", "section", "kernel_license", "map"}))
    return std::move(E);
  auto Version = Object->get("schema_version")->getAsUINT64();
  if (!Version || *Version != 1)
    return requestFailure("unsupported lowering specification version or type");
  LoweringSpec Spec;
  Spec.SchemaVersion = 1;
  for (auto Field : {std::pair<StringRef, std::string *>("model_id", &Spec.ModelID),
                     {"profile_id", &Spec.ProfileID}, {"entry", &Spec.Entry},
                     {"program_type", &Spec.ProgramType}, {"section", &Spec.Section},
                     {"kernel_license", &Spec.KernelLicense}}) {
    auto Value = Object->getString(Field.first);
    if (!Value || Value->empty())
      return requestFailure("lowering specification strings must be nonempty");
    *Field.second = Value->str();
  }
  if (auto E = validateSpec(Spec)) return std::move(E);
  auto *MapValue = Object->get("map");
  if (MapValue->getAsNull())
    return Spec;
  auto *Map = MapValue->getAsObject();
  if (!Map)
    return requestFailure("map must be null or the exact array/hash/lru/percpu object");
  if (auto E = exactFields(*Map, {"symbol", "type", "key_bits", "value_bits", "max_entries", "flags"}))
    return std::move(E);
  auto Symbol = Map->getString("symbol");
  if (!Symbol || *Symbol != "mojobpf_map0")
    return requestFailure("unsupported map symbol");
  auto Type = Map->get("type")->getAsUINT64();
  // All four single-map kinds flip in T4a-3 (array, hash,
  // LRU, percpu); any other type stays unadmitted.
  if (!Type || (*Type != 2 && *Type != 1 && *Type != 9 && *Type != 6))
    return requestFailure("unsupported map field or type");
  for (auto Expected : {std::pair<StringRef, int64_t>("key_bits", 32), {"flags", 0}}) {
    auto Actual = Map->get(Expected.first)->getAsUINT64();
    if (!Actual || *Actual != Expected.second)
      return requestFailure("unsupported array/hash/lru/percpu map field or type");
  }
  auto ValueBits = Map->get("value_bits")->getAsUINT64();
  if (!ValueBits || (*ValueBits != 64 && *ValueBits != 32768))
    return requestFailure("unsupported array/hash/lru/percpu map field or type");
  // Dense keys 0..N-1 need an N-entry map; the entry count comes
  // from the audited IR (the service authors it from the scan).
  // Publication stays gated downstream (the driver qualifies
  // shapes 1..4; wider dense shapes flow to its MBPF107). The
  // CO-RE probe reads a single 4096-byte slot (value 32768
  // bits, exactly one entry); the wide value admits no other
  // entry count.
  auto Entries = Map->get("max_entries")->getAsUINT64();
  if (!Entries || *Entries < 1 || *Entries > UINT32_MAX)
    return requestFailure("map max_entries must be a positive entry count");
  if (*ValueBits == 32768 && (*Type != 2 || *Entries != 1))
    return requestFailure("unsupported array/hash/lru/percpu map field or type");
  Spec.Map = ArrayMapSpec{"mojobpf_map0", (unsigned)*Type, 32, (unsigned)*ValueBits, (unsigned)*Entries, 0};
  return Spec;
}

Expected<TargetFacts> inspectTargetModel(const Module &M, const LoweringSpec &Spec) {
  if (auto E = validateSpec(Spec)) return std::move(E);
  // Initialize only the selected target. The target owns the layout string.
  LLVMInitializeBPFTargetInfo();
  LLVMInitializeBPFTarget();
  LLVMInitializeBPFTargetMC();
  std::string LookupError;
  const std::string BPFTriple = "bpfel-unknown-none";
  const Target *BPF = TargetRegistry::lookupTarget(BPFTriple, LookupError);
  if (!BPF)
    return targetFailure("BPF target unavailable: " + LookupError);
  std::unique_ptr<TargetMachine> Machine(BPF->createTargetMachine(
      Triple(BPFTriple), "v3", "", TargetOptions(), Reloc::Static));
  if (!Machine)
    return targetFailure("cannot construct the selected BPF v3 target machine");
  const DataLayout TargetDL = Machine->createDataLayout();
  const DataLayout &HostDL = M.getDataLayout();
  if (M.getTargetTriple().str() != "x86_64-unknown-linux-gnu")
    return targetFailure("input triple is outside the selected producer model");
  if (M.getDataLayoutStr().empty() || !HostDL.isLittleEndian() || !TargetDL.isLittleEndian() ||
      HostDL.getPointerSizeInBits(0) != 64 || HostDL.getIndexSizeInBits(0) != 64 ||
      HostDL.getPointerABIAlignment(0).value() != 8 || TargetDL.getPointerSizeInBits(0) != 64 ||
      TargetDL.getIndexSizeInBits(0) != 64 || TargetDL.getPointerABIAlignment(0).value() != 8)
    return targetFailure("little-endian AS0 pointer/index/alignment proof failed");

  auto *Entry = M.getFunction(Spec.Entry);
  if (!Entry || Entry->isDeclaration() || Entry->isVarArg() || Entry->arg_size() != 1 ||
      !Entry->getReturnType()->isIntegerTy(32) || !Entry->getArg(0)->getType()->isPointerTy() ||
      Entry->getCallingConv() != CallingConv::C || Entry->hasLocalLinkage())
    return compilerError("MBPF302", "adapter.audit", "entry must be an exported C-ABI i32(AS0 pointer) definition", Spec.Entry);

  TargetFacts Facts;
  Facts.InputTriple = M.getTargetTriple().str();
  Facts.TargetTriple = BPFTriple;
  Facts.InputLayout = M.getDataLayoutStr();
  Facts.TargetLayout = TargetDL.getStringRepresentation();
  Facts.Measured["pointer_bits"] = int64_t(HostDL.getPointerSizeInBits(0));
  Facts.Measured["index_bits"] = int64_t(HostDL.getIndexSizeInBits(0));
  Facts.Measured["pointer_alignment_bits"] = int64_t(HostDL.getPointerABIAlignment(0).value() * 8);
  Facts.Measured["little_endian"] = true;
  Facts.Measured["target_cpu"] = "v3";
  Facts.Measured["optimization_pipeline"] = "none";
  Facts.Measured["entry_abi"] = json::Object{{"symbol", Entry->getName().str()},
                                            {"signature", typeName(Entry->getFunctionType())},
                                            {"calling_convention", int64_t(Entry->getCallingConv())}};

  SmallPtrSet<Type *, 32> UsedTypes;
  SmallVector<Type *, 32> PendingTypes;
  auto AddType = [&](Type *T) { if (!T->isVoidTy() && !T->isLabelTy() && !T->isMetadataTy()) PendingTypes.push_back(T); };
  json::Array ObservedAttributes, GEPOffsets;
  SmallVector<const GetElementPtrInst *, 16> GEPs;
  SmallVector<const LoadInst *, 16> Loads;
  SmallVector<const StoreInst *, 16> Stores;
  unsigned InstructionCount = 0, BlockCount = 0;
  for (const Function &F : M) {
    if (auto E = inspectAttributes(F.getAttributes(), F.getName(), ObservedAttributes))
      return std::move(E);
    AddType(F.getReturnType());
    for (const Argument &A : F.args()) AddType(A.getType());
    for (const BasicBlock &BB : F) {
      if (++BlockCount > MaxBlocks)
        return compilerError("MBPF320", "adapter.resource", "basic-block analysis budget exhausted");
      for (const Instruction &I : BB) {
        if (++InstructionCount > MaxInstructions)
          return compilerError("MBPF320", "adapter.resource", "instruction analysis budget exhausted");
        AddType(I.getType());
        for (const Use &U : I.operands()) AddType(U->getType());
        if (auto *Call = dyn_cast<CallBase>(&I)) {
          if (auto E = inspectAttributes(Call->getAttributes(), "call in " + F.getName().str(), ObservedAttributes))
            return std::move(E);
        }
        if (auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
          AddType(GEP->getSourceElementType());
          GEPs.push_back(GEP);
        }
        if (isa<AddrSpaceCastInst>(I))
          return compilerError("MBPF311", "adapter.audit", "address-space casts are outside the model");
        if (const auto *L = dyn_cast<LoadInst>(&I)) Loads.push_back(L);
        if (const auto *S = dyn_cast<StoreInst>(&I)) Stores.push_back(S);
      }
    }
  }
  unsigned TypeWork = 0;
  std::set<std::string> SeenNames;
  json::Array Types;
  while (!PendingTypes.empty()) {
    if (++TypeWork > DefaultAnalysisBudget)
      return compilerError("MBPF320", "adapter.resource", "type analysis budget exhausted");
    Type *T = PendingTypes.pop_back_val();
    if (!UsedTypes.insert(T).second) continue;
    if (auto *P = dyn_cast<PointerType>(T)) {
      if (P->getAddressSpace() != 0 || HostDL.isNonIntegralPointerType(P) || TargetDL.isNonIntegralPointerType(P))
        return compilerError("MBPF311", "adapter.audit", "used pointer is non-AS0 or non-integral");
    } else if (auto *Integer = dyn_cast<IntegerType>(T)) {
      unsigned Bits = Integer->getBitWidth();
      if (Bits != 1 && Bits != 8 && Bits != 16 && Bits != 32 && Bits != 64)
        return numericFailure("integer width is outside the scalar emission model");
    } else if (auto *FT = dyn_cast<FunctionType>(T)) {
      AddType(FT->getReturnType());
      for (Type *Parameter : FT->params()) AddType(Parameter);
      continue;
    } else {
      return numericFailure("floating, surviving vector or aggregate runtime type is outside the scalar emission model");
    }
    if (T->isSized()) {
      if (layoutFacts(HostDL, T) != layoutFacts(TargetDL, T))
        return targetFailure("used type's storage/allocation/alignment facts differ: " + typeName(T));
      SeenNames.insert(typeName(T));
    }
  }
  for (const std::string &Name : SeenNames) {
    for (Type *T : UsedTypes) if (typeName(T) == Name) {
      auto Row = layoutFacts(HostDL, T);
      Row["type"] = Name;
      Types.push_back(std::move(Row));
      break;
    }
  }
  // Reject unsupported widths and scalable/aggregate forms before asking
  // fixed-size memory/offset APIs to establish facts about their uses.
  for (const auto *GEP : GEPs) {
    APInt HostOffset(HostDL.getIndexSizeInBits(0), 0), TargetOffset(TargetDL.getIndexSizeInBits(0), 0);
    if (!GEP->accumulateConstantOffset(HostDL, HostOffset) ||
        !GEP->accumulateConstantOffset(TargetDL, TargetOffset) || HostOffset != TargetOffset)
      return compilerError("MBPF317", "adapter.audit", "GEP offset is dynamic or differs across target layouts");
    if (GEP->isInBounds() && InboundsScalingOverflows(HostDL, GEP, HostOffset))
      return compilerError("MBPF317", "adapter.audit", "inbounds GEP index scaling overflows the recorded offset");
    GEPOffsets.push_back(json::Object{{"source_type", typeName(GEP->getSourceElementType())},
                                     {"offset", HostOffset.getSExtValue()},
                                     {"inbounds", GEP->isInBounds()}});
  }
  for (const auto *L : Loads)
    if (L->getType()->isIntegerTy(1) || L->isVolatile() || L->isAtomic() || L->getAlign() != HostDL.getABITypeAlign(L->getType()))
      return targetFailure("load alignment/volatile/atomic contract is unproved");
  for (const auto *S : Stores)
    if (S->getValueOperand()->getType()->isIntegerTy(1) || S->isVolatile() || S->isAtomic() || S->getAlign() != HostDL.getABITypeAlign(S->getValueOperand()->getType()))
      return targetFailure("store alignment/volatile/atomic contract is unproved");
  auto *Prefix = StructType::get(M.getContext(), {Type::getInt32Ty(M.getContext()), Type::getInt32Ty(M.getContext())});
  if (layoutFacts(HostDL, Prefix) != layoutFacts(TargetDL, Prefix))
    return targetFailure("two-u32 accessed prefix layout differs");
  auto PrefixFacts = layoutFacts(HostDL, Prefix);
  json::Array PrefixOffsets;
  for (unsigned Index = 0; Index != 2; ++Index) {
    auto HostOffset = HostDL.getStructLayout(Prefix)->getElementOffset(Index);
    auto BPFOffset = TargetDL.getStructLayout(Prefix)->getElementOffset(Index);
    if (HostOffset != BPFOffset || HostOffset != 4 * Index)
      return targetFailure("two-u32 accessed prefix field offset differs");
    PrefixOffsets.push_back(int64_t(HostOffset));
  }
  PrefixFacts["offsets"] = std::move(PrefixOffsets);
  Facts.Measured["prefix"] = std::move(PrefixFacts);
  Facts.Measured["types"] = std::move(Types);
  Facts.Measured["attributes"] = std::move(ObservedAttributes);
  Facts.Measured["gep_offsets"] = std::move(GEPOffsets);
  Facts.Measured["instruction_count"] = int64_t(InstructionCount);
  Facts.Measured["basic_block_count"] = int64_t(BlockCount);
  for (StringRef Name : {"producer_reader", "integer_semantics", "endian_pointer_index", "gep_alignment", "struct_entry_abi", "attributes", "pointer_provenance", "scratch_contracts", "calls_runtime", "debug_metadata", "target_transition"}) {
    json::Object Row{{"id", Name}, {"status", "admitted-semantic-subset"}, {"runtime_qualified", false}};
    if (Name == "producer_reader") {
      Row["status"] = "reader-verified";
      Row["producer_binding"] = "external capture required";
    } else if (Name == "integer_semantics" || Name == "struct_entry_abi") {
      Row["native_control"] = "external control required";
    } else if (Name == "pointer_provenance") {
      Row["backend_guest_proof"] = "required before runtime qualification";
    } else if (Name == "target_transition") {
      Row["status"] = "not-performed";
    }
    Facts.ProofObligations.push_back(std::move(Row));
  }
  return Facts;
}
} // namespace mojobpf
