// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "mojobpf/Lowering.h"
#include "llvm/BinaryFormat/Dwarf.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Verifier.h"

using namespace llvm;
namespace mojobpf {
namespace {
constexpr StringLiteral MetadataProducer = "MojoBPF typed LLVM adapter; source producer binding is external";
constexpr StringLiteral MetadataFile = "mojobpf-generated-map";
Error badMetadata() {
  return compilerError("MBPF319", "adapter.lowered", "generated map metadata differs from the finite map contract");
}
bool integerType(const DIType *T, unsigned Bits, unsigned Encoding) {
  auto *I = dyn_cast_or_null<DIBasicType>(T);
  return I && I->getMetadataID() == Metadata::DIBasicTypeKind &&
         I->getTag() == dwarf::DW_TAG_base_type && I->getSizeInBits() == Bits &&
         I->getEncoding() == Encoding && !I->getFlags() && !I->getNumExtraInhabitants();
}
bool pointerType(const DIDerivedType *T) {
  return T && T->getTag() == dwarf::DW_TAG_pointer_type && T->getSizeInBits() == 64 &&
         T->getAlignInBits() == 64 && !T->getDWARFAddressSpace() &&
         !T->getFlags() && T->getAnnotations().empty() && !T->getRawExtraData() &&
         !T->getPtrAuthData() && T->getName().empty() && !T->getFile() && !T->getScope() &&
         !T->getLine() && !T->getOffsetInBits() && !T->getNumExtraInhabitants();
}
bool compositeExtrasAbsent(const DICompositeType &T) {
  return !T.getOffsetInBits() && !T.getVTableHolder() && T.getTemplateParams().empty() &&
         T.getIdentifier().empty() && !T.getEnumKind() && !T.getSpecification() &&
         !T.getNumExtraInhabitants() && !T.getRawDiscriminator() && !T.getRawDataLocation() &&
         !T.getRawAssociated() && !T.getRawAllocated() && !T.getRawRank() && !T.getRawBitStride();
}
} // namespace

Error emitMapMetadata(ValidatedProgram &P) {
  if (auto E = P.requirePendingLowering()) return E;
  Module &M = *P.BoundModule;
  if (P.BoundSpec.Map) {
    auto *Map = M.getGlobalVariable(P.BoundSpec.Map->Symbol);
    const DataLayout &DL = M.getDataLayout();
    auto *T = cast<StructType>(Map->getValueType());
    const StructLayout *Layout = DL.getStructLayout(T);
    DIBuilder Builder(M);
    // This file describes adapter-generated metadata, not original source
    // line information. No source filename, subprogram or line is invented.
    auto *File = Builder.createFile(MetadataFile, "");
    auto *CU = Builder.createCompileUnit(dwarf::DW_LANG_Mojo, File, MetadataProducer,
                                         false, "", 0);
    auto *Int = Builder.createBasicType("int", 32, dwarf::DW_ATE_signed);
    auto *Key = Builder.createBasicType("UInt32", 32, dwarf::DW_ATE_unsigned);
    auto *Value = Builder.createBasicType("UInt64", 64, dwarf::DW_ATE_unsigned);
    auto Pointer = [&](DIType *Base) {
      return Builder.createPointerType(Base, DL.getPointerSizeInBits(0),
                                       DL.getPointerABIAlignment(0).value() * 8);
    };
    auto IntegerField = [&](unsigned Count) {
      auto *Array = Builder.createArrayType(32 * Count, 32, Int,
          Builder.getOrCreateArray({Builder.getOrCreateSubrange(0, Count)}));
      return Pointer(Array);
    };
    SmallVector<Metadata *, 4> Members;
    SmallVector<DIType *, 4> Types{IntegerField(P.BoundSpec.Map->Type),
        IntegerField(P.BoundSpec.Map->MaxEntries), Pointer(Key), Pointer(Value)};
    unsigned Index = 0;
    for (StringRef Name : {"type", "max_entries", "key", "value"}) {
      Members.push_back(Builder.createMemberType(CU, Name, File, 0,
          DL.getPointerSizeInBits(0), DL.getPointerABIAlignment(0).value() * 8,
          Layout->getElementOffsetInBits(Index), DINode::FlagZero, Types[Index]));
      ++Index;
    }
    auto *MapType = Builder.createStructType(CU, "mojobpf_array_map", File, 0,
        DL.getTypeAllocSize(T).getFixedValue() * 8, DL.getABITypeAlign(T).value() * 8,
        DINode::FlagZero, nullptr, Builder.getOrCreateArray(Members));
    auto *Global = Builder.createGlobalVariableExpression(CU, Map->getName(), Map->getName(),
        File, 0, MapType, false, true, Builder.createExpression(), nullptr, nullptr,
        DL.getABITypeAlign(T).value() * 8);
    Map->addDebugInfo(Global);
    if (!M.getModuleFlag("Debug Info Version"))
      M.addModuleFlag(Module::Warning, "Debug Info Version", DEBUG_METADATA_VERSION);
    Builder.finalize();
    P.Transformations.push_back(json::Object{{"kind", "map-metadata"}, {"symbol", Map->getName()},
        {"size", int64_t(Layout->getSizeInBytes())}, {"alignment", int64_t(DL.getABITypeAlign(T).value())},
        {"language", "Mojo"}, {"source_lines", false}, {"producer_authenticated", false}});
  }
  if (verifyModule(M, &errs()))
    return compilerError("MBPF106", "adapter.verify", "map metadata failed LLVM verification");
  if (auto E = auditLowered(M, P.BoundSpec, P.BoundFacts, P.permissive())) return E;
  P.State = ValidatedProgram::Phase::Complete;
  P.sealLoweringSnapshot();
  return Error::success();
}

// Internal to the lowering/audit implementation. No metadata is stripped
// until this exact finite graph has been checked in the actual module.
Error auditMapMetadata(const Module &M, const LoweringSpec &Spec, bool Complete) {
  for (const NamedMDNode &N : M.named_metadata()) {
    if (N.getName() == "llvm.module.flags") {
      if (N.getNumOperands() != 1) return badMetadata();
      const MDNode *Flag = N.getOperand(0);
      if (Flag->getNumOperands() != 3) return badMetadata();
      auto *Behavior = mdconst::dyn_extract<ConstantInt>(Flag->getOperand(0));
      auto *Name = dyn_cast<MDString>(Flag->getOperand(1));
      auto *Value = mdconst::dyn_extract<ConstantInt>(Flag->getOperand(2));
      if (!Behavior || !Behavior->getType()->isIntegerTy(32) || Behavior->getZExtValue() != 2 ||
          !Name || Name->getString() != "Debug Info Version" || !Value ||
          !Value->getType()->isIntegerTy(32) || Value->getZExtValue() != 3) return badMetadata();
    } else if (N.getName() != "llvm.dbg.cu" || !Complete || !Spec.Map) return badMetadata();
  }
  if (!Spec.Map || !Complete) {
    if (M.getNamedMetadata("llvm.dbg.cu")) return badMetadata();
    if (Spec.Map && M.getGlobalVariable(Spec.Map->Symbol)->hasMetadata()) return badMetadata();
    return Error::success();
  }
  auto *N = M.getNamedMetadata("llvm.dbg.cu");
  if (!N || N->getNumOperands() != 1 || !M.getModuleFlag("Debug Info Version")) return badMetadata();
  auto *CU = dyn_cast<DICompileUnit>(N->getOperand(0));
  if (!CU || CU->getSourceLanguage().getName() != dwarf::DW_LANG_Mojo || CU->getProducer() != MetadataProducer ||
      CU->isOptimized() || !CU->getFlags().empty() || CU->getRuntimeVersion() ||
      CU->getEmissionKind() != DICompileUnit::FullDebug || !CU->getEnumTypes().empty() ||
      !CU->getRetainedTypes().empty() || !CU->getImportedEntities().empty() ||
      !CU->getMacros().empty() || CU->getGlobalVariables().size() != 1 ||
      !CU->getSplitDebugFilename().empty() || CU->getDWOId() || CU->getDebugInfoForProfiling() ||
      !CU->getSplitDebugInlining() || CU->getNameTableKind() != DICompileUnit::DebugNameTableKind::Default ||
      CU->getRangesBaseAddress() || !CU->getSysRoot().empty() || !CU->getSDK().empty()) return badMetadata();
  auto *File = CU->getFile();
  if (!File || File->getFilename() != MetadataFile || !File->getDirectory().empty() ||
      File->getChecksum() || File->getSource()) return badMetadata();
  const auto *Map = M.getGlobalVariable(Spec.Map->Symbol);
  SmallVector<std::pair<unsigned, MDNode *>, 2> Attachments;
  Map->getAllMetadata(Attachments);
  if (Attachments.size() != 1 || Attachments[0].first != LLVMContext::MD_dbg) return badMetadata();
  auto *G = dyn_cast<DIGlobalVariableExpression>(Attachments[0].second);
  if (!G || G != CU->getGlobalVariables()[0] || G->getExpression()->getNumElements()) return badMetadata();
  auto *V = G->getVariable();
  if (V->getName() != Spec.Map->Symbol || V->getLinkageName() != Spec.Map->Symbol ||
      V->getScope() != CU || V->getFile() != File || V->getLine() || V->isLocalToUnit() ||
      !V->isDefinition() || V->getAlignInBits() != 64 || V->getStaticDataMemberDeclaration() ||
      V->getTemplateParams() || !V->getAnnotations().empty()) return badMetadata();
  auto *T = dyn_cast<DICompositeType>(V->getType());
  if (!T || T->getTag() != dwarf::DW_TAG_structure_type || T->getSizeInBits() != 256 ||
      T->getAlignInBits() != 64 || T->getElements().size() != 4 || T->getBaseType() ||
      T->getFlags() || T->getLine() || T->getRuntimeLang() || !T->getAnnotations().empty() ||
      !compositeExtrasAbsent(*T) || T->getFile() != File || T->getScope() || T->getName() != "mojobpf_array_map") return badMetadata();
  unsigned Index = 0;
  for (StringRef Name : {"type", "max_entries", "key", "value"}) {
    auto *Member = dyn_cast<DIDerivedType>(T->getElements()[Index]);
    if (!Member || Member->getTag() != dwarf::DW_TAG_member || Member->getName() != Name ||
        Member->getSizeInBits() != 64 || Member->getAlignInBits() != 64 || Member->getOffsetInBits() != 64 * Index ||
        Member->getLine() || Member->getFlags() || !Member->getAnnotations().empty() || Member->getRawExtraData() ||
        Member->getDWARFAddressSpace() || Member->getPtrAuthData() || Member->getNumExtraInhabitants() ||
        Member->getFile() != File || Member->getScope())
      return badMetadata();
    auto *Pointer = dyn_cast<DIDerivedType>(Member->getBaseType());
    if (!pointerType(Pointer)) return badMetadata();
    if (Index < 2) {
      auto *Array = dyn_cast_or_null<DICompositeType>(Pointer->getBaseType());
      unsigned Count = Index == 0 ? Spec.Map->Type : Spec.Map->MaxEntries;
      if (!Array || Array->getTag() != dwarf::DW_TAG_array_type || Array->getSizeInBits() != Count * 32 ||
          Array->getAlignInBits() != 32 || Array->getElements().size() != 1 || Array->getFlags() ||
          !compositeExtrasAbsent(*Array) || !Array->getAnnotations().empty() || Array->getRuntimeLang() ||
          !Array->getName().empty() || Array->getFile() || Array->getScope() || Array->getLine() ||
          !integerType(Array->getBaseType(), 32, dwarf::DW_ATE_signed)) return badMetadata();
      auto *Range = dyn_cast<DISubrange>(Array->getElements()[0]);
      auto *Number = Range ? mdconst::dyn_extract_or_null<ConstantInt>(Range->getRawCountNode()) : nullptr;
      auto *Lower = Range ? mdconst::dyn_extract_or_null<ConstantInt>(Range->getRawLowerBound()) : nullptr;
      if (!Number || Number->getZExtValue() != Count || !Lower || !Lower->isZero() ||
          Range->getRawUpperBound() || Range->getRawStride()) return badMetadata();
    } else if (!integerType(Pointer->getBaseType(), Index == 2 ? 32 : 64, dwarf::DW_ATE_unsigned)) return badMetadata();
    ++Index;
  }
  return Error::success();
}
} // namespace mojobpf
