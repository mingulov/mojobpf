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

// The CO-RE relocation graph: the local task_struct layout (a
// deliberately phony five-member record: only member names and
// indices feed relocations), the single-map description (array,
// u32 key, 4096-byte value, one entry), the compile unit tying
// them together, and the minimal entry subprogram. The two
// relocation markers load through the pinned globals; the
// preserve-access-index attachments plus the btf_ama attribute
// group are what the backend recognizes (without them no
// relocation is emitted). Member names and indices match the
// qualified Lane-A synthesis exactly; metadata numbering is the
// builder's own.
Expected<json::Object> emitCoreMetadata(Module &M, GlobalVariable *Map, Function *Entry,
                                        StringRef EntryName, bool HasRingbufSize) {
  if (!Map)
    return compilerError("MBPF314", "adapter.lowered", "core map global is missing");
  if (M.getGlobalVariable("mojobpf_map1") || HasRingbufSize)
    return compilerError("MBPF319", "adapter.lowered", "core probe carries no ring-buffer companion");
  auto *ReadGlobal = M.getGlobalVariable("llvm.task_struct:0:32$0:1");
  auto *ExistsGlobal = M.getGlobalVariable("llvm.task_struct:2:1$0:4");
  if (!ReadGlobal || !ExistsGlobal)
    return compilerError("MBPF319", "adapter.lowered", "core relocation markers are missing");
  if (!Entry || Entry->getName() != EntryName)
    return compilerError("MBPF319", "adapter.lowered", "core entry is missing");
  const DataLayout &DL = M.getDataLayout();
  auto *T = cast<StructType>(Map->getValueType());
  const StructLayout *Layout = DL.getStructLayout(T);
  DIBuilder Builder(M);
  auto *File = Builder.createFile(MetadataFile, "");
  auto *CU = Builder.createCompileUnit(dwarf::DW_LANG_Mojo, File, MetadataProducer, false, "", 0);
  auto *Int = Builder.createBasicType("int", 32, dwarf::DW_ATE_signed);
  auto *U64 = Builder.createBasicType("unsigned long long", 64, dwarf::DW_ATE_unsigned);
  auto *U32 = Builder.createBasicType("unsigned int", 32, dwarf::DW_ATE_unsigned);
  auto ArrayOf = [&](uint64_t Count) {
    return Builder.createArrayType(32 * Count, 0, Int,
        Builder.getOrCreateArray({Builder.getOrCreateSubrange(0, Count)}));
  };
  auto U64Array = [&](uint64_t Count) {
    return Builder.createArrayType(64 * Count, 0, U64,
        Builder.getOrCreateArray({Builder.getOrCreateSubrange(0, Count)}));
  };
  auto Pointer = [&](DIType *Base) { return Builder.createPointerType(Base, 64, 0); };
  // The local task_struct layout. The struct is built through
  // a forward declaration (members scope to the declaration,
  // then resolve to the completed type).
  auto *TaskFwd = Builder.createReplaceableCompositeType(dwarf::DW_TAG_structure_type, "task_struct", CU, File, 0);
  auto *ScxFwd = Builder.createReplaceableCompositeType(dwarf::DW_TAG_structure_type, "scx", TaskFwd, File, 0);
  auto *Scx = Builder.createStructType(TaskFwd, "scx", File, 0, 1664, 0, DINode::FlagZero, nullptr,
      Builder.getOrCreateArray({Builder.createMemberType(ScxFwd, "__w", File, 0, 1664, 0, 0,
          DINode::FlagZero, U64Array(26))}));
  Builder.replaceTemporary(TempMDNode(ScxFwd), Scx);
  SmallVector<Metadata *, 5> TaskMembers{
      Builder.createMemberType(TaskFwd, "__phony_pad", File, 0, 256, 0, 0, DINode::FlagZero, U64Array(4)),
      Builder.createMemberType(TaskFwd, "pid", File, 0, 32, 0, 256, DINode::FlagZero, Int),
      Builder.createMemberType(TaskFwd, "tgid", File, 0, 32, 0, 288, DINode::FlagZero, Int),
      Builder.createMemberType(TaskFwd, "__phony2", File, 0, 512, 0, 320, DINode::FlagZero, U64Array(8)),
      Builder.createMemberType(TaskFwd, "scx", File, 0, 1664, 0, 832, DINode::FlagZero, Scx)};
  auto *Task = Builder.createStructType(CU, "task_struct", File, 0, 2496, 0, DINode::FlagZero, nullptr,
      Builder.getOrCreateArray(TaskMembers));
  Builder.replaceTemporary(TempMDNode(TaskFwd), Task);
  // The single-map description. The backend's BTF emitter reads
  // the member names (type, key_size, value_size, max_entries)
  // and the array counts (2, 4, 4096, 1).
  auto *MapFwd = Builder.createReplaceableCompositeType(dwarf::DW_TAG_structure_type, "", CU, File, 0);
  SmallVector<Metadata *, 4> MapMembers;
  unsigned MapIndex = 0;
  for (auto [Name, Count] : {std::pair<StringRef, uint64_t>("type", 2), {"key_size", 4},
                             {"value_size", 4096}, {"max_entries", 1}}) {
    MapMembers.push_back(Builder.createMemberType(MapFwd, Name, File, 0, 64, 0, 64 * MapIndex,
        DINode::FlagZero, Pointer(ArrayOf(Count))));
    ++MapIndex;
  }
  auto *MapType = Builder.createStructType(CU, "", File, 0, 256, 0, DINode::FlagZero, nullptr,
      Builder.getOrCreateArray(MapMembers));
  Builder.replaceTemporary(TempMDNode(MapFwd), MapType);
  auto *Global = Builder.createGlobalVariableExpression(CU, Map->getName(), Map->getName(), File, 0,
      MapType, false, true, Builder.createExpression());
  Map->addDebugInfo(Global);
  // The minimal entry subprogram (names the relocation
  // section) with its single context parameter.
  auto *XdpFwd = Builder.createReplaceableCompositeType(dwarf::DW_TAG_structure_type, "xdp_md", File, File, 0);
  auto *XdpMd = Builder.createStructType(File, "xdp_md", File, 0, 96, 0, DINode::FlagZero, nullptr,
      Builder.getOrCreateArray({
          Builder.createMemberType(XdpFwd, "data", File, 0, 32, 0, 0, DINode::FlagZero, U32),
          Builder.createMemberType(XdpFwd, "data_end", File, 0, 32, 0, 32, DINode::FlagZero, U32),
          Builder.createMemberType(XdpFwd, "data_meta", File, 0, 32, 0, 64, DINode::FlagZero, U32)}));
  Builder.replaceTemporary(TempMDNode(XdpFwd), XdpMd);
  auto *CtxPtr = Pointer(XdpMd);
  auto *SubTy = Builder.createSubroutineType(Builder.getOrCreateTypeArray({Int, CtxPtr}));
  auto *SP = Builder.createFunction(File, Entry->getName(), Entry->getName(), File, 0, SubTy, 0,
      DINode::FlagPrototyped, DISubprogram::SPFlagDefinition);
  SP->replaceUnit(CU);
  Builder.createParameterVariable(SP, "ctx", 1, File, 0, CtxPtr, true, DINode::FlagZero);
  Entry->setSubprogram(SP);
  ReadGlobal->addMetadata("llvm.preserve.access.index", *Task);
  ExistsGlobal->addMetadata("llvm.preserve.access.index", *Task);
  AttributeSet Ama = AttributeSet::get(M.getContext(), {Attribute::get(M.getContext(), "btf_ama")});
  ReadGlobal->setAttributes(Ama);
  ExistsGlobal->setAttributes(Ama);
  if (!M.getModuleFlag("Debug Info Version"))
    M.addModuleFlag(Module::Warning, "Debug Info Version", DEBUG_METADATA_VERSION);
  Builder.finalize();
  return json::Object{{"kind", "core-metadata"}, {"symbol", Map->getName()},
      {"size", int64_t(Layout->getSizeInBytes())}, {"alignment", int64_t(DL.getABITypeAlign(T).value())},
      {"task_struct", "task_struct"}, {"subprogram", Entry->getName().str()},
      {"language", "Mojo"}, {"source_lines", false}, {"producer_authenticated", false}};
}

Error emitMapMetadata(ValidatedProgram &P) {
  if (auto E = P.requirePendingLowering()) return E;
  Module &M = *P.BoundModule;
  bool CoreMap = P.BoundSpec.Map && P.BoundSpec.Map->ValueBits == 32768;
  if (CoreMap) {
    auto *Map = M.getGlobalVariable(P.BoundSpec.Map->Symbol);
    auto Row = emitCoreMetadata(M, Map, P.BoundEntry, P.BoundSpec.Entry, (bool)P.RingbufSize);
    if (!Row) return Row.takeError();
    P.Transformations.push_back(std::move(*Row));
  }
  if (P.BoundSpec.Map && !CoreMap) {
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
    StringRef BtfName = "mojobpf_array_map";
    if (P.BoundSpec.Map->Type == 1) BtfName = "mojobpf_hash_map";
    else if (P.BoundSpec.Map->Type == 9) BtfName = "mojobpf_lru_map";
    else if (P.BoundSpec.Map->Type == 6) BtfName = "mojobpf_percpu_map";
    auto *MapType = Builder.createStructType(CU, BtfName, File, 0,
        DL.getTypeAllocSize(T).getFixedValue() * 8, DL.getABITypeAlign(T).value() * 8,
        DINode::FlagZero, nullptr, Builder.getOrCreateArray(Members));
    auto *Global = Builder.createGlobalVariableExpression(CU, Map->getName(), Map->getName(),
        File, 0, MapType, false, true, Builder.createExpression(), nullptr, nullptr,
        DL.getABITypeAlign(T).value() * 8);
    Map->addDebugInfo(Global);
    if (auto *Ringbuf = M.getGlobalVariable("mojobpf_map1")) {
      // The ring-buffer companion description: the two BTF-bound
      // attributes (type 27, max_entries from the audited size
      // tag); key and value sizes are implicitly zero, matching
      // the kernel ring-buffer contract.
      if (!P.RingbufSize)
        return compilerError("MBPF319", "adapter.lowered", "ring-buffer companion carries no audited size");
      auto *RbT = cast<StructType>(Ringbuf->getValueType());
      const StructLayout *RbLayout = DL.getStructLayout(RbT);
      SmallVector<Metadata *, 2> RbMembers;
      SmallVector<DIType *, 2> RbTypes{IntegerField(27), IntegerField(*P.RingbufSize)};
      unsigned RbIndex = 0;
      for (StringRef Name : {"type", "max_entries"}) {
        RbMembers.push_back(Builder.createMemberType(CU, Name, File, 0,
            DL.getPointerSizeInBits(0), DL.getPointerABIAlignment(0).value() * 8,
            RbLayout->getElementOffsetInBits(RbIndex), DINode::FlagZero, RbTypes[RbIndex]));
        ++RbIndex;
      }
      auto *RbMapType = Builder.createStructType(CU, "mojobpf_ringbuf_map", File, 0,
          DL.getTypeAllocSize(RbT).getFixedValue() * 8, DL.getABITypeAlign(RbT).value() * 8,
          DINode::FlagZero, nullptr, Builder.getOrCreateArray(RbMembers));
      auto *RbGlobal = Builder.createGlobalVariableExpression(CU, Ringbuf->getName(), Ringbuf->getName(),
          File, 0, RbMapType, false, true, Builder.createExpression(), nullptr, nullptr,
          DL.getABITypeAlign(RbT).value() * 8);
      Ringbuf->addDebugInfo(RbGlobal);
      P.Transformations.push_back(json::Object{{"kind", "map-metadata"}, {"symbol", Ringbuf->getName()},
          {"size", int64_t(RbLayout->getSizeInBytes())}, {"alignment", int64_t(DL.getABITypeAlign(RbT).value())},
          {"language", "Mojo"}, {"source_lines", false}, {"producer_authenticated", false}});
    } else if (P.RingbufSize) {
      return compilerError("MBPF319", "adapter.lowered", "audited ring-buffer size names no emitted companion");
    }
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

// The CO-RE relocation graph audit: the compile unit, the
// single-map description (array, u32 key, 4096-byte value, one
// entry), the local task_struct layout, the entry subprogram,
// and the preserve-access-index attachments naming the task
// type. Member names, indices, sizes, and offsets match the
// qualified synthesis exactly; only metadata numbering varies.
Error auditCoreMetadata(const Module &M, const LoweringSpec &Spec) {
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
  auto basicType = [&](const DIType *T, StringRef Name, unsigned Bits, unsigned Encoding) {
    auto *I = dyn_cast_or_null<DIBasicType>(T);
    return I && I->getMetadataID() == Metadata::DIBasicTypeKind &&
        I->getTag() == dwarf::DW_TAG_base_type && I->getName() == Name &&
        I->getSizeInBits() == Bits && I->getEncoding() == Encoding && !I->getFlags() &&
        !I->getNumExtraInhabitants();
  };
  auto pointerType = [&](const DIDerivedType *T, const DIType *Base) {
    return T && T->getTag() == dwarf::DW_TAG_pointer_type && T->getSizeInBits() == 64 &&
        T->getAlignInBits() == 0 && !T->getDWARFAddressSpace() && !T->getFlags() &&
        T->getAnnotations().empty() && !T->getRawExtraData() && !T->getPtrAuthData() &&
        T->getName().empty() && !T->getFile() && !T->getScope() && !T->getLine() &&
        !T->getOffsetInBits() && !T->getNumExtraInhabitants() && T->getBaseType() == Base;
  };
  auto arrayType = [&](const DICompositeType *A, const DIType *Base, uint64_t Count) {
    if (!A || A->getTag() != dwarf::DW_TAG_array_type || A->getSizeInBits() != Count * Base->getSizeInBits() ||
        A->getAlignInBits() != 0 || A->getElements().size() != 1 || A->getFlags() ||
        !compositeExtrasAbsent(*A) || !A->getAnnotations().empty() || A->getRuntimeLang() ||
        !A->getName().empty() || A->getFile() || A->getScope() || A->getLine() ||
        A->getBaseType() != Base)
      return false;
    auto *Range = dyn_cast<DISubrange>(A->getElements()[0]);
    auto *Number = Range ? mdconst::dyn_extract_or_null<ConstantInt>(Range->getRawCountNode()) : nullptr;
    auto *Lower = Range ? mdconst::dyn_extract_or_null<ConstantInt>(Range->getRawLowerBound()) : nullptr;
    return Range && Number && Number->getZExtValue() == Count && Lower && Lower->isZero() &&
        !Range->getRawUpperBound() && !Range->getRawStride();
  };
  auto memberType = [&](const DIDerivedType *Member, StringRef Name, const DIScope *Scope,
                        const DIType *Base, uint64_t Size, uint64_t Offset) {
    return Member && Member->getTag() == dwarf::DW_TAG_member && Member->getName() == Name &&
        Member->getSizeInBits() == Size && Member->getAlignInBits() == 0 &&
        Member->getOffsetInBits() == Offset && Member->getLine() == 0 && !Member->getFlags() &&
        Member->getAnnotations().empty() && !Member->getRawExtraData() &&
        !Member->getDWARFAddressSpace() && !Member->getPtrAuthData() &&
        !Member->getNumExtraInhabitants() && Member->getFile() == File &&
        Member->getScope() == Scope && Member->getBaseType() == Base;
  };
  const auto *Map = M.getGlobalVariable(Spec.Map->Symbol);
  SmallVector<std::pair<unsigned, MDNode *>, 2> Attachments;
  Map->getAllMetadata(Attachments);
  if (Attachments.size() != 1 || Attachments[0].first != LLVMContext::MD_dbg) return badMetadata();
  auto *G = dyn_cast<DIGlobalVariableExpression>(Attachments[0].second);
  if (!G || G != CU->getGlobalVariables()[0] || G->getExpression()->getNumElements()) return badMetadata();
  auto *V = G->getVariable();
  if (V->getName() != Spec.Map->Symbol || V->getLinkageName() != Spec.Map->Symbol ||
      V->getScope() != CU || V->getFile() != File || V->getLine() || V->isLocalToUnit() ||
      !V->isDefinition() || V->getAlignInBits() != 0 || V->getStaticDataMemberDeclaration() ||
      V->getTemplateParams() || !V->getAnnotations().empty()) return badMetadata();
  auto *T = dyn_cast<DICompositeType>(V->getType());
  if (!T || T->getTag() != dwarf::DW_TAG_structure_type || T->getSizeInBits() != 256 ||
      T->getAlignInBits() != 0 || T->getElements().size() != 4 || T->getBaseType() ||
      T->getFlags() || T->getLine() || T->getRuntimeLang() || !T->getAnnotations().empty() ||
      !compositeExtrasAbsent(*T) || T->getFile() != File || T->getScope() || !T->getName().empty())
    return badMetadata();
  unsigned MapIndex = 0;
  const DIType *Int = nullptr;
  for (auto [Name, Count] : {std::pair<StringRef, uint64_t>("type", 2), {"key_size", 4},
                             {"value_size", 4096}, {"max_entries", 1}}) {
    auto *Member = dyn_cast<DIDerivedType>(T->getElements()[MapIndex]);
    auto *Pointer = Member ? dyn_cast<DIDerivedType>(Member->getBaseType()) : nullptr;
    auto *Array = Pointer ? dyn_cast<DICompositeType>(Pointer->getBaseType()) : nullptr;
    if (!Array) return badMetadata();
    if (!Int) {
      Int = Array->getBaseType();
      if (!basicType(Int, "int", 32, dwarf::DW_ATE_signed)) return badMetadata();
    }
    if (!memberType(Member, Name, T, Pointer, 64, 64 * MapIndex) ||
        !pointerType(Pointer, Array) || !arrayType(Array, Int, Count))
      return badMetadata();
    ++MapIndex;
  }
  // The local task_struct layout: five members at the pinned
  // offsets (pid at index 1, the scx record at index 4).
  unsigned PreserveKind = M.getMDKindID("llvm.preserve.access.index");
  const auto *ReadGlobal = M.getGlobalVariable("llvm.task_struct:0:32$0:1");
  const auto *ExistsGlobal = M.getGlobalVariable("llvm.task_struct:2:1$0:4");
  auto *Task = dyn_cast_or_null<DICompositeType>(
      ReadGlobal ? ReadGlobal->getMetadata(PreserveKind) : nullptr);
  if (!Task || Task->getTag() != dwarf::DW_TAG_structure_type || Task->getName() != "task_struct" ||
      Task->getSizeInBits() != 2496 || Task->getAlignInBits() != 0 || Task->getElements().size() != 5 ||
      Task->getBaseType() || Task->getFlags() || Task->getLine() || Task->getRuntimeLang() ||
      !Task->getAnnotations().empty() || !compositeExtrasAbsent(*Task) || Task->getFile() != File ||
      Task->getScope() || (ExistsGlobal ? ExistsGlobal->getMetadata(PreserveKind) : nullptr) != Task)
    return badMetadata();
  const DIType *U64 = nullptr;
  auto *Pad = dyn_cast<DIDerivedType>(Task->getElements()[0]);
  auto *PadArray = Pad ? dyn_cast<DICompositeType>(Pad->getBaseType()) : nullptr;
  auto *Pid = dyn_cast<DIDerivedType>(Task->getElements()[1]);
  auto *Tgid = dyn_cast<DIDerivedType>(Task->getElements()[2]);
  auto *Phony2 = dyn_cast<DIDerivedType>(Task->getElements()[3]);
  auto *Phony2Array = Phony2 ? dyn_cast<DICompositeType>(Phony2->getBaseType()) : nullptr;
  auto *ScxMember = dyn_cast<DIDerivedType>(Task->getElements()[4]);
  auto *Scx = ScxMember ? dyn_cast<DICompositeType>(ScxMember->getBaseType()) : nullptr;
  if (!PadArray || !Phony2Array || !Scx) return badMetadata();
  U64 = PadArray->getBaseType();
  if (!basicType(U64, "unsigned long long", 64, dwarf::DW_ATE_unsigned)) return badMetadata();
  if (!memberType(Pad, "__phony_pad", Task, PadArray, 256, 0) || !arrayType(PadArray, U64, 4) ||
      !memberType(Pid, "pid", Task, Int, 32, 256) ||
      !memberType(Tgid, "tgid", Task, Int, 32, 288) ||
      !memberType(Phony2, "__phony2", Task, Phony2Array, 512, 320) || !arrayType(Phony2Array, U64, 8) ||
      !memberType(ScxMember, "scx", Task, Scx, 1664, 832))
    return badMetadata();
  if (Scx->getTag() != dwarf::DW_TAG_structure_type || Scx->getName() != "scx" ||
      Scx->getScope() != Task || Scx->getFile() != File || Scx->getSizeInBits() != 1664 ||
      Scx->getAlignInBits() != 0 || Scx->getElements().size() != 1 || Scx->getBaseType() ||
      Scx->getFlags() || Scx->getLine() || Scx->getRuntimeLang() || !Scx->getAnnotations().empty() ||
      !compositeExtrasAbsent(*Scx))
    return badMetadata();
  auto *Word = dyn_cast<DIDerivedType>(Scx->getElements()[0]);
  auto *WordArray = Word ? dyn_cast<DICompositeType>(Word->getBaseType()) : nullptr;
  if (!memberType(Word, "__w", Scx, WordArray, 1664, 0) || !WordArray ||
      !arrayType(WordArray, U64, 26))
    return badMetadata();
  // The entry subprogram with its single context parameter.
  const auto *F = M.getFunction(Spec.Entry);
  SmallVector<std::pair<unsigned, MDNode *>, 2> EntryAttachments;
  if (!F) return badMetadata();
  F->getAllMetadata(EntryAttachments);
  auto *SP = F->getSubprogram();
  if (EntryAttachments.size() != 1 || EntryAttachments[0].first != LLVMContext::MD_dbg ||
      EntryAttachments[0].second != SP)
    return badMetadata();
  auto *SubTy = SP ? dyn_cast<DISubroutineType>(SP->getType()) : nullptr;
  auto *CtxPtr = SubTy && SubTy->getTypeArray().size() == 2
      ? dyn_cast<DIDerivedType>(SubTy->getTypeArray()[1]) : nullptr;
  auto *XdpMd = CtxPtr ? dyn_cast<DICompositeType>(CtxPtr->getBaseType()) : nullptr;
  if (!SP || SP->getName() != Spec.Entry || SP->getLinkageName() != Spec.Entry ||
      SP->getScope() != File || SP->getFile() != File || SP->getLine() != 0 ||
      SP->getScopeLine() != 0 || SP->getUnit() != CU || !SP->isDefinition() ||
      SP->getSPFlags() != DISubprogram::SPFlagDefinition ||
      SP->getFlags() != DINode::FlagPrototyped || SP->isLocalToUnit() || SP->isOptimized() ||
      SP->getTemplateParams() || !SP->getAnnotations().empty() || SP->getThrownTypes() ||
      !SubTy || SubTy->getTypeArray().size() != 2 || SubTy->getTypeArray()[0] != Int ||
      !CtxPtr || !pointerType(CtxPtr, XdpMd) || !XdpMd)
    return badMetadata();
  if (XdpMd->getTag() != dwarf::DW_TAG_structure_type || XdpMd->getName() != "xdp_md" ||
      XdpMd->getScope() != File || XdpMd->getFile() != File || XdpMd->getSizeInBits() != 96 ||
      XdpMd->getAlignInBits() != 0 || XdpMd->getElements().size() != 3 || XdpMd->getBaseType() ||
      XdpMd->getFlags() || XdpMd->getLine() || XdpMd->getRuntimeLang() ||
      !XdpMd->getAnnotations().empty() || !compositeExtrasAbsent(*XdpMd))
    return badMetadata();
  const DIType *U32 = nullptr;
  unsigned XdpIndex = 0;
  for (StringRef Name : {"data", "data_end", "data_meta"}) {
    auto *Member = dyn_cast<DIDerivedType>(XdpMd->getElements()[XdpIndex]);
    if (!Member) return badMetadata();
    if (!U32) {
      U32 = Member->getBaseType();
      if (!basicType(U32, "unsigned int", 32, dwarf::DW_ATE_unsigned)) return badMetadata();
    }
    if (!memberType(Member, Name, XdpMd, U32, 32, 32 * XdpIndex)) return badMetadata();
    ++XdpIndex;
  }
  if (SP->getRetainedNodes().size() != 1) return badMetadata();
  auto *Ctx = dyn_cast<DILocalVariable>(SP->getRetainedNodes()[0]);
  if (!Ctx || Ctx->getName() != "ctx" || Ctx->getArg() != 1 || Ctx->getScope() != SP ||
      Ctx->getFile() != File || Ctx->getType() != CtxPtr || Ctx->getLine() != 0 ||
      Ctx->getAlignInBits() != 0 || Ctx->isArtificial() || Ctx->isObjectPointer())
    return badMetadata();
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
    if (auto *Ringbuf = M.getGlobalVariable("mojobpf_map1"))
      if (Ringbuf->hasMetadata()) return badMetadata();
    if (Spec.Map && Spec.Map->ValueBits == 32768) {
      // Pre-metadata relocation state: bare markers, bare
      // entry. The transition adds the exact relocation
      // graph the complete audit pins.
      for (StringRef Name : {"llvm.task_struct:0:32$0:1", "llvm.task_struct:2:1$0:4"}) {
        const auto *G = M.getGlobalVariable(Name);
        if (!G || G->hasMetadata() || G->getAttributes().getNumAttributes() != 0) return badMetadata();
      }
      if (const auto *F = M.getFunction(Spec.Entry); !F || F->hasMetadata()) return badMetadata();
    }
    return Error::success();
  }
  if (Spec.Map && Spec.Map->ValueBits == 32768) return auditCoreMetadata(M, Spec);
  auto *N = M.getNamedMetadata("llvm.dbg.cu");
  if (!N || N->getNumOperands() != 1 || !M.getModuleFlag("Debug Info Version")) return badMetadata();
  auto *CU = dyn_cast<DICompileUnit>(N->getOperand(0));
  if (!CU || CU->getSourceLanguage().getName() != dwarf::DW_LANG_Mojo || CU->getProducer() != MetadataProducer ||
      CU->isOptimized() || !CU->getFlags().empty() || CU->getRuntimeVersion() ||
      CU->getEmissionKind() != DICompileUnit::FullDebug || !CU->getEnumTypes().empty() ||
      !CU->getRetainedTypes().empty() || !CU->getImportedEntities().empty() ||
      !CU->getMacros().empty() || CU->getGlobalVariables().size() < 1 || CU->getGlobalVariables().size() > 2 ||
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
      !compositeExtrasAbsent(*T) || T->getFile() != File || T->getScope() ||
      T->getName() != (Spec.Map && Spec.Map->Type == 1 ? "mojobpf_hash_map" :
                       Spec.Map && Spec.Map->Type == 9 ? "mojobpf_lru_map" :
                       Spec.Map && Spec.Map->Type == 6 ? "mojobpf_percpu_map" : "mojobpf_array_map"))
      return badMetadata();
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
  const auto *Ringbuf = M.getGlobalVariable("mojobpf_map1");
  if ((CU->getGlobalVariables().size() == 2) != (Ringbuf != nullptr)) return badMetadata();
  if (Ringbuf) {
    // The companion description stands second: the two-member
    // ring-buffer struct (type 27, max_entries from the audited
    // tag, pinned here to the qualified ring-buffer sizes).
    SmallVector<std::pair<unsigned, MDNode *>, 2> RbAttachments;
    Ringbuf->getAllMetadata(RbAttachments);
    if (RbAttachments.size() != 1 || RbAttachments[0].first != LLVMContext::MD_dbg) return badMetadata();
    auto *RbG = dyn_cast<DIGlobalVariableExpression>(RbAttachments[0].second);
    if (!RbG || RbG != CU->getGlobalVariables()[1] || RbG->getExpression()->getNumElements()) return badMetadata();
    auto *RbV = RbG->getVariable();
    if (RbV->getName() != "mojobpf_map1" || RbV->getLinkageName() != "mojobpf_map1" ||
        RbV->getScope() != CU || RbV->getFile() != File || RbV->getLine() || RbV->isLocalToUnit() ||
        !RbV->isDefinition() || RbV->getAlignInBits() != 64 || RbV->getStaticDataMemberDeclaration() ||
        RbV->getTemplateParams() || !RbV->getAnnotations().empty()) return badMetadata();
    auto *RbT = dyn_cast<DICompositeType>(RbV->getType());
    if (!RbT || RbT->getTag() != dwarf::DW_TAG_structure_type || RbT->getSizeInBits() != 128 ||
        RbT->getAlignInBits() != 64 || RbT->getElements().size() != 2 || RbT->getBaseType() ||
        RbT->getFlags() || RbT->getLine() || RbT->getRuntimeLang() || !RbT->getAnnotations().empty() ||
        !compositeExtrasAbsent(*RbT) || RbT->getFile() != File || RbT->getScope() ||
        RbT->getName() != "mojobpf_ringbuf_map")
      return badMetadata();
    unsigned RbIndex = 0;
    for (StringRef Name : {"type", "max_entries"}) {
      auto *Member = dyn_cast<DIDerivedType>(RbT->getElements()[RbIndex]);
      if (!Member || Member->getTag() != dwarf::DW_TAG_member || Member->getName() != Name ||
          Member->getSizeInBits() != 64 || Member->getAlignInBits() != 64 || Member->getOffsetInBits() != 64 * RbIndex ||
          Member->getLine() || Member->getFlags() || !Member->getAnnotations().empty() || Member->getRawExtraData() ||
          Member->getDWARFAddressSpace() || Member->getPtrAuthData() || Member->getNumExtraInhabitants() ||
          Member->getFile() != File || Member->getScope())
        return badMetadata();
      auto *Pointer = dyn_cast<DIDerivedType>(Member->getBaseType());
      if (!pointerType(Pointer)) return badMetadata();
      auto *Array = dyn_cast_or_null<DICompositeType>(Pointer->getBaseType());
      auto *Range = Array ? dyn_cast<DISubrange>(Array->getElements().size() == 1 ? Array->getElements()[0] : nullptr) : nullptr;
      auto *Number = Range ? mdconst::dyn_extract_or_null<ConstantInt>(Range->getRawCountNode()) : nullptr;
      auto *Lower = Range ? mdconst::dyn_extract_or_null<ConstantInt>(Range->getRawLowerBound()) : nullptr;
      uint64_t Count = Number ? Number->getZExtValue() : 0;
      bool Qualified = RbIndex == 0 ? Count == 27 : Count == 4096 || Count == 131072;
      if (!Array || Array->getTag() != dwarf::DW_TAG_array_type || Array->getSizeInBits() != Count * 32 ||
          Array->getAlignInBits() != 32 || Array->getElements().size() != 1 || Array->getFlags() ||
          !compositeExtrasAbsent(*Array) || !Array->getAnnotations().empty() || Array->getRuntimeLang() ||
          !Array->getName().empty() || Array->getFile() || Array->getScope() || Array->getLine() ||
          !integerType(Array->getBaseType(), 32, dwarf::DW_ATE_signed) || !Number || !Qualified ||
          !Lower || !Lower->isZero() || Range->getRawUpperBound() || Range->getRawStride()) return badMetadata();
      ++RbIndex;
    }
  }
  return Error::success();
}
} // namespace mojobpf
