// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Test bindings exercise the production analysis; they never admit emission.
#include "mojobpf/Audit.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/DiagnosticPrinter.h"
#include "llvm/IR/ModuleSlotTracker.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include <map>
#include <cstdlib>

using namespace llvm;
namespace {
cl::OptionCategory Options("MojoBPF analysis-only test bindings");
cl::opt<std::string> Input("input", cl::Required, cl::cat(Options));
cl::opt<std::string> BindingsPath("bindings", cl::Required, cl::cat(Options));
cl::opt<std::string> Analysis("analysis", cl::init("key-freshness"), cl::cat(Options));

Error bindingFailure(StringRef Explanation) {
  return mojobpf::compilerError("MBPF202", "adapter.request", Explanation, "test bindings",
                               "bind actual LLVM values and explicit test-owned cell contracts");
}
Error allowedFields(const json::Object &Object, ArrayRef<StringRef> Allowed) {
  for (const auto &Field : Object)
    if (!is_contained(Allowed, Field.first.str())) return bindingFailure("unknown test binding field");
  return Error::success();
}
int report(Error ErrorValue, int FailureExit = 4) {
  bool OK = !ErrorValue;
  json::Array Diagnostics = mojobpf::takeDiagnostics(std::move(ErrorValue));
  json::Object Data{{"schema_version", 1}, {"analysis", Analysis.getValue()}, {"ok", OK},
                    {"whole_program_admitted", false}, {"runtime_qualified", false},
                    {"diagnostics", std::move(Diagnostics)}};
  outs() << formatv("{0:2}\n", json::Value(std::move(Data)));
  return OK ? 0 : FailureExit;
}
} // namespace

int main(int argc, char **argv) {
  InitLLVM Init(argc, argv);
  cl::HideUnrelatedOptions(Options);
  if (!cl::ParseCommandLineOptions(argc, argv, "MojoBPF analysis-only test driver\n", &errs())) return 2;
  if (Analysis != "key-freshness" && Analysis != "pointer-stores" && Analysis != "lowered")
    return report(bindingFailure("unknown analysis mode"), 2);
  auto InputBytes = MemoryBuffer::getFile(Input, false, false);
  auto BindingBytes = MemoryBuffer::getFile(BindingsPath, false, false);
  if (!BindingBytes) return report(bindingFailure("cannot read test bindings"), 2);
  if (!InputBytes) return report(mojobpf::compilerError("MBPF106", "adapter.parse", "cannot read input"));
  LLVMContext Context;
  SMDiagnostic Diagnostic;
  bool DebugInfoDiscarded = false;
  Context.setDiagnosticHandlerCallBack([](const DiagnosticInfo *Info, void *Opaque) {
    if (Info->getKind() == DK_DebugMetadataVersion || Info->getKind() == DK_DebugMetadataInvalid)
      *static_cast<bool *>(Opaque) = true;
    DiagnosticPrinterRawOStream Printer(errs());
    Info->print(Printer);
    errs() << '\n';
  }, &DebugInfoDiscarded);
  std::unique_ptr<Module> M;
  {
    ScopedFatalErrorHandler Fatal([](void *, const char *Reason, bool) {
      bool InvalidModule = StringRef(Reason) == "Broken module found, compilation aborted!";
      int Status = report(mojobpf::compilerError(
          InvalidModule ? "MBPF106" : "MBPF319", InvalidModule ? "adapter.verify" : "adapter.target",
          InvalidModule ? "LLVM verification failed during debug-info upgrade before analysis"
                        : std::string("LLVM reader internal failure: ") + Reason));
      outs().flush();
      errs().flush();
      std::exit(Status);
    });
    M = parseIR((*InputBytes)->getMemBufferRef(), Diagnostic, Context);
    if (!M) {
      Diagnostic.print(argv[0], errs());
      return report(mojobpf::compilerError("MBPF106", "adapter.parse", "input parse failed"));
    }
    if (verifyModule(*M, &errs()))
      return report(mojobpf::compilerError("MBPF106", "adapter.verify", "LLVM verification failed before analysis"));
  }
  if (DebugInfoDiscarded)
    return report(mojobpf::compilerError("MBPF319", "adapter.target", "LLVM reader discarded unsupported input debug metadata"));
  if (Analysis == "lowered") {
    auto Spec = mojobpf::readLoweringSpec((*BindingBytes)->getBuffer());
    if (!Spec) return report(Spec.takeError(), 2);
    mojobpf::TargetFacts Facts;
    Facts.TargetTriple = M->getTargetTriple().str();
    Facts.TargetLayout = M->getDataLayoutStr();
    return report(mojobpf::auditLowered(*M, *Spec, Facts));
  }
  auto Parsed = json::parse((*BindingBytes)->getBuffer());
  if (!Parsed) {
    consumeError(Parsed.takeError());
    return report(bindingFailure("malformed binding JSON"), 2);
  }
  auto *Object = Parsed->getAsObject();
  if (!Object) return report(bindingFailure("bindings must be an object"), 2);
  if (auto E = allowedFields(*Object, {"entry", "scratch", "key_uses", "inert_calls", "analysis_budget", "pointer_roots"}))
    return report(std::move(E), 2);
  auto EntryName = Object->getString("entry");
  auto *Scratch = Object->getArray("scratch"), *Uses = Object->getArray("key_uses"), *Inert = Object->getArray("inert_calls");
  if (!EntryName || !Scratch || !Uses || !Inert) return report(bindingFailure("missing or wrongly typed binding field"), 2);
  auto *F = M->getFunction(*EntryName);
  if (!F || F->isDeclaration()) return report(bindingFailure("bound entry is absent"), 2);
  std::map<std::string, Value *> Values;
  ModuleSlotTracker Slots(M.get());
  Slots.incorporateFunction(*F);
  auto Register = [&](Value &V) {
    std::string Name;
    raw_string_ostream OS(Name);
    V.printAsOperand(OS, false, Slots);
    Values.emplace(Name, &V);
  };
  for (Argument &A : F->args()) Register(A);
  for (BasicBlock &BB : *F) for (Instruction &I : BB) if (!I.getType()->isVoidTy()) Register(I);
  auto Resolve = [&](const json::Object &Row, StringRef Field) -> Value * {
    auto Name = Row.getString(Field);
    if (!Name) return nullptr;
    auto Found = Values.find(Name->str());
    return Found == Values.end() ? nullptr : Found->second;
  };
  mojobpf::ScratchBindings Bindings;
  if (auto *Limit = Object->get("analysis_budget")) {
    auto Number = Limit->getAsInteger();
    if (!Number || *Number <= 0 || *Number > mojobpf::DefaultAnalysisBudget)
      return report(bindingFailure("test analysis budget is out of bounds"), 2);
    Bindings.AnalysisBudget = unsigned(*Number);
  }
  if (Scratch->size() > mojobpf::MaxInstructions || Uses->size() > mojobpf::MaxInstructions || Inert->size() > mojobpf::MaxInstructions)
    return report(mojobpf::compilerError("MBPF320", "adapter.resource", "test binding count budget exhausted"));
  for (const auto &Item : *Scratch) {
    auto *Row = Item.getAsObject();
    if (!Row) return report(bindingFailure("scratch binding is not an object"), 2);
    if (auto E = allowedFields(*Row, {"value", "kind", "offset", "size", "literal", "preparation"})) return report(std::move(E), 2);
    auto *V = Resolve(*Row, "value");
    auto Name = Row->getString("kind");
    auto Offset = Row->getInteger("offset"), Size = Row->getInteger("size");
    auto Preparation = Row->getBoolean("preparation");
    if (!V || !V->getType()->isPointerTy() || !Name || !Offset || !Size || !Preparation || *Size <= 0)
      return report(bindingFailure("scratch binding does not resolve to a typed cell"), 2);
    mojobpf::CellKind Kind;
    if (*Name == "key") Kind = mojobpf::CellKind::Key;
    else if (*Name == "value") Kind = mojobpf::CellKind::Value;
    else if (*Name == "disjoint") Kind = mojobpf::CellKind::Disjoint;
    else return report(bindingFailure("unknown test cell origin"), 2);
    auto Literal = Row->getInteger("literal");
    if ((Kind == mojobpf::CellKind::Key && (*Offset != -4 || *Size != 4 || !*Preparation || !Literal || *Literal < 0 || *Literal > UINT32_MAX)) ||
        (Kind == mojobpf::CellKind::Value && (*Offset != -16 || *Size != 8 || *Preparation)) ||
        (Kind == mojobpf::CellKind::Disjoint && *Preparation))
      return report(bindingFailure("cell range/preparation contract differs"), 2);
    if (!Bindings.Cells.try_emplace(V, mojobpf::ScratchCell{Kind, *Offset, uint64_t(*Size), *Preparation, uint32_t(Literal.value_or(0))}).second)
      return report(bindingFailure("duplicate scratch binding"), 2);
  }
  std::vector<mojobpf::KeyUse> KeyUses;
  for (const auto &Item : *Uses) {
    auto *Row = Item.getAsObject();
    if (!Row) return report(bindingFailure("key-use binding is not an object"), 2);
    if (auto E = allowedFields(*Row, {"call", "buffer", "preparation", "literal"})) return report(std::move(E), 2);
    auto *Call = dyn_cast_or_null<CallBase>(Resolve(*Row, "call"));
    auto *Buffer = Resolve(*Row, "buffer");
    auto *Preparation = dyn_cast_or_null<Instruction>(Resolve(*Row, "preparation"));
    auto Literal = Row->getInteger("literal");
    if (!Call || !Buffer || !Preparation || !Literal || *Literal < 0 || *Literal > UINT32_MAX)
      return report(bindingFailure("key use does not resolve to actual LLVM operands"), 2);
    if (!is_contained(Call->args(), Buffer)) return report(bindingFailure("key buffer is not a consumer operand"), 2);
    KeyUses.push_back({Call, Buffer, Preparation, uint32_t(*Literal)});
  }
  for (const auto &Item : *Inert) {
    auto Name = Item.getAsString();
    auto Found = Name ? Values.find(Name->str()) : Values.end();
    auto *Call = Found == Values.end() ? nullptr : dyn_cast<CallBase>(Found->second);
    if (!Call || !Bindings.InertCalls.insert(Call).second) return report(bindingFailure("inert call binding is unresolved/duplicated"), 2);
  }
  if (Analysis == "pointer-stores") {
    auto *Roots = Object->getArray("pointer_roots");
    if (!Roots) return report(bindingFailure("pointer-store analysis needs explicit address roots"), 2);
    if (Roots->size() > mojobpf::MaxInstructions)
      return report(mojobpf::compilerError("MBPF320", "adapter.resource", "test pointer-root count budget exhausted"));
    std::vector<const Value *> AddressRoots;
    for (const auto &Root : *Roots) {
      auto Name = Root.getAsString();
      auto Found = Name ? Values.find(Name->str()) : Values.end();
      if (Found == Values.end()) return report(bindingFailure("pointer root is unresolved"), 2);
      AddressRoots.push_back(Found->second);
    }
    return report(mojobpf::auditPointerStores(*F, AddressRoots, Bindings.AnalysisBudget));
  }
  return report(mojobpf::auditKeyFreshness(*F, Bindings, KeyUses));
}
