// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Internal parse/verify/write and target-admission tool.

#include "mojobpf/Audit.h"
#include "mojobpf/Lowering.h"
#include "mojobpf/TargetModel.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/STLFunctionalExtras.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/DiagnosticPrinter.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/ModuleSlotTracker.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/raw_ostream.h"
#include <filesystem>
#include <cstdlib>

namespace {
enum class EmitKind { Text, Bitcode };

llvm::cl::OptionCategory Options("MojoBPF IR round-trip options");
llvm::cl::opt<std::string> Mode("mode", llvm::cl::desc("roundtrip, check-target or lower"),
                              llvm::cl::init("roundtrip"), llvm::cl::cat(Options));
llvm::cl::opt<std::string> Input("input", llvm::cl::desc("Input LLVM IR or bitcode path"),
                               llvm::cl::Required, llvm::cl::cat(Options));
llvm::cl::opt<std::string> Output("output", llvm::cl::desc("Output file path"),
                                llvm::cl::cat(Options));
llvm::cl::opt<std::string> SpecPath("spec", llvm::cl::desc("Strict lowering specification JSON"), llvm::cl::cat(Options));
llvm::cl::opt<std::string> Report("report", llvm::cl::desc("Owned report JSON path"), llvm::cl::cat(Options));
llvm::cl::opt<EmitKind> Emit(
    "emit", llvm::cl::desc("Output format"), llvm::cl::init(EmitKind::Text),
    llvm::cl::values(clEnumValN(EmitKind::Text, "llvm", "Textual LLVM IR"),
                     clEnumValN(EmitKind::Bitcode, "bitcode", "LLVM bitcode")),
    llvm::cl::cat(Options));
llvm::cl::opt<bool> PermissiveProof(
    "permissive-proof",
    llvm::cl::desc("Lowering only: record unproved properties as obligations instead of refusing"),
    llvm::cl::init(false), llvm::cl::cat(Options));
bool aliases(const std::string &Left, const std::string &Right) {
  if (Left.empty() || Right.empty()) return false;
  std::error_code E;
  if (std::filesystem::equivalent(Left, Right, E) && !E) return true;
  auto L = std::filesystem::weakly_canonical(Left, E);
  if (E) return Left == Right;
  auto R = std::filesystem::weakly_canonical(Right, E);
  return !E && L == R;
}
void printDiagnostics(const llvm::json::Array &Diagnostics) {
  for (const auto &D : Diagnostics) {
    const auto *O = D.getAsObject();
    llvm::errs() << *O->getString("code") << " (" << *O->getString("stage") << "/error): "
                 << *O->getString("explanation") << "; location: " << *O->getString("location")
                 << "; remedy: " << *O->getString("remedy") << '\n';
  }
}
bool writeReport(const llvm::json::Object &Data) {
  std::error_code Error;
  llvm::ToolOutputFile File(Report, Error, llvm::sys::fs::OF_None);
  if (Error) {
    llvm::errs() << "mojobpf-lower: cannot open report: " << Error.message() << '\n';
    return false;
  }
  File.os() << llvm::formatv("{0:2}\n", llvm::json::Value(llvm::json::Object(Data)));
  File.os().close();
  if (File.os().has_error()) {
    llvm::errs() << "mojobpf-lower: cannot write report: " << File.os().error().message() << '\n';
    File.os().clear_error();
    return false;
  }
  File.keep();
  return true;
}
} // namespace

int main(int argc, char **argv) {
  llvm::InitLLVM Init(argc, argv);
  llvm::cl::HideUnrelatedOptions(Options);
  if (!llvm::cl::ParseCommandLineOptions(
          argc, argv, "MojoBPF internal LLVM reader and candidate target admission\n",
          &llvm::errs()))
    return 2;
  bool RoundTrip = Mode == "roundtrip";
  bool Check = Mode == "check-target", Lower = Mode == "lower";
  if ((!RoundTrip && !Check && !Lower) || Input.empty() || Input == "-" || Output == "-" ||
      SpecPath == "-" || Report == "-" || (RoundTrip && (Output.empty() || !SpecPath.empty() || !Report.empty())) ||
      (Check && (!Output.empty() || Emit.getNumOccurrences())) ||
      (!RoundTrip && (SpecPath.empty() || Report.empty())) || (Lower && Output.empty())) {
    llvm::errs() << "mojobpf-lower: invalid mode/options; input, output, spec and report require appropriate file paths\n";
    return 2;
  }
  if (aliases(Output, Input) || aliases(Output, SpecPath) || aliases(Report, Input) ||
      aliases(Report, SpecPath) || aliases(Output, Report)) {
    llvm::errs() << "mojobpf-lower: output/report aliases input/spec or each other\n";
    return 2;
  }
  if (Check && PermissiveProof) {
    printDiagnostics(mojobpf::takeDiagnostics(mojobpf::compilerError(
        "MBPF202", "adapter.request", "permissive proof applies to lowering only",
        "--permissive-proof", "drop the flag for check-target")));
    return 2;
  }

  // Capture both inputs before opening any owned output. Parsing never
  // reopens user paths, including after symlink or hard-link alias checks.
  auto InputBytes = llvm::MemoryBuffer::getFile(Input, false, false);
  std::optional<mojobpf::LoweringSpec> Spec;
  std::string SpecDigest;
  if (!RoundTrip) {
    auto SpecBytes = llvm::MemoryBuffer::getFile(SpecPath, false, false);
    if (!SpecBytes) {
      llvm::errs() << "mojobpf-lower: cannot read spec: " << SpecBytes.getError().message() << '\n';
      return 2;
    }
    SpecDigest = llvm::toHex(llvm::SHA256::hash(llvm::arrayRefFromStringRef((*SpecBytes)->getBuffer())), true);
    auto Parsed = mojobpf::readLoweringSpec((*SpecBytes)->getBuffer());
    if (!Parsed) {
      printDiagnostics(mojobpf::takeDiagnostics(Parsed.takeError()));
      return 2;
    }
    Spec = std::move(*Parsed);
  }
  llvm::json::Object ReportData;
  if (!RoundTrip) {
    llvm::json::Value InputDigest = nullptr;
    if (InputBytes)
      InputDigest = llvm::toHex(llvm::SHA256::hash(llvm::arrayRefFromStringRef((*InputBytes)->getBuffer())), true);
    ReportData = llvm::json::Object{{"schema_version", 1}, {"mode", Mode.getValue()}, {"model_id", Spec->ModelID},
                  {"input_digest", std::move(InputDigest)}, {"spec_digest", SpecDigest}, {"target_facts", nullptr},
                  {"proof_obligations", llvm::json::Array{}}, {"transformations", llvm::json::Array{}},
                  {"unproved", llvm::json::Array{}}, {"unproved_total", 0}, {"unproved_truncated", false},
                  {"diagnostics", llvm::json::Array{}}, {"runtime_qualified", false}, {"ok", false}};
  }
  auto Reject = [&](llvm::Error E) {
    auto Diagnostics = mojobpf::takeDiagnostics(std::move(E));
    printDiagnostics(Diagnostics);
    if (!RoundTrip) {
      ReportData["diagnostics"] = std::move(Diagnostics);
      writeReport(ReportData);
    }
    return 4;
  };

  llvm::LLVMContext Context;
  llvm::SMDiagnostic Diagnostic;
  if (!InputBytes)
    return Reject(mojobpf::compilerError("MBPF106", "adapter.parse", "input parse failed: cannot read input", Input));
  bool DebugInfoDiscarded = false;
  Context.setDiagnosticHandlerCallBack([](const llvm::DiagnosticInfo *Info, void *Opaque) {
    if (Info->getKind() == llvm::DK_DebugMetadataVersion || Info->getKind() == llvm::DK_DebugMetadataInvalid)
      *static_cast<bool *>(Opaque) = true;
    llvm::DiagnosticPrinterRawOStream Printer(llvm::errs());
    Info->print(Printer);
    llvm::errs() << '\n';
  }, &DebugInfoDiscarded);
  std::unique_ptr<llvm::Module> Module;
  {
    // LLVM's debug-info upgrade verifies version-3 modules during parsing and
    // fatally diagnoses an invalid CFG. Terminate with a failure report;
    // never recover or reuse a partially parsed module.
    llvm::function_ref<int(llvm::Error)> ReaderReject(Reject);
    llvm::ScopedFatalErrorHandler Fatal([](void *Opaque, const char *Reason, bool) {
      auto &RejectReader = *static_cast<llvm::function_ref<int(llvm::Error)> *>(Opaque);
      bool InvalidModule = llvm::StringRef(Reason) == "Broken module found, compilation aborted!";
      int Status = RejectReader(mojobpf::compilerError(
          InvalidModule ? "MBPF106" : "MBPF319",
          InvalidModule ? "adapter.verify" : "adapter.target",
          InvalidModule ? "input module failed LLVM verification during debug-info upgrade"
                        : std::string("LLVM reader internal failure: ") + Reason, Input));
      llvm::outs().flush();
      llvm::errs().flush();
      std::exit(Status);
    }, &ReaderReject);
    Module = llvm::parseIR((*InputBytes)->getMemBufferRef(), Diagnostic, Context);
    if (!Module) {
      Diagnostic.print(argv[0], llvm::errs());
      return Reject(mojobpf::compilerError("MBPF106", "adapter.parse", "input parse failed (LLVM IR format/toolchain boundary)", Input));
    }
    if (llvm::verifyModule(*Module, &llvm::errs()))
      return Reject(mojobpf::compilerError("MBPF106", "adapter.verify", "input module failed LLVM verification", Input));
  }
  if (!RoundTrip && DebugInfoDiscarded)
    return Reject(mojobpf::compilerError("MBPF319", "adapter.target", "LLVM reader discarded unsupported input debug metadata", Input));

  if (!RoundTrip) {
    auto Facts = mojobpf::inspectTargetModel(*Module, *Spec);
    if (!Facts) return Reject(Facts.takeError());
    ReportData["target_facts"] = Facts->json();
    auto Program = mojobpf::auditSource(*Module, *Spec, *Facts, Lower && PermissiveProof);
    if (!Program) return Reject(Program.takeError());
    if (auto E = Program->requireUnchangedSource()) return Reject(std::move(E));
    llvm::ModuleSlotTracker Slots(Module.get());
    Slots.incorporateFunction(Program->entry());
    auto ValueName = [&](const llvm::Value &V) {
      std::string Name;
      llvm::raw_string_ostream OS(Name);
      V.printAsOperand(OS, false, Slots);
      return Name;
    };
    llvm::json::Array Scratch, Consumers;
    for (const auto &P : Program->primitives()) {
      auto Cell = Program->scratch().Cells.find(P.Call);
      if (Cell == Program->scratch().Cells.end()) continue;
      const auto &C = Cell->second;
      Scratch.push_back(llvm::json::Object{{"value", ValueName(*P.Call)},
                        {"origin", C.Kind == mojobpf::CellKind::Disjoint ? "independent lookup" : "shared r10 frame"},
                        {"offset", C.Offset}, {"size", int64_t(C.Size)},
                        {"preparation", C.Preparation}, {"literal", int64_t(C.Literal)}});
    }
    for (const auto &Use : Program->keyUses())
      Consumers.push_back(llvm::json::Object{{"call", ValueName(*Use.Call)},
                          {"buffer", ValueName(*Use.Buffer)}, {"preparation", ValueName(*Use.Preparation)},
                          {"literal", int64_t(Use.ExpectedLiteral)}, {"freshness", "proved"}});
    Facts->Measured["source_audit"] = llvm::json::Object{{"scratch_cells", std::move(Scratch)},
                    {"key_consumers", std::move(Consumers)}, {"helper_calls", int64_t(Program->helpers().size())},
                    {"module_flag", Module->getNamedMetadata("llvm.module.flags") ? llvm::json::Value(3) : llvm::json::Value(nullptr)},
                    {"source_mutated", false}, {"address_control_taint", "retained"}};
    ReportData["target_facts"] = Facts->json();
    ReportData["proof_obligations"] = std::move(Facts->ProofObligations);
    ReportData["unproved"] = llvm::json::Array(Program->unproved());
    ReportData["unproved_total"] = int64_t(Program->unprovedTotal());
    ReportData["unproved_truncated"] = Program->unprovedTotal() > Program->unproved().size();
    if (Check) {
      ReportData["ok"] = true;
      return writeReport(ReportData) ? 0 : 4;
    }
    if (auto E = mojobpf::lowerPrimitivesAndHelpers(*Program)) return Reject(std::move(E));
    if (auto E = mojobpf::emitMapMetadata(*Program)) return Reject(std::move(E));
    ReportData["transformations"] = llvm::json::Array(Program->transformations());
    for (auto &Row : *ReportData["proof_obligations"].getAsArray())
      if (auto *O = Row.getAsObject(); O->getString("id") == "target_transition")
        (*O)["status"] = "lowered-verified-host-only";
  }

  // Validation precedes opening output. Use an owned staging path: this
  // writer removes partial output on failure and does not replace atomically.
  std::error_code Error;
  llvm::ToolOutputFile File(Output, Error, llvm::sys::fs::OF_None);
  if (Error) {
    llvm::errs() << "mojobpf-lower: cannot open output '" << Output << "': "
                 << Error.message() << '\n';
    if (Lower) return Reject(mojobpf::compilerError("MBPF106", "adapter.write", "cannot open owned output", Output));
    return 4;
  }
  if (Lower) {
    // Pinned output must not embed the caller's absolute input path.
    // Identify the module by its source file name instead, matching
    // the hand-written fixture convention (`; ModuleID = '<src>.mojo'`).
    std::string Name = Module->getSourceFileName();
    if (Name.empty())
      Name = "adapted";
    Module->setModuleIdentifier(Name);
  }
  if (Emit == EmitKind::Bitcode)
    llvm::WriteBitcodeToFile(*Module, File.os());
  else
    Module->print(File.os(), nullptr);

  File.os().close();
  if (File.os().has_error()) {
    llvm::errs() << "mojobpf-lower: cannot write output '" << Output << "': "
                 << File.os().error().message() << '\n';
    File.os().clear_error();
    if (Lower) return Reject(mojobpf::compilerError("MBPF106", "adapter.write", "cannot write owned output", Output));
    return 4;
  }
  if (Lower) {
    // Reparse the exact closed output bytes. A successful in-memory audit is
    // insufficient if serialization or the owned staging write failed.
    auto Written = llvm::MemoryBuffer::getFile(Output, false, false);
    if (!Written) return Reject(mojobpf::compilerError("MBPF106", "adapter.write", "cannot read back owned output", Output));
    llvm::LLVMContext OutputContext;
    llvm::SMDiagnostic OutputDiagnostic;
    auto Reread = llvm::parseIR((*Written)->getMemBufferRef(), OutputDiagnostic, OutputContext);
    if (!Reread || llvm::verifyModule(*Reread, &llvm::errs()))
      return Reject(mojobpf::compilerError("MBPF106", "adapter.verify", "serialized output failed independent read/verification", Output));
    ReportData["output_digest"] = llvm::toHex(llvm::SHA256::hash(llvm::arrayRefFromStringRef((*Written)->getBuffer())), true);
    ReportData["ok"] = true;
    if (!writeReport(ReportData)) return 4;
  }
  File.keep();
  return 0;
}
