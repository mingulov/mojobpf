// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// Internal parse/verify/write tool. No target changes or semantic lowering.

#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/raw_ostream.h"

namespace {
enum class EmitKind { Text, Bitcode };

llvm::cl::OptionCategory Options("MojoBPF IR round-trip options");
llvm::cl::opt<std::string> Input("input", llvm::cl::desc("Input LLVM IR or bitcode path"),
                               llvm::cl::Required, llvm::cl::cat(Options));
llvm::cl::opt<std::string> Output("output", llvm::cl::desc("Output file path"),
                                llvm::cl::Required, llvm::cl::cat(Options));
llvm::cl::opt<EmitKind> Emit(
    "emit", llvm::cl::desc("Output format"), llvm::cl::init(EmitKind::Text),
    llvm::cl::values(clEnumValN(EmitKind::Text, "llvm", "Textual LLVM IR"),
                     clEnumValN(EmitKind::Bitcode, "bitcode", "LLVM bitcode")),
    llvm::cl::cat(Options));
} // namespace

int main(int argc, char **argv) {
  llvm::InitLLVM Init(argc, argv);
  llvm::cl::HideUnrelatedOptions(Options);
  if (!llvm::cl::ParseCommandLineOptions(
          argc, argv, "MojoBPF internal LLVM IR round trip (no lowering)\n",
          &llvm::errs()))
    return 2;
  if (Input.empty() || Output.empty() || Input == "-" || Output == "-") {
    llvm::errs() << "mojobpf-lower: input and output require file paths\n";
    return 2;
  }

  llvm::LLVMContext Context;
  llvm::SMDiagnostic Diagnostic;
  auto Module = llvm::parseIRFile(Input, Diagnostic, Context);
  if (!Module) {
    llvm::errs() << "mojobpf-lower: input parse failed (LLVM IR format/toolchain boundary)\n";
    Diagnostic.print(argv[0], llvm::errs());
    return 4;
  }
  if (llvm::verifyModule(*Module, &llvm::errs())) {
    llvm::errs() << "mojobpf-lower: input module failed LLVM verification\n";
    return 4;
  }

  // Validation precedes opening output. Use an owned staging path: this
  // writer removes partial output on failure and does not replace atomically.
  std::error_code Error;
  llvm::ToolOutputFile File(Output, Error, llvm::sys::fs::OF_None);
  if (Error) {
    llvm::errs() << "mojobpf-lower: cannot open output '" << Output << "': "
                 << Error.message() << '\n';
    return 4;
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
    return 4;
  }
  File.keep();
  return 0;
}
