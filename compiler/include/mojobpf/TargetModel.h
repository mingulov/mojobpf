// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#ifndef MOJOBPF_TARGET_MODEL_H
#define MOJOBPF_TARGET_MODEL_H

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/JSON.h"
#include <optional>
#include <string>

namespace mojobpf {

class CompilerError : public llvm::ErrorInfo<CompilerError> {
public:
  static char ID;
  std::string Code, Stage, Severity, Explanation, Location, Remedy;
  CompilerError(llvm::StringRef Code, llvm::StringRef Stage,
                llvm::StringRef Explanation, llvm::StringRef Location,
                llvm::StringRef Remedy);
  void log(llvm::raw_ostream &OS) const override;
  std::error_code convertToErrorCode() const override;
  llvm::json::Object diagnostic() const;
};

llvm::Error compilerError(llvm::StringRef Code, llvm::StringRef Stage,
                          llvm::StringRef Explanation,
                          llvm::StringRef Location = "module",
                          llvm::StringRef Remedy = "use the documented candidate subset");
llvm::json::Array takeDiagnostics(llvm::Error Error);

struct ArrayMapSpec {
  std::string Symbol;
  unsigned Type = 0, KeyBits = 0, ValueBits = 0, MaxEntries = 0, Flags = 0;
};

struct LoweringSpec {
  unsigned SchemaVersion = 0;
  std::string ModelID, ProfileID, Entry, ProgramType, Section, KernelLicense;
  std::optional<ArrayMapSpec> Map;
};

struct TargetFacts {
  std::string InputTriple, TargetTriple, InputLayout, TargetLayout;
  llvm::json::Object Measured;
  llvm::json::Array ProofObligations;
  llvm::json::Object json() const;
};

inline constexpr unsigned MaxInstructions = 4096;
inline constexpr unsigned MaxBlocks = 128;
inline constexpr unsigned DefaultAnalysisBudget = 65536;

llvm::Expected<LoweringSpec> readLoweringSpec(llvm::StringRef JSON);
llvm::Expected<TargetFacts> inspectTargetModel(const llvm::Module &Module,
                                               const LoweringSpec &Spec);
} // namespace mojobpf
#endif
