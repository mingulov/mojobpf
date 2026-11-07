// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#ifndef MOJOBPF_ISALOWERING_H
#define MOJOBPF_ISALOWERING_H

#include "mojobpf/TargetModel.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/JSON.h"
#include <string>
#include <vector>

namespace mojobpf {
// F-ISA/cpu/v3-target: explicit CPU admission for the parsed route.
// Selection itself stays in pinned llc; this unit admits the request,
// resolves the exact llc flags, and reports the facts. No silent
// default, no silent downgrade or upgrade.
struct ResolvedIsaCpu {
  std::string Cpu;
  bool Alu32 = false;
  std::vector<std::string> LlcFlags;
};

llvm::Expected<ResolvedIsaCpu> resolveCpu(llvm::StringRef Cpu,
                                          llvm::StringRef Features);
llvm::json::Object isaCpuJson(llvm::StringRef RequestedCpu,
                              llvm::StringRef RequestedFeatures,
                              const ResolvedIsaCpu &Resolved);
} // namespace mojobpf
#endif
