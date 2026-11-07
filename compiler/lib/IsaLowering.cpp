// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#include "mojobpf/IsaLowering.h"

using namespace llvm;
namespace mojobpf {
Expected<ResolvedIsaCpu> resolveCpu(StringRef Cpu, StringRef Features) {
  // The route targets BPF CPU v3 exactly (ModelID
  // mojo-1.1.0-x86_64-bpfel-v3-minimal-v1). v1/v2 lack lowering the
  // route relies on (native 32-bit forms, fetch atomics); v4 adds
  // MEMSX the audit does not model; generic aliases v1 per the
  // pinned-llc oracle. Refusal is MBPF202, the contract-mismatch
  // precedent shared with model/profile/license.
  if (Cpu != "v3")
    return compilerError("MBPF202", "adapter.request",
                         "unsupported cpu contract: want \"v3\", got \"" +
                             Cpu.str() + "\"",
                         "spec",
                         "request cpu \"v3\" (other BPF CPUs are unadmitted)");
  if (!Features.empty() && Features != "+alu32")
    return compilerError("MBPF202", "adapter.request",
                         "unsupported cpu features contract: want \"\" or "
                         "\"+alu32\", got \"" +
                             Features.str() + "\"",
                         "spec", "request features \"\" or \"+alu32\"");
  ResolvedIsaCpu Resolved;
  Resolved.Cpu = "v3";
  Resolved.Alu32 = Features == "+alu32";
  Resolved.LlcFlags = {"-mtriple=bpfel", "-mcpu=v3"};
  if (Resolved.Alu32)
    Resolved.LlcFlags.push_back("-mattr=+alu32");
  return Resolved;
}

json::Object isaCpuJson(StringRef RequestedCpu, StringRef RequestedFeatures,
                        const ResolvedIsaCpu &Resolved) {
  json::Array Flags;
  for (const auto &Flag : Resolved.LlcFlags)
    Flags.push_back(Flag);
  return json::Object{{"requested_cpu", RequestedCpu.str()},
                      {"requested_features", RequestedFeatures.str()},
                      {"resolved_cpu", Resolved.Cpu},
                      {"resolved_llc_flags", std::move(Flags)},
                      {"alu32", Resolved.Alu32}};
}
} // namespace mojobpf
