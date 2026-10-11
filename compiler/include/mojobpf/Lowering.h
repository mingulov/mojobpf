// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#ifndef MOJOBPF_LOWERING_H
#define MOJOBPF_LOWERING_H
#include "mojobpf/Audit.h"

namespace mojobpf {
// These transitions consume the exact factory-bound source proof. The caller
// retains the module's lifetime and owns its staging/output paths.
llvm::Error lowerPrimitivesAndHelpers(ValidatedProgram &Program);
llvm::Error emitMapMetadata(ValidatedProgram &Program);
} // namespace mojobpf
#endif
