# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# Negative fixture: invalid Mojo source the frontend must reject.
#
# First expected rejecting layer: the Mojo frontend itself, which must
# exit nonzero without emitting IR.

def broken(:
