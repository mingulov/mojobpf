# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
"""Exercise the internal LLVM parse/verify/write executable without lowering.

Run directly with Python 3.11+ or with pytest. Requires CMake 3.20+, a C++17
compiler, LLVM 21.1.8 development files and its opt/llvm-as/llvm-dis tools,
and the working Mojo 1.1.0 environment on PATH. No kernel access is used.
The default invocation builds the tool once in an owned temporary directory.
MOJOBPF_LOWER may select an already built executable; MOJOBPF_LLVM_CONFIG
may select llvm-config. A missing dependency fails rather than skipping.

Synthetic cases qualify LLVM plumbing only. The Mojo cases capture current
frontend output from the public source fixtures before exercising the tool.
Independent opt canonicalization checks the whole module, including target
metadata, instructions, attributes, globals and helper declarations. It
does not establish target-model correctness or kernel behavior.
"""

import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SYNTHETIC_IR = '''source_filename = "roundtrip-fixture"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-p:64:64-i64:64-i128:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@payload = private constant [3 x i8] c"abc", align 1

define i32 @"sum with spaces"(i32 %left, i32 %right) #0 {
entry:
  %sum = add i32 %left, %right
  ret i32 %sum
}

attributes #0 = { nounwind "target-cpu"="x86-64" }
!llvm.module.flags = !{!0}
!0 = !{i32 1, !"wchar_size", i32 4}
'''
LEGACY_LAYOUT_IR = SYNTHETIC_IR.replace(
    "e-m:e-p270:32:32-p271:32:32-p272:64:64-p:64:64-i64:64-i128:128-n8:16:32:64-S128",
    "e-m:e-p:64:64-i64:64-n8:16:32:64-S128",
)

VERIFIER_INVALID_IR = '''define i32 @invalid(i1 %condition) {
entry:
  br i1 %condition, label %left, label %right
left:
  br label %merge
right:
  br label %merge
merge:
  %value = phi i32 [ 1, %left ]
  ret i32 %value
}
'''


def _limit_output_size():
    """Make the child's regular-file write fail after a small prefix."""
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_FSIZE, (64, 64))


class IRRoundTripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_root = tempfile.TemporaryDirectory(prefix="mojobpf-parser-")
        cls.addClassCleanup(cls.build_root.cleanup)
        cls.lower = os.environ.get("MOJOBPF_LOWER")
        cls.config = os.environ.get("MOJOBPF_LLVM_CONFIG") or shutil.which(
            "llvm-config"
        )
        if not cls.config:
            raise RuntimeError("ENVIRONMENT FAILURE: llvm-config not found")
        bindir = Path(cls._checked([cls.config, "--bindir"]).stdout.strip())
        cls.tools = {}
        for name in ("opt", "llvm-as", "llvm-dis"):
            executable = bindir / name
            if not executable.is_file():
                raise RuntimeError("ENVIRONMENT FAILURE: missing " + str(executable))
            cls.tools[name] = str(executable)

    @staticmethod
    def _checked(argv):
        result = subprocess.run(
            [str(arg) for arg in argv], capture_output=True, text=True, timeout=600
        )
        if result.returncode != 0:
            raise AssertionError(
                f"command {argv!r} exited {result.returncode}:\n"
                f"{result.stdout}{result.stderr}"
            )
        return result

    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="mojobpf-roundtrip-")
        self.addCleanup(self.work.cleanup)
        self.workdir = Path(self.work.name)

    def _lower_executable(self):
        cls = type(self)
        if cls.lower is None:
            self.assertTrue(
                (ROOT / "compiler" / "CMakeLists.txt").is_file(),
                "parsed LLVM executable is not implemented: compiler/CMakeLists.txt missing",
            )
            cmake = shutil.which("cmake")
            self.assertIsNotNone(cmake, "ENVIRONMENT FAILURE: cmake not found")
            cmakedir = self._checked([cls.config, "--cmakedir"]).stdout.strip()
            self._checked([
                cmake, "-S", ROOT / "compiler", "-B", cls.build_root.name,
                "-DLLVM_DIR=" + cmakedir, "-DBUILD_TESTING=OFF",
            ])
            self._checked([cmake, "--build", cls.build_root.name, "--parallel", "2"])
            cls.lower = str(Path(cls.build_root.name) / "mojobpf-lower")
        self.assertTrue(Path(cls.lower).is_file(), "ENVIRONMENT FAILURE: executable missing")
        return cls.lower

    def _run_lower(self, source, output, emit="llvm", **kwargs):
        return subprocess.run(
            [self._lower_executable(), "--input", str(source), "--output", str(output),
             "--emit", emit],
            env={**os.environ, "TMPDIR": str(self.workdir)},
            capture_output=True, text=True, timeout=60, **kwargs,
        )

    def _input(self, text=SYNTHETIC_IR):
        path = self.workdir / "input.ll"
        path.write_text(text, encoding="utf-8")
        return path

    def _canonical(self, path):
        # opt reparses and verifies independently. ModuleID is an input-path
        # comment; every other printed byte must agree after canonicalization.
        result = self._checked([
            self.tools["opt"], "-S", "-passes=verify", path, "-o", "-",
        ])
        return "\n".join(
            line for line in result.stdout.splitlines()
            if not line.startswith("; ModuleID = ")
        )

    def _roundtrip(self, source, emit="llvm"):
        output = self.workdir / ("output.bc" if emit == "bitcode" else "output.ll")
        result = self._run_lower(source, output, emit)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        self.assertTrue(output.is_file())
        self.assertEqual(self._canonical(output), self._canonical(source))
        return output

    def _reject_preserving_output(self, source, diagnostic):
        output = self.workdir / "prior-good-output.ll"
        sentinel = SYNTHETIC_IR.encode("utf-8")
        output.write_bytes(sentinel)
        result = self._run_lower(source, output)
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertIn(diagnostic, result.stderr.lower())
        self.assertEqual(result.stdout, "")
        self.assertEqual(output.read_bytes(), sentinel)

    def _capture_mojo(self, source, emit="llvm"):
        mojo = shutil.which("mojo")
        self.assertIsNotNone(mojo, "ENVIRONMENT FAILURE: active Mojo compiler missing")
        output = self.workdir / (source.stem + (".bc" if emit == "llvm-bitcode" else ".ll"))
        self._checked([
            mojo, "build", "--emit", emit, "-I", ROOT / "src/mojobpf/resources/sdk",
            "-o", output, source,
        ])
        self.assertTrue(output.is_file(), "frontend emitted no artifact")
        return output

    def test_text_roundtrip_preserves_module(self):
        self._roundtrip(self._input())

    def test_text_roundtrip_does_not_replace_legacy_layout(self):
        self._roundtrip(self._input(LEGACY_LAYOUT_IR))

    def test_legacy_bitcode_layout_matches_independent_reader(self):
        # LLVM's bitcode reader upgrades older layout strings. Compare that
        # boundary with llvm-dis, rather than claiming spelling preservation.
        source = self._input(LEGACY_LAYOUT_IR)
        bitcode = self.workdir / "legacy.bc"
        self._checked([self.tools["llvm-as"], source, "-o", bitcode])
        expected = self.workdir / "independent.ll"
        self._checked([self.tools["llvm-dis"], bitcode, "-o", expected])
        output = self._roundtrip(bitcode)
        self.assertEqual(self._canonical(output), self._canonical(expected))

    def test_text_to_bitcode_is_independently_readable(self):
        output = self._roundtrip(self._input(), "bitcode")
        self.assertEqual(output.read_bytes()[:4], b"BC\xc0\xde")
        disassembled = self.workdir / "disassembled.ll"
        self._checked([self.tools["llvm-dis"], output, "-o", disassembled])
        self.assertEqual(self._canonical(disassembled), self._canonical(output))

    def test_bitcode_to_text_preserves_module(self):
        source = self._input()
        bitcode = self.workdir / "input.bc"
        self._checked([self.tools["llvm-as"], source, "-o", bitcode])
        self._roundtrip(bitcode)

    def test_bitcode_to_bitcode_preserves_module(self):
        source = self._input()
        bitcode = self.workdir / "input.bc"
        self._checked([self.tools["llvm-as"], source, "-o", bitcode])
        self._roundtrip(bitcode, "bitcode")

    def test_malformed_text_preserves_existing_output(self):
        self._reject_preserving_output(self._input("define i32 @broken( {\n"), "parse")

    def test_unknown_ir_construct_is_rejected_without_stripping(self):
        source = self._input(SYNTHETIC_IR + "attributes #1 = { future_attribute }\n")
        self._reject_preserving_output(source, "parse")

    def test_verifier_invalid_module_preserves_existing_output(self):
        self._reject_preserving_output(self._input(VERIFIER_INVALID_IR), "verif")

    def test_corrupt_bitcode_preserves_existing_output(self):
        source = self.workdir / "broken.bc"
        source.write_bytes(b"BC\xc0\xde\x00\x00\x00\x00")
        self._reject_preserving_output(source, "parse")

    def test_nonexistent_input_preserves_existing_output(self):
        self._reject_preserving_output(self.workdir / "absent.ll", "parse")

    def test_missing_required_argument_is_usage_failure(self):
        result = subprocess.run(
            [self._lower_executable(), "--output", str(self.workdir / "unused.ll")],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("input", result.stderr.lower())
        self.assertFalse((self.workdir / "unused.ll").exists())

    def test_invalid_emit_is_usage_failure(self):
        output = self.workdir / "unused.ll"
        result = self._run_lower(self._input(), output, "object")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse(output.exists())

    def test_stdio_paths_are_usage_failures(self):
        source = self._input()
        output = self.workdir / "unused.ll"
        for input_path, output_path in (("-", output), (source, "-")):
            with self.subTest(input_path=input_path, output_path=output_path):
                result = self._run_lower(input_path, output_path)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("path", result.stderr.lower())
                self.assertFalse(output.exists())

    def test_unwritable_output_is_reported(self):
        result = self._run_lower(self._input(), self.workdir)
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertIn("output", result.stderr.lower())
        self.assertEqual(result.stdout, "")

    def test_size_limit_failure_is_nonzero_and_partial_output_removed(self):
        output = self.workdir / "limited.ll"
        result = self._run_lower(self._input(), output, preexec_fn=_limit_output_size)
        # LLVM installs a SIGXFSZ handler when registering output cleanup;
        # resource-limit failure can terminate before the normal error branch.
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("file too large", result.stderr.lower())
        self.assertEqual(result.stdout, "")
        self.assertFalse(output.exists())

    def test_write_failure_is_reported_and_owned_output_removed(self):
        self.assertTrue(Path("/dev/full").exists(), "ENVIRONMENT FAILURE: /dev/full absent")
        output = self.workdir / "full-alias.ll"
        output.symlink_to("/dev/full")
        result = self._run_lower(self._input(), output)
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertIn("write", result.stderr.lower())
        self.assertEqual(result.stdout, "")
        self.assertFalse(output.is_symlink())

    def test_genuine_mojo_probe_retains_input_dependent_operations(self):
        source = self._capture_mojo(ROOT / "tests/compile/probe.mojo")
        output = self._roundtrip(source)
        body = output.read_text(encoding="utf-8")
        self.assertRegex(body, r"add i32 %0, %1")
        self.assertRegex(body, r"load i8, ptr %0")

    def test_genuine_mojo_classifier_retains_control_flow(self):
        source = self._capture_mojo(ROOT / "examples/xdp_pass/xdp_pass.mojo")
        output = self._roundtrip(source)
        body = output.read_text(encoding="utf-8")
        self.assertIn("load i32", body)
        self.assertIn("load i8", body)
        self.assertIn("br i1", body)
        self.assertRegex(body, r"\b(?:select|phi)\b.*i32")

    def test_genuine_mojo_bitcode_is_compatible(self):
        source = self._capture_mojo(ROOT / "tests/compile/probe.mojo", "llvm-bitcode")
        self._roundtrip(source, "bitcode")

    def test_genuine_mojo_map_helpers_and_mutation_are_preserved(self):
        source = self._capture_mojo(ROOT / "tests/compile/map_roundtrip.mojo")
        original = self._canonical(self._roundtrip(source))
        source = self._capture_mojo(ROOT / "tests/compile/map_roundtrip_mutated.mojo")
        mutated = self._canonical(self._roundtrip(source, "bitcode"))
        self.assertIn("@__mojobpf_lookup_v1", original)
        self.assertIn("@__mojobpf_update_v1", original)
        self.assertRegex(original, r"add i64 %\w+, 1")
        self.assertRegex(mutated, r"add i64 %\w+, 2")
        self.assertNotEqual(original, mutated)


if __name__ == "__main__":
    unittest.main()
