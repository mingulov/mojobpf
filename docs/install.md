<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Installing MojoBPF

MojoBPF ships as a standard Python wheel: the `mojobpf` command,
the Mojo SDK sources, and the adapter scripts. It builds
unprivileged and needs no root.

## Requirements

* Linux on x86-64 (the qualified host). Other operating systems
  are refused with a clear error
  (`tests/unit/test_build_commands.py::test_cli_refuses_unsupported_platform`);
  other Linux architectures are unproven — no gate tests them,
  and toolchain admission only compares tools against the
  lockfile pins, so builds there are outside the qualified
  boundary.
* Python 3.11 or later (the wheel needs nothing beyond the
  standard library).
* External toolchain, provided by you (never bundled, never
  downloaded by the installer):
  * Mojo 1.1.0 (the pinned compiler; the project's
    `toolchains.lock.json` records its exact version and hash),
  * LLVM `llc` matching the lockfile (BPF backend, `bpfel`
    triple, `v3` CPU),
  * `bpftool` and libbpf for inspection and kernel runs.
* To build the lowering binary below: CMake 3.20 or later, a C++
  compiler with C++17 support, and the LLVM 22.1.8 CMake package
  configuration. The compiler test suites additionally need
  Python 3.11 with `pytest`.

Check what the tool sees before building:

```bash
mojobpf doctor
```

`doctor` reports the tool and SDK versions, the platform, every
required tool with its version, lockfile match status, and whether
a kernel-test runner is available. It changes nothing.

## Install

From a wheel file, offline:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --no-index mojobpf-0.3.0a1-py3-none-any.whl
mojobpf doctor
```

From a source checkout or unpacked source archive (builds the
same wheel locally, no network). With `--no-build-isolation` pip
uses the ambient environment for the build backend, so
`setuptools>=61` must already be installed (no separate `wheel`
package is needed):

```bash
pip install "setuptools>=61"
pip wheel . --no-deps --no-build-isolation -w dist
pip install --no-index dist/mojobpf-0.3.0a1-py3-none-any.whl
```

## Build the lowering (`mojobpf-lower`)

Parsed-route builds lower Mojo-emitted LLVM IR through the
`mojobpf-lower` binary. It is not shipped in the wheel: build it
from the `compiler/` sources carried by the checkout or source
archive, with the pinned LLVM 22.1.8
(`compiler/CMakeLists.txt` requires exactly that version):

```bash
cmake -S compiler -B build/lower -DCMAKE_BUILD_TYPE=Release
cmake --build build/lower -j$(nproc)
export MOJOBPF_LOWER=$PWD/build/lower/mojobpf-lower
```

If CMake cannot find LLVM on your machine, point it at the
configuration directory your LLVM install reports:

```bash
cmake -S compiler -B build/lower -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_DIR=$(llvm-config --cmakedir)
```

The build also produces `mojobpf-audit-driver`, an analysis-only
helper; it is not an installed product tool. To prove the
lowering, run its test suites with the Mojo toolchain on `PATH`
(five suites; four of the five fail loudly with `ENVIRONMENT
FAILURE` when `mojo` is missing rather than passing vacuously,
and all five pass with the Mojo toolchain on `PATH`):

```bash
ctest --test-dir build/lower
```

Without a lowering binary, builds stop at once with the exact
missing item — never a hang or a silent fallback:

```text
MBPF219 (adapter.transform/error): parsed route needs mojobpf-lower:
not on PATH and MOJOBPF_LOWER is unset;
location: <build staging>/xdp_entry.raw.ll;
remedy: build the lowering (compiler/CMakeLists.txt) and set MOJOBPF_LOWER
```

Either put `mojobpf-lower` on `PATH` or set `MOJOBPF_LOWER` to
the binary.

## Lockfile for your machine

The reviewed `toolchains.lock.json` pins the qualifying machine's
exact tool versions, paths, and hashes. On any other machine,
`build` refuses with the mismatching tool named (exit 3), for
example:

```text
MBPF102 (toolchain.match/error): tool 'llc' does not match the
lockfile pin (found version '...'); location: <lockfile>: tools.llc;
remedy: install the pinned llc or re-pin the lockfile deliberately
```

Re-pin deliberately with the refresh tooling shipped in the
source archive — the inventory probe first, then generation:

```bash
python3 tests/probes/toolchain_inventory.py --output /tmp/inventory.json
python3 tools/lock_refresh.py generate --kind toolchains \
    --inventory /tmp/inventory.json \
    --pixi-lock pixi.lock --adapter-dir compiler \
    --out toolchains.local.lock.json --report lock.report.json
```

The inventory exits nonzero naming what is missing when any of
`mojo`, `llc`, `bpftool`, `clang`, `llvm-config`, or `python3`
is absent or fails; generation then refuses rather than
inventing pins, and writes neither output on failure. The
generated lock carries status `bootstrap`: builds match its pins
like any lock, but it is not a reviewed `release-approved` pin.
Copy the lock together with the `pixi.lock` beside it into your
project: the lock's distribution record binds that sibling file,
and a missing sibling fails the build (`MBPF102`) instead of
running unpinned.

Verify the install from any directory (no checkout paths needed):

```bash
mojobpf doctor --json
mojobpf build --manifest mojobpf.toml --out-dir build \
    --lockfile toolchains.local.lock.json
mojobpf inspect --object build/<artifact>.bpf.o \
    --source-license "Apache-2.0 WITH LLVM-exception" \
    --kernel-license "Apache-2.0 WITH LLVM-exception"
```

Without `--adapter`, `build` uses the packaged adapter, and the
SDK import path resolves through the installed package, so
installed builds need no repository-relative paths. The
packaging suites prove this from a clean virtual environment
(`tests/packaging/test_installed_build.py`).

## Layout and licenses

The wheel carries the tool modules, the eight Mojo SDK sources,
the three adapter scripts (byte-identical to the checkout's
`compiler/` sources) plus the admission descriptor, the eleven
contract schemas as installed data files
(`share/mojobpf/schemas/*.schema.json`), and the license texts;
its exact contents are pinned
(`tests/packaging/test_wheel_contents.py`). The first-party
license is `Apache-2.0 WITH LLVM-exception` (see `LICENSE` and
`THIRD_PARTY_NOTICES.md`, both shipped in the wheel).
Dependencies and user-authored BPF programs keep their own
licensing, and an ELF license declaration must accurately
reflect its program: it is never changed automatically to gain
kernel API access.

The adapter ships as Python source only: no adapter binary, no
compiled extensions, and no compiler binaries ride along
(`tests/packaging/test_wheel_contents.py::test_no_bundled_compiler`).
If a future release ever distributes an adapter binary, it will
carry a platform tag, declared dynamic dependencies, notices,
and a reproducible source build; that release is not this one.
