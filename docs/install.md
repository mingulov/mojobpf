<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# Installing MojoBPF

MojoBPF ships as a standard Python wheel: the `mojobpf` command,
the Mojo SDK sources, and the adapter scripts. It builds
unprivileged and needs no root.

## Requirements

* Linux on x86-64 (the qualified host). Other operating systems
  are refused with a clear error; unqualified Linux hosts fail at
  toolchain admission instead of misbuilding.
* Python 3.11 or later (the wheel needs nothing beyond the
  standard library).
* External toolchain, provided by you (never bundled, never
  downloaded by the installer):
  * Mojo 1.1.0 (the pinned compiler; the project's
    `toolchains.lock.json` records its exact version and hash),
  * LLVM `llc` matching the lockfile (BPF backend, `bpfel`
    triple, `v3` CPU),
  * `bpftool` and libbpf for inspection and kernel runs.

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
pip install --no-index mojobpf-0.1.0-py3-none-any.whl
mojobpf doctor
```

From a source checkout (builds the same wheel locally, no
network):

```bash
pip wheel . --no-deps --no-build-isolation -w dist
pip install --no-index dist/mojobpf-0.1.0-py3-none-any.whl
```

Verify the install from any directory (no checkout paths needed):

```bash
mojobpf doctor --json
mojobpf build --manifest mojobpf.toml --out-dir build \
    --lockfile toolchains.lock.json
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

The wheel carries the tool modules, the five Mojo SDK sources,
the three adapter scripts (byte-identical to the checkout's
`compiler/` sources), and the license texts; its exact contents
are pinned (`tests/packaging/test_wheel_contents.py`). The
first-party license is `Apache-2.0 WITH LLVM-exception` (see
`LICENSE` and `THIRD_PARTY_NOTICES.md`, both shipped in the
wheel). Dependencies and user-authored BPF programs keep their
own licensing, and an ELF license declaration must accurately
reflect its program: it is never changed automatically to gain
kernel API access.

The adapter ships as Python source only: no adapter binary, no
compiled extensions, and no compiler binaries ride along
(`tests/packaging/test_wheel_contents.py::test_no_bundled_compiler`).
If a future release ever distributes an adapter binary, it will
carry a platform tag, declared dynamic dependencies, notices,
and a reproducible source build; that release is not this one.
