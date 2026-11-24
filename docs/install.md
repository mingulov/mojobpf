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
  * Mojo 1.2.0 (the pinned compiler; the project's
    `toolchains.lock.json` records its exact version and hash).
    The supported acquisition route is the project's pixi
    environment: `pixi install` in the checkout provides the
    pinned Mojo. Export `MODULAR_HOME` from that environment
    (the compiler resolves its standard library through it;
    bare-PATH use fails with "unable to locate module 'std'").
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

## Obtain

Two channels, same bits:

* GitHub Release (published at release time): download
  `mojobpf-1.0.1-py3-none-any.whl` (and the `.tar.gz` source
  archive) from the `v1.0.1` release page, then install
  offline as below.
* Source checkout: `git clone
  https://github.com/mingulov/mojobpf.git`, then build the
  wheel from the tree as below.

## Install

From a wheel file, offline (any directory name works; `.venv`
is reserved for the canonical test interpreter below):

```bash
python3 -m venv install-env
source install-env/bin/activate
pip install --no-index mojobpf-1.0.1-py3-none-any.whl
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
pip install --no-index dist/mojobpf-1.0.1-py3-none-any.whl
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

Configuration enables the test suites by default and fails
without the Python 3.11 + `pytest` prerequisite above; pass
`-DBUILD_TESTING=OFF` to configure a build-only tree.

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

## Run the test lanes

The lane runner (`ci/test_lanes.py`) is the only gate; raw
`pytest` diverges from it and proves nothing. The lanes run
under one canonical interpreter, provisioned once per checkout:

<!-- canonical-test-env-start -->
```bash
set -euo pipefail
PYTHON_URL="https://github.com/astral-sh/python-build-standalone/releases/download/20261009/cpython-3.11.17+20261009-x86_64-unknown-linux-gnu-install_only.tar.gz"
PYTHON_SHA256="035b0ccfe7f3d38ab3ddab505290d200c6a265b95fbd5fac76c358751d6bb6a8"
curl -fsSL --retry 3 "$PYTHON_URL" -o /tmp/cpython.tar.gz
echo "$PYTHON_SHA256  /tmp/cpython.tar.gz" | sha256sum -c -
mkdir -p .venv && tar -xzf /tmp/cpython.tar.gz -C .venv
test -x .venv/python/bin/python3
.venv/python/bin/python3 -m pip install --require-hashes \
    --only-binary=:all: -r ci/canonical-test-requirements.txt
```
<!-- canonical-test-env-end -->

(The URL, archive hash, and package pins above are the same
values `.github/workflows/vm-matrix.yml` pins for CI; a
portability test keeps them identical.)

Then, from the checkout root:

```bash
pixi run build-lower   # fresh mojobpf-lower in build/lower
pixi run test-smoke    # bounded subset, about a minute
pixi run test-unit     # the full unit gate with tool supervision
pixi run test-package  # sdist + wheel proofs
pixi run test-compiler # the full compiler gate (slowest lane)
```

`test-smoke` runs the SDK-surface, safeio, and helper modules
plus one real example build and inspect. `test-unit` is the
same command CI runs. Every task verifies the canonical
interpreter and pins before running; the toolchain environment
(Mojo, `MOJOBPF_LOWER`) comes from the task itself, so run the
lanes through these tasks rather than invoking the runner
directly.

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

Re-pin deliberately with the single documented recipe (the
same one the [quickstart](quickstart.md) uses): a short script
that hashes each PATH-resolved tool plus the installed adapter
service. It pins `mojo`, `llc`, and `bpftool` (builds validate
all three identically; `bpftool` reports its version with the
`version` subcommand):

```bash
python3 - <<'EOF'
import hashlib, importlib.util, json, os, shutil, subprocess

def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()

tools = {}
for name, argv in (('mojo', ['--version']), ('llc', ['--version']),
                  ('bpftool', ['version'])):
    path = shutil.which(name)
    real = os.path.realpath(path)
    out = subprocess.run([path] + argv,
                         capture_output=True, text=True)
    text = out.stdout.strip() or out.stderr.strip()
    tools[name] = {'sha256': sha256_file(real),
                   'version': text.splitlines()[0].strip()}
spec = importlib.util.find_spec('mojobpf.resources.adapter')
adapter_dir = list(spec.submodule_search_locations)[0]
siblings = {}
for name in ('admission.json', 'audit.py', 'mojo_ir_adapter.py',
             'target_proof_table.json'):
    siblings[name] = sha256_file(os.path.join(adapter_dir, name))
doc = {'adapter': {
           'note': 'installed-package pins',
           'service_sha256': sha256_file(
               os.path.join(adapter_dir, 'adapter_service.py')),
           'siblings': siblings},
       'generated_by': 'install (PATH-resolved pins)',
       'license': 'Apache-2.0 WITH LLVM-exception',
       'schema_version': 1, 'tools': tools}
open('toolchains.local.lock.json', 'w').write(
    json.dumps(doc, indent=2, sort_keys=True) + '\n')
EOF
```

This recipe pins PATH-resolved tools directly, so it needs no
`pixi.lock` sibling beside the lock. (The maintainer-side
inventory-plus-`lock_refresh` route, which does bind a
`pixi.lock` sibling through its distribution record, lives in
the [maintenance notes](maintenance.md).)

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
`compiler/` sources) plus the admission descriptor and target
proof table, the twelve
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
