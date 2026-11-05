<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF quickstart

Build a Mojo XDP counter into a standard BPF object and load it
in a disposable guest. Every command below was run verbatim from
a fresh directory; every output is transcribed from that run
with only machine-specific absolute paths shortened (the
working directory to `<qs>`, user tool installations to their
bare tool names). Absolute paths on your machine will differ;
versions, exit codes, and result lines must match.

## Prerequisites

* Linux on x86-64.
* Python 3.11 or later with `venv` and `pip`.
* Mojo 1.1.0 on `PATH` (see [compatibility](compatibility.md)
  for the supported toolchain).
* LLVM `llc` with the BPF backend, `bpftool`, and `vng`
  (virtme-ng) with a cached guest image for the kernel check.

## 1. Build the wheel

From the MojoBPF source directory:

```bash
pip wheel . --no-deps --no-build-isolation -w dist
```

```text
Building wheel for mojobpf (pyproject.toml): finished with status 'done'
Created wheel for mojobpf: filename=mojobpf-0.3.0a1-py3-none-any.whl size=474639 sha256=1bcbc7fdbab3e973f6fe6348f399faac6123fe9850c5befbb2be2a202febd1aa
Successfully built mojobpf
```

(The `size`/`sha256` values are from the reference run; a
wheel built from the same sources carries the same contents
(pinned by `tests/packaging/test_wheel_contents.py`), but zip
metadata may differ — even the container hash varies between
same-tree builds. The 0.3.0a1 release contents are pinned
separately in [checksums](checksums-0.3.0a1.md).)

## 2. Install into a fresh environment

From a new, unrelated directory:

```bash
python3 -m venv .venv
.venv/bin/pip install --no-index <path-to>/mojobpf-0.3.0a1-py3-none-any.whl
export PATH="$PWD/.venv/bin:$PATH"
```

```text
Successfully installed mojobpf-0.3.0a1
```

## 3. Check the toolchain

```bash
mojobpf doctor
```

```text
mojobpf doctor
informational discovery only: pins are qualified by check/build with --lockfile, never here
mojobpf 0.3.0a1 (sdk 1.7) at <qs>/.venv/lib64/python3.14/site-packages/mojobpf
platform: linux/x86_64
tool mojo: present Mojo 1.1.0 (8189361e) at <mojo-on-PATH>
tool llc: present LLVM (http://llvm.org/): at <llc-on-PATH>
tool bpftool: present bpftool v7.6.0 at <bpftool-on-PATH>
tool python: present Python 3.14.8 at <qs>/.venv/bin/python3
target candidates: linux-bpfel-v3, linux-bpfel-v3-core, linux-bpfel-v3-hash, linux-bpfel-v3-lru, linux-bpfel-v3-net, linux-bpfel-v3-reserve, linux-bpfel-v3-subprog, linux-bpfel-v3-uprobe
kernel tests: runner available at <vng-on-PATH>
```

`doctor` changes nothing. Every tool must read `present`; a
missing tool is reported, never silently worked around.

## 4. Write the counter project

`mojobpf.toml`:

```toml
schema_version = 1

[project]
name = "quickstart-counter"

[target]
profile = "linux-bpfel-v3"
core = false

[artifact]
name = "counter"
source_license = "Apache-2.0 WITH LLVM-exception"
kernel_license = "Apache-2.0 WITH LLVM-exception"

[[programs]]
source = "counter.mojo"
entry = "xdp_entry"
program_type = "xdp"
section = "xdp"

[[maps]]
name = "mojobpf_map0"
map_type = "array"
key_type = "u32"
value_type = "u64"
max_entries = 1
```

`counter.mojo` (the SPDX header is required: builds refuse
sources without one):

```mojo
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
# XDP invocation counter written in Mojo.
#
# Behavior: add one to entry 0 of the single-entry array map on
# every invocation and return XDP_PASS (2). On a lookup miss,
# return XDP_PASS without touching the map (an in-range array
# lookup never misses; the check satisfies the kernel verifier).

from mojobpf.helpers import bpf_map_lookup, bpf_map_update
from mojobpf.maps import BPF_ANY, MapHandle, key_slot, value_slot


@export
def xdp_entry(ctx: MutPointer[UInt8, MutAnyOrigin]) abi("C") -> Int32:
    var key = key_slot()
    var found = bpf_map_lookup(MapHandle.load().addr, key)
    if found.is_null():
        return Int32(2)
    var slot = value_slot()
    var old = found.unsafe_value_ptr()[unsafe_offset=0]
    slot[unsafe_offset=0] = old + 1
    var keyb = key_slot()
    _ = bpf_map_update(MapHandle.load().addr, keyb, slot, Int64(BPF_ANY))
    return Int32(2)
```

Pin your toolchain the way any user pins theirs (version plus
SHA-256 of each resolved binary, plus the installed adapter
service the packaged default build runs):

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
for name in ('mojo', 'llc'):
    path = shutil.which(name)
    real = os.path.realpath(path)
    out = subprocess.run([path, '--version'],
                         capture_output=True, text=True)
    text = out.stdout.strip() or out.stderr.strip()
    tools[name] = {'sha256': sha256_file(real),
                   'version': text.splitlines()[0].strip()}
spec = importlib.util.find_spec('mojobpf.resources.adapter')
adapter_dir = list(spec.submodule_search_locations)[0]
siblings = {}
for name in ('admission.json', 'audit.py', 'mojo_ir_adapter.py'):
    siblings[name] = sha256_file(os.path.join(adapter_dir, name))
doc = {'adapter': {
           'note': 'quickstart (installed-package pins)',
           'service_sha256': sha256_file(
               os.path.join(adapter_dir, 'adapter_service.py')),
           'siblings': siblings},
       'generated_by': 'quickstart (PATH-resolved pins)',
       'license': 'Apache-2.0 WITH LLVM-exception',
       'schema_version': 1, 'tools': tools}
open('toolchains.lock.json', 'w').write(
    json.dumps(doc, indent=2, sort_keys=True) + '\n')
EOF
```

## 5. Build

```bash
mojobpf build --manifest mojobpf.toml --out-dir build \
    --lockfile toolchains.lock.json
```

```text
built <qs>/build/counter.bpf.o (1896 bytes, sha256 b26791510be38c737fe52a7236ee4484df2e7dbb4f5fffc007175532c6122a60)
built <qs>/build/counter.evidence.json (4796 bytes, sha256 fb24cd5eb6429d18b9f9e5381e849b7b78a88b69982312359ae421a6927325fb)
```

The directory holds the object plus its evidence sidecar; see
[artifact-format](artifact-format.md) for both layouts. The
build above used an independently installed Mojo 1.1.0 with
no repository paths, and the object is byte-identical to the
0.2.0 quickstart object; rebuilding these exact sources
anywhere produces the same object bytes
(`tests/kernel/test_cleanup.py::test_reproducible_two_paths`).

## 6. Inspect

```bash
mojobpf inspect --object build/counter.bpf.o \
    --source-license "Apache-2.0 WITH LLVM-exception" \
    --kernel-license "Apache-2.0 WITH LLVM-exception"
```

```text
object build/counter.bpf.o (profile linux-bpfel-v3): ok
observation: sections in order: , .strtab, .text, .BTF, .rel.BTF, xdp, .relxdp, license, .maps, .eh_frame, .rel.eh_frame, .symtab
observation section:license: license payload: b'Apache-2.0 WITH LLVM-exception\x00'
observation: empty executable sections: .text
observation: defined functions: xdp_entry
observation: map metadata: .maps present: True, .BTF present: True
observation: helper IDs observed: 1, 2
observation: call instructions: 2
```

## 7. Load in a disposable guest

```bash
mojobpf verify --kernel --object build/counter.bpf.o \
    --kernels-lock <sourcedir>/ci/kernels.lock.json
```

(The kernels lock travels with the source tree the wheel was
built from, not in the wheel; point at that file.)

```text
mojobpf-verify-kernel: status=pass stage=done
object: build/counter.bpf.o (sha256 b26791510be38c73)
lane: v6.12-tcg (release v6.12/tcg, expected kernel 6.12.0-061200-generic)
guest: kernel=6.12.0-061200-generic btf=present prog_type=xdp supported=True
load: attempted=True exit=0
unload: attempted=True pin_absent=True
staging: <tmpdir> (kept=False)
guest commands: load/unload only; no attach, no test-run
```

The object loaded under unmodified `bpftool`/libbpf inside a
disposable guest and unloaded cleanly: nothing was attached to
any interface, and nothing ran on the host. Exit code 0.

## What can go wrong

* `mojobpf build` without `--lockfile` fails with `MBPF104`:
  locked builds require lockfile validation. Write the
  lockfile as in step 4, including the adapter record: a
  lockfile without one fails the packaged default build
  with `MBPF104` as well.
* A source without an SPDX header fails with `MBPF707`: add
  the header line (see step 4).
* `mojobpf verify --kernel` without a guest runner fails with
  an environment report (exit 3), never a pass. Loader and
  verifier failures both exit 5, classified separately
  (`MBPF501` loader, `MBPF502` verifier).
