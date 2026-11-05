<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 0.3.0a1 checksums

Stable content hashes for the alpha. The wheel file itself is
not byte-reproducible (zip timestamps vary per build), but
the extracted contents of same-tree rebuilds are byte-identical
(`diff -r` clean). Verify the contents, not the container.

Reference wheel build (from the release tree — the matrix
commit's code plus only the docs carrying this release record,
which do not enter the wheel):

```text
mojobpf-0.3.0a1-py3-none-any.whl size=474639 sha256=dfa8dddedbc93cc5db2c6863dd15fc586d2daf4f724d3f215e7341e0375f21ba
```

The wheel carries no docs, so these contents equal a build
from the matrix commit pinned in
[evidence](evidence-0.3.0a1.md) (verified by rebuilding from
the release tree twice and diffing the extracted contents).

Reproduce it with `pip wheel . --no-deps --no-build-isolation
-w dist` from the release tree and compare the extracted files
against the table below (SHA-256 per archived path):

```text
4db9e5a8bf821077e85896df28e1252e0640f37227e9b1c6063aed3ce4356097  mojobpf-0.3.0a1.data/data/share/mojobpf/schemas/cost.schema.json
4f0d007a38b39176d3b6146bebd222bda0f3af772c5ac35f3425190011b27ff2  mojobpf-0.3.0a1.data/data/share/mojobpf/schemas/fixture.schema.json
222c12563552f5044f4fa6698ac47e304458e969a0b5f26ffa9a93a64983715b  mojobpf-0.3.0a1.data/data/share/mojobpf/schemas/result.schema.json
e48385efc38aa27616f36ba002522825718d4daf21205f4fa8ec0247a18f8af3  mojobpf-0.3.0a1.data/data/share/mojobpf/schemas/run-plan.schema.json
d5b25ab6c67fad351e0828e8918f6f7235babfdb6a2a39d1222c1d9aaa67ba21  mojobpf-0.3.0a1.data/data/share/mojobpf/schemas/target.schema.json
da2d8979ab63f4b4934949fb308f344c026f5786d1c61c58571fb5227c87b019  mojobpf-0.3.0a1.dist-info/entry_points.txt
4244bc559163163a605d3c3135f3115d04e2bb937a37ab5fb6f13194931db8bf  mojobpf-0.3.0a1.dist-info/licenses/LICENSE
58fb99503e6a21460de93d8dd2e64ca1ae60b569482955a8d0787775ce864d9f  mojobpf-0.3.0a1.dist-info/licenses/THIRD_PARTY_NOTICES.md
f61a78a34fc10e031d00394ea286cf63b1d7bd3534b22f4ca26214cc35d2656c  mojobpf-0.3.0a1.dist-info/METADATA
963bde54ebfc68bcc3de848f212f83bc4d44363ba616411e084953a9b7846fbc  mojobpf-0.3.0a1.dist-info/RECORD
45c93ebd92be7696a5a84b824c30dd91063275556c8808065abcb1b8d5025855  mojobpf-0.3.0a1.dist-info/top_level.txt
c14c80f0e6ae95195b7f032d990b2f367806af140702f90a72f466762ce5262d  mojobpf-0.3.0a1.dist-info/WHEEL
9b060ab65d7eb52f127e63024f6e94e932c210da3755259119bd278772596f77  mojobpf/build.py
6231de780c1756607bf542e5e743ca3af16fad98b6fdbf66454cdc638064d5cc  mojobpf/capabilities.py
b57e8252e3a122a68742550500331cee426932bd4e90acaa23acd3f42951fbcc  mojobpf/cli.py
48d11f8960f87cc48236fdfd9d82444f943e41a65ad71cb56c94486acb0cf618  mojobpf/diagnostics.py
b54ac9eb3d77c1e3e895ad8245b63bfb8fa3f8aaf82b469d84684b4c9527959f  mojobpf/elf_reader.py
c70a17014b9486c1da0e72c1222c0e1b6cf4e8497108cbcdc5f35d4c81aa290e  mojobpf/events.py
849797603ff0a8b4d8cd2b2465118970a94884c4830ef8e25627594bc3713448  mojobpf/evidence.py
4b8404783a676591d4141e81cee9ed235d4192e61bb8010f54a870826cd60438  mojobpf/execution.py
f6a4990cca2cbc4e523c137a08bc53445017cdd357d8af7cfcb805ad630b61e2  mojobpf/helpers.py
3a76be8f7d07b7844e57dbc36bb0460902c7aacf244d42819f25c0d2f8941972  mojobpf/__init__.py
30aa563f03612768d46127cc9bdb2b115e1143a1003cb2b661043fe8f17e8778  mojobpf/inputs.py
90f04c52c065db9efee3e3220453b5542b702db3e74bcc251d6c484f52c316ce  mojobpf/inspect.py
bc8b4c98ca0c94064c09374e9320113d2d383c987c01119caaa7418502e3b760  mojobpf/manifest.py
c840a13a9d3b5d90a3b8c5441bd05e6ca9e3dd681caac3cb7c8f01ac03dd5695  mojobpf/models.py
7fe0b70d83c26702bbd707a445908888993b742e04c190eb68dbc75b0bc07c71  mojobpf/native_adapter.py
6b4a08d7ec254b07aa0c5e6333b0d30665d1569c75d6c10e9722ed0b3e9372be  mojobpf/process_guardian.py
cddecc3fb509dbd350f3e5fba4561844cc868c6bddc6e03af9aa938a01cdb44b  mojobpf/resources/adapter/adapter_service.py
92c06052b816b60f3c98c0469cd46aefc6c10f0b0161751a1952cabafb0b65d6  mojobpf/resources/adapter/admission.json
951130967834fe01c7bfd4f8b5538761b349678594a8d34ed4637d181b40bfd7  mojobpf/resources/adapter/audit.py
1fb271ad2d020c0dcca094f6dbbacc6812812fc1bd2b322f80954f9019eb35c1  mojobpf/resources/adapter/mojo_ir_adapter.py
c7784e3806b18f5252c67d1affecb3a6febbaa3a97ce64ac56a6c27adf526a21  mojobpf/resources/sdk/mojobpf/checksum.mojo
d0d231825076babcb282694c1ab0e5083f616e24849e81429dbd4085d2d699d8  mojobpf/resources/sdk/mojobpf/core.mojo
97ecf6544f6113c3159e01f98c6bcc1691a35b942ec6caa5931d14f06e0b3e62  mojobpf/resources/sdk/mojobpf/events.mojo
090fd5321ed2dd74fc54014aa32790e8d7269840002818d76a0e5a71f1f9df94  mojobpf/resources/sdk/mojobpf/helpers.mojo
186317f50de072152867ce97aea412a7403c6b1d977a66ed06af4456f84a375e  mojobpf/resources/sdk/mojobpf/maps.mojo
8a217bf27911663ecb7e98088ed422eec4c84414c94dc409a8813a8e1e288060  mojobpf/resources/sdk/mojobpf/packet.mojo
3fa36c595e02159d3afd96b10a0c00b1697303d158784f97357d84d1ed803d9b  mojobpf/resources/sdk/mojobpf/parse.mojo
5c704956e921147eb58563c62225f07b9350f928f26a6dcb548631e721991ce9  mojobpf/resources/sdk/mojobpf/uprobe.mojo
6b07561a35a8b06ba2d6ab7579b7999a2bd833e8e175a4809c86359005843b68  mojobpf/safeio.py
ab812251e9a301c5e44a150a96af9d4fa7f840ee8f6acfe7a7bfefc5cabd5903  mojobpf/sdk.py
1afabb72c39538e5e1fff48e876461dadb459f0ff2600a4970723e1a832886a3  mojobpf/sealed_fs.py
327fe3c62999dcf2f34a4026eb7de62b7573acae39e9405c66234253ef1c1f60  mojobpf/target_controller.py
9301487644fde291026e733ce73321ba0b7eec7e9d2ccd258884f446e778487b  mojobpf/toolchain.py
8871a54d071bf1651fd192de6795352dbeeae785edb99178b3fef326d43c49ca  mojobpf/validation/aggregate.py
4b75d0a8f68168c85b7353b482454fc7c662c55f0bce1b51830e6858de3a1883  mojobpf/validation/__init__.py
4869668e60e3be0fd1724d13d499ffa923c9eaa55caf688e1b563e87f64807c7  mojobpf/validation/models.py
3d6efc318f8455ac596214f0a806b7eb6eb3614546dcb294b7b64d5e5f4a7449  mojobpf/verify.py
```

The SDK and adapter revisions are identical across the source
tree, the installed package, and the wheel (12/12 files equal):

```text
sdk/mojobpf/checksum.mojo c7784e3806b1 EQUAL
sdk/mojobpf/core.mojo d0d231825076 EQUAL
sdk/mojobpf/events.mojo 97ecf6544f61 EQUAL
sdk/mojobpf/helpers.mojo 090fd5321ed2 EQUAL
sdk/mojobpf/maps.mojo 186317f50de0 EQUAL
sdk/mojobpf/packet.mojo 8a217bf27911 EQUAL
sdk/mojobpf/parse.mojo 3fa36c595e02 EQUAL
sdk/mojobpf/uprobe.mojo 5c704956e921 EQUAL
adapter/adapter_service.py cddecc3fb509 EQUAL
adapter/admission.json 92c06052b816 EQUAL
adapter/audit.py 951130967834 EQUAL
adapter/mojo_ir_adapter.py 1fb271ad2d02 EQUAL
12 files compared, 0 differing
```

Reference object hashes (rebuilt byte-identically in the
release runs; see the [evidence
summary](evidence-0.3.0a1.md)):

```text
quickstart counter b26791510be38c737fe52a7236ee4484df2e7dbb4f5fffc007175532c6122a60
```

The quickstart counter object is byte-identical to the 0.2.0
quickstart object: the XDP counter pipeline reproduces
exactly across the minor bump. Joint-stack objects are
lane-specific (they embed per-lane test-run inputs) and are
pinned per run in the evidence bundle, not here.
