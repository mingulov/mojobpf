<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 1.0.0 checksums

Stable content hashes for the release. The wheel file itself is
not byte-reproducible (zip timestamps vary per build), but
the extracted contents of same-tree rebuilds are byte-identical
(`diff -r` clean). Verify the contents, not the container.

Reference wheel build (from a clean clone of `99ec890` —
the docs carrying this release record do not enter the
wheel, so these contents equal a build from the release
tree; verified by rebuilding from the release tree and
diffing the extracted contents):

```text
mojobpf-1.0.0-py3-none-any.whl size=497232 sha256=8f7f708e9c5205b05936da07854ba7acaac61f90131f26bc29603116d291be50
```

The wheel carries no docs and no tests, so these contents
equal a build from the matrix commit pinned in
[evidence](evidence-1.0.0.md) (verified by rebuilding from
the release tree and diffing the extracted contents).

Reproduce it with `pip wheel . --no-deps --no-build-isolation
-w dist` from the release tree and compare the extracted files
against the table below (SHA-256 per archived path):

```text
721e0d12697ce6d50ff700612f2bc91e1e77f56f197a8413f1091b7ccd044f44   mojobpf-1.0.0.data/data/share/mojobpf/schemas/artifact.schema.json
2d5ab6cb8f01fb0a0040420c623ac1b167e2a72240fbba10e496282c311af099   mojobpf-1.0.0.data/data/share/mojobpf/schemas/capability.schema.json
4db9e5a8bf821077e85896df28e1252e0640f37227e9b1c6063aed3ce4356097   mojobpf-1.0.0.data/data/share/mojobpf/schemas/cost.schema.json
d329b14116322263156dce1b3e2d90eef2c8953cfe9bb8f58408dfea48a752f9   mojobpf-1.0.0.data/data/share/mojobpf/schemas/diagnostics.schema.json
02cd66291528f41fae900246abd048ad8ec5d5b5481ae088f8b92586140c70d6   mojobpf-1.0.0.data/data/share/mojobpf/schemas/evidence.schema.json
4f0d007a38b39176d3b6146bebd222bda0f3af772c5ac35f3425190011b27ff2   mojobpf-1.0.0.data/data/share/mojobpf/schemas/fixture.schema.json
8cd312bb3fa5a108d2d5cf23fea0c510bdd2190f0d41d7361a42ebe1c9609af7   mojobpf-1.0.0.data/data/share/mojobpf/schemas/manifest.schema.json
222c12563552f5044f4fa6698ac47e304458e969a0b5f26ffa9a93a64983715b   mojobpf-1.0.0.data/data/share/mojobpf/schemas/result.schema.json
e48385efc38aa27616f36ba002522825718d4daf21205f4fa8ec0247a18f8af3   mojobpf-1.0.0.data/data/share/mojobpf/schemas/run-plan.schema.json
9a1caf0271b9b418a67438f6167232b568466c03d1d0caf9cb27a431d8961e27   mojobpf-1.0.0.data/data/share/mojobpf/schemas/size-budget.schema.json
d5b25ab6c67fad351e0828e8918f6f7235babfdb6a2a39d1222c1d9aaa67ba21   mojobpf-1.0.0.data/data/share/mojobpf/schemas/target.schema.json
da2d8979ab63f4b4934949fb308f344c026f5786d1c61c58571fb5227c87b019   mojobpf-1.0.0.dist-info/entry_points.txt
4244bc559163163a605d3c3135f3115d04e2bb937a37ab5fb6f13194931db8bf   mojobpf-1.0.0.dist-info/licenses/LICENSE
58fb99503e6a21460de93d8dd2e64ca1ae60b569482955a8d0787775ce864d9f   mojobpf-1.0.0.dist-info/licenses/THIRD_PARTY_NOTICES.md
07dbf05f350eb057db2f1f123f6699a4cc9841e1802d6614021bfad3a283de23   mojobpf-1.0.0.dist-info/METADATA
8b08fc51d39bdaca75635da776d31cd889d3d2a2467c1038515fe8a6579f58bf   mojobpf-1.0.0.dist-info/RECORD
45c93ebd92be7696a5a84b824c30dd91063275556c8808065abcb1b8d5025855   mojobpf-1.0.0.dist-info/top_level.txt
c14c80f0e6ae95195b7f032d990b2f367806af140702f90a72f466762ce5262d   mojobpf-1.0.0.dist-info/WHEEL
f0a02c92bbae08e3b94a377ec7ded9001657185253b65a9c38ffba29c92f0a34   mojobpf/build.py
b13c601c7e7152a7272fe73d655811179157f457253299ecdf6b4cd369a94a1b   mojobpf/capabilities.py
8ccac96fd599368b53b472b0cf7d780e8fe3d4eca4f35089fbd119450be5fb43   mojobpf/cli.py
48d11f8960f87cc48236fdfd9d82444f943e41a65ad71cb56c94486acb0cf618   mojobpf/diagnostics.py
b54ac9eb3d77c1e3e895ad8245b63bfb8fa3f8aaf82b469d84684b4c9527959f   mojobpf/elf_reader.py
c70a17014b9486c1da0e72c1222c0e1b6cf4e8497108cbcdc5f35d4c81aa290e   mojobpf/events.py
849797603ff0a8b4d8cd2b2465118970a94884c4830ef8e25627594bc3713448   mojobpf/evidence.py
4b8404783a676591d4141e81cee9ed235d4192e61bb8010f54a870826cd60438   mojobpf/execution.py
f6a4990cca2cbc4e523c137a08bc53445017cdd357d8af7cfcb805ad630b61e2   mojobpf/helpers.py
2885f7c54d276d0cad1d4509122ecf22a0b555e6c24cf8a82c756ba277ee3a06   mojobpf/__init__.py
30aa563f03612768d46127cc9bdb2b115e1143a1003cb2b661043fe8f17e8778   mojobpf/inputs.py
f02e7e89f7b516b73ece44e9a195e92b3ad56e103ca8f6c1bf938e07b2d2676f   mojobpf/inspect.py
bc8b4c98ca0c94064c09374e9320113d2d383c987c01119caaa7418502e3b760   mojobpf/manifest.py
c840a13a9d3b5d90a3b8c5441bd05e6ca9e3dd681caac3cb7c8f01ac03dd5695   mojobpf/models.py
f4c8bd9880aa5f5708b6ab5e6c098529071ef434acb2c2e437483ff1bcff0739   mojobpf/native_adapter.py
6b4a08d7ec254b07aa0c5e6333b0d30665d1569c75d6c10e9722ed0b3e9372be   mojobpf/process_guardian.py
55a037c358292dd9af58b2cb66f1947697d933a3ca1b5b2fe5e99e05298fb1e0   mojobpf/resources/adapter/adapter_service.py
316f8cc2a5d4736c876207f733dffb97788b03d14b2d2652f6a294304834417d   mojobpf/resources/adapter/admission.json
7fbd013294dd629c354a36c4051c3469ca9c376e75d9bed6ea417cf9d0621c8f   mojobpf/resources/adapter/audit.py
dca1c8fd70fc99d41c00a67a2102e1da0ca0e985a8bdee16bd2f2a2df5b5b2c1   mojobpf/resources/adapter/mojo_ir_adapter.py
c7784e3806b18f5252c67d1affecb3a6febbaa3a97ce64ac56a6c27adf526a21   mojobpf/resources/sdk/mojobpf/checksum.mojo
d0d231825076babcb282694c1ab0e5083f616e24849e81429dbd4085d2d699d8   mojobpf/resources/sdk/mojobpf/core.mojo
97ecf6544f6113c3159e01f98c6bcc1691a35b942ec6caa5931d14f06e0b3e62   mojobpf/resources/sdk/mojobpf/events.mojo
090fd5321ed2dd74fc54014aa32790e8d7269840002818d76a0e5a71f1f9df94   mojobpf/resources/sdk/mojobpf/helpers.mojo
72dd10fe1c91ae8bf1387636d371779dd904a2892aa7c110d6ceadf1046f076c   mojobpf/resources/sdk/mojobpf/maps.mojo
8a217bf27911663ecb7e98088ed422eec4c84414c94dc409a8813a8e1e288060   mojobpf/resources/sdk/mojobpf/packet.mojo
3fa36c595e02159d3afd96b10a0c00b1697303d158784f97357d84d1ed803d9b   mojobpf/resources/sdk/mojobpf/parse.mojo
5c704956e921147eb58563c62225f07b9350f928f26a6dcb548631e721991ce9   mojobpf/resources/sdk/mojobpf/uprobe.mojo
6b07561a35a8b06ba2d6ab7579b7999a2bd833e8e175a4809c86359005843b68   mojobpf/safeio.py
827c4423fdb54df81702406c6238795bfcbe120fa6e5e3a02eaabae1f6aaba55   mojobpf/sdk.py
1afabb72c39538e5e1fff48e876461dadb459f0ff2600a4970723e1a832886a3   mojobpf/sealed_fs.py
4bc0b073fae3e843fc0bd842d5dbca84e83d5cf4c34996d72ea88e7ec7a5ce62   mojobpf/target_controller.py
9301487644fde291026e733ce73321ba0b7eec7e9d2ccd258884f446e778487b   mojobpf/toolchain.py
8871a54d071bf1651fd192de6795352dbeeae785edb99178b3fef326d43c49ca   mojobpf/validation/aggregate.py
4b75d0a8f68168c85b7353b482454fc7c662c55f0bce1b51830e6858de3a1883   mojobpf/validation/__init__.py
4869668e60e3be0fd1724d13d499ffa923c9eaa55caf688e1b563e87f64807c7   mojobpf/validation/models.py
3d6efc318f8455ac596214f0a806b7eb6eb3614546dcb294b7b64d5e5f4a7449   mojobpf/verify.py
```
