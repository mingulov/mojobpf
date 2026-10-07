<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 0.1.0 checksums

Stable content hashes for the release. The wheel file itself is
not byte-reproducible (zip timestamps vary per build: two
consecutive builds of the same release tree hashed `0a7e1620...`
and `120b0bb3...`), but their extracted contents are byte-identical
(`diff -r` clean). Verify the contents, not the container.

Reference wheel build (from the release commit):

```text
mojobpf-0.1.0-py3-none-any.whl size=125446 sha256=af970cdaeb728f05b4d4d0ffaf3fcdb94c16ff34c9e47850738fe1ebe9aa470f
```

Reproduce it with `pip wheel . --no-deps --no-build-isolation
-w dist` from the release tree and compare the extracted files
against the table below (SHA-256 per archived path):

```text
35f48601b71322cd5a0db9767a2b1d4c6b825dd25946a89795ed08f62c33c157 mojobpf-0.1.0.dist-info/METADATA
b1ef4deb5fb959a9a9cbc0a48d8074ddce98ca09814354b8b2384d99f191d4bb mojobpf-0.1.0.dist-info/RECORD
95353a07a7887d8a224094d935cf9fc9a47a0692fa7a14f3537c466319f69fc9 mojobpf-0.1.0.dist-info/WHEEL
da2d8979ab63f4b4934949fb308f344c026f5786d1c61c58571fb5227c87b019 mojobpf-0.1.0.dist-info/entry_points.txt
077ecef8fc610215df3319c555c2fa1b4d28df60ee67a72946b9338cbc90a8a0 mojobpf-0.1.0.dist-info/licenses/LICENSE
58fb99503e6a21460de93d8dd2e64ca1ae60b569482955a8d0787775ce864d9f mojobpf-0.1.0.dist-info/licenses/THIRD_PARTY_NOTICES.md
45c93ebd92be7696a5a84b824c30dd91063275556c8808065abcb1b8d5025855 mojobpf-0.1.0.dist-info/top_level.txt
686333e091f134ce85b1c0e8670be076ef8996263ee7d28a10d75f5eab0d53a9 mojobpf/__init__.py
ab577b801cc797c747d50acdb1d086d49f891d7c4968919a7ab014d2ca2d78ad mojobpf/build.py
ea1491ccfbb2fbef5d4fb22130a2f12171b0b8acf196480fab05afa825f7e85f mojobpf/cli.py
48d11f8960f87cc48236fdfd9d82444f943e41a65ad71cb56c94486acb0cf618 mojobpf/diagnostics.py
27d7b32285d037e997eb082d1d9153f2eaf7bb519f3d8b7273100b32e42ca2e6 mojobpf/evidence.py
e75e69751f0ead1cfbea9c69a4e5b0ff8f9c3858f4af53d65e0a0bfe67f6cb34 mojobpf/inspect.py
8f49ff0e4339c82ae72328eb7b885208fad0b899c9cfb4e8ee849eb1dda4750e mojobpf/manifest.py
9715ed08ff915069ef781199db44259cecf40332129f98d7c807511ea669e324 mojobpf/resources/adapter/adapter_service.py
a1a3980f65c3c72e552603519737fe3169c96b6eff01a77e7c7015c958fac058 mojobpf/resources/adapter/audit.py
0690cf738091871bc07a519e42f2832e2226186cee122c19cf9b653d2fd3d453 mojobpf/resources/adapter/mojo_ir_adapter.py
c7784e3806b18f5252c67d1affecb3a6febbaa3a97ce64ac56a6c27adf526a21 mojobpf/resources/sdk/mojobpf/checksum.mojo
59a4548012f3c30bf86c33bb1bd5801bf2f6280d0ef6cc7372624e24b93b7857 mojobpf/resources/sdk/mojobpf/helpers.mojo
feeb45944cb89a87dce714173d1ff3d64464e7211e18b486e9fb6d818d10495b mojobpf/resources/sdk/mojobpf/maps.mojo
19cb2e841bba6810bf67b5d51bccac40993002d7c1fffbed1e2c9120a2ad20cd mojobpf/resources/sdk/mojobpf/packet.mojo
3fa36c595e02159d3afd96b10a0c00b1697303d158784f97357d84d1ed803d9b mojobpf/resources/sdk/mojobpf/parse.mojo
14c2e22c1e680eb9d7ee5f0823b15a92367b773d4041b39e2f004a3f2f4634ba mojobpf/sdk.py
6cde12fe748484dcca7f22682ee2aed379f2cc9005508dcd6ce6dae465af3d31 mojobpf/toolchain.py
f3526dac8f06e3d1c18b2cff54638fe64c8c948a1f80a8bb86d137e6db895707 mojobpf/verify.py
```

The SDK and adapter revisions are identical across the source
tree, the installed package, and the wheel (8/8 files equal):

```text
sdk/mojobpf/checksum.mojo c7784e3806b18f52 EQUAL
sdk/mojobpf/helpers.mojo 59a4548012f3c30b EQUAL
sdk/mojobpf/maps.mojo feeb45944cb89a87 EQUAL
sdk/mojobpf/packet.mojo 19cb2e841bba6810 EQUAL
sdk/mojobpf/parse.mojo 3fa36c595e02159d EQUAL
adapter/adapter_service.py 9715ed08ff915069 EQUAL
adapter/audit.py a1a3980f65c3c72e EQUAL
adapter/mojo_ir_adapter.py 0690cf738091871b EQUAL
8 files compared, 0 differing
```

Reference object hashes (rebuilt byte-identically in the release
runs; see the [evidence summary](evidence-0.1.0.md)):

```text
classifier (feasibility pin) 17570ee79a16b64ccc4f723d00d26ae316a286cffdd3382ba3a6e6b4be95097c
map round trip (feasibility pin) 18f7490634c6462360aafcb1ece85406b2374b4b74a2ca4501f90b5781e8a540
consumer canary bd1520ce3aeb0d99b8c2b9ae70336b7a064170fea1d2f978f3cb0d3c75b23840 (identical in both matrix lanes)
quickstart counter b26791510be38c737fe52a7236ee4484df2e7dbb4f5fffc007175532c6122a60
```
