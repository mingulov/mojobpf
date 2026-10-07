<!-- SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception -->

# MojoBPF 0.2.0 checksums

Stable content hashes for the release. The wheel file itself is
not byte-reproducible (zip timestamps vary per build), but
the extracted contents of same-tree rebuilds are byte-identical
(`diff -r` clean). Verify the contents, not the container.

Reference wheel build (from the release tree — the matrix
commit's code plus only the docs carrying this release record,
which do not enter the wheel):

```text
mojobpf-0.2.0-py3-none-any.whl size=148693 sha256=246f47c824be81326071d971fb3ab618bc1e1304c40e6dd1d6f114c54d45aae4
```

The wheel carries no docs, so these contents equal a build
from the matrix commit pinned in
[evidence](evidence-0.2.0.md) (verified by rebuilding from
the release tree and diffing the extracted contents).

Reproduce it with `pip wheel . --no-deps --no-build-isolation
-w dist` from the release tree and compare the extracted files
against the table below (SHA-256 per archived path):

```text
368d393ccccf8634821f6e6eb527f98bb804b3f3979bb314ed1d9297efd7cd2d  mojobpf-0.2.0.dist-info/METADATA
6881ab88b020a47a2efea09a80ed8df610a9528522645fda89b393ee398d61a3  mojobpf-0.2.0.dist-info/RECORD
95353a07a7887d8a224094d935cf9fc9a47a0692fa7a14f3537c466319f69fc9  mojobpf-0.2.0.dist-info/WHEEL
da2d8979ab63f4b4934949fb308f344c026f5786d1c61c58571fb5227c87b019  mojobpf-0.2.0.dist-info/entry_points.txt
077ecef8fc610215df3319c555c2fa1b4d28df60ee67a72946b9338cbc90a8a0  mojobpf-0.2.0.dist-info/licenses/LICENSE
58fb99503e6a21460de93d8dd2e64ca1ae60b569482955a8d0787775ce864d9f  mojobpf-0.2.0.dist-info/licenses/THIRD_PARTY_NOTICES.md
45c93ebd92be7696a5a84b824c30dd91063275556c8808065abcb1b8d5025855  mojobpf-0.2.0.dist-info/top_level.txt
df9daba372634af020f39f6d015b41fc0b48bbf0e3179139345fcd06dcd4204b  mojobpf/__init__.py
f3e97a94d9fadd988846973f852856a4827207b380b9a69fe3487f4b15f686fb  mojobpf/build.py
b48049b13a77219212e69815b0ab338fff417376c6246c2ebdf521bfb77676cc  mojobpf/cli.py
48d11f8960f87cc48236fdfd9d82444f943e41a65ad71cb56c94486acb0cf618  mojobpf/diagnostics.py
4f376d2e08d887d3f865a6d0171cbbd678650da488b3f313ffb9105aecec0388  mojobpf/events.py
27d7b32285d037e997eb082d1d9153f2eaf7bb519f3d8b7273100b32e42ca2e6  mojobpf/evidence.py
aa326417979c7b266d7ae6b0a9319846e2ab9671d4414d2207f762773004ad87  mojobpf/helpers.py
9f0ec0f28ea766d80695a1a2a3b3b30c8c47231e4191070cae22a3e872222af2  mojobpf/inspect.py
3d5b64a2f23b2bf889bc438a51481acdf9052e0783d4b6eef93b5d0f330daeb0  mojobpf/manifest.py
9715ed08ff915069ef781199db44259cecf40332129f98d7c807511ea669e324  mojobpf/resources/adapter/adapter_service.py
d9e62d72dac759222b280addc7b8ff8ec54ff4a363ba967dec03bbc22368b2f9  mojobpf/resources/adapter/audit.py
c58a1559f29570af64c9cc53ecf512e324fca9120673a2da2954db102bf3f464  mojobpf/resources/adapter/mojo_ir_adapter.py
c7784e3806b18f5252c67d1affecb3a6febbaa3a97ce64ac56a6c27adf526a21  mojobpf/resources/sdk/mojobpf/checksum.mojo
04eb8823d5d927d9dd1e588e7b92e01b3b517c78e845d13c55174165a2ae2064  mojobpf/resources/sdk/mojobpf/events.mojo
59a4548012f3c30bf86c33bb1bd5801bf2f6280d0ef6cc7372624e24b93b7857  mojobpf/resources/sdk/mojobpf/helpers.mojo
feeb45944cb89a87dce714173d1ff3d64464e7211e18b486e9fb6d818d10495b  mojobpf/resources/sdk/mojobpf/maps.mojo
19cb2e841bba6810bf67b5d51bccac40993002d7c1fffbed1e2c9120a2ad20cd  mojobpf/resources/sdk/mojobpf/packet.mojo
3fa36c595e02159d3afd96b10a0c00b1697303d158784f97357d84d1ed803d9b  mojobpf/resources/sdk/mojobpf/parse.mojo
a206c427335a20ab14227ce6eeedd7b8687cdc77f048c401c397b7e46f4f3982  mojobpf/sdk.py
6cde12fe748484dcca7f22682ee2aed379f2cc9005508dcd6ce6dae465af3d31  mojobpf/toolchain.py
1160b391df2be618739200731bf17cfa70062f4a4fdbf5fcbfa416dfb945bbf6  mojobpf/verify.py
```

The SDK and adapter revisions are identical across the source
tree, the installed package, and the wheel (9/9 files equal):

```text
sdk/mojobpf/checksum.mojo c7784e3806b18f52 EQUAL
sdk/mojobpf/events.mojo 04eb8823d5d927d9 EQUAL
sdk/mojobpf/helpers.mojo 59a4548012f3c30b EQUAL
sdk/mojobpf/maps.mojo feeb45944cb89a87 EQUAL
sdk/mojobpf/packet.mojo 19cb2e841bba6810 EQUAL
sdk/mojobpf/parse.mojo 3fa36c595e02159d EQUAL
adapter/adapter_service.py 9715ed08ff915069 EQUAL
adapter/audit.py d9e62d72dac75922 EQUAL
adapter/mojo_ir_adapter.py c58a1559f29570af EQUAL
9 files compared, 0 differing
```

Reference object hashes (rebuilt byte-identically in the release
runs; see the [evidence summary](evidence-0.2.0.md)):

```text
classifier (feasibility pin) 17570ee79a16b64ccc4f723d00d26ae316a286cffdd3382ba3a6e6b4be95097c
map round trip (feasibility pin) 18f7490634c6462360aafcb1ece85406b2374b4b74a2ca4501f90b5781e8a540
consumer canary bd1520ce3aeb0d99b8c2b9ae70336b7a064170fea1d2f978f3cb0d3c75b23840 (identical in both matrix lanes)
quickstart counter b26791510be38c737fe52a7236ee4484df2e7dbb4f5fffc007175532c6122a60
```
