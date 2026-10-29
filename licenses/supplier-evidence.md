# Supplier evidence — step 1

Collected **2026-10-27**, Darwin/arm64 host, native Linux/arm64 Docker daemon. **Evidence collection only: redistribution, provenance acceptance and publication remain blocked.** No license sign-off, reproducible-build claim or consumer adoption is supplied.

[Artifact evidence](artifact-evidence.json) records exact public URLs, response SHA-256s, registry descriptor/config identities, source claims, archive notice inventories and verification criteria. Its `approval`, `source_reproducibility_established` and `complete_transitive_notices_established` fields are false. A measured hash identifies retrieved bytes; it does not authenticate a source-to-binary relationship.

**2026-10-29 follow-up:** [Gitleaks runtime evidence](gitleaks-runtime-review.md) retrieves the exact expanded recipes from public APK control sections and matches 20 selected payload/package pairs against both hosted production archives. This supersedes the recipe-access gap below, not missing source-overlay contents, notice completeness or accountable approval.

## Snapshot and supersession

The recorded Docker/cargo-audit recipe hashes match source **`9500de1196b51e2a27143b8188fe08908d4b1f13`**. This collection predates the new Docker/plugin/provider top-level notice layers and the [official GNU cargo-audit replacement](../docs/cargo-audit-supplier.md). Statements about missing packaged notices, musl/Quickinstall pins and runtime contents below describe that snapshot, not current recipes. Historical hashes/measurements are preserved; they do not authenticate the new GNU artifacts. [Current sequence](../docs/release-readiness.md) records what remains blocked.

## Collection boundary

- Read AGENTS, README, TASKS, results, threat model, release readiness, inventory, redistribution guidance, all three skills and all nine Dockerfiles. Only these two new license evidence files and ignored `.work/approval-suppliers/` were authored. Existing/concurrent source, image and configuration changes are not this collection's work.
- Anonymous public HTTPS requests used an empty environment, synthetic HOME, no curl configuration/proxy or operator credentials. Registry pull tokens were obtained anonymously, held in memory and not published/persisted. Public supplier source archives were downloaded, not built or executed.
- Rust helpers, lockfile, raw responses, private process output and derived inventories are in `.work/approval-suppliers/` (0700 parent; downloaded evidence 0600). HTTP transfers had 90-second deadlines, streaming byte caps and SHA-256 receipts: at most 64 MiB per response. Largest retrieved response: **42,952,513 bytes**. No image archives or advisory DB copies were created.
- Four already-cached, exact pinned public supplier images were inspected with an empty Docker config and explicit local Unix endpoint. Stopped native arm64 containers were created with `--pull=never`, exported through a 512 MiB capped stream, never started, then removed. No socket was mounted into a tool container. The second export pass added actual library symlink targets and package SBOMs; both passes are retained. This relies on the trusted local daemon, not independently verified compressed layer contents.
- Only approved `.work/tasks-catalog-evidence` historical evidence was reused: three unchanged report hashes were rechecked against its `SHA256SUMS`. Historical payload digests agree with current supplier exports; they are not clean-source build provenance. No unrelated operator/private directories, real clusters, registry writes, staging, commits or pushes were used. No native amd64 execution or vulnerability scan was performed.
- These per-transfer/export limits are not a hard host-disk quota. The repository's [trust/resource limits](../docs/threat-model.md) and [readiness sequence](../docs/release-readiness.md) remain unchanged.

## Verified supplier index identities

The raw registry index, selected manifests and configs were retrieved and content-addressed hashes checked. Digests below are SHA-256 (prefix omitted).

| Supplier | Pinned index | amd64 manifest | arm64 manifest |
|---|---|---|---|
| `docker.io/library/docker` | `5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb` | `98776017a505b6d89c0adff8c63b0d8701ca10280c41315dbb0638fe3b5cf6e5` | `d54eb9ef0f4cbcd82bfb87c6f8d8951c04ce5a01daf38682f3f57ed6a03acd6d` |
| `cgr.dev/chainguard/git` | `6b5b402aaba4db9a6446e363d70bcc158c773c5d00c75d4bcd68691fdaa539cc` | `8d67f6aec430fefbea18a8ef3af4b7ad626f4ab8bf4ef9f0476d6f7821c77d1f` | `8abe3134dde050de4cc6dc8d43b2a375455ecf721bd32db142ae1537e7ece9ff` |
| `cgr.dev/chainguard/glibc-dynamic` | `5380a8b913d0900cf44180e2205bf3ebf0e0b00a32a0f2fa4ab16cb06d7f9cdf` | `fde84b5b973f0e1145c7cbde86811a64155c6d6557f0d57953d91f955bc449e2` | `f484fa2aaff355191fef1154f4b12defeb21f0099ebaff19006eb2723e6df045` |
| `ghcr.io/gitleaks/gitleaks` | `c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f` | `b109bc5f8f76a38196a3e413704fc5b9e3c32360bce4e4b603bd6f45b3721dbb` | `6b2d52241f9d176fc59e6e3b026ea52c98f390070587d9475d6ee2bc64941815` |

Registry URLs use `https://<registry>/v2/<repository>/manifests/sha256:<digest>`; Docker Hub's API host is `registry-1.docker.io`. Exact URLs/config hashes are in the JSON. Mutable tag names were not used as identity evidence.

## Docker CLI 29.9.2 / Compose 5.6.1 / Buildx 0.38.1

### Source and notices retrieved

GitHub tag-object APIs report `verification.verified=true` for the three annotated tags. These are GitHub's signature-verification assertions, not independently checked local Git signatures or binary provenance.

| Component | Peeled source commit | Retrieved files at that commit |
|---|---|---|
| Docker CLI | `a82e528901260c8df6073311379eac65f92db204` | [LICENSE](https://raw.githubusercontent.com/docker/cli/a82e528901260c8df6073311379eac65f92db204/LICENSE), [NOTICE](https://raw.githubusercontent.com/docker/cli/a82e528901260c8df6073311379eac65f92db204/NOTICE), `vendor/modules.txt` |
| Compose | `6cbc19a3fd59e305fb814dca4d854a4fb67d2941` | [LICENSE](https://raw.githubusercontent.com/docker/compose/6cbc19a3fd59e305fb814dca4d854a4fb67d2941/LICENSE), [NOTICE](https://raw.githubusercontent.com/docker/compose/6cbc19a3fd59e305fb814dca4d854a4fb67d2941/NOTICE) |
| Buildx | `0dbe87f36ed472fe36b6796c3f70b4210a731fc5` | [LICENSE](https://raw.githubusercontent.com/docker/buildx/0dbe87f36ed472fe36b6796c3f70b4210a731fc5/LICENSE); root `NOTICE` request unavailable, not proof that all dependency notices are absent |

These LICENSE files contain Apache-2.0 terms. CLI NOTICE additionally attributes `creack/pty` under MIT and contains transfer/export guidance; Compose NOTICE attributes Docker Compose authors/Docker. All text hashes are recorded; **none is a complete embedded-dependency notice bundle**.

### Attestations and payload bindings

For each architecture, retrieved `.provenance.json` and `.sigstore.json` release assets under:

- `https://github.com/docker/compose/releases/download/v5.6.1/docker-compose-linux-{x86_64,aarch64}`
- `https://github.com/docker/buildx/releases/download/v0.38.1/buildx-v0.38.1.linux-{amd64,arm64}`

Cosign **3.1.1** verified all four bundles with subject checking, certificate chain/SCT/transparency checks enabled, exact identity `https://github.com/docker/github-builder/.github/workflows/bake.yml@58cb9f5b71b1836d6f690c1e95effdeb9b98cb8a` and issuer `https://token.actions.githubusercontent.com`. All four were also reverified with certificate caller-repository (`docker/compose` or `docker/buildx`), tag-ref and peeled source-SHA constraints matching the source table. No insecure-ignore flags or claim bypasses were used. Wrong-digest and wrong-identity controls both failed. Decoded signed statements equal the separately retrieved provenance JSON.

| Binary | amd64 signed release SHA-256 | arm64 signed release SHA-256, also matched in native supplier export |
|---|---|---|
| Compose | `47737f4236e6d3ccea7291995203f8f018058783b4c3a9469119811a0b5db8c0` | `42cfa75f51ad0ccf290bad37899e0038a8c10a0069e85233ecc1d53e3ff1347d` |
| Buildx | `e25d5cd675092bb5d1d03632fdc46cdf3fede7b514dc5f023a105e00d3ce5ad4` | `3b83b3731916ba433feccaaa689fe5bcdc81c641d92c8e6c2ea865dfa141c97a` |

The signed predicates name annotated tag objects `02f05e3787e5b2e83220923907bb014e6a36b359` (Compose) and `9a43f5f060a560384f2b7508d3180d19c2e71136` (Buildx), which the tag APIs peel to the source commits above. Builder run references are [Compose 39562092012/1](https://github.com/docker/compose/actions/runs/39562092012/attempts/1) and [Buildx 39503414114/1](https://github.com/docker/buildx/actions/runs/39503414114/attempts/1). This verifies signer/subject/source assertions, not independent reproducibility or an audited builder.

The pinned Docker index contains digest-bound **unsigned** BuildKit provenance for both target platform manifests. It names [docker-library/docker at `a44773e1e79648f9fd7ebb7cb5cc00387dc05de0`, `29/cli/Dockerfile`](https://raw.githubusercontent.com/docker-library/docker/a44773e1e79648f9fd7ebb7cb5cc00387dc05de0/29/cli/Dockerfile). That recipe's plugin hashes match the signed release subjects. Its CLI download is `https://download.docker.com/linux/static/stable/{x86_64,aarch64}/docker-29.9.2.tgz`, without a literal checksum/signature check in that supplier recipe. Those archives were not downloaded here.

Native supplier `/usr/local/bin/docker` SHA-256 is `e330afc12592c0683664b00066d50fb9f3a879ab8820df589d50b9b1fe3a3c6a`, matching historical arm64 evidence. **No authenticated CLI binary-to-source build attestation was established.** A signed source tag, version and this payload hash do not fill that gap.

### Still missing

- At the collection snapshot, the repository Docker recipe copied no explicit CLI/plugin notices; current recipes now add only the retrieved top-level files. Complete Go dependency/compiler/native-component notices and applicable NOTICE propagation have not been assembled or reviewed.
- Retrieved arm64 supplier SPDX documents contain **110 Compose / 212 Buildx package records**, all with concluded licenses `NOASSERTION`, and **zero extracted license-text records**. These inventories are not notice bundles. The historical CLI inventory itself is incomplete/UNKNOWN; plugin coverage cannot repair it.
- Actual amd64 supplier payload bytes were not exported; their equality with signed plugin releases remains to be checked. No bit-for-bit source rebuild was attempted on either architecture.

## Gitleaks 8.30.1 and Git/native runtime

### Gitleaks

Pinned image configs label source revision `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`. Its [MIT LICENSE](https://raw.githubusercontent.com/gitleaks/gitleaks/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/LICENSE) hashes to the recipe pin `e3884b252b3bfc045e55be43a34d1e80da070bc6f804ac95bf4660e97d62ebc6`. Native supplier `/usr/bin/gitleaks` is `db4d43dd4ab54f047a2d18d210a8d2294e2e5cc26d1e26a299a9675916f5647d`, matching the historical final payload.

Both platform manifests have content-addressed BuildKit provenance. Its source is a local build context, builder ID is empty, and resolved dependencies identify Alpine/Go images, not an authenticated source commit. **This is not a verified signed Gitleaks source-to-binary attestation.** Embedded Go dependency/compiler notices remain incomplete.

### Exact package source claims, not inferred from version names

Native Git supplier APK records and per-package SPDX documents identify **`chainguard-dev/stereo`**, not `wolfi-dev/os`, as their build-recipe repository:

| Payload/package | Supplier recipe commit / file | Supplier-reported upstream source |
|---|---|---|
| Git `2.56.0-r3`; historical executable version `2.56.0.1.g02cd7dbd28` | `a3655395a06e663e8406d260a966b9e022e11f7e` / `git.yaml` | Git `a018953688f1b10bddf91bff8747068f5f4746a4`, upstream `v2.56.0` |
| glibc + loader `2.44-r9` | `29df9b08616c849ddc2af8dadea153f51259ac3b` / `glibc-2.44.yaml` | `https://gitlab.com/gnutools/glibc.git`, `045c51476c7abf6144815a4db44f51a118b4cb3e` |
| PCRE2 `libpcre2-8-0` `10.49-r1` | `22949b2f2440b25b7c18a18e3b62ff13f57bffd4` / `pcre2.yaml` | `PCRE2Project/pcre2` `6f9d7c1373262c541324a16a358785b33ef116cf` |
| zlib `1.3.2.1_rc20260921-r0` | `75278be0abfe311aedfbf7c3933f6f0b819980e6` / `zlib.yaml` | `madler/zlib` `767c4c947852e143f582c85f14cf573411df1b35` |

Exact recipe URLs are `https://raw.githubusercontent.com/chainguard-dev/stereo/<commit>/<file>`; all four anonymous retrieval attempts were unavailable. This does not authorize private access. The source claims/recipe identities are retained with hashes of the exported package SBOMs.

Cosign verified SLSA-v1 attestations for **both exact Git/glibc index pins**, with identity `https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main` and issuer `https://token.actions.githubusercontent.com`. Subject checks and normal transparency/SCT checks remained enabled. These predicates describe apko image assembly and package versions; **they do not supply reproducible package build attestations, exact recipe contents or a complete source/patch bundle**. The index SPDX statements describe platform variants, not complete dependency notices.

### Source and notices actually retrieved

- Supplier package SBOMs provide these public source URLs, retrieved with measured SHA-256s:
  - [Git supplier source](https://tarballs.cgr.dev/p/13d95d86c3cf193d4f0417e059a08cc793fc772f803086b07d168643a0b50f40-a018953688f1b10bddf91bff8747068f5f4746a4.tar.gz): `e0c14f098cf77326dff6bcfe75537f9f84722a4096e0413de8aaea237887bc7e`.
  - [glibc supplier source](https://tarballs.cgr.dev/g/9390037ac2ec26cf74ce7c6709d852e0ce67205355e04fbdb9b9549f47a5bb40-045c51476c7abf6144815a4db44f51a118b4cb3e.tar.gz): `9caf220e935fca38a6dd41f65e4fea8559cc94e5296ec76af64054e07252bd1e`.
  - [PCRE2 source](https://github.com/PCRE2Project/pcre2/archive/6f9d7c1373262c541324a16a358785b33ef116cf.tar.gz): `d2be545b3f16571d37a81795d0e528007e882b9d95335d6e9344a1574a9ef431`.
  - [zlib source](https://github.com/madler/zlib/archive/767c4c947852e143f582c85f14cf573411df1b35.tar.gz): `cafa75b907cd067b471fba32a2772c010a859086241ef70d3d57eda6aeea3a64`.
- A separate [GitHub Git source archive](https://github.com/git/git/archive/a018953688f1b10bddf91bff8747068f5f4746a4.tar.gz) is `898ecd505bcec4390b3b7b2c1882509af3f11f3b62c56147d19f01e2a4e81355`. Comparing regular-file contents after removing archive root prefixes found only three differing `compat/vcbuild/*.bat` files, no added files; all other regular files, including `http.c`, match the supplier archive. No symlink/mode equivalence or patch application is implied.
- Both Git archives contain `COPYING` matching the existing recipe pin `5b2198d1645f767585e8a88ac0499b04472164c0d2da22e75ecf97ef443ab32e`, plus `reftable/LICENSE`, `sha1dc/LICENSE.txt` and other component/test licenses. This confirms available notice text, **not completeness of the shipped Git builtin's notices**. The existing recipe copies only upstream COPYING.
- glibc source contains `COPYING.LESSERv2`, `COPYINGv2`, `COPYINGv3`, `LICENSES` and further notices. `LICENSES` SHA-256 is `b22a69aa3f80a5201818c66cb0df0f25f9fa13cf5861b0093a058dbd12d50dce`; its opening text explicitly calls for distribution with binary-derived documentation. An LGPL package label alone omits these additional notices. A complete source/patch/relinking arrangement and base-package review remain outstanding.
- PCRE2 [LICENCE.md](https://raw.githubusercontent.com/PCRE2Project/pcre2/6f9d7c1373262c541324a16a358785b33ef116cf/LICENCE.md) declares `BSD-3-Clause WITH PCRE2-exception`, separately discusses JIT terms, and references SLJIT's separate license. Retrieved [SLJIT LICENSE](https://raw.githubusercontent.com/zherczeg/sljit/de0259c7aaf36aa40cba8014f3fad3edde9307f9/LICENSE) at the actual PCRE2 gitlink commit. The PCRE2 source archive does not include submodule contents; JIT inclusion/complete source and notice applicability require review. Do not reduce this to the APK's `BSD-3-Clause` label.
- zlib [LICENSE](https://raw.githubusercontent.com/madler/zlib/767c4c947852e143f582c85f14cf573411df1b35/LICENSE) contains the Gailly/Adler zlib notice (`e32ff4e00d9d94930537635291da39e7e612703334bf6fde8c7f1686fe8a45a2`). Supplier metadata instead declares `MPL-2.0 AND MIT`. **This discrepancy is unresolved**; neither label is silently substituted for a file-level review.

### Public recipe/patch candidates — deliberately not supplier equivalents

Public Wolfi recipes were captured at tree `9be4d78acb4341573db86b483142a0ff0fbb95be`, using `https://raw.githubusercontent.com/wolfi-dev/os/9be4d78acb4341573db86b483142a0ff0fbb95be/<file>`.

- `git.yaml` is version `2.56.0-r3`, names base commit `a018953688f1b10bddf91bff8747068f5f4746a4`, and cherry-picks `76524c2604bceee48481909e7824494498c39a34` (curl effective-URL credentials handling). The [exact upstream patch](https://github.com/git/git/commit/76524c2604bceee48481909e7824494498c39a34.patch) was retrieved: `3b33720630833a3ffdfafde6d285fc17190a800e978ef13a9e0269d70ee7e90c`. **No proof connects that public recipe/patch to vendor commit suffix `02cd7dbd28`.** The direct upstream commit lookup for that suffix was unavailable.
- `glibc-2.44.yaml` is **r10**, not packaged r9. It names the same upstream source commit and references `glibc-2.44/0001-Link-startup-files-without-package-metadata.patch`, `fdo.patch`, `fix-allowed-failures-escaping.patch`; these three public files were retrieved and hashed. Their applicability/completeness for stereo r9 is unverified.
- `pcre2.yaml` is r1 with the same reported upstream commit; public zlib is **r1**, not packaged r0. Neither is authenticated as the exact stereo recipe.

**Git corresponding source is therefore still incomplete for redistribution review:** the exact patched source/build recipe, full applied patch set, generated vendor version, build inputs/options/toolchain and appropriate source-delivery arrangement have not been established or reproduced. A base tarball plus an apparently relevant public patch is not approval.

Native arm64 payload hashes for Git, libc, loader and resolved PCRE2/zlib targets are in the JSON and match historical captures. The glibc base also contains locale/libgcc/libstdc++/CA/baselayout payloads; those license/source obligations are not waived by inspecting only Git's ELF imports. No complete transitive notice bundle was found/assembled. Stopped exports contained no selected paths named `license`/`LICENSE`/`NOTICE`/`COPYING`; this filename search is not an exhaustive legal-content assessment.

## cargo-audit 0.22.1: official amd64 vs Quickinstall arm64

### Retrieved identities and archive contents

| Supplier / artifact URL | Verified archive SHA-256 | Actual archive contents |
|---|---|---|
| [RustSec x86_64 musl](https://github.com/rustsec/rustsec/releases/download/cargo-audit/v0.22.1/cargo-audit-x86_64-unknown-linux-musl-v0.22.1.tgz) | `c32506f338bdcdaef5a17fb9f33abb6ecf9561324cfd34237fd335f9283a1eab` | binary, LICENSE-APACHE, LICENSE-MIT, README, CHANGELOG |
| [Quickinstall aarch64 musl](https://github.com/cargo-bins/cargo-quickinstall/releases/download/cargo-audit-0.22.1/cargo-audit-0.22.1-aarch64-unknown-linux-musl.tar.gz) | `b33ed5d95ac0ccda2e281a885a117a03fa92084c3e83f468fb82c2272fb26b60` | **only `cargo-audit`**, no license/NOTICE/source files |

At the collection snapshot, both hashes matched the literal Dockerfile pins and corresponding GitHub release asset digests; those pins are now superseded by official GNU archives. Extracted binary hashes: official amd64 `d7a4f8034d548b36bc12ed6f1f341e2917436748a56faaa3d6a0e2cb0549696e`; Quickinstall arm64 `c6df2b6b85f2596026ccf3fbec9b28855aee617c3dfc638b44b03f2a62a74193`. Neither binary was executed by this collection.

The official release API offers aarch64 **GNU**, SHA-256 `4c8df835ee484441bd2c8c6bcac28c4ce4b4058ba9e7477cb9e0012fe7769f66`, and no aarch64-musl asset in the captured release. That GNU archive was not downloaded or proposed as an automatic replacement.

### Source/license evidence

RustSec tag object `c9f8506963a0050a7b53ce4d3781baa9485c7a89` peels to `efcde93a237dc51f8c32d84d880bf97b442835c8`; GitHub reports its SSH signature verified. Retrieved [source archive](https://github.com/rustsec/rustsec/archive/efcde93a237dc51f8c32d84d880bf97b442835c8.tar.gz), SHA-256 `5aa2af67748de29e70079efe93d8785216727e50086b9896970177ce0079ebfb`, workspace `Cargo.lock` and release workflow.

At that commit, `cargo-audit/LICENSE-APACHE` / `cargo-audit/LICENSE-MIT` are byte-identical to official archive notices: respectively `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2` / `29662666b44dff84977b46e05642cdef910bc3a93a17b5fd86e632bafa59cf21`. The repository image copies these official notices for both architectures. This is top-level notice coverage, **not proof that Quickinstall used those sources or that dependency notices are complete**.

The official workflow uses a floating stable toolchain, `--locked`, and cross builds for musl; its source workflow is not a signed attestation of the fetched archive. Anonymous GitHub attestation queries for both exact archive digests were unavailable. This establishes neither global absence of attestations nor authenticated release build provenance.

### Quickinstall signature verified, equivalence not established

Retrieved archive [`.sig`](https://github.com/cargo-bins/cargo-quickinstall/releases/download/cargo-audit-0.22.1/cargo-audit-0.22.1-aarch64-unknown-linux-musl.tar.gz.sig). The release tag resolves to Quickinstall commit `ca927393f74234dabd791557ab79c8dc52973a53`. Retrieved its [minisign public key](https://raw.githubusercontent.com/cargo-bins/cargo-quickinstall/ca927393f74234dabd791557ab79c8dc52973a53/minisign.pub), build script and workflow. Key-file SHA-256: `e46888d4cdb645fe475f9fc213a4575f16ba590aed56668bcf6b3d3ec216af0e`; bytes also match independently captured current tree `dfe265d82b120ce16dca1ec64a874cdd3c43c655`.

Using OpenSSL **4.0.3**, the Rust helper verified minisign `ED` key-ID equality, Ed25519 signature over the archive's BLAKE2b-512 digest, and the separate signature over signature-bytes plus trusted-comment text. Both succeeded; a mutated-digest control failed. **This authenticates possession of the key corresponding to the retrieved public key, not independent trust in that key, RustSec authorship or a reproducible build.**

The captured release-tag script uses registry `cargo install`, target/features inputs, fat LTO/codegen settings, and **falls back from `--locked` to an unlocked install**. Its workflow uses stable Rust and accepts a separate checkout-branch input. A release tag naming the script is not proof of the actual checkout, dependency resolution, crate checksum, features, Rust/std/musl/native-library versions, build run or toolchain used for this exact artifact.

**Missing:** authenticated source/dependency/toolchain/run binding for both suppliers; complete Rust and static native-component inventories/notices; Quickinstall-specific attribution/source review; independent signer accountability; source reproducibility. Matching version `0.22.1`, a valid signature and borrowed official notices do not establish supplier equivalence. Existing missing Rust binary inventories remain blocking.

## Executed validation and remaining acceptance criteria

Private helper checks only (no existing repository source/tests changed or used as new acceptance):

```text
cargo fmt --manifest-path .work/approval-suppliers/helper/Cargo.toml --all -- --check
cargo clippy --offline --locked --manifest-path .work/approval-suppliers/helper/Cargo.toml --all-targets -- -D warnings
cargo test --offline --locked --manifest-path .work/approval-suppliers/helper/Cargo.toml
```

Final results: formatting and all-target Clippy pass; **12 tests pass** (11 evidence assertions plus SHA-256 known vector). Assertions cover capture hashes/caps, registry identities, platform membership, native plugin/signed-subject/release bindings, signed/plain provenance equality, crypto success/negative records, literal pins, official license bytes, Quickinstall's notice gap, unasserted licenses, stereo/public-recipe distinction and historical report hashes. Initial helper compile/Clippy and test-working-directory mistakes were corrected locally; they are not supplier failures. Live verification additionally produced six positive Cosign cases, two rejected Cosign controls, two positive minisign-signature checks and one rejected altered digest. Eight owned stopped containers across the two native passes were removed successfully.

Before any redistribution/provenance approval, an accountable reviewer still needs:

1. Complete artifact/architecture-specific embedded and base-runtime component inventories and actual license/NOTICE texts, including Go/Rust/std/musl/native components; resolve PCRE2/zlib metadata discrepancies, not substitute labels.
2. Exact stereo recipes, complete Git/glibc applied patches/build inputs and appropriate complete corresponding-source/relinking/source-delivery arrangements. Public Wolfi candidates do not satisfy this.
3. Authenticated exact CLI/Gitleaks/cargo-audit build provenance, plus Quickinstall key/supplier accountability and actual resolution/toolchain evidence or a separately reviewed supplier replacement. No source rebuild reproducibility was established here.
4. Native amd64 payload/runtime checks, fresh unchanged inventories and all existing functional, diagnostic, vulnerability and resource gates. Evidence collection is not a severity waiver or release acceptance.

No readiness flag or blocker was changed; there is no license sign-off, registry publication or adoption approval.
