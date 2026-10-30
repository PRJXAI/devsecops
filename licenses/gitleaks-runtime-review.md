# Gitleaks runtime source review — 2026-10-29

**Evidence advanced; redistribution is not approved.** [Artifact identities](gitleaks-runtime-evidence.json) bind 20 selected package/architecture payloads to the two unchanged production archives from hosted run 40712836198, source `818c36229a839653a6952d8079e5952ae51650bc`. This supersedes the earlier inability to retrieve exact expanded recipes in [supplier evidence](supplier-evidence.md), not its remaining source/notices/provenance requirements.

## What is now established

Public APKs are available at `https://apk.cgr.dev/chainguard/{x86_64,aarch64}/...` and the Wolfi mirror. Earlier requests to `packages.cgr.dev` and private recipe GitHub URLs did not locate these bytes. Each captured APK includes `.PKGINFO` and its expanded `.melange.yaml`, including resolved build-package versions, source pins, build options and nested pipeline commands. These were read as data, never executed.

For **each architecture**, a selected payload from every package below is byte-identical to the corresponding file in the original hash-verified hosted image archive:

| Package | Version | Selected shipped material |
|---|---|---|
| git | 2.56.0-r3 | Git executable |
| glibc-2.44 | 2.44-r9 | libc |
| ld-linux-2.44 | 2.44-r9 | architecture-specific loader |
| glibc-2.44-locale-posix | 2.44-r9 | C.utf8 LC_CTYPE |
| libpcre2-8-0 | 10.49-r1 | PCRE2 shared library |
| zlib | 1.3.2.1_rc20260921-r0 | motley shared library |
| libgcc | 16.2.0-r1 | libgcc_s |
| libstdc++ | 16.2.0-r1 | libstdc++ |
| ca-certificates-bundle | 20261020-r0 | CA bundle |
| wolfi-baselayout | 20230201-r30 | os-release |

The index records original APK URL/hash/size, package/recipe identity, recipe and PKGINFO hashes, selected source/shipped paths, payload hash/size, and both original image-archive hashes. This is selected-file binding, **not proof that every packaged file, notice or static component is covered**. HTTPS and the previously authenticated image producer are trust inputs; no new package-signature verification or independent source rebuild is claimed.

Git's attached recipe confirms base `a018953688f1b10bddf91bff8747068f5f4746a4` and cherry-pick `76524c2604bceee48481909e7824494498c39a34`, with the actual build configuration and toolchain package versions. Those are no longer merely a similar public Wolfi recipe. The vendor-generated commit/version has not been independently reconstructed, nor has the binary been reproduced from source.

The glibc recipe identifies source `045c51476c7abf6144815a4db44f51a118b4cb3e` and exactly these overlay patch names:

- `0001-Link-startup-files-without-package-metadata.patch`
- `fdo.patch`
- `fix-allowed-failures-escaping.patch`

The recipe names the files but does **not** contain their bytes or hashes. Similar public Wolfi patch files are not automatically authenticated as the exact stereo inputs. Exact-commit Wolfi URLs and probed Git/glibc `-source` APK URLs were unavailable in this environment; that does not prove global absence. The captured control sections do not contain the newer melange `.source.sha256` companion-source manifest. Current melange source-package support does not retroactively establish source completeness for these older APKs.

PCRE2's actual recipe enables JIT, so its SLJIT notice/source applicability cannot be dismissed. Zlib's attached metadata still declares `MPL-2.0 AND MIT`; the previously retrieved main source license differs. That discrepancy needs file-level review, not an automatic label substitution. The base's GCC runtimes, locales, CA bundle and baselayout remain in scope too.

## Remaining supplier/reviewer request

Before approval, obtain and review:

1. The exact complete source overlays/patch bytes for the recorded recipe commits, particularly glibc `29df9b08616c849ddc2af8dadea153f51259ac3b`, with a supplier-authenticated binding to the captured package builds. Include Git's generated version/build identity and the GCC/runtime source obligations, not just upstream release tarballs.
2. Complete artifact-specific license/NOTICE text and any required source/relinking materials for Git, glibc, PCRE2/JIT, zlib and all retained base packages. Existing Go notices are already packaged; this collection does not add native notices to the image.
3. A concrete corresponding-source delivery arrangement for recipients and an accountable redistribution/provenance review of that bundle. Merely pointing at a plausible public patch or selecting the publication checkbox does not supply missing evidence.

At this source-capture step, no vendor contact, private repository access, credential use, image supplier substitution, source-build fork or publication was performed. A subsequently authorized [Debian replacement evaluation](../docs/results.md) obtains authenticated public source material and tests a separate arm64 prototype, but retains 26 blocking findings and incomplete approvals. It is not adopted and does not authenticate the old vendor's missing overlays; approval must follow complete evidence, not precede it.

## Reproduction and limits

Private captures are under `.work/approval-suppliers/gitleaks-runtime-v3/`; public APK responses and their HTTPS receipts remain under `.work/approval-suppliers/http/`. The Rust collector reads bounded concatenated gzip/tar APK members and ordered saved-image layers without extracting or executing paths. A first collector attempt refused special image filesystem entries; the corrected read-only version records their types rather than treating them as regular files. Failed work remains separate. No archive, scanner report or historical profile was rewritten.

The ordinary `runtime_source_evidence_is_two_architecture_observation_not_approval` test checks the exact two-architecture/package coverage and false approval/completeness claims. The opt-in `release::tests::recorded_runtime_recipes_and_original_artifacts_keep_their_hashes` rehashes all original APKs, expanded recipes, PKGINFO and both image archives, and checks retained selected-file identities. It does not independently rebuild packages or turn metadata into legal approval. The real initial payload comparison was performed by the private Rust collector; the replay is an integrity check on those observations.

The [loader-only diagnostic](../docs/results.md) independently reproduces the completion failure without Gitleaks/Git execution. Publication and consumer adoption remain blocked; no readiness approval changes follow from this review.
