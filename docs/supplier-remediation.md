# Supplier vulnerability remediation — step 3

## Decision and evidence boundary

**Blocked: no complete released-binary remediation identified as of 2026-10-27 UTC.** The latest public upstream releases are still Syft **1.55.0**, Grype **0.121.0** and Gitleaks **8.30.1**, already packaged here. Both `/releases/latest` and the five most recent release records were checked. No image, configuration, contract, readiness flag or consumer pin was changed by this investigation.

This is a remediation proposal, not a rescan or a fixed-status assertion. Only the explicitly approved public candidate captures, their Syft inventories, verified-count summary and update-PR snapshot were inspected. They establish native **linux/arm64** observations only. Other tools, native amd64, new binaries, redistribution/provenance acceptance and publication are not established. See [release sequence](release-readiness.md), [results](results.md) and [trust boundary](threat-model.md).

Bounded Rust helpers and private responses are under ignored `.work/approval-updates/`. Inputs were the approved `30/60/105-stdout.log` captures, `.work/tasks-native-verified-counts.json`, `.work/scans/{syft,grype,gitleaks}/input.syft.json` and `.work/approval-update-prs.json`. Network work retrieved only public release/tag/commit/module/advisory/source metadata, with cleared credential/configuration environment, HTTPS, finite deadlines and 4 MiB response limits. No binaries, images, full advisory database or new scans were downloaded/run; no operator files, credentials or consumer repository were read.

## Captured component totals

Counts are match records, **not distinct vulnerabilities**; aliases and the same component across images are not deduplicated. All severities remain included. The Rust summary agrees with the approved 15/20/69 baseline; ignored matches are zero.

| Captured payload | Compiler embedded in inventory | Standard-library matches | Other component matches | Total |
|---|---|---:|---:|---:|
| Syft 1.55.0 | Go 1.26.8 | 14 | x/crypto: 1 | 15 |
| Grype 0.121.0 | Go 1.26.8 | 14 | legacy Docker module: 5; x/crypto: 1 | 20 |
| Gitleaks 8.30.1 | Go 1.24.13 | 43 | x/crypto: 20; x/text: 2; compress, rardecode/v2, xz, x/sys: 1 each | 69 |

There are **104 match records**, including **71 in embedded Go standard libraries**. No native Git/glibc/PCRE2/zlib component appears among these captured matches; that is not a fresh clean bill for the Git closure. Nonempty analysis diagnostics remain an independent blocker even if all component findings were removed.

**Updating distroless does not replace a statically embedded Go compiler runtime or module.** The 16 approved PR records contain eight static-base updates, three extraction-stage Alpine updates and five Actions updates—not new Syft/Grype/Gitleaks payload releases. Review them separately; neither a base refresh nor automatic merging constitutes this remediation. Extraction-stage changes do not alter the copied released Go executable.

## Released identities and unreleased source

The release tags were resolved to full source commits, including dereferencing the annotated Syft/Grype tags. These are public identities, not verified build provenance. Release metadata lists Linux amd64/arm64 archives for all three tools; archive bytes/signatures were not fetched or verified. The currently packaged image digests remain those in the Dockerfiles; no mutable `latest` tag was substituted.

| Tool | Latest release/source commit | Inspected development commit | Release with all captured fixes? |
|---|---|---|---|
| Syft | [1.55.0 / f15c3343e29dfb20cf6d82c820e7090b49808c96](https://github.com/anchore/syft/tree/f15c3343e29dfb20cf6d82c820e7090b49808c96) | [fb56f1eef1908ad249a59ea7b2fe913bae16304f](https://github.com/anchore/syft/tree/fb56f1eef1908ad249a59ea7b2fe913bae16304f) | None identified |
| Grype | [0.121.0 / afe2742527d98d822da06c9f32eed86fe3d193e0](https://github.com/anchore/grype/tree/afe2742527d98d822da06c9f32eed86fe3d193e0) | [1c10431d08fdb6304b7fcbcc4dccb52fc69ad65f](https://github.com/anchore/grype/tree/1c10431d08fdb6304b7fcbcc4dccb52fc69ad65f) | None identified |
| Gitleaks | [8.30.1 / 83d9cd684c87d95d656c1458ef04895a7f1cbd8e](https://github.com/gitleaks/gitleaks/tree/83d9cd684c87d95d656c1458ef04895a7f1cbd8e) | [5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c](https://github.com/gitleaks/gitleaks/tree/5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c) | None identified |

Development source is **not** a released candidate binary:

- Syft and Grype still declare `go 1.26.8` and x/crypto **0.58.0**. Their development compress **1.20.3** update does not address these captured standard-library/x/crypto matches. Grype still requires `github.com/docker/docker` **28.5.2+incompatible**.
- Gitleaks development declares `go 1.24.11` (a source minimum, not proof of its build compiler), compress **1.18.0**, rardecode/v2 **2.2.0**, xz **0.5.15**, x/crypto **0.35.0**, x/sys **0.30.0**, x/text **0.29.0**. Only rardecode/xz meet their captured fix targets; checking out this commit alone is insufficient.
- Supplier release/build configurations were inspected as source only. Preserve actual build settings, including Gitleaks regex implementation/build tags. Neither a `go` directive nor workflow configuration overrides the observed compiler in an existing binary.

## Concrete patch candidates, without tool-major replacement

The targets below are **component candidates for an upstream maintenance release or a separately authorized, narrowly scoped tool-specific change**, not install instructions or permission to rebuild suppliers here. They preserve the existing tool major lines. A version comparison addresses only the captured records with supplied fix versions; it cannot establish a clean new image.

| Component | Captured version | Captured fixed-version requirement | Public released candidate and immutable source |
|---|---|---|---|
| Go standard library | 1.26.8; Gitleaks 1.24.13 | The captured stable 1.26 fix targets extend through **1.26.10** | Prefer [Go 1.26.10 / 4e8c85f5319d999bfd7617fdc191631e5634e3c5](https://github.com/golang/go/tree/4e8c85f5319d999bfd7617fdc191631e5634e3c5), listed stable by the public Go release service. Go 1.27.3 also exists, but that larger move is unnecessary for these targets. |
| klauspost/compress | Gitleaks 1.17.11 | **1.18.7** | [1.20.3 / b946d41b75cee10ea255ced85179e5224748a023](https://github.com/klauspost/compress/tree/b946d41b75cee10ea255ced85179e5224748a023); Go minimum 1.25 |
| nwaples/rardecode/v2 | Gitleaks 2.1.0 | **2.2.0** | [2.4.5 / ad22ba91a2ab0d3ff6bca20cd978b33ee78faab1](https://github.com/nwaples/rardecode/tree/ad22ba91a2ab0d3ff6bca20cd978b33ee78faab1); Go minimum 1.21 |
| ulikunitz/xz | Gitleaks 0.5.12 | **0.5.15** | [0.5.17 / 6ead826b4d3c7c9856f2daa905cf06403b9daddc](https://github.com/ulikunitz/xz/tree/6ead826b4d3c7c9856f2daa905cf06403b9daddc); Go minimum 1.20 |
| golang.org/x/sys | Gitleaks 0.30.0 | **0.44.0** | [0.49.0 / b6b8557e8e2974925aec7a136ba0e323eedc5f43](https://github.com/golang/sys/tree/b6b8557e8e2974925aec7a136ba0e323eedc5f43); Go minimum 1.26.0 |
| golang.org/x/text | Gitleaks 0.22.0 | Both captured targets, through **0.41.0** | [0.43.0 / ac40b0f06c159afb5bfca4d1860f8b4b60dbc160](https://github.com/golang/text/tree/ac40b0f06c159afb5bfca4d1860f8b4b60dbc160); Go minimum 1.26.0 |
| golang.org/x/crypto | Gitleaks 0.35.0; Syft/Grype 0.58.0 | Gitleaks versioned targets extend through **0.56.0**; **one additional record per image has no fixed version** | [0.58.0 / 8fdf07b3114278fb3b78c1cf1814e08bd851eb4c](https://github.com/golang/crypto/tree/8fdf07b3114278fb3b78c1cf1814e08bd851eb4c); Go minimum 1.26.0. Addresses versioned targets only, **not all x/crypto records**. |

The module candidates' declared Go minima fit Go 1.26.10; this is a necessary compatibility check, **not** a successful dependency resolution, build or CLI test. The public Go module proxy supplied version/origin-commit metadata and versioned `go.mod` files. Minimum fix versions for compression/sys/text were also resolved independently in private evidence. No new tool release containing this proposed combination was found.

### Fixes that patch bumps cannot supply

**x/crypto: no patched module version exists for the unmaintained OpenPGP package record.** The public Go advisory describes an all-version, unmaintained package and recommends the maintained ProtonMail fork for necessary OpenPGP interoperability. The current **0.58.0** source still contains the old package. Syft/Grype already use 0.58.0, so updating x/crypto again is not a concrete fix. These are three captured match records across the images, not three distinct advisories.

The exact next source review must inventory the actual importing paths and replace/remove the unsafe package **and determine whether the original x/crypto module remains embedded for other packages**. Merely migrating OpenPGP imports, or observing no reachable OpenPGP symbols, does not remove a module-level match under the current gate. If preserved CLI/contracts require retaining this module and no supplier/upstream change removes the blocking condition, zero findings is infeasible under the unchanged policy. Renaming/forking a module solely to evade matching is not remediation; a replacement needs maintained code and dependency/license review. No symbol filter, false-positive declaration or advisory waiver is approved. A same-version vendor rebuild with only a newer compiler would leave this blocker too.

**Grype's legacy Docker module: no patched release on the existing module line was identified.** Public module metadata still resolves `github.com/docker/docker` to **28.5.2+incompatible**, matching the captured payload. Public upstream advisory metadata places fixes on newer Moby lines/module paths, including v2 prereleases; that is not permission to substitute a new major or pretend an old import path is fixed.

The exact next review is a Grype-specific import/dependency migration away from the legacy root module: determine required client/API imports, direct and transitive users, and whether the old module disappears from the final executable. Current Grype already includes split Moby API/client modules **as well as** the legacy module, so adding newer split modules alone is insufficient. Public released split-module candidates are [client 0.6.2 / 21a2258cf01135bdd0f2b06f3e2de538f00dc29f](https://github.com/moby/moby/tree/21a2258cf01135bdd0f2b06f3e2de538f00dc29f) and [API 1.56.1 / 14ebc602124e280ef4ae3e1a8e688dac1255baa6](https://github.com/moby/moby/tree/14ebc602124e280ef4ae3e1a8e688dac1255baa6); neither is asserted to fix these five matches. Obtain an upstream reviewed migration/release and verify actual binary metadata. Do not use a blanket Go `replace`, Moby v2 beta adoption, or assumptions about daemon-only code as a clean-image substitute.

## Smallest next reviewed work

1. **Upstream maintenance-release requests, not a rebuild framework:** Syft needs a patched Go build plus resolution of the unversioned x/crypto blocker; Grype additionally needs the legacy Docker dependency migration; Gitleaks needs the patched compiler and coordinated compression/x/* upgrades plus resolution of its unversioned blocker. Keep the current Syft 1.x, Grype 0.121.x and Gitleaks 8.x CLI expectations unless separately reviewed compatibility evidence supports a change. These are requests, not existing release versions.
2. Prefer those released artifacts once available. If an owner instead authorizes a source patch, review one explicit tool-specific patch/build at a time, with pinned compiler/source/dependencies, provenance and complete notices. A compiler-only rebuild or today's development commits cannot achieve zero with the demonstrated dependency graph. No source build was attempted here.
3. For each actual replacement, review literal Linux amd64/arm64 artifact hashes or supplier digests, source/attestation bindings and redistribution obligations. Re-catalog unchanged native outputs; never fill UNKNOWN versions or edit an SBOM to fit expected tuples.
4. Re-run native contracts on both architectures: Syft JSON/CycloneDX/SPDX and dev/workspace/input coverage; Grype fresh-separated-DB offline detection/error controls and unchanged all-severity/ignored-match accounting; Gitleaks source/deleted/bare/all-ref/clean-HEAD/redaction, archive behavior and Git runtime closure. Retain deadlines, strict diagnostics, read-only isolation and all existing error gates. The existing timeout/coverage/diagnostic blockers remain independent.
5. Only fresh, complete native inventories/scans can establish new counts. Do not subtract the version-addressable records from today's totals and call the result measured. Keep publication blocked until all findings, diagnostics, other runtime/catalog gaps, resource limitations and artifact-specific legal/provenance approvals are resolved. No automatic merge, registry mutation or consumer adoption follows this document.

## Validation and limitations

- Rust bounded-JSON parsing and comparison reproduced all three approved aggregate counts. Public latest-release identities, exact tag/development commits, module release origins, declared compiler requirements and no-patch advisory metadata were retrieved; raw captures/responses remain private.
- Helper: formatting check and all-target offline Clippy with `-D warnings` passed; **5 tests passed** (JSON syntax/byte/depth/structure bounds, synthetic symlink rejection, captured-count consistency). Initial helper compile/path-test failures were corrected before these passing reruns.
- Repository: `cargo clippy --all-targets --locked --offline -- -D warnings` passed; `cargo test --locked --offline` passed (**87 passed, 14 ignored** across suites). `cargo fmt --all -- --check` failed on concurrently edited, unowned Rust files (initially `src/release.rs`, subsequently `src/contracts.rs`); none were reformatted by this investigation. Private validation logs/statuses are retained. These checks concern a concurrent local working tree, not an immutable source snapshot or release acceptance.
- No remediation binary was built/executed, no new vulnerability scan ran, and no architecture gained acceptance. Public metadata is evidence of available versions, not artifact authenticity, runtime compatibility, reproducibility or legal approval. Alternate vendors were not exhaustively searched; no alternate fixed binary is claimed.
