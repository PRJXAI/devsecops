# Gitleaks dependency-upgrade experiment — 2026-10-28

**Policy supersession later on 2026-10-28:** the owner authorized release with reviewed risks when no fix or viable alternative exists. The [implemented policy](release-risk-policy.md) now accepts this exact OpenPGP/module case without removing it and permits the exact pinned precision warning. The original experimental measurements and then-blocking decisions below remain historical evidence. That policy decision alone did not adopt the candidate or approve redistribution/provenance. The later gap-remediation work now adopts its fixed build/profile into production and passes local arm64 preparation with the finding retained; see [current results](results.md). Statements below about experimental-only packaging describe the original experiment.

## Measured result

The owner authorized upgrading the six dependency candidates after the [compiler-only experiment](gitleaks-compiler-experiment.md). A second local **linux/arm64** Gitleaks 8.30.1-based build retains **Go 1.27.3** and the official container's default-regex/CGO-disabled executable settings. It measures **26 → 1 match** against the compiler-only candidate. This is an experimental derivative, **not an adopted/published upstream release, clean scan or native amd64 acceptance**.

| Match records | Compiler-only baseline | Dependency candidate |
|---|---:|---:|
| Critical | 7 | **0** |
| High | 9 | **0** |
| Medium | 8 | **0** |
| Low | 1 | **0** |
| Unknown | 1 | **1** |
| Negligible / ignored matches | 0 / 0 | 0 / 0 |
| **Total** | **26** | **1** |

Both retained, unchanged native inventories were scanned offline with pinned Grype 0.121.0 and the same existing freshness-validated DB, built `2026-10-27T06:30:41Z`. The baseline is the compiler experiment's captured inventory, not a new baseline build. Pinned Syft 1.55.0 freshly cataloged the saved dependency candidate without a Docker socket. All severities and ignored matches remain included. Both scans still **reject nonempty analysis stderr**; private reports were independently validated/counted after that rejection, not accepted through an exception. The two measured experiments form **69 → 26 → 1** for these candidates/database, not a current whole-repository or both-architecture finding count.

## Exact dependency changes

| Embedded dependency | Before | After |
|---|---|---|
| `golang.org/x/crypto` | 0.35.0 | 0.58.0 |
| `golang.org/x/text` | 0.22.0 | 0.43.0 |
| `golang.org/x/sys` | 0.30.0 | 0.49.0 |
| `github.com/klauspost/compress` | 1.17.11 | 1.20.3 |
| `github.com/nwaples/rardecode/v2` | 2.1.0 | 2.4.5 |
| `github.com/ulikunitz/xz` | 0.5.12 | 0.5.17 |
| `golang.org/x/sync` (also selected by resolution) | 0.11.0 | 0.24.0 |

The module's Go minimum changes **1.24.11 → 1.26.0**. That metadata/default-behavior change is part of this experiment, not a claim of byte-equivalent runtime behavior. Both native catalogs contain the same **62 non-main/non-stdlib Go dependency names**: exactly the seven version changes above, no additions/removals. All six explicit targets are independently checked in the Go-produced module JSON and the unchanged native candidate inventory. No `replace`, `exclude`, renamed module or report rewriting was used.

[The explicit manifest patch](../patches/gitleaks-8.30.1-dependencies.patch.txt) changes only upstream `go.mod`/`go.sum`, against source commit `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`. Bounded Rust-controlled `git apply --check` and application to synthetic original manifests pass; the resulting files are byte-identical to the tested manifests. It is reviewable patch data, **not wired into production packaging**.

- Patch SHA-256: `25ffa10aef86ce506a4f66f8a294014de23031b96b27fa757be7b584f13af051`.
- Resulting `go.mod`: `ba06359b7031ccdda2687fc4553291ffa7f1075b062f38a0bce4e51f7ff4d3c0`.
- Resulting `go.sum`: `9f27b112986f235ee2b771bfa5c38e3dbf7521eac1e5722b42f5b528214b3b5c`.

## Build and test evidence

Public resolution explicitly requested those six versions using the same digest-pinned Go 1.27.3 builder and SHA-256-pinned source archive recorded in the compiler experiment. `GOTOOLCHAIN=local` forbids automatic compiler substitution. Retrieval/resolution exported only bounded, type-checked manifests; those reviewed bytes were then copied into the separate candidate build, hash-checked before/after compilation, downloaded/verified through Go's checksum database and used with `-mod=readonly`. Tests, compilation and scans were offline after retrieval. No full advisory DB copy/refresh was needed.

The complete upstream-style **`go test -race ./...`** suite passes with the updated dependencies. Race tests use CGO instrumentation; the packaged executable separately uses CGO disabled. The prior overlay-fixture rename correction remains an isolated locked writable testdata cache, with original upstream test assertions/code intact. Native version/Git smokes, final filesystem/ELF/CA/runtime closure and Gitleaks source/deleted bare/all-ref/clean-HEAD/redaction contracts pass without changed deadlines, retries or live secret validation. This is not proof of every consumer/archive behavior or resolution of the historical Docker completion issue.

The private Rust helper passes two new negative module-policy tests and an explicitly executed native-pair replay. They reject wrong/missing targets, replacements/exclusions, duplicate/malformed requirements; the replay verifies actual archive/config binding, both report/SBOM hashes, DB identity/freshness, all match/severity counts and exactly the seven observed dependency changes. Formatting and strict all-target Clippy pass. Initial validation rejected the new `.patch` extension under the existing file policy and caught unformatted private harness launchers. The patch is retained byte-identically as non-executable `.patch.txt` data, and the private launchers were formatted; no policy was relaxed. Production checks are recorded in [results](results.md). Raw logs and reports remain private under ignored `.work/gitleaks-dependency-upgrade/`; no new production command or generic supplier framework was added. Same-UID/daemon trust and missing hard host-storage quotas remain as documented.

## Remaining record: OpenPGP package vs module matching

The single Unknown-severity `x/crypto` record was cross-checked privately against the previously retrieved public [Go advisory GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), which concerns the **unmaintained OpenPGP package**, with no fixed-version event. It is not a new Critical/High result or a leaked secret.

An offline **`go list -deps .`** on the updated source graph with the actual default-regex/CGO-disabled settings observes these x/crypto package imports: `blowfish`, `bcrypt`, `pbkdf2`, `scrypt`. It observes **no OpenPGP import**. This is source import evidence, not binary reachability/absence attestation or a finding waiver. The module remains necessary for other packages and is still matched at module granularity. Updating it cannot make this advisory disappear under the existing all-match policy. No symbol filtering, advisory suppression or renamed-module workaround was added.

Both this record **and analysis diagnostics still block** under the unchanged release policy. Owner risk acceptance is recorded below; no finding/gate exception or upstream dependency redesign has been implemented. Complete native amd64 tests, captured-profile review, notices/source/provenance approval and every other release prerequisite remain outstanding. No production Dockerfile, inventory profile, readiness approval or consumer pin changed, and no clean receipt or registry publication occurred. Syft/Grype were not modified or rebuilt here.

## Owner risk acceptance — 2026-10-28

Recorded at `2026-10-28T11:11:58Z`: the owner explicitly stated in this session that they accept the risk of the remaining x/crypto/OpenPGP issue. This records that decision for the **specific local arm64 dependency candidate identified below**, with x/crypto 0.58.0 and one Unknown-severity match. It is not a rolling waiver for other artifacts/findings; no expiry was supplied.

The match remains reported and unresolved. This decision does not establish binary exploitability/absence, native amd64 success, scanner-diagnostic acceptance, redistribution/source/provenance review or other missing release evidence. The repository's mandatory zero-findings/readiness rules remain unchanged: recording risk acceptance neither labels the image clean nor authorizes bypassing those rules. No publication was attempted.

## Local candidate identities

- Engine/index ID: `sha256:52cad3a2cf92f934647b451271282c2046a026fa72b633082b1c423e05752bb2`.
- Saved native config: `sha256:8af4ca71dde2ef6c5d0254a04ead722208b071ee44c115dde64758f2a6bb338a`.
- Native Syft JSON SHA-256: `e30a9ce14a008276c5ff381df9c28af4786c37b6f0a3f21f14b0df3614d2085a`.
- Grype JSON SHA-256: `5102e0e7cb6969b7d35d1ec883829195d74a3a6549b887143abe9023a27747c5`.

Private statuses/counts/identities: `resolution.json`, `inventory-diff.json`, `functional.json`, `comparison.json`, `residual.json`, `patch-proof.json`. The explicit private `context/Dockerfile` records the tested recipe; it is not a production image definition.
