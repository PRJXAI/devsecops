# Gitleaks compiler-only experiment — 2026-10-28

**Later follow-up:** the owner-authorized [dependency-upgrade experiment](gitleaks-dependency-experiment.md) uses this compiler candidate as its baseline and measures 26 → 1 matches, still blocked. The compiler-only evidence below remains unchanged historical evidence, not the dependency-upgraded image.

## Result and scope

The owner authorized trying a newer compiler without adopting/publishing a replacement. A native **linux/arm64** Gitleaks **8.30.1** rebuild with **Go 1.27.3** reduced the measured matches **69 → 26**. All **43 embedded Go standard-library matches disappeared** in this paired scan; the other **26 dependency matches remained**. This is a local experiment, **not a clean image, native amd64 result, hosted release acceptance or consumer change**.

The baseline is the retained, unchanged native inventory of the pinned released container, not a newly rebuilt baseline image. Both its inventory and the newly captured candidate inventory were scanned offline with pinned Grype 0.121.0 and the **same existing freshness-validated database**, built `2026-10-27T06:30:41Z`. Pinned Syft 1.55.0 cataloged the saved candidate image without a Docker socket. Neither report was rewritten; every severity and ignored match remained counted. Both scanner invocations were **rejected for nonempty analysis stderr** before their private reports were independently validated/counted. Inspection is not diagnostic acceptance.

| Match records | Retained baseline | Compiler candidate |
|---|---:|---:|
| Go standard library | 43 | 0 |
| Other dependencies | 26 | 26 |
| **Total** | **69** | **26** |
| Critical | 9 | 7 |
| High | 35 | 9 |
| Medium | 21 | 8 |
| Low | 2 | 1 |
| Unknown | 2 | 1 |
| Negligible / ignored matches | 0 / 0 | 0 / 0 |

These are component/advisory match records, not deduplicated advisories or verified exploitable attacks. Remaining records concern x/crypto (20), x/text (2), compress, rardecode/v2, xz and x/sys (one each). Compiler replacement does not update those dependencies.

## Inputs and build controls

- Gitleaks source commit: `83d9cd684c87d95d656c1458ef04895a7f1cbd8e` (8.30.1).
- Public source archive SHA-256: `6b2638a733b85619dc80bdf28e84e4fed7e526a761ab5c148fbf67695aea2115`.
- Current stable compiler was checked against fresh public Go release metadata. Builder: `golang:1.27.3@sha256:898838c455eecb68ed7b0b6f0635630ebdd657e732f07a23d0ab475007a52c36`.
- Final candidate matches the upstream **container** build: `CGO_ENABLED=0`, no regex build tag, version ldflag `github.com/zricethezav/gitleaks/v8/version.Version=8.30.1`, package `.`. `GOTOOLCHAIN=local` prevents automatic compiler substitution; `-mod=readonly` prevents build-time dependency resolution edits. The same pinned Git/glibc/native runtime closure and nonroot entrypoint as production are retained. Build tools are not copied into the final image.
- Source `go.mod` and `go.sum` hashes were checked before/after compilation, and `go mod verify` passed. Public module retrieval was separated from offline tests/compilation/analysis. Actual native inventories retain the same **62 non-standard-library/non-main Go dependency names/versions**, with no additions, removals or version changes. Main module version remains `v8.30.1`; observed compiler/stdlib changes from `go1.24.13` to `go1.27.3`.
- Rust used a private source snapshot of the existing bounded driver, scanners, archive validation, counters and contracts. Retrieval/captures have finite time/size limits; work and raw output remain private under ignored `.work/compiler-gitleaks/`. Its explicit `context/Dockerfile` is an experimental recipe, not a tracked image or new production CLI/framework. Existing same-UID/daemon trust and missing host-storage-quota limits still apply.

## Executed checks and failed preliminary attempts

- Native candidate build, version/Git smokes and stopped-container filesystem/ELF/closure checks **passed**. The persistent Gitleaks source/deleted bare/all-ref/clean-HEAD/redaction contract **passed** without changing deadlines, adding retries or validating live secrets. This does not erase historical Docker runtime-completion failures.
- The complete upstream-style **`go test -race ./...`** suite **passed** offline with Go 1.27.3. Tests used CGO for race instrumentation; the packaged executable was separately built with CGO disabled.
- Initial upstream tests failed when their Git fixture directory rename encountered overlay lower-layer `EXDEV`. Fixtures were extracted into a dedicated locked writable testdata cache, keeping source/code and assertions unchanged. A separate all-package test attempted with the release-archive `gore2regex` tag failed in config-generator code due to mixed regex types. That failed experiment is retained; it is **not claimed as passing** or established as a compiler regression. Upstream CI's full race suite uses no regex tag.
- The first preliminary binary copied GoReleaser's archive regex flags instead of the official container's flags. Native inventory comparison correctly rejected its three added Wasm/regex dependencies. Its image, recipe, inventory and failures remain under `tagged-preliminary/`; it was not used for the 69 → 26 comparison. The final rebuild uses the official container settings, with exact dependency-inventory equality and fresh functional checks.
- The private helper's two ordinary module-comparison tests and explicit native-pair replay pass: added/changed/duplicate/missing dependencies reject; actual report/SBOM hashes, DB binding, full severity accounting and 43 → 0 stdlib matches are revalidated. Formatting and strict Clippy pass after correcting an initial helper lint. Production repository checks are recorded in [results](results.md).

## Candidate identities and remaining work

- Local engine/index ID: `sha256:41b41a0c37d1056c966349a175745aa8ddfb385d0a9792cacaba4247acd0edd3`.
- Saved native config: `sha256:a6f9311e08a12dee670c99c6fc0f26a480ab48065ba665806a6df341a28cbe1d`.
- Candidate native Syft JSON SHA-256: `d487221d35143a4c387699b0d506bdb93bff6ca312867d03b010a4e4d11e2feb`.
- Candidate Grype JSON SHA-256: `36f360074e817f75e8961cd9cb4e6f57529e903296547d25d19e968a60444423`.

Private comparison/status evidence is `.work/compiler-gitleaks/{plan,build,functional,inventory-diff,comparison}.json`; raw reports are private. The image is local and unpublished. No production Dockerfile, captured coverage profile, scan/diagnostic policy, readiness approval or consumer pin was changed. The new compiler has **not** gained production inventory approval. Complete provenance/notices, both-architecture validation and all existing acceptance prerequisites remain necessary.

The same experiment is plausible for **Syft and Grype**, each with 14 captured Go stdlib matches, but it was **not executed for them**. Their x/crypto findings and Grype's legacy Docker-module findings require dependency work; do not subtract 28 from historical totals and call it measured. Other tools' current inventory/functional failures are not resolved by this result. See [supplier remediation](supplier-remediation.md) for separately scoped dependency upgrades/migrations.
