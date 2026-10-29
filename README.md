# DevSecOps distroless tool images

Public source for pinned CI tool-image candidates intended for reviewed use by [PRJXAI/obsidian-sync](https://github.com/PRJXAI/obsidian-sync). **Rust is the glue layer**: build, smoke, scan, artifact verification and publication logic lives in Rust. CI only launches Cargo and pinned external Actions. Dockerfiles use declarative stages/checksummed artifacts and direct exec-form extraction—not shell programs.

## Images

GHCR namespace: **`ghcr.io/prjxai/devsecops/<tool>`**.

| Tool | Packaged version |
|---|---|
| syft | 1.55.0 |
| grype | 0.121.0 |
| gitleaks + offline Git | 8.30.1 reviewed source derivative (Go 1.27.3) + 2.56.0.1.g02cd7dbd28 |
| cargo-audit | 0.22.1 |
| cargo-deny | 0.20.2 |
| kind | 0.33.0 |
| kustomize | 5.8.1 |
| kubectl | 1.37.0 |
| docker + Compose + Buildx | 29.9.2 + 5.6.1 + 0.38.1 |

Packaging targets linux/amd64 and linux/arm64. Seven functional contracts have hosted native evidence on both; complete release acceptance is still blocked. All final stages are pinned distroless/nonroot. Git and official GNU cargo-audit require verified minimal native library closures; the other payloads are static. These are explicit CLI invocations, **not whole GitHub Actions job containers**. See the [workflow inventory and exceptions](docs/tool-inventory.md).

## Local checks

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo run --locked --bin devsecops -- check syft
cargo run --locked --bin devsecops -- check-all
cargo run --locked --bin devsecops -- contract syft
cargo run --locked --bin devsecops -- audit-dependencies
```

The driver requires a local Unix-socket Docker daemon with the native Linux architecture. Builds bind the checked effective endpoint to Buildx's default Docker driver, not an inherited builder selection. `check`/`check-all` build and smoke immutable IDs; `contract TOOL` adds final-filesystem and synthetic functional checks. cargo-deny/kind contracts deliberately fail until their missing requirements are resolved. `audit-dependencies` separately retrieves public RustSec data, validates the packaged tool and audits this repository offline; only counts/status are public.

The [release unblock plan](docs/release-blockers.md) lists each tool's remaining evidence. Tools release independently. Production Gitleaks now uses the tested fixed source/dependency patch and pinned Go 1.27.3 compiler, built and race-tested offline by Rust before packaging. Its collected Go notices are packaged and byte/mode-checked. The production profile requires the 74 tuples captured on both native architectures, rejecting the old supplier build. Hosted production preparation passes on **both amd64 and arm64** at source `818c362` as **accepted-risk: 1 accepted / 0 blocking per architecture**. Source/legal review, local runtime-stall investigation and publication/attestation validation remain outstanding. The separate experimental CI job and `gitleaks-native-candidate-*` artifacts still cannot substitute for production release handoffs. The [2026-10-29 follow-up](licenses/gitleaks-runtime-review.md) now binds public APK recipes/payloads on both architectures; a loader-only diagnostic reproduces the exit stall without Gitleaks/Git execution, but its exact cause and complete source-delivery obligations remain unresolved.

`catalog-tool TOOL` requires `GITHUB_SHA` and captures unchanged native Syft JSON plus image/config/archive identities—even when coverage is blocked. CI retains `catalog-evidence-TOOL-{amd64,arm64}` for 14 days. These are **not clean scans or publication approval**. `prepare-tool TOOL` independently runs mandatory contracts, inventory and fresh scan gates. Tool-specific `.work/catalog-evidence-TOOL/`, `.work/scans-TOOL/`, `.work/public-release-TOOL/` and `.work/release-TOOL/` directories prevent unrelated stale work from blocking another tool. Existing output for the same tool still fails closed. The former aggregate CLI commands are retired.

Analysis containers are offline/read-only apart from explicit advisory retrieval and synthetic setup; Gitleaks source/module retrieval is separate from its offline build/tests. Ordinary captures are private and capped at 8 MiB per stream. Docker save/export stdout is instead streamed into create-only files with pre-write 16 GiB/1 GiB limits, with unchanged deadlines and bounded cleanup. These are not complete consumer compatibility or host-disk-quota guarantees. See [measured results](docs/results.md) and [remaining tasks](TASKS.md). The [approval evidence sequence](docs/release-readiness.md) separates technical work from accountable sign-off.

## Updates and publishing

[CI](.github/workflows/ci.yml) calls an [isolated workflow](.github/workflows/tool.yml) per tool, with fail-fast disabled. Each invocation owns both native architecture jobs, a concurrency group, exact artifact downloads and its publish/attestation job. A failed sibling tool or candidate experiment does not block another tool. Shared first-party checks/dependency audit and the pinned analysis engines remain required. Native preparation includes: functional prerequisites, unchanged native Syft inventories, captured payload/dependency coverage and offline Grype with separately refreshed data. Public security summaries identify the first failing preparation stage and an allowlisted reason, with shared scanner/DB setup reported separately; they never include raw errors or imply later checks ran. Every finding—including Unknown/Negligible/ignored matches—remains counted. Under the owner's [reviewed no-fix policy](docs/release-risk-policy.md), an explicitly approved finding with no fix or viable alternative may pass as **accepted-risk**, never clean. The first rule covers only Gitleaks's exact `GO-2026-5932` / x/crypto `v0.58.0` case. Current fix metadata is rechecked; other findings still block. The exact pinned Grype module-granularity precision warning is now informational; all other analysis diagnostics/errors remain blocking. No symbol/severity/fixed-only filtering is enabled. Incomplete inventories and unreviewed architectures still fail closed.

Dependabot opens weekly PRs for Cargo, Docker base/supplier images and Actions. **No auto-merge or automatic publishing.** Released binary URLs/checksums, Rust toolchain, expected versions, licenses and source provenance require coordinated human review; Dependabot cannot safely update all of those by itself.

Publication is currently blocked by each tool's own unresolved evidence. To release, manually dispatch `main`, select `tool` (or `all` for independent releases), and enable both approval inputs. Rust additionally requires that tool's three approvals in `.github/publication-readiness/TOOL.json` explicitly true with no blockers. All remain false. Each record binds its tool and GHCR repository; manual review binds **both the tool and source SHA**. Neither is independent legal authentication or an override of scan/contract gates.

Within the reusable workflow, native jobs have read-only permissions; only the selected tool's publish job receives package-write/OIDC permissions, after its two native jobs succeed. Rust preflights its **two** archives/schema-3 receipts, source/age/hash/config/SBOM/coverage bindings and exact risk accounting, then validates both actual loads before any tag/push. Receipts keep the raw private report hash, all counts, reviewed exception IDs and diagnostic classification. `release-status.json` exposes clean versus accepted-risk status and per-architecture counts bound to the published manifest. Wrong-tool, missing or duplicate platform members fail closed. Engine/index and selected config identities remain separate. It publishes verified native bytes without rebuilding to `ghcr.io/prjxai/devsecops/TOOL`, creating multiarch **`sha-<full-commit>`** tags, never `latest`. GitHub provenance and `published-digests-TOOL` artifacts are scoped to that manifest. Hosted preparation is evidenced in run 40712836198; end-to-end publication/attestation remains unverified.

Consume only a digest from that tool's **fully successful publish/attestation job** (a sibling failure can leave the overall run red), for example `ghcr.io/prjxai/devsecops/syft@sha256:<verified-manifest-digest>`. A partially failed registry push is not a completed release. Consumer adoption requires separate contract verification and a reviewed pin update; this repository does not change other repositories automatically.

GHCR packages are created on the first successful push. Package visibility is separate from repository visibility: verify the package is public in its settings before promising anonymous pulls. Until then, other authorized repositories need package-read access. No image availability is implied until [results](docs/results.md) records a successful publication.

## Important limits

- [Runner/filesystem trust boundary](docs/threat-model.md): same-UID processes, OS and local Docker are trusted. Leaf nofollow/hash checks are not race-free protection against those actors; archive/DB host storage has no hard quota.
- Distroless does not remove embedded Go/Rust/native vulnerabilities. Unapproved supplier findings block publication; [current upstream releases do not contain all required fixes](docs/supplier-remediation.md). The [reviewed no-fix exception](docs/release-risk-policy.md) does not hide matches or waive fixable findings.
- cargo-audit now uses official RustSec GNU releases on both architectures, not Quickinstall, with individually verified runtime ELF files. [Supplier/runtime evidence](docs/cargo-audit-supplier.md) does not establish complete build provenance, dependency inventory or redistribution approval.
- Compiler-free cargo-deny requires external metadata and matching source/index/cache mounts. Missing-Cargo/index errors can be nonfatal: **exit 0 does not prove complete coverage**. It is not approved as a replacement for the consumer's full host cargo-deny gate; see the [native supplied-graph investigation](docs/cargo-deny-coverage.md).
- Gitleaks includes only the Git builtin/runtime closure tested for offline history, not remote helpers, LFS or shell hooks. Its [unresolved runtime-completion timeout](docs/runtime-completion.md) remains blocking; no speculative init/retry fix was retained.
- Complete dependency notices, Git corresponding source and supplier provenance must be reviewed before checking the redistribution approval input. First-party code does not relicense the packaged binaries.
- Kind now includes its pinned Docker/provider CLI, but disposable control-plane testing and the added payload inventory remain unapproved; no cluster functionality is claimed. Complete payload inventories/native acceptance also remain blocked; see the [inventory](docs/tool-inventory.md).
- Rust/Node builders, Docker daemon/BuildKit, kind nodes, RustFS and shell-dependent helpers remain separate requirements. No real cluster or current kubecontext is used for these tool checks.

Maintenance: [AGENTS.md](AGENTS.md), [skills](.agents/skills/), [inventory](docs/tool-inventory.md), [results](docs/results.md), [third-party redistribution](licenses/README.md).
