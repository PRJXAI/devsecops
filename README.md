# DevSecOps distroless tool images

Public source for pinned CI tool-image candidates intended for reviewed use by [PRJXAI/obsidian-sync](https://github.com/PRJXAI/obsidian-sync). **Rust is the glue layer**: build, smoke, scan, artifact verification and publication logic lives in Rust. CI only launches Cargo and pinned external Actions. Dockerfiles use declarative stages/checksummed artifacts and direct exec-form extraction—not shell programs.

## Images

GHCR namespace: **`ghcr.io/prjxai/devsecops/<tool>`**.

| Tool | Packaged version |
|---|---|
| syft | 1.55.0 |
| grype | 0.121.0 |
| gitleaks + offline Git | 8.30.1 + 2.56.0.1.g02cd7dbd28 |
| cargo-audit | 0.22.1 |
| cargo-deny | 0.20.2 |
| kind | 0.33.0 |
| kustomize | 5.8.1 |
| kubectl | 1.37.0 |
| docker + Compose + Buildx | 29.9.2 + 5.6.1 + 0.38.1 |

Packaging targets linux/amd64 and linux/arm64; native amd64 acceptance is not established. All final stages are pinned distroless/nonroot. Git and official GNU cargo-audit require verified minimal native library closures; the other payloads are static. These are explicit CLI invocations, **not whole GitHub Actions job containers**. See the [workflow inventory and exceptions](docs/tool-inventory.md).

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

`catalog-candidates` requires `GITHUB_SHA` and captures unchanged native Syft JSON plus image/config/archive identities for review—even when coverage is blocked. CI retains these separately as `catalog-evidence-amd64` / `catalog-evidence-arm64` for 14 days. These are **not clean scans, release receipts or publication approval**; the existing preparation/publication gates still run independently.

Containers are offline/read-only apart from explicit advisory retrieval and synthetic setup. Captures are private, capped at 8 MiB per stream, with finite process/container cleanup. These are not complete consumer compatibility or host-disk-quota guarantees. See [measured results](docs/results.md) and [remaining tasks](TASKS.md). The [approval evidence sequence](docs/release-readiness.md) separates technical work from accountable sign-off.

## Updates and publishing

[CI](.github/workflows/ci.yml) is configured for native amd64/arm64 preparation: functional prerequisites, unchanged native Syft inventories, captured payload/dependency coverage and offline Grype with separately refreshed data. Every finding—including Unknown/Negligible/ignored matches—and every scan/validation error blocks publication. Nonempty analysis diagnostics also block; no precision-notice exception or symbol-based finding filter is approved. Incomplete inventories and unreviewed architectures fail closed, not clean.

Dependabot opens weekly PRs for Cargo, Docker base/supplier images and Actions. **No auto-merge or automatic publishing.** Released binary URLs/checksums, Rust toolchain, expected versions, licenses and source provenance require coordinated human review; Dependabot cannot safely update all of those by itself.

Publication is currently blocked. Manual `main` dispatch with both inputs is necessary but insufficient: Rust also requires all three approvals in [publication readiness](.github/publication-readiness.json) explicitly true and no blockers. They remain false. Source-SHA approval is an additional trusted-workflow assertion, not independent legal review/authentication.

The configured publisher gets package-write/OIDC permissions only after both native jobs succeed. Rust preflights all 18 archives/receipts, source/age/hash/config/SBOM/coverage bindings, then validates every actual load before any tag/push. Engine/index and selected config identities are separate. It publishes verified native bytes without rebuilding and creates multiarch **`sha-<full-commit>`** tags, never `latest`. The workflow requests GitHub provenance for published manifest digests; end-to-end publication/attestation is not yet verified or evidence of reproducible supplier builds.

Consume only a digest from a **fully successful** publish/attestation run, for example `ghcr.io/prjxai/devsecops/syft@sha256:<verified-manifest-digest>`. A partially failed registry push is not a completed release. Consumer adoption requires separate contract verification and a reviewed pin update; this repository does not change other repositories automatically.

GHCR packages are created on the first successful push. Package visibility is separate from repository visibility: verify the package is public in its settings before promising anonymous pulls. Until then, other authorized repositories need package-read access. No image availability is implied until [results](docs/results.md) records a successful publication.

## Important limits

- [Runner/filesystem trust boundary](docs/threat-model.md): same-UID processes, OS and local Docker are trusted. Leaf nofollow/hash checks are not race-free protection against those actors; archive/DB host storage has no hard quota.
- Distroless does not remove embedded Go/Rust/native vulnerabilities. Existing supplier findings block publication; [current upstream releases do not contain all required fixes](docs/supplier-remediation.md). No waiver is configured.
- cargo-audit now uses official RustSec GNU releases on both architectures, not Quickinstall, with individually verified runtime ELF files. [Supplier/runtime evidence](docs/cargo-audit-supplier.md) does not establish complete build provenance, dependency inventory or redistribution approval.
- Compiler-free cargo-deny requires external metadata and matching source/index/cache mounts. Missing-Cargo/index errors can be nonfatal: **exit 0 does not prove complete coverage**. It is not approved as a replacement for the consumer's full host cargo-deny gate; see the [native supplied-graph investigation](docs/cargo-deny-coverage.md).
- Gitleaks includes only the Git builtin/runtime closure tested for offline history, not remote helpers, LFS or shell hooks. Its [unresolved runtime-completion timeout](docs/runtime-completion.md) remains blocking; no speculative init/retry fix was retained.
- Complete dependency notices, Git corresponding source and supplier provenance must be reviewed before checking the redistribution approval input. First-party code does not relicense the packaged binaries.
- Kind now includes its pinned Docker/provider CLI, but disposable control-plane testing and the added payload inventory remain unapproved; no cluster functionality is claimed. Complete payload inventories/native acceptance also remain blocked; see the [inventory](docs/tool-inventory.md).
- Rust/Node builders, Docker daemon/BuildKit, kind nodes, RustFS and shell-dependent helpers remain separate requirements. No real cluster or current kubecontext is used for these tool checks.

Maintenance: [AGENTS.md](AGENTS.md), [skills](.agents/skills/), [inventory](docs/tool-inventory.md), [results](docs/results.md), [third-party redistribution](licenses/README.md).
