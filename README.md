# DevSecOps distroless tool images

Public source for pinned CI tool images used by [PRJXAI/obsidian-sync](https://github.com/PRJXAI/obsidian-sync). **Rust is the glue layer**: build, smoke, scan, artifact verification and publication logic lives in Rust. CI only launches Cargo and pinned external Actions. Dockerfiles use declarative stages/checksummed artifacts and direct exec-form extraction—not shell programs.

## Images

GHCR namespace: **`ghcr.io/prjxai/devsecops/<tool>`**.

| Tool | Packaged version |
|---|---|
| syft | 1.55.0 |
| grype | 0.121.0 |
| gitleaks + offline Git | 8.30.1 + 2.56.0 |
| cargo-audit | 0.22.1 |
| cargo-deny | 0.20.2 |
| kind | 0.33.0 |
| kustomize | 5.8.1 |
| kubectl | 1.37.0 |
| docker + Compose + Buildx | 29.9.2 + 5.6.1 + 0.38.1 |

Dockerfiles support linux/amd64 and linux/arm64. All final stages are pinned distroless/nonroot. Git requires a small glibc/library closure; the other payloads are static. These are explicit CLI invocations, **not whole GitHub Actions job containers**. See the [workflow inventory and exceptions](docs/tool-inventory.md).

## Local checks

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo run --locked --bin devsecops -- check syft
cargo run --locked --bin devsecops -- check-all
```

The driver requires a local Unix-socket Docker daemon with the native Linux architecture. It builds and uses immutable image IDs, checks user/version/architecture, runs offline/read-only bounded containers, captures capped private logs under ignored `.work/`, and performs bounded cleanup on timeout/cancellation. Basic smoke checks are not complete consumer compatibility tests.

## Updates and publishing

[CI](.github/workflows/ci.yml) builds/smokes on native amd64 and arm64, emits Syft inventories and scans them offline with a separately refreshed Grype DB. Every finding, including Unknown/Negligible and ignored matches, and every scan/validation error blocks publication.

Dependabot opens weekly PRs for Cargo, Docker base/supplier images and Actions. **No auto-merge or automatic publishing.** Released binary URLs/checksums, Rust toolchain, expected versions, licenses and source provenance require coordinated human review; Dependabot cannot safely update all of those by itself.

To publish, run the workflow manually on `main` and explicitly enable both `publish` and `redistribution_reviewed`. The publisher receives package-write/OIDC permissions only after both native jobs succeed. Rust verifies the source, age, hashes and identities of both architectures' archives/receipts before any push. It loads and publishes the scanned bytes without rebuilding, creates multiarch **`sha-<full-commit>`** tags (no `latest`), and records digest references. GitHub provenance attestations cover the published manifest digests; they are stored with the repository, not claimed as reproducible supplier builds.

Consume only a digest from a **fully successful** publish/attestation run, for example `ghcr.io/prjxai/devsecops/syft@sha256:<verified-manifest-digest>`. A partially failed registry push is not a completed release. Consumer adoption requires separate contract verification and a reviewed pin update; this repository does not change other repositories automatically.

GHCR packages are created on the first successful push. Package visibility is separate from repository visibility: verify the package is public in its settings before promising anonymous pulls. Until then, other authorized repositories need package-read access. No image availability is implied until [results](docs/results.md) records a successful publication.

## Important limits

- Distroless does not remove embedded Go/Rust/native vulnerabilities. Existing supplier findings are expected to block the first publication; no waiver is configured.
- cargo-audit arm64 uses **Cargo Quickinstall**, a distinct supplier because RustSec provides no static arm64 release. Supplier equivalence/provenance still requires review.
- Compiler-free cargo-deny requires external metadata and matching source/index/cache mounts. Missing-Cargo/index errors can be nonfatal: **exit 0 does not prove complete coverage**. It is not approved as a replacement for the consumer's full host cargo-deny gate.
- Gitleaks includes only the Git builtin/runtime closure tested for offline history, not remote helpers, LFS or shell hooks.
- Complete dependency notices, Git corresponding source and supplier provenance must be reviewed before checking the redistribution approval input. First-party code does not relicense the packaged binaries.
- Rust/Node builders, Docker daemon/BuildKit, kind nodes, RustFS and shell-dependent helpers remain separate requirements. No real cluster or current kubecontext is used for these tool checks.

Maintenance: [AGENTS.md](AGENTS.md), [skills](.agents/skills/), [inventory](docs/tool-inventory.md), [results](docs/results.md), [third-party redistribution](licenses/README.md).
