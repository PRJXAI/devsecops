# DevSecOps tool images

**Pinned tools. Distroless runtimes. Releases you can trace.**

A focused container toolkit for SRE and DevSecOps pipelines: software inventory, vulnerability matching, secret detection and deployment utilities. Each image runs one tool as a non-root process. Rust owns the build, test and release orchestration; images do not contain a shell, compiler, package manager or embedded credentials.

These are **CLI containers**, not GitHub Actions job environments, Docker daemons, Kubernetes nodes or application builders.

## Tool catalog

| Image under `ghcr.io/prjxai/devsecops/` | Version | Purpose |
|---|---|---|
| `syft` | 1.55.0 | Native Syft JSON, SPDX and CycloneDX inventories |
| `grype` | 0.121.0 | Offline vulnerability matching against a separately refreshed database |
| `gitleaks` | 8.30.1 source derivative; Go 1.27.3 | Redacted source and offline Git-history checks |
| `cargo-audit` | 0.22.2 | RustSec lockfile checks |
| `cargo-deny` | 0.20.2 | Dependency policy checks; complete compiler-free coverage remains unqualified |
| `k3d` | 5.9.0 | Disposable Kubernetes control plane; packaged control-plane acceptance remains unqualified |
| `kustomize` | 5.8.3 | Offline manifest rendering |
| `kubectl` | 1.37.2 | Kubernetes client operations |
| `docker` | 29.9.2; Compose 5.6.1; Buildx 0.38.1 | Docker client and plugins; requires a separately authorized daemon |

Targets: **Linux amd64 and arm64**. A target is not a support claim until its native release checks succeed. Images release independently; one blocked tool does not hold another back. See [release status and verification](docs/releases.md) before choosing an image. A Dockerfile or successful version command does not mean a package has been published.

**Delivered:** Syft and Grype passed native amd64/arm64 release and provenance at `13edb5277101befe100a435f5ade8da6ea3d40af`. Their [exact digests and accepted-risk counts](docs/results.md) are recorded. The repository and both scanner packages are now public, with anonymous native-index/config/catalog/provenance verification passing after owner visibility changes. New delivery artifacts are gated on anonymous index/native/config verification after provenance, not private-token access. Other tools are not approved deliveries.

## Use by digest

Take the manifest digest from that tool's successful publish **and provenance** job. Tags identify source revisions (`sha-<full-commit>`); there is no floating `latest` release.

Set `SYFT_IMAGE` to the verified `ghcr.io/prjxai/devsecops/syft@sha256:…` reference, then inventory a public or approved local input:

```sh
docker run --rm --network none --read-only \
  --user "$(id -u):$(id -g)" --cap-drop ALL \
  --security-opt no-new-privileges \
  --cpus 2 --memory 3g --pids-limit 128 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777 \
  -v "$PWD/public-input:/input:ro" \
  "$SYFT_IMAGE" scan dir:/input --output cyclonedx-json
```

Mount only the input the tool needs. Never mount a Docker socket into a scanner. Offline analysis and network-enabled registry/advisory retrieval are separate operations. [The operations guide](docs/operations.md) covers writable caches, Grype database handling, exit codes and privileged CLI access.

## Security posture

The owner accepted the **investigated current stack risks on 2026-10-30**, including known findings with published fixes. Acceptance is recorded against exact recipes, package versions, advisory/fix identities, locations and occurrence limits—not all future findings. Matches remain in reports; a passing release with findings is **accepted-risk**, never vulnerability-free.

New or changed findings, malformed/stale reports, missing inventories, failed native contracts and cleanup errors still fail. Risk acceptance does not provide missing source, license or runtime evidence. Read [security and accepted risks](docs/security.md) and the machine-readable [risk snapshot](inventory/accepted-risks.json).

Syft and Grype include source-attributed third-party notice bundles covering their captured Go module graphs and Go 1.26.8 legal texts. [Redistribution information](licenses/README.md) describes source availability and remaining tool-specific obligations. Gitleaks's Git/native source obligations are separate from the scanner bundles.

## Build and verify

Requirements: pinned Rust toolchain, a local Unix-socket Docker daemon and a native Linux worker for the platform being qualified.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo run --locked --bin devsecops -- check syft
cargo run --locked --bin devsecops -- contract syft
cargo run --locked --bin devsecops -- audit-dependencies
```

`check` builds and verifies identity/version. `contract` adds stopped-container filesystem and real synthetic functional checks. Neither publishes. `prepare-tool` adds inventory, fresh offline matching and hash-bound handoffs. Publication requires an approved manual dispatch on `main`, both native handoffs and tool-specific readiness; it loads the tested bytes rather than rebuilding them.

## Documentation

- [Operations](docs/operations.md): invocation, mounts, caches and troubleshooting.
- [Release engineering](docs/releases.md): approvals, provenance, digests and consumer adoption.
- [Security](docs/security.md): accepted risks, non-waived gates and runner isolation.
- [Tool integration reference](docs/tool-inventory.md): contracts and replacement boundaries.
- [Verification record](docs/results.md): measured checks and outstanding gaps.
- [Third-party licenses and source](licenses/README.md).
- [llms.txt](llms.txt): concise navigation and automation constraints.

The first integration target is [obsidian-sync](https://github.com/PRJXAI/obsidian-sync). Tool images do not replace its compilers, real-client fixtures, service images or host security checks until equivalent behavior has been verified.
