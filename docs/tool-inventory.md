# Consumer workflow tool inventory

Source: PRJXAI/obsidian-sync `.github/workflows/ci.yml` plus its Dockerfile and Rust xtask calls, inspected at commit `f6fcd95` on 2026-10-26. The consumer has unrelated uncommitted simplification work; it is not imported here.

## Tool images

| Tool | Consumer version | Required behavior |
|---|---|---|
| Syft | 1.55.0 | Native Syft JSON, CycloneDX and SPDX; development/workspace lock coverage; offline directory/archive scans and controlled registry retrieval |
| Grype | 0.121.0 | Separate fresh advisory DB retrieval; offline SBOM scan; all severities and suppressed matches remain counted |
| Gitleaks | 8.30.1 | Source and all-ref bare Git history, redaction, offline operation; requires Git at runtime |
| cargo-audit | 0.22.1 | Cargo.lock/RustSec audit with separately provided advisory data |
| cargo-deny | 0.20.2 | Advisories, bans, licenses and sources; a compiler-free image requires externally generated Cargo metadata and source/cache mounts |
| kind | 0.33.0 | Local disposable clusters only; explicit private kubeconfig; Docker control-plane access is privileged |
| kustomize | 5.8.1 | Render all consumer overlays without a cluster |
| kubectl | Consumer inherits runner; this repo pins 1.37.0 | New image must choose a version compatible with the pinned kind node (Kubernetes 1.37); offline client tests first |
| Docker CLI + Compose | Consumer inherits runner; this repo pins 29.9.2 + 5.6.1, Buildx 0.38.1 | Build/save/load/inspect/exec and Compose config/services; Docker engine remains external |
| Git | Consumer inherits runner; Gitleaks image includes vendor build 2.56.0.1.g02cd7dbd28 | Local source/history operations; preserve detached/all-ref history and ignore isolation |

## Packaging and adoption limits

- Released archives/raw downloads use literal per-architecture SHA-256; supplier/base images use digest pins. Existing explicit Dockerfile frontend directives are digest-pinned; Syft/Grype/Gitleaks have no explicit directive and inherit the external builder's frontend. Do not claim a repository-wide explicit frontend pin. Native stages select architecture; extraction is exec-form/network-disabled. Rust owns orchestration/validation/publication.
- cargo-audit amd64 uses the official RustSec static release. Static arm64 uses Cargo Quickinstall as a distinct supplier, with version-matched RustSec notices; this is not verified supplier equivalence.
- cargo-deny without Cargo supports the tested external-metadata licensing/bans subset only. Real registry/source/advisory completeness is not established, and missing Cargo/index diagnostics can be nonfatal. Keep the consumer's host gate until a complete replacement is verified.
- Gitleaks uses Git plus glibc loader/libc, PCRE2 and zlib from pinned suppliers. Native arm64 source/bare/deleted/all-ref/redaction controls have passed, but a later clean-HEAD invocation timed out and failed closed; see results. Remote helpers/hooks/LFS are absent. This is not full runtime acceptance or a general runner-Git replacement.
- Docker includes both Compose and Buildx plugins. Its daemon stays external; no socket is present or mounted during image tests. Kind now includes the pinned Docker CLI it invokes, but no socket/daemon/configuration. Its control-plane contract and newly added payload inventory still block; no cluster functionality is approved.
- Literal release URL/hash updates and expected-version contracts require human review; dependency bots do not approve supplier/provenance/license changes or trigger publication.

## Current inventory acceptance boundary

`inventory/payloads.json` records 1,168 observed native arm64 package/location tuples and compiler metadata from independent pinned Syft output. Producer and publisher require those tuples without rewriting native reports. Three current catalog profiles pass. Kind's historical binary-only profile predates its added Docker CLI and now blocks even if those old tuples match. Rust tool payload inventories are missing, Docker CLI version/dependencies are incomplete, and Kustomize/Kubectl include UNKNOWN components. Those five tools, kind's added provider payload and every unreviewed amd64 profile fail closed. This is captured regression coverage, not complete static-component attestation or native consumer acceptance. [Results](results.md) distinguishes source checks, native experiments and blocked release work.

## Keep outside the distroless CLI images

- Rust 1.99.1, Cargo, rustfmt and Clippy plus musl/C/C++/CMake/Perl/linker build dependencies: build/test host or builder image, not a shell-free CLI replacement.
- Node 24.20.0/npm: genuine pinned Commonlib/PouchDB fixtures and npm audit only; not repository orchestration or runtime.
- Go on the runner: currently installs kind/kustomize. Released CLI images can eventually avoid these installs, but consumer invocation/mount changes require separate verified integration.
- Docker daemon/BuildKit and Dockerfile frontend 1.28.0: preserve the external build engine/frontend contract; a Docker CLI image is not a daemon.
- kindest/node 1.37.0: a privileged Kubernetes node with init/container runtime, not a distroless CLI.
- RustFS: an S3-compatible test service, not a scanner/tool CLI; retain its separately validated service image.
- Alpine helper: consumer fixtures explicitly use utilities such as test/rm. Do not silently remove these or claim a distroless replacement without equivalent tests.
- GitHub Actions checkout/upload/download/setup-node and the hosted runner: Actions need their supported shell/Node environment. These tool images are explicit invocations, not whole-job containers.

No Apache CouchDB or Trivy replacement is needed: the consumer already retired them. Actionlint is a local maintenance aid, not a step in the inspected consumer workflow.
