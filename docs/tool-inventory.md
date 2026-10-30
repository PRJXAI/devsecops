# Tool integration reference

| Tool | Version | Required contract | Current qualification boundary |
|---|---|---|---|
| Syft | 1.55.0 | JSON/SPDX/CycloneDX, Rust workspace/npm development locks, offline directory/archive input | Fresh native profiles and notice bundles prepared; release still requires both new native handoffs |
| Grype | 0.121.0 | Separate DB retrieval; offline clean/vulnerable/missing-data controls; all-match accounting | Fresh native profiles and notice bundles prepared; release still requires both new native handoffs |
| Gitleaks | 8.30.1 derivative / Go 1.27.3 | Source/deleted/bare/all-ref/redaction/clean-HEAD; minimal offline Git | Go notices packaged; exact Git/glibc corresponding-source and retained loader completion issue remain separate gaps |
| cargo-audit | 0.22.2 | Clean/vulnerable/missing-RustSec controls | Official GNU native closure tested; compiled Rust/native inventory and supplier review incomplete |
| cargo-deny | 0.20.2 | Complete advisories/bans/licenses/sources graph, index/cache inputs | Full compiler-free replacement is not proven; retain consumer host gate |
| k3d | 5.9.0 | Packaged native disposable control-plane lifecycle and inventory | Host-CLI consumer smoke is not packaged-image qualification |
| Kustomize | 5.8.3 | Offline rendering | Functional evidence exists; UNKNOWN component inventory remains unresolved |
| kubectl | 1.37.2 | Offline client/config operations; authorized compatible server usage | Functional evidence exists; UNKNOWN component inventory remains unresolved |
| Docker | 29.9.2 / Compose 5.6.1 / Buildx 0.38.1 | Client/plugins and offline Compose normalization | Main CLI/dependency inventory remains incomplete; daemon is external |

Every release targets native Linux amd64/arm64 independently of sibling tools. Version and top-level license checks alone do not complete qualification. See [releases](releases.md) and [results](results.md).

## Image layout

Entrypoints are `/usr/local/bin/TOOL`; cargo-audit additionally includes `audit` in its entrypoint. Final UID/GID is 65532. Gitleaks includes only the verified offline Git/native closure; cargo-audit includes its individually checked GNU loader/library closure. Docker packages Compose/Buildx plugins. K3d uses the embedded Docker SDK and includes no Docker CLI or daemon.

Scanners keep CA roots and explicit HOME/cache behavior. Database/configuration/credentials are mounts, not layers. Scanner containers receive no Docker socket. Minimal native closures are not permission to copy a whole supplier rootfs.

## Keep outside these images

- Rust/Cargo/rustfmt/Clippy and C/C++/CMake/Perl/linker dependencies belong to the application build/test environment.
- Node/npm belong only to the pinned Commonlib/PouchDB test bridge, not orchestration or the application runtime.
- Engine/BuildKit, Dockerfile frontend, K3s nodes, k3d-tools, pause and RustFS are distinct infrastructure/service assets.
- Actions need their supported shell/Node runner environment; these images are explicit tool invocations, not job containers.
- The retired kind, external CouchDB, Trivy and standalone Alpine helper are not quietly reintroduced. Historical captures remain bound to their original source/subjects.

## Maintenance

Update literal release URLs/checksums, source/version metadata, base digests, notice bundles, captured coverage and expected contracts together. Dependabot proposals do not auto-merge, approve redistribution or publish. Do not rewrite a native report, infer UNKNOWN versions from a CLI string or carry an old compiler/base profile to different bytes.

`inventory/payloads.json` and historical evidence remain immutable regression inputs. Current Syft/Grype use `inventory/scanner-production.json`; Gitleaks uses its separate upgraded production profile. Experiments cannot approve production handoffs.
