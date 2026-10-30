# Release engineering

## Release unit and current scope

Each tool owns its GHCR repository, two native jobs, handoffs, concurrency group and publish/provenance job. An unrelated failure is not a veto. Targets are Linux amd64 and arm64; cross-builds, registry scans and emulation are not native execution evidence.

Syft and Grype are the first published deliveries with refreshed captured native profiles, source-attributed notice bundles and the owner's [accepted-risk policy](security.md). Both native releases/provenance passed at `13edb5277101befe100a435f5ade8da6ea3d40af`; anonymous package access is still blocked. Other tools retain their specific inventory, runtime or redistribution gaps. Do not infer availability from this document: [the verification record](results.md) records completed publication and the workflow's `published-digests-TOOL` artifact is the digest authority.

## Required gates

1. Source formatting, strict Clippy, Rust regression/policy tests and the first-party dependency audit.
2. Native build/version, stopped-container filesystem/entrypoint/ELF/CA/notice validation and real tool-specific functional contracts.
3. Unchanged native Syft catalogs with captured executable/module/native/compiler coverage. UNKNOWN or missing payloads do not become guessed versions.
4. Separately refreshed database and offline Grype matching with all severities/ignored matches retained. Exact accepted risks pass as accepted-risk; new findings and errors fail.
5. Fresh tool/source/platform/archive/config/SBOM/report bindings and tool-specific readiness in `.github/publication-readiness/TOOL.json`.
6. Manual owner approval of the exact tool and source SHA, including artifact-specific source/notices/provenance review.
7. Both archive loads/identities checked before registry mutation; publish those bytes without rebuilding; verify native manifest configs and the two-platform index.
8. Successful provenance and `verify-public-tool`: anonymous index, both native manifests and config access must verify before a delivery artifact is uploaded. Public source and public packages are required; private-reader access is not a substitute.

A readiness field records an accountable review; it does not manufacture the evidence required by runtime gates. No advisory exception bypasses a missing contract or license obligation.

## Local preparation

```sh
cargo run --locked --bin devsecops -- contract syft
GITHUB_SHA=FULL_SOURCE_SHA cargo run --locked --bin devsecops -- catalog-tool syft
GITHUB_SHA=FULL_SOURCE_SHA cargo run --locked --bin devsecops -- prepare-tool syft
```

Use a clean committed source for release work. The catalog command captures evidence, not a release. Preparation refuses an existing tool output directory; preserve failed evidence before another corrected observation. Receipts expire after 24 hours; database freshness is checked independently. Tool-local directories avoid stale sibling work becoming an aggregate veto.

The fixed scanner notice collector reads four hash-bound native catalogs from run 41074964808, retrieves the exact public module sources with Go checksum verification and collects source-attributed legal texts. `cargo run --locked --bin devsecops -- collect-scanner-notices` writes private proposals, not readiness approval. Source caches have no hard filesystem quota. Collection failure, missing legal texts or a changed bundle must be investigated before packaging.

## Authorized publication

Dispatch **distroless-images** on `main`, choose one tool and enable `publish` plus `redistribution_reviewed` only after that tool's record is approved. `all` starts independent releases, not an atomic suite. There is no ad hoc local registry push path.

Only the publish job receives package-write/OIDC/attestation authority. Native jobs and pull requests cannot publish. The Rust publisher additionally checks repository/ref/event/tool/source-bound approval and readiness, then validates both handoffs and actual loads before its first push.

Output repository: `ghcr.io/prjxai/devsecops/TOOL`. Release tag: `sha-FULL_COMMIT`. No `latest`. Preserve `subjects.checksums`, `release-status.json` and the final manifest/platform identities from `published-digests-TOOL`. Status remains accepted-risk when findings are accepted.

A failed or incomplete push is not a release. After attestation, `cargo run --locked --bin devsecops -- verify-public-tool` checks the exact published index, both native members and their configurations through a credential-free Docker configuration/private HOME (only an empty GHCR auth entry and fixed system buildx paths are configured, preventing native keychain auto-discovery), with credential/proxy environment removed. It writes only an allowlisted `public-access.json` on success. Private/missing/substituted/foreign-platform/config/source metadata blocks `published-digests-TOOL` upload; no private-login fallback exists.

`PRJXAI/devsecops` is public. GHCR visibility is separate and new packages may initially be private. An owner must set each package's **Package settings → Change visibility → Public** once; subsequent versions retain that package visibility. The available operator OAuth token cannot administer those settings; the publisher does not claim to change GHCR visibility. Until anonymous access actually passes, report the package as unavailable publicly, even when push and provenance succeeded. Do not broaden token scopes, claim public delivery, publish dummy packages or change org defaults silently.

## Consumer adoption

1. Select the tool's successful publish/provenance job, even if a sibling made the overall run red.
2. Verify the immutable registry manifest and native config digests against its release artifact; verify GitHub provenance for the source/repository/workflow and subject digest.
3. Require successful anonymous access and the producer's public-access gate. No consumer package-reader token should be necessary.
4. Change one consumer pin at a time, preserving CLI flags, entrypoints, mounts, resource limits, output schemas and error behavior.
5. Run real inventories/detection controls and the full relevant consumer suite. Retain host gates where a container replacement is incomplete, especially cargo-deny.

Tool containers are not replacements for compilers, BuildKit/Engine, K3s nodes/tools/pause or RustFS. Application-image publication and real deployment require their own verified workflow/authorization. No fabricated placeholder digest may enter an active consumer pin.
