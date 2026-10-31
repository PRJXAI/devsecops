# Repository instructions

Read README.md, docs/operations.md, docs/releases.md, docs/security.md, docs/tool-inventory.md, docs/results.md and docs/threat-model.md before changing packaging, qualification or publication.

## Implementation

- All first-party code, tests and orchestration are Rust. CI run steps are single Cargo invocations. No first-party unsafe Rust, Python, JavaScript glue, shell programs/heredocs or generic supplier-rebuild framework.
- Keep explicit per-tool Dockerfiles. Final stages are digest-pinned distroless/nonroot, exec entrypoints and required binaries/runtime/CA/legal texts only. No shell, compiler, package manager, config, credentials, advisory DB or socket in layers.
- Pin supplier images and release archives/binaries by literal digest/SHA-256 on both architectures. Dockerfiles use declarative stages and exec-form direct extraction, never disguised shell glue or whole-rootfs copies.
- Prefer released binaries. Gitleaks is the existing fixed-source derivative with pinned source/patch/compiler, offline race tests, exact private context and checked Go notices. Do not restore historical supplier profiles as approval.

## Security and authority

Only public artifacts and synthetic data. No real vault, cluster, bucket, current kubecontext, customer data or operator configuration. Scanners receive no Docker socket. Docker/k3d control-plane access needs separately authorized disposable resources. Do not modify hosts or repository protections.

Trust limits are explicit in docs/threat-model.md: OS/root, same-UID workers and local Docker are trusted; private/nofollow/hash checks are not race-free same-UID protection. Captures do not impose a whole-host disk quota. Raw findings/errors remain private in ignored .work; publish allowlisted summaries and approved inventories only.

The owner authorized registry publication through the manual main pipeline and, on 2026-10-30, accepted the investigated current stack risks. `inventory/accepted-risks.json` is an exact snapshot, including known fixable findings—not a severity-wide or future-finding waiver. Keep all counts/suppressions and report accepted-risk, never clean. Gitleaks's exact no-fix rule and the pinned Grype precision diagnostic remain separately bounded. New/changed findings, other diagnostics, missing inventory, failed contracts, resource/cleanup errors and legal/source gaps still block.

Publication requires that tool's actual evidence/readiness and manual tool/source approval, both native handoffs and validated loads before mutation. No ad hoc push, invented approval, experimental handoff or guessed consumer digest. The owner separately authorized starting consumer adoption; only actual successful publish/provenance/access-verified digests may be adopted. Source/notice collection is not reproducible-build or regulatory certification.

## Ownership

- `images/`: explicit packaging; `checks.rs`: Docker/context/workflow/language/docs policy and mutation tests.
- `src/main.rs`: endpoint-bound build/process control; `src/builder.rs`: pinned-CLI precedence fixtures. Preserve 8 MiB ordinary streams and pre-write save/export 16 GiB/1 GiB caps, EOF/deadline/cancellation and unconditional bounded cleanup.
- `src/contracts.rs`, `filesystem.rs`, `grype_contract.rs`, `audit.rs`: native functionality, stopped-container files, detection and first-party audit. cargo-deny/k3d remain deliberately blocked until their full contracts exist.
- `src/release.rs`, `release_risk.rs`, `archive.rs`, `coverage.rs`: independent tool handoffs/readiness/publication, exact risk scope, immutable identities and native coverage. Preserve bad-second/eighteenth archive-load regressions and producer/publisher checks.
- `inventory/scanner-production.json`: refreshed native Syft/Grype profiles; `inventory/gitleaks-production.json`: upgraded Gitleaks profile. Historical captured data and UNKNOWN/missing/compiler mutations stay intact.
- `src/notices.rs`: fixed scanner source/legal collection and exact bundle validation. `src/risk_snapshot_capture.rs`: ignored proposal-only capture, never automatic approval. Legal bundles/indexes live in `licenses/scanners/`.
- `src/gitleaks_candidate.rs`: shared fixed production builder plus separate historical candidate controls; packaged Go legal bytes must match their index.
- `src/syft_candidate.rs`, `syft_dependencies.rs`, `syft_recorded.rs`, `debian_runtime.rs`, `debian_candidate.rs`, `runtime_probe.rs`: isolated historical/evaluation tests, not production fallback. Preserve failed suites, incomplete catalogs and loader stalls. No trace/host change without permission.
- `src/filesystem.rs`: only narrow backward non-executable regular TZif timezone aliases; reject general/forward/chained/escaping/executable/critical-payload hardlinks. Scanner/Gitleaks legal files have exact byte/mode checks.
- `.github/publication-readiness/TOOL.json` and reusable tool workflow: no aggregate approval fallback or sibling veto; native jobs read-only, selected publish job alone gets package/OIDC authority.

## Verification and maintenance

Run formatting, strict all-target Clippy, all locked tests and `audit-dependencies`; execute native cases serially. `check` is version/identity; `build-tool` adds filesystem and implemented functional checks, explicitly reporting cargo-deny/k3d build-only scope. `contract` still requires full functionality; `catalog-tool` is evidence only; `prepare-tool` adds fresh inventory/scans; `publish-tool` requires approved manual main context. Push/PR builds all nine tools and fully qualifies Syft/Grype; scheduled/manual runs fully qualify every selected tool. Never turn a build-only result into release acceptance. Never call emulation/cross-build/registry scans native execution.

Captured tuples come from unchanged real native output. Do not inject metadata, infer UNKNOWN versions or use package-count thresholds. Preserve all diagnostics and genuine client coverage. Both architectures, licenses/source arrangements, exact archive/config/manifest identities, provenance and package access matter independently.

Keep Cargo.lock/toolchain/Actions pins coordinated. Dependabot opens review PRs only. Update the smallest durable operator docs; remove interim pages only after transferring useful constraints, fixing inbound links and retaining evidence in Git/private captures. Follow .agents/skills/maintain-docs/SKILL.md. The repository and released packages must be public. After provenance, run the credential-free `verify-public-tool` gate before uploading delivery artifacts; never replace anonymous proof with a consumer-reader grant. New GHCR package visibility needs a one-time owner setting; do not claim to change it with insufficient OAuth scopes. Never label a partial push or private package as a verified public release.
