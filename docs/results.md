# Measured results and limitations

## TASKS.md execution — in progress

The adversarial review is being executed in isolated changes. B1 changes authorization only: publication must satisfy the existing schema-1 readiness file as well as manual/main/source-SHA approval, before any Docker load/push. False, missing or malformed readiness is not overridden by dispatch inputs. Runtime tools, scan severity policy and consumer state are unchanged. Readiness remains false while redistribution/provenance/native-contract evidence is missing. B1: 19 local tests and Clippy passed. The first parallel run caught a timestamp-only test-fixture collision; an atomic sequence now prevents collisions without relaxing production create-only behavior.

B2: private per-build IID files now replace mutable check tags; the same immutable ID is inspected, smoked, returned and saved. Twenty tests, Clippy and a native Syft build/smoke passed. The producer no longer performs a second tag-based image lookup.

B3/B9: all archive loads now precede registry mutation and must identify exactly their expected IDs. Rust-only negative subprocess fixtures reject wrong/multiple/malformed eighteenth loads with zero pushes; a real native Syft save/load roundtrip passed with its ID preloaded. Lifecycle fixtures cover overflow, hangs, descendants holding streams, both termination signals, spawn/removal failure, cancellation-safe cleanup and final bounded reaping. Current integration: 36 tests passed, with fixture/manual integration entrypoints explicitly invoked by parent tests or separately. Linux-native verification remains pending.

B6/B7: eleven policy tests now reject workflow permission/approval/comment/extra-workflow/shell bypasses and Docker case/user/entrypoint/rootfs-copy/ADD/tar/context-reinclusion mutations. All nine current Dockerfiles and the planned license-stage inlining remain positive. Language checks enumerate Git-eligible source instead of traversing ignored operator data.

## Initialization and publication pipeline — 2026-10-26

Created `PRJXAI/devsecops`, initially private, then made it public at the owner's explicit request. GHCR publication is authorized through the manual main-branch workflow, not ad hoc pushes or automatic consumer adoption. No consumer pin, production setting or real cluster was changed. The consumer's existing uncommitted simplification work remains separate.

## Executed locally

- All nine Dockerfiles built and all nine native **linux/arm64** image user/architecture/version checks passed through the Rust driver. Docker also passed Compose/Buildx versions; Gitleaks passed its packaged Git version. Exact Git supplier version is `2.56.0.1.g02cd7dbd28`; the first coarse version assertion failed and was corrected to the actual pinned vendor build, not relaxed to accept arbitrary versions.
- Scanner, Kubernetes CLI and Cargo security images cross-built for amd64. cargo-audit/deny also ran under amd64 emulation; this is **not native amd64 verification**. Docker CLI amd64 and native hosted CI remain to be checked.
- Syft native JSON/CycloneDX/SPDX covered synthetic npm development and Rust workspace-lock dependencies. Gitleaks detected one seeded source secret and one deleted bare/all-ref history secret, with clean-HEAD and redaction controls. No live secret validation occurred.
- kustomize rendered a synthetic two-object fixture offline. No kind cluster, Kubernetes API, current kubecontext or Docker socket inside a tool container was used.
- cargo-audit separate offline RustSec controls detected a synthetic vulnerable `time 0.1.43` lock entry and accepted a clean synthetic lock; missing DB failed. cargo-deny external-metadata/path-source licensing and bans positive/negative controls ran, but nonfatal missing-Cargo/index diagnostics mean full consumer coverage is **not verified**.
- Exported final filesystem inspections for scanner/Kubernetes/Cargo images found CA roots and no shell/package-manager/compiler executables. Git's glibc/PCRE2/zlib closure was executed natively. Parent rewrote Cargo/kustomize extraction as declarative stages and direct exec-form commands to enforce Rust-only glue; native rebuilds passed.
- Rust policy checks reject non-Cargo CI launchers, non-Rust glue files, shell-form/disguised shell extraction, unpinned sources/actions and improperly scoped publication settings. Unit tests exercise wrong publication context/SHA, stale or missing DB/receipts, every severity and ignored match, wrong image/package bindings, tampered/incomplete 18-asset handoffs and malformed registry indexes. Formatting, Clippy and local tests passed before the first source push.

Raw logs/artifacts are private under ignored `.work/`; only counts/statuses and approved inventories/identities are publishable.

## Publication and adoption status

The Rust pipeline refreshes Grype data separately, catalogs immutable saved image bytes, scans offline without a Docker socket, and refuses findings/errors before exporting clean handoffs. The publisher verifies both architectures and all hashes before loading/pushing, creates digest-bound multiarch SHA tags without rebuilding, then requests GitHub provenance for those manifest subjects. Native remote execution, full end-to-end publication and attestation are not yet claimed verified.

Existing embedded supplier vulnerabilities are expected to block initial publication; distroless repackaging does not remediate them. Complete transitive notices, Git corresponding source, Cargo Quickinstall arm64 supplier review, and consumer contract acceptance remain unresolved. The redistribution checkbox is an explicit SHA-bound owner review assertion, not automated legal approval. Repository/branch protections and independent approval policy are not configured by this initialization.

GHCR packages do not exist until a successful first push. Public repository visibility does not itself prove public package visibility; anonymous pulls must be verified after package creation. No image has been published, no `latest` tag is created, and other repositories must not adopt an unverified tag.
