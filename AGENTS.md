# DevSecOps repository instructions

Read README.md, TASKS.md, docs/tool-inventory.md, docs/results.md, docs/threat-model.md and docs/release-readiness.md before changing images or tests.

## Scope and simplicity

Package the released tools required by PRJXAI/obsidian-sync CI. Keep explicit Dockerfiles and small Rust tests; do not build a generic supplier-rebuild framework, image generator or release platform. One reviewed behavior change at a time. First-party code/tests/automation must be Rust; shell is limited to direct external-tool invocations. No first-party unsafe Rust or Python.

## Rust is the glue layer — enforced

All first-party build/test/validation orchestration belongs in Rust. CI `run` steps must be single Cargo invocations; call `cargo run --locked --bin devsecops -- check TOOL` for image builds/smokes. No inline Python, JavaScript/Node, shell scripts, heredocs, loops or conditionals in CI or Dockerfiles. Dockerfiles use declarative stages/checksummed ADD/COPY and exec-form direct extraction commands only. Never hide shell glue in `RUN ["sh", "-c", ...]`. Rust policy tests reject these regressions. External supplier tools may use other languages; that is not permission to implement repository glue in them.

## Image contract

- Final stages must be digest-pinned distroless, nonroot (65532:65532), with exec-form entrypoints, CA roots and only the required binary/runtime closure. No shell, package manager, compiler, configuration, credentials, advisory DB or Docker socket in image layers.
- Pin every supplier image by digest and every downloaded binary/archive by literal SHA-256 for linux/amd64 and linux/arm64. Verify exact versions, entrypoints, dependencies and licenses. Never use an unpinned download or only a checksum downloaded alongside it during the build.
- Prefer repackaging released binaries. Static Go binaries retain their embedded dependencies; distroless does not mean vulnerability-free. Dynamic tools need a verified loader/library closure. Gitleaks history needs Git; version-only tests are insufficient.
- Keep retrieval separate from offline analysis. Use read-only inputs, isolated output, explicit writable cache/tmpfs, bounded resources/time and caller identity where supported. Scanners never receive a Docker socket. Docker/kind control-plane access is privileged and requires separate explicit mounts and authorization.
- Do not present these images as whole GitHub Actions job containers: runner steps need shell/Node, builds need compilers, and kind nodes/RustFS are services. Preserve consumer tests and all finding/error gates. Never change consumer pins automatically.

## Authorization and evidence

Follow [the trust boundary](docs/threat-model.md): OS, same-UID runner processes and the local Docker daemon are trusted. Private parents/leaf checks are artifact hygiene, not race-free same-UID protection; unsigned hashes do not authenticate a malicious producer. Host archive/cache writes lack a hard storage quota. Do not broaden those claims without separate reviewed isolation.

Only public artifacts and synthetic fixtures are allowed. Never access real vaults, clusters, buckets, operator overrides or credentials. Never use the current kubecontext. The owner authorized public GHCR publication through the reviewed main-branch pipeline on 2026-10-26. Publication still requires successful native tests/scans, complete redistribution/source review and manual workflow approval; failed/missing evidence blocks it. No real deployment, repository-protection changes, ad hoc registry pushes or automatic consumer adoption.

No secrets, seed tokens, signed URLs or raw tool/provider errors in public logs. Keep raw local output in ignored .work with private permissions. Public evidence is counts/statuses and artifact identities. Keep known findings and unverified checks explicit; never blanket-waive severities/suppressed findings or call build-only CI release acceptance. The owner-approved [no-fix risk policy](docs/release-risk-policy.md) permits only explicitly reviewed cases with no fix or viable alternative. Retain all counts, report accepted-risk rather than clean, and recheck current fix metadata and exact scope. This is not permission to bypass redistribution or missing runtime/inventory evidence.

Redistribution requires complete third-party license/notices and corresponding source where applicable, particularly Git. First-party licensing does not relicense packaged binaries. Missing license/source/provenance review blocks publication.

## Workflow and ownership

- images/<tool>/Dockerfile: explicit pinned tool packaging; never copy an entire supplier rootfs.
- checks.rs: structural/workflow/Docker/context/docs policy and mutation tests.
- src/main.rs, src/builder.rs: checked build/process policy and opt-in pinned-CLI selection tests; build-only and build/smoke share endpoint binding. Docker archives use bounded stdout capture, never Docker --output writes. Preserve ordinary 8 MiB stream limits, per-archive caps, EOF/deadline/cancellation checks and unconditional container cleanup; progress-aware archive draining must not busy-wait while idle.
- src/release.rs, src/release_risk.rs, src/archive.rs, src/coverage.rs: tool-local handoff/readiness/publication, exact reviewed risk assessment and public accounting, distinct engine/config identity and fail-closed captured inventory coverage. `.github/publication-readiness/<tool>.json` binds each approval to its tool/repository; never restore an aggregate veto or approval fallback. `.github/workflows/tool.yml` owns each tool's two-architecture prerequisite and publish/attestation job; candidate experiments are separate.
- src/contracts.rs, src/filesystem.rs, src/grype_contract.rs, src/audit.rs: native synthetic/final-filesystem/audit contracts and unit tests. src/gitleaks_candidate.rs now shares one fixed-source Gitleaks builder between production and its separate evidence test. Production accepts only its private verified executable and hash-checked notice bundle through the exact reviewed images/gitleaks/Dockerfile; this is not a generic local-COPY or supplier-rebuild interface. inventory/gitleaks-production.json requires the upgraded native tuples; historical profiles remain evidence, not fallback approval. tests/fixtures/gitleaks/Dockerfile retains a separate experimental label/identity and the same notice check. tests/fixtures/docker.rs is a Rust fake Docker executable, not a native-image fixture.
- Run cargo fmt --all -- --check, cargo clippy --all-targets --locked -- -D warnings, cargo test --locked. `check TOOL`/`check-all` are version smokes; `contract TOOL` adds mandatory checks and deliberately blocks incomplete tools. Run native cases serially; ignored evidence entrypoints require their explicitly approved public inputs.
- src/runtime_probe.rs: explicitly ignored, fixed-image local arm64 exit diagnostics; no mounts, retries or production acceptance. Stop at the first failure, retain bounded owned-container state/events and confirm removal before writing evidence. The loader-only reproducer does not execute Gitleaks/Git and does not authorize privileged host investigation or changes.
- licenses/gitleaks-runtime-evidence.json: captured public APK/recipe/selected-payload bindings for both hosted architectures, not complete corresponding-source/notices or approval. Keep historical identities and false completeness assertions intact.
- docs/tool-inventory.md: consumer workflow/source revision, versions, tool/runtime requirements and deliberate exceptions.
- docs/results.md: exact executed checks, architecture, findings and blocked work, not intended outcomes.
- .agents/skills/: maintain-tool-images, verify-tool-images and maintain-docs procedures.

Use native architecture tests before claiming support; a successful cross-build is not an execution test. Captured tuple baselines must come from unchanged native supplier output, not inferred versions/count thresholds; missing/UNKNOWN payloads or unreviewed architectures block. Keep analysis diagnostics blocking except the exact pinned Grype module-granularity precision notice authorized in docs/release-risk-policy.md, only for its known offline vulnerability invocation. Never enable matching filters or hide findings to silence diagnostics. Before publishing, require fresh image SBOMs, all-severity/ignored-match vulnerability gates, licenses/source review, immutable identity/provenance and explicit manual approval. Commit Cargo.lock and pin external GitHub Actions by full commit. Dependabot opens review PRs only; never auto-merge or auto-publish a dependency update. Public GHCR package visibility is separate from repository visibility and must be verified before claiming anonymous pulls.
