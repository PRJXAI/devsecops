# Operating the tool images

## Runtime model

Each image has an exec-form tool entrypoint, UID/GID 65532, CA roots and a digest-pinned distroless base. Pass tool arguments directly. There is no shell or package installer. These images cannot serve as whole Actions jobs that require shell/Node or as application build environments.

Released images must be public: no consumer package-reader token is required or an acceptable availability workaround. Source-repository visibility is separate; owners must set each GHCR package to Public once. The post-provenance anonymous-access gate must pass before a delivery artifact is uploaded. See [release access instructions](releases.md#authorized-publication).

Use immutable manifest digests from a completed [release](releases.md). Pin Actions by commit and retain your own input, configuration and output ownership policy. CLI and Docker/Kubernetes **server** versions are separate dependencies.

## Mount and resource policy

- Provide only approved input directories, read-only. Use caller UID/GID when host ownership requires it.
- Keep the root filesystem read-only; drop capabilities and set no-new-privileges.
- Bound CPU, memory, PIDs, temporary storage, output and duration. Repository scanners use two CPUs, 3 GiB, 128 PIDs and a bounded noexec tmpfs.
- Separate input from output and advisory caches. Do not give a tool writable aliases of its input or earlier evidence.
- No Docker socket, operator HOME, current kubeconfig or real vault data in scanner containers.
- Networking disabled does not prevent a compromised tool from copying input into output. Treat reports as potentially sensitive and validate them before publication.

Host Docker storage, advisory caches and accumulated archives are not protected by a hard filesystem quota here. Provision isolated workers and monitor their capacity.

## Syft

`scan dir:/input`, `scan docker-archive:/input/image.tar` and the native JSON/SPDX/CycloneDX output formats are tested. JavaScript development dependencies and Rust workspace locks must remain covered. A nonempty package list is not sufficient when the main payload or a native dependency is missing.

Registry access is a separate network-enabled inventory operation. Do not silently allow network access during offline directory/archive analysis.

## Grype

The image does not contain an advisory database. Mount a dedicated writable cache for `db update`, then remount the completed cache read-only for `sbom:/input/syft.json` analysis. The image's cache root is `/cache/grype`; the release driver's analysis engine uses its explicitly configured cache path.

Keep automatic database/application updates disabled during analysis. Validate database schema and age separately; the release pipeline permits a database at most 72 hours old and receipts at most 24 hours old, with a five-minute future-clock tolerance. Failed retrieval must not fall back to stale data.

Do not enable `--only-fixed`, severity thresholds, symbol filtering or VEX suppression to implement risk acceptance. Preserve all effective and ignored matches. The Rust policy classifies the exact accepted snapshot after report validation. Only the pinned module-granularity precision notice is informational; other diagnostics fail.

## Gitleaks

The packaged derivative includes a minimal Git closure for local bare/all-ref history. Remote Git helpers, LFS and shell hooks are not part of the contract. Source/history checks use redaction, public/synthetic fixtures and independent bare mirrors, never an entire operator checkout with ignored private files.

Normal consumer scanning does not enable archive traversal or HTTP diagnostics. Those defaults narrow exposure but do not establish absence of all vulnerable code. Native completion and exact Git/glibc source/redistribution obligations still require their own acceptance.

## Cargo tools

`cargo-audit` expects a Cargo.lock and separately retrieved RustSec data. Missing/stale data and incomplete or filtered reports must fail. Official GNU binaries have individually checked native library closures.

Do not replace a host `cargo deny check` gate with the current compiler-free image: missing Cargo/index/source inputs can be nonfatal, and exit zero does not establish complete advisories/bans/licenses/sources coverage. Keep the existing full host gate until equivalence is demonstrated.

## Deployment clients

Kustomize rendering and kubectl offline client behavior are tested without a cluster. A real Kubernetes call requires explicit authorization and an explicit kubeconfig; never borrow the current context for tests.

K3d and Docker daemon access is privileged. The images contain no socket, daemon or configuration. Grant only separately authorized access on disposable workers, with private configuration, checked local endpoints, owned-resource cleanup and no production authority. K3d's node, tools and pause images are separate dependencies, not embedded in this CLI image.

## Failure handling

Retain private bounded logs. Distinguish findings, accepted risks, missing inventory, malformed reports, deadlines, resource overflow and cleanup failures; none is interchangeable with a clean result. Do not retry a failed contract until it happens to pass or increase a budget to conceal a failure.

A blocked `prepare-tool` emits an Actions error annotation containing the same allowlisted JSON as `security-status-TOOL-ARCH/summary.json`. Inspect `setup` and `tools[].stage`/`reason` to distinguish shared scanner setup failures from tool qualification failures. Raw supplier errors and scanner output remain private. Push/PR runs use `build-tool` for all nine tools: native version/identity, filesystem and implemented synthetic functional checks. Cargo-deny and k3d explicitly report unavailable functional qualification, never a passing full contract. Public inventories remain captured for all tools. Syft/Grype require `prepare-tool` on every run; scheduled/manual runs require it for all selected tools. A build-only result cannot authorize publication.

A failed sibling tool does not invalidate another tool's fully completed release. Conversely, a partial registry push or version-only smoke is not a release. Check that tool's publish/provenance job, immutable subjects and package access before adoption.
