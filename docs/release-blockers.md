# Release unblock work — 2026-10-28

## Why the local Gitleaks image is not yet published

There are two different objects: the **experimental upgraded Gitleaks image**, and this repository's **nine-image release**. The current publisher releases all nine tools on both architectures together: 18 fully validated handoffs must pass before any registry mutation. It has no Gitleaks-only release route. A successful Gitleaks experiment therefore cannot satisfy cargo-deny, kind, other inventories or supplier-source obligations. Changing that release scope requires a separately reviewed design, not silently dropping assets or tests.

The three readiness booleans are aggregate assertions, not missing configuration defaults. They must not be flipped merely because the owner wants publication. This page decomposes the actual missing evidence and assigns concrete work, rather than asking the owner to investigate unexplained false fields.

## Work and closure criteria

| Blocker | What is actually missing | Closure work / owner |
|---|---|---|
| Upgraded Gitleaks native evidence | Previous dependency experiment ran only arm64, not amd64; its inventory is not the production profile | Engineering: reproducible Rust-owned native candidate build, race/functional/filesystem checks and unchanged inventories on both hosted architectures; review exact tuples afterward |
| Diagnostic/finding gate | The measured arm64 derivative retains one Unknown OpenPGP module-level match and nonempty scanner diagnostics | Engineering: retain all results. Owner accepted the specific finding's risk, but the existing mandatory zero-findings/diagnostics policy is unchanged; no waiver/filter or clean claim is implemented. Additional upstream remediation is still needed under that policy |
| Nine-tool runtime contracts | Seven original tool contracts passed on both hosted native architectures; cargo-deny completeness and kind control-plane acceptance did not | Engineering: obtain a genuine complete supplied-graph cargo-deny mode or a separately reviewed runtime-policy decision. Kind testing needs separately authorized disposable infrastructure; never use the current context |
| Six other inventories | Rust executable/crate metadata is absent; Docker's main/dependencies and Kubernetes staging components include UNKNOWN/unreviewed payloads | Engineering/upstream: obtain real recoverable native binary metadata or verified replacement artifacts, then recatalog unchanged output. No filling versions from CLI strings or lowering coverage thresholds |
| Exact corresponding source/notices | The copied Git/glibc/native packages are vendor builds; their exact stereo recipes/patches are not publicly supplied by the retained evidence | Engineering/supplier: obtain the exact source/build/patch bundle, or separately review a replacement built from fully available pinned sources; collect actual embedded/base dependency notices. Existing public Wolfi recipes are not proof of the private supplier's build |
| Accountable provenance/redistribution review | Technical hashes and source collection do not by themselves establish all legal/source obligations or supplier build provenance | Engineering assembles the artifact-specific dossier; an accountable owner/reviewer evaluates it. A model cannot supply a fictional legal sign-off or treat acceptance of one vulnerability as license/provenance approval |

The repository's existing host-storage-quota and end-to-end registry/attestation acceptance limits remain documented in [TASKS](../TASKS.md) and the [threat model](threat-model.md). Real clusters, provider credentials, consumer adoption and ad hoc registry pushes remain outside this work.

## Implemented native-candidate step

`src/gitleaks_candidate.rs` is an opt-in test module, not a production CLI or publisher. It retrieves the fixed source into capped private capture, checks the source/patch/manifests, and uses a digest-pinned Go 1.27.3 container. Only module retrieval has network access; the owned build container is explicitly disconnected before module verification, the complete upstream race suite and compilation. Source/cache tmpfs, CPU/memory/PIDs, process deadlines and unconditional container removal are bounded. No host configuration or Docker socket is supplied to that container.

The final image uses one explicit reviewed fixture Dockerfile: only the verified candidate executable and the existing pinned runtime closure are copied. Its fixture-specific policy is hash-bound; production Docker policy remains unchanged. Input hash/create-only/nofollow and fixture mutation negatives persist in ordinary tests. Every compiler/manifests/version/module expectation is literal and narrow; this is not a general supplier-rebuild framework.

An initial local attempt passed upstream race tests and compilation, then failed because Docker copy could not see the live tmpfs output. The failed measurement/status is retained. Transfer now uses at most 16 capped 4 MiB captures into a create-only, synced file, verifies exact total length and SHA-256, and never raises the existing 8 MiB stream cap. The subsequent local native arm64 build, race suite, version/Git/final-filesystem/source/history/redaction checks and unchanged native inventory capture pass. That is **functional/inventory evidence only**; no vulnerability scan or release approval is implied.

CI runs this exact test on both native image runners even if original preparation fails, then uploads only `gitleaks-native-candidate-{amd64,arm64}` inventory/status artifacts. It does not upload private compiler/scanner logs or candidate archives, produce release receipts or alter publication prerequisites. Hosted results must be observed before the amd64 gap can be closed.

Local validation: 96 ordinary tests (13 policy + 83 binary), 17 fixture/opt-in entrypoints ignored in ordinary enumeration; fmt and strict all-target Clippy pass. The explicitly executed native candidate test passes on arm64 after the transfer fix. An initial SHA-256 formatting compile error was corrected, not suppressed. No readiness field or finding/diagnostic policy changed; nothing has been published.
