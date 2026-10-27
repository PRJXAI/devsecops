# Third-party redistribution

Packaged tool binaries and base images retain their upstream licenses. Source URLs, versions and immutable artifact hashes must remain in Dockerfiles/inventory. Include supplier LICENSE/NOTICE files where provided.

[Supplier evidence](supplier-evidence.md) and its [artifact identities](artifact-evidence.json) record retrieved/verified facts and missing evidence, not approval. Docker CLI/Compose/Buildx and kind's provider now package their retrieved pinned top-level LICENSE/NOTICE files; full transitive coverage remains incomplete. [Official cargo-audit replacement](../docs/cargo-audit-supplier.md) supersedes the evidence snapshot's Quickinstall packaging, not its historical measurements.

Complete transitive notices and corresponding-source obligations (especially Git/GPL) require review before distributing images. The initial private source repository and local builds are not publication approval. Do not represent this page as complete legal review or relicense third-party binaries under the first-party license.
