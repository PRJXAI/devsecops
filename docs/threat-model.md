# Trust model

## Inputs and authority

Only public supplier artifacts and synthetic fixtures enter tests. No real vaults, buckets, production clusters, operator kubeconfig or customer credentials. Repository source/workflow authorized for release, runner administration, the OS/kernel, local Docker daemon and same-UID processes are trusted.

Private parents, bounded regular-file reads and hashes reject ordinary substitution; they are not race-free protection against trusted same-UID/root mutation or a malicious producer rewriting both an artifact and its unsigned receipt. Docker reopens archive paths. Authenticated workflow artifact delivery, protected source and independent organizational review remain separate controls.

## Analysis containment

Read-only inputs/root, caller identity, dropped capabilities, no-new-privileges, finite CPU/memory/PIDs/tmpfs/time and bounded private captures. Retrieval is separate from offline analysis. No scanner socket or writable alias of inputs/earlier evidence. Network isolation does not prevent disclosure through reports; validate and allowlist published outputs.

Ordinary streams retain 8 MiB bounds. Docker save/export use pre-write create-only 16 GiB/1 GiB capture limits with exact EOF/exit, cancellation and bounded cleanup. Host caches, Docker storage and accumulation lack a hard filesystem quota. No whole-host storage-bound claim is made.

## Accepted risks and release boundary

The owner accepted the exact investigated current stack on 2026-10-30. The [security policy](security.md) records explicit scope and conservative remaining gates. Accepted findings remain visible and are never called fixed. New findings, changed scope and missing evidence do not inherit approval.

Each tool requires both native source-bound handoffs. Validate archive/config/SBOM/report/coverage/assessment and actual loads before any tag/push. Manual main/tool/source approval and its own readiness are required; no sibling, aggregate or experimental artifact supplies approval. Only the publish job gains package-write/OIDC authority. Provenance completion and package access are separate from upload success.

Complete source/notice review, native functional coverage and inventory remain required. Rootless/distroless packaging is not a guarantee of benign suppliers, complete static inventory, reproducibility, regulated readiness or authorization to deploy. See [releases](releases.md) and [redistribution](../licenses/README.md).
