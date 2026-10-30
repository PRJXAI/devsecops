# Security and accepted risks

## Owner-selected stack

On **2026-10-30**, after the applicability investigation, the repository owner accepted the investigated current stack risks and requested image delivery. This includes known findings for which fixes exist; it is not a claim that the selected versions are patched or universally optimal.

[`inventory/accepted-risks.json`](../inventory/accepted-risks.json) binds Syft/Grype acceptance to exact Dockerfile hashes and explicit package/version/type/location/advisory/namespace/severity/fix/related-advisory identities and occurrence limits. The retained baseline is **18 Syft / 23 Grype matches per architecture**. The prior exact Gitleaks OpenPGP exception remains separately bounded. No raw finding, including suppressed/Unknown/Negligible, is removed.

Policy `owner-selected-stack-2026-10-30-v1` reports **accepted-risk**, not clean. New matches, extra occurrences, changed dependencies/locations/fixes/aliases and changed recipes do not inherit the snapshot. Review source and fresh evidence when updating a rule; the capture fixture writes proposals only, never auto-approves a new stack.

Risk acceptance does not approve absent inventories, failed native functionality, malformed/stale data, cleanup failures, missing legal material or production deployment. The sole informational diagnostic remains the exact pinned Grype module-granularity warning for its known offline invocation. Other diagnostics fail.

## What the findings mean

Module/package matches are not exploit demonstrations. Windows-only filesystem behavior and stated 32-bit overflow triggers differ from the reviewed Linux/64-bit setup. Offline batch invocation does not automatically expose a network server. It can nevertheless parse hostile files or poison its outputs.

The active host builder was observed at BuildKit 0.27.1; upstream's custom-frontend Seccomp/AppArmor issue is fixed in 0.31.1. K3s HTTP/2 and runtime gRPC availability issues remain conditional concerns. Private endpoints and short fixture lifetimes reduce exposure, not the underlying defects. No host-root exploit, production attack or privileged tracing was performed; this project does not upgrade the host daemon.

Static Go symbol inspection produced partial frontend/Gitleaks results but no usable symbol metadata for seven reviewed binaries. Absence of metadata is not absence of vulnerable code; binary symbol presence is not a call graph. No automatic “not affected” VEX is issued.

## Runner capacity and authority

Trust the OS/kernel, local Docker daemon, runner administration, authorized repository/workflow source and same-UID runner processes. Use isolated ephemeral workers without production credentials, tailnet access, customer data or a real kubecontext.

Private 0700 parents and nofollow/type/hash checks provide artifact hygiene against ordinary substitution. They are not a race-free capability boundary against root or a concurrent same-UID attacker; Docker reopens archive paths. Unsigned handoff hashes detect mismatch, not a malicious producer rewriting both data and receipts. Protected source/release refs and independent organizational review are separate controls.

Ordinary process streams are bounded to 8 MiB. Docker save/export stdout has pre-write create-only **16 GiB / 1 GiB** bounds, exact EOF/exit checks, cancellation and bounded cleanup. These are not a hard host-disk quota: public source-module caches, advisory data, Docker/BuildKit storage and accumulated work still require capacity management.

## Release boundary

One tool and two native architectures form a release unit. Both fresh source-bound archives, inventories, contracts, counts and policy receipts must validate; actual archive loads must identify the expected images **before any tag/push**. Wrong/duplicate/missing platforms, stale data and unapproved readiness fail. Candidate experiments and catalog-only artifacts cannot substitute for release handoffs.

Only the manually approved `main` workflow can publish. Native jobs have read-only authority; package-write/OIDC permissions exist only in the selected publish job. Attestation and package visibility are separate post-publication checks. See [releases](releases.md).

## Privacy and assurance limits

Only public supplier artifacts and synthetic inputs enter repository tests. Raw findings, logs, operator configuration and credentials are not public CI artifacts. Allowlisted summaries retain counts/status/identities; public inventories are separately scoped. A durable owner-approved private raw-evidence archive remains an operational decision.

Distroless is a packaging boundary, not malware detection, vulnerability freedom, a FIPS validation or regulatory certification. Source/notice collection does not prove reproducible supplier builds. [Redistribution records](../licenses/README.md) distinguish collected evidence, review and unresolved obligations. Risk acceptance is not a legal relicense or permission to use production infrastructure.
