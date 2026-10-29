# Trust boundaries and current limits

Only public supplier artifacts and synthetic fixtures enter image tests. Customer data, operator credentials, current kubeconfigs and Docker sockets are never scanner inputs. Tools may be untrusted; pinned identity is not proof of benign behavior.

## Host and artifact authority

The OS/kernel, local Docker daemon, runner administration, repository/workflow source authorized for publication, and processes running as the runner's own UID are trusted. Use isolated ephemeral runners with no production authority. Private 0700 work directories exclude other users; leaf nofollow/type/size checks reject substituted symlinks and special files.

These checks are **not a race-free filesystem capability boundary against a concurrent same-UID or root attacker**. Parent directories can be replaced between checks, and Docker reopens archive paths after hashing. Such an attacker can also replace this program or Docker. Do not claim protection from that attacker without separately reviewed isolation/descriptor handoff. Tests demonstrate the distinction; ordinary artifact mismatch must still fail.

Unsigned receipts depend on authenticated same-workflow GitHub artifact delivery and trusted producers. Hashes detect substitution, not a malicious producer rewriting both receipt and data. Main/manual/readiness/source-SHA gates and final provenance remain required; repository protection and independent review are separate owner-side controls, not established by this code.

## Containers and output

Scanners have read-only inputs, no Docker socket, dropped capabilities, nonroot identity, bounded memory/CPU/PIDs/tmpfs and finite execution. Advisory retrieval is a separate public-network operation; analysis is offline. Output capture is private and capped; overflow, invalid data and cleanup failure are errors, never a clean result. No public raw provider errors or findings.

Archive-write remediation contract: Docker save/export stdout will be drained into create-only private files with the existing archive byte budgets enforced before every write. Overflow, timeout, cancellation, write/sync failure or incomplete EOF must fail; owned stopped containers still require unconditional bounded cleanup. Ordinary stdout/stderr keep their existing 8 MiB limits. No archive contents are loaded into memory in full and no partial capture is release evidence.

This is a per-stream write bound, not a filesystem quota. Advisory-cache host mounts, Docker/BuildKit storage and accumulated outputs across runs remain outside a hard host-disk quota. Capacity/isolation work remains incomplete under TASKS D4; do not describe the whole runner as storage-bounded.

## Experimental supplier replacement

The Debian Gitleaks prototype is test-only and cannot enter production handoff/readiness paths. Release-key fingerprints are pinned from Debian's published HTTPS records; signature/hash verification authenticates that supplier's package/source assertions, not independently reproduced binaries. Source inspection never executes maintainer scripts or supplier build recipes. Hash-checked selected inputs enter a private create-only context; the prototype reuses existing sandbox/capture/cleanup controls and changes no host/daemon settings.

Partial package attribution is conservative scan input, not complete installation, dynamic-loading closure or file-ownership approval. Reviewed advisory/package identities and counts may be retained as an allowlisted summary; raw reports/diagnostics stay private. All findings and existing production gates remain intact. No prototype pass or source archive can authorize a new exception, legal approval, host investigation or replacement of native two-architecture evidence.

## Publication

Release isolation contract (2026-10-28): one tool is the publication unit, still requiring both native architectures. Each allowlisted tool has its own GHCR repository, readiness record, source-and-tool approval, artifact names, preparation workspace, concurrency group and publish/attestation job. An unrelated tool's failure or the experimental Gitleaks job must not be a prerequisite. Shared first-party source checks and the pinned scanner/DB requirements remain genuine prerequisites, not optional dependencies.

Before any selected-tool tag/push, validate both of its fresh source-bound receipts, archive/config/SBOM/coverage identities and actual loads. Missing, duplicate, wrong-tool or wrong-architecture handoffs fail closed; another tool's readiness cannot authorize this one. Retain all finding counts and cleanup/resource limits. Under the owner's 2026-10-28 [reviewed-risk decision](release-risk-policy.md), an exact approved no-fix/no-viable-alternative finding is nonblocking but stays visible as accepted-risk. The exact pinned Grype precision warning is classified separately; other diagnostics and errors still block. Schema-3 receipts bind policy identity, private report hash and complete accepted/blocking/severity accounting; publisher checks also bind the exception to the verified SBOM. No aggregate approval or experimental candidate artifact may substitute for production evidence.

No real cluster or consumer repository is changed. False or incomplete selected-tool readiness blocks registry writes even with manual inputs. Legal/source/provenance review, complete native functional coverage and zero unapproved scan findings are prerequisites, not assertions inferred from a version command or a public repository. Partial registry writes are not a release; consume only digest-bound output after that tool's approved publish **and attestation** job succeeds. A failed sibling makes the overall workflow red but does not revoke a different tool's completed release.
