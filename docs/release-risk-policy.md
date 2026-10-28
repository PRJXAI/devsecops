# Release policy: reviewed risks without a fix

## Owner decision — 2026-10-28

The owner directed that an issue must not indefinitely block release when no fix or viable alternative exists. This supersedes the unconditional zero-match policy **for explicitly reviewed cases only**. A scanner's empty fix list alone does not establish that no viable alternative exists. Preserve every finding, severity and suppressed-match count. Report a qualifying release as **accepted-risk**, never clean or fixed.

The first approved case is Gitleaks's already-investigated OpenPGP module match. This decision is not legal/source/provenance approval, production adoption of the experimental candidate, permission to use real infrastructure, or a waiver of missing inventory/runtime evidence.

## Implemented scope and evidence

- Tool: `gitleaks`; package `golang.org/x/crypto`, exact version `v0.58.0`, type `go-module`, at `/usr/local/bin/gitleaks` in the unchanged SBOM.
- Advisory: [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), namespace `govulndb:language:go`, severity `Unknown`. At most one matching record per native image, including any scanner-suppressed copy.
- The retained advisory has no fixed-version event. The [dependency experiment](gitleaks-dependency-experiment.md) upgraded the version-addressable dependencies and found no OpenPGP source import: Gitleaks needs other x/crypto packages. The suggested ProtonMail OpenPGP replacement is therefore not a drop-in replacement for those bcrypt/scrypt/etc. dependencies. No viable released Gitleaks alternative removing this module-level match was identified by the retained [supplier review](supplier-remediation.md). This is not binary exploitability/absence proof.
- Before every handoff, a fresh, source-bound Grype report must still have an explicit empty fix-version array and the exact observed empty fix-state. A newly advertised fix, new related advisory, changed severity/advisory/namespace/package/version/location, additional match, unknown fix state or malformed evidence is not covered.
- Syft/Grype and any other no-fix findings are not automatically accepted: their specific alternative assessments and scope must be reviewed before adding a rule. No severity-wide, tool-wide or `only-fixed` filter is authorized.

The approved precision diagnostic is likewise narrow: the pinned Grype image's exact single warning that Go function symbols are unavailable and matching falls back to module granularity. It is advisory information, not a failed scan. Allow it only for the known offline vulnerability-scan invocation, record its presence, and retain conservative module matching. All other stderr, JSON diagnostics, scanner failures, malformed reports, stale DBs, incomplete catalogs and cleanup failures remain errors.

## Handoff and publication guarantees

Schema-3 receipts retain total/per-severity/suppressed counts, accepted and blocking counts, explicit exception IDs, diagnostic classification, policy identity and the raw private report hash. Source/tool/architecture/archive/config/SBOM bindings remain required. Raw reports stay private; the transferable record contains only allowlisted counts/statuses/identities. The publisher rechecks the selected tool's policy, counts/status consistency and exact SBOM package identity; it refuses any blocking count or unknown exception. These receipts still trust the authorized producer's report validation and authenticated same-workflow delivery, not a signature or an independent publisher rescan. Earlier schema-2 receipts cannot bypass this check.

No arbitrary expiry is invented for the owner's acceptance. Exact scope, current fix metadata, a fresh scan and the existing manual tool/source-bound publication approval are required each release. Withdraw or update the reviewed rule when a viable remedy becomes available. Acceptance does not remove the finding or authorize silent policy drift.

Both native architectures, complete runtime/inventory checks and applicable redistribution/source/provenance approval remain required independently per tool. A tool may be releasable with an accepted risk, but not with missing mandatory evidence.
