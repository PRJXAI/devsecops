# Verification record

This page records delivered behavior and measured limits, not a rolling implementation diary. Earlier investigations remain in Git history and private captures; their failures are not relabeled successful by documentation consolidation.

## Current baseline

Source baseline before this delivery: `aaab990627e8f73fb89c5807193092324e3d004d`, hosted run [41074964808](https://github.com/PRJXAI/devsecops/actions/runs/41074964808). First-party checks and both experimental Gitleaks jobs pass. All production image preparations fail on their own inventory/contract/finding gates and publication is skipped. No package availability follows from that run.

The owner accepted the investigated stack risks on **2026-10-30**. Exact rules now retain Syft's **18** and Grype's **23** known matches as accepted-risk, subject to fresh scans and exact scope. Gitleaks's existing one-match rule remains separate. Known consumer infrastructure findings are recorded in its own policy; no cross-repository automatic inheritance occurs.

## Scanner delivery preparation

- Four unchanged native Syft/Grype catalogs from run 41074964808 were downloaded, hash/source/platform checked and compared. The two architectures have matching named/compiler tuple sets. Current profiles include the refreshed base, not the older package versions.
- Source-attributed legal bundles cover **295 Syft / 319 Grype modules** plus **38 Go 1.26.8 legal texts**. Original source bytes, module checksums/origins and file hashes are retained. Bundles are **3,570,412 / 3,776,816 bytes**, SHA-256 `5d56eacef92c66e40d44034914d53dc599f68542388aa91542e71cef8b88ac15` / `2a1096158a1f761a9366ddd7b99dfb01bd50aa1eea1299d7d8f0e8e4397e86a2`.
- Both new native Linux/arm64 filesystem/functional contracts pass, including exact packaged notice bytes/mode. Full local Syft preparation reports **18 accepted / 0 blocking**, retaining two Critical/ten High/two Medium/four Unknown matches. It is a dirty-worktree observation based on `aaab990`, not a clean release handoff. New native amd64 preparation and publication remain separate workflow gates.
- Full local Grype preparation failed with `refusing existing or unwritable evidence`; it produced no transferable handoff/public summary. Captures are retained. Host storage was subsequently observed at 100% reported utilization with about 3.2 GiB available; the exact I/O cause is unconfirmed. No cap was raised, evidence deleted, daemon changed or failed preparation called successful. Fresh ephemeral hosted preparation must independently qualify both architectures.
- A source-tree response exceeded its fixed 4 MiB retrieval cap. Collection was partitioned, not given a larger bound. The first filename selector missed `LICENCE`/`UNLICENSE`; source inspection corrected it. Both failures and the initial compile/lint/test setup failures remain private. No supplier test or resource limit was waived.
- First-party formatting, **130 ordinary tests / 37 ignored explicit diagnostics**, strict all-target Clippy and fresh dependency audit pass after correcting a synthetic archive-trailer offset for the larger notice fixture and preserving no-push/incomplete-inventory regressions. Original legal text triggered whitespace checks; three exact notice-only Git attributes preserve its bytes, with a negative test rejecting wildcard/driver exemptions. The initial unreviewed-attribute rejection remains captured.

## Remaining qualifications

| Area | Status |
|---|---|
| Syft/Grype fresh release handoffs, publish and attestation | **PASS**, both native architectures at `13edb5277101befe100a435f5ade8da6ea3d40af`; exact identities below |
| Gitleaks | Exact Git/glibc source/overlay/notices/source-delivery review and retained loader-completion issue remain unresolved |
| cargo-audit/cargo-deny | Complete compiled Rust/native inventory absent; cargo-deny's full compiler-free coverage remains unproven |
| k3d | Packaged native control-plane and inventory incomplete; consumer host-CLI smoke is not equivalent |
| Docker/Kustomize/kubectl | Payload/dependency or UNKNOWN-version coverage remains incomplete |
| Package visibility | **BLOCKED for anonymous consumption:** both token requests return 401; known-public control passes. Owner must make packages public or grant/configure explicit consumer Actions read access |
| Host and private evidence | No host upgrades or real deployment; hard host-disk quota and durable private raw archive are not established |

Historical Go compiler/dependency experiments, Debian/native source evaluations and finite successful runtime batches do not erase failed suites, cap/deadline errors or the loader-only stall. They are not publication handoffs. No benchmark, native/provider/GUI certification or vulnerability-free claim is made.

## Published scanner handoffs

Both independent runs completed successfully from source **`13edb5277101befe100a435f5ade8da6ea3d40af`**, including native amd64/arm64 preparation, actual archive-load/config checks, native pushes, two-platform index and provenance:

| Tool | Successful workflow | Published manifest digest | Per-architecture disposition |
|---|---|---|---|
| Syft | [41099233895](https://github.com/PRJXAI/devsecops/actions/runs/41099233895) | `sha256:7d484d97e289e8ba108ef17a7ecd9dbbbe457398b92f5f3d79219a6445aaaf2c` | **18 accepted / 0 blocking / 0 suppressed** |
| Grype | [41099238680](https://github.com/PRJXAI/devsecops/actions/runs/41099238680) | `sha256:3079a040326484d0b50ac28c7fc2fb25894a22170e81445ab90c400d091378e0` | **23 accepted / 0 blocking / 0 suppressed** |

These identities came from successful `published-digests-TOOL` artifacts. Credentialed `gh attestation verify` checks succeeded with exact source/signer digest, repository/reusable workflow, main ref and GitHub-hosted-runner enforcement. They do not certify vulnerability freedom or independent regulated approval.

The consumer's credential-free HTTPS check passed a known-public registry control but received **401 at both scanner token endpoints**. Its first unclassified attempt, later classified attempts and HTTP 403 package-metadata query (insufficient `read:packages` scope) remain retained. No token/body was logged or private package-access grant assumed. Public repository visibility is not public package access. The consumer subsequently verified operator-authenticated index/native-config/catalog bindings and provenance, then selected these exact source-bound Syft/Grype digests with explicit package-read CI authentication and no-new-risk reconciliation. Its amd64 registry scans retain **18 / 23 accepted** matches; local arm64 private-asset exports remain blocked on missing config/layer members despite cached pull success. Hosted package grants, complete consumer qualification and the separate pause inventory gap remain unresolved. This is not public-access or application-release approval; see the [consumer verification record](https://github.com/PRJXAI/obsidian-sync/blob/main/docs/results.md).

The redundant nine-tool push run was canceled in favor of these independent manual runs; no canceled result was used as release evidence. The earlier local Grype write failure remains a failed local observation, not retroactively completed by these fresh hosted successes.
