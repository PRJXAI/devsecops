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
| Syft/Grype fresh release handoffs, publish and attestation | Required; record actual workflow result and digest before consumer adoption |
| Gitleaks | Exact Git/glibc source/overlay/notices/source-delivery review and retained loader-completion issue remain unresolved |
| cargo-audit/cargo-deny | Complete compiled Rust/native inventory absent; cargo-deny's full compiler-free coverage remains unproven |
| k3d | Packaged native control-plane and inventory incomplete; consumer host-CLI smoke is not equivalent |
| Docker/Kustomize/kubectl | Payload/dependency or UNKNOWN-version coverage remains incomplete |
| Package visibility | Public repository does not establish public GHCR access; anonymous pulls require verification |
| Host and private evidence | No host upgrades or real deployment; hard host-disk quota and durable private raw archive are not established |

Historical Go compiler/dependency experiments, Debian/native source evaluations and finite successful runtime batches do not erase failed suites, cap/deadline errors or the loader-only stall. They are not publication handoffs. No benchmark, native/provider/GUI certification or vulnerability-free claim is made.

Actual release identities are taken only from successful tool-specific `published-digests-TOOL` artifacts, never inferred from local tags or the counts above.
