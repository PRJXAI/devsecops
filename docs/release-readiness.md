# Approval evidence work

Each tool's readiness booleans in `.github/publication-readiness/TOOL.json` remain false until its own evidence and accountable review are complete. Technical checks do not provide redistribution/provenance sign-off. Publication now operates independently per tool, still requiring both native architectures and complete inventory. The subsequent owner-approved [no-fix policy](release-risk-policy.md) permits exact reviewed findings as accepted-risk and the exact pinned precision warning as informational; all other findings/diagnostics/errors block. The [release isolation contract](threat-model.md) and [blocker map](release-blockers.md) supersede the former all-nine-tool approval scope.

## Current remediation contract — Gitleaks production build

The request to address remaining gaps authorizes adopting the already tested, fixed-source Gitleaks dependency upgrade into production packaging. Rust will construct a private, create-only context from the pinned source, patch and compiler; verify manifests before and after the offline upstream race tests/build; and package the checked executable plus the existing collected Go notices. No arbitrary prebuilt executable, caller-selected source/compiler, shared mutable build tag, retry or diagnostic waiver is introduced. Build failure or cleanup failure blocks packaging. The existing Git/native closure is unchanged and its source obligations remain unresolved.

Production inventory must require the upgraded tuples captured on both native architectures; the former supplier profile must no longer authorize production Gitleaks. Historical documents remain unchanged evidence. Fresh production contracts/catalogs/scans passed on both architectures at `818c362` in run 40712836198; later publication attempts still require new, source-bound, unexpired handoffs. Notice collection/packaging is not accountable redistribution approval; readiness remains false until its remaining evidence is complete.

## Execution order

1. Collect exact supplier artifact/source/attestation identities and license/notice coverage. Distinguish retrieved evidence, verified bindings, missing evidence and human review; never infer provenance from a version or checksum alone.
2. Resolve runtime contracts: provide kind's pinned Docker CLI dependency without granting socket access; prove cargo-deny's full supplied graph/cache/advisory coverage; investigate the Gitleaks clean-HEAD timeout without weakening deadlines or dropping controls.
3. Review available supplier updates against actual findings and compatibility. If no fix or viable alternative exists, record a narrow reviewed risk under the owner's policy rather than blocking indefinitely. Re-catalog unchanged native output; never fill UNKNOWN versions or omit findings. Accepted-risk is not clean.
4. Run both native architectures and preserve all counts/statuses, including accepted risks. Incomplete inventory, unapproved diagnostics, resource errors and failed functional cases remain blocking.
5. Request artifact-specific owner/reviewer sign-off only after its evidence is complete. Update only that tool's readiness record and remove only resolved blockers. Manually dispatch `main`, selecting the tool and both approval inputs; the Rust publisher binds approval to that tool and exact source SHA. `all` runs independent releases, not an atomic suite. No ad hoc pushes or consumer adoption.

## Changed guarantees before runtime changes

Kind may gain only the pinned Docker CLI executable required by its Docker provider. It remains distroless/nonroot, with no embedded configuration, credential helper, daemon or socket. Executable presence/version is not a cluster contract; control-plane testing still needs separately authorized disposable infrastructure. New payloads must fail inventory coverage until their real native catalog is reviewed.

Cargo-deny must reject missing Cargo/index/source/advisory coverage even if the supplier exits zero. A replacement contract must prove its negative controls and exact supplied graph; no stderr waiver or partial-check success may satisfy it. Gitleaks timeout investigation must preserve source/bare/deleted/all-ref/clean-HEAD/redaction checks and unconditional bounded removal.

## Implemented evidence and remaining work

- [Supplier evidence](../licenses/supplier-evidence.md) records verified subjects, source claims, exact hashes and missing proof. Docker CLI/Compose/Buildx and kind's provider package pinned top-level notices. Transitive notices and exact Git/glibc source obligations remain incomplete.
- [Official cargo-audit](cargo-audit-supplier.md) replaces Quickinstall with RustSec GNU artifacts and only verified runtime ELF files. Native arm64 audit controls pass; full provenance and Rust inventory do not.
- [Hosted native inventory review](native-inventory-review.md) verifies all 18 unchanged report hashes/config subjects from source `9500de1`; three scanner profiles meet unchanged tuple/compiler criteria on both architectures. Six other tool profiles remain blocked.
- [cargo-deny investigation](cargo-deny-coverage.md) proves why supplied metadata/exit zero is insufficient. The always-refusing prototype remains private; the existing production refusal is retained, rather than adding a duplicate runtime API.
- [Runtime completion investigation](runtime-completion.md) retains the Gitleaks timeout as a blocker; both speculative fixes failed controls and were reverted.
- [Supplier remediation](supplier-remediation.md) identifies compatible component targets but no current upstream tool release that clears all 104 captured matches. Source patch/dependency migrations or upstream maintenance releases need reviewed work. The subsequent no-fix decision permits only the exact reviewed Gitleaks advisory and precision notice, not a blanket waiver of these matches.

The original approval-sequence validation passed 92 ordinary tests, formatting, Clippy and actionlint, plus the explicit hosted-document, native notice-byte and official-audit controls; the later production/archive remediation results and reproduced runtime failure are recorded in [results](results.md). This is not release acceptance. No boolean has been set true, no image published and no consumer pin changed.

## Hosted release/adoption attempt — 2026-10-28

The owner's request to ship the containers and use them in obsidian-sync authorizes publication/adoption work, not assertions that missing source/legal or runtime evidence exists. Commit `818c362` was pushed and run 40712836198 completed: both Gitleaks production preparations passed with one accepted risk each; the other eight tools failed their own gates. Both experimental candidate jobs passed too, without resolving the recorded local completion failure. Publication jobs were skipped because this was a push, not an approved manual dispatch; no registry image or attestation was created.

Gitleaks's two downloaded handoffs pass the real content preflight at the original evidence time, including archive/config/SBOM hashes, captured inventory and exact risk accounting. This is not publication authorization or an actual archive-load/registry/attestation test. All approval fields remain false. Obsidian-sync's existing pins and host checks remain unchanged: no unverified GHCR digest or incomplete cargo-deny replacement is adopted. Its separate all-findings supply-chain policy is not silently relaxed to inherit a producer exception. See [results](results.md) for counts and exact remaining blockers.

## Replacement evaluation — 2026-10-29

The owner separately authorized evaluating a source-complete in-image replacement while preserving production and host Docker. [Debian evidence](gitleaks-debian-runtime.md) now binds both architectures' selected packages and source archives to signed release metadata. Its arm64 prototype passes the existing functional/filesystem controls but retains **26 blocking findings and one previously accepted finding**. No replacement profile/readiness approval, source-delivery sign-off, native amd64 acceptance or runtime-stall resolution follows. No manual publication dispatch or consumer change occurred.

## Gitleaks-first follow-up — 2026-10-29

The [runtime source review](../licenses/gitleaks-runtime-review.md) captures exact expanded public APK recipes and verifies 20 selected payload/package bindings against both hosted architectures. Missing source-overlay bytes, full notices/source delivery and accountable review remain explicit. The [loader-only diagnostic](runtime-completion.md) reproduces the 120-second exit stall without Gitleaks/Git execution, with confirmed cleanup. This is a narrower investigation target, not a fix or permission to alter the host. No readiness field or consumer pin changed; publication remains blocked pending those concrete prerequisites.

## Outstanding decisions

- An accountable reviewer must approve complete notices and exact corresponding-source arrangements, especially the patched Git supplier build.
- The Quickinstall artifact has been replaced with official RustSec GNU releases, but complete archive-to-build provenance, Rust/native inventories and added runtime redistribution/source obligations still require review. The older Quickinstall evidence remains historical, not current approval.
- Native inventory completion, supplier vulnerabilities and strict analysis diagnostics remain independent publication blockers.
- Host archive/export/advisory storage has no hard filesystem quota. No storage-bounded claim is made.
