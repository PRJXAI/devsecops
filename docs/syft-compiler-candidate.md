# Fixed-source Syft compiler candidate

## Evaluation contract

The dependency/image implementation starts with an isolated Syft 1.55.0 compiler candidate, not production adoption. Keep source commit `f15c3343e29dfb20cf6d82c820e7090b49808c96`, original Go manifests and upstream Linux build tags (`containers_image_openpgp,exclude_graphdriver_btrfs`). Use the already pinned Go 1.27.3 compiler. This measures compiler effects without claiming that compiler replacement fixes x/crypto or every current finding.

Rust owns fixed-input retrieval, hashing, bounded compiler lifecycle, offline build/tests, private create-only context, native contracts, inventory and scans. Only source/module acquisition has networking; disconnect the owned compiler before module verification/build/tests. It receives no Docker socket, operator configuration or credentials. New test-only fixture policy must not authorize a production local-COPY recipe or caller-selected source/compiler/executable.

The new Syft-specific budget is four CPUs, 8 GiB memory/swap, 256 PIDs, a 512 MiB source tmpfs and 6 GiB temporary module/build cache; module acquisition/build/upstream race suite have 600/600/900-second deadlines. Source capture retains the ordinary 8 MiB cap. Binary transfer is at most 128 MiB in existing capped 4 MiB captures; archive/scanner limits remain unchanged. These are per-operation bounds, not host storage quotas.

Build and transfer the executable before the race suite. Current execution releases only the owned normal build cache and serializes race-package compilation (`-p=1`) within the same cache/memory/deadline budgets; no tests are removed. If the suite fails, remove the owned compiler and retain the failure before analyzing the already built bytes. Later functional/scan observations must not imply that failed tests passed. Cancellation or unconfirmed cleanup aborts further analysis. No retries, changed upstream tests, extended deadlines or output-based success.

Keep module manifests and inventories unchanged. Compare the actual captured candidate modules/compiler to the supplier baseline without rewriting either report. Retain raw reports privately, all severity/suppression counts and explicit source/notice/provenance incompleteness. Scan the pinned compiler input as a separate asset. A failed suite, missing inventory, finding, compiler-input issue or legal/source gap is not a release pass. No Syft risk exception is introduced, and Gitleaks's exact exception does not apply.

## Results — 2026-10-29

The compiler-only arm64 candidate measures **18 → 4 blocking findings** against a freshly rescanned supplier using the same DB (`v6.1.10`, built `2026-10-29T06:23:34Z`): 0 Critical / 1 High / 3 Unknown, none suppressed or accepted. Filesystem/version and existing Syft JSON/SPDX/CycloneDX Rust-workspace/npm-development contracts pass. Original source manifests are unchanged. The captured binary inventory additionally reports `github.com/apparentlymart/go-textseg/v17`; only stdlib changes version, with no removed captured module. This is an observed binary metadata difference, not a claim that every source/module/build property is equivalent.

The four matches are go-jose 4.1.5 (`GHSA-mgcc-cww5-fp2q`, fixed 4.1.6), x/net 0.61.0 (`GO-2026-6866`, `GO-2026-6860`, fixed 0.62.0), and x/crypto 0.58.0 (`GO-2026-5932`, no published fix). Fixed-version resolution with checksum verification produces the [literal manifest-only patch](../patches/syft-1.55.0-dependencies.patch.txt): exactly two require-version changes and four added checksum lines, with unchanged compiler minimum/module membership and no replacement/exclusion. Before/after manifest and patch hashes are pinned in the test-only builder.

The patched arm64 executable passes the native filesystem/format/dependency controls before an interrupted cold DB refresh. A **separate fresh offline scan of those exact retained bytes**, using the prior freshness-validated read-only DB, measures **1 Unknown / 1 blocking / 0 accepted / 0 suppressed**: the same x/crypto advisory. This does not make the original full run successful or inherit Gitleaks's exception. [Reviewed identities/counts](../inventory/syft-source-candidate-evidence.json) preserve both experiments and false approvals.

## Retained failures and acceptance gaps

- The first acquisition attempt failed because the sumdb cache defaulted under read-only `/go`. `GOPATH=/tmp/go` supplies a writable owned cache; checksum verification remains enabled. The failed capture remains.
- The full compiler-only upstream race suite fails, including 6 GiB tmpfs exhaustion, missing archive/repository-root prerequisites and Docker-dependent fixtures. No Docker socket was mounted to satisfy it. The patched suite still has failed/incomplete prerequisite coverage; cache scheduling changes do not erase those failures. Complete upstream fixture acquisition/isolation needs a separately reviewed bounded route, not removed tests or unreviewed supplier build scripts.
- Cataloging the pinned **compiler image**, an independently required input, exceeds the ordinary **8 MiB stdout cap**. Its partial JSON is invalid and no compiler finding count is claimed. Limits/catalogers were not relaxed to obtain a pass.
- The patched full-run outer harness timed out during cold DB retrieval. Its remaining uniquely named scanner was inspected, removed and checked absent. The later read-only scan is separately labeled retained-binary evidence, not a retry-to-success replacement for that run. No host/daemon setting changed.
- No native amd64 candidate execution, production inventory adoption, complete module/native notices/source/provenance review, new risk acceptance or publication has occurred. All production Dockerfiles/engine pins/readiness and consumer pins remain unchanged.

## Reproduction and evidence

`src/syft_candidate.rs` owns one fixed-source Syft experiment and the patched variant; `src/syft_dependencies.rs` owns the fixed two-target resolution/negative controls; `src/syft_recorded.rs` rehashes retained captures and preserves failures. The low-level saved-config reader is reused internally; release-specific label/user/source checks in `config_digest` are unchanged. The exact fixture is test-only and cannot authorize production COPY policy.

Native entrypoints (create-only evidence directories; never discard old failures):

```sh
cargo test --locked --bin devsecops release::syft_candidate::native_syft_compiler_candidate -- --ignored --exact
cargo test --locked --bin devsecops release::syft_candidate::native_syft_dependency_candidate -- --ignored --exact
```

The retained compiler comparison integrity replay and patched-binary offline measurement have separate names/scopes:

```sh
cargo test --locked --bin devsecops release::syft_candidate::recorded::recorded_syft_compiler_observation_preserves_failures_and_all_matches -- --ignored --exact
cargo test --locked --bin devsecops release::syft_candidate::recorded::recorded_syft_dependency_binary_scan_preserves_all_blockers -- --ignored --exact
```

Private inputs/results are under `.work/check-92343-1793306260278154000/`, `.work/check-36842-1793308072826242000/`, `.work/syft-recorded-observation.json` and `.work/syft-dependency-captured-measurement/`. Positive replay completion means identities/measurements were checked, not that failed upstream suites, compiler coverage or security acceptance passed. No runtime deadline or scanner byte budget was increased.
