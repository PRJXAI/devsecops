# Hosted native inventory review — run 40571222293

## Evidence and decision

Reviewed the owner's approved local `catalog-evidence-amd64` and `catalog-evidence-arm64` downloads from [run 40571222293](https://github.com/PRJXAI/devsecops/actions/runs/40571222293), clean source **`9500de1196b51e2a27143b8188fe08908d4b1f13`**. Producer platforms: native Linux `ubuntu-24.04` amd64 and `ubuntu-24.04-arm` arm64. Both summaries say **`captured-not-release`**, not clean or release-approved.

[Native evidence](../inventory/native-evidence.json) records the run/source, literal scanner pin, schema, both summary hashes and **all 18 original report SHA-256/config subjects**. Approved local inputs remain under `.work/approval-hosted/catalog-{amd64,arm64}`; no copies or report rewrites were made. Private review observations are in ignored `.work/approval-native-review/observations.json`.

Every original report hash matches its hash-bound supplied summary and the recorded evidence. All 18 have Syft **1.55.0**, schema **16.1.11**, image/Linux/native-architecture metadata and `all-layers` scope. Embedded original config bytes hash to the reported config subject; embedded manifest bytes hash to its manifest digest and reference that config/size. Config architecture, OS, nonroot user, entrypoint, source URL and revision agree with report metadata and the approved source. cargo-audit's entrypoint includes its required `audit` argument. Summary scanner identity is `anchore/syft:v1.55.0-nonroot@sha256:ec5bdbc745485920c6f444239f0c09ed87b3c4c165ff9433f95bc66b3500fbf9`.

**Permit amd64 only for Syft, Grype and Gitleaks**, using the existing unmodified [payload tuples/compilers](../inventory/payloads.json). All three satisfy every current expectation on actual unchanged native reports, not architecture, package counts or capture labels. Their amd64 summaries originally said coverage `blocked` because that producer predated this review; labels were not upgraded into proof. Historical arm64 captures and their tests remain supported. Other architectures and the six incomplete amd64 profiles remain rejected.

## Actual 18 results

Counts below describe exact comparisons, never minimum coverage thresholds. Every required named/type/version/cataloger/location tuple matches on both architectures; there are no missing tuples or changed existing compiler expectations.

| Tool | Native amd64 | Native arm64 | Exact reviewed result / gap |
|---|---|---|---|
| Syft | Profile passes | Profile passes | 299/299 tuples, no extras/UNKNOWN; `/usr/local/bin/syft` compiler/stdlib `go1.26.8` |
| Grype | Profile passes | Profile passes | 323/323 tuples, no extras/UNKNOWN; `/usr/local/bin/grype` compiler/stdlib `go1.26.8` |
| Gitleaks | Profile passes | Profile passes | 74/74 tuples, no extras/UNKNOWN; compiler/stdlib `go1.24.13`; all Git/PCRE2/zlib/APK glibc/loader tuples retained |
| cargo-audit | Blocked | Blocked | 3/3 base APK tuples only; no Rust executable/crate/compiler/stdlib/static-native inventory |
| cargo-deny | Blocked | Blocked | 3/3 base APK tuples only; same missing Rust inventory |
| kind | Blocked | Blocked | 16/16 historical tuples plus two new provider tuples; unreviewed Docker path/compiler and UNKNOWN CLI main |
| Docker | Blocked | Blocked | 325/325 tuples; UNKNOWN CLI main and no third-party dependencies at CLI path; plugin inventories cannot substitute |
| Kustomize | Blocked | Blocked | 32/32 tuples; five UNKNOWN main/components |
| Kubectl | Blocked | Blocked | 93/93 tuples; nine UNKNOWN staging components |

Each architecture has 1,170 observed tuples versus 1,168 historical required tuples: the only additions are kind's `/usr/local/bin/docker` entries, both from `go-module-binary-cataloger`:

- `github.com/docker/cli/cmd/docker`, version `UNKNOWN`;
- `stdlib`, version `go1.26.10`.

Their `goCompiledVersion` is `go1.26.10`, at a path absent from kind's reviewed compiler map; the actual profile check rejects **“Go payload location has no captured compiler inventory.”** Kind's original executable still matches `go1.26.7`. Do not approve the new provider from its presence, infer its main version, or treat its two entries as complete dependencies. Disposable control-plane testing also remains separately blocked.

Docker's compiler remains `go1.26.10` at each CLI/Buildx/Compose location; its main `github.com/docker/cli/cmd/docker` version remains UNKNOWN. Kustomize (`go1.24.0`) retains UNKNOWN `command-line-arguments` and `sigs.k8s.io/kustomize/{api,cmd/config,kustomize/v5,kyaml}`. Kubectl (`go1.26.6`) retains UNKNOWN `k8s.io/{api,apimachinery,cli-runtime,client-go,component-base,component-helpers,kubectl,metrics,streaming}`. These exact names are recorded in evidence and checked against both native reports; CLI versions/labels do not repair them. Incomplete amd64 profiles reject at the architecture/profile allowlist; separate unchanged tuple evaluation establishes these underlying gaps on both architectures.

## Executed checks and limitations

Review/check execution is local Darwin/arm64 against the authentic hosted native documents, **not a new native tool execution**. No Docker/network, operator data, consumer repository, image rebuild, registry or approval change was used. No staging/commit/push was performed.

- `cargo test --locked --offline --bin devsecops coverage::tests::hosted_native_documents_match_summaries_and_current_tuple_criteria -- --ignored --exact`: passes; all 18 hash/config/source/schema/platform/scanner-summary bindings, every required tuple/compiler, exact extras/UNKNOWN sets and six-positive/twelve-blocked outcomes. Original bytes are reread unchanged. Disposable in-memory negative controls reject omitted stdlib, changed compiler and UNKNOWN versions; they are never saved/scanned as authentic reports.
- Coverage tests: 13 pass, two opt-in evidence tests ignored in the ordinary run. Existing arm64 tuple/removal/replacement/location/compiler/plugin/library/UNKNOWN negatives are retained; amd64 also exhaustively rejects deletion of every required positive-profile tuple. Unreviewed architecture spellings reject even a complete positive profile. The historical local evidence entrypoint was preserved, not re-executed against unapproved local paths.
- `cargo fmt --all -- --check` and `cargo clippy --all-targets --locked --offline -- -D warnings`: pass. An initial test-only cargo-audit entrypoint expectation was corrected to the actual argument-bearing contract; an initial Clippy `chunks_exact` suggestion was corrected, without suppressions.
- `cargo test --locked --offline -- --test-threads=1`: **90 passed, one failed, 15 ignored** across the library/binary. The failure is `release::tests::preflight_requires_all_eighteen_hash_bound_assets_before_any_docker_use` at `src/release.rs:1411`: its hard-coded expected error is the old architecture rejection, but an unrelated malformed amd64 catalog now reaches tuple validation and fails with `missing or invalid payload coverage field`. Rejection remains fail-closed. That out-of-scope test needs an owner-reviewed expectation update; this review does not change `src/release.rs` or remap production errors to manufacture a green suite.
- The ordinary parallel full-suite rerun additionally encountered `filesystem::tests::all_payloads_and_each_distinct_closure_file_are_required` failing to create a private log directory; it passed in the serial rerun. No filesystem/process policy was changed or failure waived. The full suite is **not claimed green**. Results include other agents' concurrent working-tree changes, not an isolated clean-source snapshot.

This review uses the [D2 trust boundary](threat-model.md): the owner authenticates same-workflow artifact delivery/producer and native runner attribution. Hashes detect mismatch; they do **not** independently authenticate a malicious producer rewriting artifacts and summaries. Config bytes are hash-bound, but no saved image archives were supplied/rehashed, no complete filesystem/layer closure was independently validated here, and no universal JSON Schema validation/registry framework was introduced. Scanner pin attribution depends on the trusted summary/producer; matching descriptor text alone does not authenticate the executable.

These are scanner-recoverable regression profiles, not exhaustive static-component attestation, functional/consumer acceptance, clean vulnerability scans, license/source/provenance sign-off or release acceptance. No tuple criterion, package threshold, symbol filter, finding/diagnostic gate or readiness approval was relaxed. All evidence acceptance booleans remain false; repository readiness was not changed. Fresh independently gated native functional tests, all-severity/ignored-match scans, complete redistribution/source/provenance review and manual workflow approval remain required. Existing [results](results.md), [inventory](tool-inventory.md) and [tasks](../TASKS.md) remain historical/prior-review context, not updated claims of release readiness.
