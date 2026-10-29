# Gitleaks native-runtime replacement

## Authorized scope and guarantees

The owner authorized evaluating a source-complete replacement for the in-image vendor Git/native runtime, retaining production until its required checks pass. This does **not** authorize changes to the host Docker/Engine/containerd installation or a privileged host investigation. The existing Gitleaks source, dependency patch, compiler, Go notices, sandbox, history/redaction controls and deadlines remain unchanged.

Evaluate released Debian 13 packages, not a new maintained Git/glibc fork. Bind selected amd64/arm64 binary packages to authenticated Debian release metadata and literal hashes; retrieve the corresponding source descriptors, original sources and Debian patch archives. Copy only the reviewed offline Git executable, its necessary dynamic library/loader closure, package-identification metadata and notices into a pinned distroless/nonroot image. No package-manager executable, shell, compiler, remote Git helpers, credentials or daemon socket may ship. Preserve source-package attribution for selected files, explicitly distinguishing partial packaging from a complete package-manager installation or dependency closure.

Keep retrieval separate from offline analysis and use bounded Rust-controlled I/O/cleanup. The old production profile must not authorize a replacement: preserve historical output and capture unchanged native catalogs, source/history/redaction/filesystem tests and policy-aware scans on both architectures before adopting a replacement profile. Missing inventories, source/notices or failures remain blocking. No new vulnerability exception, automatic approval, registry publication or consumer pin change follows from this experiment.

This replacement addresses supplier source availability. It is not a presumed fix for the independently reproduced loader/runtime exit stall; retain the earlier failure and distinguish candidate functional evidence from runtime diagnosis and release approval.

## Evaluation result — 2026-10-29

**Do not adopt this prototype.** Authenticated source availability improved, and the native arm64 functional contract passed, but the scan retained **26 blocking findings plus the existing one accepted finding**. Production, readiness approvals, host Docker and consumer pins are unchanged. No new exception, publication or hosted run occurred.

| Selected package | Binary version, both architectures | Corresponding source |
|---|---|---|
| Git | `1:2.47.3-0+deb13u1` | `git`, same version |
| glibc | `2.41-12+deb13u4` | `glibc`, same version |
| PCRE2 | `10.46-1~deb13u3` | `pcre2`, same version; security pocket |
| zlib | `1:1.3.dfsg+really1.3.1-1+b1` | `zlib`, `1:1.3.dfsg+really1.3.1-1` |

### What was verified

- Debian trixie and trixie-security `InRelease` signatures pass in isolated private GPG keyrings. Imported primary fingerprints are pinned to Debian's published archive/security/release keys for Debian 12 and 13; no operator keyring or trust configuration is used. Deliberately changed signed bodies fail. This trusts Debian's published HTTPS key fingerprints and signing infrastructure, not an independently reproduced build.
- Signed SHA-256/size entries bind six package/source indexes. The selected **eight binary packages and twelve source objects** were retrieved and rehashed; each `.dsc` source/version and both transitive source-file hashes match. The twelve objects are four descriptors, four original-source archives and four Debian patch/packaging archives or diffs. They supply the exact Debian source/patch material, not replacements for the old vendor's missing overlays.
- Read-only inspection captures **18 selected file bindings**, nine per architecture: Git, loader, libc, PCRE2, zlib and four package copyright files. Native ELF machine/interpreter/NEEDED/SONAME identities were inspected for both architectures. No package maintainer script or supplier build recipe ran.
- The local arm64 prototype uses pinned `static-debian13:nonroot` index `sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99`, selected native files, package copyright texts and GPL-2/LGPL-2.1 texts from the authenticated glibc source. Gitleaks is **byte-identical** to the historical Go 1.27.3 production executable; its 64 Go inventory tuples remain unchanged. The upstream race suite was not rerun or claimed as new evidence.
- Existing nonroot/ELF/CA/forbidden-file/Go-notice filesystem checks and source/deleted-secret/bare/all-ref/clean-HEAD/redaction controls passed, with unchanged deadlines and checked container removal. No shell, package manager, compiler or remote Git helper was added.
- Pinned Syft/Grype ran offline, with read-only inputs and a freshness-validated DB built `2026-10-28T06:23:30Z`, schema `v6.1.10`. The 74 observed packages are 64 Go modules and ten Debian package records; **a count is not complete inventory approval**.

### Scan outcome and remaining gaps

The scan reports **0 Critical / 3 High / 10 Medium / 3 Low / 10 Negligible / 1 Unknown**, zero suppressed. The 26 new blocking matches attribute to **glibc 21, Git 3 and zlib 2**. High findings are `CVE-2026-19499` and `CVE-2026-5435` on libc6, and `CVE-2026-85091` on zlib1g. The only accepted match remains `GO-2026-5932` on x/crypto `v0.58.0`.

All 26 native-package records have empty fix-version arrays and `not-fixed`/`wont-fix` state in this DB. **Those labels are not exception approval or proof of no viable alternative.** These are conservative package-level matches, not individual binary exploitability determinations. No finding was removed because only selected package files ship.

Complete acceptance still needs:

- remediation or separately accountable, exact review of every blocking finding; this experiment proposes **no new exception**;
- complete source/notices/provenance review of the six distroless base package records, the base signature/build provenance, and recipient source-delivery/relinking materials;
- review of non-ELF runtime dependencies: Debian libc6 declares `libgcc-s1`, which this minimal prototype does not package. Passing this offline fixture and checking NEEDED entries do not prove every dynamic-loading path complete;
- a full selected-file ownership/inventory profile. Experimental dpkg status records attribute the selected arm64 components conservatively, not a full installation. The embedded selection document preserves the two-architecture input plan, not an assertion that amd64 files ship in the arm64 image;
- genuine native amd64 execution and fresh two-architecture contracts/scans after remediation, plus resolution of the previously reproduced runtime-completion failure. No amd64 runtime test, base signature verification or renewed loader stress investigation ran here.

The prototype is deliberately outside production and CI handoff paths. Its Dockerfile is hash-allowlisted only as an experimental fixture; it cannot pass the production recipe policy. All source/notice/delivery/provenance/release approvals in [retained evidence](../licenses/gitleaks-debian-evidence.json) remain false. That file contains reviewed identities/counts, not raw scanner reports or legal sign-off.

## Replays and evidence

`src/debian_runtime.rs` owns metadata/package/source inspection and negative/integrity tests; `src/debian_candidate.rs` owns the fixed local arm64 experiment. The public source/asset identities and native archive/SBOM/report hashes are retained in the evidence above. Original private inputs remain required; these are not general download/build commands:

```sh
cargo test --locked --bin devsecops release::debian_runtime::authenticate_debian_runtime_metadata -- --ignored --exact
cargo test --locked --bin devsecops release::debian_runtime::inspect_debian_runtime_payloads -- --ignored --exact
cargo test --locked --bin devsecops release::debian_runtime::recorded_debian_sources_and_native_observation_keep_their_hashes -- --ignored --exact
```

The explicitly authorized `release::debian_runtime::candidate::native_debian_gitleaks_feasibility` entrypoint builds/tests/captures only. Its successful test result means the observation completed, **not that the vulnerability gate passed**. The observed prototype is retained under `.work/check-20345-1793280761614233000/`; no retry, suppression or successful-run substitution resolves its findings or the historical runtime failure.
