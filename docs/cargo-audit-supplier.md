# cargo-audit supplier evidence

The 2026-10-30 owner-authorized refresh selects official **0.22.2** GNU artifacts and a refreshed pinned glibc closure. New artifact hashes are literal in `images/cargo-audit/Dockerfile`; both downloads were rehashed and native arm64 controls pass, as recorded in [results](results.md). The **0.22.1 evidence below is historical** and does not approve the new binary, libraries, provenance or redistribution.

Official RustSec GNU release artifacts replace the distinct Cargo Quickinstall arm64 supplier. This is a runtime/supplier change, not publication approval. Version and `[/usr/local/bin/cargo-audit, audit]` entrypoint are unchanged. Readiness remains false; [release gates](release-readiness.md) and the [trust boundary](threat-model.md) still apply.

## Artifact identity

Public release: `rustsec/rustsec`, tag `cargo-audit/v0.22.1`.

| Target | Official archive SHA-256 | Bytes |
|---|---|---:|
| aarch64-unknown-linux-gnu | `4c8df835ee484441bd2c8c6bcac28c4ce4b4058ba9e7477cb9e0012fe7769f66` | 5,819,816 |
| x86_64-unknown-linux-gnu | `1890badd5f15831a9af4b074399fcd21e6f7c0fe42c84e9254cdffc9f813765c` | 6,315,030 |

Both downloads were independently hashed and size-checked against the supplied public release API evidence and a fresh anonymous API capture. Extracted executable SHA-256: arm64 `9b31d2db0cae94cea882e55175ac4035e6655b42113715aaa1b167aa4b7f6f16`; amd64 `9899e591c3abee79bd54e88c3b03d27bcf8dd073fb1690af9cd3089be1267a67`.

## Minimal native ABI closure

Final base remains `cgr.dev/chainguard/static` index `sha256:17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde`, with CA roots and UID/GID 65532. Individual regular ELF files come from the existing repository-pinned `cgr.dev/chainguard/glibc-dynamic` index `sha256:5380a8b913d0900cf44180e2205bf3ebf0e0b00a32a0f2fa4ab16cb06d7f9cdf`; the whole dynamic rootfs is **not** inherited or copied.

| Architecture | Interpreter | Copied regular files under `/usr/lib` |
|---|---|---|
| arm64 | `/lib/ld-linux-aarch64.so.1` | `ld-linux-aarch64.so.1`, `libc.so.6`, `libm.so.6`, `libgcc_s.so.1`, `libpthread.so.0`, `libdl.so.2` |
| amd64 | `/lib64/ld-linux-x86-64.so.2` | `ld-linux-x86-64.so.2`, `libc.so.6`, `libm.so.6`, `libgcc_s.so.1` |

ELF program headers, DT_NEEDED and GNU version tables were captured for both official executables and every copied native object. Recursive dependencies close on these sets; loaders have no DT_NEEDED. The Rust evidence check matched all 23 arm64 and 41 amd64 provider/version namespace requirements against the copied objects' definitions, and found no RPATH/RUNPATH. This is static ABI evidence on amd64, not a native execution claim. arm64 executable requires GLIBC through 2.18, amd64 through 2.39; the pinned supplier provides glibc 2.44 and libgcc 16.2.0. No extra supplier is needed. The static base's `lib -> usr/lib` / `lib64 -> usr/lib` aliases supply the actual interpreter paths. No ld.so cache, libstdc++, ldconfig, compiler, shell, package-manager executable or advisory DB is copied from the dynamic supplier. Base defaults are not operator configuration or credentials.

Filesystem contracts require each native regular ELF and CA PEM, the exact interpreter-directory alias, and reject extra ELF payloads outside this closure. Missing, aliased, malformed and foreign-architecture closure fixtures remain blocking. Docker policy checks the explicit two-architecture stage graph, official URLs/hashes, same-source executable selection, runtime pins and exact file copies, in addition to existing nonroot/entrypoint/network/extraction restrictions.

## Source, provenance and redistribution

The public annotated tag object is `c9f8506963a0050a7b53ce4d3781baa9485c7a89`, pointing to source commit `efcde93a237dc51f8c32d84d880bf97b442835c8`. GitHub's API reports its SSH signature verified/valid; no independent maintainer-key verification or reproducible build is claimed. A tag signature binds source, **not these archive bytes**. Release `target_commitish: main` is not a binary/source binding.

The pinned supplier's selected manifests are arm64 `sha256:f484fa2aaff355191fef1154f4b12defeb21f0099ebaff19006eb2723e6df045` and amd64 `sha256:fde84b5b973f0e1145c7cbde86811a64155c6d6557f0d57953d91f955bc449e2`. Supplier signatures/build provenance were not independently verified.

Anonymous GitHub archive-attestation API requests initially failed at transport (curl exit 56); bounded retries returned HTTP 404 for both exact archive digests. No archive attestation was retrieved or verified. The release workflow captured at the source commit builds these GNU targets and uploads archives, but contains no attestation-generation step. This does not prove attestations cannot exist elsewhere, nor bind the actual release bytes to that workflow execution.

The existing Apache/MIT licenses, README and changelog remain packaged from the official amd64 archive. Their bytes match the arm64 archive and all four final packaged files; the final executable and six runtime ELF objects were also byte-compared to the verified archive/pinned supplier. Full transitive Rust/native notices, corresponding source for added glibc/libgcc and accountable redistribution/provenance review remain outstanding. A binary hash and same-repository download do not complete provenance, vulnerability acceptance or Rust dependency inventory. No SBOM baseline was fabricated or changed; cargo-audit's existing missing Rust inventory still blocks publication.

## Execution and remaining blockers

Private evidence/harness: ignored `.work/approval-official-audit/`. The Rust-only harness captures bounded direct tool invocations, archive identities, ELF details, public API evidence and an isolated copy of unchanged production code. Its initial candidate ran the real endpoint-bound `Driver::check` and `contract cargo-audit`: native Linux arm64 version, stopped-container filesystem and clean/vulnerable/missing-DB controls passed, with separate public RustSec retrieval and offline analysis. No Grype DB was downloaded.

Final production-code evidence is retained under `.work/approval-official-audit/native-final/` (original Driver directory `.work/check-75971-1793130543457140000/`). Local linux/arm64 engine image identity: `sha256:c8c75f5bc3caba172fcbc17ec3b6cc12712bd3945b9ac531addd926aa72c1cff`; this is a working-tree build labeled revision `local`, not a registry digest or clean-source release.

Executed on Darwin/arm64 against the native linux/arm64 local Docker daemon:

| Check | Result |
|---|---|
| `cargo run --locked --bin devsecops -- contract cargo-audit` | Passed: 0.22.1 version, UID/architecture/entrypoint, CA and exact ELF filesystem closure, clean audit, seeded vulnerable audit (required finding/exit 1), missing DB (specific failure/exit 1); unconditional cleanup retained |
| `cargo test --locked --lib` | 12 passed, including official supplier/closure substitutions |
| `cargo test --locked --bin devsecops filesystem::tests::` | 9 passed, 2 ignored; all critical omissions/aliases and extra/foreign/malformed ELF negatives retained |
| `cargo fmt --all -- --check` | Earlier integrated run passed; later concurrent-tree rerun failed in parent-owned `src/coverage.rs` |
| `cargo clippy --all-targets --locked -- -D warnings` | Earlier integrated run passed; later rerun failed on `src/coverage.rs:278` (`chunks_exact` constant chunk-size lint) |
| `cargo test --locked` | Earlier integrated run: 89 active tests passed (12 library + 77 binary), 14 ignored. Later concurrent-tree rerun: library 12 passed; binary 76 passed, 1 failed, 15 ignored |
| Native amd64 build/runtime/contracts | Not executed; static archive/loader/library ABI inspection only |
| Fresh image SBOM/vulnerability scans | Not executed; no clean-scan or Rust inventory claim |

The later binary failure is `release::tests::preflight_requires_all_eighteen_hash_bound_assets_before_any_docker_use` at `src/release.rs:1411`: actual `missing or invalid payload coverage field`, expected `payload coverage lacks reviewed native architecture evidence`. It appeared with concurrent parent-owned coverage/release edits, after the earlier green run; those files were not changed or repaired in this scoped work. Raw command outputs/statuses for both runs are retained. Final scoped reruns still pass: owned-file rustfmt, library Clippy, all 12 library tests and all 9 active filesystem tests (2 ignored). Do not report the latest whole tree green.

Native amd64 acceptance, complete Rust/native inventory, fresh all-finding scans, complete notices/source/provenance review and manual approval remain blockers. Cross-build/emulation is not native acceptance. No registry writes, consumer access, clusters, operator inputs or tool-mounted Docker socket were used. Parent-owned summary/inventory/readiness documents are intentionally not edited by this scoped change; historical Quickinstall/static descriptions there need parent reconciliation.
