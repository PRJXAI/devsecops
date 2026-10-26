---
name: verify-tool-images
description: Validate local distroless tool images with Rust tests, offline synthetic fixtures and honest supply-chain evidence.
---

# Verify tool images

1. Read AGENTS.md and the inventory/results. Never use real credentials, vaults, cloud accounts, current kubecontext or unapproved remote Docker engines.
2. Run cargo fmt --all -- --check, cargo clippy --all-targets --locked -- -D warnings and cargo test --locked. Run `cargo run --locked --bin devsecops -- check-all` for serial native build/version checks. `prepare-release` adds inventories/scans/artifacts; `publish-all` is restricted to the approved main-branch manual workflow. Keep command/container lifetimes and resources bounded.
3. Verify each final image's UID/entrypoint, expected version, architecture, CA roots and absence of shell/package manager/compiler. Test loader/library closure by actually executing the image.
4. Exercise meaningful contracts: Syft formats/input coverage, Grype offline detection with separately fresh DB, Gitleaks seeded source/deleted bare history/redaction, kustomize rendering, kubectl offline client, Docker Compose config, Cargo audit/deny with curated metadata/DB/source inputs. Clearly mark any contract not executed.
5. Keep scanners network-disabled and socket-free; isolate read-only inputs from output/cache. Docker/kind socket access is privileged and separate. Do not create a real cluster or contact one for a version test.
6. Preserve all findings and scan errors. Check embedded binary/native dependencies as well as OS packages. Do not call an image clean merely because it has no package manager or fewer packages.
7. Keep raw output private in ignored .work; publish only approved statuses/counts/identities. Record exact results and license/source/provenance gaps. Only the approved main-branch manual workflow may publish after all native checks, all-severity/ignored-match scans and redistribution review pass. Never claim consumer compatibility from version smoke or bypass a failed gate.
