---
name: maintain-tool-images
description: Add or refresh a pinned distroless CI tool image while preserving runtime closure, licenses and consumer contracts.
---

# Maintain tool images

1. Read AGENTS.md, README.md, docs/tool-inventory.md and docs/results.md. Inspect the actual consumer workflow/callers; never infer required behavior from a tool name alone.
2. Prefer a released, checksum/digest-pinned binary over a maintained fork. Verify linux/amd64 and linux/arm64 artifacts, version, executable path, loader/dependency closure and license/source obligations.
3. Update the smallest explicit Dockerfile. Final image must be pinned distroless/nonroot with no shell/package manager/compiler/config/secrets/DB. Do not add a template engine, generic rebuild framework or arbitrary scanner override.
4. Keep retrieval separate from offline use. Preserve CA roots, HOME/cache paths, writable tmpfs needs, exit codes, output formats, history coverage/redaction and resource bounds. Git-dependent tools must include and test a working Git closure.
5. Run Rust structural tests, native local builds and meaningful tool contracts. A cross-build or version string alone is insufficient. Record architecture, artifact identities, exact results and blocked checks.
6. Update inventory/results and maintenance docs. Dependabot PRs never auto-merge; coordinate literal artifact hashes, runtime closure and Rust expected-version contracts. Obtain owner review before changing consumer pins; publication is only through the explicitly approved main-branch manual workflow. Fresh SBOM/vulnerability/license/source/provenance checks and explicit registry authorization are publication prerequisites, not optional waivers.
