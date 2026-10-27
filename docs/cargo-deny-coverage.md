# cargo-deny supplied-graph result

**Blocked; the compiler-free image is not a full gate replacement.** Keep the consumer's host cargo-deny check and this repository's explicit contract failure. No incomplete result or diagnostic exception is approved.

## Native investigation

Eleven synthetic cases ran on native linux/arm64 with cargo-deny 0.20.2, fixed public itoa/bumpalo dependencies, Cargo-generated metadata, matching sparse index/cache/archive/source inputs and a separately retrieved, hash-verified RustSec checkout. Inputs were under 1 MiB, mounted read-only; no Cargo, compiler, Git, credentials or socket was mounted into the tool. Source/metadata retrieval used isolated host Cargo configuration; analysis was offline/nonroot with bounded capture, deadlines and unconditional removal. Native amd64 was not tested.

The clean licenses/bans/sources subset exited zero **with incomplete Cargo/index coverage diagnostics**. Removing cache/index/source inputs also produced nominal exit-zero results. License, ban and source negatives fired, but did not establish complete coverage. Both full advisory attempts failed before evaluation; this is not proof of advisory detection or an isolated missing-DB control. All eleven cases remain rejected. Final-filesystem checks passed separately.

## Pinned supplier behavior

Inspection of [0.20.2 source](https://github.com/EmbarkStudios/cargo-deny/tree/0.20.2) found:

- `src/cargo-deny/check.rs`: fetching is attempted before graph gathering even with supplied metadata; an offline flag does not eliminate the Cargo executable dependency.
- `src/cargo-deny/common.rs` and `src/lib.rs`: sparse-index/version discovery also invokes Cargo, and graph work can continue after coverage errors.
- `src/git.rs`: absent FETCH_HEAD freshness material can fall back to invoking Git. The verified read-only checkout did not satisfy that path. A genuine fetch layout may change this one condition; fabricating FETCH_HEAD is not acceptable.

## Next permitted choices

Prefer an upstream released mode that truly accepts a complete supplied graph/index identity without invoking Cargo, then repeat diagnostic-free all-check positives and independent advisory/missing-input/license/ban/source/coverage negatives. Alternatively, a separately reviewed change could expand the runtime policy to include its actual dependencies; that conflicts with the current package-manager-free image contract and is **not authorized by merely requesting implementation**. Do not supply fake executables or ignore diagnostics.

Exact bounded Rust reproducer, native captures, identities and source hashes remain private in `.work/approval-deny/REPORT.md`. No source rebuild, policy exception, image publication or consumer adoption occurred. Host storage still lacks a hard quota.
