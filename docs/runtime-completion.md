# Gitleaks runtime completion investigation

**Unresolved and blocking.** The full source/deleted/bare/all-ref/clean-HEAD/redaction contract, exact exits, stream EOF checks, 120-second deadline and unconditional bounded removal are unchanged. No retry, output-based success, longer deadline or diagnostic waiver was added.

The original failure emitted a complete clean report but did not complete the attached Docker command within 120 seconds. Independent bounded controls also reproduced stalls for Gitleaks version-only invocations. Docker reported the containers running while its process-list query contained no processes; a separate wait operation also blocked. These observations locate the symptom beyond merely parsing Git output or draining Rust's capture sockets, but do not identify an Engine/containerd/runc/kernel cause.

The observed local runtime was native Linux arm64, Ubuntu 24.04.4/kernel 6.8.0-100-generic, Engine 29.2.1 and host CLI 29.4.0. No daemon settings, host internals, operator overrides or versions were changed. This is not evidence about every runtime or native amd64.

A safe Rust diagnostic collected 3,324 bounded native observations. Three stalls occurred across direct attach, split create/start and init-assisted cases. The diagnostic observation cutoff was 8 seconds, not a substitute for the production deadline. An init-assisted batch initially showed no stalls, but a subsequent batch reproduced one; the experimental fix and its fixtures were rejected and removed. Every diagnostic case reached checked owned-container removal. An isolated successful contract does not erase a failed case.

Private raw captures and rejected experiments remain under `.work/approval-gitleaks/`; only aggregate status is recorded here. Existing ordinary negative tests still pass. Resolution needs a controlled daemon/host investigation and repeatable native contract evidence, not a supplier or runtime update inferred safe from its version. Such host changes require explicit authorization and must not affect real workloads. Publication/readiness remains false.
