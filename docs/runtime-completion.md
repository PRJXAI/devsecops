# Gitleaks runtime completion investigation

## Current controlled investigation

The owner authorized executing the Gitleaks-first plan. The diagnostic uses only the previously captured immutable native arm64 production image, with no host/input/socket mounts and one owned container at a time. The first batch alternates Gitleaks's version command with the packaged glibc loader's version command. A separate loader-only batch never starts Gitleaks or Git. Both retain the 120-second deadline, exact exit/EOF, resource restrictions and checked cleanup. On the first failure, capture only that container's state/process/event evidence and stop: no retry or successful-run substitution. No daemon, runtime, host setting or unrelated workload is changed. A finite diagnostic pass alone cannot close the existing failure.

## Loader-only reproduction — 2026-10-29

`runtime_probe::native_loader_and_gitleaks_exit_diagnostic` completed 600 invocations (300 per command). That non-reproduction was not accepted as a fix. The separate `runtime_probe::native_loader_only_exit_diagnostic`, bounded to at most 6,000 invocations/30 minutes, **failed on invocation 931** and stopped immediately. The failing command was the packaged `/usr/lib/ld-linux-aarch64.so.1 --version`: **neither Gitleaks nor Git ran**.

After its 120-second timeout, bounded owned-container probes reported `Running=true`, a nonzero reported PID, `Dead=false`, `OOMKilled=false`, an empty state error and **zero process rows** from `docker top`. Captured events were `create`, `attach`, `start`, `top`, with no `die` event in the observed window. Forced owned-container removal succeeded. Total failed-observation time, including probes/cleanup, was 130,129 ms; the batch took about 277 seconds. No deadline was increased or failure retried.

Private evidence: `.work/check-59309-1793264271708217000/exit-diagnostic.json`, SHA-256 `29b0be545c512a54efd39201642fd8233c70186018bd05b63da27225fafb477e`, with a field-allowlisted `public-exit-summary.json`. All 931 cleanup records are confirmed. The preceding 600-case batch remains under `.work/check-16729-1793263625429581000/`. Input image engine identity is `sha256:c7b85a850c361ccacdef3f8e237704262a50c4427f0a8b8f5e25a4f315596c9b`, the earlier local production build, not new hosted provenance.

The captured stack is Docker client 29.4.0 / Engine 29.2.1, containerd 2.2.1, runc 1.3.4, native Linux arm64/kernel 6.8.0-100-generic. This establishes a reproducer **outside Gitleaks/Git execution**. It does not distinguish a loader, Engine, containerd, runc or kernel fault, prove that every earlier stall has the same cause, or justify changing timeout/init/exit logic. The next runtime step is a controlled disposable daemon/host comparison or scoped host-side trace, requiring explicit authorization before privileged access or host changes. Existing hosted Gitleaks successes are preserved, not substituted for diagnosis.

## Earlier observations

**Unresolved and blocking.** The full source/deleted/bare/all-ref/clean-HEAD/redaction contract, exact exits, stream EOF checks, 120-second deadline and unconditional bounded removal are unchanged. No retry, output-based success, longer deadline or diagnostic waiver was added.

Follow-up during production adoption on 2026-10-28: two local production arm64 preparation runs passed, but the subsequent separate candidate test again failed during its clean-working-tree scan after emitting a small clean report. The 120-second bound and unconditional removal remained enforced; no candidate inventory/scan success was claimed for that run. Its failed summary and private captures are retained. Production passes therefore do not resolve the runtime blocker. Separately, a Docker filesystem-export timeout introduced by streaming was corrected by progress-aware draining; that was a different, identified capture-throughput issue, not a fix for these tool-completion stalls.

The original failure emitted a complete clean report but did not complete the attached Docker command within 120 seconds. Independent bounded controls also reproduced stalls for Gitleaks version-only invocations. Docker reported the containers running while its process-list query contained no processes; a separate wait operation also blocked. These observations locate the symptom beyond merely parsing Git output or draining Rust's capture sockets, but do not identify an Engine/containerd/runc/kernel cause.

The observed local runtime was native Linux arm64, Ubuntu 24.04.4/kernel 6.8.0-100-generic, Engine 29.2.1 and host CLI 29.4.0. No daemon settings, host internals, operator overrides or versions were changed. This is not evidence about every runtime or native amd64.

A safe Rust diagnostic collected 3,324 bounded native observations. Three stalls occurred across direct attach, split create/start and init-assisted cases. The diagnostic observation cutoff was 8 seconds, not a substitute for the production deadline. An init-assisted batch initially showed no stalls, but a subsequent batch reproduced one; the experimental fix and its fixtures were rejected and removed. Every diagnostic case reached checked owned-container removal. An isolated successful contract does not erase a failed case.

Private raw captures and rejected experiments remain under `.work/approval-gitleaks/`; only aggregate status is recorded here. Existing ordinary negative tests still pass. Resolution needs a controlled daemon/host investigation and repeatable native contract evidence, not a supplier or runtime update inferred safe from its version. Such host changes require explicit authorization and must not affect real workloads. Publication/readiness remains false.
