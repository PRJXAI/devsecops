# Trust boundaries and current limits

Only public supplier artifacts and synthetic fixtures enter image tests. Customer data, operator credentials, current kubeconfigs and Docker sockets are never scanner inputs. Tools may be untrusted; pinned identity is not proof of benign behavior.

## Host and artifact authority

The OS/kernel, local Docker daemon, runner administration, repository/workflow source authorized for publication, and processes running as the runner's own UID are trusted. Use isolated ephemeral runners with no production authority. Private 0700 work directories exclude other users; leaf nofollow/type/size checks reject substituted symlinks and special files.

These checks are **not a race-free filesystem capability boundary against a concurrent same-UID or root attacker**. Parent directories can be replaced between checks, and Docker reopens archive paths after hashing. Such an attacker can also replace this program or Docker. Do not claim protection from that attacker without separately reviewed isolation/descriptor handoff. Tests demonstrate the distinction; ordinary artifact mismatch must still fail.

Unsigned receipts depend on authenticated same-workflow GitHub artifact delivery and trusted producers. Hashes detect substitution, not a malicious producer rewriting both receipt and data. Main/manual/readiness/source-SHA gates and final provenance remain required; repository protection and independent review are separate owner-side controls, not established by this code.

## Containers and output

Scanners have read-only inputs, no Docker socket, dropped capabilities, nonroot identity, bounded memory/CPU/PIDs/tmpfs and finite execution. Advisory retrieval is a separate public-network operation; analysis is offline. Output capture is private and capped; overflow, invalid data and cleanup failure are errors, never a clean result. No public raw provider errors or findings.

Host-side archive production and advisory-cache storage do not yet have a hard filesystem quota. A post-write size check is not a disk quota, and container RAM/time limits do not bound writable host mounts. Capacity/isolation work remains blocked under TASKS D4; do not describe the whole runner as storage-bounded.

## Publication

No real cluster or consumer repository is changed. False or incomplete publication readiness blocks registry writes even with manual inputs. Legal/source/provenance review, complete native functional coverage and all-finding scan success are prerequisites, not assertions inferred from a version command or a public repository. Partial registry writes are not a release; consume only digest-bound output from a fully successful approved run.
