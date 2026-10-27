---
name: maintain-docs
description: Keep devsecops image inventory, Dockerfile usage, measured evidence and agent instructions aligned with verified behavior.
---

# Maintain documentation

1. Read AGENTS.md and changed Dockerfiles/tests before writing claims. Check git diff; distinguish requested scope, implemented files and executed tests.
2. Update README.md for actual CLI usage, AGENTS for real source/test ownership, inventory for versions/runtime exceptions, results for exact architecture/failures, TASKS for verified progress and the threat model for authority/resource limits. Separate historical measurements, configured CI, executed native checks and blocked acceptance.
3. Preserve source/license attribution and links. Never copy operator config, credentials, raw findings/provider errors or private evidence into tracked files.
4. Keep text concise. Do not add a docs framework or generated duplicate configuration. Check local Markdown links with Rust tests and review all affected pages.
5. Before commit, verify pins, documented commands and test results. Report unexecuted cross-architecture/security/license/provenance checks; no image publication or consumer adoption claim without approval.
