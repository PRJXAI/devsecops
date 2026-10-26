# These digest-pinned indexes select the released linux/amd64 or linux/arm64 files.
FROM ghcr.io/gitleaks/gitleaks:latest@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f AS supplier
FROM cgr.dev/chainguard/git:latest@sha256:6b5b402aaba4db9a6446e363d70bcc158c773c5d00c75d4bcd68691fdaa539cc AS git

# Shell-free glibc supplies the architecture-specific loader and libc.
FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:5380a8b913d0900cf44180e2205bf3ebf0e0b00a32a0f2fa4ab16cb06d7f9cdf
COPY --from=supplier /usr/bin/gitleaks /usr/local/bin/gitleaks
# Only the builtin Git commands required for offline bare/all-ref history.
# COPY resolves the supplier library symlinks to their actual shared objects.
COPY --from=git /usr/bin/git /usr/bin/git
COPY --from=git /usr/lib/libpcre2-8.so.0 /usr/lib/libpcre2-8.so.0
COPY --from=git /usr/lib/libz.so.1 /usr/lib/libz.so.1
ADD --chmod=0644 --checksum=sha256:e3884b252b3bfc045e55be43a34d1e80da070bc6f804ac95bf4660e97d62ebc6 https://raw.githubusercontent.com/gitleaks/gitleaks/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/LICENSE /usr/share/licenses/gitleaks/LICENSE
ADD --chmod=0644 --checksum=sha256:5b2198d1645f767585e8a88ac0499b04472164c0d2da22e75ecf97ef443ab32e https://raw.githubusercontent.com/git/git/v2.56.0/COPYING /usr/share/licenses/git/COPYING
# Git corresponding source and complete native/embedded notices remain release gates.
# No shell, Git remote helpers, hooks, LFS or credential programs are supplied.
ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_TERMINAL_PROMPT=0
WORKDIR /tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/gitleaks"]
