# Built only by the fixed-source Rust driver: verified Go source/patch, offline race tests.
FROM cgr.dev/chainguard/git:latest@sha256:9af245693971eacc8414e52060ddaab20387a50908bb72fb3f142ba0bcf5d003 AS git
FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:709673274b417a48f56374da8a7633ef7b2f5b27e34612ce98a335737318cc94
COPY --chmod=0555 candidate /usr/local/bin/gitleaks
COPY --chmod=0444 go-notices.txt /usr/share/licenses/gitleaks/GO-NOTICES.txt
COPY --from=git /usr/bin/git /usr/bin/git
COPY --from=git /usr/lib/libpcre2-8.so.0 /usr/lib/libpcre2-8.so.0
COPY --from=git /usr/lib/libz.so.1 /usr/lib/libz.so.1
ADD --chmod=0644 --checksum=sha256:e3884b252b3bfc045e55be43a34d1e80da070bc6f804ac95bf4660e97d62ebc6 https://raw.githubusercontent.com/gitleaks/gitleaks/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/LICENSE /usr/share/licenses/gitleaks/LICENSE
ADD --chmod=0644 --checksum=sha256:5b2198d1645f767585e8a88ac0499b04472164c0d2da22e75ecf97ef443ab32e https://raw.githubusercontent.com/git/git/v2.56.0/COPYING /usr/share/licenses/git/COPYING
# Exact vendor Git/glibc corresponding source and redistribution review remain mandatory.
ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_TERMINAL_PROMPT=0
WORKDIR /tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/gitleaks"]
