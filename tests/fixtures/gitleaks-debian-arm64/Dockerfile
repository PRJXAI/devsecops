# Native arm64 evaluation only. Partial Debian runtime, not a publication recipe.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --chmod=0555 candidate /usr/local/bin/gitleaks
COPY --chmod=0444 go-notices.txt /usr/share/licenses/gitleaks/GO-NOTICES.txt
COPY --chmod=0555 git /usr/bin/git
COPY --chmod=0555 loader /usr/lib/ld-linux-aarch64.so.1
COPY --chmod=0555 loader /lib/ld-linux-aarch64.so.1
COPY --chmod=0555 libc /usr/lib/libc.so.6
COPY --chmod=0555 pcre2 /usr/lib/libpcre2-8.so.0
COPY --chmod=0555 zlib /usr/lib/libz.so.1
COPY --chmod=0444 git-copyright /usr/share/doc/git/copyright
COPY --chmod=0444 libc6-copyright /usr/share/doc/libc6/copyright
COPY --chmod=0444 libpcre2-8-0-copyright /usr/share/doc/libpcre2-8-0/copyright
COPY --chmod=0444 zlib1g-copyright /usr/share/doc/zlib1g/copyright
COPY --chmod=0444 GPL-2 /usr/share/common-licenses/GPL-2
COPY --chmod=0444 LGPL-2.1 /usr/share/common-licenses/LGPL-2.1
COPY --chmod=0444 runtime.status /var/lib/dpkg/status.d/gitleaks-selected-runtime
COPY --chmod=0444 selection.json /usr/share/licenses/gitleaks/RUNTIME-SELECTION.json
ADD --chmod=0644 --checksum=sha256:e3884b252b3bfc045e55be43a34d1e80da070bc6f804ac95bf4660e97d62ebc6 https://raw.githubusercontent.com/gitleaks/gitleaks/83d9cd684c87d95d656c1458ef04895a7f1cbd8e/LICENSE /usr/share/licenses/gitleaks/LICENSE
LABEL devsecops.experiment="gitleaks-debian-arm64-not-for-publication"
ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_CONFIG_GLOBAL=/dev/null \
    GIT_TERMINAL_PROMPT=0 \
    LANG=C \
    LC_ALL=C
WORKDIR /tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/gitleaks"]
