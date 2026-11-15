# Released multi-architecture supplier; advisory data is never baked into layers.
FROM anchore/grype:v0.121.0@sha256:621d56d1d68106b787022c81546f7e0a36202a25d1239f0c20195fab8c16f7ea AS supplier

FROM cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9
COPY --from=supplier /grype /usr/local/bin/grype
ADD --chmod=0644 --checksum=sha256:c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4 https://raw.githubusercontent.com/anchore/grype/afe2742527d98d822da06c9f32eed86fe3d193e0/LICENSE /usr/share/licenses/grype/LICENSE
# Retrieve a fresh DB separately; mount it read-only for network-disabled analysis.
COPY --chmod=0444 licenses/scanners/grype-NOTICES.txt /usr/share/licenses/grype/THIRD-PARTY-NOTICES.txt
COPY --chmod=0444 licenses/scanners/STATIC-BASE-NOTICES.txt /usr/share/licenses/static-base/NOTICES.txt
ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    GRYPE_CHECK_FOR_APP_UPDATE=false \
    GRYPE_DB_AUTO_UPDATE=false \
    GRYPE_DB_CACHE_DIR=/cache/grype
WORKDIR /tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/grype"]
