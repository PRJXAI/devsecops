# Released multi-architecture supplier; advisory data is never baked into layers.
FROM anchore/grype:v0.121.0@sha256:621d56d1d68106b787022c81546f7e0a36202a25d1239f0c20195fab8c16f7ea AS supplier

FROM cgr.dev/chainguard/static:latest@sha256:9e2306b457ff71ce370043dc68c7b52bb1e6622c1c6c6714edbed57496f3116e
COPY --from=supplier /grype /usr/local/bin/grype
ADD --chmod=0644 --checksum=sha256:c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4 https://raw.githubusercontent.com/anchore/grype/afe2742527d98d822da06c9f32eed86fe3d193e0/LICENSE /usr/share/licenses/grype/LICENSE
# Retrieve a fresh DB separately; mount it read-only for network-disabled analysis.
# Embedded dependencies still require complete notices/SBOM review before publication.
ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache \
    GRYPE_CHECK_FOR_APP_UPDATE=false \
    GRYPE_DB_AUTO_UPDATE=false \
    GRYPE_DB_CACHE_DIR=/cache/grype
WORKDIR /tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/grype"]
