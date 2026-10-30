# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b

# Latest released patch clients; same minor as the published kindest/node v1.37.0.
# Hashes: https://dl.k8s.io/release/v1.37.2/bin/linux/{amd64,arm64}/kubectl.sha256
# Source: https://github.com/kubernetes/kubernetes/tree/c50e5395f1ae2d4a2c05f28fdcc38c0916cc1a32
FROM scratch AS binary-amd64
ADD --checksum=sha256:c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4 --chmod=0555 https://dl.k8s.io/release/v1.37.2/bin/linux/amd64/kubectl /kubectl

FROM scratch AS binary-arm64
ADD --checksum=sha256:fcc16f63186659d9722014b7e02d5fdd2d4e669cb8c0ab66365d7d3b8ba03509 --chmod=0555 https://dl.k8s.io/release/v1.37.2/bin/linux/arm64/kubectl /kubectl

FROM binary-${TARGETARCH} AS binary

# Supplier license; complete embedded-dependency notice review is required before publication.

FROM cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9
LABEL org.opencontainers.image.title="kubectl" \
      org.opencontainers.image.version="1.37.2" \
      org.opencontainers.image.source="https://github.com/kubernetes/kubernetes" \
      org.opencontainers.image.revision="c50e5395f1ae2d4a2c05f28fdcc38c0916cc1a32" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=binary /kubectl /usr/local/bin/kubectl
ADD --checksum=sha256:cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30 --chmod=0444 https://raw.githubusercontent.com/kubernetes/kubernetes/c50e5395f1ae2d4a2c05f28fdcc38c0916cc1a32/LICENSE /usr/share/licenses/kubectl/LICENSE
ENV HOME=/tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/kubectl"]
