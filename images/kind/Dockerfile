# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b

# Released upstream binaries; hashes also recorded by the v0.33.0 release API.
# Source: https://github.com/kubernetes-sigs/kind/tree/407a9675e6d9af1200b5f57f9ca52ec6cdacce74
FROM scratch AS binary-amd64
ADD --checksum=sha256:aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d --chmod=0555 https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64 /kind

FROM scratch AS binary-arm64
ADD --checksum=sha256:20022bee6cfcd5086cb7234d218e3454e6090022f2a8f55d1fa7fcf42c3867a2 --chmod=0555 https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-arm64 /kind

FROM binary-${TARGETARCH} AS binary

# kind's Docker provider invokes the CLI; a socket cannot supply this binary.
FROM docker:29.9.2-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb AS provider

# Supplier license; complete embedded-dependency notice review is required before publication.

FROM cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9
LABEL org.opencontainers.image.title="kind" \
      org.opencontainers.image.version="0.33.0" \
      org.opencontainers.image.source="https://github.com/kubernetes-sigs/kind" \
      org.opencontainers.image.revision="407a9675e6d9af1200b5f57f9ca52ec6cdacce74" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=binary /kind /usr/local/bin/kind
COPY --from=provider --chown=65532:65532 /usr/local/bin/docker /usr/local/bin/docker
ADD --checksum=sha256:b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1 --chmod=0444 https://raw.githubusercontent.com/kubernetes-sigs/kind/407a9675e6d9af1200b5f57f9ca52ec6cdacce74/LICENSE /usr/share/licenses/kind/LICENSE
# Provider's top-level notices, not complete transitive legal approval.
ADD --checksum=sha256:2d81ea060825006fc8f3fe28aa5dc0ffeb80faf325b612c955229157b8c10dc0 --chmod=0444 https://raw.githubusercontent.com/docker/cli/a82e528901260c8df6073311379eac65f92db204/LICENSE /usr/share/licenses/docker/LICENSE
ADD --checksum=sha256:a8c869fbda819afb8d80e0ac19bac52e766bc6c19cb38cf94f52d64c4be2aab6 --chmod=0444 https://raw.githubusercontent.com/docker/cli/a82e528901260c8df6073311379eac65f92db204/NOTICE /usr/share/licenses/docker/NOTICE
ENV HOME=/tmp DOCKER_CONFIG=/tmp/docker
USER 65532:65532
# Cluster operations require separately authorized control-plane access; no socket is included.
ENTRYPOINT ["/usr/local/bin/kind"]
