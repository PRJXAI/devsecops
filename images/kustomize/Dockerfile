# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b

# Released upstream archives; hashes also recorded by the kustomize/v5.8.3 release API.
# Source: https://github.com/kubernetes-sigs/kustomize/tree/6e4452f7b136fb9a261afe60830867a875183a71
FROM scratch AS archive-amd64
ADD --checksum=sha256:cb9e31198d3f63b44848bd0afc4c8efc56e6cfef9c93a4a39a211940e6decd61 https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v5.8.3/kustomize_v5.8.3_linux_amd64.tar.gz /kustomize.tar.gz

FROM scratch AS archive-arm64
ADD --checksum=sha256:9867b76482cfc6d25b546abc1d2b5a32bd137505aba640649b4b378f64f6d68f https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v5.8.3/kustomize_v5.8.3_linux_arm64.tar.gz /kustomize.tar.gz

FROM archive-${TARGETARCH} AS archive

# Extraction only, on the builder architecture; no compiler or source rebuild.
FROM --platform=$BUILDPLATFORM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS extract
COPY --from=archive /kustomize.tar.gz /tmp/kustomize.tar.gz
RUN --network=none ["mkdir", "/out"]
RUN --network=none ["tar", "-xzf", "/tmp/kustomize.tar.gz", "-C", "/out", "kustomize"]

# Supplier license; complete embedded-dependency notice review is required before publication.

FROM cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9
LABEL org.opencontainers.image.title="kustomize" \
      org.opencontainers.image.version="5.8.3" \
      org.opencontainers.image.source="https://github.com/kubernetes-sigs/kustomize" \
      org.opencontainers.image.revision="6e4452f7b136fb9a261afe60830867a875183a71" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=extract --chmod=0555 /out/kustomize /usr/local/bin/kustomize
ADD --checksum=sha256:b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1 --chmod=0444 https://raw.githubusercontent.com/kubernetes-sigs/kustomize/6e4452f7b136fb9a261afe60830867a875183a71/LICENSE /usr/share/licenses/kustomize/LICENSE
ENV HOME=/tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/kustomize"]
