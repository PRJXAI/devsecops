# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b

# Released upstream archives; hashes also recorded by the kustomize/v5.8.1 release API.
# Source: https://github.com/kubernetes-sigs/kustomize/tree/9790a1c3efd2fd35f1b768d495112834176581c1
FROM scratch AS archive-amd64
ADD --checksum=sha256:029a7f0f4e1932c52a0476cf02a0fd855c0bb85694b82c338fc648dcb53a819d https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v5.8.1/kustomize_v5.8.1_linux_amd64.tar.gz /kustomize.tar.gz

FROM scratch AS archive-arm64
ADD --checksum=sha256:0953ea3e476f66d6ddfcd911d750f5167b9365aa9491b2326398e289fef2c142 https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v5.8.1/kustomize_v5.8.1_linux_arm64.tar.gz /kustomize.tar.gz

FROM archive-${TARGETARCH} AS archive

# Extraction only, on the builder architecture; no compiler or source rebuild.
FROM --platform=$BUILDPLATFORM alpine:3.23.7@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63 AS extract
COPY --from=archive /kustomize.tar.gz /tmp/kustomize.tar.gz
RUN --network=none ["mkdir", "/out"]
RUN --network=none ["tar", "-xzf", "/tmp/kustomize.tar.gz", "-C", "/out", "kustomize"]

# Supplier license; complete embedded-dependency notice review is required before publication.

FROM cgr.dev/chainguard/static:latest@sha256:9e2306b457ff71ce370043dc68c7b52bb1e6622c1c6c6714edbed57496f3116e
LABEL org.opencontainers.image.title="kustomize" \
      org.opencontainers.image.version="5.8.1" \
      org.opencontainers.image.source="https://github.com/kubernetes-sigs/kustomize" \
      org.opencontainers.image.revision="9790a1c3efd2fd35f1b768d495112834176581c1" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=extract --chmod=0555 /out/kustomize /usr/local/bin/kustomize
ADD --checksum=sha256:b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1 --chmod=0444 https://raw.githubusercontent.com/kubernetes-sigs/kustomize/9790a1c3efd2fd35f1b768d495112834176581c1/LICENSE /usr/share/licenses/kustomize/LICENSE
ENV HOME=/tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/kustomize"]
