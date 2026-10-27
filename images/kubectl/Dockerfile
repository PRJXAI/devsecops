# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b

# Released static clients matching the consumer's kindest/node Kubernetes v1.37.0.
# Hashes: https://dl.k8s.io/release/v1.37.0/bin/linux/{amd64,arm64}/kubectl.sha256
# Source: https://github.com/kubernetes/kubernetes/tree/f54c212e3a2f75d674b717a9b29052b20b60aefc
FROM scratch AS binary-amd64
ADD --checksum=sha256:6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f --chmod=0555 https://dl.k8s.io/release/v1.37.0/bin/linux/amd64/kubectl /kubectl

FROM scratch AS binary-arm64
ADD --checksum=sha256:922df28df248cc00a9e025f947704f1d1482de64ece54cfe57e61f19eaf1eef3 --chmod=0555 https://dl.k8s.io/release/v1.37.0/bin/linux/arm64/kubectl /kubectl

FROM binary-${TARGETARCH} AS binary

# Supplier license; complete embedded-dependency notice review is required before publication.

FROM cgr.dev/chainguard/static:latest@sha256:17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde
LABEL org.opencontainers.image.title="kubectl" \
      org.opencontainers.image.version="1.37.0" \
      org.opencontainers.image.source="https://github.com/kubernetes/kubernetes" \
      org.opencontainers.image.revision="f54c212e3a2f75d674b717a9b29052b20b60aefc" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=binary /kubectl /usr/local/bin/kubectl
ADD --checksum=sha256:cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30 --chmod=0444 https://raw.githubusercontent.com/kubernetes/kubernetes/f54c212e3a2f75d674b717a9b29052b20b60aefc/LICENSE /usr/share/licenses/kubectl/LICENSE
ENV HOME=/tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/kubectl"]
