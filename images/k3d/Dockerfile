# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
# Official released binaries. k3d uses the Docker SDK, not an external Docker CLI.
FROM scratch AS binary-amd64
ADD --checksum=sha256:06d8f25bc3a971c4eb29e0ff08429b180402db0f4dec838c9eac427e296800a0 --chmod=0555 https://github.com/k3d-io/k3d/releases/download/v5.9.0/k3d-linux-amd64 /k3d
FROM scratch AS binary-arm64
ADD --checksum=sha256:03cde5cf23e6e8e67de5a039ecf26e5b85aca82fba3e5d13dadf904cd218a250 --chmod=0555 https://github.com/k3d-io/k3d/releases/download/v5.9.0/k3d-linux-arm64 /k3d
FROM binary-${TARGETARCH} AS binary
FROM cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9
LABEL org.opencontainers.image.title="k3d" \
      org.opencontainers.image.version="5.9.0" \
      org.opencontainers.image.source="https://github.com/k3d-io/k3d" \
      org.opencontainers.image.revision="15dd1e2dbd62c53ed990fce9b7332335e8cb053c" \
      org.opencontainers.image.licenses="MIT"
COPY --from=binary /k3d /usr/local/bin/k3d
ADD --checksum=sha256:8174fbb84d2253f37fbb00bb2378a1bbd622a73c450caf635f1bb65163a19a37 --chmod=0444 https://raw.githubusercontent.com/k3d-io/k3d/15dd1e2dbd62c53ed990fce9b7332335e8cb053c/LICENSE /usr/share/licenses/k3d/LICENSE
ENV HOME=/tmp
USER 65532:65532
# Docker control-plane access is privileged and never supplied to scanner/smoke checks.
ENTRYPOINT ["/usr/local/bin/k3d"]
