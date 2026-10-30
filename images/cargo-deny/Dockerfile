# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
# Released static binaries; architecture selection is declarative, not shell glue.
FROM scratch AS archive-amd64
ADD --checksum=sha256:9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f https://github.com/EmbarkStudios/cargo-deny/releases/download/0.20.2/cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz /cargo-deny.tar.gz
FROM scratch AS archive-arm64
ADD --checksum=sha256:995c82be0defc7a025cae49a2aa2644ce8245c9a3318fc4103907c6a285e8c7d https://github.com/EmbarkStudios/cargo-deny/releases/download/0.20.2/cargo-deny-0.20.2-aarch64-unknown-linux-musl.tar.gz /cargo-deny.tar.gz
FROM archive-${TARGETARCH} AS archive

FROM --platform=$BUILDPLATFORM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS extract
COPY --from=archive /cargo-deny.tar.gz /tmp/cargo-deny.tar.gz
RUN --network=none ["mkdir", "/out"]
RUN --network=none ["tar", "-xzf", "/tmp/cargo-deny.tar.gz", "-C", "/out", "--strip-components=1"]

FROM cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9
LABEL org.opencontainers.image.title="cargo-deny" org.opencontainers.image.version="0.20.2" org.opencontainers.image.source="https://github.com/EmbarkStudios/cargo-deny"
COPY --from=extract --chmod=0555 /out/cargo-deny /usr/local/bin/cargo-deny
COPY --from=extract /out/LICENSE-APACHE /out/LICENSE-MIT /out/README.md /usr/share/licenses/cargo-deny/
ENV HOME=/tmp CARGO_HOME=/tmp/cargo
WORKDIR /workspace
USER 65532:65532
# Requires external metadata and exact-path source/cache mounts. Missing Cargo/index
# diagnostics can be nonfatal: exit 0 is NOT proof of complete checks. Not approved
# as a replacement for the consumer's host cargo-deny gate. See tool inventory.
ENTRYPOINT ["/usr/local/bin/cargo-deny"]
CMD ["--help"]
