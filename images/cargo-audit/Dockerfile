# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
# RustSec's arm64 release is GNU/dynamic. The static arm64 artifact below is a
# DISTINCT supplier (Cargo Quickinstall), not an authenticated RustSec build.
FROM scratch AS archive-amd64
ADD --checksum=sha256:c32506f338bdcdaef5a17fb9f33abb6ecf9561324cfd34237fd335f9283a1eab https://github.com/rustsec/rustsec/releases/download/cargo-audit/v0.22.1/cargo-audit-x86_64-unknown-linux-musl-v0.22.1.tgz /cargo-audit.tgz
FROM scratch AS archive-arm64
ADD --checksum=sha256:b33ed5d95ac0ccda2e281a885a117a03fa92084c3e83f468fb82c2272fb26b60 https://github.com/cargo-bins/cargo-quickinstall/releases/download/cargo-audit-0.22.1/cargo-audit-0.22.1-aarch64-unknown-linux-musl.tar.gz /cargo-audit.tgz

FROM --platform=$BUILDPLATFORM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS extract
RUN --network=none ["mkdir", "/out"]
FROM extract AS binary-amd64
COPY --from=archive-amd64 /cargo-audit.tgz /tmp/cargo-audit.tgz
RUN --network=none ["tar", "-xzf", "/tmp/cargo-audit.tgz", "-C", "/out", "--strip-components=1"]
FROM extract AS binary-arm64
COPY --from=archive-arm64 /cargo-audit.tgz /tmp/cargo-audit.tgz
RUN --network=none ["tar", "-xzf", "/tmp/cargo-audit.tgz", "-C", "/out"]
FROM binary-${TARGETARCH} AS binary

FROM cgr.dev/chainguard/static:latest@sha256:17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde
LABEL org.opencontainers.image.title="cargo-audit" org.opencontainers.image.version="0.22.1" org.opencontainers.image.source="https://github.com/rustsec/rustsec" org.prjxai.audit.arm64.supplier="cargo-bins/cargo-quickinstall"
COPY --from=binary --chmod=0555 /out/cargo-audit /usr/local/bin/cargo-audit
COPY --from=binary-amd64 /out/LICENSE-APACHE /out/LICENSE-MIT /out/README.md /out/CHANGELOG.md /usr/share/licenses/cargo-audit/
ENV HOME=/tmp CARGO_HOME=/tmp/cargo
WORKDIR /workspace
USER 65532:65532
# Retrieve RustSec separately. Offline: --db /rustsec --no-fetch --file /workspace/Cargo.lock.
# Entry point already supplies the Cargo-plugin subcommand; do not repeat audit.
ENTRYPOINT ["/usr/local/bin/cargo-audit", "audit"]
CMD ["--help"]
