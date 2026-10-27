# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
# Official RustSec GNU releases on both architectures; see docs/cargo-audit-supplier.md.
FROM scratch AS archive-amd64
ADD --checksum=sha256:1890badd5f15831a9af4b074399fcd21e6f7c0fe42c84e9254cdffc9f813765c https://github.com/rustsec/rustsec/releases/download/cargo-audit/v0.22.1/cargo-audit-x86_64-unknown-linux-gnu-v0.22.1.tgz /cargo-audit.tgz
FROM scratch AS archive-arm64
ADD --checksum=sha256:4c8df835ee484441bd2c8c6bcac28c4ce4b4058ba9e7477cb9e0012fe7769f66 https://github.com/rustsec/rustsec/releases/download/cargo-audit/v0.22.1/cargo-audit-aarch64-unknown-linux-gnu-v0.22.1.tgz /cargo-audit.tgz

FROM --platform=$BUILDPLATFORM alpine:3.23.7@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63 AS extract
RUN --network=none ["mkdir", "/out"]
FROM extract AS binary-amd64
COPY --from=archive-amd64 /cargo-audit.tgz /tmp/cargo-audit.tgz
RUN --network=none ["tar", "-xzf", "/tmp/cargo-audit.tgz", "-C", "/out", "--strip-components=1"]
FROM extract AS binary-arm64
COPY --from=archive-arm64 /cargo-audit.tgz /tmp/cargo-audit.tgz
RUN --network=none ["tar", "-xzf", "/tmp/cargo-audit.tgz", "-C", "/out", "--strip-components=1"]
FROM binary-${TARGETARCH} AS binary

# Select individual verified ELF objects, not the supplier's rootfs, utilities,
# libstdc++, locale, package metadata or loader configuration.
FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:5380a8b913d0900cf44180e2205bf3ebf0e0b00a32a0f2fa4ab16cb06d7f9cdf AS glibc
FROM cgr.dev/chainguard/static:latest@sha256:17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde AS runtime-amd64
COPY --from=glibc /usr/lib/ld-linux-x86-64.so.2 /usr/lib/ld-linux-x86-64.so.2
COPY --from=glibc /usr/lib/libc.so.6 /usr/lib/libm.so.6 /usr/lib/libgcc_s.so.1 /usr/lib/
FROM cgr.dev/chainguard/static:latest@sha256:17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde AS runtime-arm64
COPY --from=glibc /usr/lib/ld-linux-aarch64.so.1 /usr/lib/ld-linux-aarch64.so.1
COPY --from=glibc /usr/lib/libc.so.6 /usr/lib/libm.so.6 /usr/lib/libgcc_s.so.1 /usr/lib/libpthread.so.0 /usr/lib/libdl.so.2 /usr/lib/
FROM runtime-${TARGETARCH}
LABEL org.opencontainers.image.title="cargo-audit" org.opencontainers.image.version="0.22.1" org.opencontainers.image.source="https://github.com/rustsec/rustsec"
COPY --from=binary --chmod=0555 /out/cargo-audit /usr/local/bin/cargo-audit
COPY --from=binary-amd64 /out/LICENSE-APACHE /out/LICENSE-MIT /out/README.md /out/CHANGELOG.md /usr/share/licenses/cargo-audit/
ENV HOME=/tmp CARGO_HOME=/tmp/cargo
WORKDIR /workspace
USER 65532:65532
# Retrieve RustSec separately. Offline: --db /rustsec --no-fetch --file /workspace/Cargo.lock.
# Entry point already supplies the Cargo-plugin subcommand; do not repeat audit.
ENTRYPOINT ["/usr/local/bin/cargo-audit", "audit"]
CMD ["--help"]
