# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b
# Official RustSec GNU releases on both architectures; see docs/cargo-audit-supplier.md.
FROM scratch AS archive-amd64
ADD --checksum=sha256:ab28a1bdb54db4d5d8ad5981cf1f959410370b3d28250dbd35f6a44248620e39 https://github.com/rustsec/rustsec/releases/download/cargo-audit/v0.22.2/cargo-audit-x86_64-unknown-linux-gnu-v0.22.2.tgz /cargo-audit.tgz
FROM scratch AS archive-arm64
ADD --checksum=sha256:c6603814ddaa45e51263dafd31c0ac98808f688d26f7395804f9670b0fd599dd https://github.com/rustsec/rustsec/releases/download/cargo-audit/v0.22.2/cargo-audit-aarch64-unknown-linux-gnu-v0.22.2.tgz /cargo-audit.tgz

FROM --platform=$BUILDPLATFORM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS extract
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
FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:709673274b417a48f56374da8a7633ef7b2f5b27e34612ce98a335737318cc94 AS glibc
FROM cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9 AS runtime-amd64
COPY --from=glibc /usr/lib/ld-linux-x86-64.so.2 /usr/lib/ld-linux-x86-64.so.2
COPY --from=glibc /usr/lib/libc.so.6 /usr/lib/libm.so.6 /usr/lib/libgcc_s.so.1 /usr/lib/
FROM cgr.dev/chainguard/static:latest@sha256:fc42af33e643f20d08baf03cddcc1c02ba57052dfb02edb0d79f3fc47bcea8d9 AS runtime-arm64
COPY --from=glibc /usr/lib/ld-linux-aarch64.so.1 /usr/lib/ld-linux-aarch64.so.1
COPY --from=glibc /usr/lib/libc.so.6 /usr/lib/libm.so.6 /usr/lib/libgcc_s.so.1 /usr/lib/libpthread.so.0 /usr/lib/libdl.so.2 /usr/lib/
FROM runtime-${TARGETARCH}
LABEL org.opencontainers.image.title="cargo-audit" org.opencontainers.image.version="0.22.2" org.opencontainers.image.source="https://github.com/rustsec/rustsec"
COPY --from=binary --chmod=0555 /out/cargo-audit /usr/local/bin/cargo-audit
COPY --from=binary-amd64 /out/LICENSE-APACHE /out/LICENSE-MIT /out/README.md /out/CHANGELOG.md /usr/share/licenses/cargo-audit/
ENV HOME=/tmp CARGO_HOME=/tmp/cargo
WORKDIR /workspace
USER 65532:65532
# Retrieve RustSec separately. Offline: --db /rustsec --no-fetch --file /workspace/Cargo.lock.
# Entry point already supplies the Cargo-plugin subcommand; do not repeat audit.
ENTRYPOINT ["/usr/local/bin/cargo-audit", "audit"]
CMD ["--help"]
